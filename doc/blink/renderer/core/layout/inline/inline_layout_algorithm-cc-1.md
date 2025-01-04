Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They are particularly interested in:

1. **Listing the functions:** Identify what the code does.
2. **Connections to web technologies (JavaScript, HTML, CSS):** Explain how the code relates to these technologies with examples.
3. **Logic and assumptions:** If the code performs calculations or makes decisions, describe the inputs and outputs.
4. **Common errors:** Point out potential mistakes users or programmers could make that would interact with this code.
5. **Summarize overall functionality:** Provide a concise description of the code's purpose as the second part of a larger file.

Let
Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
line" block-level out-of-flow positioned
  // object is placed on, we need to keep track of if there is any inline-level
  // content preceeding it.
  bool has_preceding_inline_level_content = false;
  bool has_rtl_block_level_out_of_flow_objects = false;
  bool is_ltr = IsLtr(line_info.BaseDirection());

  for (LogicalLineItem& child : *line_box) {
    has_preceding_inline_level_content |= child.HasInFlowFragment();

    const LayoutObject* box = child.out_of_flow_positioned_box;
    if (!box)
      continue;

    LogicalOffset static_offset(LayoutUnit(), baseline_adjustment);
    if (box->StyleRef().IsOriginalDisplayInlineType()) {
      // An inline-level OOF element positions itself within the line, at the
      // position it would have been if it was in-flow.
      static_offset.inline_offset = child.rect.offset.inline_offset;

      // The static-position of inline-level OOF-positioned nodes depends on
      // previous floats (if any).
      //
      // If we are an empty-inline we may not have the correct BFC block-offset
      // yet. Due to this we need to mark this node as having adjoining
      // objects, and perform a re-layout if our position shifts.
      container_builder_.AddAdjoiningObjectTypes(kAdjoiningInlineOutOfFlow);
    } else {
      // A block-level OOF element positions itself on the "next" line. However
      // only shifts down if there is preceding inline-level content.
      static_offset.inline_offset = block_level_inline_offset;
      if (is_ltr) {
        if (has_preceding_inline_level_content)
          static_offset.block_offset += line_height;
      } else {
        // "Preceding" is in logical order, but this loop is in visual order. In
        // RTL, move objects down in the reverse-order loop below.
        has_rtl_block_level_out_of_flow_objects = true;
      }
    }

    child.rect.offset = static_offset;
  }

  if (has_rtl_block_level_out_of_flow_objects) [[unlikely]] {
    has_preceding_inline_level_content = false;
    for (LogicalLineItem& child : base::Reversed(*line_box)) {
      const LayoutObject* box = child.out_of_flow_positioned_box;
      if (!box) {
        has_preceding_inline_level_content |= child.HasInFlowFragment();
        continue;
      }
      if (has_preceding_inline_level_content &&
          !box->StyleRef().IsOriginalDisplayInlineType()) {
        child.rect.offset.block_offset += line_height;
      }
    }
  }
}

void InlineLayoutAlgorithm::PlaceFloatingObjects(
    const FontHeight& line_box_metrics,
    const LineLayoutOpportunity& opportunity,
    LayoutUnit ruby_block_start_adjust,
    LineInfo* line_info,
    LogicalLineItems* line_box) {
  DCHECK(line_info->IsEmptyLine() || !line_box_metrics.IsEmpty())
      << "Non-empty lines must have a valid set of linebox metrics.";

  // All children within the linebox are positioned relative to the baseline,
  // then shifted later using LineBoxFragmentBuilder::MoveInBlockDirection.
  LayoutUnit baseline_adjustment =
      line_info->IsEmptyLine() ? LayoutUnit() : -line_box_metrics.ascent;

  LayoutUnit line_height =
      line_info->IsEmptyLine() ? LayoutUnit() : line_box_metrics.LineHeight();

  // Any unpositioned floats we encounter need to be placed on the "next" line.
  // This BFC block-offset represents the start of the "next" line.
  LayoutUnit origin_bfc_block_offset =
      opportunity.bfc_block_offset + line_height;

  LayoutUnit bfc_line_offset = container_builder_.BfcLineOffset();
  LayoutUnit bfc_block_offset =
      line_info->IsEmptyLine()
          ? GetConstraintSpace().ExpectedBfcBlockOffset()
          : line_info->GetBfcOffset().block_offset + ruby_block_start_adjust;

  for (LogicalLineItem& child : *line_box) {
    // We need to position any floats which should be on the "next" line now.
    // If this is an empty inline, all floats are positioned during the
    // PositionLeadingFloats step.
    if (child.unpositioned_float) {
      // If we're resuming in a parallel fragmentation flow, the line breaker
      // should not leave any unpositioned floats behind.
      DCHECK(!GetBreakToken() || !GetBreakToken()->IsInParallelBlockFlow());

      PositionedFloat positioned_float =
          PositionFloat(origin_bfc_block_offset, child.unpositioned_float,
                        &GetExclusionSpace());
      const BlockBreakToken* break_token = positioned_float.BreakToken();
      if (break_token) {
        const auto* parallel_token =
            InlineBreakToken::CreateForParallelBlockFlow(
                node_, child.item_index, *break_token);
        line_info->PropagateParallelFlowBreakToken(parallel_token);
        if (positioned_float.minimum_space_shortage) {
          line_info->PropagateMinimumSpaceShortage(
              positioned_float.minimum_space_shortage);
        }
      }
      if (!break_token || !break_token->IsBreakBefore()) {
        child.layout_result = std::move(positioned_float.layout_result);
        child.bfc_offset = positioned_float.bfc_offset;
        child.unpositioned_float = nullptr;
      }
    }

    // Skip any children which aren't positioned floats.
    if (!child.layout_result ||
        !child.layout_result->GetPhysicalFragment().IsFloating()) {
      continue;
    }

    LayoutUnit block_offset =
        child.bfc_offset.block_offset - bfc_block_offset + baseline_adjustment;

    // We need to manually account for the flipped-lines writing mode here :(.
    if (IsFlippedLinesWritingMode(GetConstraintSpace().GetWritingMode())) {
      LogicalFragment fragment(GetConstraintSpace().GetWritingDirection(),
                               child.layout_result->GetPhysicalFragment());

      block_offset = -fragment.BlockSize() - block_offset;
    }

    child.rect.offset = {child.bfc_offset.line_offset - bfc_line_offset,
                         block_offset};
  }
}

// Apply the 'text-align' property to |line_info|. Returns the amount to move
// the line in the inline direction.
LayoutUnit InlineLayoutAlgorithm::ApplyTextAlign(LineInfo* line_info) {
  // LineInfo::WidthForAlignment may return a negative value, as text-indent
  // can accept negative values. We need to use this un-clamped value for
  // alignment, instead of just LineInfo::Width.
  LayoutUnit space =
      line_info->AvailableWidth() - line_info->WidthForAlignment();

  ETextAlign text_align = line_info->TextAlign();
  if (text_align == ETextAlign::kJustify) {
    JustificationTarget target = JustificationTarget::kNormal;
    if (Node().IsSvgText()) {
      target = JustificationTarget::kSvgText;
    } else if (line_info->IsRubyBase()) {
      target = JustificationTarget::kRubyBase;
    } else if (line_info->IsRubyText()) {
      target = JustificationTarget::kRubyText;
    }
    std::optional<LayoutUnit> offset =
        ApplyJustification(space, target, line_info);
    if (offset)
      return *offset;

    // If justification fails, fallback to 'text-align: start'.
    text_align = ETextAlign::kStart;
  }

  return LineOffsetForTextAlign(text_align, line_info->BaseDirection(), space);
}

LayoutUnit InlineLayoutAlgorithm::SetAnnotationOverflow(
    const LineInfo& line_info,
    const LogicalLineItems& line_box,
    const FontHeight& line_box_metrics,
    std::optional<FontHeight> annotation_font_height) {
  AnnotationMetrics annotation_metrics =
      ComputeAnnotationOverflow(line_box, line_box_metrics,
                                line_info.LineStyle(), annotation_font_height);
  LayoutUnit annotation_overflow_block_start;
  LayoutUnit annotation_overflow_block_end;
  LayoutUnit annotation_space_block_start;
  LayoutUnit annotation_space_block_end;
  if (!IsFlippedLinesWritingMode(line_info.LineStyle().GetWritingMode())) {
    annotation_overflow_block_start = annotation_metrics.overflow_over;
    annotation_overflow_block_end = annotation_metrics.overflow_under;
    annotation_space_block_start = annotation_metrics.space_over;
    annotation_space_block_end = annotation_metrics.space_under;
  } else {
    annotation_overflow_block_start = annotation_metrics.overflow_under;
    annotation_overflow_block_end = annotation_metrics.overflow_over;
    annotation_space_block_start = annotation_metrics.space_under;
    annotation_space_block_end = annotation_metrics.space_over;
  }

  LayoutUnit block_offset_shift = annotation_overflow_block_start;
  // If the previous line has block-end annotation overflow and this line has
  // block-start annotation space, shift up the block offset of this line.
  if (GetConstraintSpace().BlockStartAnnotationSpace() < LayoutUnit() &&
      annotation_space_block_start) {
    const LayoutUnit overflow =
        -GetConstraintSpace().BlockStartAnnotationSpace();
    block_offset_shift = -std::min(annotation_space_block_start, overflow);
  }

  // If this line has block-start annotation overflow and the previous line
  // has block-end annotation space, borrow the block-end space of the
  // previous line and shift down the block offset by |overflow - space|.
  if (annotation_overflow_block_start &&
      GetConstraintSpace().BlockStartAnnotationSpace() > LayoutUnit()) {
    block_offset_shift = (annotation_overflow_block_start -
                          GetConstraintSpace().BlockStartAnnotationSpace())
                             .ClampNegativeToZero();
  }

  if (annotation_overflow_block_end)
    container_builder_.SetAnnotationOverflow(annotation_overflow_block_end);
  else if (annotation_space_block_end)
    container_builder_.SetBlockEndAnnotationSpace(annotation_space_block_end);

  return block_offset_shift;
}

bool InlineLayoutAlgorithm::AddAnyClearanceAfterLine(
    const LineInfo& line_info) {
  const InlineItemResults& line_items = line_info.Results();
  if (line_items.empty())
    return true;

  // If the last item was a <br> we need to adjust the content_size to clear
  // floats if specified. The <br> element must be at the back of the item
  // result list as it forces a line to break.
  const InlineItemResult& item_result = line_items.back();
  DCHECK(item_result.item);
  const InlineItem& item = *item_result.item;
  const LayoutObject* layout_object = item.GetLayoutObject();
  const LayoutUnit content_size =
      container_builder_.LineHeight() -
      container_builder_.TrimBlockEndBy().value_or(LayoutUnit());

  // layout_object may be null in certain cases, e.g. if it's a kBidiControl.
  if (layout_object && layout_object->IsBR()) {
    const LayoutUnit line_box_bfc_block_offset =
        *container_builder_.LineBoxBfcBlockOffset();
    BfcOffset bfc_offset = {LayoutUnit(),
                            line_box_bfc_block_offset + content_size};
    LayoutUnit block_end_offset_without_clearence = bfc_offset.block_offset;
    const auto clear_type = item.Style()->Clear(Style());
    if (clear_type != EClear::kNone) {
      AdjustToClearance(GetExclusionSpace().ClearanceOffset(clear_type),
                        &bfc_offset);

      // Unlike regular CSS clearance (which adds space *before* content), BR
      // clearance is about adding space *after* content. Store the amount of
      // space to add, so that we push subsequent content (and stretch the
      // container) past the relevant floats.
      container_builder_.SetClearanceAfterLine(
          bfc_offset.block_offset - block_end_offset_without_clearence);
    }

    if (GetConstraintSpace().HasBlockFragmentation() &&
        GetExclusionSpace().NeedsClearancePastFragmentainer(clear_type)) {
      return false;
    }
  }
  return true;
}

const LayoutResult* InlineLayoutAlgorithm::Layout() {
  const auto& constraint_space = GetConstraintSpace();
  ExclusionSpace initial_exclusion_space(constraint_space.GetExclusionSpace());

  // Clear break tokens (for fragmented floats) propagated from the previous
  // line (or even the *current* line, in cases where we retry layout after
  // having resolved the BFC offset).
  context_->ClearParallelFlowBreakTokens();

  end_margin_strut_ = constraint_space.GetMarginStrut();
  container_builder_.SetAdjoiningObjectTypes(
      constraint_space.GetAdjoiningObjectTypes());
  lines_until_clamp_ = constraint_space.GetLineClampData().LinesUntilClamp(
      /*show_measured_lines*/ true);

  // In order to get the correct list of layout opportunities, we need to
  // position any "leading" floats within the exclusion space first.
  LeadingFloats leading_floats;
  PositionLeadingFloats(initial_exclusion_space, leading_floats);

  // Determine our BFC block-offset, but *don't* set it on the builder yet as
  // we might be an empty line.
  bool is_pushed_by_floats = false;
  LayoutUnit bfc_block_offset =
      constraint_space.ForcedBfcBlockOffset().value_or(
          constraint_space.GetBfcOffset().block_offset +
          constraint_space.GetMarginStrut().Sum());

  // Also apply clearance if necessary.
  if (constraint_space.HasClearanceOffset() &&
      bfc_block_offset < constraint_space.ClearanceOffset()) {
    bfc_block_offset = constraint_space.ClearanceOffset();
    is_pushed_by_floats = true;
  }

  // For initial letter, we should clear previous block's initial letter[1][2]
  // if:
  //   - new formatting context
  //   - starts with an initial letter
  //   - `clear` in start direction of initial letter containing block.
  //
  // [1] https://drafts.csswg.org/css-inline/#short-para-initial-letter
  // [2]
  // https://wpt.live/css/css-inline/initial-letter/initial-letter-short-para-initial-letter-clears.html
  if (!context_->ItemsBuilder()->Size()) {
    EClear clear_type;
    if (Node().HasInitialLetterBox()) [[unlikely]] {
      clear_type = EClear::kBoth;
    } else {
      clear_type = Node().Style().Clear(constraint_space.Direction());
    }
    const LayoutUnit initial_letter_clearance =
        constraint_space.GetExclusionSpace().InitialLetterClearanceOffset(
            clear_type);
    if (initial_letter_clearance > bfc_block_offset) {
      // The initial letter box causes container separation to reuse layout
      // result, e.g.
      //    <div class="initial-letter-1">abc</div>
      //    <!-- change to 11px and will result in a bad layout -->
      //    <div style="height: 1px"></div>
      //    <div class="initial-letter-2">xyz</div>
      //
      bfc_block_offset = initial_letter_clearance;
      is_pushed_by_floats = true;
    }
  }

  // We query all the layout opportunities on the initial exclusion space up
  // front, as if the line breaker may add floats and change the opportunities.
  LayoutOpportunityVector opportunities =
      initial_exclusion_space.AllLayoutOpportunities(
          {constraint_space.GetBfcOffset().line_offset, bfc_block_offset},
          constraint_space.AvailableSize().inline_size);
  ClearCollectionScope scope(&opportunities);

  const InlineBreakToken* break_token = GetBreakToken();

  if (break_token && break_token->IsInParallelBlockFlow()) {
    container_builder_.SetIsLineForParallelFlow();
  }

  FragmentItemsBuilder* const items_builder = context_->ItemsBuilder();
  DCHECK(items_builder);
  LogicalLineContainer* const line_container =
      items_builder->AcquireLogicalLineContainer();
  DCHECK(line_container);
  // Determine which line breaker to use.
  LineBreakStrategy line_break_strategy(context_, Node(), Style(), break_token,
                                        column_spanner_path_);
  bool is_line_created = false;
  bool is_end_paragraph = false;
  LayoutUnit line_block_size;
  LayoutUnit block_delta;
  auto opportunities_it = opportunities.begin();
  while (opportunities_it != opportunities.end()) {
    const LayoutOpportunity& opportunity = *opportunities_it;

#if DCHECK_IS_ON()
    // Make sure the last opportunity has the correct properties.
    if (opportunities_it + 1 == opportunities.end()) {
      // We shouldn't have any shapes affecting the last opportunity.
      DCHECK(!opportunity.HasShapeExclusions());
      DCHECK_EQ(line_block_size, LayoutUnit());
      DCHECK_EQ(block_delta, LayoutUnit());

      // The opportunity should match the given available size, (however need
      // to check if the inline-size got saturated first).
      if (opportunity.rect.InlineSize() != LayoutUnit::Max()) {
        DCHECK_EQ(opportunity.rect.InlineSize(),
                  constraint_space.AvailableSize().inline_size);
      }
      DCHECK_EQ(opportunity.rect.BlockSize(), LayoutUnit::Max());
    }
#endif

    // Reset any state that may have been modified in a previous pass.
    container_builder_.Reset();
    container_builder_.SetExclusionSpace(initial_exclusion_space);
    is_line_created = false;

    LineLayoutOpportunity line_opportunity =
        opportunity.ComputeLineLayoutOpportunity(constraint_space,
                                                 line_block_size, block_delta);
    if (line_break_strategy.NeedsToPrepare()) [[unlikely]] {
      line_break_strategy.Prepare(
          context_, Node(), constraint_space,
          base::make_span(opportunities_it, opportunities.end()),
          line_opportunity, leading_floats, break_token, &GetExclusionSpace());
    }
    bool is_line_info_cached = false;
    LineInfo& line_info =
        context_->GetLineInfo(break_token, is_line_info_cached);
    if (is_line_info_cached) [[unlikely]] {
      // Update the BFC offset because it was not known when the `line_info` was
      // cached.
      line_info.SetBfcOffset({line_opportunity.line_left_offset,
                              line_opportunity.bfc_block_offset});
    } else {
      LineBreaker line_breaker(Node(), LineBreakerMode::kContent,
                               constraint_space, line_opportunity,
                               leading_floats, break_token,
                               column_spanner_path_, &GetExclusionSpace());
      line_break_strategy.SetupLineBreaker(context_, line_breaker);
      line_breaker.NextLine(&line_info);
    }

    if (Node().IsInitialLetterBox()) [[unlikely]] {
      // Because `LineBreaker` doesn't calculate the inline size of initial
      // letter box from text ink bounds as performance reason. We calculate
      // here for `LineInfo::Width()` for text alignment and RTL[1][2].
      // [1]
      // https://wpt.live/css/css-inline/initial-letter/initial-letter-indentation-rtl.html
      // [2]
      // https://wpt.live/css/css-inline/initial-letter/initial-letter-indentation.html
      line_info.SetWidth(line_info.AvailableWidth(),
                         CalculateInitialLetterBoxInlineSize(line_info));
    }

    const auto* block_in_inline_result = line_info.BlockInInlineLayoutResult();
    if (block_in_inline_result) {
      if (block_in_inline_result->Status() != LayoutResult::kSuccess)
          [[unlikely]] {
        items_builder->ReleaseCurrentLogicalLineContainer();
        return block_in_inline_result;
      }

      if (block_in_inline_result->IsPushedByFloats())
        container_builder_.SetIsPushedByFloats();
      else if (block_in_inline_result->SubtreeModifiedMarginStrut())
        container_builder_.SetSubtreeModifiedMarginStrut();
    }

    // Set our BFC block-offset if we aren't an empty line.
    if (!line_info.IsEmptyLine()) {
      if (block_in_inline_result && block_in_inline_result->BfcBlockOffset()) {
        const auto result_bfc_block_offset =
            block_in_inline_result->BfcBlockOffset();
        container_builder_.SetBfcBlockOffset(*result_bfc_block_offset);
        container_builder_.SetLineBoxBfcBlockOffset(*result_bfc_block_offset);
      } else {
        container_builder_.SetBfcBlockOffset(bfc_block_offset);
        container_builder_.SetLineBoxBfcBlockOffset(
            line_info.GetBfcOffset().block_offset);
        if (is_pushed_by_floats)
          container_builder_.SetIsPushedByFloats();
      }

      // Abort if something before needs to know the correct BFC block-offset.
      if (container_builder_.GetAdjoiningObjectTypes() &&
          bfc_block_offset != constraint_space.ExpectedBfcBlockOffset()) {
        items_builder->ReleaseCurrentLogicalLineContainer();
        return container_builder_.Abort(LayoutResult::kBfcBlockOffsetResolved);
      }
    }

    // If this fragment will be larger than the inline-size of the opportunity,
    // *and* the opportunity is smaller than the available inline-size, and the
    // container autowraps, continue to the next opportunity.
    if (line_info.HasOverflow() &&
        !line_opportunity.IsEqualToAvailableFloatInlineSize(
            constraint_space.AvailableSize().inline_size) &&
        Node().Style().ShouldWrapLine()) {
      DCHECK(!line_info.IsBlockInInline());

      // Shapes are *special*. We need to potentially increment the block-delta
      // by 1px each loop to properly test each potential position of the line.
      if (opportunity.HasShapeExclusions() &&
          block_delta < opportunity.rect.BlockSize() &&
          !opportunity.IsBlockDeltaBelowShapes(block_delta)) [[unlikely]] {
        block_delta += LayoutUnit(1);
        line_block_size = LayoutUnit();
        continue;
      }
      // We've either don't have any shapes, or run out of block-delta space
      // to test, proceed to the next layout opportunity.
      if (opportunities_it + 1 != opportunities.end()) {
        block_delta = LayoutUnit();
        line_block_size = LayoutUnit();
        ++opportunities_it;
        continue;
      }
      // Normally the last opportunity should fit the line, but arithmetic
      // overflow can lead to failures for all opportunities. Just let the line
      // to overflow in that case.
    }

    PrepareBoxStates(line_info, break_token);

    CreateLine(line_opportunity, &line_info, line_container);
    is_line_created = true;
    is_end_paragraph = line_info.IsEndParagraph();

    // Adjust the line BFC block-offset if we have a ruby annotation, raise
    // initial letter or sunken initial letter.
    const LayoutUnit block_start_adjust =
        line_info.ComputeBlockStartAdjustment();
    if (block_start_adjust) [[unlikely]] {
      DCHECK(container_builder_.BfcBlockOffset());
      DCHECK(container_builder_.LineBoxBfcBlockOffset());
      DCHECK(!line_info.IsEmptyLine());
      container_builder_.SetLineBoxBfcBlockOffset(
          line_info.GetBfcOffset().block_offset + block_start_adjust);
      container_builder_.SetAnnotationBlockOffsetAdjustment(
          line_info.ComputeAnnotationBlockOffsetAdjustment());
    }

    // We now can check the block-size of the fragment, and it fits within the
    // opportunity. Also include the ruby annotations so that they don't
    // intersect with any floats.
    //
    // To use next opportunity, `total_block_size` contains initial letter box
    // block-size.
    //
    // opportunities[0] 111    ***** his is first line.
    //                  111      *   This is second line.
    // opportunities[1] 222222   *   This is third line.
    //                  222222   *   This is fourth line.
    //                  This is fifth line.
    // opportunities[2] 333 This is sixth line.
    //
    // where '1', '2', '3' are `float:left` with `clear:left`.
    //
    // If we don't set `initial_letter_box_block_size`, the test[1] fails.
    // [1]
    // https://wpt.live/css/css-inline/initial-letter/initial-letter-floats-003.html
    const LayoutUnit total_block_size = line_info.ComputeTotalBlockSize(
        container_builder_.LineHeight(),
        container_builder_.AnnotationOverflow().ClampNegativeToZero());

    // Now that we have the block-size of the line, we can re-test the layout
    // opportunity to see if we fit into the (potentially) non-rectangular
    // shape area.
    //
    // If the AvailableInlineSize changes we need to run the line breaker again
    // with the calculated line_block_size. This is *safe* as the line breaker
    // won't produce a line which has a larger block-size, (as it can only
    // decrease or stay the same size).
    //
    // We skip attempting to fit empty lines into the shape area, as they
    // should only contain floats and/or abs-pos which shouldn't be affected by
    // this logic.
    if (opportunity.HasShapeExclusions() && !line_info.IsEmptyLine())
        [[unlikely]] {
      LineLayoutOpportunity line_opportunity_with_height =
          opportunity.ComputeLineLayoutOpportunity(
              constraint_space, total_block_size, block_delta);

      if (line_opportunity_with_height.AvailableInlineSize() !=
          line_opportunity.AvailableInlineSize()) {
        line_block_size = total_block_size;
        continue;
      }
    }

    // Check if the line will fit in the current opportunity.
    if (total_block_size + block_delta > opportunity.rect.BlockSize()) {
      block_delta = LayoutUnit();
      line_block_size = LayoutUnit();
      ++opportunities_it;
      continue;
    }

    // Success!
    container_builder_.SetBreakToken(line_info.GetBreakToken());
    container_builder_.SetBaseDirection(line_info.BaseDirection());

    // Propagate any break tokens for floats that we fragmented before or inside
    // to the block container in 3 steps: 1) in `PositionLeadingFloats`, 2) from
    // `LineInfo` here, 3) then `CreateLine` may propagate more.
    for (const InlineBreakToken* parallel_token :
         line_info.ParallelFlowBreakTokens()) {
      DCHECK(parallel_token->IsInParallelBlockFlow());
      context_->PropagateParallelFlowBreakToken(parallel_token);
    }
    if (std::optional<LayoutUnit> minimum_space_shortage =
            line_info.MinimumSpaceShortage()) {
      container_builder_.PropagateSpaceShortage(minimum_space_shortage);
    }

    if (line_info.IsEmptyLine()) {
      DCHECK_EQ(container_builder_.BlockSize(), LayoutUnit());
      DCHECK(!container_builder_.BfcBlockOffset());

      container_builder_.SetIsSelfCollapsing();
      container_builder_.SetIsEmptyLineBox();

      // Finally respect the forced BFC block-offset if present.
      if (auto forced_bfc_block_offset =
              constraint_space.ForcedBfcBlockOffset()) {
        container_builder_.SetBfcBlockOffset(*forced_bfc_block_offset);
        container_builder_.SetLineBoxBfcBlockOffset(*forced_bfc_block_offset);
      }
    } else {
      if (!AddAnyClearanceAfterLine(line_info)) {
        return container_builder_.Abort(LayoutResult::kOutOfFragmentainerSpace);
      }
      container_builder_.SetBlockSize(container_builder_.LineHeight());

      // Margins should only collapse across "certain zero-height line boxes".
      // https://drafts.csswg.org/css2/box.html#collapsing-margins
      if (!line_info.IsBlockInInline()) {
        end_margin_strut_ = MarginStrut();

        if (lines_until_clamp_) {
          if (constraint_space.GetLineClampData().state ==
              LineClampData::kClampByLines) {
            *lines_until_clamp_ = *lines_until_clamp_ - 1;
          } else {
            DCHECK_EQ(constraint_space.GetLineClampData().state,
                      LineClampData::kMeasureLinesUntilBfcOffset);
            *lines_until_clamp_ = *lines_until_clamp_ + 1;
          }
        }
      }

      // As we aren't an empty inline we should have correctly placed all
      // our adjoining objects, and shouldn't propagate this information
      // to siblings.
      container_builder_.ResetAdjoiningObjectTypes();
    }
    break;
  }

  CHECK(is_line_created);
  container_builder_.SetEndMarginStrut(end_margin_strut_);
  if (lines_until_clamp_) {
    container_builder_.SetLinesUntilClamp(lines_until_clamp_);
  }

  DCHECK(items_builder);
  container_builder_.PropagateChildrenData(*line_container);
  const LayoutResult* layout_result = container_builder_.ToLineBoxFragment();
  items_builder->AssociateLogicalLineContainer(
      line_container, layout_result->GetPhysicalFragment());
  line_break_strategy.DidCreateLine(is_end_paragraph);
  return layout_result;
}

// This positions any "leading" floats within the given exclusion space.
// If we are also an empty inline, it will add any out-of-flow descendants.
void InlineLayoutAlgorithm::PositionLeadingFloats(
    ExclusionSpace& exclusion_space,
    LeadingFloats& leading_floats) {
  if (GetBreakToken() && GetBreakToken()->IsInParallelBlockFlow()) {
    // Bail, and let the line breaker deal with any kind of parallel flow.
    return;
  }

  const HeapVector<InlineItem>& items =
      Node().ItemsData(/* is_first_line */ false).items;

  unsigned index = GetBreakToken() ? GetBreakToken()->StartItemIndex() : 0;
  HeapVector<PositionedFloat>& positioned_floats = leading_floats.floats;
  for (; index < items.size(); ++index) {
    const InlineItem& item = items[index];

    // Abort if we've found something non-empty.
    if (!item.IsEmptyItem())
      break;

    if (item.Type() != InlineItem::kFloating) {
      continue;
    }

    container_builder_.AddAdjoiningObjectTypes(
        item.GetLayoutObject()->StyleRef().Floating(
            GetConstraintSpace().Direction()) == EFloat::kLeft
            ? kAdjoiningFloatLeft
            : kAdjoiningFloatRight);

    // Place any floats at the "expected" BFC block-offset, this may be an
    // optimistic guess.
    const LayoutUnit origin_bfc_block_offset =
        GetConstraintSpace().ExpectedBfcBlockOffset();
    PositionedFloat positioned_float = PositionFloat(
        origin_bfc_block_offset, item.GetLayoutObject(), &exclusion_space);

    if (GetConstraintSpace().HasBlockFragmentation()) {
      // Propagate any breaks before or inside floats to the block container.
      if (const auto* float_break_token = positioned_float.BreakToken()) {
        const auto* parallel_token =
            InlineBreakToken::CreateForParallelBlockFlow(
                node_, {index, item.StartOffset()}, *float_break_token);
        context_->PropagateParallelFlowBreakToken(parallel_token);
      }
    }

    positioned_floats.push_back(positioned_float);
  }

  leading_floats.handled_index = index;
}

PositionedFloat InlineLayoutAlgorithm::PositionFloat(
    LayoutUnit origin_bfc_block_offset,
    LayoutObject* floating_object,
    ExclusionSpace* exclusion_space) {
  const auto& space = GetConstraintSpace();
  BfcOffset origin_bfc_offset = {space.GetBfcOffset().line_offset,
                                 origin_bfc_block_offset};

  // The BFC offset passed to `ShouldHideForPaint` should be the bottom offset
  // of the line, which we don't know at this point. However, since block layout
  // will relayout to fix the clamp BFC offset to the bottom of the last line
  // before clamp, we now that if the line's BFC offset is equal or greater than
  // the clamp BFC offset in the final relayout, the line will be hidden.
  bool is_hidden_for_paint =
      GetConstraintSpace().GetLineClampData().ShouldHideForPaint();
  UnpositionedFloat unpositioned_float(
      BlockNode(To<LayoutBox>(floating_object)),
      /* break_token */ nullptr, space.AvailableSize(),
      space.PercentageResolutionSize(),
      space.ReplacedPercentageResolutionSize(), origin_bfc_offset, space,
      Style(), space.FragmentainerBlockSize(), space.FragmentainerOffset(),
      is_hidden_for_paint);

  PositionedFloat positioned_float =
      ::blink::PositionFloat(&unpositioned_float, exclusion_space);

  if (positioned_float.minimum_space_shortage) {
    container_builder_.PropagateSpaceShortage(
        positioned_float.minimum_space_shortage);
  }

  return positioned_float;
}

}  // namespace blink

"""


```