Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `fragmentation_utils.cc`. I need to identify the key operations related to layout fragmentation within the Chromium Blink engine. Specifically, I should look for functions and logic that deal with:

1. **Determining break points:**  Where to split content across fragments.
2. **Handling different break types:** Forced breaks, soft breaks, and break avoidance.
3. **Managing fragmentainer size and overflow:** How much space is available in a fragment and what happens when content exceeds it.
4. **Dealing with various layout scenarios:** Columns, rows, and handling of margins and padding.
5. **Interaction with break tokens:**  Markers indicating where a break occurred.
6. **Error handling or common mistakes:**  Situations where the layout might go wrong.

I should also check for connections to HTML, CSS, and JavaScript features, providing examples if any are found. Logical inferences with input/output examples are also required.
```
功能归纳:

该代码片段主要负责处理布局过程中的分片逻辑，特别是针对块级元素的处理。它包含了一系列函数，用于判断是否需要在元素或其子元素前后进行分片（例如分页或分列），并管理分片后的状态和信息。

**主要功能点:**

1. **判断和执行分片时机:**
   - `FinishFragmentForBlock`:  决定一个块级元素的片段是否完成，以及是否需要在当前片段容器的末尾插入一个分片标记。
   - `FinishFragmentationForFragmentainer`:  处理片段容器完成时的分片状态，例如计算其使用的空间和是否需要为溢出内容预留空间。
   - `HasBreakOpportunityBeforeNextChild`:  判断在下一个子元素之前是否存在潜在的分片点。
   - `BreakBeforeChildIfNeeded`:  根据元素的 `break-before` 属性和其它条件，决定是否需要在子元素之前强制或建议分片。
   - `BreakBeforeChild`:  执行在子元素之前分片的操作，并更新相应的状态。
   - `MovePastBreakpoint`:  尝试跳过一个潜在的分片点，并评估这样做的影响。
   - `AttemptSoftBreak`:  尝试插入一个软分片点。

2. **处理分片相关的空间和溢出:**
   - 计算剩余空间 (`space_left`).
   - 处理单体溢出 (`MonolithicOverflow`).
   - 预留溢出空间 (`ReserveSpaceForMonolithicOverflow`).
   - 传播空间不足信息 (`PropagateSpaceShortage`).
   - 计算空间不足量 (`CalculateSpaceShortage`).
   - 更新最小空间不足量 (`UpdateMinimalSpaceShortage`).

3. **管理分片标记 (Break Token):**
   - 设置分片标记的状态，例如是否在块的末尾 (`SetIsAtBlockEnd`).
   - 设置分片标记消耗的块大小 (`SetConsumedBlockSize`).

4. **处理早期分片 (Early Break):**
   - `UpdateEarlyBreakAtBlockChild`:  记录在子元素内部或之前找到的更优的分片点。
   - `EnterEarlyBreakInChild`:  进入子元素的早期分片点。
   - `IsEarlyBreakTarget`:  判断是否到达了早期分片的目标。

5. **创建和管理约束空间 (Constraint Space):**
   - `CreateConstraintSpaceForFragmentainer`:  为新的片段容器创建约束空间。

**与 JavaScript, HTML, CSS 的关系：**

- **CSS 属性:** 代码直接对应 CSS 的分片相关属性，例如 `break-before`, `break-after`, `break-inside`。例如，`CalculateBreakBetweenValue` 函数会根据 CSS 的 `break-before` 和 `break-after` 属性来决定是否强制分片。
- **HTML 结构:** 代码处理的是基于 HTML 元素构建的布局树。分片决策是基于元素的类型和其在文档流中的位置。
- **JavaScript (间接):**  JavaScript 可以通过修改元素的样式（包括分片相关的 CSS 属性）来影响分片行为。虽然这段代码本身不是 JavaScript，但它是渲染引擎的一部分，负责解析和应用 JavaScript 可能修改的样式。

**举例说明:**

**假设输入与输出 (逻辑推理):**

假设一个 `<div>` 元素内部包含多个 `<p>` 元素，且其 CSS 样式设置了 `break-inside: avoid;`。

* **输入:** `FinishFragmentForBlock` 函数接收到该 `<div>` 元素的 `BoxFragmentBuilder`，其中子元素 `<p>` 还没有完全放入当前片段容器。
* **逻辑推理:** `builder->ShouldBreakInside()` 将返回 `false`，因为 CSS 设置了避免内部断开。如果剩余空间不足以容纳整个 `<div>` 的剩余内容，则会创建一个分片标记，指示需要在 `<div>` 元素之后进行分片。
* **输出:** `FinishFragmentForBlock` 可能返回 `BreakStatus::kContinue`，但会设置 `builder` 的状态，以便在父级元素处理时知道需要创建一个分片。

**用户或编程常见的使用错误:**

- **误用 `break-inside: avoid;`:** 如果一个元素的内容非常长，且设置了 `break-inside: avoid;`，可能会导致该元素溢出其父级片段容器，从而产生非预期的布局。
    ```html
    <div style="height: 200px; overflow: auto;">
      <p style="break-inside: avoid;">This is a very long paragraph that will not break within the div.</p>
    </div>
    ```
    在这个例子中，如果段落的长度超过 200px，它将超出 `div` 的高度，即使 `div` 设置了 `overflow: auto;` 也可能不会像期望的那样工作，因为分片逻辑会尝试避免在段落内部断开。
- **忘记考虑 margin 和 padding:** 在计算剩余空间时，如果没有正确考虑元素的 margin 和 padding，可能会导致分片位置不准确。例如，一个元素的底部 margin 可能导致即使内容本身可以放入，也会提前分片。

**功能归纳 (针对第 2 部分):**

这部分代码主要关注 **在一个块级元素完成布局并准备分片到下一个片段容器时，以及在决定是否在子元素之前进行分片时的逻辑处理**。它详细地描述了如何计算剩余空间，判断是否需要分片，并记录分片状态和相关信息，例如消耗的块大小和早期分片点。 核心目标是根据 CSS 分片属性和布局约束，精确地确定分片的位置和时机，并为后续的布局过程提供必要的信息。
```
Prompt: 
```
这是目录为blink/renderer/core/layout/fragmentation_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
t
    // fragmentainer as well. This only happens when printing monolithic
    // content.
    LayoutUnit remaining_overflow =
        previous_break_token->MonolithicOverflow() -
        FragmentainerCapacity(*builder, /*is_for_children=*/false);
    if (remaining_overflow > LayoutUnit()) {
      builder->ReserveSpaceForMonolithicOverflow(remaining_overflow);
    }
  }

  if (builder->ShouldBreakInside()) {
    // We need to break before or inside one of our children (or have already
    // done so). Even if we fit within the remaining space, and even if the
    // child involved in the break were to be in a parallel flow, we still need
    // to prepare a break token for this node, so that we can resume layout of
    // its broken or unstarted children in the next fragmentainer.
    //
    // If we're at the end of the node, we need to mark the outgoing break token
    // as such. This is a way for the parent algorithm to determine whether we
    // need to insert a break there, or whether we may continue with any sibling
    // content. If we are allowed to continue, while there's still child content
    // left to be laid out, said content ends up in a parallel flow.
    // https://www.w3.org/TR/css-break-3/#parallel-flows
    //
    // TODO(mstensho): The spec actually says that we enter a parallel flow once
    // we're past the block-end *content edge*, but here we're checking against
    // the *border edge* instead. Does it matter?
    if (is_past_end) {
      builder->SetIsAtBlockEnd();
      // We entered layout already at the end of the block (but with overflowing
      // children). So we should take up no more space on our own.
      DCHECK_EQ(final_block_size, LayoutUnit());
    } else if (desired_block_size <= space_left) {
      // We have room for the calculated block-size in the current
      // fragmentainer, but we need to figure out whether this node is going to
      // produce more non-zero block-size fragments or not.
      //
      // If the block-size is constrained / fixed (in which case
      // IsKnownToFitInFragmentainer() will return true now), we know that we're
      // at the end. If block-size is unconstrained (or at least allowed to grow
      // a bit more), we're only at the end if no in-flow content inside broke.
      if (!was_broken_by_child || builder->IsKnownToFitInFragmentainer()) {
        if (node.HasNonVisibleBlockOverflow() && builder->ShouldBreakInside()) {
          // We have reached the end of a fragmentable node that clips overflow
          // in the block direction. If something broke inside at this point, we
          // need to relayout without fragmentation, so that we don't generate
          // any additional fragments (apart from the one we're working on) from
          // this node. We don't want any zero-sized clipped fragments that
          // contribute to superfluous fragmentainers.
          return BreakStatus::kDisableFragmentation;
        }

        builder->SetIsAtBlockEnd();
      }
    }

    if (builder->IsAtBlockEnd()) {
      // This node is to be resumed in the next fragmentainer. Make sure that
      // consumed block-size includes the entire remainder of the fragmentainer.
      // The fragment will normally take up all that space, but not if we've
      // reached the end of the node (and we are breaking because of
      // overflow). We include the entire fragmentainer in consumed block-size
      // in order to write offsets correctly back to legacy layout.
      builder->SetConsumedBlockSize(previously_consumed_block_size +
                                    std::max(final_block_size, space_left));
    } else {
      // If we're not at the end, it means that block-end border and shadow
      // should be omitted, unless box decorations are to be cloned.
      if (!builder->ShouldCloneBoxEndDecorations()) {
        sides.block_end = false;
        builder->SetSidesToInclude(sides);
      }
    }

    return BreakStatus::kContinue;
  }

  if (desired_block_size > space_left) {
    // No child inside broke, but we're too tall to fit.
    if (!previously_consumed_block_size) {
      // This is the first fragment generated for the node. Avoid breaking
      // inside block-start border, scrollbar and padding, if possible. No valid
      // breakpoints there.
      const FragmentGeometry& geometry = builder->InitialFragmentGeometry();
      LayoutUnit block_start_unbreakable_space =
          geometry.border.block_start + geometry.scrollbar.block_start +
          geometry.padding.block_start;
      if (space_left < block_start_unbreakable_space)
        builder->ClampBreakAppeal(kBreakAppealLastResort);
    }
    if (space.BlockFragmentationType() == kFragmentColumn &&
        !space.IsInitialColumnBalancingPass())
      builder->PropagateSpaceShortage(desired_block_size - space_left);
    if (desired_block_size <= desired_intrinsic_block_size) {
      // We only want to break inside if there's a valid class C breakpoint [1].
      // That is, we need a non-zero gap between the last child (outer block-end
      // edge) and this container (inner block-end edge). We've just found that
      // not to be the case. If we have found a better early break, we should
      // break there. Otherwise mark the break as unappealing, as breaking here
      // means that we're going to break inside the block-end padding or border,
      // or right before them. No valid breakpoints there.
      //
      // [1] https://www.w3.org/TR/css-break-3/#possible-breaks
      if (builder->HasEarlyBreak())
        return BreakStatus::kNeedsEarlierBreak;
      builder->ClampBreakAppeal(kBreakAppealLastResort);
    }
    return BreakStatus::kContinue;
  }

  // The end of the block fits in the current fragmentainer.
  builder->SetIsAtBlockEnd();
  return BreakStatus::kContinue;
}

BreakStatus FinishFragmentationForFragmentainer(BoxFragmentBuilder* builder) {
  const ConstraintSpace& space = builder->GetConstraintSpace();
  DCHECK(builder->IsFragmentainerBoxType());
  const BlockBreakToken* previous_break_token = builder->PreviousBreakToken();
  LayoutUnit consumed_block_size =
      previous_break_token ? previous_break_token->ConsumedBlockSize()
                           : LayoutUnit();
  if (space.HasKnownFragmentainerBlockSize()) {
    // Just copy the block-size from the constraint space. Calculating the
    // size the regular way would cause some problems with overflow. For one,
    // we don't want to produce a break token if there's no child content that
    // requires it. When we lay out, we use FragmentainerCapacity(), so this
    // is what we need to add to consumed block-size for the next break
    // token. The fragment block-size itself will be based directly on the
    // fragmentainer size from the constraint space, though.
    LayoutUnit block_size = space.FragmentainerBlockSize();
    LayoutUnit fragmentainer_capacity =
        FragmentainerCapacity(*builder, /*is_for_children=*/false);
    builder->SetFragmentBlockSize(block_size);
    consumed_block_size += fragmentainer_capacity;
    builder->SetConsumedBlockSize(consumed_block_size);

    // We clamp the fragmentainer block size from 0 to 1 for legacy write-back
    // if there is content that overflows the zero-height fragmentainer.
    // Set the consumed block size adjustment for legacy if this results
    // in a different consumed block size than is used for NG layout.
    LayoutUnit consumed_block_size_for_legacy =
        previous_break_token
            ? previous_break_token->ConsumedBlockSizeForLegacy()
            : LayoutUnit();
    LayoutUnit legacy_fragmentainer_block_size =
        (builder->IntrinsicBlockSize() > LayoutUnit()) ? fragmentainer_capacity
                                                       : block_size;
    LayoutUnit consumed_block_size_legacy_adjustment =
        consumed_block_size_for_legacy + legacy_fragmentainer_block_size -
        consumed_block_size;
    builder->SetConsumedBlockSizeLegacyAdjustment(
        consumed_block_size_legacy_adjustment);

    if (previous_break_token && previous_break_token->MonolithicOverflow()) {
      // Add pages as long as there's monolithic overflow that requires it.
      LayoutUnit remaining_overflow =
          previous_break_token->MonolithicOverflow() -
          FragmentainerCapacity(*builder, /*is_for_children=*/false);
      if (remaining_overflow > LayoutUnit()) {
        builder->ReserveSpaceForMonolithicOverflow(remaining_overflow);
      }
    }
  } else {
    LayoutUnit fragments_total_block_size = builder->FragmentsTotalBlockSize();
    // Just pass the value through. This is a fragmentainer, and fragmentainers
    // don't have previously consumed block-size baked in, unlike any other
    // fragments.
    builder->SetFragmentBlockSize(fragments_total_block_size);
    builder->SetConsumedBlockSize(fragments_total_block_size +
                                  consumed_block_size);
  }
  if (builder->IsEmptySpannerParent() &&
      builder->HasOutOfFlowFragmentainerDescendants())
    builder->SetIsEmptySpannerParent(false);

  return BreakStatus::kContinue;
}

bool HasBreakOpportunityBeforeNextChild(
    const PhysicalFragment& child_fragment,
    const BreakToken* incoming_child_break_token) {
  // Once we have added a child, there'll be a valid class A/B breakpoint [1]
  // before consecutive siblings, which implies that we have container
  // separation, which means that we may break before such siblings. Exclude
  // children in parallel flows, since they shouldn't affect this flow.
  //
  // [1] https://www.w3.org/TR/css-break-3/#possible-breaks
  if (IsA<PhysicalBoxFragment>(&child_fragment)) {
    const auto* block_break_token =
        To<BlockBreakToken>(incoming_child_break_token);
    return !block_break_token || !block_break_token->IsAtBlockEnd();
  }

  // Only establish a valid break opportunity after a line box if it has
  // non-zero height. When there's a block inside an inline, a zero-height line
  // may be created before and after the block, but for the sake of
  // fragmentation, pretend that they're not there.
  DCHECK(child_fragment.IsLineBox());
  LogicalFragment fragment(child_fragment.Style().GetWritingDirection(),
                           child_fragment);
  return fragment.BlockSize() != LayoutUnit();
}

BreakStatus BreakBeforeChildIfNeeded(
    const ConstraintSpace& space,
    LayoutInputNode child,
    const LayoutResult& layout_result,
    LayoutUnit fragmentainer_block_offset,
    LayoutUnit fragmentainer_block_size,
    bool has_container_separation,
    BoxFragmentBuilder* builder,
    bool is_row_item,
    FlexColumnBreakInfo* flex_column_break_info) {
  DCHECK(space.HasBlockFragmentation());

  // Break-before and break-after are handled at the row level.
  if (has_container_separation && !is_row_item) {
    EBreakBetween break_between =
        CalculateBreakBetweenValue(child, layout_result, *builder);
    if (IsForcedBreakValue(space, break_between)) {
      BreakBeforeChild(space, child, &layout_result, fragmentainer_block_offset,
                       fragmentainer_block_size, kBreakAppealPerfect,
                       /*is_forced_break=*/true, builder);
      return BreakStatus::kBrokeBefore;
    }
  }

  BreakAppeal appeal_before = CalculateBreakAppealBefore(
      space, child, layout_result, *builder, has_container_separation);

  // Attempt to move past the break point, and if we can do that, also assess
  // the appeal of breaking there, even if we didn't.
  if (MovePastBreakpoint(space, child, layout_result,
                         fragmentainer_block_offset, fragmentainer_block_size,
                         appeal_before, builder, is_row_item,
                         flex_column_break_info)) {
    return BreakStatus::kContinue;
  }

  // Breaking inside the child isn't appealing, and we're out of space. Figure
  // out where to insert a soft break. It will either be before this child, or
  // before an earlier sibling, if there's a more appealing breakpoint there.
  if (!AttemptSoftBreak(
          space, child, &layout_result, fragmentainer_block_offset,
          fragmentainer_block_size, appeal_before, builder,
          /*block_size_override=*/std::nullopt, flex_column_break_info)) {
    return BreakStatus::kNeedsEarlierBreak;
  }

  return BreakStatus::kBrokeBefore;
}

void BreakBeforeChild(const ConstraintSpace& space,
                      LayoutInputNode child,
                      const LayoutResult* layout_result,
                      LayoutUnit fragmentainer_block_offset,
                      LayoutUnit fragmentainer_block_size,
                      std::optional<BreakAppeal> appeal,
                      bool is_forced_break,
                      BoxFragmentBuilder* builder,
                      std::optional<LayoutUnit> block_size_override) {
#if DCHECK_IS_ON()
  DCHECK(layout_result || block_size_override);
  if (layout_result && layout_result->Status() == LayoutResult::kSuccess) {
    // In order to successfully break before a node, this has to be its first
    // fragment.
    const auto& physical_fragment = layout_result->GetPhysicalFragment();
    DCHECK(!physical_fragment.IsBox() ||
           To<PhysicalBoxFragment>(physical_fragment).IsFirstForNode());
  }
#endif

  if (space.HasKnownFragmentainerBlockSize()) {
    PropagateSpaceShortage(space, layout_result, fragmentainer_block_offset,
                           fragmentainer_block_size, builder,
                           block_size_override);
  }

  if (layout_result && space.ShouldPropagateChildBreakValues() &&
      !is_forced_break)
    builder->PropagateChildBreakValues(*layout_result);

  // We'll drop the fragment (if any) on the floor and retry at the start of the
  // next fragmentainer.
  builder->AddBreakBeforeChild(child, appeal, is_forced_break);
}

void PropagateSpaceShortage(const ConstraintSpace& space,
                            const LayoutResult* layout_result,
                            LayoutUnit fragmentainer_block_offset,
                            LayoutUnit fragmentainer_block_size,
                            FragmentBuilder* builder,
                            std::optional<LayoutUnit> block_size_override) {
  // Only multicol cares about space shortage.
  if (space.BlockFragmentationType() != kFragmentColumn)
    return;

  LayoutUnit space_shortage =
      CalculateSpaceShortage(space, layout_result, fragmentainer_block_offset,
                             fragmentainer_block_size, block_size_override);

  // TODO(mstensho): Turn this into a DCHECK, when the engine is ready for
  // it. Space shortage should really be positive here, or we might ultimately
  // fail to stretch the columns (column balancing).
  if (space_shortage > LayoutUnit())
    builder->PropagateSpaceShortage(space_shortage);
}

LayoutUnit CalculateSpaceShortage(
    const ConstraintSpace& space,
    const LayoutResult* layout_result,
    LayoutUnit fragmentainer_block_offset,
    LayoutUnit fragmentainer_block_size,
    std::optional<LayoutUnit> block_size_override) {
  // Space shortage is only reported for soft breaks, and they can only exist if
  // we know the fragmentainer block-size.
  DCHECK(space.HasKnownFragmentainerBlockSize());
  DCHECK(layout_result || block_size_override);

  // Only multicol cares about space shortage.
  DCHECK_EQ(space.BlockFragmentationType(), kFragmentColumn);

  LayoutUnit space_shortage;
  if (block_size_override) {
    space_shortage = fragmentainer_block_offset + block_size_override.value() -
                     fragmentainer_block_size;
  } else if (!layout_result->MinimalSpaceShortage()) {
    // Calculate space shortage: Figure out how much more space would have been
    // sufficient to make the child fragment fit right here in the current
    // fragmentainer. If layout aborted, though, we can't calculate anything.
    if (layout_result->Status() != LayoutResult::kSuccess) {
      return kIndefiniteSize;
    }
    LogicalFragment fragment(space.GetWritingDirection(),
                             layout_result->GetPhysicalFragment());
    space_shortage = fragmentainer_block_offset + fragment.BlockSize() -
                     fragmentainer_block_size;
  } else {
    // However, if space shortage was reported inside the child, use that. If we
    // broke inside the child, we didn't complete layout, so calculating space
    // shortage for the child as a whole would be impossible and pointless.
    space_shortage = *layout_result->MinimalSpaceShortage();
  }
  return space_shortage;
}

void UpdateMinimalSpaceShortage(std::optional<LayoutUnit> new_space_shortage,
                                LayoutUnit* minimal_space_shortage) {
  DCHECK(minimal_space_shortage);
  if (!new_space_shortage || *new_space_shortage <= LayoutUnit())
    return;
  if (*minimal_space_shortage == kIndefiniteSize) {
    *minimal_space_shortage = *new_space_shortage;
  } else {
    *minimal_space_shortage =
        std::min(*minimal_space_shortage, *new_space_shortage);
  }
}

bool MovePastBreakpoint(const ConstraintSpace& space,
                        LayoutInputNode child,
                        const LayoutResult& layout_result,
                        LayoutUnit fragmentainer_block_offset,
                        LayoutUnit fragmentainer_block_size,
                        BreakAppeal appeal_before,
                        BoxFragmentBuilder* builder,
                        bool is_row_item,
                        FlexColumnBreakInfo* flex_column_break_info) {
  if (layout_result.Status() != LayoutResult::kSuccess) {
    // Layout aborted - no fragment was produced. There's nothing to move
    // past. We need to break before.
    DCHECK_EQ(layout_result.Status(), LayoutResult::kOutOfFragmentainerSpace);
    // The only case where this should happen is with BR clear=all.
    DCHECK(child.IsInline());
    return false;
  }

  if (child.IsBlock()) {
    const auto& box_fragment =
        To<PhysicalBoxFragment>(layout_result.GetPhysicalFragment());

    // If we're at a resumed fragment, don't break before it. Once we've found
    // room for the first fragment, we cannot skip fragmentainers afterwards. We
    // might be out of space at a subsequent fragment e.g. if all space is taken
    // up by a float that got pushed ahead from a previous fragmentainer, but we
    // still need to allow this fragment here. Inserting a break before on a
    // node that has already started producing fragments would result in
    // restarting layout from scratch once we find room for a fragment
    // again. Preventing breaking here should have no visual effect, since the
    // block-size of the fragment will typically be 0 anyway.
    if (!box_fragment.IsFirstForNode())
      return true;

    // If clearance forces the child to the next fragmentainer, we cannot move
    // past the breakpoint, but rather retry in the next fragmentainer.
    if (builder && builder->GetExclusionSpace().NeedsClearancePastFragmentainer(
                       child.Style().Clear(space.Direction()))) {
      return false;
    }
  }

  if (!space.HasKnownFragmentainerBlockSize() &&
      space.IsInitialColumnBalancingPass() && builder) {
    if (layout_result.GetPhysicalFragment().IsMonolithic() ||
        (child.IsBlock() &&
         IsAvoidBreakValue(space, child.Style().BreakInside()))) {
      // If this is the initial column balancing pass, attempt to make the
      // column block-size at least as large as the tallest piece of monolithic
      // content and/or block with break-inside:avoid.
      LayoutUnit block_size =
          BlockSizeForFragmentation(layout_result, space.GetWritingDirection());
      PropagateUnbreakableBlockSize(block_size, fragmentainer_block_offset,
                                    builder);
    }
  }

  bool move_past =
      MovePastBreakpoint(space, layout_result, fragmentainer_block_offset,
                         fragmentainer_block_size, appeal_before, builder,
                         is_row_item, flex_column_break_info);

  if (move_past && builder && child.IsBlock() && !is_row_item) {
    // We're tentatively not going to break before this child, but we'll check
    // the appeal of breaking there anyway. It may be the best breakpoint we'll
    // ever find. (Note that we only do this for block children, since, when it
    // comes to inline layout, we first need to lay out all the line boxes, so
    // that we know what do to in order to honor orphans and widows, if at all
    // possible. We also only do this for non-row items since items in a row
    // will be parallel to one another.)
    UpdateEarlyBreakAtBlockChild(space, To<BlockNode>(child), layout_result,
                                 appeal_before, builder,
                                 flex_column_break_info);
  }

  return move_past;
}

bool MovePastBreakpoint(const ConstraintSpace& space,
                        const LayoutResult& layout_result,
                        LayoutUnit fragmentainer_block_offset,
                        LayoutUnit fragmentainer_block_size,
                        BreakAppeal appeal_before,
                        BoxFragmentBuilder* builder,
                        bool is_row_item,
                        FlexColumnBreakInfo* flex_column_break_info) {
  DCHECK_EQ(layout_result.Status(), LayoutResult::kSuccess);

  if (!space.HasKnownFragmentainerBlockSize()) {
    // We only care about soft breaks if we have a fragmentainer block-size.
    // During column balancing this may be unknown.
    return true;
  }

  const auto& physical_fragment = layout_result.GetPhysicalFragment();
  LogicalFragment fragment(space.GetWritingDirection(), physical_fragment);
  const auto* break_token =
      DynamicTo<BlockBreakToken>(physical_fragment.GetBreakToken());

  LayoutUnit space_left = fragmentainer_block_size - fragmentainer_block_offset;

  // If we haven't used any space at all in the fragmentainer yet, we cannot
  // break before this child, or there'd be no progress. We'd risk creating an
  // infinite number of fragmentainers without putting any content into them. If
  // we have set a minimum break appeal (better than kBreakAppealLastResort),
  // though, we might have to allow breaking here.
  bool refuse_break_before = space_left >= fragmentainer_block_size &&
                             (!builder || !IsBreakableAtStartOfResumedContainer(
                                              space, layout_result, *builder));

  // If the child starts past the end of the fragmentainer (probably due to a
  // block-start margin), we must break before it.
  bool must_break_before = false;
  if (space_left < LayoutUnit()) {
    must_break_before = true;
  } else if (space_left == LayoutUnit()) {
    // If the child starts exactly at the end, we'll allow the child here if the
    // fragment contains the block-end of the child, or if it's a column
    // spanner. Otherwise we have to break before it. We don't want empty
    // fragments with nothing useful inside, if it's to be resumed in the next
    // fragmentainer.
    must_break_before = !layout_result.GetColumnSpannerPath() &&
                        IsBreakInside(break_token) &&
                        !break_token->IsAtBlockEnd();
  }
  if (must_break_before) {
    DCHECK(!refuse_break_before);
    return false;
  }

  LayoutUnit block_size =
      BlockSizeForFragmentation(layout_result, space.GetWritingDirection());
  BreakAppeal appeal_inside = CalculateBreakAppealInside(space, layout_result);

  // If breaking before is impossible, we have to move past.
  bool move_past = refuse_break_before;

  if (!move_past) {
    if (block_size <= space_left) {
      if (IsBreakInside(break_token) || appeal_inside < kBreakAppealPerfect) {
        // The block child broke inside, either in this fragmentation context,
        // or in an inner one. We now need to decide whether to keep that break,
        // or if it would be better to break before it. Allow breaking inside if
        // it has the same appeal or higher than breaking before or breaking
        // earlier.
        if (appeal_inside >= appeal_before) {
          if (flex_column_break_info) {
            if (!flex_column_break_info->early_break ||
                appeal_inside >=
                    flex_column_break_info->early_break->GetBreakAppeal()) {
              move_past = true;
            }
          } else if (!builder || !builder->HasEarlyBreak() ||
                     appeal_inside >=
                         builder->GetEarlyBreak().GetBreakAppeal()) {
            move_past = true;
          }
        }
      } else {
        move_past = true;
      }
    } else if (appeal_before == kBreakAppealLastResort && builder &&
               builder->RequiresContentBeforeBreaking()) {
      // The fragment doesn't fit, but we need to force it to stay here anyway.
      builder->SetIsBlockSizeForFragmentationClamped();
      move_past = true;
    }
  }

  if (move_past) {
    if (builder) {
      if (block_size > space_left) {
        // We're moving past the breakpoint even if the child doesn't fit. This
        // may happen with monolithic content at the beginning of the
        // fragmentainer. Report space shortage.
        PropagateSpaceShortage(space, &layout_result,
                               fragmentainer_block_offset,
                               fragmentainer_block_size, builder);
      }
    }
    return true;
  }

  // We don't want to break inside, so we should attempt to break before.
  return false;
}

void UpdateEarlyBreakAtBlockChild(const ConstraintSpace& space,
                                  BlockNode child,
                                  const LayoutResult& layout_result,
                                  BreakAppeal appeal_before,
                                  BoxFragmentBuilder* builder,
                                  FlexColumnBreakInfo* flex_column_break_info) {
  // We may need to create early-breaks even if we have broken inside the child,
  // in case it establishes a parallel flow, in which case a break inside won't
  // help honor any break avoidance requests that come after this child. But
  // breaking *before* the child might help.
  const auto* break_token =
      To<BlockBreakToken>(layout_result.GetPhysicalFragment().GetBreakToken());
  // See if there's a good breakpoint inside the child.
  BreakAppeal appeal_inside = kBreakAppealLastResort;
  if (const auto* breakpoint = layout_result.GetEarlyBreak()) {
    // If the child broke inside, it shouldn't have any early-break.
    DCHECK(!IsBreakInside(break_token));

    appeal_inside = CalculateBreakAppealInside(space, layout_result,
                                               breakpoint->GetBreakAppeal());
    if (flex_column_break_info) {
      if (!flex_column_break_info->early_break ||
          flex_column_break_info->early_break->GetBreakAppeal() <=
              breakpoint->GetBreakAppeal()) {
        // Found a good breakpoint inside the child. Add the child to the early
        // break chain for the current column.
        auto* parent_break =
            MakeGarbageCollected<EarlyBreak>(child, appeal_inside, breakpoint);
        flex_column_break_info->early_break = parent_break;
      }
    } else if (!builder->HasEarlyBreak() ||
               builder->GetEarlyBreak().GetBreakAppeal() <=
                   breakpoint->GetBreakAppeal()) {
      // Found a good breakpoint inside the child. Add the child to the early
      // break container chain, and store it.
      auto* parent_break =
          MakeGarbageCollected<EarlyBreak>(child, appeal_inside, breakpoint);
      builder->SetEarlyBreak(parent_break);
    }
  }

  // Breaking before isn't better if it's less appealing than what we already
  // have (obviously), and also not if it has the same appeal as the break
  // location inside the child that we just found (when the appeal is the same,
  // whatever takes us further wins).
  if (appeal_before <= appeal_inside)
    return;

  if (flex_column_break_info) {
    if (flex_column_break_info->early_break &&
        flex_column_break_info->early_break->GetBreakAppeal() > appeal_before) {
      return;
    }
    flex_column_break_info->early_break =
        MakeGarbageCollected<EarlyBreak>(child, appeal_before);
    return;
  }

  if (builder->HasEarlyBreak() &&
      builder->GetEarlyBreak().GetBreakAppeal() > appeal_before) {
    return;
  }

  builder->SetEarlyBreak(
      MakeGarbageCollected<EarlyBreak>(child, appeal_before));
}

bool AttemptSoftBreak(const ConstraintSpace& space,
                      LayoutInputNode child,
                      const LayoutResult* layout_result,
                      LayoutUnit fragmentainer_block_offset,
                      LayoutUnit fragmentainer_block_size,
                      BreakAppeal appeal_before,
                      BoxFragmentBuilder* builder,
                      std::optional<LayoutUnit> block_size_override,
                      FlexColumnBreakInfo* flex_column_break_info) {
  DCHECK(layout_result || block_size_override);
  // If there's a breakpoint with higher appeal among earlier siblings, we need
  // to abort and re-layout to that breakpoint.
  bool found_earlier_break = false;
  if (flex_column_break_info) {
    found_earlier_break =
        flex_column_break_info->early_break &&
        flex_column_break_info->early_break->GetBreakAppeal() > appeal_before;
  } else {
    found_earlier_break =
        builder->HasEarlyBreak() &&
        builder->GetEarlyBreak().GetBreakAppeal() > appeal_before;
  }
  if (found_earlier_break) {
    // Found a better place to break. Before aborting, calculate and report
    // space shortage from where we'd actually break.
    PropagateSpaceShortage(space, layout_result, fragmentainer_block_offset,
                           fragmentainer_block_size, builder,
                           block_size_override);
    return false;
  }

  // Break before the child. Note that there may be a better break further up
  // with higher appeal (but it's too early to tell), in which case this
  // breakpoint will be replaced.
  BreakBeforeChild(space, child, layout_result, fragmentainer_block_offset,
                   fragmentainer_block_size, appeal_before,
                   /* is_forced_break */ false, builder, block_size_override);
  return true;
}

const EarlyBreak* EnterEarlyBreakInChild(const BlockNode& child,
                                         const EarlyBreak& early_break) {
  if (early_break.Type() != EarlyBreak::kBlock ||
      early_break.GetBlockNode() != child) {
    return nullptr;
  }

  // If there's no break inside, we should already have broken before the child.
  DCHECK(early_break.BreakInside());
  return early_break.BreakInside();
}

bool IsEarlyBreakTarget(const EarlyBreak& early_break,
                        const BoxFragmentBuilder& builder,
                        const LayoutInputNode& child) {
  if (early_break.Type() == EarlyBreak::kLine) {
    DCHECK(child.IsInline() || child.IsFlexItem());
    return early_break.LineNumber() == builder.LineCount();
  }
  return early_break.IsBreakBefore() && early_break.GetBlockNode() == child;
}

ConstraintSpace CreateConstraintSpaceForFragmentainer(
    const ConstraintSpace& parent_space,
    FragmentationType fragmentation_type,
    LogicalSize fragmentainer_size,
    LogicalSize percentage_resolution_size,
    bool balance_columns,
    BreakAppeal min_break_appeal) {
  ConstraintSpaceBuilder space_builder(
      parent_space, parent_space.GetWritingDirection(), /* is_new_fc */ true);
  space_builder.SetAvailableSize(fragmentainer_size);
  space_builder.SetPercentageResolutionSize(percentage_resolution_size);
  space_builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  space_builder.SetFragmentationType(fragmentation_type);
  space_builder.SetShouldPropagateChildBreakValues();
  space_builder.SetFragmentainerBlockSize(fragmentainer_size.block_size);
  space_builder.SetIsAnonymous(true);
  if (fragmentation_type == kFragmentColumn) {
    space_builder.SetIsInColumnBfc();
  }
  if (balance_columns) {
    DCHECK_EQ(fragmentation_type, kFragmentColumn);
    space_builder.SetIsInsideBalancedColumns();
  }
  space_builder.SetMinBreakAppeal(min_break_appeal);
  space_builder.SetBaselineAlgorithmType(
      parent_space.GetBaselineAlgorithmType());

  return space_builder.ToConstraintSpace();
}

BoxFragmentBuilder CreateContainerBuilderForMulticol(
    const BlockNode& multicol,
    const ConstraintSpace& space,
    const FragmentGeometry& fragment_geometry) {
  const ComputedStyle* style = &multicol.Style();
  BoxFragmentBuilder multicol_container_builder(

"""


```