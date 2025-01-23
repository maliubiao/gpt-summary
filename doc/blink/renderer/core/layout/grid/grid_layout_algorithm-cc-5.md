Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The file name `grid_layout_algorithm.cc` and the surrounding context (Chromium's Blink rendering engine, in the `layout/grid` directory) immediately tell me this code is responsible for the core logic of laying out grid items within a CSS grid container.

2. **Break Down into Logical Sections:** I scan the code and notice distinct functions and blocks of code that seem to handle different aspects of grid layout. Key functions like `LayoutGridItems`, `PlaceOutOfFlowItems`, and helper functions for calculating offsets and sizes jump out.

3. **Analyze Key Functions:**

   * **`LayoutGridItems`:** This is clearly the central function for positioning in-flow grid items. I note its parameters: `layout_data`, `sizing_tree`, `intrinsic_block_size`, `offset_in_stitched_container`, `fragmentainer_space`, and `container_builder_`. These tell me it's involved in:
      * Using pre-calculated grid track information (`layout_data`).
      * Possibly interacting with a sizing tree (though this specific snippet doesn't heavily use it).
      * Handling block fragmentation (`fragmentainer_space`).
      * Building the final layout structure (`container_builder_`).

   * **`PlaceItems` (within `LayoutGridItems`):** This nested lambda function iterates through grid items and performs the actual placement. I see calculations for `grid_area`, handling of break tokens for fragmentation, and calls to `grid_item.node.Layout()` which suggests the recursive layout of individual grid items. The logic for handling row expansion and breakpoints is also important.

   * **`PlaceOutOfFlowItems`:** This function specifically handles absolutely or fixed positioned grid items. I note how it determines the containing block and calculates the offsets based on grid lines.

   * **Helper Functions (e.g., `ComputeTrackSizesInRange`, `TrackStartOffset`, `TrackEndOffset`, `ComputeOutOfFlowOffsetAndSize`):** These functions are essential for translating grid line definitions (numbers, spans) into concrete pixel offsets. They deal with repeating tracks and gutters.

4. **Identify Relationships to Web Technologies:**

   * **CSS Grid Layout:** The entire file is about implementing CSS Grid. Key CSS properties like `grid-template-rows`, `grid-template-columns`, `grid-row-start`, `grid-column-start`, `grid-area`, `justify-self`, `align-self`, and fragmentation properties (`break-before`, `break-after`, `break-inside`) are directly relevant.

   * **HTML:** Grid items are typically HTML elements. The code interacts with `LayoutBox` and `Element` objects, confirming this connection.

   * **JavaScript:**  While this C++ code doesn't directly *execute* JavaScript, the layout it produces directly affects how a web page looks and behaves, which JavaScript can then interact with (e.g., manipulating element styles, getting element positions).

5. **Look for Logic and Assumptions:**

   * **Fragmentation:** The code heavily deals with fragmentation, evident in the `fragmentainer_space` parameter and the handling of break tokens. This suggests that the grid can be split across multiple pages or columns.
   * **Stitching:** The `offset_in_stitched_container` suggests a concept of a continuous block of content being fragmented.
   * **Subgrids:** The handling of `subgrid_layout_subtree` indicates support for nested grids.
   * **Out-of-flow Items:**  The specific handling of absolutely and fixed positioned items shows awareness of how these interact with the grid layout.

6. **Identify Potential User/Programming Errors:**  Based on the code, I can infer common mistakes:

   * **Incorrect Grid Line Numbers/Spans:** Specifying grid lines that don't exist or create overlaps.
   * **Mixing Absolute/Fixed Positioning with Grid Items:** Understanding how these interact with the grid's flow.
   * **Fragmentation Issues:**  Not accounting for how content will break across fragments, leading to unexpected layout.
   * **Misunderstanding Implicit Grid Creation:**  The code implicitly creates grid tracks if items are placed outside explicitly defined tracks.

7. **Synthesize and Summarize:** Finally, I combine my observations to produce a clear summary of the file's functionality, its relationship to web technologies, its underlying logic, and potential error scenarios. I also try to organize the information logically.

8. **Address the "Part 6 of 6" Instruction:** I explicitly state that this part focuses on the core layout algorithm and the placement of both in-flow and out-of-flow items, as evidenced by the functions and logic within the provided snippet. I note the handling of fragmentation as a key aspect.
这是一个 Chromium Blink 引擎中 `blink/renderer/core/layout/grid/grid_layout_algorithm.cc` 文件的代码片段，它是网格布局算法的核心部分。根据提供的代码，我们可以归纳出以下功能：

**核心功能：网格项目布局（Grid Item Placement）**

这段代码的主要职责是计算和放置网格容器内的各个网格项目（grid items）。它处理了在可能存在分片（fragmentation）的情况下，如何将网格项目定位到正确的位置。

**具体功能分解：**

1. **处理网格项目的迭代:**  代码通过循环遍历网格项目 (`for (const auto& grid_item : grid_items)`) 并逐个进行布局。

2. **考虑分片 (Fragmentation):**  代码中多次出现了与分片相关的逻辑，例如 `fragmentainer_space`，`break_token`，`container_builder_` 等。这表明该算法需要处理网格容器在页面或多列布局中被分割成多个片段的情况。

3. **计算和调整项目偏移 (Offset Calculation and Adjustment):**  代码计算每个网格项目在其所在的行或列中的偏移量 (`item_placement_data.offset.inline_offset`, `child_block_offset`)。并且，为了适应分片和可能出现的溢出情况，会进行偏移量的调整 (`row_offset_adjustments`).

4. **创建约束空间 (Constraint Space):**  `CreateConstraintSpaceForLayout` 函数用于为每个网格项目创建一个布局约束空间，这可能涉及到考虑网格项目是否是子网格 (subgrid)。

5. **检查项目是否应该放在当前片段 (Fragment Check):** 代码会检查计算出的网格区域 (`grid_area`) 是否位于当前的片段容器内。如果项目应该放在后续的片段中，则会跳过当前的处理。

6. **执行子节点的布局 (Layout of Child Nodes):**  调用 `grid_item.node.Layout(space, break_token)` 来实际布局网格项目的内容。

7. **累积基线 (Baseline Accumulation):**  `baseline_accumulator.Accumulate` 用于处理网格项目的基线对齐。

8. **处理行分隔和断点 (Row Separation and Breakpoints):** 代码检查行是否具有容器分隔，并根据 `break-before`, `break-after`, `break-inside` 等 CSS 属性来决定是否需要在当前行进行分片。

9. **处理行扩展 (Row Expansion):**  当网格项目由于分片需要扩展时，代码会调整行的大小 (`max_row_expansion`) 并重新运行布局过程。

10. **处理断点移动 (Breakpoint Shifting):**  如果需要在特定的行进行分片，代码会调整断点的位置，并将该行移动到下一个片段容器中。

11. **处理溢出 (Overflow):**  代码中提到由于单体内容导致的溢出情况，并尝试通过调整可用空间来补偿。

12. **处理流外项目 (Out-of-Flow Items):** `PlaceOutOfFlowItems` 函数专门处理绝对定位或固定定位的网格项目，计算它们的包含块和偏移量。

13. **设置阅读顺序元素 (Reading Flow Elements):** `SetReadingFlowElements` 函数根据 `reading-flow` CSS 属性来设置元素的阅读顺序。

14. **计算轨道尺寸和偏移 (Track Size and Offset Calculation):**  一些辅助函数如 `ComputeTrackSizesInRange`, `TrackStartOffset`, `TrackEndOffset` 用于计算网格轨道的大小和偏移量，这对于定位网格项目至关重要。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:** 该代码直接响应 CSS 网格布局的属性，例如 `grid-template-rows`，`grid-template-columns`，`grid-row-start`，`grid-column-start`，`grid-area`，以及分片相关的属性如 `break-before`，`break-after`，`break-inside`。代码中的逻辑是 CSS 网格布局规范在浏览器渲染引擎中的具体实现。
    * **示例:** CSS 中定义 `grid-row-start: 2; grid-column-start: 3;` 会影响 `item_placement_data` 中的行和列起始位置，从而指导 `LayoutGridItems` 函数将该项目放置在网格的第二行和第三列的交叉点。
    * **示例:** CSS 中设置 `break-before: page;` 在一个网格项目所在的行上，会导致 `ShiftBreakpointIntoNextFragmentainer` 函数将该行移动到下一个页面片段。

* **HTML:** 网格容器和网格项目都是 HTML 元素。这段代码处理的是 `LayoutBox` 对象，这些对象是与 HTML 元素对应的渲染对象。
    * **示例:** HTML 中 `<div>` 元素设置了 `display: grid;`，那么该 `<div>` 元素对应的 `LayoutBox` 将会使用 `GridLayoutAlgorithm` 进行布局。

* **JavaScript:** 虽然这段 C++ 代码本身不涉及 JavaScript 执行，但 JavaScript 可以通过 DOM API 改变元素的样式（包括网格布局属性），从而间接地影响这段代码的执行结果。此外，JavaScript 可以查询元素的布局信息，这些信息是由这段代码计算出来的。
    * **示例:** JavaScript 可以动态修改一个网格项目的 `grid-column-start` 属性，这将导致浏览器重新运行布局算法，包括执行 `LayoutGridItems` 函数来更新该项目的位置。

**逻辑推理的假设输入与输出：**

假设输入：

* 一个包含多个网格项目的网格容器的 `GridLayoutData`，包括每个项目的行和列的起始和结束位置、跨度等信息。
* 一个 `SizingTree`，包含网格轨道尺寸的计算结果。
* 当前片段容器的可用空间 `fragmentainer_space`。
* 一个指示是否需要强制分片的 `break_token`。

假设输出：

* `container_builder_` 中包含了每个网格项目在当前片段中的最终布局位置（偏移量）。
* 更新后的 `intrinsic_block_size`，反映了网格容器在当前片段中的高度。
* 更新后的 `offset_in_stitched_container`，指示了当前片段在整体内容中的偏移量。
* 可能设置了 `container_builder_` 的 `HasSubsequentChildren` 或 `HasForcedBreak` 标志，指示后续片段的处理方式。

**用户或编程常见的使用错误举例：**

1. **网格线编号错误:**  在 CSS 中指定不存在的网格线编号或负数编号可能导致布局混乱或项目无法正确放置。
    * **示例:** `grid-column-start: 99;` 如果网格只有 8 列，会导致项目放置到隐式创建的轨道上，位置可能不符合预期。

2. **项目重叠:**  不小心定义了重叠的网格区域，导致多个项目占据相同的空间。浏览器会根据源顺序或 `z-index` 来决定哪个项目显示在上层。
    * **示例:** 两个项目都设置了 `grid-area: 1 / 1 / 2 / 2;` 会导致它们重叠。

3. **对齐属性的误用:**  对网格容器或网格项目使用错误的对齐属性（如 `justify-items`, `align-items`, `justify-content`, `align-content`, `justify-self`, `align-self`）可能导致项目没有按照预期的方式对齐。

4. **分片属性的意外影响:**  不理解 `break-before`, `break-after`, `break-inside` 等属性对多列布局或分页的影响，可能导致页面在不希望的位置断开。

5. **绝对定位和网格布局的混淆:**  对网格项目使用绝对定位 (`position: absolute;`) 会使其脱离正常的网格布局流程，其定位是相对于其包含块，而不是网格线。这可能导致布局混乱，尤其是在期望项目仍然受到网格布局影响的情况下。

**总结 `GridLayoutAlgorithm::LayoutGridItems` 的功能 (第 6 部分归纳):**

作为第 6 部分，这段代码主要关注 `GridLayoutAlgorithm` 中 **布局网格项目** 的核心逻辑，特别是处理在存在 **分片** 情况下的项目放置。它迭代处理每个网格项目，计算其在片段中的偏移量，处理行分隔和断点，以及可能的行扩展。此外，它还涉及处理流外项目和设置阅读顺序元素。 这部分代码是网格布局算法的关键组成部分，确保了网格项目在各种布局场景下都能被正确渲染。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
has overflowed the fragmentainer (in a
        // previous fragment) due to monolithic content, the grid container has
        // been stretched to encompass it, but the other grid items (like this
        // one) have not (we still want the non-overflowed items to fragment
        // properly). The available space left in the row needs to be shrunk, in
        // order to compensate for this, or this item might overflow the grid
        // row.
        const auto* grid_data =
            To<GridBreakTokenData>(GetBreakToken()->TokenData());
        unavailable_block_size = grid_data->offset_in_stitched_container -
                                 (item_placement_data.offset.block_offset +
                                  break_token->ConsumedBlockSize());
      }

      GridLayoutSubtree subgrid_layout_subtree;
      if (grid_item.IsSubgrid()) {
        DCHECK(next_subgrid_subtree);
        subgrid_layout_subtree = next_subgrid_subtree;
        next_subgrid_subtree = next_subgrid_subtree.NextSibling();
      }

      LogicalRect grid_area;
      const auto space = CreateConstraintSpaceForLayout(
          grid_item, layout_data, std::move(subgrid_layout_subtree), &grid_area,
          unavailable_block_size,
          min_block_size_should_encompass_intrinsic_size, child_block_offset);

      // Make the grid area relative to this fragment.
      const auto item_row_set_index = grid_item.SetIndices(kForRows).begin;
      grid_area.offset.block_offset +=
          (*row_offset_adjustments)[item_row_set_index] -
          *offset_in_stitched_container;

      // Check to see if this child should be placed within this fragmentainer.
      // We base this calculation on the grid-area rather than the offset.
      // The row can either be:
      //  - Above, we've handled it already in a previous fragment.
      //  - Below, we'll handle it within a subsequent fragment.
      //
      // NOTE: Basing this calculation of the row position has the effect that
      // a child with a negative margin will be placed in the fragmentainer
      // with its row, but placed above the block-start edge of the
      // fragmentainer.
      if (fragmentainer_space != kIndefiniteSize &&
          grid_area.offset.block_offset >= fragmentainer_space) {
        if (constraint_space.IsInsideBalancedColumns() &&
            !constraint_space.IsInitialColumnBalancingPass()) {
          // Although we know that this item isn't going to fit here, we're
          // inside balanced multicol, so we need to figure out how much more
          // fragmentainer space we'd need to fit more content.
          DisableLayoutSideEffectsScope disable_side_effects;
          auto* result = grid_item.node.Layout(space, break_token);
          PropagateSpaceShortage(constraint_space, result,
                                 fragmentainer_block_offset,
                                 fragmentainer_block_size, &container_builder_);
        }
        has_subsequent_children = true;
        continue;
      }
      if (grid_area.offset.block_offset < LayoutUnit() && !break_token)
        continue;

      auto* result = grid_item.node.Layout(space, break_token);
      DCHECK_EQ(result->Status(), LayoutResult::kSuccess);
      result_and_offsets.emplace_back(
          result,
          LogicalOffset(item_placement_data.offset.inline_offset,
                        child_block_offset),
          item_placement_data.relative_offset);

      const LogicalBoxFragment fragment(
          container_writing_direction,
          To<PhysicalBoxFragment>(result->GetPhysicalFragment()));
      baseline_accumulator.Accumulate(grid_item, fragment, child_block_offset);

      // If the row has container separation we are able to push it into the
      // next fragmentainer. If it doesn't we, need to take the current
      // breakpoint (even if it is undesirable).
      const bool row_has_container_separation =
          grid_area.offset.block_offset > LayoutUnit();

      if (row_has_container_separation &&
          item_row_set_index < breakpoint_row_set_index) {
        const auto break_between = row_break_between[item_row_set_index];

        // The row may have a forced break, move it to the next fragmentainer.
        if (IsForcedBreakValue(constraint_space, break_between)) {
          container_builder_.SetHasForcedBreak();
          UpdateBreakpointRowSetIndex(item_row_set_index);
          continue;
        }

        container_builder_.SetPreviousBreakAfter(break_between);
        const BreakAppeal appeal_before = CalculateBreakAppealBefore(
            constraint_space, grid_item.node, *result, container_builder_,
            row_has_container_separation);

        // TODO(layout-dev): Explain the special usage of
        // MovePastBreakpoint(). No fragment builder passed?
        if (!::blink::MovePastBreakpoint(constraint_space, grid_item.node,
                                         *result, fragmentainer_block_offset,
                                         fragmentainer_block_size,
                                         appeal_before,
                                         /*builder=*/nullptr)) {
          UpdateBreakpointRowSetIndex(item_row_set_index);

          // We are choosing to add an early breakpoint at a row. Propagate our
          // space shortage to the column balancer.
          PropagateSpaceShortage(constraint_space, result,
                                 fragmentainer_block_offset,
                                 fragmentainer_block_size, &container_builder_);

          // We may have "break-before:avoid" or similar on this row. Instead
          // of just breaking on this row, search upwards for a row with a
          // better EBreakBetween.
          if (IsAvoidBreakValue(constraint_space, break_between)) {
            for (int index = item_row_set_index - 1; index >= 0; --index) {
              // Only consider rows within this fragmentainer.
              LayoutUnit offset = layout_data.Rows().GetSetOffset(index) +
                                  (*row_offset_adjustments)[index] -
                                  *offset_in_stitched_container;
              if (offset <= LayoutUnit())
                break;

              // Forced row breaks should have been already handled, accept any
              // row with an "auto" break-between.
              if (row_break_between[index] == EBreakBetween::kAuto) {
                UpdateBreakpointRowSetIndex(index);
                break;
              }
            }
          }
          continue;
        }
      }

      // We should only try to expand this grid's rows below if we have no grid
      // layout subtree, as a subgrid cannot alter its subgridded tracks.
      const bool is_standalone_grid = !constraint_space.GetGridLayoutSubtree();

      // This item may want to expand due to fragmentation. Record how much we
      // should grow the row by (if applicable).
      if (is_standalone_grid &&
          min_block_size_should_encompass_intrinsic_size &&
          item_row_set_index <= expansion_row_set_index &&
          IsExpansionMakingProgress(item_row_set_index) &&
          fragmentainer_space != kIndefiniteSize &&
          grid_area.BlockEndOffset() <= fragmentainer_space) {
        // Check if we've found a different row to expand.
        if (expansion_row_set_index != item_row_set_index) {
          expansion_row_set_index = item_row_set_index;
          max_row_expansion = LayoutUnit();
        }

        LayoutUnit item_expansion;
        if (result->GetPhysicalFragment().GetBreakToken()) {
          // This item may have a break, and will want to expand into the next
          // fragmentainer, (causing the row to expand into the next
          // fragmentainer). We can't use the size of the fragment, as we don't
          // know how large the subsequent fragments will be (and how much
          // they'll expand the row).
          //
          // Instead of using the size of the fragment, expand the row to the
          // rest of the fragmentainer, with an additional epsilon. This epsilon
          // will ensure that we continue layout for children in this row in
          // the next fragmentainer. Without it we'd drop those subsequent
          // fragments.
          item_expansion =
              (fragmentainer_space - grid_area.BlockEndOffset()).AddEpsilon();
        } else {
          item_expansion = fragment.BlockSize() - grid_area.BlockEndOffset();
        }
        max_row_expansion = std::max(max_row_expansion, item_expansion);
      }

      // Keep track of the tallest item, in case it overflows the fragmentainer
      // with monolithic content.
      max_item_block_end = std::max(max_item_block_end,
                                    child_block_offset + fragment.BlockSize());
    }
  };

  // Adjust by |delta| the pre-computed item-offset for all grid items with a
  // row begin index greater or equal than |row_index|.
  auto AdjustItemOffsets = [&](wtf_size_t row_index, LayoutUnit delta) {
    auto current_item = grid_items.begin();

    for (auto& item_placement_data : *grid_items_placement_data) {
      if (row_index <= (current_item++)->SetIndices(kForRows).begin)
        item_placement_data.offset.block_offset += delta;
    }
  };

  // Adjust our grid break-token data to accommodate the larger item in the row.
  // Returns true if this function adjusted the break-token data in any way.
  auto ExpandRow = [&]() -> bool {
    if (max_row_expansion == 0)
      return false;

    DCHECK_GT(max_row_expansion, 0);
    DCHECK(IsExpansionMakingProgress(expansion_row_set_index));

    *intrinsic_block_size += max_row_expansion;
    AdjustItemOffsets(expansion_row_set_index + 1, max_row_expansion);
    layout_data.Rows().AdjustSetOffsets(expansion_row_set_index + 1,
                                        max_row_expansion);

    previous_expansion_row_set_index = expansion_row_set_index;
    return true;
  };

  // Shifts the row where we wish to take a breakpoint (indicated by
  // |breakpoint_row_set_index|) into the next fragmentainer.
  // Returns true if this function adjusted the break-token data in any way.
  auto ShiftBreakpointIntoNextFragmentainer = [&]() -> bool {
    if (breakpoint_row_set_index == kNotFound)
      return false;

    LayoutUnit row_offset =
        layout_data.Rows().GetSetOffset(breakpoint_row_set_index) +
        (*row_offset_adjustments)[breakpoint_row_set_index];

    const LayoutUnit fragment_relative_row_offset =
        row_offset - *offset_in_stitched_container;

    // We may be within the initial column-balancing pass (where we have an
    // indefinite fragmentainer size). If we have a forced break, re-run
    // |PlaceItems()| assuming the breakpoint offset is the fragmentainer size.
    if (fragmentainer_space == kIndefiniteSize) {
      fragmentainer_space = fragment_relative_row_offset;
      return true;
    }

    const LayoutUnit row_offset_delta =
        fragmentainer_space - fragment_relative_row_offset;

    // An expansion may have occurred in |ExpandRow| which already pushed this
    // row into the next fragmentainer.
    if (row_offset_delta <= LayoutUnit())
      return false;

    row_offset += row_offset_delta;
    *intrinsic_block_size += row_offset_delta;
    AdjustItemOffsets(breakpoint_row_set_index, row_offset_delta);

    auto it = row_offset_adjustments->begin() + breakpoint_row_set_index;
    while (it != row_offset_adjustments->end())
      *(it++) += row_offset_delta;

    return true;
  };

  PlaceItems();

  // See if we need to expand any rows, and if so re-run |PlaceItems()|. We
  // track the previous row we expanded, so this loop should eventually break.
  while (ExpandRow())
    PlaceItems();

  // See if we need to take a row break-point, and if-so re-run |PlaceItems()|.
  // We only need to do this once.
  if (ShiftBreakpointIntoNextFragmentainer()) {
    PlaceItems();
  } else if (fragmentainer_space != kIndefiniteSize) {
    // Encompass any fragmentainer overflow (caused by monolithic content)
    // that hasn't been accounted for. We want this to contribute to the
    // grid container fragment size, and it is also needed to shift any
    // breakpoints all the way into the next fragmentainer.
    fragmentainer_space =
        std::max(fragmentainer_space,
                 max_item_block_end - cloned_block_start_decoration);
  }

  if (has_subsequent_children)
    container_builder_.SetHasSubsequentChildren();

  // Add all the results into the builder.
  for (auto& result_and_offset : result_and_offsets) {
    container_builder_.AddResult(
        *result_and_offset.result, result_and_offset.offset,
        /* margins */ std::nullopt, result_and_offset.relative_offset);
  }

  // Propagate the baselines.
  if (auto first_baseline = baseline_accumulator.FirstBaseline())
    container_builder_.SetFirstBaseline(*first_baseline);
  if (auto last_baseline = baseline_accumulator.LastBaseline())
    container_builder_.SetLastBaseline(*last_baseline);

  if (fragmentainer_space != kIndefiniteSize) {
    *offset_in_stitched_container += fragmentainer_space;
  }
}

void GridLayoutAlgorithm::PlaceOutOfFlowItems(
    const GridLayoutData& layout_data,
    const LayoutUnit block_size,
    HeapVector<Member<LayoutBox>>& oof_children) {
  DCHECK(!oof_children.empty());

  HeapVector<Member<LayoutBox>> oofs;
  std::swap(oofs, oof_children);

  bool should_process_block_end = true;
  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    should_process_block_end = !container_builder_.DidBreakSelf() &&
                               !container_builder_.ShouldBreakInside();
  }

  const auto& node = Node();
  const auto& container_style = Style();
  const auto& placement_data = node.CachedPlacementData();
  const bool is_absolute_container = node.IsAbsoluteContainer();
  const bool is_fixed_container = node.IsAbsoluteContainer();

  const LayoutUnit previous_consumed_block_size =
      GetBreakToken() ? GetBreakToken()->ConsumedBlockSize() : LayoutUnit();
  const LogicalSize total_fragment_size = {container_builder_.InlineSize(),
                                           block_size};
  const auto default_containing_block_size =
      ShrinkLogicalSize(total_fragment_size, BorderScrollbarPadding());

  for (LayoutBox* oof_child : oofs) {
    GridItemData out_of_flow_item(BlockNode(oof_child), container_style);
    DCHECK(out_of_flow_item.IsOutOfFlow());

    std::optional<LogicalRect> containing_block_rect;
    const auto position = out_of_flow_item.node.Style().GetPosition();

    // If the current grid is also the containing-block for the OOF-positioned
    // item, pick up the static-position from the grid-area.
    if ((is_absolute_container && position == EPosition::kAbsolute) ||
        (is_fixed_container && position == EPosition::kFixed)) {
      containing_block_rect.emplace(ComputeOutOfFlowItemContainingRect(
          placement_data, layout_data, container_style,
          container_builder_.Borders(), total_fragment_size,
          &out_of_flow_item));
    }

    auto child_offset = containing_block_rect
                            ? containing_block_rect->offset
                            : BorderScrollbarPadding().StartOffset();
    const auto containing_block_size = containing_block_rect
                                           ? containing_block_rect->size
                                           : default_containing_block_size;

    LogicalStaticPosition::InlineEdge inline_edge;
    LogicalStaticPosition::BlockEdge block_edge;

    AlignmentOffsetForOutOfFlow(out_of_flow_item.Alignment(kForColumns),
                                out_of_flow_item.Alignment(kForRows),
                                containing_block_size, &inline_edge,
                                &block_edge, &child_offset);

    // Make the child offset relative to our fragment.
    child_offset.block_offset -= previous_consumed_block_size;

    // We will attempt to add OOFs in the fragment in which their static
    // position belongs. However, the last fragment has the most up-to-date grid
    // geometry information (e.g. any expanded rows, etc), so for center aligned
    // items or items with a grid-area that is not in the first or last
    // fragment, we could end up with an incorrect static position.
    if (should_process_block_end ||
        child_offset.block_offset <= FragmentainerCapacityForChildren()) {
      container_builder_.AddOutOfFlowChildCandidate(
          out_of_flow_item.node, child_offset, inline_edge, block_edge);
    } else {
      oof_children.emplace_back(oof_child);
    }
  }
}

void GridLayoutAlgorithm::SetReadingFlowElements(
    const GridSizingTree& sizing_tree) {
  const auto& style = Style();
  const EReadingFlow reading_flow = style.ReadingFlow();
  if (reading_flow != EReadingFlow::kGridRows &&
      reading_flow != EReadingFlow::kGridColumns &&
      reading_flow != EReadingFlow::kGridOrder) {
    return;
  }
  const auto& grid_items = sizing_tree.TreeRootData().grid_items;
  HeapVector<Member<Element>> reading_flow_elements;
  reading_flow_elements.ReserveInitialCapacity(grid_items.Size());
  // Add grid item if it is a DOM element
  auto AddItemIfNeeded = [&](const GridItemData& grid_item) {
    if (Element* element = DynamicTo<Element>(grid_item.node.GetDOMNode())) {
      reading_flow_elements.push_back(element);
    }
  };

  if (reading_flow == EReadingFlow::kGridRows ||
      reading_flow == EReadingFlow::kGridColumns) {
    Vector<const GridItemData*, 16> reordered_grid_items;
    reordered_grid_items.ReserveInitialCapacity(grid_items.Size());
    for (const auto& grid_item : grid_items) {
      reordered_grid_items.emplace_back(&grid_item);
    }
    // We reorder grid items by their row/column indices.
    // If reading-flow is grid-rows, we should sort by row, then column.
    // If reading-flow is grid-columns, we should sort by column, then
    // row.
    GridTrackSizingDirection reading_direction_first = kForRows;
    GridTrackSizingDirection reading_direction_second = kForColumns;
    if (reading_flow == EReadingFlow::kGridColumns) {
      reading_direction_first = kForColumns;
      reading_direction_second = kForRows;
    }
    auto CompareGridItemsForReadingFlow =
        [reading_direction_first, reading_direction_second](const auto& lhs,
                                                            const auto& rhs) {
          if (lhs->SetIndices(reading_direction_first).begin ==
              rhs->SetIndices(reading_direction_first).begin) {
            return lhs->SetIndices(reading_direction_second).begin <
                   rhs->SetIndices(reading_direction_second).begin;
          }
          return lhs->SetIndices(reading_direction_first).begin <
                 rhs->SetIndices(reading_direction_first).begin;
        };
    std::stable_sort(reordered_grid_items.begin(), reordered_grid_items.end(),
                     CompareGridItemsForReadingFlow);
    for (const auto& grid_item : reordered_grid_items) {
      AddItemIfNeeded(*grid_item);
    }
  } else {
    for (const auto& grid_item : grid_items) {
      AddItemIfNeeded(grid_item);
    }
  }
  container_builder_.SetReadingFlowElements(std::move(reading_flow_elements));
}

namespace {

Vector<std::div_t> ComputeTrackSizesInRange(
    const GridLayoutTrackCollection& track_collection,
    const wtf_size_t range_begin_set_index,
    const wtf_size_t range_set_count) {
  Vector<std::div_t> track_sizes;
  track_sizes.ReserveInitialCapacity(range_set_count);

  const wtf_size_t ending_set_index = range_begin_set_index + range_set_count;
  for (wtf_size_t i = range_begin_set_index; i < ending_set_index; ++i) {
    // Set information is stored as offsets. To determine the size of a single
    // track in a givent set, first determine the total size the set takes up
    // by finding the difference between the offsets and subtracting the gutter
    // size for each track in the set.
    LayoutUnit set_size =
        track_collection.GetSetOffset(i + 1) - track_collection.GetSetOffset(i);
    const wtf_size_t set_track_count = track_collection.GetSetTrackCount(i);

    DCHECK_GE(set_size, 0);
    set_size = (set_size - track_collection.GutterSize() * set_track_count)
                   .ClampNegativeToZero();

    // Once we have determined the size of the set, we can find the size of a
    // given track by dividing the |set_size| by the |set_track_count|.
    DCHECK_GT(set_track_count, 0u);
    track_sizes.emplace_back(std::div(set_size.RawValue(), set_track_count));
  }
  return track_sizes;
}

// For out of flow items that are located in the middle of a range, computes
// the extra offset relative to the start of its containing range.
LayoutUnit ComputeTrackOffsetInRange(
    const GridLayoutTrackCollection& track_collection,
    const wtf_size_t range_begin_set_index,
    const wtf_size_t range_set_count,
    const wtf_size_t offset_in_range) {
  if (!range_set_count || !offset_in_range)
    return LayoutUnit();

  // To compute the index offset, we have to determine the size of the
  // tracks within the grid item's span.
  Vector<std::div_t> track_sizes = ComputeTrackSizesInRange(
      track_collection, range_begin_set_index, range_set_count);

  // Calculate how many sets there are from the start of the range to the
  // |offset_in_range|. This division can produce a remainder, which would
  // mean that not all of the sets are repeated the same amount of times from
  // the start to the |offset_in_range|.
  const wtf_size_t floor_set_track_count = offset_in_range / range_set_count;
  const wtf_size_t remaining_track_count = offset_in_range % range_set_count;

  // Iterate over the sets and add the sizes of the tracks to |index_offset|.
  LayoutUnit index_offset = track_collection.GutterSize() * offset_in_range;
  for (wtf_size_t i = 0; i < track_sizes.size(); ++i) {
    // If we have a remainder from the |floor_set_track_count|, we have to
    // consider it to get the correct offset.
    const wtf_size_t set_count =
        floor_set_track_count + ((remaining_track_count > i) ? 1 : 0);
    index_offset +=
        LayoutUnit::FromRawValue(std::min<int>(set_count, track_sizes[i].rem) +
                                 (set_count * track_sizes[i].quot));
  }
  return index_offset;
}

template <bool snap_to_end_of_track>
LayoutUnit TrackOffset(const GridLayoutTrackCollection& track_collection,
                       const wtf_size_t range_index,
                       const wtf_size_t offset_in_range) {
  const wtf_size_t range_begin_set_index =
      track_collection.RangeBeginSetIndex(range_index);
  const wtf_size_t range_track_count =
      track_collection.RangeTrackCount(range_index);
  const wtf_size_t range_set_count =
      track_collection.RangeSetCount(range_index);

  LayoutUnit track_offset;
  if (offset_in_range == range_track_count) {
    DCHECK(snap_to_end_of_track);
    track_offset =
        track_collection.GetSetOffset(range_begin_set_index + range_set_count);
  } else {
    DCHECK(offset_in_range || !snap_to_end_of_track);
    DCHECK_LT(offset_in_range, range_track_count);

    // If an out of flow item starts/ends in the middle of a range, compute and
    // add the extra offset to the start offset of the range.
    track_offset =
        track_collection.GetSetOffset(range_begin_set_index) +
        ComputeTrackOffsetInRange(track_collection, range_begin_set_index,
                                  range_set_count, offset_in_range);
  }

  // |track_offset| includes the gutter size at the end of the last track,
  // when we snap to the end of last track such gutter size should be removed.
  // However, only snap if this range is not collapsed or if it can snap to the
  // end of the last track in the previous range of the collection.
  if (snap_to_end_of_track && (range_set_count || range_index))
    track_offset -= track_collection.GutterSize();
  return track_offset;
}

LayoutUnit TrackStartOffset(const GridLayoutTrackCollection& track_collection,
                            const wtf_size_t range_index,
                            const wtf_size_t offset_in_range) {
  if (!track_collection.RangeCount()) {
    // If the start line of an out of flow item is not 'auto' in an empty and
    // undefined grid, start offset is the start border scrollbar padding.
    DCHECK_EQ(range_index, 0u);
    DCHECK_EQ(offset_in_range, 0u);
    return track_collection.GetSetOffset(0);
  }

  const wtf_size_t range_track_count =
      track_collection.RangeTrackCount(range_index);

  if (offset_in_range == range_track_count &&
      range_index == track_collection.RangeCount() - 1) {
    // The only case where we allow the offset to be equal to the number of
    // tracks in the range is for the last range in the collection, which should
    // match the end line of the implicit grid; snap to the track end instead.
    return TrackOffset</* snap_to_end_of_track */ true>(
        track_collection, range_index, offset_in_range);
  }

  DCHECK_LT(offset_in_range, range_track_count);
  return TrackOffset</* snap_to_end_of_track */ false>(
      track_collection, range_index, offset_in_range);
}

LayoutUnit TrackEndOffset(const GridLayoutTrackCollection& track_collection,
                          const wtf_size_t range_index,
                          const wtf_size_t offset_in_range) {
  if (!track_collection.RangeCount()) {
    // If the end line of an out of flow item is not 'auto' in an empty and
    // undefined grid, end offset is the start border scrollbar padding.
    DCHECK_EQ(range_index, 0u);
    DCHECK_EQ(offset_in_range, 0u);
    return track_collection.GetSetOffset(0);
  }

  if (!offset_in_range && !range_index) {
    // Only allow the offset to be 0 for the first range in the collection,
    // which is the start line of the implicit grid; don't snap to the end.
    return TrackOffset</* snap_to_end_of_track */ false>(
        track_collection, range_index, offset_in_range);
  }

  DCHECK_GT(offset_in_range, 0u);
  return TrackOffset</* snap_to_end_of_track */ true>(
      track_collection, range_index, offset_in_range);
}

void ComputeOutOfFlowOffsetAndSize(
    const GridItemData& out_of_flow_item,
    const GridLayoutTrackCollection& track_collection,
    const BoxStrut& borders,
    const LogicalSize& border_box_size,
    LayoutUnit* start_offset,
    LayoutUnit* size) {
  DCHECK(start_offset && size && out_of_flow_item.IsOutOfFlow());
  OutOfFlowItemPlacement item_placement;
  LayoutUnit end_offset;

  // The default padding box value for |size| is used for out of flow items in
  // which both the start line and end line are defined as 'auto'.
  if (track_collection.Direction() == kForColumns) {
    item_placement = out_of_flow_item.column_placement;
    *start_offset = borders.inline_start;
    end_offset = border_box_size.inline_size - borders.inline_end;
  } else {
    item_placement = out_of_flow_item.row_placement;
    *start_offset = borders.block_start;
    end_offset = border_box_size.block_size - borders.block_end;
  }

  // If the start line is defined, the size will be calculated by subtracting
  // the offset at |start_index|; otherwise, use the computed border start.
  if (item_placement.range_index.begin != kNotFound) {
    DCHECK_NE(item_placement.offset_in_range.begin, kNotFound);

    *start_offset =
        TrackStartOffset(track_collection, item_placement.range_index.begin,
                         item_placement.offset_in_range.begin);
  }

  // If the end line is defined, the offset (which can be the offset at the
  // start index or the start border) and the added grid gap after the spanned
  // tracks are subtracted from the offset at the end index.
  if (item_placement.range_index.end != kNotFound) {
    DCHECK_NE(item_placement.offset_in_range.end, kNotFound);

    end_offset =
        TrackEndOffset(track_collection, item_placement.range_index.end,
                       item_placement.offset_in_range.end);
  }

  // |start_offset| can be greater than |end_offset| if the used track sizes or
  // gutter size saturated the set offsets of the track collection.
  *size = (end_offset - *start_offset).ClampNegativeToZero();
}

}  // namespace

LayoutUnit GridLayoutAlgorithm::ComputeGridItemAvailableSize(
    const GridItemData& grid_item,
    const GridLayoutTrackCollection& track_collection,
    LayoutUnit* start_offset) const {
  DCHECK(!grid_item.IsOutOfFlow());
  DCHECK(!grid_item.is_subgridded_to_parent_grid);

  const auto& [begin_set_index, end_set_index] =
      grid_item.SetIndices(track_collection.Direction());

  if (start_offset) {
    *start_offset = track_collection.GetSetOffset(begin_set_index);
  }

  const auto available_size =
      track_collection.ComputeSetSpanSize(begin_set_index, end_set_index);
  return available_size.MightBeSaturated() ? LayoutUnit() : available_size;
}

// static
LogicalRect GridLayoutAlgorithm::ComputeOutOfFlowItemContainingRect(
    const GridPlacementData& placement_data,
    const GridLayoutData& layout_data,
    const ComputedStyle& grid_style,
    const BoxStrut& borders,
    const LogicalSize& border_box_size,
    GridItemData* out_of_flow_item) {
  DCHECK(out_of_flow_item && out_of_flow_item->IsOutOfFlow());

  out_of_flow_item->ComputeOutOfFlowItemPlacement(layout_data.Columns(),
                                                  placement_data, grid_style);
  out_of_flow_item->ComputeOutOfFlowItemPlacement(layout_data.Rows(),
                                                  placement_data, grid_style);

  LogicalRect containing_rect;

  ComputeOutOfFlowOffsetAndSize(
      *out_of_flow_item, layout_data.Columns(), borders, border_box_size,
      &containing_rect.offset.inline_offset, &containing_rect.size.inline_size);

  ComputeOutOfFlowOffsetAndSize(
      *out_of_flow_item, layout_data.Rows(), borders, border_box_size,
      &containing_rect.offset.block_offset, &containing_rect.size.block_size);

  return containing_rect;
}

}  // namespace blink

WTF_ALLOW_CLEAR_UNUSED_SLOTS_WITH_MEM_FUNCTIONS(blink::ResultAndOffsets)
```