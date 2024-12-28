Response:
The user wants a summary of the functionality of the `grid_layout_algorithm.cc` file, focusing on its relationship with web technologies, logical inferences, and common user errors. This is the first part of a six-part analysis, so the response should focus on the code provided in this specific snippet.

**Plan:**

1. **Identify Core Functionality:**  Scan the code for key class names, function calls, and data structures to understand the primary purpose.
2. **Relate to Web Technologies:** Connect the identified functionalities to concepts in HTML, CSS, and JavaScript.
3. **Analyze Logical Inferences:**  Look for conditional statements and calculations that suggest logical reasoning within the code. Formulate hypothetical inputs and outputs.
4. **Identify Potential User Errors:**  Consider how developers might misuse the features implemented in this code.
5. **Summarize the First Part:**  Provide a concise overview of the functionalities present in the provided code snippet.
```
GridLayoutAlgorithm::GridLayoutAlgorithm(const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params) {
  DCHECK(params.space.IsNewFormattingContext());

  const auto& node = Node();
  const auto& constraint_space = GetConstraintSpace();

  // At various stages of the algorithm we need to know the grid available-size.
  // If it's initially indefinite, we need to know the min/max sizes as well.
  // Initialize all these to the same value.
  grid_available_size_ = grid_min_available_size_ = grid_max_available_size_ =
      ChildAvailableSize();

  // If our inline-size is indefinite, compute the min/max inline-sizes.
  if (grid_available_size_.inline_size == kIndefiniteSize) {
    const LayoutUnit border_scrollbar_padding =
        BorderScrollbarPadding().InlineSum();

    const MinMaxSizes sizes = ComputeMinMaxInlineSizes(
        constraint_space, node, container_builder_.BorderPadding(),
        /* auto_min_length */ nullptr, [](SizeType) -> MinMaxSizesResult {
          // If we've reached here we are inside the |ComputeMinMaxSizes| pass,
          // and also have something like "min-width: min-content". This is
          // cyclic. Just return indefinite.
          return {{kIndefiniteSize, kIndefiniteSize},
                  /* depends_on_block_constraints */ false};
        });

    grid_min_available_size_.inline_size =
        (sizes.min_size - border_scrollbar_padding).ClampNegativeToZero();
    grid_max_available_size_.inline_size =
        (sizes.max_size == LayoutUnit::Max())
            ? sizes.max_size
            : (sizes.max_size - border_scrollbar_padding).ClampNegativeToZero();
  }

  // And similar for the min/max block-sizes.
  if (grid_available_size_.block_size == kIndefiniteSize) {
    const LayoutUnit border_scrollbar_padding =
        BorderScrollbarPadding().BlockSum();
    const MinMaxSizes sizes = ComputeInitialMinMaxBlockSizes(
        constraint_space, node, container_builder_.BorderPadding());

    grid_min_available_size_.block_size =
        (sizes.min_size - border_scrollbar_padding).ClampNegativeToZero();
    grid_max_available_size_.block_size =
        (sizes.max_size == LayoutUnit::Max())
            ? sizes.max_size
            : (sizes.max_size - border_scrollbar_padding).ClampNegativeToZero();

    // If block-size containment applies compute the block-size ignoring
    // children (just based on the row definitions).
    if (node.ShouldApplyBlockSizeContainment()) {
      contain_intrinsic_block_size_ =
          ComputeIntrinsicBlockSizeIgnoringChildren();

      // Resolve the block-size, and set the available sizes.
      const LayoutUnit block_size = ComputeBlockSizeForFragment(
          constraint_space, node, BorderPadding(),
          *contain_intrinsic_block_size_, container_builder_.InlineSize());

      grid_available_size_.block_size = grid_min_available_size_.block_size =
          grid_max_available_size_.block_size =
              (block_size - border_scrollbar_padding).ClampNegativeToZero();
    }
  }
}
```

**功能归纳:**

这段代码是 `GridLayoutAlgorithm` 类的构造函数，负责初始化网格布局算法所需的一些关键尺寸信息。它的主要功能是：

1. **初始化可用空间尺寸:**  将网格的初始可用宽度和高度 (`grid_available_size_`) 以及最小和最大可用宽度和高度 (`grid_min_available_size_`, `grid_max_available_size_`) 设置为子元素的可用尺寸。
2. **处理无限宽度:** 如果网格的初始宽度是无限的 (`kIndefiniteSize`)，则会计算网格的最小和最大宽度。这个计算会考虑边框、滚动条的内外边距，并且可能会涉及一个用于处理循环依赖情况的回调函数。
3. **处理无限高度:** 类似地，如果网格的初始高度是无限的，它会计算网格的最小和最大高度，同样考虑边框和滚动条的内外边距。
4. **处理块尺寸包含 (Block-size containment):** 如果应用了块尺寸包含，构造函数会计算忽略子元素的固有块尺寸 (`contain_intrinsic_block_size_`)，然后基于此计算最终的块尺寸，并更新可用尺寸。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **CSS `display: grid;`:** 这个文件中的代码是 Chromium 渲染引擎处理 CSS `display: grid;` 属性的核心部分。当浏览器遇到一个设置了 `display: grid;` 的 HTML 元素时，就会使用 `GridLayoutAlgorithm` 来进行布局计算。
*   **CSS 网格属性 (grid-template-rows, grid-template-columns, 等):**  构造函数中计算最小和最大尺寸的过程会受到 CSS 网格属性的影响。例如，`grid-template-columns: min-content auto max-content;` 将直接影响最小和最大宽度的计算。
    *   **举例:**  假设有以下 CSS：
        ```css
        .container {
          display: grid;
          grid-template-columns: 100px auto;
        }
        ```
        如果 `.container` 的可用宽度是无限的，`GridLayoutAlgorithm` 会计算出最小宽度至少是 100px (第一个列的固定宽度)，而最大宽度则取决于内容和剩余空间。
*   **CSS `min-width`, `max-width`, `min-height`, `max-height`:**  这些 CSS 属性会影响 `ComputeMinMaxInlineSizes` 和 `ComputeInitialMinMaxBlockSizes` 的计算结果。
    *   **举例:**  如果一个网格容器设置了 `min-width: 300px;`，即使其内容只需要 200px，`grid_min_available_size_.inline_size` 也会至少是 300px 减去边框和内边距。
*   **CSS 块尺寸包含 (`contain: size;` 或 `contain: layout inline-size;`):**  `node.ShouldApplyBlockSizeContainment()` 的检查直接与 CSS 的 `contain` 属性相关。
    *   **举例:**
        ```css
        .container {
          display: grid;
          contain: size; /* 或 contain: layout inline-size; */
        }
        ```
        在这种情况下，构造函数会调用 `ComputeIntrinsicBlockSizeIgnoringChildren()` 来计算高度，而不考虑子元素的高度。
*   **JavaScript 操作样式:** JavaScript 可以动态地修改元素的 CSS 样式，包括网格相关的属性。这些修改会触发重新布局，并可能导致 `GridLayoutAlgorithm` 重新执行。
    *   **假设输入:**  一个 HTML 元素初始时没有设置宽度，通过 JavaScript 设置了 `element.style.width = '500px';`
    *   **输出:**  在下一次布局计算中，`grid_available_size_.inline_size` 将会是 500px（减去边框和内边距）。

**逻辑推理及假设输入与输出:**

*   **假设输入:** 网格容器的 `grid_available_size_.inline_size` 初始化为 `kIndefiniteSize`。容器的 `BorderScrollbarPadding().InlineSum()` 计算结果为 10px。 `ComputeMinMaxInlineSizes` 返回 `sizes.min_size = 200px` 和 `sizes.max_size = 500px`。
*   **输出:**  `grid_min_available_size_.inline_size` 将被计算为 `(200 - 10).ClampNegativeToZero()`，即 190px。`grid_max_available_size_.inline_size` 将被计算为 `(500 - 10).ClampNegativeToZero()`，即 490px。
*   **假设输入:** `node.ShouldApplyBlockSizeContainment()` 返回 `true`。`ComputeIntrinsicBlockSizeIgnoringChildren()` 返回 300px。容器的 `BorderPadding()` 的高度为 5px。 `container_builder_.InlineSize()` 为 400px。 `ComputeBlockSizeForFragment` 基于这些输入计算出的 `block_size` 为 320px。 容器的 `BorderScrollbarPadding().BlockSum()` 为 8px。
*   **输出:** `grid_available_size_.block_size`, `grid_min_available_size_.block_size`, 和 `grid_max_available_size_.block_size` 都将被设置为 `(320 - 8).ClampNegativeToZero()`，即 312px。

**用户或编程常见的使用错误:**

*   **循环依赖导致无限循环:**  如果 CSS 中存在循环依赖，例如 `min-width: min-content;` 并且内容的最小宽度又依赖于容器的宽度，这可能会导致布局引擎陷入无限循环。代码中的匿名 lambda 函数 (`[](SizeType) -> MinMaxSizesResult`) 就是为了处理这种情况，遇到循环依赖时直接返回无限尺寸。  用户错误可能在于过于复杂的、互相依赖的尺寸定义。
*   **未考虑边框和内边距:** 开发者在计算网格轨道大小时，可能会忘记考虑容器的边框和内边距，导致内容溢出或布局错乱。`GridLayoutAlgorithm` 中减去 `BorderScrollbarPadding()` 的操作正是为了避免这种情况。
*   **错误理解 `contain` 属性的影响:**  开发者可能错误地使用了 `contain: size;`，认为它只会影响尺寸计算，而忽略了它还会阻止子元素影响父元素的布局大小。这可能导致父元素的大小不符合预期。
*   **在 JavaScript 中过度依赖精确的像素值:**  当 JavaScript 代码依赖于布局计算出的精确像素值时，可能会因为浏览器实现细节或字体渲染差异导致跨浏览器或跨设备的不一致性。

**第一部分功能归纳:**

这段代码主要负责 `GridLayoutAlgorithm` 对象的初始化，其核心任务是确定网格容器的可用空间尺寸，特别是处理宽度和高度为无限的情况，并考虑边框、内边距以及 CSS 的 `contain` 属性。它是网格布局计算的起点，为后续的布局步骤准备必要的尺寸信息。

Prompt: 
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/grid/grid_break_token_data.h"
#include "third_party/blink/renderer/core/layout/grid/grid_item.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"

namespace blink {

GridLayoutAlgorithm::GridLayoutAlgorithm(const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params) {
  DCHECK(params.space.IsNewFormattingContext());

  const auto& node = Node();
  const auto& constraint_space = GetConstraintSpace();

  // At various stages of the algorithm we need to know the grid available-size.
  // If it's initially indefinite, we need to know the min/max sizes as well.
  // Initialize all these to the same value.
  grid_available_size_ = grid_min_available_size_ = grid_max_available_size_ =
      ChildAvailableSize();

  // If our inline-size is indefinite, compute the min/max inline-sizes.
  if (grid_available_size_.inline_size == kIndefiniteSize) {
    const LayoutUnit border_scrollbar_padding =
        BorderScrollbarPadding().InlineSum();

    const MinMaxSizes sizes = ComputeMinMaxInlineSizes(
        constraint_space, node, container_builder_.BorderPadding(),
        /* auto_min_length */ nullptr, [](SizeType) -> MinMaxSizesResult {
          // If we've reached here we are inside the |ComputeMinMaxSizes| pass,
          // and also have something like "min-width: min-content". This is
          // cyclic. Just return indefinite.
          return {{kIndefiniteSize, kIndefiniteSize},
                  /* depends_on_block_constraints */ false};
        });

    grid_min_available_size_.inline_size =
        (sizes.min_size - border_scrollbar_padding).ClampNegativeToZero();
    grid_max_available_size_.inline_size =
        (sizes.max_size == LayoutUnit::Max())
            ? sizes.max_size
            : (sizes.max_size - border_scrollbar_padding).ClampNegativeToZero();
  }

  // And similar for the min/max block-sizes.
  if (grid_available_size_.block_size == kIndefiniteSize) {
    const LayoutUnit border_scrollbar_padding =
        BorderScrollbarPadding().BlockSum();
    const MinMaxSizes sizes = ComputeInitialMinMaxBlockSizes(
        constraint_space, node, container_builder_.BorderPadding());

    grid_min_available_size_.block_size =
        (sizes.min_size - border_scrollbar_padding).ClampNegativeToZero();
    grid_max_available_size_.block_size =
        (sizes.max_size == LayoutUnit::Max())
            ? sizes.max_size
            : (sizes.max_size - border_scrollbar_padding).ClampNegativeToZero();

    // If block-size containment applies compute the block-size ignoring
    // children (just based on the row definitions).
    if (node.ShouldApplyBlockSizeContainment()) {
      contain_intrinsic_block_size_ =
          ComputeIntrinsicBlockSizeIgnoringChildren();

      // Resolve the block-size, and set the available sizes.
      const LayoutUnit block_size = ComputeBlockSizeForFragment(
          constraint_space, node, BorderPadding(),
          *contain_intrinsic_block_size_, container_builder_.InlineSize());

      grid_available_size_.block_size = grid_min_available_size_.block_size =
          grid_max_available_size_.block_size =
              (block_size - border_scrollbar_padding).ClampNegativeToZero();
    }
  }
}

namespace {

void CacheGridItemsProperties(const GridLayoutTrackCollection& track_collection,
                              GridItems* grid_items) {
  DCHECK(grid_items);

  GridItemDataPtrVector grid_items_spanning_multiple_ranges;
  const auto track_direction = track_collection.Direction();

  for (auto& grid_item : grid_items->IncludeSubgriddedItems()) {
    if (!grid_item.MustCachePlacementIndices(track_direction)) {
      continue;
    }

    const auto& range_indices = grid_item.RangeIndices(track_direction);
    auto& track_span_properties = (track_direction == kForColumns)
                                      ? grid_item.column_span_properties
                                      : grid_item.row_span_properties;

    grid_item.ComputeSetIndices(track_collection);
    track_span_properties.Reset();

    // If a grid item spans only one range, then we can just cache the track
    // span properties directly. On the contrary, if a grid item spans multiple
    // tracks, it is added to |grid_items_spanning_multiple_ranges| as we need
    // to do more work to cache its track span properties.
    //
    // TODO(layout-dev): Investigate applying this concept to spans > 1.
    if (range_indices.begin == range_indices.end) {
      track_span_properties =
          track_collection.RangeProperties(range_indices.begin);
    } else {
      grid_items_spanning_multiple_ranges.emplace_back(&grid_item);
    }
  }

  if (grid_items_spanning_multiple_ranges.empty())
    return;

  auto CompareGridItemsByStartLine =
      [track_direction](GridItemData* lhs, GridItemData* rhs) -> bool {
    return lhs->StartLine(track_direction) < rhs->StartLine(track_direction);
  };
  std::sort(grid_items_spanning_multiple_ranges.begin(),
            grid_items_spanning_multiple_ranges.end(),
            CompareGridItemsByStartLine);

  auto CacheGridItemsSpanningMultipleRangesProperty =
      [&](TrackSpanProperties::PropertyId property) {
        // At this point we have the remaining grid items sorted by start line
        // in the respective direction; this is important since we'll process
        // both, the ranges in the track collection and the grid items,
        // incrementally.
        wtf_size_t current_range_index = 0;
        const wtf_size_t range_count = track_collection.RangeCount();

        for (auto* grid_item : grid_items_spanning_multiple_ranges) {
          // We want to find the first range in the collection that:
          //   - Spans tracks located AFTER the start line of the current grid
          //   item; this can be done by checking that the last track number of
          //   the current range is NOT less than the current grid item's start
          //   line. Furthermore, since grid items are sorted by start line, if
          //   at any point a range is located BEFORE the current grid item's
          //   start line, the same range will also be located BEFORE any
          //   subsequent item's start line.
          //   - Contains a track that fulfills the specified property.
          while (current_range_index < range_count &&
                 (track_collection.RangeEndLine(current_range_index) <=
                      grid_item->StartLine(track_direction) ||
                  !track_collection.RangeProperties(current_range_index)
                       .HasProperty(property))) {
            ++current_range_index;
          }

          // Since we discarded every range in the track collection, any
          // following grid item cannot fulfill the property.
          if (current_range_index == range_count)
            break;

          // Notice that, from the way we build the ranges of a track collection
          // (see |GridRangeBuilder::EnsureTrackCoverage|), any given range
          // must either be completely contained or excluded from a grid item's
          // span. Thus, if the current range's last track is also located
          // BEFORE the item's end line, then this range, including a track that
          // fulfills the specified property, is completely contained within
          // this item's boundaries. Otherwise, this and every subsequent range
          // are excluded from the grid item's span, meaning that such item
          // cannot satisfy the property we are looking for.
          if (track_collection.RangeEndLine(current_range_index) <=
              grid_item->EndLine(track_direction)) {
            grid_item->SetTrackSpanProperty(property, track_direction);
          }
        }
      };

  CacheGridItemsSpanningMultipleRangesProperty(
      TrackSpanProperties::kHasFlexibleTrack);
  CacheGridItemsSpanningMultipleRangesProperty(
      TrackSpanProperties::kHasIntrinsicTrack);
  CacheGridItemsSpanningMultipleRangesProperty(
      TrackSpanProperties::kHasAutoMinimumTrack);
  CacheGridItemsSpanningMultipleRangesProperty(
      TrackSpanProperties::kHasFixedMinimumTrack);
  CacheGridItemsSpanningMultipleRangesProperty(
      TrackSpanProperties::kHasFixedMaximumTrack);
}

bool HasBlockSizeDependentGridItem(const GridItems& grid_items) {
  for (const auto& grid_item : grid_items.IncludeSubgriddedItems()) {
    if (grid_item.is_sizing_dependent_on_block_size)
      return true;
  }
  return false;
}

}  // namespace

const LayoutResult* GridLayoutAlgorithm::Layout() {
  const auto* result = LayoutInternal();
  if (result->Status() == LayoutResult::kDisableFragmentation) {
    DCHECK(GetConstraintSpace().HasBlockFragmentation());
    return RelayoutWithoutFragmentation<GridLayoutAlgorithm>();
  }
  return result;
}

const LayoutResult* GridLayoutAlgorithm::LayoutInternal() {
  PaintLayerScrollableArea::DelayScrollOffsetClampScope delay_clamp_scope;

  const auto& node = Node();
  LayoutUnit intrinsic_block_size;
  GridSizingTree grid_sizing_tree;
  HeapVector<Member<LayoutBox>> oof_children;

  if (IsBreakInside(GetBreakToken())) {
    // TODO(layout-dev): When we support variable inlinesize fragments we'll
    // need to re-run |ComputeGridGeometry| for the different inline size while
    // making sure that we don't recalculate the automatic repetitions (which
    // depend on the available size), as this might change the grid structure
    // significantly (e.g., pull a child up into the first row).
    const auto* grid_data =
        To<GridBreakTokenData>(GetBreakToken()->TokenData());
    grid_sizing_tree = grid_data->grid_sizing_tree.CopyForFragmentation();
    intrinsic_block_size = grid_data->intrinsic_block_size;

    if (Style().BoxDecorationBreak() == EBoxDecorationBreak::kClone &&
        !GetBreakToken()->IsAtBlockEnd()) {
      // In the cloning box decorations model, the intrinsic block-size of a
      // node effectively grows by the size of the box decorations each time it
      // fragments.
      intrinsic_block_size += BorderScrollbarPadding().BlockSum();
    }
  } else {
    grid_sizing_tree = node.ChildLayoutBlockedByDisplayLock()
                           ? BuildGridSizingTreeIgnoringChildren()
                           : BuildGridSizingTree(&oof_children);
    ComputeGridGeometry(grid_sizing_tree, &intrinsic_block_size);
  }

  Vector<EBreakBetween> row_break_between;
  LayoutUnit previous_offset_in_stitched_container;
  LayoutUnit offset_in_stitched_container;
  Vector<GridItemPlacementData> grid_items_placement_data;
  Vector<LayoutUnit> row_offset_adjustments;

  const auto& layout_data = grid_sizing_tree.TreeRootData().layout_data;

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    // Either retrieve all items offsets, or generate them using the
    // non-fragmented |PlaceGridItems| pass.
    if (IsBreakInside(GetBreakToken())) {
      const auto* grid_data =
          To<GridBreakTokenData>(GetBreakToken()->TokenData());

      previous_offset_in_stitched_container = offset_in_stitched_container =
          grid_data->offset_in_stitched_container;
      grid_items_placement_data = grid_data->grid_items_placement_data;
      row_offset_adjustments = grid_data->row_offset_adjustments;
      row_break_between = grid_data->row_break_between;
      oof_children = grid_data->oof_children;
    } else {
      row_offset_adjustments =
          Vector<LayoutUnit>(layout_data.Rows().GetSetCount() + 1);
      PlaceGridItems(grid_sizing_tree, &row_break_between,
                     &grid_items_placement_data);
    }

    PlaceGridItemsForFragmentation(
        grid_sizing_tree, row_break_between, &grid_items_placement_data,
        &row_offset_adjustments, &intrinsic_block_size,
        &offset_in_stitched_container);
  } else {
    PlaceGridItems(grid_sizing_tree, &row_break_between);
  }

  const auto& border_padding = BorderPadding();
  const auto& constraint_space = GetConstraintSpace();

  const auto block_size = ComputeBlockSizeForFragment(
      constraint_space, Node(), border_padding, intrinsic_block_size,
      container_builder_.InlineSize());

  // For scrollable overflow purposes grid is unique in that the "inflow-bounds"
  // are the size of the grid, and *not* where the inflow grid-items are placed.
  // Explicitly set the inflow-bounds to the grid size.
  if (node.IsScrollContainer()) {
    LogicalOffset offset = {layout_data.Columns().GetSetOffset(0),
                            layout_data.Rows().GetSetOffset(0)};

    LogicalSize size = {layout_data.Columns().ComputeSetSpanSize(),
                        layout_data.Rows().ComputeSetSpanSize()};

    container_builder_.SetInflowBounds(LogicalRect(offset, size));
  }
  container_builder_.SetMayHaveDescendantAboveBlockStart(false);

  // Grid is slightly different to other layout modes in that the contents of
  // the grid won't change if the initial block-size changes definiteness (for
  // example). We can safely mark ourselves as not having any children
  // dependent on the block constraints.
  container_builder_.SetHasDescendantThatDependsOnPercentageBlockSize(false);

  if (constraint_space.HasKnownFragmentainerBlockSize()) {
    // |FinishFragmentation| uses |BoxFragmentBuilder::IntrinsicBlockSize| to
    // determine the final size of this fragment.
    container_builder_.SetIntrinsicBlockSize(
        offset_in_stitched_container - previous_offset_in_stitched_container +
        BorderScrollbarPadding().block_end);
  } else {
    container_builder_.SetIntrinsicBlockSize(intrinsic_block_size);
  }
  container_builder_.SetFragmentsTotalBlockSize(block_size);

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    auto status = FinishFragmentation(&container_builder_);
    if (status == BreakStatus::kDisableFragmentation) {
      return container_builder_.Abort(LayoutResult::kDisableFragmentation);
    }
    DCHECK_EQ(status, BreakStatus::kContinue);
  } else {
#if DCHECK_IS_ON()
    // If we're not participating in a fragmentation context, no block
    // fragmentation related fields should have been set.
    container_builder_.CheckNoBlockFragmentation();
#endif
  }

  // Set our break-before/break-after.
  if (constraint_space.ShouldPropagateChildBreakValues()) {
    container_builder_.SetInitialBreakBefore(row_break_between.front());
    container_builder_.SetPreviousBreakAfter(row_break_between.back());
  }

  if (!oof_children.empty())
    PlaceOutOfFlowItems(layout_data, block_size, oof_children);

  // Copy grid layout data for use in computed style and devtools.
  container_builder_.TransferGridLayoutData(
      std::make_unique<GridLayoutData>(layout_data));

  SetReadingFlowElements(grid_sizing_tree);

  if (constraint_space.HasBlockFragmentation()) {
    container_builder_.SetBreakTokenData(
        MakeGarbageCollected<GridBreakTokenData>(
            container_builder_.GetBreakTokenData(), std::move(grid_sizing_tree),
            intrinsic_block_size, offset_in_stitched_container,
            grid_items_placement_data, row_offset_adjustments,
            row_break_between, oof_children));
  }

  container_builder_.HandleOofsAndSpecialDescendants();
  return container_builder_.ToBoxFragment();
}

MinMaxSizesResult GridLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  const auto& node = Node();
  const LayoutUnit override_intrinsic_inline_size =
      node.OverrideIntrinsicContentInlineSize();

  auto FixedMinMaxSizes = [&](LayoutUnit size) -> MinMaxSizesResult {
    size += BorderScrollbarPadding().InlineSum();
    return {{size, size}, /* depends_on_block_constraints */ false};
  };

  if (override_intrinsic_inline_size != kIndefiniteSize) {
    return FixedMinMaxSizes(override_intrinsic_inline_size);
  }

  if (const auto* layout_subtree =
          GetConstraintSpace().GetGridLayoutSubtree()) {
    return FixedMinMaxSizes(
        layout_subtree->LayoutData().Columns().ComputeSetSpanSize());
  }

  // If we have inline size containment ignore all children.
  auto grid_sizing_tree = node.ShouldApplyInlineSizeContainment()
                              ? BuildGridSizingTreeIgnoringChildren()
                              : BuildGridSizingTree();

  bool depends_on_block_constraints = false;
  auto& sizing_data = grid_sizing_tree.TreeRootData();

  auto ComputeTotalColumnSize =
      [&](SizingConstraint sizing_constraint) -> LayoutUnit {
    InitializeTrackSizes(grid_sizing_tree);

    bool needs_additional_pass = false;
    CompleteTrackSizingAlgorithm(grid_sizing_tree, kForColumns,
                                 sizing_constraint, &needs_additional_pass);

    if (needs_additional_pass ||
        HasBlockSizeDependentGridItem(sizing_data.grid_items)) {
      // If we need to calculate the row geometry, then we have a dependency on
      // our block constraints.
      depends_on_block_constraints = true;
      CompleteTrackSizingAlgorithm(grid_sizing_tree, kForRows,
                                   sizing_constraint, &needs_additional_pass);

      if (needs_additional_pass) {
        InitializeTrackSizes(grid_sizing_tree, kForColumns);
        CompleteTrackSizingAlgorithm(grid_sizing_tree, kForColumns,
                                     sizing_constraint);
      }
    }
    return sizing_data.layout_data.Columns().ComputeSetSpanSize();
  };

  MinMaxSizes sizes{ComputeTotalColumnSize(SizingConstraint::kMinContent),
                    ComputeTotalColumnSize(SizingConstraint::kMaxContent)};
  sizes += BorderScrollbarPadding().InlineSum();
  return {sizes, depends_on_block_constraints};
}

MinMaxSizes GridLayoutAlgorithm::ComputeSubgridMinMaxSizes(
    const GridSizingSubtree& sizing_subtree) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  return {ComputeSubgridIntrinsicSize(sizing_subtree, kForColumns,
                                      SizingConstraint::kMinContent),
          ComputeSubgridIntrinsicSize(sizing_subtree, kForColumns,
                                      SizingConstraint::kMaxContent)};
}

LayoutUnit GridLayoutAlgorithm::ComputeSubgridIntrinsicBlockSize(
    const GridSizingSubtree& sizing_subtree) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  return ComputeSubgridIntrinsicSize(sizing_subtree, kForRows,
                                     SizingConstraint::kMaxContent);
}

namespace {

GridArea SubgriddedAreaInParent(const SubgriddedItemData& opt_subgrid_data) {
  if (!opt_subgrid_data.IsSubgrid()) {
    return GridArea();
  }

  auto subgridded_area_in_parent = opt_subgrid_data->resolved_position;

  if (!opt_subgrid_data->has_subgridded_columns) {
    subgridded_area_in_parent.columns = GridSpan::IndefiniteGridSpan();
  }
  if (!opt_subgrid_data->has_subgridded_rows) {
    subgridded_area_in_parent.rows = GridSpan::IndefiniteGridSpan();
  }

  if (!opt_subgrid_data->is_parallel_with_root_grid) {
    std::swap(subgridded_area_in_parent.columns,
              subgridded_area_in_parent.rows);
  }
  return subgridded_area_in_parent;
}

FragmentGeometry CalculateInitialFragmentGeometryForSubgrid(
    const GridItemData& subgrid_data,
    const ConstraintSpace& space,
    const GridSizingSubtree& sizing_subtree = kNoGridSizingSubtree) {
  DCHECK(subgrid_data.IsSubgrid());

  const auto& node = To<GridNode>(subgrid_data.node);
  {
    const bool subgrid_has_standalone_columns =
        subgrid_data.is_parallel_with_root_grid
            ? !subgrid_data.has_subgridded_columns
            : !subgrid_data.has_subgridded_rows;

    // We won't be able to resolve the intrinsic sizes of a subgrid if its
    // tracks are subgridded, i.e., their sizes can't be resolved by the subgrid
    // itself, or if `sizing_subtree` is not provided, i.e., the grid sizing
    // tree it's not completed at this step of the sizing algorithm.
    if (subgrid_has_standalone_columns && sizing_subtree) {
      return CalculateInitialFragmentGeometry(
          space, node, /* break_token */ nullptr,
          [&](SizeType) -> MinMaxSizesResult {
            return node.ComputeSubgridMinMaxSizes(sizing_subtree, space);
          });
    }
  }

  bool needs_to_compute_min_max_sizes = false;

  const auto fragment_geometry = CalculateInitialFragmentGeometry(
      space, node, /* break_token */ nullptr,
      [&needs_to_compute_min_max_sizes](SizeType) -> MinMaxSizesResult {
        // We can't call `ComputeMinMaxSizes` for a subgrid with an incomplete
        // grid sizing tree, as its intrinsic size relies on its subtree. If we
        // end up in this function, we need to use an intrinsic fragment
        // geometry instead to avoid a cyclic dependency.
        needs_to_compute_min_max_sizes = true;
        return MinMaxSizesResult();
      });

  if (needs_to_compute_min_max_sizes) {
    return CalculateInitialFragmentGeometry(space, node,
                                            /* break_token */ nullptr,
                                            /* is_intrinsic */ true);
  }
  return fragment_geometry;
}

}  // namespace

wtf_size_t GridLayoutAlgorithm::BuildGridSizingSubtree(
    GridSizingTree* sizing_tree,
    HeapVector<Member<LayoutBox>>* opt_oof_children,
    const SubgriddedItemData& opt_subgrid_data,
    const GridLineResolver* opt_parent_line_resolver,
    bool must_invalidate_placement_cache,
    bool must_ignore_children) const {
  DCHECK(sizing_tree);

  const auto& node = Node();
  const auto& style = node.Style();
  const auto subgrid_area = SubgriddedAreaInParent(opt_subgrid_data);
  const auto writing_mode = GetConstraintSpace().GetWritingMode();

  auto& sizing_node = sizing_tree->CreateSizingData(
      opt_subgrid_data ? opt_subgrid_data->node : node);

  const wtf_size_t column_auto_repetitions =
      ComputeAutomaticRepetitions(subgrid_area.columns, kForColumns);
  const wtf_size_t row_auto_repetitions =
      ComputeAutomaticRepetitions(subgrid_area.rows, kForRows);

  // Initialize this grid's line resolver.
  const auto line_resolver =
      opt_parent_line_resolver
          ? GridLineResolver(style, *opt_parent_line_resolver, subgrid_area,
                             column_auto_repetitions, row_auto_repetitions)
          : GridLineResolver(style, column_auto_repetitions,
                             row_auto_repetitions);

  wtf_size_t column_start_offset = 0;
  wtf_size_t row_start_offset = 0;
  bool has_nested_subgrid = false;

  if (!must_ignore_children) {
    // Construct grid items that are not subgridded.
    sizing_node.grid_items =
        node.ConstructGridItems(line_resolver, &must_invalidate_placement_cache,
                                opt_oof_children, &has_nested_subgrid);

    column_start_offset = node.CachedPlacementData().column_start_offset;
    row_start_offset = node.CachedPlacementData().row_start_offset;
  }

  auto BuildSizingCollection = [&](GridTrackSizingDirection track_direction) {
    GridRangeBuilder range_builder(style, line_resolver, track_direction,
                                   (track_direction == kForColumns)
                                       ? column_start_offset
                                       : row_start_offset);

    bool must_create_baselines = false;
    for (auto& grid_item : sizing_node.grid_items.IncludeSubgriddedItems()) {
      if (grid_item.IsConsideredForSizing(track_direction)) {
        must_create_baselines |= grid_item.IsBaselineSpecified(track_direction);
      }

      if (grid_item.MustCachePlacementIndices(track_direction)) {
        auto& range_indices = grid_item.RangeIndices(track_direction);
        range_builder.EnsureTrackCoverage(grid_item.StartLine(track_direction),
                                          grid_item.SpanSize(track_direction),
                                          &range_indices.begin,
                                          &range_indices.end);
      }
    }

    sizing_node.layout_data.SetTrackCollection(
        std::make_unique<GridSizingTrackCollection>(
            range_builder.FinalizeRanges(), must_create_baselines,
            track_direction));
  };

  const bool has_standalone_columns = subgrid_area.columns.IsIndefinite();
  const bool has_standalone_rows = subgrid_area.rows.IsIndefinite();

  if (has_standalone_columns) {
    BuildSizingCollection(kForColumns);
  }
  if (has_standalone_rows) {
    BuildSizingCollection(kForRows);
  }

  auto AddSubgriddedItemLookupData = [&](const GridItemData& grid_item) {
    // We don't want to add lookup data for grid items that are not going to be
    // subgridded to the parent grid. We need to check for both axes:
    //   - If it's standalone, then this subgrid's items won't be subgridded.
    //   - Otherwise, if the grid item is a subgrid itself and its respective
    //   axis is also subgridded, we won't need its lookup data.
    if ((has_standalone_columns || grid_item.has_subgridded_columns) &&
        (has_standalone_rows || grid_item.has_subgridded_rows)) {
      return;
    }
    sizing_tree->AddSubgriddedItemLookupData(
        SubgriddedItemData(grid_item, sizing_node.layout_data, writing_mode));
  };

  if (!has_nested_subgrid) {
    for (const auto& grid_item : sizing_node.grid_items) {
      AddSubgriddedItemLookupData(grid_item);
    }
    return sizing_node.subtree_size;
  }

  InitializeTrackCollection(opt_subgrid_data, kForColumns,
                            &sizing_node.layout_data);
  InitializeTrackCollection(opt_subgrid_data, kForRows,
                            &sizing_node.layout_data);

  if (has_standalone_columns) {
    sizing_node.layout_data.SizingCollection(kForColumns)
        .CacheDefiniteSetsGeometry();
  }
  if (has_standalone_rows) {
    sizing_node.layout_data.SizingCollection(kForRows)
        .CacheDefiniteSetsGeometry();
  }

  // |AppendSubgriddedItems| rely on the cached placement data of a subgrid to
  // construct its grid items, so we need to build their subtrees beforehand.
  for (auto& grid_item : sizing_node.grid_items) {
    AddSubgriddedItemLookupData(grid_item);

    if (!grid_item.IsSubgrid())
      continue;

    // TODO(ethavar): Currently we have an issue where we can't correctly cache
    // the set indices of this grid item to determine its available space. This
    // happens because subgridded items are not considered by the range builder
    // since they can't be placed before we recurse into subgrids.
    grid_item.ComputeSetIndices(sizing_node.layout_data.Columns());
    grid_item.ComputeSetIndices(sizing_node.layout_data.Rows());

    const auto space =
        CreateConstraintSpaceForLayout(grid_item, sizing_node.layout_data);
    const auto fragment_geometry =
        CalculateInitialFragmentGeometryForSubgrid(grid_item, space);

    const GridLayoutAlgorithm subgrid_algorithm(
        {grid_item.node, fragment_geometry, space});

    sizing_node.subtree_size += subgrid_algorithm.BuildGridSizingSubtree(
        sizing_tree, /*opt_oof_children=*/nullptr,
        SubgriddedItemData(grid_item, sizing_node.layout_data, writing_mode),
        &line_resolver, must_invalidate_placement_cache);

    // After we accommodate subgridded items in their respective sizing track
    // collections, their placement indices might be incorrect, so we want to
    // recompute them when we call |InitializeTrackSizes|.
    grid_item.ResetPlacementIndices();
  }

  node.AppendSubgriddedItems(&sizing_node.grid_items);

  // We need to recreate the track builder collections to ensure track coverage
  // for subgridded items; it would be ideal to have them accounted for already,
  // but we might need the track collections to compute a subgrid's automatic
  // repetitions, so we do this process twice to avoid a cyclic dependency.
  if (has_standalone_columns) {
    BuildSizingCollection(kForColumns);
  }
  if (has_standalone_rows) {
    BuildSizingCollection(kForRows);
  }
  return sizing_node.subtree_size;
}

GridSizingTree GridLayoutAlgorithm::BuildGridSizingTree(
    HeapVector<Member<LayoutBox>>* opt_oof_children) const {
  GridSizingTree sizing_tree;

  if (const auto* layout_subtree =
          GetConstraintSpace().GetGridLayoutSubtree()) {
    const auto& node = Node();
    auto& [grid_items, layout_data, subtree_size] =
        sizing_tree.CreateSizingData(node);

    bool must_invalidate_placement_cache = false;
    grid_items = node.ConstructGridItems(node.CachedLineResolver(),
                                         &must_invalidate_placement_cache,
                                         opt_oof_children);

    DCHECK(!must_invalidate_placement_cache)
        << "We shouldn't need to invalidate the placement cache if we relied "
           "on the cached line resolver; it must produce the same placement.";

    layout_data = layout_subtree->LayoutData();
    for (auto& grid_item : grid_items) {
      grid_item.ComputeSetIndices(layout_data.Columns());
      grid_item.ComputeSetIndices(layout_data.Rows());
    }
  } else {
    BuildGridSizingSubtree(&sizing_tree, opt_oof_children);
  }
  return sizing_tree;
}

GridSizingTree GridLayoutAlgorithm::BuildGridSizingTreeIgnoringChildren()
    const {
  GridSizingTree sizing_tree;
  BuildGridSizingSubtree(&sizing_tree, /*opt_oof_children=*/nullptr,
                         /*opt_subgrid_data=*/kNoSubgriddedItemData,
                         /*opt_parent_line_resolver=*/nullptr,
                         /*must_invalidate_placement_cache=*/false,
                         /*must_ignore_children=*/true);
  return sizing_tree;
}

LayoutUnit GridLayoutAlgorithm::Baseline(
    const GridLayoutData& layout_data,
    const GridItemData& grid_item,
    GridTrackSizingDirection track_direction) const {
  // "If a box spans multiple shared alignment contexts, then it participates
  //  in first/last baseline alignment within its start-most/end-most shared
  //  alignment context along that axis"
  // https://www.w3.org/TR/css-align-3/#baseline-sharing-group
  const auto& track_collection = (track_direction == kForColumns)
                                     ? layout_data.Columns()
                                     : layout_data.Rows();
  const auto& [begin_set_index, end_set_index] =
      grid_item.SetIndices(track_direction);

  return (grid_item.BaselineGroup(track_direction) == BaselineGroup::kMajor)
             ? track_collection.MajorBaseline(begin_set_index)
             : track_collection.MinorBaseline(end_set_index - 1);
}

namespace {

struct FirstSetGeometry {
  LayoutUnit start_offset;
  LayoutUnit gutter_size;
};

FirstSetGeometry ComputeFirstSetGeometry(
    const GridSizingTrackCollection& track_collection,
    const ComputedStyle& container_style,
    LayoutUnit available_size,
    LayoutUnit start_border_scrollbar_padding) {
  const bool is_for_columns = track_collection.Direction() == kForColumns;

  const auto& content_alignment = is_for_columns
                                      ? container_style.JustifyContent()
                                      : container_style.AlignContent();
  const auto overflow = content_alignment.Overflow();

  // Determining the free-space is typically unnecessary, i.e. if there is
  // default alignment. Only compute this on-demand.
  auto FreeSpace = [&]() -> LayoutUnit {
    LayoutUnit free_space = available_size - track_collection.TotalTrackSize();

    // If overflow is 'safe', make sure we don't overflow the 'start' edge
    // (potentially causing some data loss as the overflow is unreachable).
    return (overflow == OverflowAlignment::kSafe)
               ? free_space.ClampNegativeToZero()
               : free_space;
  };

  // The default alignment, perform adjustments on top of this.
  FirstSetGeometry geometry{start_border_scrollbar_padding,
                            track_collection.GutterSize()};

  // If we have an indefinite |available_size| we can't perform any alignment,
  // just return the default alignment.
  if (available_size == kIndefiniteSize)
    return geometry;

  // TODO(ikilpatrick):
"""


```