Response:
My thinking process to arrive at the summary of the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the *provided code snippet* (part 2 of 6) from `grid_layout_algorithm.cc`. It emphasizes functionality, relationships with web technologies (JS, HTML, CSS), logical reasoning (input/output), and common errors. Since it's part 2, it's important to remember this is likely a subsection of a larger task.

2. **Initial Scan and Identify Key Sections:** I quickly skim the code, looking for distinct blocks of functionality. I notice:
    * A function `ComputeGridGeometry`.
    * A function `ComputeIntrinsicBlockSizeIgnoringChildren`.
    * A namespace `anonymous` containing several helper functions like `LayoutGridItemForMeasure`, `GetExtraMarginForBaseline`, `GetLogicalBaseline`, `GetSynthesizedLogicalBaseline`, and `ComputeBlockSizeForSubgrid`.
    * A function `ContributionSizeForGridItem`.
    * A function `ComputeAutomaticRepetitions`.
    * A function `ComputeAutomaticRepetitionsForSubgrid`.

3. **Analyze `ComputeGridGeometry`:** This function seems central. I look at its purpose and the steps it takes:
    * Takes `GridSizingTree` and a pointer to `intrinsic_block_size`.
    * Determines if it's a standalone grid.
    * Initializes track sizes.
    * Calls `CompleteTrackSizingAlgorithm` for both columns and rows. This strongly suggests it's responsible for calculating the dimensions of the grid tracks.
    * Calculates the intrinsic block size, considering content and potentially clamping it.
    * If not a standalone grid, it returns early.
    * Handles cases where the block size is indefinite or `auto`. It recalculates the grid if necessary.
    * Applies content alignment (`align-content`).
    * Potentially runs the track sizing algorithm again if needed (based on `needs_additional_pass`).
    * Calls `CompleteFinalBaselineAlignment`. This indicates it also deals with baseline alignment.

4. **Analyze `ComputeIntrinsicBlockSizeIgnoringChildren`:** The name is quite descriptive. It calculates the intrinsic block size *without* considering the children. It builds a `GridSizingTreeIgnoringChildren` and calls the track sizing algorithm for rows.

5. **Analyze the Anonymous Namespace:** The functions within this namespace seem to be *helper functions* for the main algorithms:
    * `LayoutGridItemForMeasure`:  Clearly related to laying out individual grid items, possibly for measuring their dimensions. The comment about disabling side effects during MinMax computation is a key detail.
    * Baseline-related functions (`GetExtraMarginForBaseline`, `GetLogicalBaseline`, `GetSynthesizedLogicalBaseline`): These handle the complexities of baseline alignment in grid layout, taking into account margins and subgrids.
    * `ComputeBlockSizeForSubgrid`: Specifically calculates the block size for subgrids.

6. **Analyze `ContributionSizeForGridItem`:** This function appears to calculate the contribution of a *single grid item* to the size of a grid track. It considers different contribution types (min/max content, intrinsic mins, etc.) and whether the item is parallel to the track direction. The extensive `switch` statement within shows how it handles different length types (auto, fixed, min-content, etc.). The comments about handling replaced elements and potential additional passes are important.

7. **Analyze `ComputeAutomaticRepetitions` and `ComputeAutomaticRepetitionsForSubgrid`:** These functions deal with the `repeat(auto-fill, ...)` and `repeat(auto-fit, ...)` syntax in CSS grid templates. They calculate how many times the repeating tracks should be created based on available space or the span of a subgrid.

8. **Identify Relationships with Web Technologies:** Based on the function names and the CSS properties mentioned in comments (like `align-content`, `grid-template-columns`, `grid-template-rows`), the strong connection to CSS grid layout is evident. The handling of inline and block sizes relates to HTML box model concepts. While JavaScript isn't directly present in this *code*, the layout calculations performed here are what the browser engine uses when rendering web pages based on CSS and HTML.

9. **Consider Logical Reasoning (Input/Output):** For `ComputeGridGeometry`, inputs are the `GridSizingTree` and available sizes. The outputs are the calculated track sizes and the intrinsic block size. For `ContributionSizeForGridItem`, the input is a `GridItemData` and the contribution type, and the output is the calculated contribution size. For the auto-repeat functions, the input is available space or subgrid span, and the output is the number of repetitions.

10. **Think about Common Errors:**  Misunderstanding how `auto-fill` and `auto-fit` work, especially in subgrids, is a common source of confusion for developers. Incorrectly specifying grid-template values can also lead to unexpected layouts. The comments about indefinite sizes and the need for multiple passes hint at potential performance issues if layouts become too complex.

11. **Synthesize and Structure the Summary:** Finally, I organize my findings into a clear and concise summary, addressing the specific points requested in the prompt. I group related functionalities together and provide examples where necessary. Since it's part 2, I frame the summary acknowledging it's a segment of a larger process. I explicitly mention the core functions and their roles, the helper functions, and the relationships with web technologies, logical reasoning, and potential errors. I make sure to highlight the *specific* functionalities present in *this part* of the code.这是 `blink/renderer/core/layout/grid/grid_layout_algorithm.cc` 文件的第 2 部分，主要负责网格布局算法中关于 **确定网格轨道大小和网格容器尺寸** 的核心逻辑。

以下是该部分代码功能的归纳总结：

**核心功能：**

1. **处理内容对齐 (Content Alignment):**
   - 实现了 CSS 属性 `align-content` 和 `justify-content` 中 `space-between`, `space-around`, 和 `space-evenly` 的逻辑。
   - 根据可用空间和轨道数量，计算轨道之间的间距和起始偏移量，以实现不同的内容分布效果。
   - 还处理了 `left`, `right`, `center`, `end`, `start` 等位置对齐方式。

2. **计算网格几何属性 (ComputeGridGeometry):**
   - 这是核心函数，用于计算网格的最终布局尺寸。
   - **初始化轨道大小 (InitializeTrackSizes):** 为列和行轨道初始化大小信息。
   - **完成轨道大小调整算法 (CompleteTrackSizingAlgorithm):**  多次调用以迭代地确定列和行轨道的最终大小，考虑到内容、约束和 `fr` 单位等。
   - **计算固有块大小 (intrinsic_block_size):**  在没有明确高度的情况下，计算网格的固有高度，考虑内容和边框滚动条等。
   - **处理 `contain-intrinsic-size`:** 如果设置了 `contain-intrinsic-size`，则使用该值作为固有高度。
   - **处理自适应最小尺寸 (applies_auto_min_size):**  当容器的 `min-height` 为 `auto` 且 `overflow` 可见或裁剪时，进行特殊处理。
   - **处理百分比间距和依赖可用尺寸的轨道:** 如果行间距使用了百分比或者轨道大小依赖于可用尺寸，则可能需要额外的布局pass。
   - **处理 flex 项目:** 当网格容器是 flex 项目时，需要特殊处理其块大小的计算。
   - **应用内容对齐 (Apply content alignment):** 在确定了可用块大小后，应用 `align-content` 属性来调整行轨道的位置。
   - **完成最终基线对齐 (CompleteFinalBaselineAlignment):** 计算整个网格的最终基线位置。

3. **计算忽略子元素的固有块大小 (ComputeIntrinsicBlockSizeIgnoringChildren):**
   - 用于在某些情况下，例如 `contain: size;` 时，计算不考虑子元素影响的网格固有块大小。
   - 构建一个忽略子元素的网格尺寸树，并运行轨道大小调整算法。

4. **计算网格项的贡献大小 (ContributionSizeForGridItem):**
   - 这是一个非常重要的函数，用于计算单个网格项对网格轨道大小的贡献。
   - 考虑不同的贡献类型：
     - `kForContentBasedMinimums`: 内容决定的最小尺寸。
     - `kForIntrinsicMaximums`: 内容决定的最大尺寸。
     - `kForIntrinsicMinimums`: 固有最小尺寸（与 `min-width`/`min-height` 相关）。
     - `kForMaxContentMinimums`/`kForMaxContentMaximums`: 最大内容尺寸相关的最小值/最大值。
   - 根据网格项是否与轨道方向平行，以及是否是 subgrid，采取不同的计算方式。
   - 涉及到布局网格项以测量其尺寸（`LayoutGridItemForMeasure`）。
   - 处理基线对齐的情况。
   - 处理 `min-content`, `max-content` 等关键字。
   - 考虑 `min-width`/`min-height` 属性的影响。

5. **计算自动重复次数 (ComputeAutomaticRepetitions & ComputeAutomaticRepetitionsForSubgrid):**
   - 用于处理 `grid-template-columns` 和 `grid-template-rows` 中使用 `repeat(auto-fill, ...)` 或 `repeat(auto-fit, ...)` 的情况。
   - 根据可用空间和重复模式中轨道的大小，计算需要重复多少次。
   - `ComputeAutomaticRepetitionsForSubgrid` 专门处理 subgrid 的自动重复计算，逻辑与独立网格有所不同。

**与 Javascript, HTML, CSS 的关系：**

- **CSS:** 这部分代码直接实现了 CSS Grid Layout 的规范，包括对齐属性 (`align-content`, `justify-content`) 和轨道定义 (`grid-template-columns`, `grid-template-rows`) 的解析和计算。 例如：
    - **`align-content: space-between;`**: 代码中的 `ContentDistributionType::kSpaceBetween` 分支就是处理这种情况，它会计算剩余空间并将其分配到轨道之间。
    - **`grid-template-columns: repeat(auto-fill, 100px);`**: `ComputeAutomaticRepetitions` 函数负责计算 `auto-fill` 需要重复多少次，使得每个轨道至少有 100px 的空间。

- **HTML:** 网格布局应用于 HTML 元素上，这段代码负责计算这些元素的布局。例如，当一个 `<div>` 元素的 `display` 属性设置为 `grid` 时，这段代码就会被调用来确定其子元素的布局。

- **Javascript:** Javascript 可以通过 DOM API 操作元素的样式，从而影响这段代码的执行。例如，通过 Javascript 动态地修改元素的 `grid-template-columns` 属性，会导致这段代码重新计算网格布局。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `ComputeGridGeometry`):**

- `grid_sizing_tree`: 一个描述网格结构和每个网格项尺寸信息的树状数据结构。
- `grid_available_size_`: 网格容器可用的内联尺寸和块尺寸（例如，父容器的可用宽度和高度）。
- `container_style`: 网格容器的 CSS 样式信息，包括 `align-content`, `justify-content`, `grid-template-columns`, `grid-template-rows` 等属性。

**假设输出 (针对 `ComputeGridGeometry`):**

- `intrinsic_block_size`: 计算出的网格固有块大小。
- 修改 `grid_sizing_tree` 中的数据，例如更新每个网格轨道的位置和大小。

**假设输入 (针对 `ContributionSizeForGridItem`):**

- `sizing_subtree`: 当前网格的尺寸树信息。
- `contribution_type`: 请求的贡献类型（例如 `kForIntrinsicMinimums`）。
- `track_direction`:  当前计算的是列还是行的贡献。
- `grid_item`:  需要计算贡献的网格项的数据。

**假设输出 (针对 `ContributionSizeForGridItem`):**

- `contribution`: 计算出的网格项对轨道大小的贡献值。

**涉及用户或编程常见的使用错误：**

1. **`align-content: space-between` 或类似的属性没有效果:** 这可能是因为网格容器的块轴方向没有足够的剩余空间。例如，如果网格只有一行，`space-between` 就不会产生明显的效果。

   ```html
   <div style="display: grid; align-content: space-between; height: 100px;">
     <div>Item 1</div>
   </div>
   ```
   在这个例子中，因为只有一个网格项，`space-between` 无法分配空间。

2. **误解 `auto-fill` 和 `auto-fit` 的区别:**  `auto-fill` 会填充尽可能多的轨道，即使这些轨道是空的，而 `auto-fit` 会折叠空轨道。如果开发者期望 `auto-fit` 的行为但使用了 `auto-fill`，可能会看到意料之外的空轨道。

   ```css
   .grid {
     display: grid;
     grid-template-columns: repeat(auto-fill, 100px); /* 可能产生空轨道 */
   }

   .grid-fit {
     display: grid;
     grid-template-columns: repeat(auto-fit, 100px);  /* 会折叠空轨道 */
   }
   ```

3. **在 subgrid 中错误地使用 `auto-fill`:**  subgrid 的 `auto-fill` 行为与独立网格不同，它会尝试匹配父网格的 span。如果父网格不存在或计算方式不明确，可能会导致意外的结果。

**总结:**

这部分代码是 Blink 引擎中实现 CSS Grid Layout 算法的关键部分，专注于计算网格轨道的大小、网格容器的尺寸以及处理各种内容对齐和自动重复的情况。它深入处理了 CSS Grid 规范的复杂性，并与 HTML 和 Javascript 相互作用，共同构建网页的布局。理解这部分代码有助于深入了解浏览器如何渲染和布局网格结构。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
'space-between', 'space-around', and 'space-evenly' all
  // divide by the free-space, and may have a non-zero modulo. Investigate if
  // this should be distributed between the tracks.
  switch (content_alignment.Distribution()) {
    case ContentDistributionType::kSpaceBetween: {
      // Default behavior for 'space-between' is to start align content.
      const wtf_size_t track_count = track_collection.NonCollapsedTrackCount();
      const LayoutUnit free_space = FreeSpace();
      if (track_count < 2 || free_space < LayoutUnit())
        return geometry;

      geometry.gutter_size += free_space / (track_count - 1);
      return geometry;
    }
    case ContentDistributionType::kSpaceAround: {
      // Default behavior for 'space-around' is to safe center content.
      const wtf_size_t track_count = track_collection.NonCollapsedTrackCount();
      const LayoutUnit free_space = FreeSpace();
      if (free_space < LayoutUnit()) {
        return geometry;
      }
      if (track_count < 1) {
        geometry.start_offset += free_space / 2;
        return geometry;
      }

      LayoutUnit track_space = free_space / track_count;
      geometry.start_offset += track_space / 2;
      geometry.gutter_size += track_space;
      return geometry;
    }
    case ContentDistributionType::kSpaceEvenly: {
      // Default behavior for 'space-evenly' is to safe center content.
      const wtf_size_t track_count = track_collection.NonCollapsedTrackCount();
      const LayoutUnit free_space = FreeSpace();
      if (free_space < LayoutUnit()) {
        return geometry;
      }

      LayoutUnit track_space = free_space / (track_count + 1);
      geometry.start_offset += track_space;
      geometry.gutter_size += track_space;
      return geometry;
    }
    case ContentDistributionType::kStretch:
    case ContentDistributionType::kDefault:
      break;
  }

  switch (content_alignment.GetPosition()) {
    case ContentPosition::kLeft: {
      DCHECK(is_for_columns);
      if (IsLtr(container_style.Direction()))
        return geometry;

      geometry.start_offset += FreeSpace();
      return geometry;
    }
    case ContentPosition::kRight: {
      DCHECK(is_for_columns);
      if (IsRtl(container_style.Direction()))
        return geometry;

      geometry.start_offset += FreeSpace();
      return geometry;
    }
    case ContentPosition::kCenter: {
      geometry.start_offset += FreeSpace() / 2;
      return geometry;
    }
    case ContentPosition::kEnd:
    case ContentPosition::kFlexEnd: {
      geometry.start_offset += FreeSpace();
      return geometry;
    }
    case ContentPosition::kStart:
    case ContentPosition::kFlexStart:
    case ContentPosition::kNormal:
    case ContentPosition::kBaseline:
    case ContentPosition::kLastBaseline:
      return geometry;
  }
}

}  // namespace

void GridLayoutAlgorithm::ComputeGridGeometry(
    const GridSizingTree& grid_sizing_tree,
    LayoutUnit* intrinsic_block_size) {
  DCHECK(intrinsic_block_size);
  DCHECK_NE(grid_available_size_.inline_size, kIndefiniteSize);

  const auto& constraint_space = GetConstraintSpace();
  const bool is_standalone_grid = !constraint_space.GetGridLayoutSubtree();

  bool needs_additional_pass = false;
  if (is_standalone_grid) {
    InitializeTrackSizes(grid_sizing_tree);

    CompleteTrackSizingAlgorithm(grid_sizing_tree, kForColumns,
                                 SizingConstraint::kLayout,
                                 &needs_additional_pass);
    CompleteTrackSizingAlgorithm(grid_sizing_tree, kForRows,
                                 SizingConstraint::kLayout,
                                 &needs_additional_pass);
  }

  const auto& border_scrollbar_padding = BorderScrollbarPadding();
  auto& sizing_data = grid_sizing_tree.TreeRootData();
  auto& layout_data = sizing_data.layout_data;

  const auto& node = Node();
  const auto& container_style = Style();

  if (contain_intrinsic_block_size_) {
    *intrinsic_block_size = *contain_intrinsic_block_size_;
  } else {
    *intrinsic_block_size = layout_data.Rows().ComputeSetSpanSize() +
                            border_scrollbar_padding.BlockSum();

    // TODO(layout-dev): This isn't great but matches legacy. Ideally this
    // would only apply when we have only flexible track(s).
    if (sizing_data.grid_items.IsEmpty() && node.HasLineIfEmpty()) {
      *intrinsic_block_size = std::max(
          *intrinsic_block_size, border_scrollbar_padding.BlockSum() +
                                     node.EmptyLineBlockSize(GetBreakToken()));
    }

    *intrinsic_block_size = ClampIntrinsicBlockSize(
        constraint_space, node, GetBreakToken(), border_scrollbar_padding,
        *intrinsic_block_size);
  }

  if (!is_standalone_grid) {
    return;
  }

  const bool applies_auto_min_size =
      container_style.LogicalMinHeight().HasAuto() &&
      container_style.IsOverflowVisibleOrClip() &&
      !container_style.AspectRatio().IsAuto();
  if (grid_available_size_.block_size == kIndefiniteSize ||
      applies_auto_min_size) {
    const auto block_size = ComputeBlockSizeForFragment(
        constraint_space, node, BorderPadding(), *intrinsic_block_size,
        container_builder_.InlineSize());

    DCHECK_NE(block_size, kIndefiniteSize);

    grid_available_size_.block_size = grid_min_available_size_.block_size =
        grid_max_available_size_.block_size =
            (block_size - border_scrollbar_padding.BlockSum())
                .ClampNegativeToZero();

    // If we have any rows, gaps which will resolve differently if we have a
    // definite |grid_available_size_| re-compute the grid using the
    // |block_size| calculated above.
    needs_additional_pass |=
        (container_style.RowGap() && container_style.RowGap()->HasPercent()) ||
        layout_data.Rows().IsDependentOnAvailableSize();

    // If we are a flex-item, we may have our initial block-size forced to be
    // indefinite, however grid layout always re-computes the grid using the
    // final "used" block-size.
    // We can detect this case by checking if computing our block-size (with an
    // indefinite intrinsic size) is definite.
    //
    // TODO(layout-dev): A small optimization here would be to do this only if
    // we have 'auto' tracks which fill the remaining available space.
    if (constraint_space.IsInitialBlockSizeIndefinite()) {
      needs_additional_pass |=
          ComputeBlockSizeForFragment(
              constraint_space, node, BorderPadding(),
              /* intrinsic_block_size */ kIndefiniteSize,
              container_builder_.InlineSize()) != kIndefiniteSize;
    }

    // After resolving the block-size, if we don't need to rerun the track
    // sizing algorithm, simply apply any content alignment to its rows.
    if (!needs_additional_pass &&
        container_style.AlignContent() !=
            ComputedStyleInitialValues::InitialAlignContent()) {
      auto& track_collection = layout_data.SizingCollection(kForRows);

      // Re-compute the row geometry now that we resolved the available block
      // size. "align-content: space-evenly", etc, require the resolved size.
      auto first_set_geometry = ComputeFirstSetGeometry(
          track_collection, container_style, grid_available_size_.block_size,
          border_scrollbar_padding.block_start);

      track_collection.FinalizeSetsGeometry(first_set_geometry.start_offset,
                                            first_set_geometry.gutter_size);
    }
  }

  if (needs_additional_pass) {
    InitializeTrackSizes(grid_sizing_tree, kForColumns);
    CompleteTrackSizingAlgorithm(grid_sizing_tree, kForColumns,
                                 SizingConstraint::kLayout);

    InitializeTrackSizes(grid_sizing_tree, kForRows);
    CompleteTrackSizingAlgorithm(grid_sizing_tree, kForRows,
                                 SizingConstraint::kLayout);
  }

  // Calculate final alignment baselines of the entire grid sizing tree.
  CompleteFinalBaselineAlignment(grid_sizing_tree);
}

LayoutUnit GridLayoutAlgorithm::ComputeIntrinsicBlockSizeIgnoringChildren()
    const {
  const auto& node = Node();
  const LayoutUnit override_intrinsic_block_size =
      node.OverrideIntrinsicContentBlockSize();
  DCHECK(node.ShouldApplyBlockSizeContainment());

  // First check 'contain-intrinsic-size'.
  if (override_intrinsic_block_size != kIndefiniteSize)
    return BorderScrollbarPadding().BlockSum() + override_intrinsic_block_size;

  auto grid_sizing_tree = BuildGridSizingTreeIgnoringChildren();

  InitializeTrackSizes(grid_sizing_tree, kForRows);
  CompleteTrackSizingAlgorithm(grid_sizing_tree, kForRows,
                               SizingConstraint::kLayout);

  return grid_sizing_tree.TreeRootData()
             .layout_data.Rows()
             .ComputeSetSpanSize() +
         BorderScrollbarPadding().BlockSum();
}

namespace {

const LayoutResult* LayoutGridItemForMeasure(
    const GridItemData& grid_item,
    const ConstraintSpace& constraint_space,
    SizingConstraint sizing_constraint) {
  const auto& node = grid_item.node;

  // Disable side effects during MinMax computation to avoid potential "MinMax
  // after layout" crashes. This is not necessary during the layout pass, and
  // would have a negative impact on performance if used there.
  //
  // TODO(ikilpatrick): For subgrid, ideally we don't want to disable side
  // effects as it may impact performance significantly; this issue can be
  // avoided by introducing additional cache slots (see crbug.com/1272533).
  std::optional<DisableLayoutSideEffectsScope> disable_side_effects;
  if (!node.GetLayoutBox()->NeedsLayout() &&
      (sizing_constraint != SizingConstraint::kLayout ||
       grid_item.is_subgridded_to_parent_grid)) {
    disable_side_effects.emplace();
  }
  return node.Layout(constraint_space);
}

LayoutUnit GetExtraMarginForBaseline(const BoxStrut& margins,
                                     const SubgriddedItemData& subgridded_item,
                                     GridTrackSizingDirection track_direction,
                                     WritingMode writing_mode) {
  const auto& track_collection = (track_direction == kForColumns)
                                     ? subgridded_item.Columns(writing_mode)
                                     : subgridded_item.Rows(writing_mode);
  const auto& [begin_set_index, end_set_index] =
      subgridded_item->SetIndices(track_collection.Direction());

  const LayoutUnit extra_margin =
      (subgridded_item->BaselineGroup(track_direction) == BaselineGroup::kMajor)
          ? track_collection.StartExtraMargin(begin_set_index)
          : track_collection.EndExtraMargin(end_set_index);

  return extra_margin +
         (subgridded_item->IsLastBaselineSpecified(track_direction)
              ? margins.block_end
              : margins.block_start);
}

LayoutUnit GetLogicalBaseline(const GridItemData& grid_item,
                              const LogicalBoxFragment& baseline_fragment,
                              GridTrackSizingDirection track_direction) {
  const auto font_baseline = grid_item.parent_grid_font_baseline;

  return grid_item.IsLastBaselineSpecified(track_direction)
             ? baseline_fragment.BlockSize() -
                   baseline_fragment.LastBaselineOrSynthesize(font_baseline)
             : baseline_fragment.FirstBaselineOrSynthesize(font_baseline);
}

LayoutUnit GetSynthesizedLogicalBaseline(
    const GridItemData& grid_item,
    LayoutUnit block_size,
    GridTrackSizingDirection track_direction) {
  const auto synthesized_baseline = LogicalBoxFragment::SynthesizedBaseline(
      grid_item.parent_grid_font_baseline,
      grid_item.BaselineWritingDirection(track_direction).IsFlippedLines(),
      block_size);

  return grid_item.IsLastBaselineSpecified(track_direction)
             ? block_size - synthesized_baseline
             : synthesized_baseline;
}

LayoutUnit ComputeBlockSizeForSubgrid(const GridSizingSubtree& sizing_subtree,
                                      const GridItemData& subgrid_data,
                                      const ConstraintSpace& space) {
  DCHECK(sizing_subtree);
  DCHECK(subgrid_data.IsSubgrid());

  const auto& node = To<GridNode>(subgrid_data.node);
  return ComputeBlockSizeForFragment(
      space, node,
      ComputeBorders(space, node) + ComputePadding(space, node.Style()),
      node.ComputeSubgridIntrinsicBlockSize(sizing_subtree, space),
      space.AvailableSize().inline_size);
}

}  // namespace

LayoutUnit GridLayoutAlgorithm::ContributionSizeForGridItem(
    const GridSizingSubtree& sizing_subtree,
    GridItemContributionType contribution_type,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint,
    GridItemData* grid_item) const {
  DCHECK(grid_item);
  DCHECK(grid_item->IsConsideredForSizing(track_direction));

  const auto& node = grid_item->node;
  const auto& item_style = node.Style();
  const auto& constraint_space = GetConstraintSpace();

  const bool is_for_columns = track_direction == kForColumns;
  const bool is_parallel_with_track_direction =
      is_for_columns == grid_item->is_parallel_with_root_grid;

  const auto writing_mode = constraint_space.GetWritingMode();
  const auto subgridded_item =
      grid_item->is_subgridded_to_parent_grid
          ? sizing_subtree.LookupSubgriddedItemData(*grid_item)
          : SubgriddedItemData(*grid_item, sizing_subtree.LayoutData(),
                               writing_mode);

  // TODO(ikilpatrick): We'll need to record if any child used an indefinite
  // size for its contribution, such that we can then do the 2nd pass on the
  // track-sizing algorithm.
  const auto space =
      CreateConstraintSpaceForMeasure(subgridded_item, track_direction);

  LayoutUnit baseline_shim;
  auto CalculateBaselineShim = [&](LayoutUnit baseline) -> void {
    const auto track_baseline =
        Baseline(sizing_subtree.LayoutData(), *grid_item, track_direction);

    if (track_baseline == LayoutUnit::Min())
      return;

    const auto extra_margin = GetExtraMarginForBaseline(
        ComputeMarginsFor(space, item_style,
                          grid_item->BaselineWritingDirection(track_direction)),
        subgridded_item, track_direction, writing_mode);

    // Determine the delta between the baselines; subtract out the margin so it
    // doesn't get added a second time at the end of this method.
    baseline_shim = track_baseline - baseline - extra_margin;
  };

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    if (grid_item->IsSubgrid()) {
      return To<GridNode>(node).ComputeSubgridMinMaxSizes(
          sizing_subtree.SubgridSizingSubtree(*grid_item), space);
    }
    return node.ComputeMinMaxSizes(item_style.GetWritingMode(), type, space);
  };

  auto MinOrMaxContentSize = [&](bool is_min_content) -> LayoutUnit {
    const auto result = ComputeMinAndMaxContentContributionForSelf(
        node, space, MinMaxSizesFunc);

    // The min/max contribution may depend on the block-size of the grid-area:
    // <div style="display: inline-grid; grid-template-columns: auto auto;">
    //   <div style="height: 100%">
    //     <img style="height: 50%;" />
    //   </div>
    //   <div>
    //     <div style="height: 100px;"></div>
    //   </div>
    // </div>
    // Mark ourselves as requiring an additional pass to re-resolve the column
    // tracks for this case.
    if (grid_item->is_parallel_with_root_grid &&
        result.depends_on_block_constraints) {
      grid_item->is_sizing_dependent_on_block_size = true;
    }

    const auto content_size =
        is_min_content ? result.sizes.min_size : result.sizes.max_size;

    if (grid_item->IsBaselineAligned(track_direction)) {
      CalculateBaselineShim(GetSynthesizedLogicalBaseline(
          *grid_item, content_size, track_direction));
    }
    return content_size + baseline_shim;
  };

  auto MinContentSize = [&]() -> LayoutUnit {
    return MinOrMaxContentSize(/*is_min_content=*/true);
  };
  auto MaxContentSize = [&]() -> LayoutUnit {
    return MinOrMaxContentSize(/*is_min_content=*/false);
  };

  // This function will determine the correct block-size of a grid-item.
  // TODO(ikilpatrick): This should try and skip layout when possible. Notes:
  //  - We'll need to do a full layout for tables.
  //  - We'll need special logic for replaced elements.
  //  - We'll need to respect the aspect-ratio when appropriate.
  auto BlockContributionSize = [&]() -> LayoutUnit {
    DCHECK(!is_parallel_with_track_direction);

    if (grid_item->IsSubgrid()) {
      return ComputeBlockSizeForSubgrid(
          sizing_subtree.SubgridSizingSubtree(*grid_item), *grid_item, space);
    }

    // TODO(ikilpatrick): This check is potentially too broad, i.e. a fixed
    // inline size with no %-padding doesn't need the additional pass.
    if (is_for_columns)
      grid_item->is_sizing_dependent_on_block_size = true;

    const LayoutResult* result = nullptr;
    if (space.AvailableSize().inline_size == kIndefiniteSize) {
      // If we are orthogonal grid item, resolving against an indefinite size,
      // set our inline size to our max-content contribution size.
      const auto fallback_space = CreateConstraintSpaceForMeasure(
          subgridded_item, track_direction,
          /*opt_fixed_inline_size=*/MaxContentSize());

      result = LayoutGridItemForMeasure(*grid_item, fallback_space,
                                        sizing_constraint);
    } else {
      result = LayoutGridItemForMeasure(*grid_item, space, sizing_constraint);
    }

    LogicalBoxFragment baseline_fragment(
        grid_item->BaselineWritingDirection(track_direction),
        To<PhysicalBoxFragment>(result->GetPhysicalFragment()));

    if (grid_item->IsBaselineAligned(track_direction)) {
      CalculateBaselineShim(
          GetLogicalBaseline(*grid_item, baseline_fragment, track_direction));
    }
    return baseline_fragment.BlockSize() + baseline_shim;
  };

  const auto& track_collection = is_for_columns
                                     ? subgridded_item.Columns(writing_mode)
                                     : subgridded_item.Rows(writing_mode);

  const auto margins = ComputeMarginsFor(space, item_style, constraint_space);
  const auto& [begin_set_index, end_set_index] =
      subgridded_item->SetIndices(track_collection.Direction());

  const auto margin_sum =
      (is_for_columns ? margins.InlineSum() : margins.BlockSum()) +
      track_collection.StartExtraMargin(begin_set_index) +
      track_collection.EndExtraMargin(end_set_index);

  LayoutUnit contribution;
  switch (contribution_type) {
    case GridItemContributionType::kForContentBasedMinimums:
    case GridItemContributionType::kForIntrinsicMaximums:
      contribution = is_parallel_with_track_direction ? MinContentSize()
                                                      : BlockContributionSize();
      break;
    case GridItemContributionType::kForIntrinsicMinimums: {
      // TODO(ikilpatrick): All of the below is incorrect for replaced elements.
      const auto& main_length = is_parallel_with_track_direction
                                    ? item_style.LogicalWidth()
                                    : item_style.LogicalHeight();
      const auto& min_length = is_parallel_with_track_direction
                                   ? item_style.LogicalMinWidth()
                                   : item_style.LogicalMinHeight();

      // We could be clever is and make this an if-stmt, but each type has
      // subtle consequences. This forces us in the future when we add a new
      // length type to consider what the best thing is for grid.
      switch (main_length.GetType()) {
        case Length::kAuto:
        case Length::kFitContent:
        case Length::kStretch:
        case Length::kPercent:
        case Length::kCalculated: {
          const auto border_padding =
              ComputeBorders(space, node) + ComputePadding(space, item_style);

          // All of the above lengths are considered 'auto' if we are querying a
          // minimum contribution. They all require definite track sizes to
          // determine their final size.
          //
          // From https://drafts.csswg.org/css-grid/#min-size-auto:
          //   To provide a more reasonable default minimum size for grid items,
          //   the used value of its automatic minimum size in a given axis is
          //   the content-based minimum size if all of the following are true:
          //     - it is not a scroll container
          //     - it spans at least one track in that axis whose min track
          //     sizing function is 'auto'
          //     - if it spans more than one track in that axis, none of those
          //     tracks are flexible
          //   Otherwise, the automatic minimum size is zero, as usual.
          //
          // Start by resolving the cases where |min_length| is non-auto or its
          // automatic minimum size should be zero.
          if (!min_length.HasAuto() || item_style.IsScrollContainer() ||
              !grid_item->IsSpanningAutoMinimumTrack(track_direction) ||
              (grid_item->IsSpanningFlexibleTrack(track_direction) &&
               grid_item->SpanSize(track_direction) > 1)) {
            // TODO(ikilpatrick): This block needs to respect the aspect-ratio,
            // and apply the transferred min/max sizes when appropriate. We do
            // this sometimes elsewhere so should unify and simplify this code.
            if (is_parallel_with_track_direction) {
              contribution =
                  ResolveMinInlineLength(space, item_style, border_padding,
                                         MinMaxSizesFunc, min_length);
            } else {
              contribution = ResolveInitialMinBlockLength(
                  space, item_style, border_padding, min_length);
            }
            break;
          }

          // Resolve the content-based minimum size.
          contribution = is_parallel_with_track_direction
                             ? MinContentSize()
                             : BlockContributionSize();

          auto spanned_tracks_definite_max_size =
              track_collection.ComputeSetSpanSize(begin_set_index,
                                                  end_set_index);

          if (spanned_tracks_definite_max_size != kIndefiniteSize) {
            // Further clamp the minimum size to less than or equal to the
            // stretch fit into the grid area’s maximum size in that dimension,
            // as represented by the sum of those grid tracks’ max track sizing
            // functions plus any intervening fixed gutters.
            const auto border_padding_sum = is_parallel_with_track_direction
                                                ? border_padding.InlineSum()
                                                : border_padding.BlockSum();
            DCHECK_GE(contribution, baseline_shim + border_padding_sum);

            // The stretch fit into a given size is that size, minus the box’s
            // computed margins, border, and padding in the given dimension,
            // flooring at zero so that the inner size is not negative.
            spanned_tracks_definite_max_size =
                (spanned_tracks_definite_max_size - baseline_shim - margin_sum -
                 border_padding_sum)
                    .ClampNegativeToZero();

            // Add the baseline shim, border, and padding (margins will be added
            // later) back to the contribution, since we don't want the outer
            // size of the minimum size to overflow its grid area; these are
            // already accounted for in the current value of `contribution`.
            contribution =
                std::min(contribution, spanned_tracks_definite_max_size +
                                           baseline_shim + border_padding_sum);
          }
          break;
        }
        case Length::kMinContent:
        case Length::kMaxContent:
        case Length::kFixed: {
          // All of the above lengths are "definite" (non-auto), and don't need
          // the special min-size treatment above. (They will all end up being
          // the specified size).
          if (is_parallel_with_track_direction) {
            contribution = main_length.IsMaxContent() ? MaxContentSize()
                                                      : MinContentSize();
          } else {
            contribution = BlockContributionSize();
          }
          break;
        }
        case Length::kMinIntrinsic:
        case Length::kFlex:
        case Length::kExtendToZoom:
        case Length::kDeviceWidth:
        case Length::kDeviceHeight:
        case Length::kNone:
        case Length::kContent:
          NOTREACHED();
      }
      break;
    }
    case GridItemContributionType::kForMaxContentMinimums:
    case GridItemContributionType::kForMaxContentMaximums:
      contribution = is_parallel_with_track_direction ? MaxContentSize()
                                                      : BlockContributionSize();
      break;
    case GridItemContributionType::kForFreeSpace:
      NOTREACHED() << "`kForFreeSpace` should only be used to distribute extra "
                      "space in maximize tracks and stretch auto tracks steps.";
  }
  return (contribution + margin_sum).ClampNegativeToZero();
}

// https://drafts.csswg.org/css-grid-2/#auto-repeat
wtf_size_t GridLayoutAlgorithm::ComputeAutomaticRepetitions(
    const GridSpan& subgrid_span,
    GridTrackSizingDirection track_direction) const {
  const bool is_for_columns = track_direction == kForColumns;
  const auto& track_list = is_for_columns
                               ? Style().GridTemplateColumns().track_list
                               : Style().GridTemplateRows().track_list;

  if (!track_list.HasAutoRepeater())
    return 0;

  // Subgrids compute auto repetitions differently than standalone grids.
  // See https://drafts.csswg.org/css-grid-2/#auto-repeat.
  if (track_list.IsSubgriddedAxis()) {
    if (subgrid_span.IsIndefinite()) {
      // From https://drafts.csswg.org/css-grid-2/#subgrid-listing
      // "If there is no parent grid, ..., the used value is the initial
      // value, 'none', and the grid container is not a subgrid.
      return 0;
    }

    return ComputeAutomaticRepetitionsForSubgrid(subgrid_span.IntegerSpan(),
                                                 track_direction);
  }

  LayoutUnit available_size = is_for_columns ? grid_available_size_.inline_size
                                             : grid_available_size_.block_size;
  LayoutUnit max_available_size = available_size;

  if (available_size == kIndefiniteSize) {
    max_available_size = is_for_columns ? grid_max_available_size_.inline_size
                                        : grid_max_available_size_.block_size;
    available_size = is_for_columns ? grid_min_available_size_.inline_size
                                    : grid_min_available_size_.block_size;
  }

  LayoutUnit auto_repeater_size;
  LayoutUnit non_auto_specified_size;
  const LayoutUnit gutter_size = GutterSize(track_direction);

  for (wtf_size_t repeater_index = 0;
       repeater_index < track_list.RepeaterCount(); ++repeater_index) {
    const auto repeat_type = track_list.RepeatType(repeater_index);
    const bool is_auto_repeater =
        repeat_type == NGGridTrackRepeater::kAutoFill ||
        repeat_type == NGGridTrackRepeater::kAutoFit;

    LayoutUnit repeater_size;
    const wtf_size_t repeater_track_count =
        track_list.RepeatSize(repeater_index);

    for (wtf_size_t i = 0; i < repeater_track_count; ++i) {
      const auto& track_size = track_list.RepeatTrackSize(repeater_index, i);

      std::optional<LayoutUnit> fixed_min_track_breadth;
      if (track_size.HasFixedMinTrackBreadth()) {
        fixed_min_track_breadth.emplace(MinimumValueForLength(
            track_size.MinTrackBreadth(), available_size));
      }

      std::optional<LayoutUnit> fixed_max_track_breadth;
      if (track_size.HasFixedMaxTrackBreadth()) {
        fixed_max_track_breadth.emplace(MinimumValueForLength(
            track_size.MaxTrackBreadth(), available_size));
      }

      LayoutUnit track_contribution;
      if (fixed_max_track_breadth && fixed_min_track_breadth) {
        track_contribution =
            std::max(*fixed_max_track_breadth, *fixed_min_track_breadth);
      } else if (fixed_max_track_breadth) {
        track_contribution = *fixed_max_track_breadth;
      } else if (fixed_min_track_breadth) {
        track_contribution = *fixed_min_track_breadth;
      }

      // For the purpose of finding the number of auto-repeated tracks in a
      // standalone axis, the UA must floor the track size to a UA-specified
      // value to avoid division by zero. It is suggested that this floor be
      // 1px.
      if (is_auto_repeater)
        track_contribution = std::max(LayoutUnit(1), track_contribution);

      repeater_size += track_contribution + gutter_size;
    }

    if (!is_auto_repeater) {
      non_auto_specified_size +=
          repeater_size * track_list.RepeatCount(repeater_index, 0);
    } else {
      DCHECK_EQ(0, auto_repeater_size);
      auto_repeater_size = repeater_size;
    }
  }

  DCHECK_GT(auto_repeater_size, 0);

  // We can compute the number of repetitions by satisfying the expression
  // below. Notice that we subtract an extra |gutter_size| since it was included
  // in the contribution for the last set in the collection.
  //   available_size =
  //       (repetitions * auto_repeater_size) +
  //       non_auto_specified_size - gutter_size
  //
  // Solving for repetitions we have:
  //   repetitions =
  //       available_size - (non_auto_specified_size - gutter_size) /
  //       auto_repeater_size
  non_auto_specified_size -= gutter_size;

  // First we want to allow as many repetitions as possible, up to the max
  // available-size. Only do this if we have a definite max-size.
  // If a definite available-size was provided, |max_available_size| will be
  // set to that value.
  if (max_available_size != LayoutUnit::Max()) {
    // Use floor to ensure that the auto repeater sizes goes under the max
    // available-size.
    const int count = FloorToInt(
        (max_available_size - non_auto_specified_size) / auto_repeater_size);
    return (count <= 0) ? 1u : count;
  }

  // Next, consider the min available-size, which was already used to floor
  // |available_size|. Use ceil to ensure that the auto repeater size goes
  // above this min available-size.
  const int count = CeilToInt((available_size - non_auto_specified_size) /
                              auto_repeater_size);
  return (count <= 0) ? 1u : count;
}

wtf_size_t GridLayoutAlgorithm::ComputeAutomaticRepetitionsForSubgrid(
    wtf_size_t subgrid_span_size,
    GridTrackSizingDirection track_direction) const {
  // "On a subgridded axis, the auto-fill keyword is only valid once per
  // <line-name-list>, and repeats enough times for the name list to match the
  // subgrid’s specified grid span (falling back to 0 if the span is already
  // fulfilled).
  // https://drafts.csswg.org/css-grid-2/#auto-repeat
  const auto& computed_track_list = (track_direction == kForColumns)
                                        ? Style().GridTemplateColumns()
                                        : Style().GridTemplateRows();
  const auto& track_list = computed_track_list.track_list;
  DCHECK(track_list.HasAutoRepeater());

  const wtf_size_t non_auto_repeat_line_count =
      track_list.NonAutoRepeatLineCount();

  if (non_auto_repeat_line_count > subgrid_span_size) {
    // No more room left for auto repetitions due to the number of non-auto
    // repeat named grid lines (the span is already fulfilled).
    return 0;
  }

  const wtf_size_t tracks_per_repeat = track_list.AutoRepeatTrackCount();
  if (tracks_per_repeat > subgrid_span_size) {
    // No room left for auto repetitions because each repetition is too large.
    return 0;
  }

  const wtf_size_t tracks_left_over_for_auto_repeat =
      subgrid_span_size - non_auto_repeat_line_count + 1;
  DCHECK_GT(tracks_per_repeat, 0u);
  return static_cast<wtf_size_t>(
      std::floor(tracks_left_over_for_auto_repeat / tracks_per_repeat));
}

void GridLayoutAlgorithm::ComputeGridItemBaselines(
    const scoped_refptr<const GridLayoutTree>& layout_tree,
    const GridSizingSubtree& sizing_subtree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint) const {
  auto& track_collection = sizing_subtree.SizingCollection(track_direction);

  if (!tra
```