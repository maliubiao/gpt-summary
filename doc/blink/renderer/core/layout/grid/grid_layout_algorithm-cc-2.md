Response:
My goal is to analyze the provided C++ code snippet from Chromium's Blink engine and explain its functionality, relating it to web technologies where applicable. Here's a breakdown of the thinking process to generate the detailed explanation:

1. **Understand the Request:** The request asks for a functional description of the code, connections to HTML/CSS/JavaScript, logical reasoning, examples of user/programming errors, and a summary (since this is part 3 of 6).

2. **Initial Code Scan and Keyword Identification:**  I first scanned the code for prominent keywords and function names:
    * `GridLayoutAlgorithm`
    * `ComputeBaselineAlignment`
    * `ComputeUsedTrackSizes`
    * `CompleteTrackSizingAlgorithm`
    * `CreateSubgridTrackCollection`
    * `InitializeTrackCollection`
    * `InitializeTrackSizes`
    * `ForEachSubgrid`
    * `ComputeSubgridIntrinsicSize`
    * `GridTrackSizingDirection` (kForColumns, kForRows)
    * `SizingConstraint`
    * `GridItemData`, `GridLayoutData`, `GridSizingSubtree`, `GridSizingTree`
    * `Baseline`
    * `fr` (flexible tracks)
    * `min-content`, `max-content`

3. **Infer Core Functionality:** Based on the keywords, I inferred that this code is responsible for the *layout* of CSS Grid containers. Specifically, it's dealing with the sizing of rows and columns ("tracks") within the grid. The presence of "baseline" suggests handling text alignment within grid items. "Subgrid" indicates support for nested grids.

4. **Break Down Key Functions and Their Roles:** I then analyzed individual functions:

    * **`ComputeBaselineAlignment`:**  Focuses on aligning grid items based on their text baselines. This directly relates to CSS's `align-items: baseline`, `align-content: baseline`, etc.
    * **`ComputeUsedTrackSizes`:**  Implements the core track sizing algorithm. This is the heart of how the grid determines the width of columns and the height of rows, considering factors like `fr` units, `min-content`, `max-content`, and available space.
    * **`CompleteTrackSizingAlgorithm`:** Likely orchestrates the entire track sizing process, potentially calling `ComputeUsedTrackSizes` and handling subgrids.
    * **`CreateSubgridTrackCollection`:**  Deals specifically with creating track collections for nested grids, inheriting or adapting from the parent grid.
    * **`InitializeTrackCollection` and `InitializeTrackSizes`:** Handle the initial setup of the track sizing process, setting up data structures and potentially caching initial sizes.
    * **`ForEachSubgrid`:**  A utility function to recursively process nested grid layouts.
    * **`ComputeSubgridIntrinsicSize`:** Calculates the minimum or maximum size of a subgrid, crucial for intrinsic sizing.

5. **Connect to HTML, CSS, and JavaScript:**

    * **HTML:** The grid layout is applied to HTML elements. The structure of the HTML (parent grid and grid items) dictates how the algorithm operates.
    * **CSS:**  This code directly implements CSS Grid Layout properties: `grid-template-columns`, `grid-template-rows`, `grid-auto-rows`, `grid-auto-columns`, `fr` units, `min-content`, `max-content`, `minmax()`, `align-items`, `align-content`, `justify-items`, `justify-content`, and subgrid features (`grid-template-columns: subgrid`, `grid-template-rows: subgrid`).
    * **JavaScript:** While this specific C++ code isn't directly JavaScript, the results of this layout algorithm influence how JavaScript interacts with the DOM. JavaScript can query element sizes and positions, which are determined by this code. JavaScript might also trigger relayouts.

6. **Logical Reasoning and Examples:**

    * **Assumptions:** I made assumptions about how the functions operate based on their names and the context of CSS Grid. For example, `ComputeUsedTrackSizes` likely goes through the steps outlined in the CSS Grid specification.
    * **Input/Output:**  I considered hypothetical scenarios:
        * **Input:** A grid container with specific `grid-template-columns` and `grid-template-rows`.
        * **Output:** The calculated sizes of the grid tracks.
        * **Input:** A grid item spanning multiple rows/columns.
        * **Output:** How the algorithm distributes space to accommodate it.
        * **Input:** A subgrid.
        * **Output:** How its track sizes are determined based on the parent.

7. **User and Programming Errors:** I thought about common mistakes developers make with CSS Grid:
    * Incorrect `fr` unit usage.
    * Conflicting sizing constraints.
    * Not understanding how `min-content` and `max-content` work.
    * Issues with subgrid definition.

8. **Summarization (Part 3 of 6):** I focused on summarizing the *specific* functionality covered in this snippet, which is primarily track sizing (with a focus on intrinsic sizing, flexible sizing, and baseline alignment) and handling subgrids. I noted that it builds upon the initialization steps from earlier parts.

9. **Refinement and Organization:** I organized the information logically, using headings and bullet points for clarity. I ensured the examples were concrete and easy to understand. I also double-checked that the language was technical but still accessible. I made sure to explicitly state the assumptions made.

10. **Self-Correction/Improvements:**  During the process, I considered alternative interpretations of some function names. For example, `CompleteTrackSizingAlgorithm` *could* have meant just the finalization step, but its broad scope suggested it was more of an orchestrator. I made sure to justify my interpretations based on the code's context. I also ensured I linked the code back to the relevant CSS Grid concepts clearly and provided specific CSS property examples.
好的，让我们来归纳一下 `blink/renderer/core/layout/grid/grid_layout_algorithm.cc` 文件中提供的这部分代码的功能。

**核心功能归纳：网格布局算法 - 轨道尺寸计算和基线对齐（第三部分）**

这部分代码主要集中在 CSS Grid 布局算法中的以下几个关键方面：

1. **基线对齐 (Baseline Alignment):**
   - **计算和设置基线:**  遍历网格项，如果它们指定了基线对齐方式，则计算它们的基线位置。
   - **处理子网格基线:**  考虑嵌套子网格的基线，并在必要时重新创建子网格的轨道集合以继承基线信息。
   - **处理跨轨道项的基线:**  对于跨越多个共享对齐上下文的网格项，确定其参与基线对齐的上下文。
   - **设置对齐回退:**  当无法确定基线时，设置对齐方式回退。
   - **影响因素:**  网格项的 `baseline-shift` 属性（虽然代码中没有直接体现，但这是基线对齐的基础概念）。

2. **子网格轨道集合创建 (Subgrid Track Collection Creation):**
   - **为子网格创建轨道集合:**  `CreateSubgridTrackCollection` 函数负责为子网格创建独立的轨道集合，但会继承父网格的相关信息，例如轨道大小和间距。
   - **确定子网格的轨道范围:**  根据子网格的定义，从父网格的轨道集合中提取相应的轨道范围。
   - **处理子网格的方向性:**  考虑子网格的行和列方向与父网格的关系。

3. **轨道集合初始化 (Track Collection Initialization):**
   - **为指定方向初始化轨道集合:**  `InitializeTrackCollection` 函数负责为网格的行或列创建一个 `GridLayoutTrackCollection` 对象。
   - **处理子网格的继承:** 如果当前网格是子网格，并且正在处理继承的轴，则直接使用父网格的轨道集合。
   - **构建轨道集合的 Set:** 调用 `BuildSets` 方法，根据可用的空间和间距信息，将轨道划分为不同的 Set（逻辑分组）。

4. **轨道尺寸初始化 (Track Sizes Initialization):**
   - **初始化行和列的轨道尺寸:**  `InitializeTrackSizes` 函数负责初始化网格布局的行和列轨道尺寸。
   - **缓存网格项属性:**  调用 `CacheGridItemsProperties` 将网格项的相关属性缓存到轨道集合中。
   - **处理所有轨道都有确定尺寸的情况:**  如果所有轨道都有明确的尺寸，则可以立即计算出最终的轨道尺寸和偏移量。
   - **处理基线:**  如果轨道集合需要支持基线对齐，则进行初始化设置。
   - **递归处理子网格:**  遍历子网格并递归调用 `InitializeTrackSizes`。

5. **计算使用的轨道尺寸 (Compute Used Track Sizes):**
   - **核心的轨道尺寸计算逻辑:** `ComputeUsedTrackSizes` 函数实现了网格布局算法中计算轨道实际使用尺寸的关键步骤。
   - **处理固有尺寸 (Intrinsic Sizes):**  调用 `ResolveIntrinsicTrackSizes` 处理具有 `min-content`、`max-content` 等固有尺寸关键字的轨道。
   - **处理剩余空间分配:**  如果存在剩余空间，则根据规则将其分配给轨道。
   - **处理弹性尺寸 (Flexible Sizes - `fr` 单位):**  调用 `ExpandFlexibleTracks` 处理使用 `fr` 单位的轨道。
   - **拉伸 auto 尺寸的轨道:** 调用 `StretchAutoTracks` 处理 `max-width: auto` 或 `max-height: auto` 的轨道。

6. **完成轨道尺寸计算算法 (Complete Track Sizing Algorithm):**
   - **协调整个轨道尺寸计算流程:** `CompleteTrackSizingAlgorithm` 函数统筹整个轨道尺寸计算的过程。
   - **处理非固定尺寸的轨道:**  如果存在非固定尺寸的轨道，则调用 `ComputeUsedTrackSizes` 进行计算。
   - **处理块级尺寸依赖的网格项:** 在计算行尺寸后，检查是否有网格项的贡献大小依赖于块级尺寸的变化，并决定是否需要额外的布局Pass。
   - **递归处理子网格:**  遍历子网格并递归调用 `CompleteTrackSizingAlgorithm`。

7. **验证 MinMaxSizes 缓存 (Validate MinMaxSizes Cache):**
   - **处理子网格缓存失效:**  `ValidateMinMaxSizesCache` 函数用于检查和处理子网格的 `MinMaxSizes` 缓存失效的情况。
   - **考虑继承的轨道集合变化:**  当子网格继承了不同的轨道集合时，可能需要使其缓存失效。

8. **递归处理子网格 (ForEachSubgrid):**
   - **提供遍历子网格的通用方法:** `ForEachSubgrid` 是一个模板函数，用于遍历当前网格下的所有子网格，并执行回调函数。
   - **创建子网格的布局算法对象:**  为每个子网格创建一个新的 `GridLayoutAlgorithm` 对象。

9. **计算子网格的固有尺寸 (ComputeSubgridIntrinsicSize):**
   - **计算子网格的最小或最大尺寸:**  `ComputeSubgridIntrinsicSize` 用于计算子网格在特定方向上的固有尺寸（例如，最小内容尺寸或最大内容尺寸）。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS `grid-template-columns: 1fr 2fr;`**:  `ComputeUsedTrackSizes` 函数会处理 `fr` 单位，计算出这两个列的实际宽度，使得第二个列的宽度是第一个列的两倍。
* **CSS `grid-template-rows: min-content auto;`**: `ResolveIntrinsicTrackSizes` 会处理 `min-content` 关键字，计算出第一行的高度恰好包裹其内容所需的最小高度。
* **CSS `align-items: baseline;`**: `ComputeBaselineAlignment` 函数会根据网格项的基线位置来调整它们在行内的垂直位置，确保它们的文本基线对齐。
* **HTML `<div style="display: grid; grid-template-columns: subgrid;">...</div>`**: `CreateSubgridTrackCollection` 函数会被调用，为这个子网格创建一个继承自父网格列定义的轨道集合。
* **JavaScript 获取元素尺寸 `element.offsetWidth` / `element.offsetHeight`**:  虽然这段 C++ 代码不直接涉及 JavaScript，但其计算出的布局结果会被渲染引擎用于最终渲染，并可以通过 JavaScript API 查询到。

**逻辑推理的假设输入与输出：**

**假设输入：**

```css
.container {
  display: grid;
  grid-template-columns: 100px auto 1fr;
  grid-template-rows: min-content max-content;
}
.item {
  grid-column: 2 / 4;
  grid-row: 1;
}
```

**推断的 `ComputeUsedTrackSizes` 输出（针对列）：**

1. **第一列 (100px):**  尺寸固定为 100px。
2. **第二列 (auto):**  宽度会根据其内容自动调整到足以容纳最宽的内容。
3. **第三列 (1fr):**  会占据剩余的可用空间，其宽度与可用空间减去第一列和第二列的宽度成正比。

**假设输入（基线对齐）：**

```css
.container {
  display: grid;
  align-items: baseline;
}
.item1 {
  /* ... font-size: 16px; ... */
}
.item2 {
  /* ... font-size: 20px; ... */
}
```

**推断的 `ComputeBaselineAlignment` 行为：**

算法会找到 `item1` 和 `item2` 的基线位置，并调整它们在网格行中的垂直位置，使得它们的基线对齐。由于 `item2` 的字体更大，其顶部会相对更高一些。

**用户或编程常见的使用错误举例说明：**

* **误解 `fr` 单位的分配:**  开发者可能认为 `1fr 1fr` 会将剩余空间完全平分，但如果网格项有最小内容尺寸或最大内容尺寸的限制，实际分配可能会有所不同。
* **子网格配置错误:**  错误地定义子网格的行列范围可能导致布局混乱或子网格无法正确显示。例如，子网格的起始或结束行/列号超出了父网格的范围。
* **混淆 `align-items` 和 `align-content`:** 开发者可能将 `align-items: baseline;` 应用于一个只有单行的网格，期望内容垂直居中，但基线对齐只在多行或多项的情况下有意义。
* **循环依赖导致无限循环:**  在复杂的布局中，如果网格项的尺寸依赖于网格轨道的尺寸，而网格轨道的尺寸又依赖于网格项的尺寸，可能会导致布局引擎陷入无限循环尝试计算尺寸。Blink 的代码中会有机制来检测和避免这种情况。

**总结（基于提供的代码片段）：**

这段代码是 Chromium Blink 引擎中负责 CSS Grid 布局核心计算的重要组成部分，专注于：

- **计算网格轨道（行和列）的尺寸，** 包括处理固定尺寸、弹性尺寸、固有尺寸以及剩余空间的分配。
- **实现基线对齐，** 确保网格项内的文本内容能够按照基线进行对齐。
- **处理嵌套的子网格，**  为其创建和管理独立的轨道集合，并考虑其与父网格的尺寸和对齐关系。

这部分代码的功能是后续网格项定位和渲染的基础，它确保了 CSS Grid 布局规范在浏览器中的正确实现。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ck_collection.HasBaselines()) {
    return;
  }

  const auto writing_mode = GetConstraintSpace().GetWritingMode();
  track_collection.ResetBaselines();

  for (auto& grid_item :
       sizing_subtree.GetGridItems().IncludeSubgriddedItems()) {
    if (!grid_item.IsBaselineSpecified(track_direction) ||
        !grid_item.IsConsideredForSizing(track_direction)) {
      continue;
    }

    GridLayoutSubtree subgrid_layout_subtree;
    if (grid_item.IsSubgrid()) {
      subgrid_layout_subtree = GridLayoutSubtree(
          layout_tree, sizing_subtree.LookupSubgridIndex(grid_item));

      if (subgrid_layout_subtree.HasUnresolvedGeometry()) {
        // Calling `Layout` for a nested subgrid rely on the geometry of its
        // respective layout subtree to be fully resolved. Otherwise, the
        // subgrid won't be able to resolve its intrinsic sizes.
        continue;
      }
    }

    const auto subgridded_item =
        grid_item.is_subgridded_to_parent_grid
            ? sizing_subtree.LookupSubgriddedItemData(grid_item)
            : SubgriddedItemData(grid_item, sizing_subtree.LayoutData(),
                                 writing_mode);

    LayoutUnit inline_offset, block_offset;
    LogicalSize containing_grid_area_size = {
        ComputeGridItemAvailableSize(
            *subgridded_item, subgridded_item.ParentLayoutData().Columns(),
            &inline_offset),
        ComputeGridItemAvailableSize(*subgridded_item,
                                     subgridded_item.ParentLayoutData().Rows(),
                                     &block_offset)};
    // TODO(kschmi) : Add a cache slot parameter to
    //  `CreateConstraintSpaceForLayout` to avoid variables above.
    const auto space =
        CreateConstraintSpace(LayoutResultCacheSlot::kMeasure, *subgridded_item,
                              containing_grid_area_size,
                              /* fixed_available_size */ kIndefiniteLogicalSize,
                              std::move(subgrid_layout_subtree));

    // Skip this item if we aren't able to resolve our inline size.
    if (CalculateInitialFragmentGeometry(space, grid_item.node,
                                         /* break_token */ nullptr)
            .border_box_size.inline_size == kIndefiniteSize) {
      continue;
    }

    const auto* result =
        LayoutGridItemForMeasure(grid_item, space, sizing_constraint);

    const auto baseline_writing_direction =
        grid_item.BaselineWritingDirection(track_direction);
    const LogicalBoxFragment baseline_fragment(
        baseline_writing_direction,
        To<PhysicalBoxFragment>(result->GetPhysicalFragment()));

    const bool has_synthesized_baseline =
        !baseline_fragment.FirstBaseline().has_value();
    grid_item.SetAlignmentFallback(track_direction, has_synthesized_baseline);

    if (!grid_item.IsBaselineAligned(track_direction)) {
      continue;
    }

    const LayoutUnit extra_margin = GetExtraMarginForBaseline(
        ComputeMarginsFor(space, grid_item.node.Style(),
                          baseline_writing_direction),
        subgridded_item, track_direction, writing_mode);

    const LayoutUnit baseline =
        extra_margin +
        GetLogicalBaseline(grid_item, baseline_fragment, track_direction);

    // "If a box spans multiple shared alignment contexts, then it participates
    //  in first/last baseline alignment within its start-most/end-most shared
    //  alignment context along that axis"
    // https://www.w3.org/TR/css-align-3/#baseline-sharing-group
    const auto& [begin_set_index, end_set_index] =
        grid_item.SetIndices(track_direction);
    if (grid_item.BaselineGroup(track_direction) == BaselineGroup::kMajor) {
      track_collection.SetMajorBaseline(begin_set_index, baseline);
    } else {
      track_collection.SetMinorBaseline(end_set_index - 1, baseline);
    }
  }
}

std::unique_ptr<GridLayoutTrackCollection>
GridLayoutAlgorithm::CreateSubgridTrackCollection(
    const SubgriddedItemData& subgrid_data,
    GridTrackSizingDirection track_direction) const {
  DCHECK(subgrid_data.IsSubgrid());

  const bool is_for_columns_in_parent = subgrid_data->is_parallel_with_root_grid
                                            ? track_direction == kForColumns
                                            : track_direction == kForRows;
  const auto& parent_track_collection =
      is_for_columns_in_parent ? subgrid_data.Columns() : subgrid_data.Rows();

  const auto& range_indices = is_for_columns_in_parent
                                  ? subgrid_data->column_range_indices
                                  : subgrid_data->row_range_indices;

  return std::make_unique<GridLayoutTrackCollection>(
      parent_track_collection.CreateSubgridTrackCollection(
          range_indices.begin, range_indices.end,
          GutterSize(track_direction, parent_track_collection.GutterSize()),
          ComputeMarginsForSelf(GetConstraintSpace(), Style()),
          BorderScrollbarPadding(), track_direction,
          is_for_columns_in_parent
              ? subgrid_data->is_opposite_direction_in_root_grid_columns
              : subgrid_data->is_opposite_direction_in_root_grid_rows));
}

void GridLayoutAlgorithm::InitializeTrackCollection(
    const SubgriddedItemData& opt_subgrid_data,
    GridTrackSizingDirection track_direction,
    GridLayoutData* layout_data) const {
  if (layout_data->HasSubgriddedAxis(track_direction)) {
    // If we don't have a sizing collection for this axis, then we're in a
    // subgrid that must inherit the track collection of its parent grid.
    DCHECK(opt_subgrid_data.IsSubgrid());

    layout_data->SetTrackCollection(
        CreateSubgridTrackCollection(opt_subgrid_data, track_direction));
    return;
  }

  auto& track_collection = layout_data->SizingCollection(track_direction);
  track_collection.BuildSets(Style(),
                             (track_direction == kForColumns)
                                 ? grid_available_size_.inline_size
                                 : grid_available_size_.block_size,
                             GutterSize(track_direction));
}

namespace {

GridTrackSizingDirection RelativeDirectionInSubgrid(
    GridTrackSizingDirection track_direction,
    const GridItemData& subgrid_data) {
  DCHECK(subgrid_data.IsSubgrid());

  const bool is_for_columns = subgrid_data.is_parallel_with_root_grid ==
                              (track_direction == kForColumns);
  return is_for_columns ? kForColumns : kForRows;
}

std::optional<GridTrackSizingDirection> RelativeDirectionFilterInSubgrid(
    const std::optional<GridTrackSizingDirection>& opt_track_direction,
    const GridItemData& subgrid_data) {
  DCHECK(subgrid_data.IsSubgrid());

  if (opt_track_direction) {
    return RelativeDirectionInSubgrid(*opt_track_direction, subgrid_data);
  }
  return std::nullopt;
}

}  // namespace

void GridLayoutAlgorithm::InitializeTrackSizes(
    const GridSizingSubtree& sizing_subtree,
    const SubgriddedItemData& opt_subgrid_data,
    const std::optional<GridTrackSizingDirection>& opt_track_direction) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  auto& grid_items = sizing_subtree.GetGridItems();
  auto& layout_data = sizing_subtree.LayoutData();

  auto InitAndCacheTrackSizes = [&](GridTrackSizingDirection track_direction) {
    InitializeTrackCollection(opt_subgrid_data, track_direction, &layout_data);

    if (layout_data.HasSubgriddedAxis(track_direction)) {
      const auto& track_collection = (track_direction == kForColumns)
                                         ? layout_data.Columns()
                                         : layout_data.Rows();
      for (auto& grid_item : grid_items) {
        grid_item.ComputeSetIndices(track_collection);
      }
    } else {
      auto& track_collection = layout_data.SizingCollection(track_direction);
      CacheGridItemsProperties(track_collection, &grid_items);

      const bool is_for_columns = track_direction == kForColumns;
      const auto start_border_scrollbar_padding =
          is_for_columns ? BorderScrollbarPadding().inline_start
                         : BorderScrollbarPadding().block_start;

      // If all tracks have a definite size upfront, we can use the current set
      // sizes as the used track sizes (applying alignment, if present).
      if (!track_collection.HasNonDefiniteTrack()) {
        auto first_set_geometry = ComputeFirstSetGeometry(
            track_collection, Style(),
            is_for_columns ? grid_available_size_.inline_size
                           : grid_available_size_.block_size,
            start_border_scrollbar_padding);

        track_collection.FinalizeSetsGeometry(first_set_geometry.start_offset,
                                              first_set_geometry.gutter_size);
      } else {
        track_collection.CacheInitializedSetsGeometry(
            start_border_scrollbar_padding);
      }

      if (track_collection.HasBaselines()) {
        track_collection.ResetBaselines();
      }
    }
  };

  if (opt_track_direction) {
    InitAndCacheTrackSizes(*opt_track_direction);
  } else {
    InitAndCacheTrackSizes(kForColumns);
    InitAndCacheTrackSizes(kForRows);
  }

  ForEachSubgrid(
      sizing_subtree,
      [&](const GridLayoutAlgorithm& subgrid_algorithm,
          const GridSizingSubtree& subgrid_subtree,
          const SubgriddedItemData& subgrid_data) {
        subgrid_algorithm.InitializeTrackSizes(
            subgrid_subtree, subgrid_data,
            RelativeDirectionFilterInSubgrid(opt_track_direction,
                                             *subgrid_data));
      },
      /* should_compute_min_max_sizes */ false);
}

void GridLayoutAlgorithm::InitializeTrackSizes(
    const GridSizingTree& sizing_tree,
    const std::optional<GridTrackSizingDirection>& opt_track_direction) const {
  InitializeTrackSizes(GridSizingSubtree(sizing_tree),
                       /* opt_subgrid_data */ kNoSubgriddedItemData,
                       opt_track_direction);
}

namespace {

struct BlockSizeDependentGridItem {
  GridItemIndices row_set_indices;
  LayoutUnit cached_block_size;
};

Vector<BlockSizeDependentGridItem> BlockSizeDependentGridItems(
    const GridItems& grid_items,
    const GridSizingTrackCollection& track_collection) {
  DCHECK_EQ(track_collection.Direction(), kForRows);

  Vector<BlockSizeDependentGridItem> dependent_items;
  dependent_items.ReserveInitialCapacity(grid_items.Size());

  // TODO(ethavar): We need to take into account the block size dependent
  // subgridded items that might change its contribution size in a nested
  // subgrid's standalone axis, but doing so implies a more refined change.
  // We'll revisit this issue in a later patch, in the meantime we simply
  // want to skip over subgridded items to avoid DCHECKs.
  for (const auto& grid_item : grid_items) {
    if (!grid_item.is_sizing_dependent_on_block_size)
      continue;

    const auto& set_indices = grid_item.SetIndices(kForRows);
    BlockSizeDependentGridItem dependent_item = {
        set_indices, track_collection.ComputeSetSpanSize(set_indices.begin,
                                                         set_indices.end)};
    dependent_items.emplace_back(std::move(dependent_item));
  }
  return dependent_items;
}

bool MayChangeBlockSizeDependentGridItemContributions(
    const Vector<BlockSizeDependentGridItem>& dependent_items,
    const GridSizingTrackCollection& track_collection) {
  DCHECK_EQ(track_collection.Direction(), kForRows);

  for (const auto& grid_item : dependent_items) {
    const LayoutUnit block_size = track_collection.ComputeSetSpanSize(
        grid_item.row_set_indices.begin, grid_item.row_set_indices.end);

    DCHECK_NE(block_size, kIndefiniteSize);
    if (block_size != grid_item.cached_block_size)
      return true;
  }
  return false;
}

}  // namespace

// https://drafts.csswg.org/css-grid-2/#algo-track-sizing
void GridLayoutAlgorithm::ComputeUsedTrackSizes(
    const GridSizingSubtree& sizing_subtree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint,
    bool* opt_needs_additional_pass) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  auto& track_collection =
      sizing_subtree.LayoutData().SizingCollection(track_direction);

  track_collection.BuildSets(Style(),
                             (track_direction == kForColumns)
                                 ? grid_available_size_.inline_size
                                 : grid_available_size_.block_size,
                             GutterSize(track_direction));

  // 2. Resolve intrinsic track sizing functions to absolute lengths.
  if (track_collection.HasIntrinsicTrack()) {
    ResolveIntrinsicTrackSizes(sizing_subtree, track_direction,
                               sizing_constraint);
  }

  // If any track still has an infinite growth limit (i.e. it had no items
  // placed in it), set its growth limit to its base size before maximizing.
  track_collection.SetIndefiniteGrowthLimitsToBaseSize();

  // 3. If the free space is positive, distribute it equally to the base sizes
  // of all tracks, freezing tracks as they reach their growth limits (and
  // continuing to grow the unfrozen tracks as needed).
  MaximizeTracks(sizing_constraint, &track_collection);

  // 4. This step sizes flexible tracks using the largest value it can assign to
  // an 'fr' without exceeding the available space.
  if (track_collection.HasFlexibleTrack()) {
    ExpandFlexibleTracks(sizing_subtree, track_direction, sizing_constraint);
  }

  // 5. Stretch tracks with an 'auto' max track sizing function.
  StretchAutoTracks(sizing_constraint, &track_collection);
}

void GridLayoutAlgorithm::CompleteTrackSizingAlgorithm(
    const GridSizingSubtree& sizing_subtree,
    const SubgriddedItemData& opt_subgrid_data,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint,
    bool* opt_needs_additional_pass) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  auto& layout_data = sizing_subtree.LayoutData();

  const bool is_for_columns = track_direction == kForColumns;
  const bool has_non_definite_track =
      is_for_columns ? layout_data.Columns().HasNonDefiniteTrack()
                     : layout_data.Rows().HasNonDefiniteTrack();

  if (has_non_definite_track) {
    if (layout_data.HasSubgriddedAxis(track_direction)) {
      // If we don't have a sizing collection for this axis, then we're in a
      // subgrid that must inherit the track collection of its parent grid.
      DCHECK(opt_subgrid_data.IsSubgrid());

      layout_data.SetTrackCollection(
          CreateSubgridTrackCollection(opt_subgrid_data, track_direction));
    } else {
      ComputeUsedTrackSizes(sizing_subtree, track_direction, sizing_constraint,
                            opt_needs_additional_pass);

      // After computing row sizes, if we're still trying to determine whether
      // we need to perform and additional pass, check if there is a grid item
      // whose contributions may change with the new available block size.
      const bool needs_to_check_block_size_dependent_grid_items =
          !is_for_columns && opt_needs_additional_pass &&
          !(*opt_needs_additional_pass);

      Vector<BlockSizeDependentGridItem> block_size_dependent_grid_items;
      auto& track_collection = layout_data.SizingCollection(track_direction);

      if (needs_to_check_block_size_dependent_grid_items) {
        block_size_dependent_grid_items = BlockSizeDependentGridItems(
            sizing_subtree.GetGridItems(), track_collection);
      }

      auto first_set_geometry = ComputeFirstSetGeometry(
          track_collection, Style(),
          is_for_columns ? grid_available_size_.inline_size
                         : grid_available_size_.block_size,
          is_for_columns ? BorderScrollbarPadding().inline_start
                         : BorderScrollbarPadding().block_start);

      track_collection.FinalizeSetsGeometry(first_set_geometry.start_offset,
                                            first_set_geometry.gutter_size);

      if (needs_to_check_block_size_dependent_grid_items) {
        *opt_needs_additional_pass =
            MayChangeBlockSizeDependentGridItemContributions(
                block_size_dependent_grid_items, track_collection);
      }
    }
  }

  ForEachSubgrid(
      sizing_subtree, [&](const GridLayoutAlgorithm& subgrid_algorithm,
                          const GridSizingSubtree& subgrid_subtree,
                          const SubgriddedItemData& subgrid_data) {
        subgrid_algorithm.CompleteTrackSizingAlgorithm(
            subgrid_subtree, subgrid_data,
            RelativeDirectionInSubgrid(track_direction, *subgrid_data),
            sizing_constraint, opt_needs_additional_pass);
      });
}

namespace {

// A subgrid's `MinMaxSizes` cache is stored in its respective `LayoutGrid` and
// gets invalidated via the `IsSubgridMinMaxSizesCacheDirty` flag.
//
// However, a subgrid might need to invalidate the cache if it inherited a
// different track collection in its subgridded axis, which might cause its
// intrinsic sizes to change. This invalidation goes from parent to children,
// which is not accounted for by the invalidation logic in `LayoutObject`.
//
// This method addresses such issue by traversing the tree in postorder checking
// whether the cache at each subgrid level is reusable or not: if the subgrid
// has a valid cache, but its input tracks for the subgridded axis changed,
// then we'll invalidate the cache for that subgrid and its ancestors.
bool ValidateMinMaxSizesCache(const GridNode& grid_node,
                              const GridSizingSubtree& sizing_subtree,
                              GridTrackSizingDirection track_direction) {
  DCHECK(sizing_subtree.HasValidRootFor(grid_node));

  bool should_invalidate_min_max_sizes_cache = false;

  // Only iterate over items if this grid has nested subgrids.
  if (auto next_subgrid_subtree = sizing_subtree.FirstChild()) {
    for (const auto& grid_item : sizing_subtree.GetGridItems()) {
      if (!grid_item.IsSubgrid()) {
        continue;
      }

      DCHECK(next_subgrid_subtree);
      should_invalidate_min_max_sizes_cache |= ValidateMinMaxSizesCache(
          To<GridNode>(grid_item.node), next_subgrid_subtree,
          RelativeDirectionInSubgrid(track_direction, grid_item));
      next_subgrid_subtree = next_subgrid_subtree.NextSibling();
    }
  }

  const auto& layout_data = sizing_subtree.LayoutData();
  if (layout_data.IsSubgridWithStandaloneAxis(track_direction)) {
    // If no nested subgrid marked this subtree to be invalidated already, check
    // that the cached intrinsic sizes are reusable by the current sizing tree.
    if (!should_invalidate_min_max_sizes_cache) {
      should_invalidate_min_max_sizes_cache =
          grid_node.ShouldInvalidateSubgridMinMaxSizesCacheFor(layout_data);
    }

    if (should_invalidate_min_max_sizes_cache) {
      grid_node.InvalidateSubgridMinMaxSizesCache();
    }
  }
  return should_invalidate_min_max_sizes_cache;
}

}  // namespace

void GridLayoutAlgorithm::CompleteTrackSizingAlgorithm(
    const GridSizingTree& sizing_tree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint,
    bool* opt_needs_additional_pass) const {
  const auto sizing_subtree = GridSizingSubtree(sizing_tree);

  ValidateMinMaxSizesCache(Node(), sizing_subtree, track_direction);

  ComputeBaselineAlignment(sizing_tree.FinalizeTree(), sizing_subtree,
                           /* opt_subgrid_data */ kNoSubgriddedItemData,
                           track_direction, sizing_constraint);

  CompleteTrackSizingAlgorithm(
      sizing_subtree, /* opt_subgrid_data */ kNoSubgriddedItemData,
      track_direction, sizing_constraint, opt_needs_additional_pass);
}

void GridLayoutAlgorithm::ComputeBaselineAlignment(
    const scoped_refptr<const GridLayoutTree>& layout_tree,
    const GridSizingSubtree& sizing_subtree,
    const SubgriddedItemData& opt_subgrid_data,
    const std::optional<GridTrackSizingDirection>& opt_track_direction,
    SizingConstraint sizing_constraint) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  auto& layout_data = sizing_subtree.LayoutData();

  auto ComputeOrRecreateBaselines =
      [&](GridTrackSizingDirection track_direction) {
        if (layout_data.HasSubgriddedAxis(track_direction)) {
          DCHECK(opt_subgrid_data.IsSubgrid());
          // Recreate the subgrid track collection if there are baselines which
          // need to be inherited.
          const bool is_for_columns_in_parent =
              opt_subgrid_data->is_parallel_with_root_grid
                  ? track_direction == kForColumns
                  : track_direction == kForRows;
          const auto& parent_track_collection = is_for_columns_in_parent
                                                    ? opt_subgrid_data.Columns()
                                                    : opt_subgrid_data.Rows();
          if (parent_track_collection.HasBaselines()) {
            layout_data.SetTrackCollection(CreateSubgridTrackCollection(
                opt_subgrid_data, track_direction));
          }
        } else {
          ComputeGridItemBaselines(layout_tree, sizing_subtree, track_direction,
                                   sizing_constraint);
        }
      };

  if (opt_track_direction) {
    ComputeOrRecreateBaselines(*opt_track_direction);
  } else {
    ComputeOrRecreateBaselines(kForColumns);
    ComputeOrRecreateBaselines(kForRows);
  }

  ForEachSubgrid(sizing_subtree,
                 [&](const GridLayoutAlgorithm& subgrid_algorithm,
                     const GridSizingSubtree& subgrid_subtree,
                     const SubgriddedItemData& subgrid_data) {
                   subgrid_algorithm.ComputeBaselineAlignment(
                       layout_tree, subgrid_subtree, subgrid_data,
                       RelativeDirectionFilterInSubgrid(opt_track_direction,
                                                        *subgrid_data),
                       sizing_constraint);
                 });
}

void GridLayoutAlgorithm::CompleteFinalBaselineAlignment(
    const GridSizingTree& sizing_tree) const {
  ComputeBaselineAlignment(
      sizing_tree.FinalizeTree(), GridSizingSubtree(sizing_tree),
      /* opt_subgrid_data */ kNoSubgriddedItemData,
      /* opt_track_direction */ std::nullopt, SizingConstraint::kLayout);
}

template <typename CallbackFunc>
void GridLayoutAlgorithm::ForEachSubgrid(
    const GridSizingSubtree& sizing_subtree,
    const CallbackFunc& callback_func,
    bool should_compute_min_max_sizes) const {
  // Exit early if this subtree doesn't have nested subgrids.
  auto next_subgrid_subtree = sizing_subtree.FirstChild();
  if (!next_subgrid_subtree) {
    return;
  }

  const auto& layout_data = sizing_subtree.LayoutData();

  for (const auto& grid_item : sizing_subtree.GetGridItems()) {
    if (!grid_item.IsSubgrid()) {
      continue;
    }

    const auto space = CreateConstraintSpaceForLayout(grid_item, layout_data);
    const auto fragment_geometry = CalculateInitialFragmentGeometryForSubgrid(
        grid_item, space,
        should_compute_min_max_sizes ? next_subgrid_subtree
                                     : kNoGridSizingSubtree);

    const GridLayoutAlgorithm subgrid_algorithm(
        {grid_item.node, fragment_geometry, space});

    DCHECK(next_subgrid_subtree);
    callback_func(subgrid_algorithm, next_subgrid_subtree,
                  SubgriddedItemData(grid_item, layout_data,
                                     GetConstraintSpace().GetWritingMode()));

    next_subgrid_subtree = next_subgrid_subtree.NextSibling();
  }
}

LayoutUnit GridLayoutAlgorithm::ComputeSubgridIntrinsicSize(
    const GridSizingSubtree& sizing_subtree,
    GridTrackSizingDirection track_direction,
    SizingConstraint sizing_constraint) const {
  DCHECK(sizing_subtree.HasValidRootFor(Node()));

  ComputeUsedTrackSizes(sizing_subtree, track_direction, sizing_constraint,
                        /* opt_needs_additional_pass */ nullptr);

  const auto border_scrollbar_padding =
      (track_direction == kForColumns) ? BorderScrollbarPadding().InlineSum()
                                       : BorderScrollbarPadding().BlockSum();

  return border_scrollbar_padding + sizing_subtree.LayoutData()
                                        .SizingCollection(track_direction)
                                        .TotalTrackSize();
}

// Helpers for the track sizing algorithm.
namespace {

using ClampedFloat = base::ClampedNumeric<float>;
using SetIterator = GridSizingTrackCollection::SetIterator;

const float kFloatEpsilon = std::numeric_limits<float>::epsilon();

SetIterator GetSetIteratorForItem(const GridItemData& grid_item,
                                  GridSizingTrackCollection& track_collection) {
  const auto& set_indices = grid_item.SetIndices(track_collection.Direction());
  return track_collection.GetSetIterator(set_indices.begin, set_indices.end);
}

LayoutUnit DefiniteGrowthLimit(const GridSet& set) {
  LayoutUnit growth_limit = set.GrowthLimit();
  // For infinite growth limits, substitute the track’s base size.
  return (growth_limit == kIndefiniteSize) ? set.BaseSize() : growth_limit;
}

// Returns the corresponding size to be increased by accommodating a grid item's
// contribution; for intrinsic min track sizing functions, return the base size.
// For intrinsic max track sizing functions, return the growth limit.
LayoutUnit AffectedSizeForContribution(
    const GridSet& set,
    GridItemContributionType contribution_type) {
  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
    case GridItemContributionType::kForContentBasedMinimums:
    case GridItemContributionType::kForMaxContentMinimums:
      return set.BaseSize();
    case GridItemContributionType::kForIntrinsicMaximums:
    case GridItemContributionType::kForMaxContentMaximums:
      return DefiniteGrowthLimit(set);
    case GridItemContributionType::kForFreeSpace:
      NOTREACHED();
  }
}

void GrowAffectedSizeByPlannedIncrease(
    GridItemContributionType contribution_type,
    GridSet* set) {
  DCHECK(set);

  set->is_infinitely_growable = false;
  const LayoutUnit planned_increase = set->planned_increase;

  // Only grow sets that accommodated a grid item.
  if (planned_increase == kIndefiniteSize)
    return;

  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
    case GridItemContributionType::kForContentBasedMinimums:
    case GridItemContributionType::kForMaxContentMinimums:
      set->IncreaseBaseSize(set->BaseSize() + planned_increase);
      return;
    case GridItemContributionType::kForIntrinsicMaximums:
      // Mark any tracks whose growth limit changed from infinite to finite in
      // this step as infinitely growable for the next step.
      set->is_infinitely_growable = set->GrowthLimit() == kIndefiniteSize;
      set->IncreaseGrowthLimit(DefiniteGrowthLimit(*set) + planned_increase);
      return;
    case GridItemContributionType::kForMaxContentMaximums:
      set->IncreaseGrowthLimit(DefiniteGrowthLimit(*set) + planned_increase);
      return;
    case GridItemContributionType::kForFreeSpace:
      NOTREACHED();
  }
}

void AccomodateSubgridExtraMargins(
    LayoutUnit start_extra_margin,
    LayoutUnit end_extra_margin,
    GridItemIndices set_indices,
    GridSizingTrackCollection* track_collection) {
  auto AccomodateExtraMargin = [track_collection](LayoutUnit extra_margin,
                                                  wtf_size_t set_index) {
    auto& set = track_collection->GetSetAt(set_index);

    if (set.track_size.HasIntrinsicMinTrackBreadth() &&
        set.BaseSize() < extra_margin) {
      set.IncreaseBaseSize(extra_margin);
    }
  };

  if (set_indices.begin == set_indices.end - 1) {
    AccomodateExtraMargin(start_extra_margin + end_extra_margin,
                          set_indices.begin);
  } else {
    AccomodateExtraMargin(start_extra_margin, set_indices.begin);
    AccomodateExtraMargin(end_extra_margin, set_indices.end - 1);
  }
}

// Returns true if a set should increase its used size according to the steps in
// https://drafts.csswg.org/css-grid-2/#algo-spanning-items; false otherwise.
bool IsContributionAppliedToSet(const GridSet& set,
                                GridItemContributionType contribution_type) {
  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
      return set.track_size.HasIntrinsicMinTrackBreadth();
    case GridItemContributionType::kForContentBasedMinimums:
      return set.track_size.HasMinOrMaxContentMinTrackBreadth();
    case GridItemContributionType::kForMaxContentMinimums:
      // TODO(ethavar): Check if the grid container is being sized under a
      // 'max-content' constraint to consider 'auto' min track sizing functions,
      // see https://drafts.csswg.org/css-grid-2/#track-size-max-content-min.
      return set.track_size.HasMaxContentMinTrackBreadth();
    case GridItemContributionType::kForIntrinsicMaximums:
      return set.track_size.HasIntrinsicMaxTrackBreadth();
    case GridItemContributionType::kForMaxContentMaximums:
      return set.track_size.HasMaxContentOrAutoMaxTrackBreadth();
    case GridItemContributionType::kForFreeSpace:
      return true;
  }
}

// https://drafts.csswg.org/css-grid-2/#extra-space
// Returns true if a set's used size should be consider to grow beyond its limit
// (see the "Distribute space beyond limits" section); otherwise, false.
// Note that we will deliberately return false in cases where we don't have a
// collection of tracks different than "all affected tracks".
bool ShouldUsedSizeGrowBeyondLimit(const GridSet& set,
                                   GridItemContributionType contribution_type) {
  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
    case GridItemContributionType::kForContentBasedMinimums:
      return set.track_size.HasIntrinsicMaxTrackBreadth();
    case GridItemContributionType::kForMaxContentMinimums:
      return set.track_size.HasMaxContentOrAutoMaxTrackBreadth();
    case GridItemContributionType::kForIntrinsicMaximums:
    case GridItemContributionType::kForMaxContentMaximums:
    case GridItemContributionType::kForFreeSpace:
      return false;
  }
}

bool IsDistributionForGrowthLimits(GridItemContributionType contribution_type) {
  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
    case GridItemContributionType::kForContentBasedMinimums:
    case GridItemContributionType::kForMaxContentMinimums:
    case GridItemContributionType::kForFreeSpace:
      return false;
    case GridItemContributionType::kForIntrinsicMaximums:
    case GridItemContributionType::kForMaxContentMaximums:
      return true;
  }
}

enum class InfinitelyGrowableBehavior { kEnforce, kIgnore };

// We define growth potential = limit - affected size; for base sizes, the limit
// is its growth limit. For growth limits, the limit is infinity if it is marked
// as "infinitely growable", and equal to the growth limit otherwise.
LayoutUnit GrowthPotentialForSet(
    const GridSet& set,
    GridItemContributionType contribution_type,
    InfinitelyGrowableBehavior infinitely_growable_behavior =
        InfinitelyGrowableBehavior::kEnforce) {
  switch (contribution_type) {
    case GridItemContributionType::kForIntrinsicMinimums:
    case GridItemContributionType::kForContentBasedMinimums:
    case GridItemContributionType::kForMaxContentMinimums: {
      LayoutUnit growth_limit = set.GrowthLimit();
      if (growth_limit == kIndefiniteSize)
        return kIndefiniteSize;

      LayoutUnit increased_base_size =
          set.BaseSize() + set.item_incurred_increase;
      DCHECK_LE(increased_base_size, growth_limit);
      return growth_limit - increased_base_size;
    }
    case GridItemContributionType::kForIntrinsicMaximums:
    case GridItemContributionType::kForMaxContentMaximums: {
      if (infinitely_growable_behavior ==
              InfinitelyGrowableBehavior::kEnforce &&
          set.GrowthLimit() != kIndefiniteSize && !set.is_infinitely_growable) {
        // For growth limits, the potential is infinite if its value is infinite
        // too or if the set is marked as infinitely growable; otherwise, zero.
        return LayoutUnit();
      }

      DCHECK(set.fit_content_limit >= 0 ||
             set.fit_content_limit == kIndefiniteSize);

      // The max track sizing function of a 'fit-content' track is treated as
      // 'max-content
```