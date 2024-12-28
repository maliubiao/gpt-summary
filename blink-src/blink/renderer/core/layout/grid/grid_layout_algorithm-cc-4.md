Response:
My thought process for summarizing the provided code snippet goes through these stages:

1. **Identify the Core Task:** The file name `grid_layout_algorithm.cc` immediately tells me this code is responsible for the core logic of laying out grid items within a CSS Grid container. The current snippet is just a part of this larger algorithm.

2. **Scan for Key Actions and Concepts:** I quickly read through the code, looking for recurring verbs and nouns that indicate the main operations. I see terms like:
    * `FindFrSize`:  This strongly suggests handling of `fr` units (flexible lengths).
    * `free space`:  This refers to the available space after fixed-size tracks are accounted for.
    * `track_collection`:  Represents the grid's rows or columns.
    * `grid_item`: The individual elements placed within the grid.
    * `base size`, `expanded_size`: Indicate the process of calculating track sizes.
    * `gutter size`:  Handling the spacing between grid tracks.
    * `DetermineFreeSpace`:  Calculating the available space based on sizing constraints.
    * `AlignmentOffset`:  Calculating the position of grid items within their grid areas based on alignment properties.
    * `CreateConstraintSpace`: Setting up the constraints under which individual grid items will be laid out.
    * `PlaceGridItems`, `PlaceGridItemsForFragmentation`: The core functions responsible for positioning the grid items.
    * `BaselineAccumulator`:  Dealing with the alignment of content based on baselines.
    * `row_break_between`:  Handling page breaks within the grid layout.
    * `fragmentation`:  Dealing with how the grid layout is broken across multiple pages or columns.

3. **Group Related Actions:**  I start grouping the identified concepts into functional blocks:
    * **Flexible Track Sizing:**  The `FindFrSize` logic and the loop iterating over flexible tracks. This clearly deals with how `fr` units are resolved.
    * **Gutter Sizing:** The `GutterSize` function is straightforward.
    * **Free Space Calculation:** The `DetermineFreeSpace` function.
    * **Alignment:** The `AlignmentOffset` and related functions.
    * **Constraint Space Creation:**  The various `CreateConstraintSpace` functions.
    * **Grid Item Placement (Basic):** The `PlaceGridItems` function.
    * **Grid Item Placement (Fragmentation):** The `PlaceGridItemsForFragmentation` function.
    * **Baseline Handling:** The `BaselineAccumulator` and related logic within `PlaceGridItems`.
    * **Fragmentation Handling:** Logic within `PlaceGridItemsForFragmentation` related to breakpoints and handling items spanning across fragments.

4. **Infer Purpose and Relationships:**  Now, I start connecting the dots and understanding the "why" behind the code.
    * **`fr` Unit Resolution:** The code aims to distribute available space proportionally to the `fr` factors of the flexible tracks. It handles both definite and indefinite available space.
    * **Alignment:**  The code implements the CSS grid alignment properties (`justify-items`, `align-items`, `justify-content`, `align-content`).
    * **Constraint Spaces:** The constraint spaces define the environment under which individual grid items are laid out, taking into account subgrids and fragmentation.
    * **Placement:** The `PlaceGridItems` functions are the culmination of the sizing and alignment calculations, actually positioning the elements.
    * **Fragmentation:** The fragmentation logic is crucial for handling grids that need to be split across multiple pages or columns.

5. **Consider Interactions with Web Technologies:** I think about how these functions relate to HTML, CSS, and JavaScript:
    * **CSS:**  This code directly implements CSS Grid Layout features like `grid-template-columns`, `grid-template-rows`, `fr` units, `gap`, `justify-items`, `align-items`, `justify-content`, `align-content`, `min-width`, `max-width`, `min-height`, `max-height`, and fragmentation properties (`break-before`, `break-after`, `break-inside`).
    * **HTML:** The structure of the HTML content (the grid container and its items) dictates how this code will operate. The code iterates over `grid_item` data, which is derived from the HTML structure.
    * **JavaScript:** While this specific file is C++, the results of this layout algorithm are used by the rendering engine to display the web page. JavaScript can manipulate the CSS properties that trigger this layout code.

6. **Identify Potential Errors:** I consider common mistakes developers might make:
    * Incorrect use of `fr` units leading to unexpected sizing.
    * Conflicting alignment properties.
    * Not understanding how fragmentation affects layout.
    * Incorrectly specifying grid areas.

7. **Structure the Summary:**  Finally, I organize my thoughts into a clear and concise summary, using headings and bullet points to make it easy to read. I aim to address the prompt's specific questions about functionality, relationships with web technologies, logical inferences, potential errors, and the overall purpose of the code snippet. I also make sure to note that this is only a part of the larger file.

By following these steps, I can effectively analyze and summarize even complex code snippets like the one provided, extracting the key information and understanding its role within the larger system.好的，让我们归纳一下这部分代码的功能。

**核心功能归纳：**

这部分代码主要负责 CSS Grid 布局算法中的 **处理弹性 (flexible, `fr` 单位) 轨道大小** 和 **计算和应用网格项的对齐方式**，以及为后续的网格项布局创建必要的约束空间。它还涉及处理网格的 **分页 (fragmentation)** 问题。

**具体功能点：**

1. **计算弹性轨道大小 (`FindFrSize` 函数部分):**
    *   **处理确定可用空间：** 如果网格容器有明确的尺寸限制，则根据可用空间和所有网格轨道的需求，计算 `fr` 单位的大小。
    *   **处理不确定可用空间：** 如果网格容器的尺寸是不确定的（例如，内容自适应），则需要考虑每个跨越弹性轨道的网格项的最大内容贡献，以及每个弹性轨道自身的 `base size` 和 `flex factor`，来确定 `fr` 单位的大小。
    *   **处理精度问题：**  由于 `fr` 单位的计算可能产生浮点数，代码会累积小的剩余部分，以确保所有可用空间被尽可能准确地分配。
    *   **TODO：处理 `min-width/height` 和 `max-width/height`：** 代码中有一个 TODO 注释，指出未来需要考虑容器的 `min-width/height` 和 `max-width/height` 属性对 `fr` 单位计算的影响。

2. **计算网格间距 (`GutterSize` 函数):**
    *   根据 CSS 属性 `column-gap` 和 `row-gap` 的值，计算列和行之间的间距大小。
    *   如果未指定间距，则对于独立网格使用默认值 0，对于子网格使用父网格的间距大小。

3. **确定可用空间 (`DetermineFreeSpace` 函数):**
    *   根据不同的尺寸约束 (`SizingConstraint`)，计算网格布局中可用的自由空间。
    *   对于 `kLayout` 约束，计算容器的可用空间减去所有轨道大小的总和。如果轨道占用空间超过容器可用空间，则自由空间为 0。
    *   对于 `kMaxContent` 约束，自由空间被认为是无限的。
    *   对于 `kMinContent` 约束，自由空间为 0。

4. **计算对齐偏移 (`AlignmentOffset` 函数及其调用处):**
    *   计算网格项在其网格区域内的对齐偏移量，考虑了 `justify-items`、`align-items` 等 CSS 属性、边距以及基线对齐。
    *   `AlignmentOffsetForOutOfFlow` 函数处理浮动定位元素的对齐。

5. **创建约束空间 (`CreateConstraintSpace` 系列函数):**
    *   为每个网格项创建一个 `ConstraintSpace` 对象，该对象包含了布局所需的各种约束信息，例如可用尺寸、书写模式、是否为新的格式化上下文等。
    *   `CreateConstraintSpaceForLayout` 用于常规布局，考虑了网格区域的大小、子网格的情况以及不可用的块大小。
    *   `CreateConstraintSpaceForMeasure` 用于测量子网格项的大小。

6. **放置网格项 (`PlaceGridItems` 函数):**
    *   遍历所有网格项，并根据其计算出的位置和对齐方式，将它们放置在网格中。
    *   考虑了相对定位的偏移量。
    *   如果需要处理分页，则只记录初始位置。
    *   处理基线对齐，并记录网格的第一个和最后一个基线位置。
    *   处理分页符 (`break-before`, `break-after`)。

7. **处理分页情况下的网格项放置 (`PlaceGridItemsForFragmentation` 函数):**
    *   专门处理网格在分页时的布局。
    *   核心思想是确定在分页符处如何分割网格，并调整后续页面的布局。
    *   会考虑 `min-block-size` 是否应该包含其固有大小，以及项目是否跨越多行。
    *   维护一个 `BaselineAccumulator` 来处理分页情况下的基线。
    *   处理由于分页符导致的行扩展。

**与 JavaScript, HTML, CSS 的关系：**

*   **CSS:** 这部分代码是 **直接实现 CSS Grid Layout 规范** 的核心逻辑。例如：
    *   **`fr` 单位:**  `FindFrSize` 函数直接对应了 CSS 中 `fr` 单位的计算规则。
    *   **`column-gap`, `row-gap`:** `GutterSize` 函数处理了这些 CSS 属性。
    *   **`justify-items`, `align-items`:** `AlignmentOffset` 函数及其调用处实现了这些对齐属性。
    *   **`break-before`, `break-after`, `break-inside`:** `PlaceGridItems` 和 `PlaceGridItemsForFragmentation` 函数中处理了这些分页属性。
    *   **`min-width`, `max-width`, `min-height`, `max-height`:** 虽然当前代码片段的 TODO 中提到了，但这些属性会影响可用空间的计算，从而间接影响 `fr` 单位的计算和最终布局。

*   **HTML:** HTML 结构定义了网格容器及其子项，这部分代码读取这些信息 (`grid_item`) 并进行布局计算。

*   **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而触发这部分 C++ 代码的执行。例如，通过 JavaScript 修改元素的 `display: grid` 或相关的网格属性，会导致浏览器重新运行这部分布局算法。

**逻辑推理的假设输入与输出：**

假设有以下简单的 HTML 和 CSS：

```html
<div style="display: grid; width: 300px; grid-template-columns: 1fr 2fr;">
  <div>Item 1</div>
  <div>Item 2</div>
</div>
```

**假设输入：**

*   `grid_available_size_.inline_size` (容器可用宽度): 300px
*   `track_collection` (列轨道集合):
    *   轨道 1: `flex-factor` = 1
    *   轨道 2: `flex-factor` = 2

**逻辑推理与输出：**

*   **`FindFrSize` 函数 (确定可用空间):**  可用空间是明确的 300px。
*   **`FindFrSize` 函数 (计算 `fr` 大小):**
    *   总 `flex-factor` = 1 + 2 = 3
    *   `fr_size` = 300px / 3 = 100px
*   **弹性轨道大小：**
    *   轨道 1 大小 = 1 * 100px = 100px
    *   轨道 2 大小 = 2 * 100px = 200px

**假设输入（包含对齐）：**

```html
<div style="display: grid; width: 300px; height: 200px; grid-template-columns: 100px; grid-template-rows: 50px; align-items: center; justify-items: end;">
  <div>Item 1</div>
</div>
```

**假设输入：**

*   容器宽度: 300px
*   容器高度: 200px
*   列轨道大小: 100px
*   行轨道大小: 50px
*   `align-items`: `center`
*   `justify-items`: `end`

**逻辑推理与输出 (`PlaceGridItems` 函数中的对齐部分):**

*   网格项宽度 (假设内容宽度小于 100px): 例如 80px
*   网格项高度 (假设内容高度小于 50px): 例如 30px
*   **水平对齐 (`justify-items: end`):**
    *   `free_space` (水平剩余空间) = 100px - 80px = 20px
    *   `AlignmentOffset` 返回 `margin_start + free_space` (假设没有 margin)，即 `0 + 20px = 20px`。网格项的水平偏移量为 20px，使其靠右对齐。
*   **垂直对齐 (`align-items: center`):**
    *   `free_space` (垂直剩余空间) = 50px - 30px = 20px
    *   `AlignmentOffset` 返回 `margin_start + (free_space / 2)`，即 `0 + (20px / 2) = 10px`。网格项的垂直偏移量为 10px，使其垂直居中。

**用户或编程常见的使用错误：**

1. **过度依赖 `fr` 单位而忽略内容大小:** 用户可能期望 `1fr` 的轨道总是占据剩余的所有空间，但如果内容过大，轨道可能会超出预期。
2. **对齐属性理解错误:**  `justify-items` 和 `justify-content` (以及 `align-items` 和 `align-content`) 的作用对象不同，容易混淆。`justify-items` 控制网格项在其网格区域内的对齐，而 `justify-content` 控制网格轨道在容器内的对齐。
3. **不理解 `min-content` 和 `max-content` 的影响:**  使用这些关键字作为轨道大小可能会导致意想不到的布局。
4. **分页符使用不当:**  错误地使用 `break-before`、`break-after` 或 `break-inside` 可能会导致布局断裂或内容丢失。
5. **在子网格中使用百分比尺寸:**  在某些情况下，子网格中的百分比尺寸解析可能会与预期不同，需要仔细考虑上下文。

**总结本部分的功能：**

这部分 `grid_layout_algorithm.cc` 代码是 Chromium Blink 引擎中 CSS Grid 布局算法的关键组成部分，负责**处理弹性轨道的大小计算、网格项的对齐以及初步的布局放置**。它还深入处理了**网格在分页时的复杂布局逻辑**。 这部分代码的功能直接对应了 CSS Grid 规范中的核心概念和属性，确保浏览器能够正确地渲染和显示使用 Grid 布局的网页。

Prompt: 
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
 free space is a definite length, the used flex fraction
    // is the result of finding the size of an fr using all of the grid tracks
    // and a space to fill of the available grid space.
    fr_size = FindFrSize(track_collection.GetSetIterator(),
                         (track_direction == kForColumns)
                             ? grid_available_size_.inline_size
                             : grid_available_size_.block_size);
  } else {
    // Otherwise, if the free space is an indefinite length, the used flex
    // fraction is the maximum of:
    //   - For each grid item that crosses a flexible track, the result of
    //   finding the size of an fr using all the grid tracks that the item
    //   crosses and a space to fill of the item’s max-content contribution.
    for (auto& grid_item :
         sizing_subtree.GetGridItems().IncludeSubgriddedItems()) {
      if (grid_item.IsConsideredForSizing(track_direction) &&
          grid_item.IsSpanningFlexibleTrack(track_direction)) {
        float grid_item_fr_size =
            FindFrSize(GetSetIteratorForItem(grid_item, track_collection),
                       ContributionSizeForGridItem(
                           sizing_subtree,
                           GridItemContributionType::kForMaxContentMaximums,
                           track_direction, sizing_constraint, &grid_item));
        fr_size = std::max(grid_item_fr_size, fr_size);
      }
    }

    //   - For each flexible track, if the flexible track’s flex factor is
    //   greater than one, the result of dividing the track’s base size by its
    //   flex factor; otherwise, the track’s base size.
    for (auto set_iterator = track_collection.GetConstSetIterator();
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      auto& set = set_iterator.CurrentSet();
      if (!set.track_size.HasFlexMaxTrackBreadth())
        continue;

      DCHECK_GT(set.track_count, 0u);
      float set_flex_factor = base::ClampMax(set.FlexFactor(), set.track_count);
      fr_size = std::max(set.BaseSize().RawValue() / set_flex_factor, fr_size);
    }
  }

  // Notice that the fr size multiplied by a set's flex factor can result in a
  // non-integer size; since we floor the expanded size to fit in a LayoutUnit,
  // when multiple sets lose the fractional part of the computation we may not
  // distribute the entire free space. We fix this issue by accumulating the
  // leftover fractional part from every flexible set.
  float leftover_size = 0;

  for (auto set_iterator = track_collection.GetSetIterator();
       !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
    auto& set = set_iterator.CurrentSet();
    if (!set.track_size.HasFlexMaxTrackBreadth())
      continue;

    const ClampedFloat fr_share = fr_size * set.FlexFactor() + leftover_size;
    // Add an epsilon to round up values very close to the next integer.
    const LayoutUnit expanded_size =
        LayoutUnit::FromRawValue(fr_share + kFloatEpsilon);

    if (!expanded_size.MightBeSaturated() && expanded_size >= set.BaseSize()) {
      set.IncreaseBaseSize(expanded_size);
      // The epsilon added above might make |expanded_size| greater than
      // |fr_share|, in that case avoid a negative leftover by flooring to 0.
      leftover_size = base::ClampMax(fr_share - expanded_size.RawValue(), 0);
    }
  }

  // TODO(ethavar): If using this flex fraction would cause the grid to be
  // smaller than the grid container’s min-width/height (or larger than the grid
  // container’s max-width/height), then redo this step, treating the free space
  // as definite and the available grid space as equal to the grid container’s
  // inner size when it’s sized to its min-width/height (max-width/height).
}

LayoutUnit GridLayoutAlgorithm::GutterSize(
    GridTrackSizingDirection track_direction,
    LayoutUnit parent_grid_gutter_size) const {
  const bool is_for_columns = track_direction == kForColumns;
  const auto& gutter_size =
      is_for_columns ? Style().ColumnGap() : Style().RowGap();

  if (!gutter_size) {
    // No specified gutter size means we must use the "normal" gap behavior:
    //   - For standalone grids `parent_grid_gutter_size` will default to zero.
    //   - For subgrids we must provide the parent grid's gutter size.
    return parent_grid_gutter_size;
  }

  return MinimumValueForLength(
      *gutter_size, (is_for_columns ? grid_available_size_.inline_size
                                    : grid_available_size_.block_size)
                        .ClampIndefiniteToZero());
}

// TODO(ikilpatrick): Determine if other uses of this method need to respect
// |grid_min_available_size_| similar to |StretchAutoTracks|.
LayoutUnit GridLayoutAlgorithm::DetermineFreeSpace(
    SizingConstraint sizing_constraint,
    const GridSizingTrackCollection& track_collection) const {
  const auto track_direction = track_collection.Direction();

  // https://drafts.csswg.org/css-sizing-3/#auto-box-sizes: both min-content and
  // max-content block sizes are the size of the content after layout.
  if (track_direction == kForRows)
    sizing_constraint = SizingConstraint::kLayout;

  switch (sizing_constraint) {
    case SizingConstraint::kLayout: {
      LayoutUnit free_space = (track_direction == kForColumns)
                                  ? grid_available_size_.inline_size
                                  : grid_available_size_.block_size;

      if (free_space != kIndefiniteSize) {
        // If tracks consume more space than the grid container has available,
        // clamp the free space to zero as there's no more room left to grow.
        free_space = (free_space - track_collection.TotalTrackSize())
                         .ClampNegativeToZero();
      }
      return free_space;
    }
    case SizingConstraint::kMaxContent:
      // If sizing under a max-content constraint, the free space is infinite.
      return kIndefiniteSize;
    case SizingConstraint::kMinContent:
      // If sizing under a min-content constraint, the free space is zero.
      return LayoutUnit();
  }
}

namespace {

// Returns the alignment offset for either the inline or block direction.
LayoutUnit AlignmentOffset(LayoutUnit container_size,
                           LayoutUnit size,
                           LayoutUnit margin_start,
                           LayoutUnit margin_end,
                           LayoutUnit baseline_offset,
                           AxisEdge axis_edge,
                           bool is_overflow_safe) {
  LayoutUnit free_space = container_size - size - margin_start - margin_end;
  // If overflow is 'safe', we have to make sure we don't overflow the
  // 'start' edge (potentially cause some data loss as the overflow is
  // unreachable).
  if (is_overflow_safe)
    free_space = free_space.ClampNegativeToZero();
  switch (axis_edge) {
    case AxisEdge::kStart:
      return margin_start;
    case AxisEdge::kCenter:
      return margin_start + (free_space / 2);
    case AxisEdge::kEnd:
      return margin_start + free_space;
    case AxisEdge::kFirstBaseline:
    case AxisEdge::kLastBaseline:
      return baseline_offset;
  }
  NOTREACHED();
}

void AlignmentOffsetForOutOfFlow(AxisEdge inline_axis_edge,
                                 AxisEdge block_axis_edge,
                                 LogicalSize container_size,
                                 LogicalStaticPosition::InlineEdge* inline_edge,
                                 LogicalStaticPosition::BlockEdge* block_edge,
                                 LogicalOffset* offset) {
  using InlineEdge = LogicalStaticPosition::InlineEdge;
  using BlockEdge = LogicalStaticPosition::BlockEdge;

  switch (inline_axis_edge) {
    case AxisEdge::kStart:
    case AxisEdge::kFirstBaseline:
      *inline_edge = InlineEdge::kInlineStart;
      break;
    case AxisEdge::kCenter:
      *inline_edge = InlineEdge::kInlineCenter;
      offset->inline_offset += container_size.inline_size / 2;
      break;
    case AxisEdge::kEnd:
    case AxisEdge::kLastBaseline:
      *inline_edge = InlineEdge::kInlineEnd;
      offset->inline_offset += container_size.inline_size;
      break;
  }

  switch (block_axis_edge) {
    case AxisEdge::kStart:
    case AxisEdge::kFirstBaseline:
      *block_edge = BlockEdge::kBlockStart;
      break;
    case AxisEdge::kCenter:
      *block_edge = BlockEdge::kBlockCenter;
      offset->block_offset += container_size.block_size / 2;
      break;
    case AxisEdge::kEnd:
    case AxisEdge::kLastBaseline:
      *block_edge = BlockEdge::kBlockEnd;
      offset->block_offset += container_size.block_size;
      break;
  }
}

}  // namespace

ConstraintSpace GridLayoutAlgorithm::CreateConstraintSpace(
    LayoutResultCacheSlot cache_slot,
    const GridItemData& grid_item,
    const LogicalSize& containing_grid_area_size,
    const LogicalSize& fixed_available_size,
    GridLayoutSubtree&& opt_layout_subtree,
    bool min_block_size_should_encompass_intrinsic_size,
    std::optional<LayoutUnit> opt_child_block_offset) const {
  const auto& container_constraint_space = GetConstraintSpace();

  ConstraintSpaceBuilder builder(
      container_constraint_space, grid_item.node.Style().GetWritingDirection(),
      /* is_new_fc */ true, /* adjust_inline_size_if_needed */ false);

  builder.SetCacheSlot(cache_slot);
  builder.SetIsPaintedAtomically(true);

  {
    auto available_size = containing_grid_area_size;
    if (fixed_available_size.inline_size != kIndefiniteSize) {
      available_size.inline_size = fixed_available_size.inline_size;
      builder.SetIsFixedInlineSize(true);
    }

    if (fixed_available_size.block_size != kIndefiniteSize) {
      available_size.block_size = fixed_available_size.block_size;
      builder.SetIsFixedBlockSize(true);
    }
    builder.SetAvailableSize(available_size);
  }

  if (opt_layout_subtree) {
    DCHECK(grid_item.IsSubgrid());
    DCHECK(!opt_layout_subtree.HasUnresolvedGeometry());
    builder.SetGridLayoutSubtree(std::move(opt_layout_subtree));
  }

  builder.SetPercentageResolutionSize(containing_grid_area_size);
  builder.SetInlineAutoBehavior(grid_item.column_auto_behavior);
  builder.SetBlockAutoBehavior(grid_item.row_auto_behavior);

  if (container_constraint_space.HasBlockFragmentation() &&
      opt_child_block_offset) {
    if (min_block_size_should_encompass_intrinsic_size)
      builder.SetMinBlockSizeShouldEncompassIntrinsicSize();

    SetupSpaceBuilderForFragmentation(container_builder_, grid_item.node,
                                      *opt_child_block_offset, &builder);
  }
  return builder.ToConstraintSpace();
}

ConstraintSpace GridLayoutAlgorithm::CreateConstraintSpaceForLayout(
    const GridItemData& grid_item,
    const GridLayoutData& layout_data,
    GridLayoutSubtree&& opt_layout_subtree,
    LogicalRect* containing_grid_area,
    LayoutUnit unavailable_block_size,
    bool min_block_size_should_encompass_intrinsic_size,
    std::optional<LayoutUnit> opt_child_block_offset) const {
  LayoutUnit inline_offset, block_offset;

  LogicalSize containing_grid_area_size = {
      ComputeGridItemAvailableSize(grid_item, layout_data.Columns(),
                                   &inline_offset),
      ComputeGridItemAvailableSize(grid_item, layout_data.Rows(),
                                   &block_offset)};

  if (containing_grid_area) {
    containing_grid_area->offset.inline_offset = inline_offset;
    containing_grid_area->offset.block_offset = block_offset;
    containing_grid_area->size = containing_grid_area_size;
  }

  if (containing_grid_area_size.block_size != kIndefiniteSize) {
    containing_grid_area_size.block_size -= unavailable_block_size;
    DCHECK_GE(containing_grid_area_size.block_size, LayoutUnit());
  }

  auto fixed_available_size = kIndefiniteLogicalSize;

  if (grid_item.IsSubgrid()) {
    const auto [fixed_inline_size, fixed_block_size] = ShrinkLogicalSize(
        containing_grid_area_size,
        ComputeMarginsFor(grid_item.node.Style(),
                          containing_grid_area_size.inline_size,
                          GetConstraintSpace().GetWritingDirection()));

    fixed_available_size = {
        grid_item.has_subgridded_columns ? fixed_inline_size : kIndefiniteSize,
        grid_item.has_subgridded_rows ? fixed_block_size : kIndefiniteSize};
  }

  return CreateConstraintSpace(
      LayoutResultCacheSlot::kLayout, grid_item, containing_grid_area_size,
      fixed_available_size, std::move(opt_layout_subtree),
      min_block_size_should_encompass_intrinsic_size, opt_child_block_offset);
}

ConstraintSpace GridLayoutAlgorithm::CreateConstraintSpaceForMeasure(
    const SubgriddedItemData& subgridded_item,
    GridTrackSizingDirection track_direction,
    std::optional<LayoutUnit> opt_fixed_inline_size) const {
  auto containing_grid_area_size = kIndefiniteLogicalSize;
  const auto writing_mode = GetConstraintSpace().GetWritingMode();

  if (track_direction == kForColumns) {
    containing_grid_area_size.block_size = ComputeGridItemAvailableSize(
        *subgridded_item, subgridded_item.Rows(writing_mode));
  } else {
    containing_grid_area_size.inline_size = ComputeGridItemAvailableSize(
        *subgridded_item, subgridded_item.Columns(writing_mode));
  }

  auto fixed_available_size =
      subgridded_item.IsSubgrid()
          ? ShrinkLogicalSize(
                containing_grid_area_size,
                ComputeMarginsFor(subgridded_item->node.Style(),
                                  containing_grid_area_size.inline_size,
                                  GetConstraintSpace().GetWritingDirection()))
          : kIndefiniteLogicalSize;

  if (opt_fixed_inline_size) {
    const auto item_writing_mode =
        subgridded_item->node.Style().GetWritingMode();
    auto& fixed_size = IsParallelWritingMode(item_writing_mode, writing_mode)
                           ? fixed_available_size.inline_size
                           : fixed_available_size.block_size;

    DCHECK_EQ(fixed_size, kIndefiniteSize);
    fixed_size = *opt_fixed_inline_size;
  }

  return CreateConstraintSpace(LayoutResultCacheSlot::kMeasure,
                               *subgridded_item, containing_grid_area_size,
                               fixed_available_size);
}

namespace {

// Determining the grid's baseline is prioritized based on grid order (as
// opposed to DOM order). The baseline of the grid is determined by the first
// grid item with baseline alignment in the first row. If no items have
// baseline alignment, fall back to the first item in row-major order.
class BaselineAccumulator {
  STACK_ALLOCATED();

 public:
  explicit BaselineAccumulator(FontBaseline font_baseline)
      : font_baseline_(font_baseline) {}

  void Accumulate(const GridItemData& grid_item,
                  const LogicalBoxFragment& fragment,
                  const LayoutUnit block_offset) {
    auto StartsBefore = [](const GridArea& a, const GridArea& b) -> bool {
      if (a.rows.StartLine() < b.rows.StartLine())
        return true;
      if (a.rows.StartLine() > b.rows.StartLine())
        return false;
      return a.columns.StartLine() < b.columns.StartLine();
    };

    auto EndsAfter = [](const GridArea& a, const GridArea& b) -> bool {
      if (a.rows.EndLine() > b.rows.EndLine())
        return true;
      if (a.rows.EndLine() < b.rows.EndLine())
        return false;
      // Use greater-or-equal to prefer the "last" grid-item.
      return a.columns.EndLine() >= b.columns.EndLine();
    };

    if (!first_fallback_baseline_ ||
        StartsBefore(grid_item.resolved_position,
                     first_fallback_baseline_->resolved_position)) {
      first_fallback_baseline_.emplace(
          grid_item.resolved_position,
          block_offset + fragment.FirstBaselineOrSynthesize(font_baseline_));
    }

    if (!last_fallback_baseline_ ||
        EndsAfter(grid_item.resolved_position,
                  last_fallback_baseline_->resolved_position)) {
      last_fallback_baseline_.emplace(
          grid_item.resolved_position,
          block_offset + fragment.LastBaselineOrSynthesize(font_baseline_));
    }

    // Keep track of the first/last set which has content.
    const auto& set_indices = grid_item.SetIndices(kForRows);
    if (first_set_index_ == kNotFound || set_indices.begin < first_set_index_)
      first_set_index_ = set_indices.begin;
    if (last_set_index_ == kNotFound || set_indices.end - 1 > last_set_index_)
      last_set_index_ = set_indices.end - 1;
  }

  void AccumulateRows(const GridLayoutTrackCollection& rows) {
    for (wtf_size_t i = 0; i < rows.GetSetCount(); ++i) {
      LayoutUnit set_offset = rows.GetSetOffset(i);
      LayoutUnit major_baseline = rows.MajorBaseline(i);
      if (major_baseline != LayoutUnit::Min()) {
        LayoutUnit baseline_offset = set_offset + major_baseline;
        if (!first_major_baseline_)
          first_major_baseline_.emplace(i, baseline_offset);
        last_major_baseline_.emplace(i, baseline_offset);
      }

      LayoutUnit minor_baseline = rows.MinorBaseline(i);
      if (minor_baseline != LayoutUnit::Min()) {
        LayoutUnit baseline_offset =
            set_offset + rows.ComputeSetSpanSize(i, i + 1) - minor_baseline;
        if (!first_minor_baseline_)
          first_minor_baseline_.emplace(i, baseline_offset);
        last_minor_baseline_.emplace(i, baseline_offset);
      }
    }
  }

  std::optional<LayoutUnit> FirstBaseline() const {
    if (first_major_baseline_ &&
        first_major_baseline_->set_index == first_set_index_) {
      return first_major_baseline_->baseline;
    }
    if (first_minor_baseline_ &&
        first_minor_baseline_->set_index == first_set_index_) {
      return first_minor_baseline_->baseline;
    }
    if (first_fallback_baseline_)
      return first_fallback_baseline_->baseline;
    return std::nullopt;
  }

  std::optional<LayoutUnit> LastBaseline() const {
    if (last_minor_baseline_ &&
        last_minor_baseline_->set_index == last_set_index_) {
      return last_minor_baseline_->baseline;
    }
    if (last_major_baseline_ &&
        last_major_baseline_->set_index == last_set_index_) {
      return last_major_baseline_->baseline;
    }
    if (last_fallback_baseline_)
      return last_fallback_baseline_->baseline;
    return std::nullopt;
  }

 private:
  struct SetIndexAndBaseline {
    SetIndexAndBaseline(wtf_size_t set_index, LayoutUnit baseline)
        : set_index(set_index), baseline(baseline) {}
    wtf_size_t set_index;
    LayoutUnit baseline;
  };
  struct PositionAndBaseline {
    PositionAndBaseline(const GridArea& resolved_position, LayoutUnit baseline)
        : resolved_position(resolved_position), baseline(baseline) {}
    GridArea resolved_position;
    LayoutUnit baseline;
  };

  FontBaseline font_baseline_;
  wtf_size_t first_set_index_ = kNotFound;
  wtf_size_t last_set_index_ = kNotFound;

  std::optional<SetIndexAndBaseline> first_major_baseline_;
  std::optional<SetIndexAndBaseline> first_minor_baseline_;
  std::optional<PositionAndBaseline> first_fallback_baseline_;

  std::optional<SetIndexAndBaseline> last_major_baseline_;
  std::optional<SetIndexAndBaseline> last_minor_baseline_;
  std::optional<PositionAndBaseline> last_fallback_baseline_;
};

}  // namespace

void GridLayoutAlgorithm::PlaceGridItems(
    const GridSizingTree& sizing_tree,
    Vector<EBreakBetween>* out_row_break_between,
    Vector<GridItemPlacementData>* out_grid_items_placement_data) {
  DCHECK(out_row_break_between);

  const auto& container_space = GetConstraintSpace();
  const auto& [grid_items, layout_data, tree_size] = sizing_tree.TreeRootData();

  const auto* cached_layout_subtree = container_space.GetGridLayoutSubtree();
  const auto container_writing_direction =
      container_space.GetWritingDirection();
  const bool should_propagate_child_break_values =
      container_space.ShouldPropagateChildBreakValues();

  if (should_propagate_child_break_values) {
    *out_row_break_between = Vector<EBreakBetween>(
        layout_data.Rows().GetSetCount() + 1, EBreakBetween::kAuto);
  }

  BaselineAccumulator baseline_accumulator(Style().GetFontBaseline());

  const auto layout_subtree =
      cached_layout_subtree ? *cached_layout_subtree
                            : GridLayoutSubtree(sizing_tree.FinalizeTree());
  auto next_subgrid_subtree = layout_subtree.FirstChild();

  for (const auto& grid_item : grid_items) {
    GridLayoutSubtree child_layout_subtree;

    if (grid_item.IsSubgrid()) {
      DCHECK(next_subgrid_subtree);
      child_layout_subtree = next_subgrid_subtree;
      next_subgrid_subtree = next_subgrid_subtree.NextSibling();
    }

    LogicalRect containing_grid_area;
    const auto space = CreateConstraintSpaceForLayout(
        grid_item, layout_data, std::move(child_layout_subtree),
        &containing_grid_area);

    const auto& item_style = grid_item.node.Style();
    const auto margins = ComputeMarginsFor(space, item_style, container_space);

    auto* result = grid_item.node.Layout(space);
    const auto& physical_fragment =
        To<PhysicalBoxFragment>(result->GetPhysicalFragment());
    LogicalBoxFragment fragment(container_writing_direction, physical_fragment);

    auto BaselineOffset = [&](GridTrackSizingDirection track_direction,
                              LayoutUnit size) -> LayoutUnit {
      if (!grid_item.IsBaselineAligned(track_direction)) {
        return LayoutUnit();
      }

      LogicalBoxFragment baseline_fragment(
          grid_item.BaselineWritingDirection(track_direction),
          physical_fragment);
      // The baseline offset is the difference between the grid item's baseline
      // and its track baseline.
      const LayoutUnit baseline_delta =
          Baseline(layout_data, grid_item, track_direction) -
          GetLogicalBaseline(grid_item, baseline_fragment, track_direction);
      if (grid_item.BaselineGroup(track_direction) == BaselineGroup::kMajor)
        return baseline_delta;

      // BaselineGroup::kMinor
      const LayoutUnit item_size = (track_direction == kForColumns)
                                       ? fragment.InlineSize()
                                       : fragment.BlockSize();
      return size - baseline_delta - item_size;
    };

    LayoutUnit inline_baseline_offset =
        BaselineOffset(kForColumns, containing_grid_area.size.inline_size);
    LayoutUnit block_baseline_offset =
        BaselineOffset(kForRows, containing_grid_area.size.block_size);

    // Apply the grid-item's alignment (if any).
    containing_grid_area.offset += LogicalOffset(
        AlignmentOffset(containing_grid_area.size.inline_size,
                        fragment.InlineSize(), margins.inline_start,
                        margins.inline_end, inline_baseline_offset,
                        grid_item.Alignment(kForColumns),
                        grid_item.IsOverflowSafe(kForColumns)),
        AlignmentOffset(
            containing_grid_area.size.block_size, fragment.BlockSize(),
            margins.block_start, margins.block_end, block_baseline_offset,
            grid_item.Alignment(kForRows), grid_item.IsOverflowSafe(kForRows)));

    // Grid is special in that %-based offsets resolve against the grid-area.
    // Determine the relative offset here (instead of in the builder). This is
    // safe as grid *also* has special inflow-bounds logic (otherwise this
    // wouldn't work).
    LogicalOffset relative_offset = LogicalOffset();
    if (item_style.GetPosition() == EPosition::kRelative) {
      relative_offset += ComputeRelativeOffsetForBoxFragment(
          physical_fragment, container_writing_direction,
          containing_grid_area.size);
    }

    // If |out_grid_items_placement_data| is present we just want to record the
    // initial position of all the children for the purposes of fragmentation.
    // Don't add these to the builder.
    if (out_grid_items_placement_data) {
      out_grid_items_placement_data->emplace_back(
          containing_grid_area.offset, relative_offset,
          result->HasDescendantThatDependsOnPercentageBlockSize());
    } else {
      container_builder_.AddResult(*result, containing_grid_area.offset,
                                   margins, relative_offset);
      baseline_accumulator.Accumulate(grid_item, fragment,
                                      containing_grid_area.offset.block_offset);
    }

    if (should_propagate_child_break_values) {
      auto item_break_before = JoinFragmentainerBreakValues(
          item_style.BreakBefore(), result->InitialBreakBefore());
      auto item_break_after = JoinFragmentainerBreakValues(
          item_style.BreakAfter(), result->FinalBreakAfter());

      const auto& set_indices = grid_item.SetIndices(kForRows);
      (*out_row_break_between)[set_indices.begin] =
          JoinFragmentainerBreakValues(
              (*out_row_break_between)[set_indices.begin], item_break_before);
      (*out_row_break_between)[set_indices.end] = JoinFragmentainerBreakValues(
          (*out_row_break_between)[set_indices.end], item_break_after);
    }
  }

  // Propagate the baselines.
  if (layout_data.Rows().HasBaselines()) {
    baseline_accumulator.AccumulateRows(layout_data.Rows());
  }
  if (auto first_baseline = baseline_accumulator.FirstBaseline())
    container_builder_.SetFirstBaseline(*first_baseline);
  if (auto last_baseline = baseline_accumulator.LastBaseline())
    container_builder_.SetLastBaseline(*last_baseline);
}

// This is only used in GridLayoutAlgorithm::PlaceGridItemsForFragmentation(),
// but placed here to add WTF VectorTraits.
struct ResultAndOffsets {
  DISALLOW_NEW();

 public:
  ResultAndOffsets(const LayoutResult* result,
                   LogicalOffset offset,
                   LogicalOffset relative_offset)
      : result(result), offset(offset), relative_offset(relative_offset) {}

  void Trace(Visitor* visitor) const { visitor->Trace(result); }

  Member<const LayoutResult> result;
  LogicalOffset offset;
  LogicalOffset relative_offset;
};

void GridLayoutAlgorithm::PlaceGridItemsForFragmentation(
    const GridSizingTree& sizing_tree,
    const Vector<EBreakBetween>& row_break_between,
    Vector<GridItemPlacementData>* grid_items_placement_data,
    Vector<LayoutUnit>* row_offset_adjustments,
    LayoutUnit* intrinsic_block_size,
    LayoutUnit* offset_in_stitched_container) {
  DCHECK(grid_items_placement_data && row_offset_adjustments &&
         intrinsic_block_size && offset_in_stitched_container);

  // TODO(ikilpatrick): Update |SetHasSeenAllChildren| and early exit if true.
  const auto& constraint_space = GetConstraintSpace();
  const auto& [grid_items, layout_data, tree_size] = sizing_tree.TreeRootData();

  const auto* cached_layout_subtree = constraint_space.GetGridLayoutSubtree();
  const auto container_writing_direction =
      constraint_space.GetWritingDirection();

  LayoutUnit fragmentainer_block_size = FragmentainerCapacityForChildren();

  // The following roughly comes from:
  // https://drafts.csswg.org/css-grid-1/#fragmentation-alg
  //
  // We are interested in cases where the grid-item *may* expand due to
  // fragmentation (lines pushed down by a fragmentation line, etc).
  auto MinBlockSizeShouldEncompassIntrinsicSize =
      [&](const GridItemData& grid_item,
          bool has_descendant_that_depends_on_percentage_block_size) -> bool {
    // If this item has (any) descendant that is percentage based, we can end
    // up in a situation where we'll constantly try and expand the row. E.g.
    // <div style="display: grid;">
    //   <div style="min-height: 100px;">
    //     <div style="height: 200%;"></div>
    //   </div>
    // </div>
    if (has_descendant_that_depends_on_percentage_block_size)
      return false;

    if (grid_item.node.IsMonolithic())
      return false;

    const auto& item_style = grid_item.node.Style();

    // NOTE: We currently assume that writing-mode roots are monolithic, but
    // this may change in the future.
    DCHECK_EQ(container_writing_direction.GetWritingMode(),
              item_style.GetWritingMode());

    // Only allow growth on "auto" block-size items, unless box decorations are
    // to be cloned. Even a fixed block-size item can grow if box decorations
    // are cloned (as long as box-sizing is content-box).
    if (!item_style.LogicalHeight().HasAutoOrContentOrIntrinsic() &&
        item_style.BoxDecorationBreak() != EBoxDecorationBreak::kClone) {
      return false;
    }

    // Only allow growth on items which only span a single row.
    if (grid_item.SpanSize(kForRows) > 1)
      return false;

    // If we have a fixed maximum track, we assume that we've hit this maximum,
    // and as such shouldn't grow.
    if (grid_item.IsSpanningFixedMaximumTrack(kForRows) &&
        !grid_item.IsSpanningIntrinsicTrack(kForRows))
      return false;

    return !grid_item.IsSpanningFixedMinimumTrack(kForRows) ||
           Style().LogicalHeight().HasAutoOrContentOrIntrinsic();
  };

  wtf_size_t previous_expansion_row_set_index = kNotFound;
  auto IsExpansionMakingProgress = [&](wtf_size_t row_set_index) -> bool {
    return previous_expansion_row_set_index == kNotFound ||
           row_set_index > previous_expansion_row_set_index;
  };

  HeapVector<ResultAndOffsets> result_and_offsets;
  BaselineAccumulator baseline_accumulator(Style().GetFontBaseline());
  LayoutUnit max_row_expansion;
  LayoutUnit max_item_block_end;
  wtf_size_t expansion_row_set_index;
  wtf_size_t breakpoint_row_set_index;
  bool has_subsequent_children;

  auto UpdateBreakpointRowSetIndex = [&](wtf_size_t row_set_index) {
    if (row_set_index >= breakpoint_row_set_index)
      return;

    breakpoint_row_set_index = row_set_index;
  };

  LayoutUnit fragmentainer_space = FragmentainerSpaceLeftForChildren();
  LayoutUnit cloned_block_start_decoration;
  if (fragmentainer_space != kIndefiniteSize) {
    // Cloned block-start box decorations take up space at the beginning of a
    // fragmentainer, and are baked into fragmentainer_space, but this is not
    // part of the content progress.
    cloned_block_start_decoration =
        ClonedBlockStartDecoration(container_builder_);
    fragmentainer_space -= cloned_block_start_decoration;
  }

  base::span<const Member<const BreakToken>> child_break_tokens;
  if (GetBreakToken()) {
    child_break_tokens = GetBreakToken()->ChildBreakTokens();
  }

  auto PlaceItems = [&]() {
    // Reset our state.
    result_and_offsets.clear();
    baseline_accumulator = BaselineAccumulator(Style().GetFontBaseline());
    max_row_expansion = LayoutUnit();
    max_item_block_end = LayoutUnit();
    expansion_row_set_index = kNotFound;
    breakpoint_row_set_index = kNotFound;
    has_subsequent_children = false;

    auto child_break_token_it = child_break_tokens.begin();
    auto placement_data_it = grid_items_placement_data->begin();

    const auto layout_subtree =
        cached_layout_subtree ? *cached_layout_subtree
                              : GridLayoutSubtree(sizing_tree.FinalizeTree());
    auto next_subgrid_subtree = layout_subtree.FirstChild();

    for (const auto& grid_item : grid_items) {
      // Grab the offsets and break-token (if present) for this child.
      auto& item_placement_data = *(placement_data_it++);
      const BlockBreakToken* break_token = nullptr;
      if (child_break_token_it != child_break_tokens.end()) {
        if ((*child_break_token_it)->InputNode() == grid_item.node)
          break_token = To<BlockBreakToken>((child_break_token_it++)->Get());
      }

      LayoutUnit child_block_offset;
      if (IsBreakInside(break_token)) {
        child_block_offset = BorderScrollbarPadding().block_start;
      } else {
        // Include any cloned block-start box decorations. The item offset
        // offset is in the imaginary stitched container that we would have had
        // had we not been fragmented, and now we want actual layout offsets for
        // the current fragment.
        child_block_offset = item_placement_data.offset.block_offset -
                             *offset_in_stitched_container +
                             cloned_block_start_decoration;
      }
      LayoutUnit fragmentainer_block_offset =
          FragmentainerOffsetForChildren() + child_block_offset;
      const bool min_block_size_should_encompass_intrinsic_size =
          MinBlockSizeShouldEncompassIntrinsicSize(
              grid_item,
              item_placement_data
                  .has_descendant_that_depends_on_percentage_block_size);

      LayoutUnit unavailable_block_size;
      if (IsBreakInside(GetBreakToken()) && IsBreakInside(break_token)) {
        // If a sibling grid item
"""


```