Response:
Let's break down the thought process for analyzing this `grid_item.cc` file.

1. **Understand the Goal:** The request asks for the *functionality* of the file, its relation to web technologies (JS, HTML, CSS), examples, logical deductions, and common user errors. Essentially, it's a deep dive into what this code does and how it fits into the bigger picture.

2. **Initial Skim and Keywords:** Quickly read through the code, looking for recognizable keywords and concepts related to CSS Grid Layout. Terms like "GridItemData," "alignment," "tracks," "subgrid," "margin," "writing-mode," "justify-self," "align-self," "auto," "stretch," "baseline," and "out-of-flow" immediately stand out. These provide a high-level understanding that the file deals with properties and behaviors of items within a CSS Grid.

3. **Focus on the Core Class: `GridItemData`:** This is clearly the central structure. Analyze its constructor and member variables. The constructor takes `BlockNode`, `ComputedStyle` of the parent and root grid, and some boolean flags. This suggests that `GridItemData` holds information *about* a specific HTML element (the `BlockNode`) within a grid context, using its computed styles.

4. **Deconstruct Key Functions:**  Go through each significant function within `GridItemData` and the anonymous namespace:

    * **`AxisEdgeFromItemPosition`:**  This function is crucial. Notice how it takes various styling properties (`item_style`, `parent_grid_style`, `root_grid_style`) and outputs an `AxisEdge` and modifies `auto_behavior` and `is_overflow_safe`. This screams "calculating alignment based on CSS properties." Pay close attention to the logic for handling `auto` margins, `justify-self`, `align-self`, writing modes, and overflow behavior. The `LogicalToPhysical` and `PhysicalToLogical` converters highlight the complexity of dealing with different writing directions.

    * **`GridItemData` Constructor (again, more detailed):**  Look at how the member variables are initialized. The constructor determines if the item is part of a subgrid, its writing mode relative to the root, and crucially, calls `AxisEdgeFromItemPosition` to calculate initial alignments.

    * **`SetAlignmentFallback`:** This deals with situations where baseline alignment cannot be performed due to cyclic dependencies. The logic around `IsSpanningIntrinsicTrack` and `IsSpanningFlexibleTrack` is key here.

    * **`ComputeSetIndices`:**  This function seems to be related to efficient storage and retrieval of grid item placement within the grid tracks. The use of `RangeIndexFromGridLine` and `RangeBeginSetIndex` suggests optimization for lookups.

    * **`ComputeOutOfFlowItemPlacement`:**  Specifically handles the placement of absolutely positioned elements within the grid. It uses `GridPlacement::ResolveOutOfFlowItemGridLines` which indicates interaction with another part of the layout engine.

    * **`GridItems` Class:** This seems like a container for `GridItemData` objects. The `SortByOrderProperty` function reveals that `z-index` (implied by "order") is a factor in how grid items are processed.

5. **Identify Relationships with Web Technologies:**

    * **CSS:** The core of this file is about implementing CSS Grid Layout. Every function and variable is directly related to CSS properties like `grid-template-columns`, `grid-template-rows`, `justify-self`, `align-self`, `margin`, `writing-mode`, `order`, and the concept of subgrids. Give specific examples of how these properties influence the logic in the code (e.g., `justify-self: start` leading to `AxisEdge::kStart`).

    * **HTML:** The `BlockNode` represents an HTML element. The file operates on these elements within the context of a grid container. Mention that the existence of HTML elements is the prerequisite for this code to function.

    * **JavaScript:** While this is C++ code, JavaScript interacts with the layout engine indirectly. Changes in CSS styles via JavaScript will trigger recalculations that involve this code. Mention scenarios like dynamically adding or removing grid items or changing their styles.

6. **Infer Logical Deductions (Hypothetical Inputs and Outputs):**  Think about specific CSS rules and how they would be processed by the functions. For example:

    * **Input:** `justify-self: center`
    * **Output:** `AxisEdge::kCenter` from `AxisEdgeFromItemPosition`.

    * **Input:** An item spanning an intrinsically sized track with `align-items: baseline`.
    * **Output:**  Potentially triggering the fallback logic in `SetAlignmentFallback` if a cyclic dependency is detected.

7. **Consider Common User/Programming Errors:**  Think about mistakes developers make when using CSS Grid:

    * Incorrectly specifying grid lines leading to unexpected placement.
    * Not understanding how `auto` margins interact with alignment properties.
    * Confusion about the behavior of subgrids.
    * Forgetting about the impact of writing modes on alignment.
    * Misunderstanding how absolutely positioned items interact with the grid.

8. **Structure the Answer:** Organize the findings logically. Start with a high-level summary of the file's purpose, then delve into the details of the key functions and their relationships to web technologies. Use clear headings and bullet points for readability. Provide concrete examples for each point.

9. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more detail could be added. Ensure the language is precise and avoids jargon where possible (or explains it when necessary). For instance, explicitly state the CSS properties being referred to.

This methodical approach, starting with a broad overview and gradually focusing on specifics, allows for a comprehensive understanding of the code's functionality and its role in the larger web development ecosystem.
这是 `blink/renderer/core/layout/grid/grid_item.cc` 文件，它是 Chromium Blink 渲染引擎中负责处理 CSS Grid 布局中网格项目（grid items）的核心代码文件。它的主要功能是：

**核心功能：管理和计算网格项目在网格容器内的布局和属性**

更具体地说，`GridItem.cc` 负责以下方面：

1. **存储网格项目的布局相关数据 (GridItemData):**  `GridItemData` 类存储了关于单个网格项目的各种信息，这些信息在网格布局算法中至关重要。这些数据包括：
    * **节点信息:** 指向代表该网格项目的 `BlockNode`。
    * **子网格信息:** 标记该项目是否是子网格 (subgrid)，以及它在列和行方向上是否是子网格。
    * **尺寸调整信息:** 标记该项目是否参与列和行的尺寸调整计算。
    * **对齐方式:**  存储项目在列和行方向上的对齐方式 (`justify-self` 和 `align-self` 的解析值）。
    * **基线对齐信息:** 存储项目在列和行方向上的基线对齐分组。
    * **书写模式信息:**  存储项目相对于根网格的书写模式信息，用于处理布局方向。
    * **自动尺寸行为:** 确定在自动尺寸调整期间如何处理项目。
    * **溢出安全标志:**  指示对齐是否是溢出安全的。
    * **放置信息:**  存储项目在网格中的起始和结束行号或名称。

2. **计算网格项目的轴对齐方式 (`AxisEdgeFromItemPosition`):**  该函数根据网格项目的样式属性（如 `justify-self`、`align-self`、`margin`）、父网格和根网格的样式，以及书写模式等因素，确定项目在给定轴上的对齐方式。这包括处理 `auto` 关键字的行为和溢出安全。

3. **处理基线对齐回退 (`SetAlignmentFallback`):**  当网格项目指定了基线对齐，但由于循环依赖等原因无法参与基线对齐时，此函数负责设置回退对齐方式。

4. **计算已设置的索引 (`ComputeSetIndices`):**  对于非脱离文档流的网格项目，此函数计算其在网格轨道集合中的起始和结束范围和集合索引，用于优化布局计算。

5. **计算脱离文档流项目的放置 (`ComputeOutOfFlowItemPlacement`):**  对于绝对定位的网格项目，此函数根据其 `grid-row-start`、`grid-row-end`、`grid-column-start`、`grid-column-end` 属性，以及网格轨道集合的信息，计算其在网格中的放置位置。

6. **管理网格项目集合 (`GridItems`):**  `GridItems` 类用于存储和管理 `GridItemData` 对象的集合。它提供了添加、排序（基于 `order` 属性）等功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`grid_item.cc` 的功能与 HTML 结构和 CSS 样式密切相关，并且通过渲染引擎间接地与 JavaScript 交互。

* **HTML:**  HTML 结构定义了哪些元素是网格容器的子元素，从而成为网格项目。`GridItem.cc` 中的 `BlockNode` 对象正是代表这些 HTML 元素。
    * **举例:**  以下 HTML 代码中，`<div>Item 1</div>` 和 `<div>Item 2</div>` 就是网格项目。
      ```html
      <div style="display: grid;">
        <div>Item 1</div>
        <div>Item 2</div>
      </div>
      ```

* **CSS:** CSS 样式决定了网格项目的布局属性，例如 `grid-row-start`、`grid-column-end`、`justify-self`、`align-self`、`margin`、`order` 等。 `GridItem.cc` 的核心职责就是解析和应用这些 CSS 属性。
    * **举例 (对齐):**  CSS 样式 `justify-self: center;` 会影响 `AxisEdgeFromItemPosition` 函数的计算，最终将网格项目在其网格区域的行内轴上居中对齐。假设输入了 `justify-self: center`，`AxisEdgeFromItemPosition` 函数会返回 `AxisEdge::kCenter`。
    * **举例 (放置):** CSS 样式 `grid-column: 2 / 4;` 会影响 `GridItemData` 中存储的列放置信息。如果一个非脱离文档流的项目应用了这个样式，`ComputeSetIndices` 会根据网格轨道信息计算出该项目占据的列轨道范围的索引。
    * **举例 (脱离文档流放置):**  对于 CSS 样式 `position: absolute; grid-column: 1 / 3;` 的网格项目，`ComputeOutOfFlowItemPlacement` 会根据 `grid-column` 属性计算其在网格中的列放置范围。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 修改了与网格布局相关的样式时，Blink 渲染引擎会重新计算布局，这会涉及到 `grid_item.cc` 中的代码。
    * **举例:**  JavaScript 可以使用 `element.style.justifySelf = 'end';` 来动态修改网格项目的 `justify-self` 属性。这将导致渲染引擎重新运行布局算法，`AxisEdgeFromItemPosition` 会根据新的样式值重新计算对齐方式。
    * **举例:** JavaScript 可以动态添加或删除网格项目，这将导致 `GridItems` 集合的更新和布局的重新计算。

**逻辑推理的假设输入与输出:**

* **假设输入 (对齐):**
    * `item_style.ResolvedJustifySelf` 返回 `ItemPosition::kCenter`。
    * 该项目没有自动 margin。
    * `parent_grid_style` 和 `root_grid_style` 的书写模式配置导致不需要进行复杂的书写模式转换。
    * `is_overflow_safe` 的初始值为 false。
* **输出 (对齐):**
    * `AxisEdgeFromItemPosition` 函数将返回 `AxisEdge::kCenter`。
    * `is_overflow_safe` 的值保持为 `false` (因为 `ItemPosition::kCenter` 默认不是溢出安全的，除非显式指定 `safe` 关键字)。

* **假设输入 (自动 margin):**
    * `item_style.MarginInlineStartUsing(root_grid_style).IsAuto()` 返回 `true`。
    * `item_style.MarginInlineEndUsing(root_grid_style).IsAuto()` 返回 `false`。
    * `is_for_columns` 为 `true`。
* **输出 (自动 margin):**
    * `AxisEdgeFromItemPosition` 函数将返回 `AxisEdge::kEnd` (因为只有起始 margin 是 auto)。
    * `is_overflow_safe` 的值将被设置为 `true`，因为存在自动 margin。

**涉及用户或编程常见的使用错误:**

1. **错误的网格线命名或索引:**  用户可能在 CSS 中使用不存在的网格线名称或错误的索引，导致网格项目放置到意想不到的位置。
    * **举例:**  CSS 中定义了三条列网格线，但设置 `grid-column-start: 4;` 会导致项目放置到隐式创建的网格线。

2. **混淆 `justify-items` 和 `justify-self`:**  用户可能混淆了应用于网格容器的 `justify-items` 和应用于网格项目的 `justify-self`。`justify-items` 设置所有网格项目的默认对齐方式，而 `justify-self` 覆盖单个项目的对齐方式。
    * **举例:** 用户可能认为设置了 `justify-items: center;` 后，所有项目都会居中，但如果某个项目设置了 `justify-self: start;`，则该项目会靠左对齐。

3. **不理解 `auto` margin 在网格布局中的作用:** 用户可能不清楚 `auto` margin 如何在网格项目中分配剩余空间以实现对齐。
    * **举例:**  用户可能希望使用 `justify-self: stretch;` 来拉伸项目，但如果项目同时设置了 `margin-left: auto; margin-right: auto;`，则 `auto` margin 会优先，导致项目居中而不是拉伸。

4. **忽略书写模式的影响:**  在处理不同的书写模式（如 `rtl`）时，用户可能会忘记对齐属性的行为会发生变化。
    * **举例:**  在 `ltr` 模式下，`justify-self: start;` 将项目放在起始边缘，但在 `rtl` 模式下，起始边缘在右侧。

5. **子网格使用不当:**  用户可能不理解子网格的尺寸调整和对齐行为，导致布局出现意外。
    * **举例:**  用户可能期望子网格的尺寸与其父网格的轨道完全一致，但子网格的尺寸仍然受到其自身内容和样式的约束。

6. **绝对定位项目与网格的交互理解不足:**  用户可能不清楚绝对定位的网格项目是如何相对于其网格区域进行定位的，以及它们是否参与网格的尺寸调整。
    * **举例:**  用户可能认为绝对定位的项目会影响网格轨道的尺寸，但实际上它们不会影响。

总而言之，`blink/renderer/core/layout/grid/grid_item.cc` 是 Blink 渲染引擎中处理 CSS Grid 布局中网格项目的关键组成部分，负责管理和计算网格项目的各种布局属性，确保网页能够按照 CSS Grid 规范正确渲染。理解其功能有助于开发者更好地理解和使用 CSS Grid 布局。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_item.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_item.h"

#include "third_party/blink/renderer/core/layout/grid/grid_placement.h"
#include "third_party/blink/renderer/platform/text/writing_mode_utils.h"

namespace blink {

namespace {

// Given an `item_style` determines the correct `AxisEdge` alignment.
// Additionally will determine:
//  - The behavior of 'auto' via the `auto_behavior` out-parameter.
//  - If the alignment is safe via the `is_overflow_safe` out-parameter.
AxisEdge AxisEdgeFromItemPosition(GridTrackSizingDirection track_direction,
                                  bool has_subgridded_axis,
                                  bool is_replaced,
                                  bool is_out_of_flow,
                                  const ComputedStyle& item_style,
                                  const ComputedStyle& parent_grid_style,
                                  const ComputedStyle& root_grid_style,
                                  AutoSizeBehavior* auto_behavior,
                                  bool* is_overflow_safe) {
  DCHECK(auto_behavior && is_overflow_safe);

  if (has_subgridded_axis) {
    *auto_behavior = AutoSizeBehavior::kStretchImplicit;
    *is_overflow_safe = true;
    return AxisEdge::kStart;
  }

  const bool is_for_columns = track_direction == kForColumns;
  const auto root_grid_writing_direction =
      root_grid_style.GetWritingDirection();
  const StyleSelfAlignmentData normal_value(ItemPosition::kNormal,
                                            OverflowAlignment::kDefault);

  const auto& alignment =
      (is_for_columns ==
       IsParallelWritingMode(root_grid_writing_direction.GetWritingMode(),
                             parent_grid_style.GetWritingMode()))
          ? item_style.ResolvedJustifySelf(normal_value, &parent_grid_style)
          : item_style.ResolvedAlignSelf(normal_value, &parent_grid_style);

  *auto_behavior = AutoSizeBehavior::kFitContent;
  *is_overflow_safe = alignment.Overflow() == OverflowAlignment::kSafe;

  // Auto-margins take precedence over any alignment properties.
  if (item_style.MayHaveMargin() && !is_out_of_flow) {
    const bool is_start_auto =
        is_for_columns
            ? item_style.MarginInlineStartUsing(root_grid_style).IsAuto()
            : item_style.MarginBlockStartUsing(root_grid_style).IsAuto();

    const bool is_end_auto =
        is_for_columns
            ? item_style.MarginInlineEndUsing(root_grid_style).IsAuto()
            : item_style.MarginBlockEndUsing(root_grid_style).IsAuto();

    // 'auto' margin alignment is always "safe".
    if (is_start_auto || is_end_auto)
      *is_overflow_safe = true;

    if (is_start_auto && is_end_auto)
      return AxisEdge::kCenter;
    else if (is_start_auto)
      return AxisEdge::kEnd;
    else if (is_end_auto)
      return AxisEdge::kStart;
  }

  switch (const auto item_position = alignment.GetPosition()) {
    case ItemPosition::kSelfStart:
    case ItemPosition::kSelfEnd: {
      // In order to determine the correct "self" axis-edge without a
      // complicated set of if-branches we use two converters.

      // First use the grid-item's writing-direction to convert the logical
      // edge into the physical coordinate space.
      LogicalToPhysical<AxisEdge> physical(item_style.GetWritingDirection(),
                                           AxisEdge::kStart, AxisEdge::kEnd,
                                           AxisEdge::kStart, AxisEdge::kEnd);

      // Then use the container's writing-direction to convert the physical
      // edges, into our logical coordinate space.
      PhysicalToLogical<AxisEdge> logical(root_grid_writing_direction,
                                          physical.Top(), physical.Right(),
                                          physical.Bottom(), physical.Left());

      if (item_position == ItemPosition::kSelfStart) {
        return is_for_columns ? logical.InlineStart() : logical.BlockStart();
      }
      return is_for_columns ? logical.InlineEnd() : logical.BlockEnd();
    }
    case ItemPosition::kAnchorCenter:
    case ItemPosition::kCenter:
      return AxisEdge::kCenter;
    case ItemPosition::kFlexStart:
    case ItemPosition::kStart:
      return AxisEdge::kStart;
    case ItemPosition::kFlexEnd:
    case ItemPosition::kEnd:
      return AxisEdge::kEnd;
    case ItemPosition::kStretch:
      *auto_behavior = AutoSizeBehavior::kStretchExplicit;
      return AxisEdge::kStart;
    case ItemPosition::kBaseline:
      return AxisEdge::kFirstBaseline;
    case ItemPosition::kLastBaseline:
      return AxisEdge::kLastBaseline;
    case ItemPosition::kLeft:
      DCHECK(is_for_columns);
      return root_grid_writing_direction.IsLtr() ? AxisEdge::kStart
                                                 : AxisEdge::kEnd;
    case ItemPosition::kRight:
      DCHECK(is_for_columns);
      return root_grid_writing_direction.IsRtl() ? AxisEdge::kStart
                                                 : AxisEdge::kEnd;
    case ItemPosition::kNormal:
      *auto_behavior = is_replaced ? AutoSizeBehavior::kFitContent
                                   : AutoSizeBehavior::kStretchImplicit;
      return AxisEdge::kStart;
    case ItemPosition::kLegacy:
    case ItemPosition::kAuto:
      NOTREACHED();
  }
}

}  // namespace

GridItemData::GridItemData(
    BlockNode item_node,
    const ComputedStyle& parent_grid_style,
    const ComputedStyle& root_grid_style,
    bool parent_must_consider_grid_items_for_column_sizing,
    bool parent_must_consider_grid_items_for_row_sizing)
    : node(std::move(item_node)),
      has_subgridded_columns(false),
      has_subgridded_rows(false),
      is_considered_for_column_sizing(false),
      is_considered_for_row_sizing(false),
      is_sizing_dependent_on_block_size(false),
      is_subgridded_to_parent_grid(false),
      must_consider_grid_items_for_column_sizing(false),
      must_consider_grid_items_for_row_sizing(false),
      parent_grid_font_baseline(parent_grid_style.GetFontBaseline()) {
  const auto& style = node.Style();

  const auto root_grid_writing_direction =
      root_grid_style.GetWritingDirection();
  const auto item_writing_mode = style.GetWritingMode();

  is_parallel_with_root_grid = IsParallelWritingMode(
      root_grid_writing_direction.GetWritingMode(), item_writing_mode);

  column_baseline_writing_mode = DetermineBaselineWritingMode(
      root_grid_writing_direction, item_writing_mode,
      /* is_parallel_context */ false);

  row_baseline_writing_mode = DetermineBaselineWritingMode(
      root_grid_writing_direction, item_writing_mode,
      /* is_parallel_context */ true);

  // From https://drafts.csswg.org/css-grid-2/#subgrid-listing:
  //   "...if the grid container is otherwise forced to establish an independent
  //   formatting context... the grid container is not a subgrid."
  //
  // Only layout and paint containment establish an independent formatting
  // context as specified in:
  //   https://drafts.csswg.org/css-contain-2/#containment-layout
  //   https://drafts.csswg.org/css-contain-2/#containment-paint
  if (node.IsGrid() && !node.ShouldApplyLayoutContainment() &&
      !node.ShouldApplyPaintContainment() &&
      !style.IsContainerForSizeContainerQueries()) {
    has_subgridded_columns =
        is_parallel_with_root_grid
            ? style.GridTemplateColumns().IsSubgriddedAxis()
            : style.GridTemplateRows().IsSubgriddedAxis();
    has_subgridded_rows = is_parallel_with_root_grid
                              ? style.GridTemplateRows().IsSubgriddedAxis()
                              : style.GridTemplateColumns().IsSubgriddedAxis();
  }

  const bool is_out_of_flow = node.IsOutOfFlowPositioned();
  const bool is_replaced = node.IsReplaced();

  // Determine the alignment for the grid item ahead of time (we may need to
  // know if it stretches to correctly determine any block axis contribution).
  bool is_overflow_safe;
  column_alignment = AxisEdgeFromItemPosition(
      kForColumns, has_subgridded_columns, is_replaced, is_out_of_flow, style,
      parent_grid_style, root_grid_style, &column_auto_behavior,
      &is_overflow_safe);
  is_overflow_safe_for_columns = is_overflow_safe;

  column_baseline_group = DetermineBaselineGroup(
      root_grid_writing_direction, column_baseline_writing_mode,
      /* is_parallel_context */ false,
      /* is_last_baseline */ column_alignment == AxisEdge::kLastBaseline);

  row_alignment = AxisEdgeFromItemPosition(
      kForRows, has_subgridded_rows, is_replaced, is_out_of_flow, style,
      parent_grid_style, root_grid_style, &row_auto_behavior,
      &is_overflow_safe);
  is_overflow_safe_for_rows = is_overflow_safe;

  row_baseline_group = DetermineBaselineGroup(
      root_grid_writing_direction, row_baseline_writing_mode,
      /* is_parallel_context */ true,
      /* is_last_baseline */ row_alignment == AxisEdge::kLastBaseline);

  // The `false, true, false, true` parameters get the converter to calculate
  // whether the subgrids and its root grid are opposite direction in all cases.
  const LogicalToLogical<bool> direction_converter(
      style.GetWritingDirection(), root_grid_writing_direction,
      /* inline_start */ false, /* inline_end */ true,
      /* block_start */ false, /* block_end */ true);

  is_opposite_direction_in_root_grid_columns =
      direction_converter.InlineStart();
  is_opposite_direction_in_root_grid_rows = direction_converter.BlockStart();

  // From https://drafts.csswg.org/css-grid-2/#subgrid-size-contribution:
  //   The subgrid itself [...] acts as if it was completely empty for track
  //   sizing purposes in the subgridded dimension.
  //
  // Mark any subgridded axis as not considered for sizing, effectively ignoring
  // its contribution in `GridLayoutAlgorithm::ResolveIntrinsicTrackSizes`.
  if (parent_must_consider_grid_items_for_column_sizing) {
    must_consider_grid_items_for_column_sizing = has_subgridded_columns;
    is_considered_for_column_sizing = !has_subgridded_columns;
  }

  if (parent_must_consider_grid_items_for_row_sizing) {
    must_consider_grid_items_for_row_sizing = has_subgridded_rows;
    is_considered_for_row_sizing = !has_subgridded_rows;
  }
}

void GridItemData::SetAlignmentFallback(
    GridTrackSizingDirection track_direction,
    bool has_synthesized_baseline) {
  // Alignment fallback is only possible when baseline alignment is specified.
  if (!IsBaselineSpecified(track_direction)) {
    return;
  }

  auto CanParticipateInBaselineAlignment = [&]() -> bool {
    // "If baseline alignment is specified on a grid item whose size in that
    // axis depends on the size of an intrinsically-sized track (whose size is
    // therefore dependent on both the item’s size and baseline alignment,
    // creating a cyclic dependency), that item does not participate in
    // baseline alignment, and instead uses its fallback alignment as if that
    // were originally specified. For this purpose, <flex> track sizes count
    // as “intrinsically-sized” when the grid container has an indefinite size
    // in the relevant axis."
    // https://drafts.csswg.org/css-grid-2/#row-align
    if (has_synthesized_baseline &&
        (IsSpanningIntrinsicTrack(track_direction) ||
         IsSpanningFlexibleTrack(track_direction))) {
      // Parallel grid items with a synthesized baseline support baseline
      // alignment only of the height doesn't depend on the track size.
      const auto& item_style = node.Style();
      const bool is_parallel_to_baseline_axis =
          is_parallel_with_root_grid == (track_direction == kForRows);

      if (is_parallel_to_baseline_axis) {
        return !item_style.LogicalHeight().HasPercentOrStretch() &&
               !item_style.LogicalMinHeight().HasPercentOrStretch() &&
               !item_style.LogicalMaxHeight().HasPercentOrStretch();
      } else {
        return !item_style.LogicalWidth().HasPercentOrStretch() &&
               !item_style.LogicalMinWidth().HasPercentOrStretch() &&
               !item_style.LogicalMaxWidth().HasPercentOrStretch();
      }
    }
    return true;
  };

  auto& fallback_alignment = (track_direction == kForColumns)
                                 ? column_fallback_alignment
                                 : row_fallback_alignment;

  if (CanParticipateInBaselineAlignment()) {
    // Reset the alignment fallback if eligibility has changed.
    fallback_alignment.reset();
  } else {
    // Set fallback alignment to start edges if an item requests baseline
    // alignment but does not meet the requirements for it.
    fallback_alignment =
        (BaselineGroup(track_direction) == BaselineGroup::kMajor)
            ? AxisEdge::kStart
            : AxisEdge::kEnd;
  }
}

void GridItemData::ComputeSetIndices(
    const GridLayoutTrackCollection& track_collection) {
  DCHECK(!IsOutOfFlow());

  const auto track_direction = track_collection.Direction();
  DCHECK(MustCachePlacementIndices(track_direction));

  auto& range_indices = RangeIndices(track_direction);

#if DCHECK_IS_ON()
  if (range_indices.begin != kNotFound) {
    // Check the range index caching was correct by running a binary search.
    wtf_size_t computed_range_index =
        track_collection.RangeIndexFromGridLine(StartLine(track_direction));
    DCHECK_EQ(computed_range_index, range_indices.begin);

    computed_range_index =
        track_collection.RangeIndexFromGridLine(EndLine(track_direction) - 1);
    DCHECK_EQ(computed_range_index, range_indices.end);
  }
#endif

  if (range_indices.begin == kNotFound) {
    DCHECK_EQ(range_indices.end, kNotFound);

    range_indices.begin =
        track_collection.RangeIndexFromGridLine(StartLine(track_direction));
    range_indices.end =
        track_collection.RangeIndexFromGridLine(EndLine(track_direction) - 1);
  }

  DCHECK_LT(range_indices.end, track_collection.RangeCount());
  DCHECK_LE(range_indices.begin, range_indices.end);

  auto& set_indices =
      (track_direction == kForColumns) ? column_set_indices : row_set_indices;
  set_indices.begin = track_collection.RangeBeginSetIndex(range_indices.begin);
  set_indices.end = track_collection.RangeBeginSetIndex(range_indices.end) +
                    track_collection.RangeSetCount(range_indices.end);
}

void GridItemData::ComputeOutOfFlowItemPlacement(
    const GridLayoutTrackCollection& track_collection,
    const GridPlacementData& placement_data,
    const ComputedStyle& grid_style) {
  DCHECK(IsOutOfFlow());

  const auto track_direction = track_collection.Direction();
  const bool is_for_columns = track_direction == kForColumns;

  auto& start_line = is_for_columns ? column_placement.offset_in_range.begin
                                    : row_placement.offset_in_range.begin;
  auto& end_line = is_for_columns ? column_placement.offset_in_range.end
                                  : row_placement.offset_in_range.end;

  GridPlacement::ResolveOutOfFlowItemGridLines(
      track_collection, placement_data.line_resolver, grid_style, node.Style(),
      placement_data.StartOffset(track_direction), &start_line, &end_line);

#if DCHECK_IS_ON()
  if (start_line != kNotFound && end_line != kNotFound) {
    DCHECK_LE(end_line, track_collection.EndLineOfImplicitGrid());
    DCHECK_LT(start_line, end_line);
  } else if (start_line != kNotFound) {
    DCHECK_LE(start_line, track_collection.EndLineOfImplicitGrid());
  } else if (end_line != kNotFound) {
    DCHECK_LE(end_line, track_collection.EndLineOfImplicitGrid());
  }
#endif

  // We only calculate the range placement if the line was not defined as 'auto'
  // and it is within the bounds of the grid, since an out of flow item cannot
  // create grid lines.
  const wtf_size_t range_count = track_collection.RangeCount();
  auto& start_range_index = is_for_columns ? column_placement.range_index.begin
                                           : row_placement.range_index.begin;
  if (start_line != kNotFound) {
    if (!range_count) {
      // An undefined and empty grid has a single start/end grid line and no
      // ranges. Therefore, if the start offset isn't 'auto', the only valid
      // offset is zero.
      DCHECK_EQ(start_line, 0u);
      start_range_index = 0;
    } else {
      // If the start line of an out of flow item is the last line of the grid,
      // we can just subtract one unit to the range count.
      start_range_index =
          (start_line < track_collection.EndLineOfImplicitGrid())
              ? track_collection.RangeIndexFromGridLine(start_line)
              : range_count - 1;
      start_line -= track_collection.RangeStartLine(start_range_index);
    }
  }

  auto& end_range_index = is_for_columns ? column_placement.range_index.end
                                         : row_placement.range_index.end;
  if (end_line != kNotFound) {
    if (!range_count) {
      // Similarly to the start offset, if we have an undefined, empty grid and
      // the end offset isn't 'auto', the only valid offset is zero.
      DCHECK_EQ(end_line, 0u);
      end_range_index = 0;
    } else {
      // If the end line of an out of flow item is the first line of the grid,
      // then |last_spanned_range| is set to zero.
      end_range_index =
          end_line ? track_collection.RangeIndexFromGridLine(end_line - 1) : 0;
      end_line -= track_collection.RangeStartLine(end_range_index);
    }
  }
}

GridItems::GridItems(const GridItems& other)
    : first_subgridded_item_index_(other.first_subgridded_item_index_) {
  item_data_.ReserveInitialCapacity(other.item_data_.size());
  for (const auto& grid_item : other.item_data_) {
    item_data_.emplace_back(std::make_unique<GridItemData>(*grid_item));
  }
}

void GridItems::Append(GridItems* other) {
  item_data_.reserve(item_data_.size() + other->item_data_.size());
  for (auto& grid_item : other->item_data_)
    item_data_.emplace_back(std::move(grid_item));
}

void GridItems::SortByOrderProperty() {
  auto CompareItemsByOrderProperty =
      [](const std::unique_ptr<GridItemData>& lhs,
         const std::unique_ptr<GridItemData>& rhs) {
        return lhs->node.Style().Order() < rhs->node.Style().Order();
      };
  std::stable_sort(item_data_.begin(), item_data_.end(),
                   CompareItemsByOrderProperty);
}

}  // namespace blink
```