Response:
Let's break down the thought process for analyzing this `grid_placement.cc` file.

1. **Understand the Purpose:** The first and most crucial step is to understand the file's overall goal. The directory `blink/renderer/core/layout/grid/` immediately suggests it's related to CSS Grid Layout. The filename `grid_placement.cc` strongly indicates that this file is responsible for determining the position of grid items within a grid container.

2. **Identify Key Classes/Structures:**  Scan the code for important classes and structs. The primary class is `GridPlacement`. Other significant elements include:
    * `GridArea`: Represents the area a grid item occupies.
    * `GridSpan`: Defines the span of a grid item across grid lines.
    * `GridPlacementData`: Holds the final placement information.
    * `GridLineResolver`:  Responsible for resolving grid line names and numbers.
    * `AutoPlacementCursor`:  Manages the cursor during the auto-placement algorithm.
    * `PlacedGridItem`: Represents a grid item that has been placed.
    * `PlacedGridItemsList`:  Manages the list of placed grid items.
    * Enums like `AutoPlacementType` and `PackingBehavior`.

3. **Follow the Core Algorithm:** The function `RunAutoPlacementAlgorithm` is the heart of the file. Break down its steps:
    * **Step 1 (Place Non-Auto Items):**  This suggests handling explicitly positioned items first. The function `PlaceNonAutoGridItems` does this. Note how it deals with negative indices and calculates offsets for implicit grids.
    * **Step 2 (Process Locked Items):**  This refers to items with a definite position on the major axis but auto on the minor axis. `PlaceGridItemsLockedToMajorAxis` handles this.
    * **Step 3 (Determine Implicit Tracks):** The comment clarifies this is handled within the previous steps.
    * **Step 4 (Position Remaining Items):** This is the core auto-placement logic. It iterates through items not explicitly positioned and uses `PlaceAutoBothAxisGridItem` and `PlaceAutoMajorAxisGridItem`.

4. **Analyze Individual Functions:** For each important function, understand its inputs, operations, and outputs. For example:
    * `PlaceNonAutoGridItems`: Takes a list of grid items and determines their initial positions based on CSS properties. It also identifies items that need auto-placement.
    * `PlaceGridItemsLockedToMajorAxis`: Handles placing items with a fixed position on the major axis.
    * `PlaceAutoMajorAxisGridItem` and `PlaceAutoBothAxisGridItem`: Implement the auto-placement logic for different scenarios.
    * `MoveCursorToFitGridSpan`: A key function within auto-placement, responsible for finding a suitable spot for an item.

5. **Connect to CSS, HTML, and JavaScript:**  Think about how these functions relate to web development:
    * **CSS:**  The code directly interacts with `ComputedStyle` to get values from CSS properties like `grid-template-columns`, `grid-template-rows`, `grid-column-start`, `grid-row-start`, `grid-auto-flow`, etc. Provide concrete examples of how these CSS properties influence the placement logic.
    * **HTML:** The grid container and grid items are defined in HTML. The code operates *on* these elements to determine their layout. Show how HTML structures create the context for grid layout.
    * **JavaScript:** While this specific file isn't directly executed by JavaScript, the layout engine (Blink) that uses this code is triggered by browser rendering, which can be influenced by JavaScript manipulating the DOM and CSS styles.

6. **Consider Logic and Assumptions:**  Identify any logical deductions made in the code. For example, the `AutoPlacement` function makes decisions based on whether the grid item's span is definite or indefinite. Provide example inputs (e.g., `grid-column: auto / span 2;`) and the expected output (e.g., `AutoPlacementType::kMajor`).

7. **Identify Potential Errors:** Think about common mistakes developers make when using CSS Grid:
    * Incorrect grid line numbers/names.
    * Conflicting placement rules.
    * Misunderstanding `grid-auto-flow`.
    * Not accounting for implicit grid creation.
    * Issues with spanning items.

8. **Structure the Answer:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionalities.
    * Explain the relationships with CSS, HTML, and JavaScript with examples.
    * Provide logical reasoning with input/output examples.
    * Discuss common usage errors.

9. **Refine and Clarify:**  Review the answer for clarity and accuracy. Ensure the examples are easy to understand and directly relate to the code's functionality. Use precise terminology. For instance, distinguish between "explicit grid" and "implicit grid".

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just places grid items."  **Correction:** It's more nuanced. It handles both explicit placement and the auto-placement algorithm.
* **Initially focused too much on specific lines of code:** **Correction:** Shift the focus to the overall algorithms and data flow. The individual lines support these higher-level concepts.
* **Not enough concrete examples:** **Correction:**  Realized the need to illustrate the concepts with specific CSS and HTML snippets.
* **Overlooked the connection to implicit grids:** **Correction:** Recognized the importance of how the code handles items that extend beyond the explicitly defined grid.

By following this structured approach, including self-correction, you can thoroughly analyze and explain the functionality of a complex source code file like `grid_placement.cc`.
好的，我们来分析一下 `blink/renderer/core/layout/grid/grid_placement.cc` 这个文件。

**文件功能概述:**

`grid_placement.cc` 文件是 Chromium Blink 引擎中负责 CSS Grid 布局中网格项目放置的核心组件。它的主要功能是实现 CSS Grid 规范中定义的网格项目自动放置算法。简单来说，它决定了当网格项目没有被显式地定位在网格中时，它们应该如何被排列。

**具体功能分解:**

1. **自动放置算法 (`RunAutoPlacementAlgorithm`):** 这是该文件最核心的功能。它按照 CSS Grid 规范中详细描述的步骤，自动地将网格项目放置到网格中。这个算法会考虑以下因素：
    * **显式放置的网格项目:**  首先处理已经被明确指定了 `grid-row-start`, `grid-column-start` 等属性的网格项目。
    * **`grid-auto-flow` 属性:**  决定了自动放置是如何进行的，是按行填充 (`row`) 还是按列填充 (`column`)，以及是否采用密集填充 (`dense`) 或稀疏填充 (`sparse`)。
    * **隐式网格的创建:** 当网格项目被放置在显式定义的网格之外时，会自动创建额外的行或列。
    * **网格项目的尺寸:**  考虑网格项目自身的跨度 (`grid-row-span`, `grid-column-span`)。
    * **已放置的网格项目:**  避免与已经放置的网格项目重叠。

2. **处理非自动放置的网格项目 (`PlaceNonAutoGridItems`):** 这个函数负责处理那些已经被显式定位的网格项目。它会解析 CSS 样式中的定位信息，并将其转换为内部表示。同时，它也会确定需要进行自动放置的网格项目。

3. **处理锁定在主轴上的网格项目 (`PlaceGridItemsLockedToMajorAxis`):**  这个函数处理那些在 `grid-auto-flow` 指定的主轴方向上是自动放置，但在交叉轴方向上有明确位置的网格项目。

4. **自动放置单轴网格项目 (`PlaceAutoMajorAxisGridItem`):**  当网格项目在主轴方向上是自动放置时，此函数负责找到合适的放置位置。

5. **自动放置双轴网格项目 (`PlaceAutoBothAxisGridItem`):** 当网格项目在两个轴向上都是自动放置时，此函数负责找到合适的放置位置。

6. **网格项目的最终放置 (`PlaceGridItemAtCursor`):**  一旦确定了网格项目的位置，这个函数会将其添加到已放置项目的列表中。

7. **处理子网格 (`ClampGridItemsToFitSubgridArea`, `ClampMinorMaxToSubgridArea`):** 当网格容器是子网格时，需要确保网格项目的放置不会超出子网格的范围。这些函数负责进行边界检查和调整。

8. **辅助数据结构和类:**
    * `GridPlacementData`: 存储网格项目的放置结果和其他相关信息。
    * `GridLineResolver`:  用于解析 CSS 样式中定义的网格线名称和编号。
    * `AutoPlacementCursor`:  在自动放置过程中跟踪当前放置位置。
    * `PlacedGridItem`:  表示一个已经被放置的网格项目，包含其位置信息。
    * `PlacedGridItemsList`:  管理已放置的网格项目列表。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`grid_placement.cc` 的功能直接关联到 CSS Grid Layout 的实现，因此与 JavaScript, HTML, CSS 都有密切关系。

* **CSS:**  这个文件直接读取和解析 CSS 属性来决定网格项目的放置。
    * **示例:**  当 CSS 中设置了 `grid-auto-flow: row dense;` 时，`GridPlacement` 对象会根据这个设置选择相应的自动放置策略（按行填充，密集填充）。`packing_behavior_` 和 `major_direction_` 等成员变量会根据 CSS 的值进行初始化。
    * **示例:**  如果 CSS 中定义了 `grid-column: span 2; grid-row: auto;`，那么在 `RunAutoPlacementAlgorithm` 中，`AutoPlacement(*position, major_direction_)` 会返回 `AutoPlacementType::kMajor`，表明需要在主轴方向上进行自动放置。

* **HTML:** HTML 结构定义了网格容器和网格项目。`grid_placement.cc` 的作用就是根据这些 HTML 元素及其关联的 CSS 样式来计算布局。
    * **示例:**  以下 HTML 结构包含一个网格容器和几个网格项目：
      ```html
      <div style="display: grid; grid-template-columns: 100px 100px;">
        <div>Item 1</div>
        <div style="grid-column: 2;">Item 2</div>
        <div>Item 3</div>
      </div>
      ```
      `grid_placement.cc` 会处理这些 `div` 元素的布局。`Item 2` 显式地放置在第二列，而 `Item 1` 和 `Item 3` 的位置将由自动放置算法决定。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响 `grid_placement.cc` 的行为。
    * **示例:**  JavaScript 可以添加或删除网格项目，或者修改网格容器的 `grid-template-columns` 属性。这些操作会导致浏览器重新计算布局，并再次调用 `grid_placement.cc` 中的相关函数来确定新的网格项目位置。

**逻辑推理及假设输入与输出:**

假设我们有以下 CSS 和 HTML：

**CSS:**

```css
.container {
  display: grid;
  grid-template-columns: 50px 50px;
  grid-auto-flow: row dense;
}

.item1 {
  grid-column: 1;
}

.item3 {
  grid-row: 2;
}
```

**HTML:**

```html
<div class="container">
  <div class="item1">Item 1</div>
  <div>Item 2</div>
  <div class="item3">Item 3</div>
  <div>Item 4</div>
</div>
```

**逻辑推理:**

1. **`PlaceNonAutoGridItems`:**
   - `Item 1` 的 `grid-column: 1` 会被解析，其列起始位置被确定为 1。
   - `Item 3` 的 `grid-row: 2` 会被解析，其行起始位置被确定为 2。
   - `Item 2` 和 `Item 4` 没有显式的位置信息，需要进行自动放置。

2. **`RunAutoPlacementAlgorithm`:**
   - 首先放置 `Item 1` 和 `Item 3`。
   - 然后处理需要自动放置的 `Item 2` 和 `Item 4`。由于 `grid-auto-flow: row dense;`，算法会尝试在已放置项目后尽可能紧凑地放置剩余项目。
   - `Item 2` 会尝试放在第一行的空闲位置。如果第一行 `Item 1` 之后有空间，则放在那里。
   - `Item 4` 会尝试放在下一行的空闲位置。

**假设输入与输出 (针对 `RunAutoPlacementAlgorithm` 中处理自动放置部分):**

**假设输入:**  一个包含 `Item 2` 和 `Item 4` 的待放置列表，以及当前的网格状态（`Item 1` 在第一列，`Item 3` 在第二行）。

**预期输出:**

- `Item 2` 的最终位置：行 1，列 2 (假设第一行有空闲空间)。
- `Item 4` 的最终位置：行 2，列 1 (由于 `dense` 填充，会尝试填充前面的空位)。

**用户或编程常见的使用错误及举例说明:**

1. **网格线索引错误:**  使用超出网格范围的索引或错误的命名网格线。
   * **示例 CSS:** `grid-column-start: 99;` (如果网格只有少量列)。这会导致项目放置在隐式创建的轨道上，可能不是预期的结果。

2. **`grid-auto-flow` 理解错误:**  不理解 `dense` 和 `sparse` 的区别，导致自动放置结果与预期不符。
   * **示例:** 期望项目按顺序填充，但使用了 `grid-auto-flow: column;`，导致项目按列填充，顺序可能被打乱。

3. **显式放置冲突:**  多个项目被显式地放置在同一个网格区域。
   * **示例 CSS:**
     ```css
     .item1 { grid-column: 1; grid-row: 1; }
     .item2 { grid-column: 1; grid-row: 1; }
     ```
     这会导致其中一个项目覆盖另一个项目，具体哪个被覆盖取决于它们在 HTML 中的顺序。`grid_placement.cc` 会按照规则进行放置，但开发者可能没有意识到这种冲突。

4. **负索引理解错误:**  不理解负索引的工作方式（相对于网格末尾计算）。
   * **示例 CSS:** `grid-column-end: -1;` 可能被误认为放置到倒数第一列的 *起始线*，实际上是放置到最后一列的 *结束线*。

5. **未考虑隐式网格:**  假设所有项目都在显式定义的网格内，但实际上由于自动放置，项目可能会被放置到隐式创建的轨道上。
   * **示例:**  如果 `grid-row-start` 设置了一个很大的值，而 `grid-template-rows` 定义的行数很少，则项目会被放置在隐式创建的行上。

总而言之，`grid_placement.cc` 是 Blink 引擎中实现 CSS Grid 布局自动放置逻辑的关键部分，它根据 CSS 属性和 HTML 结构来智能地安排网格项目中那些没有被显式定位的部分。理解其工作原理有助于开发者更好地掌握和使用 CSS Grid 布局。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_placement.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_placement.h"

#include "third_party/blink/renderer/core/layout/grid/grid_item.h"

namespace blink {

namespace {

enum class AutoPlacementType { kNotNeeded, kMajor, kMinor, kBoth };

AutoPlacementType AutoPlacement(const GridArea& position,
                                GridTrackSizingDirection major_direction) {
  const GridTrackSizingDirection minor_direction =
      (major_direction == kForColumns) ? kForRows : kForColumns;
  DCHECK(!position.Span(major_direction).IsUntranslatedDefinite() &&
         !position.Span(minor_direction).IsUntranslatedDefinite());

  const bool is_major_indefinite =
      position.Span(major_direction).IsIndefinite();
  const bool is_minor_indefinite =
      position.Span(minor_direction).IsIndefinite();

  if (is_minor_indefinite && is_major_indefinite)
    return AutoPlacementType::kBoth;
  if (is_minor_indefinite)
    return AutoPlacementType::kMinor;
  if (is_major_indefinite)
    return AutoPlacementType::kMajor;
  return AutoPlacementType::kNotNeeded;
}

}  // namespace

GridPlacement::GridPlacement(const ComputedStyle& grid_style,
                             const GridLineResolver& line_resolver)
    : placement_data_(line_resolver),
      packing_behavior_(grid_style.IsGridAutoFlowAlgorithmSparse()
                            ? PackingBehavior::kSparse
                            : PackingBehavior::kDense),
      // The major direction is the one specified in the 'grid-auto-flow'
      // property (row or column), the minor direction is its opposite.
      major_direction_(grid_style.IsGridAutoFlowDirectionRow() ? kForRows
                                                               : kForColumns),
      minor_direction_(grid_style.IsGridAutoFlowDirectionRow() ? kForColumns
                                                               : kForRows) {}

// https://drafts.csswg.org/css-grid/#auto-placement-algo
GridPlacementData GridPlacement::RunAutoPlacementAlgorithm(
    const GridItems& grid_items) {
#if DCHECK_IS_ON()
  DCHECK(!auto_placement_algorithm_called_)
      << "Auto-placement algorithm should only be called once.";
  auto_placement_algorithm_called_ = true;
#endif

  auto FinalizeResolvedPositions = [&]() -> GridPlacementData {
    ClampGridItemsToFitSubgridArea(kForColumns);
    ClampGridItemsToFitSubgridArea(kForRows);
    return std::move(placement_data_);
  };

  // Step 1. Position anything that’s not auto-placed; if no items need
  // auto-placement, then we are done.
  PlacedGridItemsList placed_items;
  PositionVector positions_locked_to_major_axis;
  PositionVector positions_not_locked_to_major_axis;

  if (!PlaceNonAutoGridItems(grid_items, &placed_items,
                             &positions_locked_to_major_axis,
                             &positions_not_locked_to_major_axis)) {
    return FinalizeResolvedPositions();
  }

  placed_items.AppendCurrentItemsToOrderedList();

  // Step 2. Process the items locked to the major axis.
  PlaceGridItemsLockedToMajorAxis(positions_locked_to_major_axis,
                                  &placed_items);

  // Step 3. Determine the number of minor tracks in the implicit grid.
  // This is already accomplished within the |PlaceNonAutoGridItems| and
  // |PlaceGridItemsLockedToMajorAxis| methods; nothing else to do here.

  // Before performing auto placement, clamp items to the subgridded area so the
  // auto-placement algorithm is dealing with accurate positions.
  ClampGridItemsToFitSubgridArea(kForColumns);
  ClampGridItemsToFitSubgridArea(kForRows);

  // Step 4. Position remaining grid items.
  AutoPlacementCursor placement_cursor(placed_items.FirstPlacedItem());
  for (auto* position : positions_not_locked_to_major_axis) {
    switch (AutoPlacement(*position, major_direction_)) {
      case AutoPlacementType::kBoth:
        PlaceAutoBothAxisGridItem(position, &placed_items, &placement_cursor);
        break;
      case AutoPlacementType::kMajor:
        PlaceAutoMajorAxisGridItem(position, &placed_items, &placement_cursor);
        break;
      case AutoPlacementType::kMinor:
      case AutoPlacementType::kNotNeeded:
        NOTREACHED() << "Placement of non-auto placed items and items locked "
                        "to a major axis should've already occurred.";
    }
    if (!HasSparsePacking()) {
      // For dense packing, set the cursor’s major and minor positions to the
      // start-most row and column lines in the implicit grid.
      placement_cursor = AutoPlacementCursor(placed_items.FirstPlacedItem());
    }
  }
  return FinalizeResolvedPositions();
}

bool GridPlacement::PlaceNonAutoGridItems(
    const GridItems& grid_items,
    PlacedGridItemsList* placed_items,
    PositionVector* positions_locked_to_major_axis,
    PositionVector* positions_not_locked_to_major_axis) {
  DCHECK(placed_items && positions_locked_to_major_axis &&
         positions_not_locked_to_major_axis);

  placement_data_.grid_item_positions.ReserveInitialCapacity(grid_items.Size());
  placement_data_.column_start_offset = placement_data_.row_start_offset = 0;

  for (const auto& grid_item : grid_items) {
    const auto& item_style = grid_item.node.Style();

    GridArea position;
    position.columns =
        placement_data_.line_resolver.ResolveGridPositionsFromStyle(
            item_style, kForColumns);
    DCHECK(!position.columns.IsTranslatedDefinite());

    position.rows = placement_data_.line_resolver.ResolveGridPositionsFromStyle(
        item_style, kForRows);
    DCHECK(!position.rows.IsTranslatedDefinite());

    // When we have negative indices that go beyond the start of the explicit
    // grid we need to prepend tracks to it; count how many tracks are needed by
    // checking the minimum negative start line of definite spans, the negative
    // of that minimum is the number of tracks we need to prepend.
    // Simplifying the logic above: maximize the negative value of start lines.
    if (position.columns.IsUntranslatedDefinite()) {
      placement_data_.column_start_offset =
          std::max<int>(placement_data_.column_start_offset,
                        -position.columns.UntranslatedStartLine());
    }

    if (position.rows.IsUntranslatedDefinite()) {
      placement_data_.row_start_offset =
          std::max<int>(placement_data_.row_start_offset,
                        -position.rows.UntranslatedStartLine());
    }
    placement_data_.grid_item_positions.emplace_back(position);
  }

  minor_max_end_line_ = IntrinsicEndLine(minor_direction_);

  placed_items->needs_to_sort_item_vector = false;
  auto& non_auto_placed_items = placed_items->item_vector;
  non_auto_placed_items.ReserveInitialCapacity(grid_items.Size());

  for (auto& position : placement_data_.grid_item_positions) {
    GridSpan item_major_span = position.Span(major_direction_);
    GridSpan item_minor_span = position.Span(minor_direction_);

    const bool has_indefinite_major_span = item_major_span.IsIndefinite();
    const bool has_indefinite_minor_span = item_minor_span.IsIndefinite();

    if (!has_indefinite_major_span) {
      item_major_span.Translate((major_direction_ == kForColumns)
                                    ? placement_data_.column_start_offset
                                    : placement_data_.row_start_offset);
      position.SetSpan(item_major_span, major_direction_);
    }

    if (!has_indefinite_minor_span) {
      item_minor_span.Translate((minor_direction_ == kForColumns)
                                    ? placement_data_.column_start_offset
                                    : placement_data_.row_start_offset);
      position.SetSpan(item_minor_span, minor_direction_);
    }

    minor_max_end_line_ = std::max<wtf_size_t>(
        minor_max_end_line_, has_indefinite_minor_span
                                 ? item_minor_span.IndefiniteSpanSize()
                                 : item_minor_span.EndLine());

    // Prevent intrinsic tracks from overflowing the subgrid.
    if (!placement_data_.HasStandaloneAxis(minor_direction_)) {
      ClampMinorMaxToSubgridArea();
    }

    if (!has_indefinite_major_span && !has_indefinite_minor_span) {
      auto placed_item = std::make_unique<PlacedGridItem>(
          position, major_direction_, minor_direction_);

      // We will need to sort the item vector if the new placed item should be
      // inserted to the ordered list before the last item in the vector.
      placed_items->needs_to_sort_item_vector |=
          !non_auto_placed_items.empty() &&
          *placed_item < *non_auto_placed_items.back();

      non_auto_placed_items.emplace_back(std::move(placed_item));
    } else {
      if (has_indefinite_major_span)
        positions_not_locked_to_major_axis->emplace_back(&position);
      else
        positions_locked_to_major_axis->emplace_back(&position);
    }
  }
  return !positions_not_locked_to_major_axis->empty() ||
         !positions_locked_to_major_axis->empty();
}

void GridPlacement::PlaceGridItemsLockedToMajorAxis(
    const PositionVector& positions_locked_to_major_axis,
    PlacedGridItemsList* placed_items) {
  DCHECK(placed_items);

  // Mapping between the major axis tracks and the last auto-placed item's end
  // line inserted on that track. This is needed to implement "sparse" packing
  // for grid items locked to a given major axis track.
  // See https://drafts.csswg.org/css-grid/#auto-placement-algo.
  HashMap<wtf_size_t, wtf_size_t, IntWithZeroKeyHashTraits<wtf_size_t>>
      minor_cursors;

  for (auto* position : positions_locked_to_major_axis) {
    DCHECK_EQ(AutoPlacement(*position, major_direction_),
              AutoPlacementType::kMinor);

    const wtf_size_t minor_span_size =
        position->Span(minor_direction_).IndefiniteSpanSize();
    const wtf_size_t major_start_line = position->StartLine(major_direction_);

    AutoPlacementCursor placement_cursor(placed_items->FirstPlacedItem());
    placement_cursor.MoveToMajorLine(major_start_line);
    if (HasSparsePacking() && minor_cursors.Contains(major_start_line))
      placement_cursor.MoveToMinorLine(minor_cursors.at(major_start_line));

    placement_cursor.MoveCursorToFitGridSpan(
        position->SpanSize(major_direction_), minor_span_size,
        minor_max_end_line_, CursorMovementBehavior::kForceMajorLine);

    wtf_size_t minor_end_line = placement_cursor.MinorLine() + minor_span_size;
    if (HasSparsePacking())
      minor_cursors.Set(major_start_line, minor_end_line);
    minor_max_end_line_ = std::max(minor_max_end_line_, minor_end_line);

    // Prevent intrinsic tracks from overflowing the subgrid.
    if (!placement_data_.HasStandaloneAxis(minor_direction_)) {
      ClampMinorMaxToSubgridArea();
    }

    // Update grid item placement for minor axis.
    GridSpan grid_item_span = GridSpan::TranslatedDefiniteGridSpan(
        placement_cursor.MinorLine(), minor_end_line);
    position->SetSpan(grid_item_span, minor_direction_);

    PlaceGridItemAtCursor(*position, placed_items, &placement_cursor);
  }
}

void GridPlacement::PlaceAutoMajorAxisGridItem(
    GridArea* position,
    PlacedGridItemsList* placed_items,
    AutoPlacementCursor* placement_cursor) const {
  DCHECK(position && placed_items && placement_cursor);
  const wtf_size_t major_span_size =
      position->Span(major_direction_).IndefiniteSpanSize();

  placement_cursor->MoveToMinorLine(position->StartLine(minor_direction_));
  placement_cursor->MoveCursorToFitGridSpan(
      major_span_size, position->SpanSize(minor_direction_),
      minor_max_end_line_, CursorMovementBehavior::kForceMinorLine);

  // Update grid item placement for major axis.
  GridSpan grid_item_span = GridSpan::TranslatedDefiniteGridSpan(
      placement_cursor->MajorLine(),
      placement_cursor->MajorLine() + major_span_size);
  position->SetSpan(grid_item_span, major_direction_);

  PlaceGridItemAtCursor(*position, placed_items, placement_cursor);
}

void GridPlacement::PlaceAutoBothAxisGridItem(
    GridArea* position,
    PlacedGridItemsList* placed_items,
    AutoPlacementCursor* placement_cursor) const {
  DCHECK(position && placed_items && placement_cursor);

  const wtf_size_t major_span_size =
      position->Span(major_direction_).IndefiniteSpanSize();
  const wtf_size_t minor_span_size =
      position->Span(minor_direction_).IndefiniteSpanSize();

  placement_cursor->MoveCursorToFitGridSpan(major_span_size, minor_span_size,
                                            minor_max_end_line_,
                                            CursorMovementBehavior::kAuto);

  // Update grid item placement for both axis.
  GridSpan grid_item_span = GridSpan::TranslatedDefiniteGridSpan(
      placement_cursor->MajorLine(),
      placement_cursor->MajorLine() + major_span_size);
  position->SetSpan(grid_item_span, major_direction_);

  grid_item_span = GridSpan::TranslatedDefiniteGridSpan(
      placement_cursor->MinorLine(),
      placement_cursor->MinorLine() + minor_span_size);
  position->SetSpan(grid_item_span, minor_direction_);

  PlaceGridItemAtCursor(*position, placed_items, placement_cursor);
}

void GridPlacement::PlaceGridItemAtCursor(
    const GridArea& position,
    PlacedGridItemsList* placed_items,
    AutoPlacementCursor* placement_cursor) const {
  DCHECK(placed_items && placement_cursor);

  auto new_placed_item = std::make_unique<PlacedGridItem>(
      position, major_direction_, minor_direction_);
  const auto* next_placed_item = placement_cursor->NextPlacedItem();

  placed_items->ordered_list.InsertAfter(
      new_placed_item.get(), next_placed_item
                                 ? next_placed_item->Prev()
                                 : placed_items->ordered_list.Tail());

  placement_cursor->InsertPlacedItemAtCurrentPosition(new_placed_item.get());
  placed_items->item_vector.emplace_back(std::move(new_placed_item));
}

void GridPlacement::ClampGridItemsToFitSubgridArea(
    GridTrackSizingDirection track_direction) {
  const wtf_size_t subgrid_span_size =
      placement_data_.SubgridSpanSize(track_direction);

  // If no subgrid span size was specified, then we should create implicit grid
  // lines for placement, so we don't need to clamp the resolved positions.
  if (subgrid_span_size == kNotFound)
    return;

  DCHECK_GT(subgrid_span_size, 0u);
  const int start_offset = placement_data_.StartOffset(track_direction);

  for (auto& resolved_position : placement_data_.grid_item_positions) {
    // This may be called before all positions are finalized. Any definite
    // positions need to be clamped, as their positions may be used to determine
    // relative positions of the positions that are still indefinite. While
    // clamping, these indefinite positions can be skipped.
    if ((track_direction == kForColumns &&
         !resolved_position.columns.IsTranslatedDefinite()) ||
        (track_direction == kForRows &&
         !resolved_position.rows.IsTranslatedDefinite())) {
      continue;
    }

    int start_line =
        resolved_position.StartLine(track_direction) - start_offset;
    int end_line = resolved_position.EndLine(track_direction) - start_offset;

    resolved_position.SetSpan(
        GridSpan::TranslatedDefiniteGridSpan(
            ClampTo<int>(start_line, 0, subgrid_span_size - 1),
            ClampTo<int>(end_line, 1, subgrid_span_size)),
        track_direction);
  }

  // At this point, any grid item placed on a implicit grid line before the
  // subgrid's explicit grid should be clamped to its first line.
  // As such, the start offset of the explicit grid should be 0.
  if (track_direction == kForColumns)
    placement_data_.column_start_offset = 0;
  else
    placement_data_.row_start_offset = 0;
}

void GridPlacement::ClampMinorMaxToSubgridArea() {
  DCHECK(!placement_data_.HasStandaloneAxis(minor_direction_));
  wtf_size_t subgrid_max_size = IntrinsicEndLine(minor_direction_);

  // `minor_max_end_line_` starts at `subgrid_max_size` and can only grow
  // larger.
  DCHECK_GE(minor_max_end_line_, subgrid_max_size);
  if (minor_max_end_line_ > subgrid_max_size) {
    minor_max_end_line_ = subgrid_max_size;
  }
}

bool GridPlacement::HasSparsePacking() const {
  return packing_behavior_ == PackingBehavior::kSparse;
}

wtf_size_t GridPlacement::IntrinsicEndLine(
    GridTrackSizingDirection track_direction) const {
  return (track_direction == kForColumns)
             ? placement_data_.column_start_offset +
                   placement_data_.ExplicitGridTrackCount(kForColumns)
             : placement_data_.row_start_offset +
                   placement_data_.ExplicitGridTrackCount(kForRows);
}

// A grid position is defined as the intersection between a line from the major
// axis and another from the minor axis. Following the auto-placement algorithm
// convention, a position with lesser major axis line comes first; in case of
// ties, a position with lesser minor axis line comes first.
bool GridPlacement::GridPosition::operator<=(const GridPosition& other) const {
  return (major_line == other.major_line) ? minor_line <= other.minor_line
                                          : major_line < other.major_line;
}
bool GridPlacement::GridPosition::operator<(const GridPosition& other) const {
  return (major_line != other.major_line) ? major_line < other.major_line
                                          : minor_line < other.minor_line;
}

GridPlacement::PlacedGridItem::PlacedGridItem(
    const GridArea& position,
    GridTrackSizingDirection major_direction,
    GridTrackSizingDirection minor_direction)
    : start_{position.StartLine(major_direction),
             position.StartLine(minor_direction)},
      end_{position.EndLine(major_direction),
           position.EndLine(minor_direction)} {}

GridPlacement::GridPosition
GridPlacement::PlacedGridItem::EndOnPreviousMajorLine() const {
  DCHECK_GT(end_.major_line, 0u);
  return {end_.major_line - 1, end_.minor_line};
}

void GridPlacement::AutoPlacementCursor::MoveCursorToFitGridSpan(
    const wtf_size_t major_span_size,
    const wtf_size_t minor_span_size,
    const wtf_size_t minor_max_end_line,
    const CursorMovementBehavior movement_behavior) {
  DCHECK_LE(minor_span_size, minor_max_end_line);

  wtf_size_t next_minor_line;
  const bool allow_minor_line_movement =
      movement_behavior != CursorMovementBehavior::kForceMinorLine;

  // If we want to force the current major line, it's okay to place this grid
  // span beyond the implicit grid's maximum minor end line.
  const wtf_size_t minor_max_start_line =
      (movement_behavior == CursorMovementBehavior::kForceMajorLine)
          ? minor_max_end_line
          : minor_max_end_line - minor_span_size;

  auto NeedsToMoveToNextMajorLine = [&]() -> bool {
    // If we need to force the minor line, or the grid span would go beyond the
    // maximum minor end line, there is no point to keep looking for overlapping
    // items in the current major line, i.e. needs to move the major line.
    return next_minor_line > minor_max_start_line ||
           (!allow_minor_line_movement &&
            next_minor_line != current_position_.minor_line);
  };

  auto DoesCurrentPositionFitGridSpan = [&]() -> bool {
    if (NeedsToMoveToNextMajorLine()) {
      MoveToNextMajorLine(allow_minor_line_movement);
    } else {
      // If the minor line didn't move, it means there was no overlap with any
      // previously placed item, and we don't need to move any further.
      if (current_position_.minor_line == next_minor_line)
        return true;

      DCHECK_LT(current_position_.minor_line, next_minor_line);
      MoveToMinorLine(next_minor_line);
    }
    return false;
  };

  if (current_position_.minor_line > minor_max_start_line)
    MoveToNextMajorLine(allow_minor_line_movement);

  while (true) {
    UpdateItemsOverlappingMajorLine();
    next_minor_line = current_position_.minor_line;
    for (const auto* placed_item : items_overlapping_major_line_) {
      const wtf_size_t minor_span_end_line = next_minor_line + minor_span_size;
      const wtf_size_t item_minor_end_line = placed_item->MinorEndLine();

      // Since we know that this item will overlap with the current major line,
      // we only need to check if the minor span will overlap too.
      if (next_minor_line < item_minor_end_line &&
          placed_item->MinorStartLine() < minor_span_end_line) {
        next_minor_line = item_minor_end_line;
        if (NeedsToMoveToNextMajorLine())
          break;
      }
    }

    // If the next minor line was moved because it overlapped with a placed
    // item, we don't need to check for overlaps with the rest of the upcoming
    // placed items; keep looking for a position that doesn't overlap with the
    // set of items overlapping the current major line first.
    if (!DoesCurrentPositionFitGridSpan())
      continue;

    const auto* upcoming_item = next_placed_item_;
    while (upcoming_item) {
      const wtf_size_t major_span_end_line =
          current_position_.major_line + major_span_size;
      const wtf_size_t minor_span_end_line = next_minor_line + minor_span_size;
      const wtf_size_t item_minor_end_line = upcoming_item->MinorEndLine();

      // Check if the cursor would overlap the upcoming placed item.
      if (next_minor_line < item_minor_end_line &&
          current_position_.major_line < upcoming_item->MajorEndLine() &&
          upcoming_item->MajorStartLine() < major_span_end_line &&
          upcoming_item->MinorStartLine() < minor_span_end_line) {
        next_minor_line = item_minor_end_line;
        if (NeedsToMoveToNextMajorLine())
          break;
      }
      upcoming_item = upcoming_item->Next();
    }

    if (DoesCurrentPositionFitGridSpan()) {
      // No overlap with any placed item.
      break;
    }
  }
}

void GridPlacement::AutoPlacementCursor::UpdateItemsOverlappingMajorLine() {
  DCHECK(std::is_heap(items_overlapping_major_line_.begin(),
                      items_overlapping_major_line_.end(),
                      ComparePlacedGridItemsByEnd));

  while (!items_overlapping_major_line_.empty()) {
    // Notice that the |EndOnPreviousMajorLine| of an item "A" is the first
    // position such that any upcoming grid position (located at a greater
    // major/minor position) is guaranteed to not overlap with "A".
    auto last_overlapping_position =
        items_overlapping_major_line_.front()->EndOnPreviousMajorLine();

    // We cannot discard any items since they're still overlapping.
    if (current_position_ < last_overlapping_position)
      break;

    // When we are located at the major line right before the current item's
    // major end line, we want to ensure that we move to the next major line
    // since it won't be considered overlapping in |MoveToNextMajorLine| now
    // that we moved past the item's |EndOnPreviousMajorLine|.
    if (current_position_.major_line == last_overlapping_position.major_line)
      should_move_to_next_item_major_end_line_ = false;

    std::pop_heap(items_overlapping_major_line_.begin(),
                  items_overlapping_major_line_.end(),
                  ComparePlacedGridItemsByEnd);
    items_overlapping_major_line_.pop_back();
  }

  while (next_placed_item_ && next_placed_item_->Start() <= current_position_) {
    auto last_overlapping_position =
        next_placed_item_->EndOnPreviousMajorLine();

    // If the current position's major line overlaps the next placed item, we
    // should retry the auto-placement algorithm on the next major line before
    // trying to skip to the nearest major end line of an overlapping item.
    if (current_position_.major_line <= last_overlapping_position.major_line)
      should_move_to_next_item_major_end_line_ = false;

    if (current_position_ < last_overlapping_position) {
      items_overlapping_major_line_.emplace_back(next_placed_item_);
      std::push_heap(items_overlapping_major_line_.begin(),
                     items_overlapping_major_line_.end(),
                     ComparePlacedGridItemsByEnd);
    }
    next_placed_item_ = next_placed_item_->Next();
  }
}

void GridPlacement::AutoPlacementCursor::MoveToMajorLine(
    const wtf_size_t major_line) {
  DCHECK_LE(current_position_.major_line, major_line);
  current_position_.major_line = major_line;
}

void GridPlacement::AutoPlacementCursor::MoveToMinorLine(
    const wtf_size_t minor_line) {
  // Since the auto-placement cursor only moves forward to the next minor line,
  // if the cursor is located at a position after the minor line we want to
  // force, cycle back to such minor line in the next major line.
  if (minor_line < current_position_.minor_line)
    ++current_position_.major_line;
  current_position_.minor_line = minor_line;
}

void GridPlacement::AutoPlacementCursor::MoveToNextMajorLine(
    bool allow_minor_line_movement) {
  ++current_position_.major_line;

  if (should_move_to_next_item_major_end_line_ &&
      !items_overlapping_major_line_.empty()) {
    DCHECK_GE(items_overlapping_major_line_.front()->MajorEndLine(),
              current_position_.major_line);
    current_position_.major_line =
        items_overlapping_major_line_.front()->MajorEndLine();
  }

  if (allow_minor_line_movement)
    current_position_.minor_line = 0;
  should_move_to_next_item_major_end_line_ = true;
}

void GridPlacement::AutoPlacementCursor::InsertPlacedItemAtCurrentPosition(
    const PlacedGridItem* new_placed_item) {
  // This update must happen after the doubly linked list already updated its
  // element links to keep the necessary order for the cursor's logic.
#if DCHECK_IS_ON()
  if (next_placed_item_) {
    DCHECK_EQ(next_placed_item_->Prev(), new_placed_item);
    DCHECK(*new_placed_item < *next_placed_item_);
  }
#endif
  DCHECK_EQ(new_placed_item->Next(), next_placed_item_);
  next_placed_item_ = new_placed_item;

  MoveToMinorLine(new_placed_item->MinorEndLine());
  UpdateItemsOverlappingMajorLine();
}

void GridPlacement::PlacedGridItemsList::AppendCurrentItemsToOrderedList() {
  DCHECK(ordered_list.empty());

  auto ComparePlacedGridItemPointers =
      [](const std::unique_ptr<PlacedGridItem>& lhs,
         const std::unique_ptr<PlacedGridItem>& rhs) { return *lhs < *rhs; };

  if (needs_to_sort_item_vector) {
    std::sort(item_vector.begin(), item_vector.end(),
              ComparePlacedGridItemPointers);
  }
  DCHECK(std::is_sorted(item_vector.begin(), item_vector.end(),
                        ComparePlacedGridItemPointers));

  for (auto& placed_item : item_vector)
    ordered_list.Append(placed_item.get());
}

// static
void GridPlacement::ResolveOutOfFlowItemGridLines(
    const GridLayoutTrackCollection& track_collection,
    const GridLineResolver& line_resolver,
    const ComputedStyle& grid_style,
    const ComputedStyle& item_style,
    wtf_size_t start_offset,
    wtf_size_t* start_line,
    wtf_size_t* end_line) {
  DCHECK(start_line && end_line);

  *start_line = kNotFound;
  *end_line = kNotFound;

  const auto track_direction = track_collection.Direction();
  const bool is_for_columns = track_direction == kForColumns;

  const auto span =
      line_resolver.ResolveGridPositionsFromStyle(item_style, track_direction);

  if (span.IsIndefinite())
    return;

  const int span_start_line = span.UntranslatedStartLine() + start_offset;
  const int span_end_line = span.UntranslatedEndLine() + start_offset;

  if (span_start_line >= 0 &&
      (is_for_columns ? !item_style.GridColumnStart().IsAuto()
                      : !item_style.GridRowStart().IsAuto()) &&
      track_collection.IsGridLineWithinImplicitGrid(span_start_line)) {
    *start_line = span_start_line;
  }

  if (span_end_line >= 0 &&
      (is_for_columns ? !item_style.GridColumnEnd().IsAuto()
                      : !item_style.GridRowEnd().IsAuto()) &&
      track_collection.IsGridLineWithinImplicitGrid(span_end_line)) {
    *end_line = span_end_line;
  }
}

}  // namespace blink
```