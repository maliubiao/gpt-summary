Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to class names, function names, and any obvious data structures. Keywords like `GridLineResolver`, `ComputedStyle`, `GridPosition`, `GridSpan`, `NamedGridLinesMap`, and `NamedGridAreaMap` jump out. The `#include` directives also give clues about the context (layout, grid). From this initial skim, I can infer that this code is likely responsible for figuring out the positions of grid lines within a CSS grid layout.

**2. Deconstructing the Class `GridLineResolver`:**

The core of the code is the `GridLineResolver` class. I'll go through its member variables and methods.

* **Member Variables:** These tell me the state the class needs to maintain. I see things like `style_`, `column_auto_repetitions_`, `row_auto_repetitions_`, and various `NamedGridLinesMap` and `NamedGridAreaMap` members. The presence of both "explicit" and "implicit" named lines suggests handling both explicitly defined grid lines and those inferred from grid areas. The "subgridded" prefix on some variables indicates support for nested grids.

* **Constructor:** The constructor is crucial. It takes a `ComputedStyle`, a parent `GridLineResolver`, `GridArea` for subgrids, and auto-repeat counts. This signals that the resolver can be constructed in the context of a regular grid or a subgrid, inheriting information from its parent. The logic inside the constructor, especially the `MergeNamedGridLinesWithParent`, `ExpandAutoRepeatTracksFromParent`, `ClampSubgridAreas`, and `MergeAndClampGridAreasWithParent` lambda functions, points to the core function of combining and adjusting grid line and area information from parent grids for subgrids.

* **Key Methods:**  I'll look for methods that perform important operations:
    * Methods starting with `Resolve`:  `ResolveNamedGridLinePosition`, `ResolveGridPositionAgainstOppositePosition`. These strongly suggest the core responsibility of translating grid placement values into concrete line numbers.
    * Methods involving `LookAhead` and `LookBack`:  These seem related to searching for named grid lines.
    * Methods involving `Span`: `DefiniteGridSpanWithNamedSpanAgainstOpposite`, `SpanSizeFromPositions`. These likely deal with calculating the size of a grid item based on its placement.
    * Methods related to grid dimensions: `ExplicitGridColumnCount`, `ExplicitGridRowCount`, `AutoRepetitions`. These provide information about the grid's structure.
    * Methods dealing with subgrids: `IsSubgridded`, `SubgridSpanSize`.

**3. Identifying Relationships with Web Technologies:**

Now I'll connect the dots between the code and web technologies:

* **CSS Grid Layout:** The entire context is about CSS grid. Keywords like "grid-template-columns", "grid-template-rows", "grid-template-areas", "grid-column-start", "grid-row-end", and the concepts of "span" and named lines directly map to CSS grid properties and concepts.

* **HTML:** While the code doesn't directly manipulate HTML, it operates on the layout of HTML elements styled with CSS grid. The output of this code will determine the position and size of elements within the grid.

* **JavaScript:** JavaScript can interact with grid layout by modifying the CSS styles. This code would be used by the rendering engine to interpret those style changes. For example, if JavaScript changes the `grid-column-start` property, this code will be involved in calculating the new position.

**4. Inferring Logic and Assumptions:**

The code contains several logical steps, especially in the constructor:

* **Merging Named Lines:** The `MergeNamedGridLinesWithParent` lambda handles the merging of named lines from a parent grid into a subgrid, taking into account the subgrid's boundaries and potential name collisions.

* **Expanding Auto-Repeats:** The `ExpandAutoRepeatTracksFromParent` lambda deals with the complexities of `repeat()` notation in `grid-template-columns` and `grid-template-rows` when subgrids are involved.

* **Clamping Grid Areas:** The `ClampSubgridAreas` and `MergeAndClampGridAreasWithParent` lambdas ensure that named grid areas in subgrids are correctly scoped and merged with parent grid areas.

* **Searching for Named Lines:** The `LookAheadForNamedGridLine` and `LookBackForNamedGridLine` functions implement a search strategy for finding grid lines by name, considering both explicit and implicit lines.

**5. Considering Potential Errors:**

By examining the methods, I can identify potential user errors or scenarios that the code handles:

* **Conflicting Placements:** The code handles cases where both start and end lines are specified with `span`, resolving the conflict by treating the end line as `auto`.
* **Invalid Span Values:** Although not explicitly error handling, the code assumes positive span values. The comment "Negative positions are not allowed per the specification and should have been handled during parsing" highlights this.
* **Named Line Not Found:** While the code searches for named lines, it doesn't explicitly throw errors if a name isn't found. The result might be a fallback to implicit placement or a default behavior.

**6. Structuring the Explanation:**

Finally, I organize my findings into a clear and structured explanation, covering the key functionalities, relationships with web technologies, logical reasoning with examples, and potential user errors. I aim for a balance between technical detail and high-level understanding. The "Part 1 of 2" instruction prompts me to focus on summarizing the core functionality in this part.

This iterative process of skimming, deconstruction, connection, inference, and structuring allows for a comprehensive understanding of the given code snippet.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/core/layout/grid/grid_line_resolver.cc` 功能的归纳总结（第 1 部分）：

**总体功能：解析 CSS Grid 布局中的网格线位置**

`GridLineResolver` 类的主要职责是根据 CSS 样式信息（特别是 grid 相关的属性）以及可能的父网格布局信息，解析和计算 CSS Grid 布局中网格线的位置。它负责将开发者在 CSS 中定义的网格线名称、数字索引、`span` 关键字等转化为实际的网格线数字索引，以便后续的布局计算。

**核心功能点：**

1. **处理显式和隐式命名的网格线：**
   - 识别并存储显式定义的网格线名称（通过 `grid-template-columns` 和 `grid-template-rows` 的 `[]` 语法）。
   - 根据 `grid-template-areas` 属性创建隐式命名的网格线。

2. **处理 `span` 关键字：**
   - 当网格项的位置使用 `span` 关键字时，根据指定的跨度值和可选的网格线名称，向前或向后查找相应的网格线。

3. **处理子网格 (Subgrid)：**
   - 能够合并父网格的命名网格线和网格区域信息到子网格中，并进行相应的调整和过滤，确保子网格的网格线索引在其自身范围内。
   - 考虑父子网格的 writing-mode 和 direction 属性，进行正确的坐标转换。
   - 处理子网格的自动重复轨道 (auto-repeat tracks)。

4. **解析网格项的起始和结束位置：**
   - 根据网格项的 `grid-column-start`, `grid-column-end`, `grid-row-start`, `grid-row-end` 属性，获取其初始的网格线位置信息。
   - 处理当起始和结束位置都使用 `span` 时的回退逻辑。
   - 处理当一个位置是 `auto`，另一个是带有命名线的 `span` 时的特殊情况。

5. **查找指定名称的网格线：**
   - 提供 `LookAheadForNamedGridLine` 和 `LookBackForNamedGridLine` 方法，用于在给定的起始位置向前或向后查找指定数量的具有特定名称的网格线。

6. **确定网格的显式大小：**
   - 计算显式定义的网格列数和行数，包括考虑 `grid-template-areas` 中定义的轨道。
   - 对于子网格，获取其继承的跨度大小。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:** `GridLineResolver` 直接解析和解释 CSS Grid 布局相关的属性，如 `grid-template-columns`, `grid-template-rows`, `grid-template-areas`, `grid-column-start`, `grid-column-end`, `grid-row-start`, `grid-row-end`。 它将 CSS 中声明的逻辑值（如网格线名称、`span` 关键字）转换为布局引擎可以理解的数字索引。
    * **例子:**  如果 CSS 中定义了 `grid-column-start: my-line 2;`，`GridLineResolver` 会查找名为 `my-line` 的第二条网格线。

* **HTML:**  `GridLineResolver` 处理的是应用了 CSS Grid 布局的 HTML 元素的布局。它确定了这些元素在网格中的具体位置。
    * **例子:**  一个 `<div>` 元素应用了 `display: grid;`，其子元素通过 `grid-column-start` 等属性被放置在网格中，`GridLineResolver` 负责计算这些子元素的位置。

* **JavaScript:** JavaScript 可以通过修改元素的 CSS 样式来动态地改变网格布局。当 JavaScript 修改了相关的 CSS 属性时，布局引擎会重新运行布局计算，其中 `GridLineResolver` 会被用来解析新的网格线位置。
    * **例子:**  JavaScript 可以通过 `element.style.gridColumnStart = 'auto';` 来改变一个元素的起始列，布局引擎会使用 `GridLineResolver` 来确定其新的默认位置。

**逻辑推理示例 (假设输入与输出)：**

**假设输入 CSS:**

```css
.container {
  display: grid;
  grid-template-columns: [col-start] 1fr [col-mid] 1fr [col-end];
  grid-template-rows: [row-start] 100px [row-end];
}

.item {
  grid-column-start: col-start;
  grid-row-end: row-end;
}
```

**假设输入 `GridLineResolver` 的上下文：** 上述 `.container` 元素的 `ComputedStyle`。

**逻辑推理和输出:**

当处理 `.item` 元素的 `grid-column-start` 时：

- 输入的 `GridPosition`:  名称为 `col-start` 的起始线。
- `GridLineResolver` 会查找名为 `col-start` 的列起始线。
- **输出:**  `col-start` 对应的网格线索引 `1` (假设网格线索引从 1 开始)。

当处理 `.item` 元素的 `grid-row-end` 时：

- 输入的 `GridPosition`: 名称为 `row-end` 的结束线。
- `GridLineResolver` 会查找名为 `row-end` 的行结束线。
- **输出:** `row-end` 对应的网格线索引 `2`。

**用户或编程常见的使用错误示例：**

1. **拼写错误的网格线名称:** 如果 CSS 中使用了 `grid-column-start: col-star;` (拼写错误)，`GridLineResolver` 将无法找到名为 `col-star` 的网格线，导致布局出现意外或回退到默认行为。

2. **超出范围的 `span` 值:** 如果一个网格只有 3 列，但使用了 `grid-column-start: span 5;`，`GridLineResolver` 在查找时可能会超出网格的范围，导致布局错误。

3. **在子网格中引用父网格不存在的命名线:**  如果在子网格的定义中尝试引用一个只存在于父网格但没有被继承下来的命名线，`GridLineResolver` 将无法找到该命名线。

4. **起始线和结束线冲突导致无限循环 (在更复杂的场景中):**  虽然这个文件本身不太可能直接导致无限循环，但在更高级的布局计算中，如果对网格线的解析逻辑出现错误，可能会导致布局引擎进入无限的重计算循环。

**归纳总结 (第 1 部分的功能):**

`GridLineResolver` 的核心功能是 **解析 CSS Grid 布局中定义的各种网格线引用方式，将其转化为具体的网格线数字索引**。它负责处理显式和隐式的命名线，`span` 关键字，以及子网格的复杂情况，为后续的布局计算提供准确的网格线位置信息。它在理解和实现 CSS Grid 规范方面扮演着至关重要的角色。

Prompt: 
```
这是目录为blink/renderer/core/layout/grid/grid_line_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_line_resolver.h"

#include <algorithm>
#include "third_party/blink/renderer/core/layout/grid/grid_data.h"
#include "third_party/blink/renderer/core/layout/grid/grid_named_line_collection.h"
#include "third_party/blink/renderer/core/style/computed_grid_template_areas.h"
#include "third_party/blink/renderer/core/style/computed_grid_track_list.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/grid_area.h"
#include "third_party/blink/renderer/core/style/grid_position.h"

namespace blink {

static inline GridTrackSizingDirection DirectionFromSide(
    GridPositionSide side) {
  return side == kColumnStartSide || side == kColumnEndSide ? kForColumns
                                                            : kForRows;
}

static inline String ImplicitNamedGridLineForSide(const String& line_name,
                                                  GridPositionSide side) {
  return line_name + ((side == kColumnStartSide || side == kRowStartSide)
                          ? "-start"
                          : "-end");
}

GridLineResolver::GridLineResolver(const ComputedStyle& grid_style,
                                   const GridLineResolver& parent_line_resolver,
                                   GridArea subgrid_area,
                                   wtf_size_t column_auto_repetitions,
                                   wtf_size_t row_auto_repetitions)
    : style_(&grid_style),
      column_auto_repetitions_(column_auto_repetitions),
      row_auto_repetitions_(row_auto_repetitions),
      subgridded_columns_merged_explicit_grid_line_names_(
          grid_style.GridTemplateColumns().named_grid_lines),
      subgridded_rows_merged_explicit_grid_line_names_(
          grid_style.GridTemplateRows().named_grid_lines) {
  if (subgrid_area.columns.IsTranslatedDefinite()) {
    subgridded_columns_span_size_ = subgrid_area.SpanSize(kForColumns);
  }
  if (subgrid_area.rows.IsTranslatedDefinite()) {
    subgridded_rows_span_size_ = subgrid_area.SpanSize(kForRows);
  }

  // TODO(kschmi) - use a collector design (similar to
  // `OrderedNamedLinesCollector`) to collect all of the lines first and then
  // do a single step of filtering and adding them to the subgrid list. Also
  // consider moving these to class methods.
  auto MergeNamedGridLinesWithParent =
      [](NamedGridLinesMap& subgrid_map, const NamedGridLinesMap& parent_map,
         GridSpan subgrid_span, bool is_opposite_direction_to_parent) -> void {
    // Update `subgrid_map` to a merged map from a parent grid or subgrid map
    // (`parent_map`). The map is a key-value store with keys as the line name
    // and the value as an array of ascending indices.
    for (const auto& pair : parent_map) {
      // TODO(kschmi) : Benchmark whether this is faster with an std::map, which
      // would eliminate the need for sorting and removing duplicates below.
      // Perf will vary based on the number of named lines defined.
      Vector<wtf_size_t, 16> merged_list;
      for (const auto& position : pair.value) {
        // Filter out parent named lines that are out of the subgrid range. Also
        // offset entries by `subgrid_start_line` before inserting them into the
        // merged map so they are all relative to offset 0. These are already in
        // ascending order so there's no need to sort.
        if (subgrid_span.Contains(position)) {
          if (is_opposite_direction_to_parent) {
            merged_list.push_back(subgrid_span.EndLine() - position);
          } else {
            merged_list.push_back(position - subgrid_span.StartLine());
          }
        }
      }

      // If there's a name collision, merge the values and sort. These are from
      // the subgrid and not the parent container, so they are already relative
      // to index 0 and don't need to be offset.
      const auto& existing_entry = subgrid_map.find(pair.key);
      if (existing_entry != subgrid_map.end()) {
        for (const auto& value : existing_entry->value) {
          merged_list.push_back(value);
        }

        // TODO(kschmi): Reverse the list if `is_opposite_direction_to_parent`
        // and there was no existing entry, as it will be sorted backwards.
        std::sort(merged_list.begin(), merged_list.end());

        // Remove any duplicated entries in the sorted list. Duplicates can
        // occur when the parent grid and the subgrid define line names with the
        // same name at the same index. It doesn't matter which one takes
        // precedence (grid vs subgrid), as long as there is only a single entry
        // per index. Without this call, there will be bugs when we need to
        // iterate over the nth entry with a given name (e.g. "a 5") - the
        // duplicate will make all entries past it off-by-one.
        // `std::unique` doesn't change the size of the vector (it just moves
        // duplicates to the end), so we need to erase the duplicates via the
        // iterator returned.
        merged_list.erase(std::unique(merged_list.begin(), merged_list.end()),
                          merged_list.end());
      }

      // Override the existing subgrid's line names map with the new merged
      // list for this particular line name entry. `merged_list` list can be
      // empty if all entries for a particular line name are out of the
      // subgrid range.
      if (!merged_list.empty()) {
        subgrid_map.Set(pair.key, merged_list);
      }
    }
  };
  auto ExpandAutoRepeatTracksFromParent =
      [](NamedGridLinesMap& subgrid_map,
         const NamedGridLinesMap& parent_auto_repeat_map,
         const blink::ComputedGridTrackList& track_list, GridSpan subgrid_span,
         wtf_size_t auto_repetitions, bool is_opposite_direction_to_parent,
         bool is_nested_subgrid) -> void {
    const wtf_size_t auto_repeat_track_count =
        track_list.track_list.AutoRepeatTrackCount();
    const wtf_size_t auto_repeat_total_tracks =
        auto_repeat_track_count * auto_repetitions;
    if (auto_repeat_total_tracks == 0) {
      return;
    }

    // First, we need to offset the existing (non auto repeat) line names that
    // come after the auto repeater. This is because they were parsed without
    // knowledge of the number of repeats. Now that we know how many auto
    // repeats there are, we need to shift the existing entries by the total
    // number of auto repeat tracks. For now, skip this on nested subgrids,
    // as it will double-shift non-auto repeat lines.
    // TODO(kschmi): Properly shift line names after the insertion point for
    // nested subgrids. This should happen in `MergeNamedGridLinesWithParent`.
    // TODO(kschmi): Do we also need to do this for implicit lines?
    const wtf_size_t insertion_point = track_list.auto_repeat_insertion_point;
    if (!is_nested_subgrid) {
      for (const auto& pair : subgrid_map) {
        Vector<wtf_size_t> shifted_list;
        for (const auto& position : pair.value) {
          if (position >= insertion_point) {
            wtf_size_t expanded_position = position + auto_repeat_total_tracks;
            // These have already been offset relative to index 0, so explicitly
            // do not offset by `subgrid_span` like we do below.
            if (subgrid_span.Contains(expanded_position)) {
              shifted_list.push_back(expanded_position);
            }
          }
        }
        subgrid_map.Set(pair.key, shifted_list);
      }
    }

    // Now expand the auto repeaters into `subgrid_map`.
    for (const auto& pair : parent_auto_repeat_map) {
      Vector<wtf_size_t, 16> merged_list;
      for (const auto& position : pair.value) {
        // The outer loop is the number of repeats.
        for (wtf_size_t i = 0; i < auto_repetitions; ++i) {
          // The inner loop expands out a single repeater.
          for (wtf_size_t j = 0; j < auto_repeat_track_count; ++j) {
            // The expanded position always starts at the insertion point, then
            // factors in the line name index, incremented by both auto repeat
            // loops.
            wtf_size_t expanded_position = insertion_point + position + i + j;

            // Filter out parent named lines that are out of the subgrid range.
            // Also offset entries by `subgrid_start_line` before inserting them
            // into the merged map so they are all relative to offset 0. These
            // are already in ascending order so there's no need to sort.
            if (subgrid_span.Contains(expanded_position)) {
              if (is_opposite_direction_to_parent) {
                merged_list.push_back(subgrid_span.EndLine() -
                                      expanded_position);
              } else {
                merged_list.push_back(expanded_position -
                                      subgrid_span.StartLine());
              }
            }
          }
        }

        // If there's a name collision, merge the values and sort. These are
        // from the subgrid and not the parent, so they are already relative to
        // index 0 and don't need to be offset.
        const auto& existing_entry = subgrid_map.find(pair.key);
        if (existing_entry != subgrid_map.end()) {
          for (const auto& value : existing_entry->value) {
            merged_list.push_back(value);
          }
          // TODO(kschmi): Reverse the list if `is_opposite_direction_to_parent`
          // and there was no existing entry, as it will be sorted backwards.
          std::sort(merged_list.begin(), merged_list.end());
        }

        // If the merged list is empty, it means that all of the entries from
        // the parent were out of the subgrid range.
        if (!merged_list.empty()) {
          subgrid_map.Set(pair.key, merged_list);
        }
      }
    }
  };

  // Copies each entry from `style_map` into `subgrid_map`, clamping all values
  // to be in area defined by `subgridded_columns` and `subgridded_rows`.
  auto ClampSubgridAreas = [](NamedGridAreaMap& subgrid_map,
                              const NamedGridAreaMap& style_map,
                              const GridArea& subgrid_span) {
    for (const auto& pair : style_map) {
      auto clamped_area = pair.value;

      if (subgrid_span.columns.IsTranslatedDefinite()) {
        clamped_area.columns.Intersect(0, subgrid_span.columns.IntegerSpan());
      }
      if (subgrid_span.rows.IsTranslatedDefinite()) {
        clamped_area.rows.Intersect(0, subgrid_span.rows.IntegerSpan());
      }
      subgrid_map.Set(pair.key, std::move(clamped_area));
    }
  };

  // Copies each entry from `parent` into `subgrid_map`, clamping all values
  // to be in area defined by `subgridded_columns` and `subgridded_rows`. Grid
  // areas that are out of the subgrid range are discarded, and areas that are
  // partially or fully in the subgrid area are clamped to fit within the
  // subgrid area. Areas that are defined in both the parent and subgrid map are
  // merged according to spec.
  auto MergeAndClampGridAreasWithParent =
      [](NamedGridAreaMap& subgrid_map, const NamedGridAreaMap& parent_map,
         GridArea subgrid_span, bool is_parallel_to_parent) -> void {
    const bool has_subgridded_columns =
        subgrid_span.columns.IsTranslatedDefinite();
    const bool has_subgridded_rows = subgrid_span.rows.IsTranslatedDefinite();
    wtf_size_t subgrid_column_start_line =
        has_subgridded_columns ? subgrid_span.columns.StartLine() : 0;
    wtf_size_t subgrid_row_start_line =
        has_subgridded_rows ? subgrid_span.rows.StartLine() : 0;
    wtf_size_t subgrid_column_end_line =
        has_subgridded_columns ? subgrid_span.columns.EndLine() : 1;
    wtf_size_t subgrid_row_end_line =
        has_subgridded_rows ? subgrid_span.rows.EndLine() : 1;
    for (const auto& pair : parent_map) {
      auto position = pair.value;
      DCHECK(position.columns.IsTranslatedDefinite());
      DCHECK(position.rows.IsTranslatedDefinite());

      if (!is_parallel_to_parent) {
        position.Transpose();
      }

      // "Note: If a named grid area only partially overlaps the subgrid, its
      // implicitly-assigned line names will be assigned to the first and/or
      // last line of the subgrid such that a named grid area exists
      // representing that partially overlapped area of the subgrid..."
      //
      // https://www.w3.org/TR/css-grid-2/#subgrid-area-inheritance
      //
      // Discard grid areas that don't intersect the subgrid at all.
      const bool rows_intersect =
          has_subgridded_rows && subgrid_span.rows.Intersects(position.rows);
      const bool columns_intersect =
          has_subgridded_columns &&
          subgrid_span.columns.Intersects(position.columns);
      if (!rows_intersect && !columns_intersect) {
        continue;
      }

      // At this point, the current grid area must be either fully or partially
      // within the subgrid. We can safely clamp this to the subgrid range per
      // the above quote.
      position.columns.Intersect(subgrid_column_start_line,
                                 subgrid_column_end_line);
      position.rows.Intersect(subgrid_row_start_line, subgrid_row_end_line);

      // Now offset the position by the subgrid's start lines, as subgrids
      // always begin at index 0.
      position.rows.Translate(-subgrid_row_start_line);
      position.columns.Translate(-subgrid_column_start_line);

      const auto& existing_entry = subgrid_map.find(pair.key);
      if (existing_entry != subgrid_map.end()) {
        // Handle overlapping entries between the subgrid and parent grid by
        // taking the lesser value.
        const auto& existing_position = existing_entry->value;
        position.rows.SetStart(std::min(position.rows.StartLine(),
                                        existing_position.rows.StartLine()));
        position.rows.SetEnd(std::min(position.rows.EndLine(),
                                      existing_position.rows.EndLine()));
        position.columns.SetStart(
            std::min(position.columns.StartLine(),
                     existing_position.columns.StartLine()));
        position.columns.SetEnd(std::min(position.columns.EndLine(),
                                         existing_position.columns.EndLine()));
      }

      GridArea clamped_area(position.rows, position.columns);
      subgrid_map.Set(pair.key, clamped_area);
    }
  };
  const bool is_opposite_direction_to_parent =
      grid_style.Direction() != parent_line_resolver.style_->Direction();
  const bool is_parallel_to_parent =
      IsParallelWritingMode(grid_style.GetWritingMode(),
                            parent_line_resolver.style_->GetWritingMode());

  if (subgrid_area.columns.IsTranslatedDefinite()) {
    const auto track_direction_in_parent =
        is_parallel_to_parent ? kForColumns : kForRows;
    MergeNamedGridLinesWithParent(
        *subgridded_columns_merged_explicit_grid_line_names_,
        parent_line_resolver.ExplicitNamedLinesMap(track_direction_in_parent),
        subgrid_area.columns, is_opposite_direction_to_parent);
    // TODO(kschmi): Also expand the subgrid's repeaters. Otherwise, we could
    // have issues with precedence.
    ExpandAutoRepeatTracksFromParent(
        *subgridded_columns_merged_explicit_grid_line_names_,
        parent_line_resolver.AutoRepeatLineNamesMap(track_direction_in_parent),
        parent_line_resolver.ComputedGridTrackList(track_direction_in_parent),
        subgrid_area.columns,
        parent_line_resolver.AutoRepetitions(track_direction_in_parent),
        is_opposite_direction_to_parent,
        parent_line_resolver.IsSubgridded(track_direction_in_parent));
  }
  if (subgrid_area.rows.IsTranslatedDefinite()) {
    const auto track_direction_in_parent =
        is_parallel_to_parent ? kForRows : kForColumns;
    MergeNamedGridLinesWithParent(
        *subgridded_rows_merged_explicit_grid_line_names_,
        parent_line_resolver.ExplicitNamedLinesMap(track_direction_in_parent),
        subgrid_area.rows, is_opposite_direction_to_parent);
    // Expand auto repeaters from the parent into the named line map.
    // TODO(kschmi): Also expand the subgrid's repeaters. Otherwise, we could
    // have issues with precedence.
    ExpandAutoRepeatTracksFromParent(
        *subgridded_rows_merged_explicit_grid_line_names_,
        parent_line_resolver.AutoRepeatLineNamesMap(track_direction_in_parent),
        parent_line_resolver.ComputedGridTrackList(track_direction_in_parent),
        subgrid_area.rows,
        parent_line_resolver.AutoRepetitions(track_direction_in_parent),
        is_opposite_direction_to_parent,
        parent_line_resolver.IsSubgridded(track_direction_in_parent));
  }

  // If the subgrid has grid areas defined, create a merged grid areas map and
  // copy the map from style object, clamping values to the subgrid's range.
  // `is_parallel_to_parent` doesn't apply, since no parent grid is involved.
  if (grid_style.GridTemplateAreas()) {
    subgrid_merged_named_areas_.emplace();
    ClampSubgridAreas(*subgrid_merged_named_areas_,
                      grid_style.GridTemplateAreas()->named_areas,
                      subgrid_area);
  }

  if (const NamedGridAreaMap* parent_areas =
          parent_line_resolver.NamedAreasMap()) {
    // If the subgrid doesn't have any grid areas defined, emplace an empty one.
    // We still need to call `MergeAndClampGridAreasWithParent` to copy and
    // clamp the parent's map to the subgrid range.
    if (!subgrid_merged_named_areas_) {
      subgrid_merged_named_areas_.emplace();
    }
    MergeAndClampGridAreasWithParent(*subgrid_merged_named_areas_,
                                     *parent_areas, subgrid_area,
                                     is_parallel_to_parent);
  }

  // If we have a merged named grid area map, we need to generate new implicit
  // lines based on the merged map.
  if (subgrid_merged_named_areas_) {
    subgridded_columns_merged_implicit_grid_line_names_ =
        ComputedGridTemplateAreas::CreateImplicitNamedGridLinesFromGridArea(
            *subgrid_merged_named_areas_, kForColumns);
    subgridded_rows_merged_implicit_grid_line_names_ =
        ComputedGridTemplateAreas::CreateImplicitNamedGridLinesFromGridArea(
            *subgrid_merged_named_areas_, kForRows);
  }
}

bool GridLineResolver::operator==(const GridLineResolver& other) const {
  // This should only compare input data for placement. |style_| isn't
  // applicable since we shouldn't compare line resolvers of different nodes,
  // and the named line maps are a product of the computed style and the inputs.
  return column_auto_repetitions_ == other.column_auto_repetitions_ &&
         row_auto_repetitions_ == other.row_auto_repetitions_ &&
         subgridded_columns_span_size_ == other.subgridded_columns_span_size_ &&
         subgridded_rows_span_size_ == other.subgridded_rows_span_size_;
}

void GridLineResolver::InitialAndFinalPositionsFromStyle(
    const ComputedStyle& grid_item_style,
    GridTrackSizingDirection track_direction,
    GridPosition& initial_position,
    GridPosition& final_position) const {
  const bool is_for_columns = track_direction == kForColumns;
  initial_position = is_for_columns ? grid_item_style.GridColumnStart()
                                    : grid_item_style.GridRowStart();
  final_position = is_for_columns ? grid_item_style.GridColumnEnd()
                                  : grid_item_style.GridRowEnd();

  // We must handle the placement error handling code here instead of in the
  // StyleAdjuster because we don't want to overwrite the specified values.
  if (initial_position.IsSpan() && final_position.IsSpan())
    final_position.SetAutoPosition();

  // If the grid item has an automatic position and a grid span for a named line
  // in a given dimension, instead treat the grid span as one.
  if (initial_position.IsAuto() && final_position.IsSpan() &&
      !final_position.NamedGridLine().IsNull()) {
    final_position.SetSpanPosition(1, g_null_atom);
  }
  if (final_position.IsAuto() && initial_position.IsSpan() &&
      !initial_position.NamedGridLine().IsNull()) {
    initial_position.SetSpanPosition(1, g_null_atom);
  }
}

wtf_size_t GridLineResolver::LookAheadForNamedGridLine(
    int start,
    wtf_size_t number_of_lines,
    wtf_size_t grid_last_line,
    GridNamedLineCollection& lines_collection) const {
  DCHECK(number_of_lines);

  // Only implicit lines on the search direction are assumed to have the given
  // name, so we can start to look from first line.
  // See: https://drafts.csswg.org/css-grid/#grid-placement-span-int
  wtf_size_t end = std::max(start, 0);

  if (!lines_collection.HasNamedLines()) {
    end = std::max(end, grid_last_line + 1);
    return end + number_of_lines - 1;
  }

  for (; number_of_lines; ++end) {
    if (end > grid_last_line || lines_collection.Contains(end))
      number_of_lines--;
  }

  DCHECK(end);
  return end - 1;
}

int GridLineResolver::LookBackForNamedGridLine(
    int end,
    wtf_size_t number_of_lines,
    int grid_last_line,
    GridNamedLineCollection& lines_collection) const {
  DCHECK(number_of_lines);

  // Only implicit lines on the search direction are assumed to have the given
  // name, so we can start to look from last line.
  // See: https://drafts.csswg.org/css-grid/#grid-placement-span-int
  int start = std::min(end, grid_last_line);

  if (!lines_collection.HasNamedLines()) {
    start = std::min(start, -1);
    return start - number_of_lines + 1;
  }

  for (; number_of_lines; --start) {
    if (start < 0 || lines_collection.Contains(start))
      number_of_lines--;
  }

  return start + 1;
}

GridSpan GridLineResolver::DefiniteGridSpanWithNamedSpanAgainstOpposite(
    int opposite_line,
    const GridPosition& position,
    GridPositionSide side,
    int last_line,
    GridNamedLineCollection& lines_collection) const {
  int start, end;
  const int span_position = position.SpanPosition();
  if (side == kRowStartSide || side == kColumnStartSide) {
    start = LookBackForNamedGridLine(opposite_line - 1, span_position,
                                     last_line, lines_collection);
    end = opposite_line;
  } else {
    start = opposite_line;
    end = LookAheadForNamedGridLine(opposite_line + 1, span_position, last_line,
                                    lines_collection);
  }

  return GridSpan::UntranslatedDefiniteGridSpan(start, end);
}

bool GridLineResolver::IsSubgridded(
    GridTrackSizingDirection track_direction) const {
  // The merged explicit line names only exist when a direction is subgridded.
  const auto& merged_explicit_grid_line_names =
      (track_direction == kForColumns)
          ? subgridded_columns_merged_explicit_grid_line_names_
          : subgridded_rows_merged_explicit_grid_line_names_;

  return merged_explicit_grid_line_names.has_value();
}

wtf_size_t GridLineResolver::ExplicitGridColumnCount() const {
  if (subgridded_columns_span_size_ != kNotFound) {
    return subgridded_columns_span_size_;
  }

  wtf_size_t column_count =
      style_->GridTemplateColumns().track_list.TrackCountWithoutAutoRepeat() +
      AutoRepeatTrackCount(kForColumns);
  if (const auto& grid_template_areas = style_->GridTemplateAreas()) {
    column_count = std::max(column_count, grid_template_areas->column_count);
  }

  return std::min<wtf_size_t>(column_count, kGridMaxTracks);
}

wtf_size_t GridLineResolver::ExplicitGridRowCount() const {
  if (subgridded_rows_span_size_ != kNotFound) {
    return subgridded_rows_span_size_;
  }

  wtf_size_t row_count =
      style_->GridTemplateRows().track_list.TrackCountWithoutAutoRepeat() +
      AutoRepeatTrackCount(kForRows);
  if (const auto& grid_template_areas = style_->GridTemplateAreas()) {
    row_count = std::max(row_count, grid_template_areas->row_count);
  }

  return std::min<wtf_size_t>(row_count, kGridMaxTracks);
}

wtf_size_t GridLineResolver::ExplicitGridTrackCount(
    GridTrackSizingDirection track_direction) const {
  return (track_direction == kForColumns) ? ExplicitGridColumnCount()
                                          : ExplicitGridRowCount();
}

wtf_size_t GridLineResolver::AutoRepetitions(
    GridTrackSizingDirection track_direction) const {
  return (track_direction == kForColumns) ? column_auto_repetitions_
                                          : row_auto_repetitions_;
}

wtf_size_t GridLineResolver::AutoRepeatTrackCount(
    GridTrackSizingDirection track_direction) const {
  return AutoRepetitions(track_direction) *
         ComputedGridTrackList(track_direction)
             .track_list.AutoRepeatTrackCount();
}

wtf_size_t GridLineResolver::SubgridSpanSize(
    GridTrackSizingDirection track_direction) const {
  return (track_direction == kForColumns) ? subgridded_columns_span_size_
                                          : subgridded_rows_span_size_;
}

bool GridLineResolver::HasStandaloneAxis(
    GridTrackSizingDirection track_direction) const {
  return (track_direction == kForColumns)
             ? subgridded_columns_span_size_ == kNotFound
             : subgridded_rows_span_size_ == kNotFound;
}

wtf_size_t GridLineResolver::ExplicitGridSizeForSide(
    GridPositionSide side) const {
  return (side == kColumnStartSide || side == kColumnEndSide)
             ? ExplicitGridColumnCount()
             : ExplicitGridRowCount();
}

GridSpan GridLineResolver::ResolveNamedGridLinePositionAgainstOppositePosition(
    int opposite_line,
    const GridPosition& position,
    GridPositionSide side) const {
  DCHECK(position.IsSpan());
  DCHECK(!position.NamedGridLine().IsNull());
  // Negative positions are not allowed per the specification and should have
  // been handled during parsing.
  DCHECK_GT(position.SpanPosition(), 0);

  GridTrackSizingDirection track_direction = DirectionFromSide(side);
  const auto& implicit_grid_line_names = ImplicitNamedLinesMap(track_direction);
  const auto& explicit_grid_line_names = ExplicitNamedLinesMap(track_direction);
  const auto& computed_grid_track_list = ComputedGridTrackList(track_direction);
  const auto& auto_repeat_tracks_count = AutoRepeatTrackCount(track_direction);

  wtf_size_t last_line = ExplicitGridSizeForSide(side);

  GridNamedLineCollection lines_collection(
      position.NamedGridLine(), track_direction, implicit_grid_line_names,
      explicit_grid_line_names, computed_grid_track_list, last_line,
      auto_repeat_tracks_count, IsSubgridded(track_direction));
  return DefiniteGridSpanWithNamedSpanAgainstOpposite(
      opposite_line, position, side, last_line, lines_collection);
}

static GridSpan DefiniteGridSpanWithSpanAgainstOpposite(
    int opposite_line,
    const GridPosition& position,
    GridPositionSide side) {
  wtf_size_t position_offset = position.SpanPosition();
  if (side == kColumnStartSide || side == kRowStartSide) {
    return GridSpan::UntranslatedDefiniteGridSpan(
        opposite_line - position_offset, opposite_line);
  }

  return GridSpan::UntranslatedDefiniteGridSpan(
      opposite_line, opposite_line + position_offset);
}

const NamedGridLinesMap& GridLineResolver::ImplicitNamedLinesMap(
    GridTrackSizingDirection track_direction) const {
  const auto& subgrid_merged_implicit_grid_line_names =
      (track_direction == kForColumns)
          ? subgridded_columns_merged_implicit_grid_line_names_
          : subgridded_rows_merged_implicit_grid_line_names_;
  if (subgrid_merged_implicit_grid_line_names) {
    return *subgrid_merged_implicit_grid_line_names;
  }

  if (const auto& grid_template_areas = style_->GridTemplateAreas()) {
    return (track_direction == kForColumns)
               ? grid_template_areas->implicit_named_grid_column_lines
               : grid_template_areas->implicit_named_grid_row_lines;
  }

  DEFINE_STATIC_LOCAL(const NamedGridLinesMap, empty, ());
  return empty;
}

const NamedGridLinesMap& GridLineResolver::ExplicitNamedLinesMap(
    GridTrackSizingDirection track_direction) const {
  const auto& subgrid_merged_grid_line_names =
      (track_direction == kForColumns)
          ? subgridded_columns_merged_explicit_grid_line_names_
          : subgridded_rows_merged_explicit_grid_line_names_;

  return subgrid_merged_grid_line_names
             ? *subgrid_merged_grid_line_names
             : ComputedGridTrackList(track_direction).named_grid_lines;
}

const NamedGridAreaMap* GridLineResolver::NamedAreasMap() const {
  if (subgrid_merged_named_areas_) {
    return &subgrid_merged_named_areas_.value();
  }
  if (auto& areas = style_->GridTemplateAreas()) {
    return &areas->named_areas;
  }
  return nullptr;
}

const NamedGridLinesMap& GridLineResolver::AutoRepeatLineNamesMap(
    GridTrackSizingDirection track_direction) const {
  // Auto repeat line names always come from the style object, as they get
  // merged into the explicit line names map for subgrids.
  return ComputedGridTrackList(track_direction).auto_repeat_named_grid_lines;
}

const blink::ComputedGridTrackList& GridLineResolver::ComputedGridTrackList(
    GridTrackSizingDirection track_direction) const {
  // TODO(kschmi): Refactor so this isn't necessary and handle auto-repeats
  // for subgrids.
  return (track_direction == kForColumns) ? style_->GridTemplateColumns()
                                          : style_->GridTemplateRows();
}

GridSpan GridLineResolver::ResolveGridPositionAgainstOppositePosition(
    int opposite_line,
    const GridPosition& position,
    GridPositionSide side) const {
  if (position.IsAuto()) {
    if (side == kColumnStartSide || side == kRowStartSide) {
      return GridSpan::UntranslatedDefiniteGridSpan(opposite_line - 1,
                                                    opposite_line);
    }
    return GridSpan::UntranslatedDefiniteGridSpan(opposite_line,
                                                  opposite_line + 1);
  }

  DCHECK(position.IsSpan());
  DCHECK_GT(position.SpanPosition(), 0);

  if (!position.NamedGridLine().IsNull()) {
    // span 2 'c' -> we need to find the appropriate grid line before / after
    // our opposite position.
    return ResolveNamedGridLinePositionAgainstOppositePosition(opposite_line,
                                                               position, side);
  }

  return DefiniteGridSpanWithSpanAgainstOpposite(opposite_line, position, side);
}

wtf_size_t GridLineResolver::SpanSizeFromPositions(
    const GridPosition& initial_position,
    const GridPosition& final_position) const {
  // This method will only be used when both positions need to be resolved
  // against the opposite one.
  DCHECK(initial_position.ShouldBeResolvedAgainstOppositePosition() &&
         final_position.ShouldBeResolvedAgainstOppositePosition());

  if (initial_position.IsAuto() && final_position.IsAuto())
    return 1;

  const GridPosition& span_position =
      initial_position.IsSpan() ? initial_position : final_position;
  DCHECK(span_position.IsSpan() && span_position.SpanPosition());
  return span_position.SpanPosition();
}

wtf_size_t GridLineResolver::SpanSizeForAutoPlacedItem(
    const ComputedStyle& grid_item_style,
    GridTrackSizingDirection track_direction) const {
  GridPosition initial_position, final_position;
  InitialAndFinalPositionsFromStyle(grid_item_style, track_direction,
                                    initial_position, final_position);
  return SpanSizeFromPositions(initial_position, final_position);
}

int GridLineResolver::ResolveNamedGridLinePosition(
    const GridPosition& position,
    GridPositionSide side) const {
  DCHECK(!position.NamedGridLine().IsNull());

  wtf_size_t last_line = ExplicitGridSizeForSide(side);
  GridTrackSizingDirection track_direction = DirectionFromSide(side);
  const auto& implicit_grid_line_names = ImplicitNamedLinesMap(track_direction);
  const auto& explicit_grid_line_names = ExplicitNamedLinesMap(track_direction);
  const auto& track_list = ComputedGridTrackList(track_direction);
  const auto& auto_repeat_tracks_count = AutoRepeatTrackCount(track_direction);

  GridNamedLineCollection lines_collection(
      position.NamedGridLine(), track_direction, implicit_grid_line_names,
      explicit_grid_line_names, track_list, last_line, auto_repeat_tracks_count,
      IsSubgridded(track_direction));

  if (position.IsPositive()) {
    return LookAheadForNamedGridLine(0, abs(position.IntegerPosition()),
                                     last_line, lines_collection);
  }

 
"""


```