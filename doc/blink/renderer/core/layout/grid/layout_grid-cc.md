Response:
Let's break down the thought process for analyzing the `layout_grid.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this C++ file within the Chromium Blink rendering engine, specifically focusing on its role in CSS Grid Layout. Key aspects include:
    * Listing its functions.
    * Explaining its relationship to JavaScript, HTML, and CSS.
    * Identifying any logical deductions and providing examples.
    * Pointing out common user/programming errors.

2. **Initial Code Scan (Keywords and Structure):**  A quick skim reveals important keywords and structural elements:
    * `LayoutGrid`:  The central class. This immediately suggests it's responsible for the layout of grid containers.
    * `#include`:  Includes related headers like `layout_grid.h`, `subgrid_min_max_sizes_cache.h`, and `layout_result.h`. These hint at dependencies and related concepts.
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * Methods like `AddChild`, `RemoveChild`, `StyleDidChange`, `LayoutData`, `GridGap`, `TrackSizesForComputedStyle`, `RowPositions`, `ColumnPositions`. These directly relate to grid layout concepts.
    * Use of `ComputedStyle`:  Indicates interaction with CSS style information.
    * Use of `GridPlacementData` and `GridLayoutData`:  These are likely data structures holding information about the grid's structure and item placement.
    * `Trace`:  Suggests this class supports debugging and potentially DevTools integration.
    * `SetGridPlacementDirty`:  Indicates a mechanism for tracking changes that require recalculating grid layout.
    * Helper functions within an anonymous namespace (like `ExplicitGridDidResize` and `NamedGridLinesDefinitionDidChange`): These encapsulate specific logic related to style changes.

3. **Categorize Functionality:** Based on the initial scan, I can start grouping the methods by their purpose:
    * **Object Lifecycle/Management:** `LayoutGrid` (constructor), `Trace`.
    * **Child Management:** `AddChild`, `RemoveChild`.
    * **Style Handling:** `StyleDidChange`.
    * **Placement Data Management:** `HasCachedPlacementData`, `CachedPlacementData`, `SetCachedPlacementData`, `SetGridPlacementDirty`.
    * **Subgrid Data Management:** `HasCachedSubgridMinMaxSizes`, `CachedSubgridMinMaxSizes`, `SetSubgridMinMaxSizesCache`, `ShouldInvalidateSubgridMinMaxSizesCacheFor`.
    * **Layout Information Retrieval:** `LayoutData`, `AutoRepeatCountForDirection`, `ExplicitGridStartForDirection`, `ExplicitGridEndForDirection`, `GridGap`, `GridItemOffset`.
    * **Track and Position Calculation:** `TrackSizesForComputedStyle`, `RowPositions`, `ColumnPositions`, `ComputeTrackSizeRepeaterForRange`, `ComputeExpandedPositions`.

4. **Relate to HTML, CSS, and JavaScript:** Now, connect the categorized functionality to web technologies:

    * **HTML:** The `LayoutGrid` is associated with an `Element*`. This element is typically an HTML element styled with `display: grid` or `display: inline-grid`. Adding/removing children corresponds to adding/removing elements within the grid container in the HTML.

    * **CSS:** The `StyleDidChange` method is the primary interaction point with CSS. The code checks for changes in various grid-related CSS properties like `grid-template-columns`, `grid-template-rows`, `grid-auto-columns`, `grid-auto-rows`, `grid-auto-flow`, `grid-template-areas`, and named grid lines. The helper functions analyze specific CSS property changes. The calculated track sizes and positions are directly derived from CSS grid definitions.

    * **JavaScript:** While this file is C++, it provides the underlying layout engine that JavaScript interacts with indirectly. JavaScript can modify the CSS (and therefore trigger `StyleDidChange`), add/remove elements (triggering `AddChild`/`RemoveChild`), and potentially query layout information (though this file doesn't directly expose a JS API). DevTools, often used by developers via JavaScript interactions, might use the `Trace` method for debugging.

5. **Identify Logical Deductions and Examples:** Look for places where the code makes decisions or calculations based on input:

    * **Dirty Flags:** The `SetGridPlacementDirty` flag is a crucial deduction. Changes in CSS or child elements *imply* that the grid layout needs to be recalculated. *Example:* If the `grid-template-columns` property is changed, `StyleDidChange` will set `GridPlacementDirty` to true.

    * **Cached Data:** The caching mechanisms (`cached_placement_data_`, `cached_subgrid_min_max_sizes_`) are optimizations. The code checks if cached data is valid before recalculating. *Example:* If the grid properties haven't changed since the last layout, the cached placement data can be reused.

    * **Track Size Calculation:** The `ComputeTrackSizeRepeaterForRange` and `ComputeExpandedPositions` methods implement the logic for calculating track sizes and grid line positions based on the CSS definitions. This involves handling `fr` units, `auto` sizes, and implicit tracks. *Example:* Given `grid-template-columns: 1fr 2fr;`, these functions would calculate the relative widths of the two columns based on the available space.

6. **Spot Common Errors:** Think about common mistakes developers make with CSS Grid:

    * **Incorrect Grid Definitions:** Defining conflicting or nonsensical grid track sizes or areas can lead to unexpected layouts. The code handles these definitions, but the *user error* is in the CSS. *Example:* Setting `grid-template-columns: 100px 1fr;` on a container with less than 100px of available width might lead to content overflow.

    * **Forgetting Grid Items:** Developers might define a grid but forget to place items within it using properties like `grid-column`, `grid-row`, or `grid-area`. While this file doesn't directly *cause* this, understanding its functionality helps in debugging such issues. *Example:* A div inside a grid container without explicit placement rules will be auto-placed according to `grid-auto-flow`.

    * **Overriding Grid Settings:**  Applying conflicting grid properties or styles can lead to confusion. The `StyleDidChange` method detects these changes and triggers necessary updates. *Example:*  Setting `display: block` on an element that was previously a grid container will negate the grid layout.

7. **Refine and Structure:** Organize the findings into a clear and structured format, using headings, bullet points, and code examples where appropriate. Ensure the language is clear and avoids overly technical jargon where possible. Emphasize the connections between the C++ code and the higher-level web technologies.

8. **Review and Iterate:**  Read through the explanation, checking for accuracy and completeness. Are the examples clear and illustrative?  Is the connection to HTML, CSS, and JavaScript well-explained?  Are the common errors relevant?  This iterative process helps in polishing the explanation.

This detailed thought process, moving from high-level understanding to specific code analysis and then back to the broader context of web development, allows for a comprehensive and accurate explanation of the `layout_grid.cc` file's functionality.
这个文件 `blink/renderer/core/layout/grid/layout_grid.cc` 是 Chromium Blink 引擎中负责处理 **CSS Grid Layout** 的核心组件之一。它的主要功能是管理和计算应用了 `display: grid` 或 `display: inline-grid` 的 HTML 元素的布局。

以下是该文件功能的详细列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理和常见错误示例：

**主要功能:**

1. **表示 Grid 容器:** `LayoutGrid` 类继承自 `LayoutBlock`，它代表了 DOM 树中一个应用了 CSS Grid 布局的元素。它存储了与该 Grid 容器相关的布局信息。

2. **跟踪 Grid Item 的添加和移除:**
   - `AddChild(LayoutObject* new_child, LayoutObject* before_child)`: 当新的子元素添加到 Grid 容器时被调用。它会调用父类的 `AddChild` 方法，并设置一个标志 `SetGridPlacementDirty(true)`，表示需要重新计算 Grid 布局，因为子元素的添加可能会影响 Grid 的排列。
   - `RemoveChild(LayoutObject* child)`: 当子元素从 Grid 容器中移除时被调用。同样，它会调用父类的 `RemoveChild` 方法，并设置 `SetGridPlacementDirty(true)`，因为子元素的移除也可能影响 Grid 的排列。
   - **与 HTML 关系:**  当 JavaScript 操作 DOM，例如使用 `appendChild` 或 `removeChild` 添加或删除 Grid 容器的子元素时，会间接触发这些方法。

3. **响应样式变化:**
   - `StyleDidChange(StyleDifference diff, const ComputedStyle* old_style)`: 当 Grid 容器的 CSS 样式发生变化时被调用。这个方法会检查影响 Grid 布局的关键样式属性，例如：
     - `grid-template-columns`, `grid-template-rows`: 定义显式网格的列和行。
     - `grid-auto-columns`, `grid-auto-rows`: 定义隐式创建的列和行的大小。
     - `grid-auto-flow`: 控制自动放置算法如何排列网格项。
     - `grid-template-areas`: 使用命名区域定义网格布局。
     - Grid 轨道列表的改变 (包括 `auto-repeat` 的变化)。
     - 命名的 Grid 线条的定义变化。
   - 如果检测到这些影响布局的样式变化，它会设置 `SetGridPlacementDirty(true)`，表示需要重新计算布局。
   - **与 CSS 关系:**  这个方法直接响应 CSS 属性的改变。例如，当 JavaScript 修改元素的 `style` 属性，或者通过 CSS 规则匹配到新的样式时，会触发此方法。
   - **与 JavaScript 关系:** JavaScript 可以通过 DOM API 修改元素的样式，从而间接地触发 `StyleDidChange`。

4. **缓存和管理布局数据:**
   - `cached_placement_data_`:  缓存 Grid 布局计算的结果，例如每个 Grid Item 的位置和大小。
   - `HasCachedPlacementData()`, `CachedPlacementData()`, `SetCachedPlacementData()`:  用于检查、获取和设置缓存的布局数据。这是一种性能优化手段，避免在布局没有变化时重复计算。
   - `IsGridPlacementDirty()`:  检查是否需要重新计算 Grid 布局。
   - `SetGridPlacementDirty(bool)`:  设置是否需要重新计算 Grid 布局的标志。

5. **缓存和管理 Subgrid 的最小/最大尺寸:**
   - `cached_subgrid_min_max_sizes_`: 缓存 Subgrid (嵌套 Grid) 的最小和最大尺寸信息。
   - `HasCachedSubgridMinMaxSizes()`, `CachedSubgridMinMaxSizes()`, `SetSubgridMinMaxSizesCache()`: 用于管理 Subgrid 的尺寸缓存。
   - `IsSubgridMinMaxSizesCacheDirty()`: 检查 Subgrid 的尺寸缓存是否需要更新。
   - `SetSubgridMinMaxSizesCacheDirty(bool)`: 设置 Subgrid 尺寸缓存是否需要更新的标志。
   - `ShouldInvalidateSubgridMinMaxSizesCacheFor(const GridLayoutData& layout_data) const`:  判断 Subgrid 的尺寸缓存是否因为布局数据变化而失效。

6. **获取布局数据:**
   - `LayoutData() const`:  获取最近一次布局计算的结果，包含了 Grid 的几何信息，例如轨道大小、间隙等。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个应用了 `display: grid` 的 `<div>` 元素，其 CSS 定义了 `grid-template-columns: 100px 1fr;` 和 `grid-template-rows: 50px auto;`。
     - **输出:** `LayoutData()` 返回的 `GridLayoutData` 对象将包含列的轨道信息为 `[100px, flexible(1fr)]`，行的轨道信息为 `[50px, auto]`。实际的 `1fr` 的值需要根据可用空间计算。

7. **获取自动重复轨道数量和显式网格范围:**
   - `AutoRepeatCountForDirection(GridTrackSizingDirection track_direction) const`: 获取在指定方向上使用 `repeat()` 函数定义的自动重复轨道的数量。
   - `ExplicitGridStartForDirection(GridTrackSizingDirection track_direction) const`: 获取显式网格在指定方向上的起始索引（通常为 0）。
   - `ExplicitGridEndForDirection(GridTrackSizingDirection track_direction) const`: 获取显式网格在指定方向上的结束索引。
   - **与 CSS 关系:** 这些方法与 CSS 的 `repeat()` 函数相关。例如，如果 `grid-template-columns: repeat(3, 100px);`，则 `AutoRepeatCountForDirection(kForColumns)` 将返回 3。

8. **获取 Grid 间隙 (Gaps):**
   - `GridGap(GridTrackSizingDirection track_direction) const`: 获取列或行之间的间隙大小。
   - **与 CSS 关系:**  与 CSS 属性 `grid-column-gap` (`column-gap`), `grid-row-gap` (`row-gap`), 和 `grid-gap` 相关。

9. **获取 Grid Item 的偏移量:**
   - `GridItemOffset(GridTrackSizingDirection track_direction) const`:  在 GridNG 中，分布偏移已融入到 `gutter_size` 中，所以此方法返回 `LayoutUnit()`。

10. **获取计算后的轨道大小:**
    - `TrackSizesForComputedStyle(GridTrackSizingDirection track_direction) const`:  返回 Grid 容器在指定方向上所有轨道的计算后的大小。这会考虑显式定义的轨道、自动轨道和隐式创建的轨道。
    - **与 CSS 关系:**  这个方法的结果直接反映了 CSS 中定义的轨道大小，例如 `px`, `fr`, `auto` 等单位的计算结果。
    - **逻辑推理 (假设输入与输出):**
        - **假设输入:** 一个 Grid 容器，`grid-template-columns: 1fr 200px auto;`，容器宽度为 600px。
        - **输出:** `TrackSizesForComputedStyle(kForColumns)` 可能会返回类似 `[200px, 200px, 200px]` 的大小，其中 `1fr` 被计算为 `(600px - 200px 的 auto 列) / (1 + 0) = 400px`，但由于只有一个 `fr`，所以剩余空间会被分配给它。`auto` 列的大小取决于其内容。实际计算会更复杂，需要考虑内容大小等因素。

11. **获取行和列的位置:**
    - `RowPositions() const`: 返回所有水平网格线的位置。
    - `ColumnPositions() const`: 返回所有垂直网格线的位置。
    - **与 CSS 关系:** 这些位置是根据 CSS 中定义的轨道大小和间隙计算出来的。
    - **逻辑推理 (假设输入与输出):**
        - **假设输入:** `grid-template-columns: 100px 200px; grid-column-gap: 10px;`
        - **输出:** `ColumnPositions()` 可能会返回 `[0px, 100px, 310px]`。

12. **计算轨道大小的重复模式:**
    - `ComputeTrackSizeRepeaterForRange(const GridLayoutTrackCollection& track_collection, wtf_size_t range_index) const`:  处理 `repeat()` 函数定义的轨道大小模式，并计算每个重复轨道的大小。

13. **计算扩展后的位置:**
    - `ComputeExpandedPositions(GridTrackSizingDirection track_direction) const`: 计算所有网格线的位置，包括隐式创建的网格线。

**用户或编程常见的使用错误示例:**

1. **忘记设置 `display: grid` 或 `display: inline-grid`:**  初学者可能会定义 Grid 相关的 CSS 属性，但忘记在容器元素上设置 `display: grid` 或 `display: inline-grid`，导致 Grid 布局不生效。
   - **错误代码 (HTML):**
     ```html
     <div class="container">
       <div>Item 1</div>
       <div>Item 2</div>
     </div>
     ```
   - **错误代码 (CSS):**
     ```css
     .container {
       grid-template-columns: 100px 100px;
     }
     ```
   - **说明:**  缺少 `display: grid;`，`.container` 仍然是一个普通的块级元素，Grid 属性不会生效。

2. **在 Grid Item 上错误地使用绝对定位:** 虽然可以在 Grid Item 上使用绝对定位，但这会将其从正常的 Grid 布局流中移除，可能导致意想不到的布局结果。开发者可能期望绝对定位的元素仍然遵循 Grid 的约束，但实际上它会相对于其最近的定位祖先进行定位。
   - **错误代码 (CSS):**
     ```css
     .item {
       position: absolute;
       top: 10px;
       left: 20px;
     }
     ```
   - **说明:** `.item` 将会相对于其包含块定位，而不是在 Grid 单元格内的相对位置。

3. **Grid Item 重叠:**  如果 Grid Item 的放置规则（例如使用 `grid-column`, `grid-row`, 或 `grid-area`）导致它们占据相同的 Grid 单元格，那么它们会重叠。这可能是期望的行为，但也可能是布局错误。
   - **错误代码 (CSS):**
     ```css
     .item1 {
       grid-column: 1;
       grid-row: 1;
     }
     .item2 {
       grid-column: 1;
       grid-row: 1;
     }
     ```
   - **说明:** `.item1` 和 `.item2` 都被放置在 Grid 的第一个单元格，它们会重叠显示。

4. **对齐属性的误解:**  开发者可能对 `justify-items`, `align-items`, `justify-content`, `align-content`, `place-items`, `place-content` 等对齐属性的作用范围和效果理解不足，导致 Grid Item 或 Grid 轨道组没有按照预期对齐。

5. **隐式 Grid 的意外行为:**  当 Grid Item 被放置到显式定义的网格之外时，Grid 容器会创建隐式网格轨道。如果没有正确理解 `grid-auto-rows` 和 `grid-auto-columns` 的作用，隐式轨道的大小可能不是预期的。

**总结:**

`layout_grid.cc` 文件在 Blink 渲染引擎中扮演着至关重要的角色，它负责实现 CSS Grid Layout 的核心逻辑，包括响应样式变化、管理子元素、计算轨道大小和位置等。它与 HTML、CSS 和 JavaScript 都有密切的关系：它根据 HTML 结构和 CSS 样式来计算布局，并且 JavaScript 可以通过操作 DOM 和样式来间接影响 `LayoutGrid` 的行为。理解这个文件的功能有助于深入了解浏览器如何渲染和管理 CSS Grid 布局。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/layout_grid.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/layout_grid.h"

#include "third_party/blink/renderer/core/layout/grid/subgrid_min_max_sizes_cache.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"

namespace blink {

LayoutGrid::LayoutGrid(Element* element) : LayoutBlock(element) {}

void LayoutGrid::Trace(Visitor* visitor) const {
  visitor->Trace(cached_subgrid_min_max_sizes_);
  LayoutBlock::Trace(visitor);
}

void LayoutGrid::AddChild(LayoutObject* new_child, LayoutObject* before_child) {
  NOT_DESTROYED();
  LayoutBlock::AddChild(new_child, before_child);

  // Out-of-flow grid items don't impact placement.
  if (!new_child->IsOutOfFlowPositioned())
    SetGridPlacementDirty(true);
}

void LayoutGrid::RemoveChild(LayoutObject* child) {
  NOT_DESTROYED();
  LayoutBlock::RemoveChild(child);

  // Out-of-flow grid items don't impact placement.
  if (!child->IsOutOfFlowPositioned())
    SetGridPlacementDirty(true);
}

namespace {

bool ExplicitGridDidResize(const ComputedStyle& new_style,
                           const ComputedStyle& old_style) {
  const auto& old_ng_columns_track_list =
      old_style.GridTemplateColumns().track_list;
  const auto& new_ng_columns_track_list =
      new_style.GridTemplateColumns().track_list;
  const auto& old_ng_rows_track_list = old_style.GridTemplateRows().track_list;
  const auto& new_ng_rows_track_list = new_style.GridTemplateRows().track_list;

  return old_ng_columns_track_list.TrackCountWithoutAutoRepeat() !=
             new_ng_columns_track_list.TrackCountWithoutAutoRepeat() ||
         old_ng_rows_track_list.TrackCountWithoutAutoRepeat() !=
             new_ng_rows_track_list.TrackCountWithoutAutoRepeat() ||
         old_ng_columns_track_list.AutoRepeatTrackCount() !=
             new_ng_columns_track_list.AutoRepeatTrackCount() ||
         old_ng_rows_track_list.AutoRepeatTrackCount() !=
             new_ng_rows_track_list.AutoRepeatTrackCount();
}

bool NamedGridLinesDefinitionDidChange(const ComputedStyle& new_style,
                                       const ComputedStyle& old_style) {
  return new_style.GridTemplateRows().named_grid_lines !=
             old_style.GridTemplateRows().named_grid_lines ||
         new_style.GridTemplateColumns().named_grid_lines !=
             old_style.GridTemplateColumns().named_grid_lines;
}

}  // namespace

void LayoutGrid::StyleDidChange(StyleDifference diff,
                                const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutBlock::StyleDidChange(diff, old_style);
  if (!old_style)
    return;

  const auto& new_style = StyleRef();
  const auto& new_grid_columns_track_list =
      new_style.GridTemplateColumns().track_list;
  const auto& new_grid_rows_track_list =
      new_style.GridTemplateRows().track_list;

  if (new_grid_columns_track_list !=
          old_style->GridTemplateColumns().track_list ||
      new_grid_rows_track_list != old_style->GridTemplateRows().track_list ||
      new_style.GridAutoColumns() != old_style->GridAutoColumns() ||
      new_style.GridAutoRows() != old_style->GridAutoRows() ||
      new_style.GetGridAutoFlow() != old_style->GetGridAutoFlow()) {
    SetGridPlacementDirty(true);
  }

  if (ExplicitGridDidResize(new_style, *old_style) ||
      NamedGridLinesDefinitionDidChange(new_style, *old_style) ||
      !base::ValuesEquivalent(new_style.GridTemplateAreas(),
                              old_style->GridTemplateAreas()) ||
      (diff.NeedsLayout() &&
       (new_grid_columns_track_list.AutoRepeatTrackCount() ||
        new_grid_rows_track_list.AutoRepeatTrackCount()))) {
    SetGridPlacementDirty(true);
  }
}

bool LayoutGrid::HasCachedPlacementData() const {
  return cached_placement_data_ && !IsGridPlacementDirty();
}

const GridPlacementData& LayoutGrid::CachedPlacementData() const {
  DCHECK(HasCachedPlacementData());
  return *cached_placement_data_;
}

void LayoutGrid::SetCachedPlacementData(GridPlacementData&& placement_data) {
  cached_placement_data_ = std::move(placement_data);
  SetGridPlacementDirty(false);
}

bool LayoutGrid::HasCachedSubgridMinMaxSizes() const {
  return cached_subgrid_min_max_sizes_ && !IsSubgridMinMaxSizesCacheDirty();
}

const MinMaxSizes& LayoutGrid::CachedSubgridMinMaxSizes() const {
  DCHECK(HasCachedSubgridMinMaxSizes());
  return **cached_subgrid_min_max_sizes_;
}

void LayoutGrid::SetSubgridMinMaxSizesCache(MinMaxSizes&& min_max_sizes,
                                            const GridLayoutData& layout_data) {
  cached_subgrid_min_max_sizes_ = MakeGarbageCollected<SubgridMinMaxSizesCache>(
      std::move(min_max_sizes), layout_data);
  SetSubgridMinMaxSizesCacheDirty(false);
}

bool LayoutGrid::ShouldInvalidateSubgridMinMaxSizesCacheFor(
    const GridLayoutData& layout_data) const {
  return HasCachedSubgridMinMaxSizes() &&
         !cached_subgrid_min_max_sizes_->IsValidFor(layout_data);
}

const GridLayoutData* LayoutGrid::LayoutData() const {
  // Retrieve the layout data from the last fragment as it has the most
  // up-to-date grid geometry.
  const wtf_size_t fragment_count = PhysicalFragmentCount();
  if (fragment_count == 0)
    return nullptr;
  return GetLayoutResult(fragment_count - 1)->GetGridLayoutData();
}

wtf_size_t LayoutGrid::AutoRepeatCountForDirection(
    GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  if (!HasCachedPlacementData())
    return 0;
  return cached_placement_data_->AutoRepeatTrackCount(track_direction);
}

wtf_size_t LayoutGrid::ExplicitGridStartForDirection(
    GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  if (!HasCachedPlacementData())
    return 0;
  return cached_placement_data_->StartOffset(track_direction);
}

wtf_size_t LayoutGrid::ExplicitGridEndForDirection(
    GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  if (!HasCachedPlacementData())
    return 0;

  return base::checked_cast<wtf_size_t>(
      ExplicitGridStartForDirection(track_direction) +
      cached_placement_data_->ExplicitGridTrackCount(track_direction));
}

LayoutUnit LayoutGrid::GridGap(GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  const auto* grid_layout_data = LayoutData();
  if (!grid_layout_data)
    return LayoutUnit();

  return (track_direction == kForColumns)
             ? grid_layout_data->Columns().GutterSize()
             : grid_layout_data->Rows().GutterSize();
}

LayoutUnit LayoutGrid::GridItemOffset(
    GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  // Distribution offset is baked into the gutter_size in GridNG.
  return LayoutUnit();
}

Vector<LayoutUnit, 1> LayoutGrid::TrackSizesForComputedStyle(
    GridTrackSizingDirection track_direction) const {
  NOT_DESTROYED();
  Vector<LayoutUnit, 1> track_sizes;
  const auto* grid_layout_data = LayoutData();
  if (!grid_layout_data)
    return track_sizes;

  const auto& track_collection = (track_direction == kForColumns)
                                     ? grid_layout_data->Columns()
                                     : grid_layout_data->Rows();

  // |EndLineOfImplicitGrid| is equivalent to the total track count.
  track_sizes.ReserveInitialCapacity(std::min<wtf_size_t>(
      track_collection.EndLineOfImplicitGrid(), kGridMaxTracks));

  const wtf_size_t range_count = track_collection.RangeCount();
  for (wtf_size_t i = 0; i < range_count; ++i) {
    auto track_sizes_in_range =
        ComputeTrackSizeRepeaterForRange(track_collection, i);

    const wtf_size_t range_track_count = track_collection.RangeTrackCount(i);
    for (wtf_size_t j = 0; j < range_track_count; ++j) {
      track_sizes.emplace_back(
          track_sizes_in_range[j % track_sizes_in_range.size()]);

      // Respect total track count limit.
      DCHECK(track_sizes.size() <= kGridMaxTracks);
      if (track_sizes.size() == kGridMaxTracks)
        return track_sizes;
    }
  }
  return track_sizes;
}

Vector<LayoutUnit> LayoutGrid::RowPositions() const {
  NOT_DESTROYED();
  return ComputeExpandedPositions(kForRows);
}

Vector<LayoutUnit> LayoutGrid::ColumnPositions() const {
  NOT_DESTROYED();
  return ComputeExpandedPositions(kForColumns);
}

Vector<LayoutUnit> LayoutGrid::ComputeTrackSizeRepeaterForRange(
    const GridLayoutTrackCollection& track_collection,
    wtf_size_t range_index) const {
  const wtf_size_t range_set_count =
      track_collection.RangeSetCount(range_index);

  if (!range_set_count)
    return {LayoutUnit()};

  Vector<LayoutUnit> track_sizes;
  track_sizes.ReserveInitialCapacity(range_set_count);

  const wtf_size_t begin_set_index =
      track_collection.RangeBeginSetIndex(range_index);
  const wtf_size_t end_set_index = begin_set_index + range_set_count;

  for (wtf_size_t i = begin_set_index; i < end_set_index; ++i) {
    LayoutUnit set_size =
        track_collection.GetSetOffset(i + 1) - track_collection.GetSetOffset(i);
    const wtf_size_t set_track_count = track_collection.GetSetTrackCount(i);

    DCHECK_GE(set_size, 0);
    set_size = (set_size - track_collection.GutterSize() * set_track_count)
                   .ClampNegativeToZero();

    // Once we have determined the size of the set, we can find the size of a
    // given track by dividing the |set_size| by the |set_track_count|.
    // In some situations, this will leave a remainder, but rather than try to
    // distribute the space unequally between tracks, discard it to prefer equal
    // length tracks.
    DCHECK_GT(set_track_count, 0u);
    track_sizes.emplace_back(set_size / set_track_count);
  }
  return track_sizes;
}

Vector<LayoutUnit> LayoutGrid::ComputeExpandedPositions(
    GridTrackSizingDirection track_direction) const {
  Vector<LayoutUnit> expanded_positions;
  const auto* grid_layout_data = LayoutData();
  if (!grid_layout_data)
    return expanded_positions;

  const auto& track_collection = (track_direction == kForColumns)
                                     ? grid_layout_data->Columns()
                                     : grid_layout_data->Rows();

  // |EndLineOfImplicitGrid| is equivalent to the total track count.
  expanded_positions.ReserveInitialCapacity(std::min<wtf_size_t>(
      track_collection.EndLineOfImplicitGrid() + 1, kGridMaxTracks + 1));

  auto current_offset = track_collection.GetSetOffset(0);
  expanded_positions.emplace_back(current_offset);

  auto last_applied_gutter_size = LayoutUnit();
  auto BuildExpandedPositions = [&]() {
    const wtf_size_t range_count = track_collection.RangeCount();

    for (wtf_size_t i = 0; i < range_count; ++i) {
      auto track_sizes_in_range =
          ComputeTrackSizeRepeaterForRange(track_collection, i);
      last_applied_gutter_size = track_collection.RangeSetCount(i)
                                     ? track_collection.GutterSize()
                                     : LayoutUnit();

      const wtf_size_t range_track_count = track_collection.RangeTrackCount(i);
      for (wtf_size_t j = 0; j < range_track_count; ++j) {
        current_offset +=
            track_sizes_in_range[j % track_sizes_in_range.size()] +
            last_applied_gutter_size;
        expanded_positions.emplace_back(current_offset);

        // Respect total track count limit, don't forget to account for the
        // initial offset.
        DCHECK(expanded_positions.size() <= kGridMaxTracks + 1);
        if (expanded_positions.size() == kGridMaxTracks + 1)
          return;
      }
    }
  };

  BuildExpandedPositions();
  expanded_positions.back() -= last_applied_gutter_size;
  return expanded_positions;
}

}  // namespace blink
```