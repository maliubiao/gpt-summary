Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ code for `GridTrackCollection` in Chromium's Blink rendering engine, specifically focusing on its function, relationship to web technologies (JavaScript, HTML, CSS), and potential user/developer errors. It's also the *second* part of a larger file, implying we should synthesize the overall purpose.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and structures. This helps establish the general domain and purpose. Keywords like `Grid`, `Track`, `Collection`, `Sizing`, `Baseline`, `Gutter`, `Flexible`, `Intrinsic`, `Definite`, `Range`, `Set`, `LayoutUnit`, `ComputedStyle`, `NGGridTrackList` immediately point towards a system for managing the dimensions and properties of grid tracks in a layout engine.

**3. Dissecting Key Classes and Methods:**

Next, focus on understanding the key classes and their methods:

*   **`GridLayoutTrackCollection`:**  This appears to be a base class or a lightweight collection, primarily focused on tracking properties of grid tracks (flexible, intrinsic, definite, etc.). Methods like `HasFlexibleTrack`, `HasIntrinsicTrack`, etc., confirm this. The `CreateSubgridTrackCollection` method is important as it shows how subgrids are handled.

*   **`GridSizingTrackCollection`:**  This seems to be the core class for managing the sizes of grid tracks. The constructor takes `GridRangeVector`, suggesting it deals with contiguous groups of tracks. Key methods include:
    *   `TotalTrackSize()`: Calculates the total size of tracks.
    *   `CacheDefiniteSetsGeometry()`, `CacheInitializedSetsGeometry()`, `FinalizeSetsGeometry()`: These suggest a multi-stage process for determining and storing the position and size of track sets. The "geometry" aspect is crucial.
    *   `BuildSets()`:  This is a complex method responsible for creating "sets" of tracks based on CSS grid definitions. It handles explicit and implicit tracks, as well as repeat patterns.
    *   `InitializeSets()`:  Initializes the base size and growth limits of the track sets based on CSS properties like `min-content`, `max-content`, and fixed lengths.
    *   Methods for managing baselines (`SetMajorBaseline`, `SetMinorBaseline`, `ResetBaselines`).

*   **`GridSet`:**  (Referenced but not fully defined in this snippet) This likely represents a group of contiguous tracks with shared sizing properties.

*   **`GridRange`:** (Referenced but not fully defined) Represents a span of grid tracks.

**4. Connecting to Web Technologies:**

Now, think about how these C++ structures relate to HTML, CSS, and JavaScript:

*   **CSS:** The most direct connection is to CSS Grid Layout properties like `grid-template-columns`, `grid-template-rows`, `grid-auto-columns`, `grid-auto-rows`, `grid-gap`, `minmax()`, `fr` units, and the `subgrid` keyword. The code clearly parses and interprets these CSS constructs.

*   **HTML:** The structure of the HTML elements with `display: grid` or `display: inline-grid` will influence how these track collections are created and used.

*   **JavaScript:** While this C++ code doesn't directly execute JavaScript, the layout it produces will affect the visual rendering and layout of the page, which can be manipulated by JavaScript (e.g., getting element sizes, triggering reflows).

**5. Identifying Logic and Potential Errors:**

Consider the internal logic of the methods. For example, `BuildSets` has nested loops and conditions based on whether tracks are explicit or implicit, and whether repeat patterns are used. This area is prone to errors if the CSS parsing or logic is flawed. Think about edge cases, such as invalid CSS values or complex repeat patterns. User errors in *writing* CSS are a primary concern.

**6. Inferring Overall Function (Combining with Part 1):**

Knowing this is "Part 2" implies there's a preceding "Part 1."  The likely scenario is that "Part 1" handles the initial parsing and setup of grid information, while this "Part 2" focuses on the *sizing* and geometry calculations of those tracks. The classes and methods here are heavily geared towards determining the final dimensions of the grid.

**7. Structuring the Response:**

Finally, organize the findings into a clear and structured response, addressing each part of the prompt:

*   **Function:**  Summarize the main purpose of the code.
*   **Relationship to Web Technologies:** Provide concrete examples linking the C++ code to CSS, HTML, and JavaScript.
*   **Logic and Assumptions:**  Explain any key assumptions made by the code and how it processes input to produce output. Provide examples.
*   **User/Developer Errors:**  Illustrate common mistakes users or developers might make when writing CSS that could impact this code.
*   **Summary of Function (Part 2):** Briefly reiterate the specific role of this code within the larger context.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on individual methods. It's important to step back and see the bigger picture of how these methods work together to achieve grid layout.
*   I might not immediately grasp the significance of `GridRange` and `GridSet`. Realizing they represent logical groupings of tracks is crucial.
*   The connection to "baselines" might not be immediately obvious. Researching CSS Grid baselines would be necessary for a complete understanding.
*   Ensuring the examples are concrete and directly related to the code is vital. Avoid vague statements.

By following this structured approach, combining code analysis with knowledge of web technologies, and considering potential errors, a comprehensive and accurate response can be generated.
这是对`blink/renderer/core/layout/grid/grid_track_collection.cc`文件第二部分的分析和功能归纳。

**功能归纳（基于第二部分）：**

这部分代码主要负责实现 `GridSizingTrackCollection` 类，该类是用于**计算和管理 CSS Grid 布局中网格轨道（tracks）的尺寸和几何信息**的核心组件。 它继承自 `GridLayoutTrackCollection` 并扩展了其功能，专注于处理轨道的大小、基线以及在不同阶段缓存和最终确定轨道的布局信息。

**具体功能点：**

1. **管理轨道集合 (Sets):**
    *   存储和管理网格轨道的分组信息，称为 "sets" (`sets_`)。每个 set 可以包含一个或多个连续的轨道，并具有相同的尺寸属性。
    *   提供方法来获取特定索引的 set (`GetSetAt`) 以及迭代器 (`GetSetIterator`) 来遍历所有 set。

2. **计算总轨道尺寸:**
    *   `TotalTrackSize()` 方法计算所有轨道（包括 gutter）的总尺寸。

3. **缓存和管理轨道几何信息:**
    *   `CacheDefiniteSetsGeometry()`:  缓存具有确定尺寸的 set 的几何信息（偏移量），用于优化布局过程。
    *   `CacheInitializedSetsGeometry()`: 缓存已初始化的 set 的几何信息，可能在布局的中间阶段使用。
    *   `FinalizeSetsGeometry()`:  在布局的最后阶段，根据最终的 gutter 尺寸，计算并缓存所有 set 的最终几何信息。

4. **处理不定尺寸的轨道:**
    *   `last_indefinite_index_`:  跟踪最后一个不定尺寸轨道的索引，用于处理具有弹性或自动尺寸的轨道。
    *   `SetIndefiniteGrowthLimitsToBaseSize()`: 将不定尺寸轨道的增长限制设置为其基本尺寸，这可能在某些布局阶段使用。

5. **管理基线 (Baselines):**
    *   `baselines_`:  可选地存储网格的基线信息（主要和次要基线）。
    *   `ResetBaselines()`:  重置基线信息。
    *   `SetMajorBaseline()` 和 `SetMinorBaseline()`:  设置特定 set 的主要和次要基线。

6. **构建轨道集合 (BuildSets):**
    *   `BuildSets(const ComputedStyle& grid_style, ...)`:  根据计算后的样式（`ComputedStyle`）和可用的网格尺寸，构建轨道集合。
    *   `BuildSets(const NGGridTrackList& explicit_track_list, ...)`:  更底层的构建方法，根据显式和隐式定义的轨道列表（来自 CSS 属性 `grid-template-columns`/`grid-template-rows` 和 `grid-auto-columns`/`grid-auto-rows`）创建 set。
    *   处理 `fr` 单位、`minmax()` 函数、`auto` 关键字等不同的轨道尺寸定义。
    *   考虑了 `subgrid` 的情况。

7. **初始化轨道集合 (InitializeSets):**
    *   `InitializeSets()`:  根据轨道尺寸的定义（例如，`min-content`, `max-content`, 固定长度，`fr` 单位），初始化每个 set 的基本尺寸和增长限制。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:** 这个类直接对应于 CSS Grid 布局规范中关于轨道尺寸的定义和计算。
    *   **举例:**  当 CSS 中定义 `grid-template-columns: 100px 1fr auto;` 时，`BuildSets` 方法会解析这个定义，创建三个对应的 set。第一个 set 的尺寸是固定的 100px，第二个 set 的尺寸是弹性单位 `1fr`，第三个 set 的尺寸是 `auto`。 `InitializeSets` 会根据这些定义初始化 set 的 `base_size` 和 `growth_limit`。
    *   **举例:**  CSS 中的 `grid-gap: 10px;` 会影响 `FinalizeSetsGeometry` 方法中 gutter 尺寸的计算。
    *   **举例:**  `minmax(100px, 200px)` 函数会影响 set 的基本尺寸和增长限制的初始化。
    *   **举例:** `subgrid` 关键字的出现会触发 `CreateSubgridTrackCollection` 的调用。

*   **HTML:** HTML 结构决定了哪些元素被应用了 Grid 布局，从而触发 `GridTrackCollection` 的创建和使用。
    *   **举例:**  当一个 `<div>` 元素的 CSS `display` 属性设置为 `grid` 或 `inline-grid` 时，Blink 引擎会创建相应的 `GridTrackCollection` 对象来管理其布局。

*   **JavaScript:** JavaScript 可以通过 DOM API 获取和修改元素的样式，从而间接地影响 `GridTrackCollection` 的行为。
    *   **举例:**  JavaScript 可以动态修改元素的 `grid-template-columns` 属性，这会导致 Blink 重新计算轨道尺寸，并可能创建一个新的 `GridTrackCollection`。
    *   **举例:**  JavaScript 可以读取元素的布局信息（例如，使用 `getBoundingClientRect()`)，这些信息是基于 `GridTrackCollection` 计算的结果。

**逻辑推理与假设输入/输出:**

假设 CSS 定义为:

```css
.container {
  display: grid;
  grid-template-columns: 100px 1fr auto;
  grid-gap: 10px;
  width: 500px; /* 容器的可用宽度 */
}
```

**假设输入:**

*   `grid_style.GridTemplateColumns().track_list`:  包含三个 `NGGridTrackSize` 对象，分别表示 100px, 1fr, auto。
*   `gutter_size`: 10px。
*   `grid_available_size`: 500px。

**逻辑推理 (`BuildSets` 和 `InitializeSets` 的简化过程):**

1. `BuildSets` 会创建三个 `GridSet` 对象。
    *   第一个 set 的 `track_count` 为 1，`track_size` 为固定长度 100px。
    *   第二个 set 的 `track_count` 为 1，`track_size` 为 `1fr`。
    *   第三个 set 的 `track_count` 为 1，`track_size` 为 `auto`。
2. `InitializeSets` 会初始化每个 set 的 `base_size` 和 `growth_limit`。
    *   第一个 set 的 `base_size` 初始化为 100px。
    *   第二个 set 的 `growth_limit` 初始化为 `kIndefiniteSize`，因为它是一个弹性轨道。
    *   第三个 set 的 `base_size` 初始化为 0 (对于 `auto` 轨道，初始基本尺寸为 0)。

**可能的输出 (简化):**

*   `sets_[0].base_size`: 100px
*   `sets_[1].growth_limit`: `kIndefiniteSize`
*   `sets_[2].base_size`: 0

**假设输入 (考虑 `FinalizeSetsGeometry`):**

假设经过布局算法的计算，`1fr` 对应的实际像素值是 240px（(500 - 100 - 0 - 2 * 10) / 1）。

**逻辑推理 (`FinalizeSetsGeometry`):**

1. 遍历 `sets_`。
2. 计算每个 set 的偏移量，包括 gutter。

**可能的输出 (简化):**

*   `sets_geometry_[0].offset`: 0
*   `sets_geometry_[1].offset`: 100 + 10 = 110px
*   `sets_geometry_[2].offset`: 110 + 240 + 10 = 360px
*   `sets_geometry_[3].offset`: 360 + auto 轨道的实际尺寸 + 10

**用户或编程常见的使用错误:**

1. **CSS 定义错误:**
    *   **错误举例:**  在 `grid-template-columns` 中使用了无效的单位或值，例如 `grid-template-columns: abc;` 或 `grid-template-columns: 100;` (缺少单位)。这会导致 Blink 解析 CSS 失败，可能无法创建正确的 `GridTrackCollection` 或导致布局错误。
    *   **错误举例:**  `fr` 单位的分配逻辑不明确，例如，所有轨道都是 `1fr` 且容器宽度是 `auto`，会导致无法计算轨道尺寸。

2. **逻辑上的不一致:**
    *   **错误举例:**  定义了过多的弹性轨道 (`fr`)，导致在有限的空间内无法满足所有轨道的最小尺寸要求，可能会导致布局溢出或意外的尺寸调整。
    *   **错误举例:**  混淆了显式网格和隐式网格的定义，导致意外的轨道生成或尺寸计算。

3. **JavaScript 操作不当:**
    *   **错误举例:**  使用 JavaScript 动态修改 Grid 容器的样式，导致频繁的布局重计算，影响性能。
    *   **错误举例:**  JavaScript 计算布局时假设了固定的轨道尺寸，但实际 CSS 中使用了弹性单位，导致计算结果与实际渲染不符。

**总结 (针对第 2 部分的功能):**

`GridSizingTrackCollection` 类的主要功能是**负责网格布局中轨道尺寸的计算、管理和缓存**。它根据 CSS 样式定义构建轨道集合，初始化轨道的尺寸属性，并在布局的不同阶段缓存和最终确定轨道的几何信息。 这个类是实现 CSS Grid 布局的核心组成部分，确保了网格轨道能够按照规范正确地进行尺寸计算和布局。 它处理了各种复杂的轨道尺寸定义，包括固定长度、弹性单位、自动尺寸以及 `minmax()` 和 `fit-content()` 等函数，并为后续的布局算法提供了必要的轨道尺寸信息。

### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_track_collection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
}

    if (is_opposite_direction_in_root_grid) {
      std::swap(subgrid_baselines.major, subgrid_baselines.minor);
    }

    subgrid_track_collection.baselines_.emplace(std::move(subgrid_baselines));
  }

  subgrid_track_collection.gutter_size_ = subgrid_gutter_size;
  return subgrid_track_collection;
}

bool GridLayoutTrackCollection::HasFlexibleTrack() const {
  return properties_.HasProperty(TrackSpanProperties::kHasFlexibleTrack);
}

bool GridLayoutTrackCollection::HasIntrinsicTrack() const {
  return properties_.HasProperty(TrackSpanProperties::kHasIntrinsicTrack);
}

bool GridLayoutTrackCollection::HasNonDefiniteTrack() const {
  return properties_.HasProperty(TrackSpanProperties::kHasNonDefiniteTrack);
}

bool GridLayoutTrackCollection::IsDependentOnAvailableSize() const {
  return properties_.HasProperty(
      TrackSpanProperties::kIsDependentOnAvailableSize);
}

bool GridLayoutTrackCollection::HasIndefiniteSet() const {
  return !last_indefinite_index_.empty() &&
         last_indefinite_index_.back() != kNotFound;
}

GridSizingTrackCollection::GridSizingTrackCollection(
    GridRangeVector&& ranges,
    bool must_create_baselines,
    GridTrackSizingDirection track_direction)
    : GridLayoutTrackCollection(track_direction) {
  ranges_ = std::move(ranges);

  if (must_create_baselines) {
    baselines_.emplace();
  }

  wtf_size_t set_count = 0;
  for (const auto& range : ranges_) {
    if (!range.IsCollapsed()) {
      non_collapsed_track_count_ += range.track_count;
      set_count += range.set_count;
    }
  }

  last_indefinite_index_.ReserveInitialCapacity(set_count + 1);
  sets_geometry_.ReserveInitialCapacity(set_count + 1);
  sets_.ReserveInitialCapacity(set_count);
}

GridSet& GridSizingTrackCollection::GetSetAt(wtf_size_t set_index) {
  DCHECK_LT(set_index, sets_.size());
  return sets_[set_index];
}

const GridSet& GridSizingTrackCollection::GetSetAt(wtf_size_t set_index) const {
  DCHECK_LT(set_index, sets_.size());
  return sets_[set_index];
}

GridSizingTrackCollection::SetIterator
GridSizingTrackCollection::GetSetIterator() {
  return SetIterator(this, 0, sets_.size());
}

GridSizingTrackCollection::ConstSetIterator
GridSizingTrackCollection::GetConstSetIterator() const {
  return ConstSetIterator(this, 0, sets_.size());
}

GridSizingTrackCollection::SetIterator
GridSizingTrackCollection::GetSetIterator(wtf_size_t begin_set_index,
                                          wtf_size_t end_set_index) {
  return SetIterator(this, begin_set_index, end_set_index);
}

LayoutUnit GridSizingTrackCollection::TotalTrackSize() const {
  if (sets_.empty())
    return LayoutUnit();

  LayoutUnit total_track_size;
  for (const auto& set : sets_)
    total_track_size += set.BaseSize() + set.track_count * gutter_size_;
  return total_track_size - gutter_size_;
}

void GridSizingTrackCollection::CacheDefiniteSetsGeometry() {
  DCHECK(sets_geometry_.empty() && last_indefinite_index_.empty());

  LayoutUnit first_set_offset;
  last_indefinite_index_.push_back(kNotFound);
  sets_geometry_.emplace_back(first_set_offset);

  for (const auto& set : sets_) {
    if (set.track_size.IsDefinite()) {
      first_set_offset += set.base_size + gutter_size_ * set.track_count;
      last_indefinite_index_.push_back(last_indefinite_index_.back());
    } else {
      last_indefinite_index_.push_back(last_indefinite_index_.size() - 1);
    }

    DCHECK_LE(sets_geometry_.back().offset, first_set_offset);
    sets_geometry_.emplace_back(first_set_offset, set.track_count);
  }
}

void GridSizingTrackCollection::CacheInitializedSetsGeometry(
    LayoutUnit first_set_offset) {
  last_indefinite_index_.Shrink(0);
  sets_geometry_.Shrink(0);

  last_indefinite_index_.push_back(kNotFound);
  sets_geometry_.emplace_back(first_set_offset);

  for (const auto& set : sets_) {
    if (set.growth_limit == kIndefiniteSize) {
      last_indefinite_index_.push_back(last_indefinite_index_.size() - 1);
    } else {
      first_set_offset += set.growth_limit + gutter_size_ * set.track_count;
      last_indefinite_index_.push_back(last_indefinite_index_.back());
    }

    DCHECK_LE(sets_geometry_.back().offset, first_set_offset);
    sets_geometry_.emplace_back(first_set_offset, set.track_count);
  }
}

void GridSizingTrackCollection::FinalizeSetsGeometry(
    LayoutUnit first_set_offset,
    LayoutUnit override_gutter_size) {
  gutter_size_ = override_gutter_size;

  last_indefinite_index_.Shrink(0);
  sets_geometry_.Shrink(0);

  sets_geometry_.emplace_back(first_set_offset);

  for (const auto& set : sets_) {
    first_set_offset += set.BaseSize() + gutter_size_ * set.track_count;
    DCHECK_LE(sets_geometry_.back().offset, first_set_offset);
    sets_geometry_.emplace_back(first_set_offset, set.track_count);
  }
}

void GridSizingTrackCollection::SetIndefiniteGrowthLimitsToBaseSize() {
  for (auto& set : sets_) {
    if (set.GrowthLimit() == kIndefiniteSize)
      set.growth_limit = set.base_size;
  }
}

void GridSizingTrackCollection::ResetBaselines() {
  DCHECK(baselines_);

  const wtf_size_t set_count = sets_.size();
  baselines_->major = Vector<LayoutUnit, 16>(set_count, LayoutUnit::Min());
  baselines_->minor = Vector<LayoutUnit, 16>(set_count, LayoutUnit::Min());
}

void GridSizingTrackCollection::SetMajorBaseline(
    wtf_size_t set_index,
    LayoutUnit candidate_baseline) {
  DCHECK(baselines_ && set_index < baselines_->major.size());
  if (candidate_baseline > baselines_->major[set_index])
    baselines_->major[set_index] = candidate_baseline;
}

void GridSizingTrackCollection::SetMinorBaseline(
    wtf_size_t set_index,
    LayoutUnit candidate_baseline) {
  DCHECK(baselines_ && set_index < baselines_->minor.size());
  if (candidate_baseline > baselines_->minor[set_index])
    baselines_->minor[set_index] = candidate_baseline;
}

void GridSizingTrackCollection::BuildSets(const ComputedStyle& grid_style,
                                          LayoutUnit grid_available_size,
                                          LayoutUnit gutter_size) {
  const bool is_for_columns = track_direction_ == kForColumns;
  gutter_size_ = gutter_size;

  BuildSets(
      is_for_columns ? grid_style.GridTemplateColumns().track_list
                     : grid_style.GridTemplateRows().track_list,
      is_for_columns ? grid_style.GridAutoColumns() : grid_style.GridAutoRows(),
      grid_available_size == kIndefiniteSize);
  InitializeSets(grid_available_size);
}

void GridSizingTrackCollection::BuildSets(
    const NGGridTrackList& explicit_track_list,
    const NGGridTrackList& implicit_track_list,
    bool is_available_size_indefinite) {
  properties_.Reset();
  sets_.Shrink(0);

  for (auto& range : ranges_) {
    // Notice that |GridRange::Reset| does not reset the |kIsCollapsed| or
    // |kIsImplicit| flags as they're not affected by the set definitions.
    range.properties.Reset();

    // Collapsed ranges don't produce sets as they will be sized to zero anyway.
    if (range.IsCollapsed())
      continue;

    auto CacheSetProperties = [&range](const GridSet& set) {
      const auto& set_track_size = set.track_size;

      // From https://drafts.csswg.org/css-grid-2/#algo-terms, a <flex> minimum
      // sizing function shouldn't happen as it would be normalized to 'auto'.
      DCHECK(!set_track_size.HasFlexMinTrackBreadth());

      if (set_track_size.HasAutoMinTrackBreadth())
        range.properties.SetProperty(TrackSpanProperties::kHasAutoMinimumTrack);

      if (set_track_size.HasFixedMinTrackBreadth()) {
        range.properties.SetProperty(
            TrackSpanProperties::kHasFixedMinimumTrack);
      }

      if (set_track_size.HasFixedMaxTrackBreadth()) {
        range.properties.SetProperty(
            TrackSpanProperties::kHasFixedMaximumTrack);
      }

      if (set_track_size.HasFlexMaxTrackBreadth()) {
        range.properties.SetProperty(TrackSpanProperties::kHasFlexibleTrack);
        range.properties.SetProperty(
            TrackSpanProperties::kIsDependentOnAvailableSize);
      }

      if (set_track_size.HasIntrinsicMinTrackBreadth() ||
          set_track_size.HasIntrinsicMaxTrackBreadth()) {
        range.properties.SetProperty(TrackSpanProperties::kHasIntrinsicTrack);
      }

      if (!set_track_size.IsDefinite())
        range.properties.SetProperty(TrackSpanProperties::kHasNonDefiniteTrack);
    };

    if (range.repeater_index == kNotFound) {
      // The only cases where a range doesn't have a repeater index are when the
      // range is in the implicit grid and there are no auto track definitions,
      // or when 'subgrid' is specified on a track definition but it's not a
      // child of a grid (and thus not a subgrid); in both cases, fill the
      // entire range with a single set of 'auto' tracks.
      DCHECK(range.IsImplicit() || explicit_track_list.IsSubgriddedAxis());
      CacheSetProperties(sets_.emplace_back(range.track_count));
    } else {
      const auto& specified_track_list =
          range.IsImplicit() ? implicit_track_list : explicit_track_list;

      const wtf_size_t current_repeater_size =
          specified_track_list.RepeatSize(range.repeater_index);
      DCHECK_LT(range.repeater_offset, current_repeater_size);

      // The following two variables help compute how many tracks a set element
      // compresses; suppose we want to print the range, we would circle through
      // the repeater's track list, starting at the range's repeater offset,
      // printing every definition until we cover its track count.
      //
      // 1. |floor_set_track_count| is the number of times we would return to
      // the range's repeater offset, meaning that every definition in the
      // repeater's track list appears at least that many times.
      const wtf_size_t floor_set_track_count =
          range.track_count / current_repeater_size;

      // 2. The remaining track count would not complete another iteration over
      // the entire repeater; this means that the first |remaining_track_count|
      // definitions appear one more time in the range.
      const wtf_size_t remaining_track_count =
          range.track_count % current_repeater_size;

      for (wtf_size_t i = 0; i < range.set_count; ++i) {
        const wtf_size_t set_track_count =
            floor_set_track_count + ((i < remaining_track_count) ? 1 : 0);
        const wtf_size_t set_repeater_offset =
            (range.repeater_offset + i) % current_repeater_size;
        const auto& set_track_size = specified_track_list.RepeatTrackSize(
            range.repeater_index, set_repeater_offset);

        // Record if any of the track sizes depend on the available size; we
        // need to record any percentage tracks *before* normalization as they
        // will change to 'auto' if the available size is indefinite.
        if (set_track_size.HasPercentage()) {
          range.properties.SetProperty(
              TrackSpanProperties::kIsDependentOnAvailableSize);
        }

        CacheSetProperties(sets_.emplace_back(set_track_count, set_track_size,
                                              is_available_size_indefinite));
      }
    }
    properties_ |= range.properties;
  }
}

// https://drafts.csswg.org/css-grid-2/#algo-init
void GridSizingTrackCollection::InitializeSets(LayoutUnit grid_available_size) {
  for (auto& set : sets_) {
    const auto& track_size = set.track_size;

    if (track_size.IsFitContent()) {
      // Indefinite lengths cannot occur, as they must be normalized to 'auto'.
      DCHECK(!track_size.FitContentTrackBreadth().HasPercent() ||
             grid_available_size != kIndefiniteSize);

      LayoutUnit fit_content_argument = MinimumValueForLength(
          track_size.FitContentTrackBreadth(), grid_available_size);
      set.fit_content_limit = fit_content_argument * set.track_count;
    }

    if (track_size.HasFixedMaxTrackBreadth()) {
      DCHECK(!track_size.MaxTrackBreadth().HasPercent() ||
             grid_available_size != kIndefiniteSize);

      // A fixed sizing function: Resolve to an absolute length and use that
      // size as the track’s initial growth limit; if the growth limit is less
      // than the base size, increase the growth limit to match the base size.
      LayoutUnit fixed_max_breadth = MinimumValueForLength(
          track_size.MaxTrackBreadth(), grid_available_size);
      set.growth_limit = fixed_max_breadth * set.track_count;
    } else {
      // An intrinsic or flexible sizing function: Use an initial growth limit
      // of infinity.
      set.growth_limit = kIndefiniteSize;
    }

    if (track_size.HasFixedMinTrackBreadth()) {
      DCHECK(!track_size.MinTrackBreadth().HasPercent() ||
             grid_available_size != kIndefiniteSize);

      // A fixed sizing function: Resolve to an absolute length and use that
      // size as the track’s initial base size.
      LayoutUnit fixed_min_breadth = MinimumValueForLength(
          track_size.MinTrackBreadth(), grid_available_size);
      set.InitBaseSize(fixed_min_breadth * set.track_count);
    } else {
      // An intrinsic sizing function: Use an initial base size of zero.
      DCHECK(track_size.HasIntrinsicMinTrackBreadth());
      set.InitBaseSize(LayoutUnit());
    }
  }
}

}  // namespace blink
```