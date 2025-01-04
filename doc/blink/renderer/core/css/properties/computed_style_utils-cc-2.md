Response:
The user wants a summary of the functionality of the provided C++ code snippet from `computed_style_utils.cc`. The summary should specifically highlight the relationships to HTML, CSS, and JavaScript, provide examples, discuss potential user errors, and outline debugging approaches.

**Plan:**

1. **Identify Core Functionality:**  The code primarily deals with collecting and formatting named grid lines for CSS grid layout.
2. **Explain CSS Relationship:**  Focus on how this code represents the `grid-template-rows`, `grid-template-columns`, and related CSS properties.
3. **Illustrate with CSS Examples:**  Show how named lines in CSS translate to the logic in the code.
4. **Address HTML and JavaScript (Indirect):**  Explain that while not directly manipulating HTML or JavaScript, this code is crucial for the *rendering* of elements defined by HTML and styled by CSS, including how JavaScript might interact with these styles.
5. **Consider User Errors:** Think about common mistakes users make when defining grid layouts that could lead to this code being executed.
6. **Outline Debugging Steps:** Describe how a developer might end up inspecting this part of the Blink engine during debugging.
7. **Provide Hypothetical Input/Output:**  Create a simple CSS grid example and trace how the named lines would be processed.
这是 `blink/renderer/core/css/properties/computed_style_utils.cc` 文件的第 3 部分，主要关注 CSS Grid 布局中**已计算样式**的 **命名网格线** 的处理。它定义了一些类和方法，用于收集、组织和表示网格线的名称，以便在计算样式时使用。

**功能归纳：**

这部分代码的主要功能是定义了用于处理 CSS Grid 布局中命名网格线的机制。它包括：

1. **`OrderedNamedLinesCollector` 类及其子类 `OrderedNamedLinesCollectorInGridLayout`：**  这两个类负责收集和存储有序的命名网格线。它们区分了普通命名线和自动重复生成的命名线。`OrderedNamedLinesCollectorInGridLayout` 是用于处理布局网格的特定版本，它考虑了自动重复轨道的情况。

2. **`AppendLines` 方法：**  该方法将指定索引处的命名线添加到 `CSSBracketedValueList` 中。它会根据网格是否是布局网格以及是否在重复区域内来决定是否添加特定的命名线。

3. **`CollectLineNamesForIndex` 方法：**  这是一个虚方法，用于收集特定索引处的命名线。`OrderedNamedLinesCollectorInGridLayout` 重写了这个方法，以处理自动重复轨道的情况，并根据索引的位置添加相应的命名线。

4. **`AddValuesForNamedGridLinesAtIndex` 函数：**  该函数根据提供的 `OrderedNamedLinesCollector` 对象，收集指定索引处的命名线，并将它们添加到 `CSSValueList` 中。它还会处理 subgrid 的情况，跳过折叠的自动重复线。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:** 这部分代码直接服务于 CSS Grid 布局。CSS 中定义的命名网格线 (例如 `grid-template-columns: [col-start] 1fr [col-end];`) 会被解析并存储，然后通过这里的类和方法进行处理，以便在渲染时确定元素的位置和大小。

   **举例：**
   ```css
   .container {
     display: grid;
     grid-template-columns: [main-start] 1fr [content-start] 2fr [content-end] 1fr [main-end];
     grid-template-rows: [top-start] auto [top-end] auto [bottom-start] auto [bottom-end];
   }

   .item {
     grid-column-start: content-start;
     grid-column-end: content-end;
     grid-row-start: top-end;
   }
   ```
   当浏览器渲染这个 CSS 时，`OrderedNamedLinesCollector` 类会存储 `main-start`, `content-start`, `content-end`, `main-end`, `top-start`, `top-end`, `bottom-start`, `bottom-end` 这些命名线以及它们对应的索引。`CollectLineNamesForIndex` 会根据 `.item` 的 `grid-column-start` 等属性的值 (`content-start`)，找到对应的索引，从而确定 `.item` 的起始位置。

* **HTML:** HTML 结构提供了应用 CSS 样式的元素。CSS Grid 布局应用于 HTML 元素，使得这里的代码能够处理这些元素的布局。

   **举例：**
   ```html
   <div class="container">
     <div class="item">Content</div>
   </div>
   ```
   `ComputedStyleUtils` 中的代码会根据 `.container` 的 CSS 样式，特别是 `grid-template-columns` 和 `grid-template-rows` 中定义的命名线，来计算 `.item` 的最终布局位置。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式，包括与 Grid 布局相关的属性。当 JavaScript 修改了与命名网格线相关的 CSS 属性时，Blink 引擎会重新计算样式，并可能再次执行这里的代码来更新命名线的收集和存储。

   **举例：**
   ```javascript
   const container = document.querySelector('.container');
   container.style.gridTemplateColumns = '[new-start] 1fr [new-end]';
   ```
   这段 JavaScript 代码修改了 `.container` 的 `grid-template-columns` 属性。浏览器会重新解析 CSS，并可能调用 `OrderedNamedLinesCollector` 来存储新的命名线 `new-start` 和 `new-end`。

**逻辑推理的假设输入与输出：**

**假设输入（CSS）：**

```css
.grid {
  display: grid;
  grid-template-columns: repeat(2, [col-start] 1fr [col-end]);
  grid-template-rows: [row-a] auto [row-b];
}
```

**假设 `OrderedNamedLinesCollectorInGridLayout` 的实例被创建，用于处理列 (`grid-template-columns`)，并且 `auto_repeat_total_tracks_` 为 4 (因为 repeat(2, ...) 有 4 个逻辑轨道)，`auto_repeat_track_list_length_` 为 2 (因为每个重复单元有 2 个命名线块 `[col-start] 1fr [col-end]`)。**

**输出（`CollectLineNamesForIndex` 的行为）：**

* 当 `i = 0` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-start` (来自普通命名线)
* 当 `i = 1` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-end` (来自普通命名线)
* 当 `i = 2` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-start` (来自自动重复命名线，索引 0)
* 当 `i = 3` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-end` (来自自动重复命名线，索引 1)
* 当 `i = 4` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-start` (来自自动重复命名线，索引 0)
* 当 `i = 5` 时，`CollectLineNamesForIndex` 会调用 `AppendLines`，添加 `col-end` (来自自动重复命名线，索引 1)

**用户或编程常见的使用错误：**

* **命名线拼写错误：** 用户在 CSS 中定义的命名线与在 `grid-column-start` 等属性中使用的名称不一致。这会导致元素无法正确放置。
   **例子：**
   ```css
   .container {
     display: grid;
     grid-template-columns: [mian-start] 1fr; /* 拼写错误 */
   }
   .item {
     grid-column-start: main-start;
   }
   ```
   Blink 引擎会尝试查找名为 `main-start` 的线，但实际上只有 `mian-start`，导致布局可能出现意外。

* **重复的命名线：** 虽然允许在不同的上下文中重复使用相同的命名线名称，但在同一个 `grid-template-rows` 或 `grid-template-columns` 中，可能会导致混淆，尤其是在使用 `span` 关键字时。

* **Subgrid 中对齐线理解错误：** 用户可能不清楚 subgrid 的对齐线是如何继承或重新定义的，导致布局不符合预期。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在 HTML 文件中创建了一个包含 CSS Grid 布局的容器元素。**
2. **用户在 CSS 文件中定义了该容器的 `display: grid;` 以及 `grid-template-columns` 和 `grid-template-rows` 属性，并在其中使用了命名网格线。**
3. **用户发现页面上的某个网格项没有按照预期的位置显示。**
4. **开发者打开浏览器的开发者工具，检查该网格项的计算样式。**
5. **开发者可能注意到 `grid-column-start` 或 `grid-row-start` 等属性的值与预期的命名线不匹配，或者计算出的位置不正确。**
6. **为了深入了解问题，开发者可能会尝试在 Blink 引擎的源代码中设置断点，例如在 `ComputedStyleUtils::ValueForGridTrackList` 或 `OrderedNamedLinesCollector::CollectLineNamesForIndex` 等方法中，以便查看命名线是如何被收集和处理的。**
7. **通过单步调试，开发者可以观察 `ordered_named_grid_lines_` 和 `ordered_named_auto_repeat_grid_lines_` 的内容，以及 `insertion_point_` 等变量的值，来理解命名线是如何被组织和用于计算布局的。**

总而言之，这部分代码是 Blink 引擎中处理 CSS Grid 布局命名网格线的核心部分，它负责将 CSS 中定义的命名线转化为可以用于布局计算的数据结构。理解这部分代码对于调试复杂的 Grid 布局问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/computed_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
InsertionPoint() const { return insertion_point_; }
  bool HasAutoRepeatNamedLinesSpecified() const {
    return AutoRepeatNamedLinesCount() > 0;
  }
  wtf_size_t AutoRepeatNamedLinesCount() const {
    return ordered_named_auto_repeat_grid_lines_.size();
  }
  // A collapsed auto repeat track is a specified auto-repeat track that was
  // clamped to zero repeats. This can only happen for subgrids, as
  // standalone grids guarantee a minimum of 1 repeat. This also requires that
  // auto repetitions were computed, which only happens for layout grids.
  bool HasCollapsedAutoRepeatNamedLines() const {
    return is_layout_grid_ && IsSubgriddedAxis() &&
           HasAutoRepeatNamedLinesSpecified() && auto_repeat_total_tracks_ == 0;
  }
  virtual void CollectLineNamesForIndex(cssvalue::CSSBracketedValueList&,
                                        wtf_size_t index,
                                        NamedLinesType type,
                                        bool is_in_repeat) const;

 protected:
  void AppendLines(cssvalue::CSSBracketedValueList&,
                   wtf_size_t index,
                   NamedLinesType,
                   bool is_in_repeat = false) const;

  const OrderedNamedGridLines& ordered_named_grid_lines_;
  const OrderedNamedGridLines& ordered_named_auto_repeat_grid_lines_;

  // The auto-repeat index.
  wtf_size_t insertion_point_{0};

  // The total number of auto-repeat tracks, factoring in the number of
  // repetitions (e.g. `repeat(auto-fit, [a][b])` with `auto-fit` calculated at
  // 3 repetitions would be 6).
  wtf_size_t auto_repeat_total_tracks_{0};

  // The size of one auto repeat track (e.g. `repeat(auto-fit, [a][b])` has an
  // auto repeat track list length of 2, regardless of the number of repetitions
  // computed for `auto-fit`).
  wtf_size_t auto_repeat_track_list_length_{0};

  // Whether the track definition has `subgrid` specified.
  bool is_subgridded_axis_{false};

  // Whether the element associated with the track collection performs grid
  // layout.
  bool is_layout_grid_{false};
};

class OrderedNamedLinesCollectorInGridLayout
    : public OrderedNamedLinesCollector {
 public:
  OrderedNamedLinesCollectorInGridLayout(
      const OrderedNamedGridLines& ordered_named_grid_lines,
      const OrderedNamedGridLines& ordered_named_auto_repeat_grid_lines,
      wtf_size_t insertion_point,
      wtf_size_t auto_repeat_total_tracks,
      wtf_size_t auto_repeat_track_list_length,
      bool is_subgridded_track)
      : OrderedNamedLinesCollector(ordered_named_grid_lines,
                                   ordered_named_auto_repeat_grid_lines,
                                   is_subgridded_track,
                                   /* is_layout_grid */ true) {
    insertion_point_ = insertion_point;
    auto_repeat_total_tracks_ = auto_repeat_total_tracks;
    auto_repeat_track_list_length_ = auto_repeat_track_list_length;
  }
  void CollectLineNamesForIndex(cssvalue::CSSBracketedValueList&,
                                wtf_size_t index,
                                NamedLinesType type,
                                bool is_in_repeat) const override;
};

void OrderedNamedLinesCollector::AppendLines(
    cssvalue::CSSBracketedValueList& line_names_value,
    wtf_size_t index,
    NamedLinesType type,
    bool is_in_repeat) const {
  const bool is_auto = type == NamedLinesType::kAutoRepeatNamedLines;
  auto iter = is_auto ? ordered_named_auto_repeat_grid_lines_.find(index)
                      : ordered_named_grid_lines_.find(index);
  auto end_iter = is_auto ? ordered_named_auto_repeat_grid_lines_.end()
                          : ordered_named_grid_lines_.end();
  if (iter == end_iter) {
    return;
  }

  for (auto named_grid_line : iter->value) {
    // For layout grids, insert all values. For non-layout grids, in order to
    // round-trip repeaters, we need to prevent inserting certain line names.
    // In particular, don't insert lines from repeaters if we're not in a
    // repeater, and only add the first repeat.
    const bool is_not_in_repeat =
        !is_in_repeat && !named_grid_line.is_in_repeat;
    const bool is_valid_repeat_line =
        is_in_repeat && named_grid_line.is_first_repeat;
    if (is_layout_grid_ || is_not_in_repeat || is_valid_repeat_line) {
      line_names_value.Append(*MakeGarbageCollected<CSSCustomIdentValue>(
          AtomicString(named_grid_line.line_name)));
    }
  }
}

void OrderedNamedLinesCollector::CollectLineNamesForIndex(
    cssvalue::CSSBracketedValueList& line_names_value,
    wtf_size_t i,
    NamedLinesType type,
    bool is_in_repeat) const {
  DCHECK(IsSubgriddedAxis() || !IsEmpty());
  AppendLines(line_names_value, i, type, is_in_repeat);
}

void OrderedNamedLinesCollectorInGridLayout::CollectLineNamesForIndex(
    cssvalue::CSSBracketedValueList& line_names_value,
    wtf_size_t i,
    NamedLinesType type,
    bool is_in_repeat) const {
  DCHECK(IsSubgriddedAxis() || !IsEmpty());

  // Handle lines before the auto repeat insertion point. If we don't have any
  // auto repeat tracks, we can skip all of the auto repeat logic below.
  if (auto_repeat_total_tracks_ == 0LU || i < insertion_point_) {
    AppendLines(line_names_value, i, NamedLinesType::kNamedLines);
    return;
  }

  DCHECK(auto_repeat_total_tracks_);

  // Handle tracks after the auto repeaters.
  if (i > insertion_point_ + auto_repeat_total_tracks_) {
    AppendLines(line_names_value, i - (auto_repeat_total_tracks_ - 1),
                NamedLinesType::kNamedLines);
    return;
  }

  // Handle the auto repeat track at the insertion point.
  if (i == insertion_point_) {
    AppendLines(line_names_value, i, NamedLinesType::kNamedLines);
    AppendLines(line_names_value, 0, NamedLinesType::kAutoRepeatNamedLines);
    return;
  }

  // Handle the final auto repeat track.
  if (i == insertion_point_ + auto_repeat_total_tracks_) {
    AppendLines(line_names_value, auto_repeat_track_list_length_,
                NamedLinesType::kAutoRepeatNamedLines);
    AppendLines(line_names_value, insertion_point_ + 1,
                NamedLinesType::kNamedLines);
    return;
  }

  // Handle tracks in the auto repeat range.
  wtf_size_t auto_repeat_index_in_first_repetition =
      (i - insertion_point_) % auto_repeat_track_list_length_;
  if (!auto_repeat_index_in_first_repetition && i > insertion_point_) {
    AppendLines(line_names_value, auto_repeat_track_list_length_,
                NamedLinesType::kAutoRepeatNamedLines);
  }
  AppendLines(line_names_value, auto_repeat_index_in_first_repetition,
              NamedLinesType::kAutoRepeatNamedLines);
}

void AddValuesForNamedGridLinesAtIndex(OrderedNamedLinesCollector& collector,
                                       wtf_size_t i,
                                       CSSValueList& list,
                                       NamedLinesType type,
                                       bool is_in_repeat = false) {
  if (collector.IsSubgriddedAxis()) {
    // Skip collapsed lines at the auto repeat insertion point.
    if (i == collector.InsertionPoint() &&
        collector.HasCollapsedAutoRepeatNamedLines()) {
      return;
    }
  } else if (collector.IsEmpty()) {
    return;
  }

  auto* line_names = MakeGarbageCollected<cssvalue::CSSBracketedValueList>();
  collector.CollectLineNamesForIndex(*line_names, i, type, is_in_repeat);

  // Subgridded track listings include empty lines per
  // https://www.w3.org/TR/css-grid-2/#resolved-track-list-subgrid.
  if (line_names->length() || collector.IsSubgriddedAxis()) {
    list.Append(*line_names);
  }
}

CSSValue* ComputedStyleUtils::ValueForGridAutoTrackList(
    GridTrackSizingDirection track_direction,
    const LayoutObject* layout_object,
    const ComputedStyle& style) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const NGGridTrackList& auto_track_list = track_direction == kForColumns
                                               ? style.GridAutoColumns()
                                               : style.GridAutoRows();
  if (auto_track_list.RepeaterCount() == 1) {
    for (wtf_size_t i = 0; i < auto_track_list.RepeatSize(0); ++i) {
      list->Append(*SpecifiedValueForGridTrackSize(
          auto_track_list.RepeatTrackSize(0, i), style));
    }
  }
  return list;
}

void PopulateGridTrackListUsedValues(CSSValueList* list,
                                     OrderedNamedLinesCollector& collector,
                                     const Vector<LayoutUnit, 1>& tracks,
                                     const ComputedStyle& style,
                                     wtf_size_t start,
                                     wtf_size_t end,
                                     int offset,
                                     bool discard_line_names) {
  DCHECK_LE(start, end);
  if (collector.HasCollapsedAutoRepeatNamedLines()) {
    // If the collector has a collapsed auto-repeat track, we need to adjust
    // `end` to account for it, as `AddValuesForNamedGridLinesAtIndex` expects
    // `insertion_point` to consume one track. Since there can only be one
    // auto-repeat track, this will always need to be incremented by one.
    if (collector.InsertionPoint() < end) {
      ++end;
    }
  }
  for (wtf_size_t i = start; i < end; ++i) {
    if (!discard_line_names &&
        (offset >= 0 || i >= static_cast<wtf_size_t>(-offset))) {
      AddValuesForNamedGridLinesAtIndex(collector, i + offset, *list,
                                        NamedLinesType::kNamedLines);
    }
    // Subgrids do not include sizes in the track listing.
    if (!collector.IsSubgriddedAxis()) {
      DCHECK_LE(i, tracks.size());
      list->Append(*ZoomAdjustedPixelValue(tracks[i], style));
    }
  }
  // Subgrid track names are always relative to offset 0, so they can ignore the
  // tracks after the offset.
  if (!collector.IsSubgriddedAxis() &&
      (!discard_line_names &&
       (offset >= 0 || end >= static_cast<wtf_size_t>(-offset)))) {
    AddValuesForNamedGridLinesAtIndex(collector, end + offset, *list,
                                      NamedLinesType::kNamedLines);
  }
}

void PopulateNonRepeater(CSSValueList* list,
                         OrderedNamedLinesCollector& collector,
                         const blink::NGGridTrackList& track_list,
                         wtf_size_t repeater_index,
                         wtf_size_t track_index,
                         const ComputedStyle& style) {
  DCHECK_EQ(track_list.RepeatType(repeater_index),
            NGGridTrackRepeater::RepeatType::kNoRepeat);

  AddValuesForNamedGridLinesAtIndex(collector, track_index, *list,
                                    NamedLinesType::kNamedLines);
  // Subgrid definitions do not include track sizes.
  if (!track_list.IsSubgriddedAxis()) {
    list->Append(*ComputedStyleUtils::SpecifiedValueForGridTrackSize(
        track_list.RepeatTrackSize(repeater_index, 0), style));
  }
}

void PopulateAutoRepeater(CSSValueList* list,
                          OrderedNamedLinesCollector& collector,
                          const blink::NGGridTrackList& track_list,
                          wtf_size_t repeater_index,
                          const ComputedStyle& style) {
  blink::NGGridTrackRepeater::RepeatType repeat_type =
      track_list.RepeatType(repeater_index);
  DCHECK(repeat_type == NGGridTrackRepeater::RepeatType::kAutoFill ||
         repeat_type == NGGridTrackRepeater::RepeatType::kAutoFit);

  const bool is_subgrid = track_list.IsSubgriddedAxis();
  CSSValueList* repeated_values;
  wtf_size_t repeat_size = is_subgrid
                               ? track_list.LineNameIndicesCount(repeater_index)
                               : track_list.RepeatSize(repeater_index);

  repeated_values = MakeGarbageCollected<cssvalue::CSSGridAutoRepeatValue>(
      repeat_type == NGGridTrackRepeater::RepeatType::kAutoFill
          ? CSSValueID::kAutoFill
          : CSSValueID::kAutoFit);

  // Unlike integer repeats, line names for auto repeats start at index 0 and go
  // to `repeat_size`. This is because auto repeat named lines are in their own
  // line name collection, while line names for integer repeats are expanded and
  // interspersed with non-repeaters in the track list.
  for (wtf_size_t i = 0; i < repeat_size; ++i) {
    AddValuesForNamedGridLinesAtIndex(collector, i, *repeated_values,
                                      NamedLinesType::kAutoRepeatNamedLines);

    // Subgrids do not support track sizes.
    if (!is_subgrid) {
      const GridTrackSize& track_size =
          track_list.RepeatTrackSize(repeater_index, i);
      repeated_values->Append(
          *ComputedStyleUtils::SpecifiedValueForGridTrackSize(track_size,
                                                              style));
    }
  }

  // Add any additional auto repeat line names after size definitions.
  for (wtf_size_t i = repeat_size; i < collector.AutoRepeatNamedLinesCount();
       ++i) {
    AddValuesForNamedGridLinesAtIndex(collector, i, *repeated_values,
                                      NamedLinesType::kAutoRepeatNamedLines);
  }
  // Subgrids allow for empty line definitions.
  if (is_subgrid && repeat_size == 0) {
    repeated_values->Append(
        *MakeGarbageCollected<cssvalue::CSSBracketedValueList>());
  }

  list->Append(*repeated_values);
}

// Returns the number of tracks populated after expanding repetitions.
wtf_size_t PopulateIntegerRepeater(CSSValueList* list,
                                   OrderedNamedLinesCollector& collector,
                                   const blink::NGGridTrackList& track_list,
                                   wtf_size_t repeater_index,
                                   wtf_size_t track_index,
                                   const ComputedStyle& style) {
  const bool is_subgrid = track_list.IsSubgriddedAxis();
  CSSValueList* repeated_values;
  wtf_size_t number_of_repetitions = track_list.RepeatCount(repeater_index, 0);
  wtf_size_t repeat_size = is_subgrid
                               ? track_list.LineNameIndicesCount(repeater_index)
                               : track_list.RepeatSize(repeater_index);

  repeated_values = MakeGarbageCollected<cssvalue::CSSGridIntegerRepeatValue>(
      number_of_repetitions);

  // Line names for integer repeats get expanded and interspersed with
  // non-repeaters in the track list.
  for (wtf_size_t i = 0; i < repeat_size; ++i) {
    AddValuesForNamedGridLinesAtIndex(
        collector, track_index + i, *repeated_values,
        NamedLinesType::kNamedLines, /* is_in_repeat */ true);

    // Subgrids do not support track sizes.
    if (!is_subgrid) {
      const GridTrackSize& track_size =
          track_list.RepeatTrackSize(repeater_index, i);
      repeated_values->Append(
          *ComputedStyleUtils::SpecifiedValueForGridTrackSize(track_size,
                                                              style));
    }
  }

  // Standalone grids may have line names after track sizes.
  if (!is_subgrid) {
    AddValuesForNamedGridLinesAtIndex(
        collector, track_index + repeat_size, *repeated_values,
        NamedLinesType::kNamedLines, /* is_in_repeat */ true);
  } else if (repeat_size == 0) {
    // Subgrids allow for empty line definitions.
    repeated_values->Append(
        *MakeGarbageCollected<cssvalue::CSSBracketedValueList>());
  }

  list->Append(*repeated_values);

  return repeat_size * number_of_repetitions;
}

void PopulateGridTrackListComputedValues(
    CSSValueList* list,
    OrderedNamedLinesCollector& collector,
    const blink::NGGridTrackList& track_list,
    const ComputedStyle& style) {
  const bool is_subgrid = collector.IsSubgriddedAxis();
  wtf_size_t track_index = 0;

  // Iterate over each repeater. This will cover all tracks because even non
  // repeats will add repeaters of type `kNoRepeat` to their track list.
  for (wtf_size_t i = 0; i < track_list.RepeaterCount(); ++i) {
    switch (track_list.RepeatType(i)) {
      case NGGridTrackRepeater::RepeatType::kNoRepeat:
        PopulateNonRepeater(list, collector, track_list, i, track_index, style);

        // Non repeaters always consume one track index.
        ++track_index;
        break;

      case NGGridTrackRepeater::RepeatType::kInteger:
        // Standalone grids can have line names between sizes and repeaters.
        if (!is_subgrid) {
          AddValuesForNamedGridLinesAtIndex(collector, track_index, *list,
                                            NamedLinesType::kNamedLines);
        }
        // `PopulateIntegerRepeater` will return the number of tracks populated.
        // We need to update `track_index` by this value, as the track list
        // has expanded integer repeaters and interspersed them with
        // non-repeaters.
        track_index += PopulateIntegerRepeater(list, collector, track_list, i,
                                               track_index, style);
        break;

      case NGGridTrackRepeater::RepeatType::kAutoFill:
      case NGGridTrackRepeater::RepeatType::kAutoFit:
        // Standalone grids can have line names between sizes and repeaters.
        if (!is_subgrid) {
          AddValuesForNamedGridLinesAtIndex(collector, track_index, *list,
                                            NamedLinesType::kNamedLines);
        }
        PopulateAutoRepeater(list, collector, track_list, i, style);

        // Auto repeaters always consume one track index.
        ++track_index;
        break;
      default:
        NOTREACHED();
    }
  }
  // Standalone grids can have line names after sizes and repeaters.
  if (!is_subgrid) {
    AddValuesForNamedGridLinesAtIndex(collector, track_index, *list,
                                      NamedLinesType::kNamedLines);
  }
}

CSSValue* ComputedStyleUtils::ValueForGridTrackList(
    GridTrackSizingDirection direction,
    const LayoutObject* layout_object,
    const ComputedStyle& style,
    bool force_computed_value) {
  const bool is_for_columns = direction == kForColumns;
  const ComputedGridTrackList& computed_grid_track_list =
      is_for_columns ? style.GridTemplateColumns() : style.GridTemplateRows();
  const auto* grid = DynamicTo<LayoutGrid>(layout_object);

  // Handle the 'none' case.
  bool is_track_list_empty =
      !computed_grid_track_list.track_list.RepeaterCount();
  if (grid && is_track_list_empty) {
    // For grids we should consider every listed track, whether implicitly or
    // explicitly created. Empty grids have a sole grid line per axis.
    const Vector<LayoutUnit>& positions =
        is_for_columns ? grid->ColumnPositions() : grid->RowPositions();
    is_track_list_empty = positions.size() == 1;
  }

  const bool is_subgrid_specified = computed_grid_track_list.IsSubgriddedAxis();
  const bool is_subgrid_valid =
      (grid && grid->HasCachedPlacementData())
          ? grid->CachedPlacementData().SubgridSpanSize(direction) != kNotFound
          : false;
  const bool is_subgrid = is_subgrid_specified && is_subgrid_valid;

  // Standalone grids with empty track lists should compute to `none`, but
  // this is not the case for subgrids. Subgrids need to account for the
  // following: "If there is no parent grid, this value is equivalent to the
  // initial value, `none`, and the grid container is not a subgrid."
  // https://www.w3.org/TR/css-grid-2/#subgrid-listing
  //
  // Interestingly, specifying `subgrid` on a non-grid *will* compute to
  // `subgrid` syntax.
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (is_subgrid || (is_subgrid_specified && !grid)) {
    list->Append(
        *MakeGarbageCollected<CSSIdentifierValue>(CSSValueID::kSubgrid));
  } else if (!is_subgrid_specified && is_track_list_empty) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  wtf_size_t auto_repeat_insertion_point =
      computed_grid_track_list.auto_repeat_insertion_point;
  const NGGridTrackList& ng_track_list = computed_grid_track_list.track_list;

  // "Note: In general, resolved values are the computed values, except for a
  // small list of legacy 2.1 properties. However, compatibility with early
  // implementations of this module requires us to define grid-template-rows and
  // grid-template-columns as returning used values."
  //
  // https://www.w3.org/TR/css-grid-2/#resolved-track-list-standalone
  //
  // Default to the used value if it's a layout grid, unless
  // `force_computed_value` is set (which is used for `grid-template`). Non
  // layout-grids will always report the computed value.
  if (grid && !force_computed_value) {
    // The number of auto repeat tracks. For 'repeat(auto-fill, [x][y])' this
    // will be 2, regardless of what auto-fill computes to. For subgrids, use
    // the number of grid line names specified on the track definition. For
    // standalone grids, this will be the number of track sizes, as this can
    // can differ from the count on the track definition.
    wtf_size_t auto_repeat_track_list_length =
        ng_track_list.AutoRepeatTrackCount();

    // Standalone grids will report the track sizes in the computed style
    // string, so base the start and end indices on it.
    auto track_sizes = grid->TrackSizesForComputedStyle(direction);
    wtf_size_t start_index = 0;
    wtf_size_t end_index = track_sizes.size();
    if (is_subgrid) {
      // For subgrids, track sizes are not supported. Instead, calculate the end
      // index by subtracting the grid end from its start.
      start_index = grid->ExplicitGridStartForDirection(direction);
      end_index = grid->ExplicitGridEndForDirection(direction) -
                  grid->ExplicitGridStartForDirection(direction) + 1;
    }
    // If the element is a grid container, the resolved value is the used value,
    // specifying track sizes in pixels (if it's a standalone grid), and
    // expanding the repeat() notation.
    OrderedNamedLinesCollectorInGridLayout collector(
        computed_grid_track_list.ordered_named_grid_lines,
        computed_grid_track_list.auto_repeat_ordered_named_grid_lines,
        auto_repeat_insertion_point,
        grid->AutoRepeatCountForDirection(direction),
        auto_repeat_track_list_length, is_subgrid);
    // Named grid line indices are relative to the explicit grid, but we are
    // including all tracks. So we need to subtract the number of leading
    // implicit tracks in order to get the proper line index. This is ignored
    // for subgrids because they only have explicit tracks.
    int offset = -base::checked_cast<int>(
        grid->ExplicitGridStartForDirection(direction));

    // If `subgrid` is specified in `grid-template-rows/columns`, but the
    // element is not a valid subgrid, computed style should behave as if it's a
    // standalone grid. It should also drop any line names specified in the
    // invalid subgrid rows/column definitions. See
    // https://github.com/w3c/csswg-drafts/issues/9015.
    const bool discard_line_names =
        grid && is_subgrid_specified && !is_subgrid_valid;
    PopulateGridTrackListUsedValues(list, collector, track_sizes, style,
                                    start_index, end_index, offset,
                                    discard_line_names);
    return list;
  }

  OrderedNamedLinesCollector collector(
      computed_grid_track_list.ordered_named_grid_lines,
      computed_grid_track_list.auto_repeat_ordered_named_grid_lines,
      is_subgrid_specified, !!grid);
  PopulateGridTrackListComputedValues(list, collector, ng_track_list, style);
  return list;
}

CSSValue* ComputedStyleUtils::ValueForGridPosition(
    const GridPosition& position) {
  if (position.IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  if (position.IsNamedGridArea()) {
    return MakeGarbageCollected<CSSCustomIdentValue>(position.NamedGridLine());
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const bool has_named_line = !position.NamedGridLine().IsNull();
  if (position.IsSpan()) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kSpan));

    // Do not include the numeric value of 1 if followed by a line name.
    if (position.SpanPosition() != 1 || !has_named_line) {
      list->Append(*CSSNumericLiteralValue::Create(
          position.SpanPosition(), CSSPrimitiveValue::UnitType::kNumber));
    }
  } else {
    list->Append(*CSSNumericLiteralValue::Create(
        position.IntegerPosition(), CSSPrimitiveValue::UnitType::kNumber));
  }

  if (has_named_line) {
    list->Append(
        *MakeGarbageCollected<CSSCustomIdentValue>(position.NamedGridLine()));
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForMasonrySlack(
    const std::optional<Length>& slack_length,
    const ComputedStyle& style) {
  return slack_length ? ZoomAdjustedPixelValueForLength(*slack_length, style)
                      : CSSIdentifierValue::Create(CSSValueID::kNormal);
}

CSSValue* ComputedStyleUtils::ValueForMasonryTrackList(
    const LayoutObject* layout_object,
    const ComputedStyle& style) {
  const auto& computed_track_list = style.MasonryTemplateTracks();
  DCHECK_GT(computed_track_list.track_list.RepeaterCount(), 0u);

  auto* list = CSSValueList::CreateSpaceSeparated();
  OrderedNamedLinesCollector collector(
      computed_track_list.ordered_named_grid_lines,
      computed_track_list.auto_repeat_ordered_named_grid_lines,
      computed_track_list.IsSubgriddedAxis(), /*is_layout_grid=*/false);

  PopulateGridTrackListComputedValues(list, collector,
                                      computed_track_list.track_list, style);
  return list;
}

static bool IsSVGObjectWithWidthAndHeight(const LayoutObject& layout_object) {
  DCHECK(layout_object.IsSVGChild());
  return layout_object.IsSVGImage() || layout_object.IsSVGForeignObject() ||
         (layout_object.IsSVGShape() &&
          IsA<SVGRectElement>(layout_object.GetNode()));
}

gfx::SizeF ComputedStyleUtils::UsedBoxSize(const LayoutObject& layout_object) {
  if (layout_object.IsSVGChild() &&
      IsSVGObjectWithWidthAndHeight(layout_object)) {
    gfx::SizeF size = layout_object.ObjectBoundingBox().size();
    // The object bounding box does not have zoom applied. Multiply with zoom
    // here since we'll divide by it when we produce the CSS value.
    size.Scale(layout_object.StyleRef().EffectiveZoom());
    return size;
  }
  if (!layout_object.IsBox()) {
    return gfx::SizeF();
  }
  const auto& box = To<LayoutBox>(layout_object);
  return gfx::SizeF(box.StyleRef().BoxSizing() == EBoxSizing::kBorderBox
                        ? box.PhysicalBorderBoxRect().size
                        : box.ComputedCSSContentBoxRect().size);
}

CSSValue* ComputedStyleUtils::RenderTextDecorationFlagsToCSSValue(
    TextDecorationLine text_decoration) {
  switch (text_decoration) {
    case TextDecorationLine::kNone:
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    case TextDecorationLine::kSpellingError:
      return CSSIdentifierValue::Create(CSSValueID::kSpellingError);
    case TextDecorationLine::kGrammarError:
      return CSSIdentifierValue::Create(CSSValueID::kGrammarError);
    default:
      break;
  }

  // Blink value is ignored.
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (EnumHasFlags(text_decoration, TextDecorationLine::kUnderline)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kUnderline));
  }
  if (EnumHasFlags(text_decoration, TextDecorationLine::kOverline)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kOverline));
  }
  if (EnumHasFlags(text_decoration, TextDecorationLine::kLineThrough)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kLineThrough));
  }

  if (!list->length()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return list;
}

CSSValue* ComputedStyleUtils::ValueForTextDecorationStyle(
    ETextDecorationStyle text_decoration_style) {
  switch (text_decoration_style) {
    case ETextDecorationStyle::kSolid:
      return CSSIdentifierValue::Create(CSSValueID::kSolid);
    case ETextDecorationStyle::kDouble:
      return CSSIdentifierValue::Create(CSSValueID::kDouble);
    case ETextDecorationStyle::kDotted:
      return CSSIdentifierValue::Create(CSSValueID::kDotted);
    case ETextDecorationStyle::kDashed:
      return CSSIdentifierValue::Create(CSSValueID::kDashed);
    case ETextDecorationStyle::kWavy:
      return CSSIdentifierValue::Create(CSSValueID::kWavy);
  }

  NOTREACHED();
}

CSSValue* ComputedStyleUtils::ValueForTextDecorationSkipInk(
    ETextDecorationSkipInk text_decoration_skip_ink) {
  if (text_decoration_skip_ink == ETextDecorationSkipInk::kNone) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return CSSIdentifierValue::Create(CSSValueID::kAuto);
}

CSSValue* ComputedStyleUtils::TouchActionFlagsToCSSValue(
    TouchAction touch_action) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (touch_action == TouchAction::kAuto) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  } else if (touch_action == TouchAction::kNone) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  } else if (touch_action == TouchAction::kManipulation) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kManipulation));
  } else {
    if ((touch_action & TouchAction::kPanX) == TouchAction::kPanX) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanX));
    } else if ((touch_action & TouchAction::kPanLeft) != TouchAction::kNone) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanLeft));
    } else if ((touch_action & TouchAction::kPanRight) != TouchAction::kNone) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanRight));
    }
    if ((touch_action & TouchAction::kPanY) == TouchAction::kPanY) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanY));
    } else if ((touch_action & TouchAction::kPanUp) != TouchAction::kNone) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanUp));
    } else if ((touch_action & TouchAction::kPanDown) != TouchAction::kNone) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPanDown));
    }

    if ((touch_action & TouchAction::kPinchZoom) == TouchAction::kPinchZoom) {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kPinchZoom));
    }
  }

  DCHECK(list->length());
  return list;
}

CSSValue* ComputedStyleUtils::ValueForWillChange(
    const Vector<CSSPropertyID>& will_change_properties,
    bool will_change_contents,
    bool will_change_scroll_position) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  if (will_change_contents) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kContents));
  }
  if (will_change_scroll_position) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kScrollPosition));
  }
  for (wtf_size_t i = 0; i < will_change_properties.size(); ++i) {
    list->Append(
        *MakeGarbageCollected<CSSCustomIdentValue>(will_change_properties[i]));
  }
  if (!list->length()) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  }
  return list;
}

namespace {

template <typename T, wtf_size_t C, typename Func, typename... Args>
CSSValue* CreateAnimationValueList(const Vector<T, C>& values,
                                   Func item_func,
                                   Args&&... args) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const T& value : values) {
    list->Append(*item_func(value, std::forward<Args>(args)...));
  }
  return list;
}

}  // namespace

CSSValue* ComputedStyleUtils::ValueForAnimationDelay(
    const Timing::Delay& delay) {
  return CSSNumericLiteralValue::Create(delay.AsTimeValue().InSecondsF(),
                                        CSSPrimitiveValue::UnitType::kSeconds);
}

CSSValue* ComputedStyleUtils::ValueForAnimationDelayList(
    const CSSTimingData* timing_data) {
  return CreateAnimationValueList(
      timing_data
          ? timing_data->DelayStartList()
          : Vector<Timing::Delay, 1>{CSSTimingData::InitialDelayStart()},
      &ValueForAnimationDelay);
}

CSSValue* ComputedStyleUtils::ValueForAnimationDirection(
    Timing::PlaybackDirection direction) {
  switch (direction) {
    case Timing::PlaybackDirection::NORMAL:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case Timing::PlaybackDirection::ALTERNATE_NORMAL:
      return CSSIdentifierValue::Create(CSSValueID::kAlternate);
    case Timing::PlaybackDirection::REVERSE:
      return CSSIdentifierValue::Create(CSSValueID::kReverse);
    case Timing::PlaybackDirection::ALTERNATE_REVERSE:
      return CSSIdentifierValue::Create(CSSValueID::kAlternateReverse);
    default:
      NOTREACH
"""


```