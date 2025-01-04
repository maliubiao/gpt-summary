Response:
The user wants a summary of the functionality of the provided C++ code snippet from `inspector_highlight.cc`. I need to analyze the code and identify its key responsibilities. The prompt specifically asks about relationships with HTML, CSS, and JavaScript, examples of logical reasoning (with input/output), common usage errors, and confirmation that this is part 2 of 4.

Here's a breakdown of the code's functionality:

1. **Grid Layout Highlighting:**  The code contains several functions related to highlighting CSS Grid layouts (`BuildGridInfo`, `BuildGridPositiveLineNumberPositions`, `BuildGridNegativeLineNumberPositions`, `BuildAreaNamePaths`, `BuildGridLineNames`, `BuildGridTrackSizes`). These functions calculate and generate data structures (protocol buffers) representing the grid lines, areas, and track sizes for visualization in developer tools.

2. **Flexbox Layout Highlighting:**  Similar to Grid, there are functions for highlighting Flexbox layouts (`BuildFlexContainerInfo`, `BuildFlexItemInfo`, `GetFlexLinesAndItems`). These functions gather information about flex lines, flex items, and their dimensions.

3. **Common Highlight Building Blocks:**  There are utility functions for building geometric representations (paths and quads) used in the highlighting process (`BuildPosition`, `QuadToPath`, `RowQuadToPath`, `ColumnQuadToPath`).

4. **Layout Information Retrieval:**  Functions like `GetRotationAngle`, `GetWritingMode`, `IsLayoutNGFlexibleBox`, `IsLayoutNGFlexItem`, `IsHorizontalFlex` extract layout properties needed for accurate highlighting.

5. **Coordinate Transformations:**  Functions like `LocalToAbsolutePoint`, `FrameQuadToViewport` handle the conversion of coordinates between different frames of reference.

6. **CSS Property Access:**  The code interacts with `ComputedStyle` objects to access CSS property values relevant for layout and highlighting (e.g., `IsLeftToRightDirection`, `GridGap`, `GridTemplateAreas`, `FlexBasis`).

7. **Data Structures for Communication:** The code uses `protocol::ListValue` and `protocol::DictionaryValue` to structure the highlighting information for communication with the frontend (likely JavaScript in the developer tools).

**Plan:**

1. **Summarize Core Functionality:** Focus on its role in providing data for visual debugging of layout.
2. **Relate to Web Technologies:**  Show how the data represents HTML elements styled with CSS Grid and Flexbox.
3. **Illustrate Logical Reasoning:** Pick a simple function like `BuildGridPositiveLineNumberPositions` and explain how it calculates positions based on input parameters. Provide a hypothetical scenario with input and output.
4. **Identify Potential User/Programming Errors:**  Think about scenarios where incorrect or missing data could lead to issues.
5. **Acknowledge Part 2/4:** Explicitly state this is the second part.
这是`blink/renderer/core/inspector/inspector_highlight.cc`文件的第二部分，主要功能是**构建用于在开发者工具中高亮显示各种网页元素的布局信息的数据结构**。 这些数据结构会被发送到前端（通常是 JavaScript），以便在页面上绘制高亮覆盖层。

以下是该部分代码功能的归纳和详细说明：

**主要功能归纳:**

* **构建 CSS Grid 布局的高亮信息:**  包括网格线的位置、负/正行号、列号、区域名称、轨道尺寸等。
* **构建 Flexbox 布局的高亮信息:** 包括容器的边界、flex 线的布局、flex 项目的边界和基线位置等。
* **提供构建高亮信息的辅助函数:** 例如坐标转换、路径生成、CSS 属性获取等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:**  这些代码的目标是分析和可视化 HTML 元素。它接收 `Node*` 对象作为输入，这些 `Node` 对象对应着 HTML 结构中的元素。

   * **例子:**  `BuildGridInfo(Element* element, ...)` 函数接收一个 `Element` 指针，这个 `Element` 可以是 HTML 中的一个 `<div>` 或其他应用了 `display: grid` 的元素。

2. **CSS:**  代码会读取和解析元素的 CSS 样式，特别是与布局相关的属性，如 `display: grid`, `display: flex`, `grid-template-rows`, `grid-template-columns`, `flex-direction`, `align-items` 等。

   * **例子:**
      * `To<LayoutGrid>(node->GetLayoutObject())->StyleRef()` 用于获取 Grid 容器的样式。
      * `grid->GridGap(kForRows)` 获取 Grid 行间距，这是 CSS 属性 `row-gap` 的体现。
      * `layout_object->StyleRef().IsDisplayFlexibleBox()` 判断元素是否是 Flexbox 容器。
      * `style->GetPropertyCSSValue(CSSPropertyID::kAlignItems)->CssText()` 获取 Flexbox 容器的 `align-items` 属性值。

3. **JavaScript:**  构建好的高亮信息（例如 `protocol::DictionaryValue` 和 `protocol::ListValue`）最终会通过 Chrome DevTools 的协议发送到前端的 JavaScript 代码。JavaScript 代码会解析这些数据，然后在浏览器窗口中绘制高亮覆盖层，帮助开发者理解元素的布局。

   * **例子:**  `BuildGridInfo` 函数会返回一个 `protocol::DictionaryValue`，其中包含了网格线的坐标、区域名称等信息。前端 JavaScript 会接收这个字典，并根据其中的坐标信息绘制网格线和区域高亮。

**逻辑推理的假设输入与输出:**

让我们以 `BuildGridPositiveLineNumberPositions` 函数为例，来演示逻辑推理：

**函数签名:**

```c++
std::unique_ptr<protocol::ListValue> BuildGridPositiveLineNumberPositions(
    Node* node,
    LayoutUnit grid_gap,
    GridTrackSizingDirection direction,
    float scale,
    LayoutUnit rtl_offset,
    const Vector<LayoutUnit>& positions,
    const Vector<LayoutUnit>& alt_axis_positions)
```

**假设输入:**

* `node`: 指向一个 CSS Grid 容器的 `Element` 节点。
* `grid_gap`:  `LayoutUnit(10)` (假设网格间距为 10px)。
* `direction`: `kForColumns` (表示计算列号位置)。
* `scale`: `1.0f` (缩放比例为 1)。
* `rtl_offset`: `LayoutUnit(0)` (假设不是 RTL 布局)。
* `positions`: `[LayoutUnit(0), LayoutUnit(100), LayoutUnit(200)]` (列轨道的位置)。
* `alt_axis_positions`: `[LayoutUnit(0), LayoutUnit(150)]` (行轨道的位置，用于确定列号的垂直位置)。

**逻辑推理:**

该函数旨在计算正向网格线的数字标签的位置。对于列，它会遍历 `positions` 数组，计算每个列线中间的位置。

* **第一列线 (索引 0):**
    * `first_offset` 将是 `positions[0]`，即 `LayoutUnit(0)`.
    * 列号的水平位置将是 `first_offset`。
    * 列号的垂直位置将从 `alt_axis_positions` 获取。
* **后续列线 (索引 1 及以上):**
    * `gapOffset` 将是 `grid_gap / 2`，即 `LayoutUnit(5)`.
    * 列线的位置将从 `positions` 数组获取。
    * 列号的水平位置将是 `positions[i] - gapOffset`.

**预期输出 (简化表示):**

一个 `protocol::ListValue`，其中包含表示列号位置的 `protocol::DictionaryValue` 对象。每个字典可能包含 "x" 和 "y" 键，表示绝对坐标。

```json
[
  {"x": 0, "y": /* 根据 alt_axis_positions 计算 */},  // 第一列线
  {"x": 100 - 5, "y": /* 根据 alt_axis_positions 计算 */} // 第二列线
]
```

**涉及用户或者编程常见的使用错误:**

1. **CSS 样式未生效:** 如果 HTML 元素没有正确应用 `display: grid` 或 `display: flex` 样式，这些高亮代码可能无法正确识别和处理布局，导致高亮信息不准确或无法显示。
   * **例子:** 开发者忘记在 CSS 中设置 `display: grid`，但期望看到 Grid 高亮。

2. **布局计算错误:**  Blink 引擎在进行布局计算时可能会遇到一些边缘情况或 bug，导致计算出的轨道位置、间距等信息不正确，从而影响高亮效果。这通常是引擎内部的问题，但开发者可能会看到高亮显示不符合预期。

3. **RTL 布局处理错误:**  对于从右到左 (RTL) 的布局，计算位置和偏移需要特殊处理。如果 `rtl_offset` 计算错误或未正确应用，可能会导致高亮线位置偏移。
   * **例子:**  在 RTL 布局中，列号可能出现在列的错误一侧。

4. **缩放问题:** `scale` 参数用于处理页面缩放。如果缩放比例计算或传递错误，高亮元素的大小和位置可能与实际元素不匹配。

5. **假设 `positions` 数组已排序:** 代码通常假设 `positions` 数组是按顺序排列的。如果由于某种原因，这个数组的顺序不正确，计算出的高亮位置也会错误。

**功能归纳 (作为第2部分):**

作为 `blink/renderer/core/inspector/inspector_highlight.cc` 文件的第二部分，该代码片段的核心功能是**专门负责构建 CSS Grid 和 Flexbox 布局的详细高亮信息**。它接收底层的布局信息和 CSS 样式数据，并将其转换为结构化的数据格式，以便 DevTools 前端能够理解并可视化这些布局结构。这部分代码是整个高亮机制中处理复杂二维布局的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_highlight.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
tUnit rtl_offset,
    const Vector<LayoutUnit>& positions,
    const Vector<LayoutUnit>& alt_axis_positions) {
  auto* grid = To<LayoutGrid>(node->GetLayoutObject());
  bool is_rtl = !grid->StyleRef().IsLeftToRightDirection();

  std::unique_ptr<protocol::ListValue> number_positions =
      protocol::ListValue::create();

  wtf_size_t track_count = positions.size();
  LayoutUnit alt_axis_pos = GetPositionForLastTrack(
      grid, direction == kForRows ? kForColumns : kForRows, alt_axis_positions);
  if (is_rtl && direction == kForRows)
    alt_axis_pos += rtl_offset;

  // This is the number of tracks from the start of the grid, to the end of the
  // explicit grid (including any leading implicit tracks).
  size_t explicit_grid_end_track_count =
      grid->ExplicitGridEndForDirection(direction);

  {
    LayoutUnit first_offset =
        GetPositionForFirstTrack(grid, direction, positions);
    if (is_rtl && direction == kForColumns)
      first_offset += rtl_offset;

    // Always start negative numbers at the first line.
    std::unique_ptr<protocol::DictionaryValue> pos =
        protocol::DictionaryValue::create();
    PhysicalOffset number_position(first_offset, alt_axis_pos);
    if (direction == kForRows)
      number_position = Transpose(number_position);
    number_positions->pushValue(
        BuildPosition(LocalToAbsolutePoint(node, number_position, scale)));
  }

  // Then go line by line, calculating the offset to fall in the middle of gaps
  // if needed.
  for (wtf_size_t i = 1; i <= explicit_grid_end_track_count; i++) {
    LayoutUnit gapOffset = grid_gap / 2;
    if (is_rtl && direction == kForColumns)
      gapOffset *= -1;
    if (grid_gap == 0 ||
        (i == explicit_grid_end_track_count && i == track_count - 1)) {
      gapOffset = LayoutUnit();
    }
    LayoutUnit offset = GetPositionForTrackAt(grid, i, direction, positions);
    if (is_rtl && direction == kForColumns)
      offset += rtl_offset;
    PhysicalOffset number_position(offset - gapOffset, alt_axis_pos);
    if (direction == kForRows)
      number_position = Transpose(number_position);
    number_positions->pushValue(
        BuildPosition(LocalToAbsolutePoint(node, number_position, scale)));
  }

  return number_positions;
}

bool IsLayoutNGFlexibleBox(const LayoutObject& layout_object) {
  return layout_object.StyleRef().IsDisplayFlexibleBox() &&
         layout_object.IsFlexibleBox();
}

bool IsLayoutNGFlexItem(const LayoutObject& layout_object) {
  return !layout_object.GetNode()->IsDocumentNode() &&
         IsLayoutNGFlexibleBox(*layout_object.Parent()) &&
         To<LayoutBox>(layout_object).IsFlexItem();
}

std::unique_ptr<protocol::DictionaryValue> BuildAreaNamePaths(
    Node* node,
    float scale,
    const Vector<LayoutUnit>& rows,
    const Vector<LayoutUnit>& columns) {
  const auto* grid = To<LayoutGrid>(node->GetLayoutObject());
  LocalFrameView* containing_view = node->GetDocument().View();
  bool is_rtl = !grid->StyleRef().IsLeftToRightDirection();

  std::unique_ptr<protocol::DictionaryValue> area_paths =
      protocol::DictionaryValue::create();

  if (!grid->StyleRef().GridTemplateAreas()) {
    return area_paths;
  }

  LayoutUnit row_gap = grid->GridGap(kForRows);
  LayoutUnit column_gap = grid->GridGap(kForColumns);

  if (const NamedGridAreaMap* named_area_map =
          grid->CachedPlacementData().line_resolver.NamedAreasMap()) {
    for (const auto& item : *named_area_map) {
      const GridArea& area = item.value;
      const String& name = item.key;

      const auto start_column = GetPositionForTrackAt(
          grid, area.columns.StartLine(), kForColumns, columns);
      const auto end_column = GetPositionForTrackAt(
          grid, area.columns.EndLine(), kForColumns, columns);
      const auto start_row =
          GetPositionForTrackAt(grid, area.rows.StartLine(), kForRows, rows);
      const auto end_row =
          GetPositionForTrackAt(grid, area.rows.EndLine(), kForRows, rows);

      // Only subtract the gap size if the end line isn't the last line in the
      // container.
      const auto row_gap_offset =
          (area.rows.EndLine() == rows.size() - 1) ? LayoutUnit() : row_gap;
      auto column_gap_offset = (area.columns.EndLine() == columns.size() - 1)
                                   ? LayoutUnit()
                                   : column_gap;
      if (is_rtl) {
        column_gap_offset = -column_gap_offset;
      }

      PhysicalOffset position(start_column, start_row);
      PhysicalSize size(end_column - start_column - column_gap_offset,
                        end_row - start_row - row_gap_offset);
      gfx::QuadF area_quad = grid->LocalRectToAbsoluteQuad({position, size});
      FrameQuadToViewport(containing_view, area_quad);
      PathBuilder area_builder;
      area_builder.AppendPath(QuadToPath(area_quad), scale);

      area_paths->setValue(name, area_builder.Release());
    }
  }
  return area_paths;
}

std::unique_ptr<protocol::ListValue> BuildGridLineNames(
    Node* node,
    GridTrackSizingDirection direction,
    float scale,
    const Vector<LayoutUnit>& positions,
    const Vector<LayoutUnit>& alt_axis_positions) {
  auto* grid = To<LayoutGrid>(node->GetLayoutObject());
  const ComputedStyle& grid_container_style = grid->StyleRef();
  bool is_rtl = direction == kForColumns &&
                !grid_container_style.IsLeftToRightDirection();

  std::unique_ptr<protocol::ListValue> lines = protocol::ListValue::create();

  LayoutUnit gap = grid->GridGap(direction);
  LayoutUnit alt_axis_pos = GetPositionForFirstTrack(
      grid, direction == kForRows ? kForColumns : kForRows, alt_axis_positions);

  auto process_grid_lines_map = [&](const NamedGridLinesMap& named_lines_map) {
    for (const auto& item : named_lines_map) {
      const String& name = item.key;

      for (const wtf_size_t index : item.value) {
        LayoutUnit track =
            GetPositionForTrackAt(grid, index, direction, positions);

        LayoutUnit gap_offset =
            index > 0 && index < positions.size() - 1 ? gap / 2 : LayoutUnit();
        if (is_rtl)
          gap_offset *= -1;

        LayoutUnit main_axis_pos = track - gap_offset;
        PhysicalOffset line_name_pos(main_axis_pos, alt_axis_pos);

        if (direction == kForRows)
          line_name_pos = Transpose(line_name_pos);

        std::unique_ptr<protocol::DictionaryValue> line =
            BuildPosition(LocalToAbsolutePoint(node, line_name_pos, scale));

        line->setString("name", name);

        lines->pushValue(std::move(line));
      }
    }
  };

  const NamedGridLinesMap& explicit_lines_map =
      grid->CachedPlacementData().line_resolver.ExplicitNamedLinesMap(
          direction);
  process_grid_lines_map(explicit_lines_map);
  const NamedGridLinesMap& implicit_lines_map =
      grid->CachedPlacementData().line_resolver.ImplicitNamedLinesMap(
          direction);
  process_grid_lines_map(implicit_lines_map);

  return lines;
}

// Gets the rotation angle of the grid layout (clock-wise).
int GetRotationAngle(LayoutObject* layout_object) {
  // Local vector has 135deg bearing to the Y axis.
  int local_vector_bearing = 135;
  gfx::PointF local_a(0, 0);
  gfx::PointF local_b(1, 1);
  gfx::PointF abs_a = layout_object->LocalToAbsolutePoint(local_a);
  gfx::PointF abs_b = layout_object->LocalToAbsolutePoint(local_b);
  // Compute bearing of the absolute vector against the Y axis.
  double theta = atan2(abs_b.x() - abs_a.x(), abs_a.y() - abs_b.y());
  if (theta < 0.0)
    theta += kTwoPiDouble;
  int bearing = std::round(Rad2deg(theta));
  return bearing - local_vector_bearing;
}

String GetWritingMode(const ComputedStyle& computed_style) {
  // The grid overlay uses this to flip the grid lines and labels accordingly.
  switch (computed_style.GetWritingMode()) {
    case WritingMode::kVerticalLr:
      return "vertical-lr";
    case WritingMode::kVerticalRl:
      return "vertical-rl";
    case WritingMode::kSidewaysLr:
      return "sideways-lr";
    case WritingMode::kSidewaysRl:
      return "sideways-rl";
    case WritingMode::kHorizontalTb:
      return "horizontal-tb";
  }
}

// Gets the list of authored track size values resolving repeat() functions
// and skipping line names.
Vector<String> GetAuthoredGridTrackSizes(const CSSValue* value,
                                         size_t auto_repeat_count) {
  Vector<String> result;

  if (!value)
    return result;

  // TODO(alexrudenko): this would not handle track sizes defined using CSS
  // variables.
  const CSSValueList* value_list = DynamicTo<CSSValueList>(value);

  if (!value_list)
    return result;

  for (auto list_value : *value_list) {
    if (IsA<cssvalue::CSSGridAutoRepeatValue>(list_value.Get())) {
      Vector<String> repeated_track_sizes;
      for (auto auto_repeat_value : To<CSSValueList>(*list_value)) {
        if (!auto_repeat_value->IsGridLineNamesValue())
          repeated_track_sizes.push_back(auto_repeat_value->CssText());
      }
      // There could be only one auto repeat value in a |value_list|, therefore,
      // resetting auto_repeat_count to zero after inserting repeated values.
      for (; auto_repeat_count; --auto_repeat_count)
        result.AppendVector(repeated_track_sizes);
      continue;
    }

    if (auto* repeated_values =
            DynamicTo<cssvalue::CSSGridIntegerRepeatValue>(list_value.Get())) {
      size_t repetitions = repeated_values->Repetitions();
      for (size_t i = 0; i < repetitions; ++i) {
        for (auto repeated_value : *repeated_values) {
          if (repeated_value->IsGridLineNamesValue())
            continue;
          result.push_back(repeated_value->CssText());
        }
      }
      continue;
    }

    if (list_value->IsGridLineNamesValue())
      continue;

    result.push_back(list_value->CssText());
  }

  return result;
}

bool IsHorizontalFlex(LayoutObject* layout_flex) {
  return layout_flex->StyleRef().IsHorizontalWritingMode() !=
         layout_flex->StyleRef().ResolvedIsColumnFlexDirection();
}

DevtoolsFlexInfo GetFlexLinesAndItems(LayoutBox* layout_box,
                                      bool is_horizontal,
                                      bool is_reverse) {
  if (auto* layout_ng_flex = DynamicTo<LayoutFlexibleBox>(layout_box)) {
    const DevtoolsFlexInfo* flex_info_from_layout =
        layout_ng_flex->FlexLayoutData();
    if (flex_info_from_layout)
      return *flex_info_from_layout;
  }

  DevtoolsFlexInfo flex_info;
  Vector<DevtoolsFlexInfo::Line>& flex_lines = flex_info.lines;
  // Flex containers can't get fragmented yet, but this may change in the
  // future.
  for (const auto& fragment : layout_box->PhysicalFragments()) {
    LayoutUnit progression;

    for (const auto& child : fragment.Children()) {
      const PhysicalFragment* child_fragment = child.get();
      if (!child_fragment || child_fragment->IsOutOfFlowPositioned())
        continue;

      PhysicalSize fragment_size = child_fragment->Size();
      PhysicalOffset fragment_offset = child.Offset();

      const LayoutObject* object = child_fragment->GetLayoutObject();
      const auto* box = To<LayoutBox>(object);

      LayoutUnit baseline =
          LogicalBoxFragment(layout_box->StyleRef().GetWritingDirection(),
                             *To<PhysicalBoxFragment>(child_fragment))
              .FirstBaselineOrSynthesize(
                  layout_box->StyleRef().GetFontBaseline());
      float adjusted_baseline = AdjustForAbsoluteZoom::AdjustFloat(
          baseline + box->MarginTop(), box->StyleRef());

      PhysicalRect item_rect =
          PhysicalRect(fragment_offset.left - box->MarginLeft(),
                       fragment_offset.top - box->MarginTop(),
                       fragment_size.width + box->MarginWidth(),
                       fragment_size.height + box->MarginHeight());

      LayoutUnit item_start = is_horizontal ? item_rect.X() : item_rect.Y();
      LayoutUnit item_end = is_horizontal ? item_rect.X() + item_rect.Width()
                                          : item_rect.Y() + item_rect.Height();

      if (flex_lines.empty() ||
          (is_reverse ? item_end > progression : item_start < progression)) {
        flex_lines.emplace_back();
      }

      flex_lines.back().items.push_back(
          DevtoolsFlexInfo::Item(item_rect, LayoutUnit(adjusted_baseline)));

      progression = is_reverse ? item_start : item_end;
    }
  }

  return flex_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildFlexContainerInfo(
    Element* element,
    const InspectorFlexContainerHighlightConfig&
        flex_container_highlight_config,
    float scale) {
  CSSComputedStyleDeclaration* style =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
  LocalFrameView* containing_view = element->GetDocument().View();
  LayoutObject* layout_object = element->GetLayoutObject();
  auto* layout_box = To<LayoutBox>(layout_object);
  DCHECK(layout_object);
  bool is_horizontal = IsHorizontalFlex(layout_object);
  bool is_reverse = layout_object->StyleRef().ResolvedIsReverseFlexDirection();

  std::unique_ptr<protocol::DictionaryValue> flex_info =
      protocol::DictionaryValue::create();

  // Create the path for the flex container
  PathBuilder container_builder;
  PhysicalRect content_box = layout_box->PhysicalContentBoxRect();
  gfx::QuadF content_quad = layout_object->LocalRectToAbsoluteQuad(content_box);
  FrameQuadToViewport(containing_view, content_quad);
  container_builder.AppendPath(QuadToPath(content_quad), scale);

  // Gather all flex items, sorted by flex line.
  DevtoolsFlexInfo flex_lines =
      GetFlexLinesAndItems(layout_box, is_horizontal, is_reverse);

  // We send a list of flex lines, each containing a list of flex items, with
  // their baselines, to the frontend.
  std::unique_ptr<protocol::ListValue> lines_info =
      protocol::ListValue::create();
  for (auto line : flex_lines.lines) {
    std::unique_ptr<protocol::ListValue> items_info =
        protocol::ListValue::create();
    for (auto item_data : line.items) {
      std::unique_ptr<protocol::DictionaryValue> item_info =
          protocol::DictionaryValue::create();

      gfx::QuadF item_margin_quad =
          layout_object->LocalRectToAbsoluteQuad(item_data.rect);
      FrameQuadToViewport(containing_view, item_margin_quad);
      PathBuilder item_builder;
      item_builder.AppendPath(QuadToPath(item_margin_quad), scale);

      item_info->setValue("itemBorder", item_builder.Release());
      item_info->setDouble("baseline", item_data.baseline);

      items_info->pushValue(std::move(item_info));
    }
    lines_info->pushValue(std::move(items_info));
  }

  flex_info->setValue("containerBorder", container_builder.Release());
  flex_info->setArray("lines", std::move(lines_info));
  flex_info->setBoolean("isHorizontalFlow", is_horizontal);
  flex_info->setBoolean("isReverse", is_reverse);
  flex_info->setString(
      "alignItemsStyle",
      style->GetPropertyCSSValue(CSSPropertyID::kAlignItems)->CssText());

  double row_gap_value = 0;
  const CSSValue* row_gap = style->GetPropertyCSSValue(CSSPropertyID::kRowGap);
  if (row_gap->IsNumericLiteralValue()) {
    row_gap_value = To<CSSNumericLiteralValue>(row_gap)->DoubleValue();
  }

  double column_gap_value = 0;
  const CSSValue* column_gap =
      style->GetPropertyCSSValue(CSSPropertyID::kColumnGap);
  if (column_gap->IsNumericLiteralValue()) {
    column_gap_value = To<CSSNumericLiteralValue>(column_gap)->DoubleValue();
  }

  flex_info->setDouble("mainGap",
                       is_horizontal ? column_gap_value : row_gap_value);
  flex_info->setDouble("crossGap",
                       is_horizontal ? row_gap_value : column_gap_value);

  flex_info->setValue(
      "flexContainerHighlightConfig",
      BuildFlexContainerHighlightConfigInfo(flex_container_highlight_config));

  return flex_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildFlexItemInfo(
    Element* element,
    const InspectorFlexItemHighlightConfig& flex_item_highlight_config,
    float scale) {
  std::unique_ptr<protocol::DictionaryValue> flex_info =
      protocol::DictionaryValue::create();

  LayoutObject* layout_object = element->GetLayoutObject();
  bool is_horizontal = IsHorizontalFlex(layout_object->Parent());
  Length base_size = Length::Auto();

  const Length& flex_basis = layout_object->StyleRef().FlexBasis();
  const Length& size = is_horizontal ? layout_object->StyleRef().Width()
                                     : layout_object->StyleRef().Height();

  if (flex_basis.IsFixed()) {
    base_size = flex_basis;
  } else if (flex_basis.IsAuto() && size.IsFixed()) {
    base_size = size;
  }

  // For now, we only care about the cases where we can know the base size.
  if (base_size.IsFixed()) {
    flex_info->setDouble("baseSize", base_size.Pixels() * scale);
    flex_info->setBoolean("isHorizontalFlow", is_horizontal);
    auto box_sizing = layout_object->StyleRef().BoxSizing();
    flex_info->setString("boxSizing", box_sizing == EBoxSizing::kBorderBox
                                          ? "border"
                                          : "content");

    flex_info->setValue(
        "flexItemHighlightConfig",
        BuildFlexItemHighlightConfigInfo(flex_item_highlight_config));
  }

  return flex_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildGridInfo(
    Element* element,
    const InspectorGridHighlightConfig& grid_highlight_config,
    float scale,
    bool isPrimary) {
  LocalFrameView* containing_view = element->GetDocument().View();
  DCHECK(element->GetLayoutObject());
  auto* grid = To<LayoutGrid>(element->GetLayoutObject());

  std::unique_ptr<protocol::DictionaryValue> grid_info =
      protocol::DictionaryValue::create();

  const Vector<LayoutUnit> rows = grid->RowPositions();
  const Vector<LayoutUnit> columns = grid->ColumnPositions();

  grid_info->setInteger("rotationAngle", GetRotationAngle(grid));

  // The grid track information collected in this method and sent to the overlay
  // frontend assumes that the grid layout is in a horizontal-tb writing-mode.
  // It is the responsibility of the frontend to flip the rendering of the grid
  // overlay based on the following writingMode value.
  grid_info->setString("writingMode", GetWritingMode(grid->StyleRef()));

  auto row_gap = grid->GridGap(kForRows) + grid->GridItemOffset(kForRows);
  auto column_gap =
      grid->GridGap(kForColumns) + grid->GridItemOffset(kForColumns);

  // The last column in RTL will not go to the extent of the grid if not
  // necessary, and will stop sooner if the tracks don't take up the full size
  // of the grid.
  LayoutUnit rtl_offset =
      grid->LogicalWidth() - columns.back() - grid->BorderAndPaddingInlineEnd();

  if (grid_highlight_config.show_track_sizes) {
    StyleResolver& style_resolver = element->GetDocument().GetStyleResolver();

    HeapHashMap<CSSPropertyName, Member<const CSSValue>> cascaded_values =
        style_resolver.CascadedValuesForElement(element, kPseudoIdNone);

    auto FindCSSValue =
        [&cascaded_values](CSSPropertyID id) -> const CSSValue* {
      auto it = cascaded_values.find(CSSPropertyName(id));
      return it != cascaded_values.end() ? it->value : nullptr;
    };
    Vector<String> column_authored_values = GetAuthoredGridTrackSizes(
        FindCSSValue(CSSPropertyID::kGridTemplateColumns),
        grid->AutoRepeatCountForDirection(kForColumns));
    Vector<String> row_authored_values = GetAuthoredGridTrackSizes(
        FindCSSValue(CSSPropertyID::kGridTemplateRows),
        grid->AutoRepeatCountForDirection(kForRows));

    grid_info->setValue(
        "columnTrackSizes",
        BuildGridTrackSizes(element, kForColumns, scale, column_gap, rtl_offset,
                            columns, rows, &column_authored_values));
    grid_info->setValue(
        "rowTrackSizes",
        BuildGridTrackSizes(element, kForRows, scale, row_gap, rtl_offset, rows,
                            columns, &row_authored_values));
  }

  bool is_ltr = grid->StyleRef().IsLeftToRightDirection();

  PathBuilder row_builder;
  PathBuilder row_gap_builder;
  LayoutUnit row_left = columns.front();
  if (!is_ltr) {
    row_left += rtl_offset;
  }
  LayoutUnit row_width = columns.back() - columns.front();
  for (wtf_size_t i = 1; i < rows.size(); ++i) {
    // Rows
    PhysicalOffset position(row_left, rows.at(i - 1));
    PhysicalSize size(row_width, rows.at(i) - rows.at(i - 1));
    if (i != rows.size() - 1)
      size.height -= row_gap;
    PhysicalRect row(position, size);
    gfx::QuadF row_quad = grid->LocalRectToAbsoluteQuad(row);
    FrameQuadToViewport(containing_view, row_quad);
    row_builder.AppendPath(
        RowQuadToPath(row_quad, i == rows.size() - 1 || row_gap > 0), scale);
    // Row Gaps
    if (i != rows.size() - 1) {
      PhysicalOffset gap_position(row_left, rows.at(i) - row_gap);
      PhysicalSize gap_size(row_width, row_gap);
      PhysicalRect gap(gap_position, gap_size);
      gfx::QuadF gap_quad = grid->LocalRectToAbsoluteQuad(gap);
      FrameQuadToViewport(containing_view, gap_quad);
      row_gap_builder.AppendPath(QuadToPath(gap_quad), scale);
    }
  }
  grid_info->setValue("rows", row_builder.Release());
  grid_info->setValue("rowGaps", row_gap_builder.Release());

  PathBuilder column_builder;
  PathBuilder column_gap_builder;
  LayoutUnit column_top = rows.front();
  LayoutUnit column_height = rows.back() - rows.front();
  for (wtf_size_t i = 1; i < columns.size(); ++i) {
    PhysicalSize size(columns.at(i) - columns.at(i - 1), column_height);
    if (i != columns.size() - 1)
      size.width -= column_gap;
    LayoutUnit line_left =
        GetPositionForTrackAt(grid, i - 1, kForColumns, columns);
    if (!is_ltr) {
      line_left += rtl_offset - size.width;
    }
    PhysicalOffset position(line_left, column_top);
    PhysicalRect column(position, size);
    gfx::QuadF column_quad = grid->LocalRectToAbsoluteQuad(column);
    FrameQuadToViewport(containing_view, column_quad);
    bool draw_end_line = is_ltr ? i == columns.size() - 1 : i == 1;
    column_builder.AppendPath(
        ColumnQuadToPath(column_quad, draw_end_line || column_gap > 0), scale);
    // Column Gaps
    if (i != columns.size() - 1) {
      LayoutUnit gap_left =
          GetPositionForTrackAt(grid, i, kForColumns, columns);
      if (is_ltr)
        gap_left -= column_gap;
      else
        gap_left += rtl_offset;
      PhysicalOffset gap_position(gap_left, column_top);
      PhysicalSize gap_size(column_gap, column_height);
      PhysicalRect gap(gap_position, gap_size);
      gfx::QuadF gap_quad = grid->LocalRectToAbsoluteQuad(gap);
      FrameQuadToViewport(containing_view, gap_quad);
      column_gap_builder.AppendPath(QuadToPath(gap_quad), scale);
    }
  }
  grid_info->setValue("columns", column_builder.Release());
  grid_info->setValue("columnGaps", column_gap_builder.Release());

  // Positive Row and column Line positions
  if (grid_highlight_config.show_positive_line_numbers) {
    grid_info->setValue(
        "positiveRowLineNumberPositions",
        BuildGridPositiveLineNumberPositions(element, row_gap, kForRows, scale,
                                             rtl_offset, rows, columns));
    grid_info->setValue(
        "positiveColumnLineNumberPositions",
        BuildGridPositiveLineNumberPositions(element, column_gap, kForColumns,
                                             scale, rtl_offset, columns, rows));
  }

  // Negative Row and column Line positions
  if (grid_highlight_config.show_negative_line_numbers) {
    grid_info->setValue(
        "negativeRowLineNumberPositions",
        BuildGridNegativeLineNumberPositions(element, row_gap, kForRows, scale,
                                             rtl_offset, rows, columns));
    grid_info->setValue(
        "negativeColumnLineNumberPositions",
        BuildGridNegativeLineNumberPositions(element, column_gap, kForColumns,
                                             scale, rtl_offset, columns, rows));
  }

  // Area names
  if (grid_highlight_config.show_area_names) {
    grid_info->setValue("areaNames",
                        BuildAreaNamePaths(element, scale, rows, columns));
  }

  // line names
  if (grid_highlight_config.show_line_names) {
    grid_info->setValue(
        "rowLineNameOffsets",
        BuildGridLineNames(element, kForRows, scale, rows, columns));
    grid_info->setValue(
        "columnLineNameOffsets",
        BuildGridLineNames(element, kForColumns, scale, columns, rows));
  }

  // Grid border
  PathBuilder grid_border_builder;
  PhysicalOffset grid_position(row_left, column_top);
  PhysicalSize grid_size(row_width, column_height);
  PhysicalRect grid_rect(grid_position, grid_size);
  gfx::QuadF grid_quad = grid->LocalRectToAbsoluteQuad(grid_rect);
  FrameQuadToViewport(containing_view, grid_quad);
  grid_border_builder.AppendPath(QuadToPath(grid_quad), scale);
  grid_info->setValue("gridBorder", grid_border_builder.Release());
  grid_info->setValue("gridHighlightConfig",
                      BuildGridHighlightConfigInfo(grid_highlight_config));

  grid_info->setBoolean("isPrimaryGrid", isPrimary);
  return grid_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildGridInfo(
    Element* element,
    const InspectorHighlightConfig& highlight_config,
    float scale,
    bool isPrimary) {
  // Legacy support for highlight_config.css_grid
  if (highlight_config.css_grid != Color::kTransparent) {
    std::unique_ptr<InspectorGridHighlightConfig> grid_config =
        std::make_unique<InspectorGridHighlightConfig>();
    grid_config->row_line_color = highlight_config.css_grid;
    grid_config->column_line_color = highlight_config.css_grid;
    grid_config->row_line_dash = true;
    grid_config->column_line_dash = true;
    return BuildGridInfo(element, *grid_config, scale, isPrimary);
  }

  return BuildGridInfo(element, *(highlight_config.grid_highlight_config),
                       scale, isPrimary);
}

void CollectQuads(Node* node,
                  bool adjust_for_absolute_zoom,
                  Vector<gfx::QuadF>& out_quads) {
  LayoutObject* layout_object = node->GetLayoutObject();
  // For inline elements, absoluteQuads will return a line box based on the
  // line-height and font metrics, which is technically incorrect as replaced
  // elements like images should use their intristic height and expand the
  // linebox  as needed. To get an appropriate quads we descend
  // into the children and have them add their boxes.
  //
  // Elements with display:contents style (such as slots) do not have layout
  // objects and we always look at their contents.
  if (((layout_object && layout_object->IsLayoutInline()) ||
       (!layout_object && node->IsElementNode() &&
        To<Element>(node)->HasDisplayContentsStyle())) &&
      LayoutTreeBuilderTraversal::FirstChild(*node)) {
    for (Node* child = LayoutTreeBuilderTraversal::FirstChild(*node); child;
         child = LayoutTreeBuilderTraversal::NextSibling(*child))
      CollectQuads(child, adjust_for_absolute_zoom, out_quads);
  } else if (layout_object) {
    wtf_size_t old_size = out_quads.size();
    layout_object->AbsoluteQuads(out_quads);
    wtf_size_t new_size = out_quads.size();
    LocalFrameView* containing_view = layout_object->GetFrameView();
    for (wtf_size_t i = old_size; i < new_size; i++) {
      if (containing_view)
        FrameQuadToViewport(containing_view, out_quads[i]);
      if (adjust_for_absolute_zoom) {
        AdjustForAbsoluteZoom::AdjustQuadMaybeExcludingCSSZoom(out_quads[i],
                                                               *layout_object);
      }
    }
  }
}

std::unique_ptr<protocol::Array<double>> RectForPhysicalRect(
    const PhysicalRect& rect) {
  return std::make_unique<std::vector<double>, std::initializer_list<double>>(
      {rect.X(), rect.Y(), rect.Width(), rect.Height()});
}

// Returns |layout_object|'s bounding box in document coordinates.
PhysicalRect RectInRootFrame(const LayoutObject* layout_object) {
  LocalFrameView* local_frame_view = layout_object->GetFrameView();
  PhysicalRect rect_in_absolute =
      PhysicalRect::EnclosingRect(layout_object->AbsoluteBoundingBoxRectF());
  return local_frame_view
             ? local_frame_view->ConvertToRootFrame(rect_in_absolute)
             : rect_in_absolute;
}

PhysicalRect TextFragmentRectInRootFrame(
    const LayoutObject* layout_object,
    const LayoutText::TextBoxInfo& text_box) {
  PhysicalRect absolute_coords_text_box_rect =
      layout_object->LocalToAbsoluteRect(text_box.local_rect);
  LocalFrameView* local_frame_view = layout_object->GetFrameView();
  return local_frame_view ? local_frame_view->ConvertToRootFrame(
                                absolute_coords_text_box_rect)
                          : absolute_coords_text_box_rect;
}

}  // namespace

InspectorHighlightConfig::InspectorHighlightConfig()
    : show_info(false),
      show_styles(false),
      show_rulers(false),
      show_extension_lines(false),
      show_accessibility_info(true),
      color_format(ColorFormat::kHex) {}

InspectorHighlight::InspectorHighlight(float scale)
    : InspectorHighlightBase(scale),
      show_rulers_(false),
      show_extension_lines_(false),
      show_accessibility_info_(true),
      color_format_(ColorFormat::kHex) {}

InspectorSourceOrderConfig::InspectorSourceOrderConfig() = default;

LineStyle::LineStyle() = default;

BoxStyle::BoxStyle() = default;

InspectorGridHighlightConfig::InspectorGridHighlightConfig()
    : show_grid_extension_lines(false),
      grid_border_dash(false),
      row_line_dash(false),
      column_line_dash(false),
      show_positive_line_numbers(false),
      show_negative_line_numbers(false),
      show_area_names(false),
      show_line_names(false),
      show_track_sizes(false) {}

InspectorFlexContainerHighlightConfig::InspectorFlexContainerHighlightConfig() =
    default;

InspectorFlexItemHighlightConfig::InspectorFlexItemHighlightConfig() = default;

InspectorHighlightBase::InspectorHighlightBase(float scale)
    : highlight_paths_(protocol::ListValue::create()), scale_(scale) {}

InspectorHighlightBase::InspectorHighlightBase(Node* node)
    : highlight_paths_(protocol::ListValue::create()), scale_(1.f) {
  DCHECK(!DisplayLockUtilities::LockedAncestorPreventingPaint(*node));
  LocalFrameView* frame_view = node->GetDocument().View();
  if (frame_view)
    scale_ = DeviceScaleFromFrameView(frame_view);
}

bool InspectorHighlightBase::BuildNodeQuads(Node* node,
                                            gfx::QuadF* content,
                                            gfx::QuadF* padding,
                                            gfx::QuadF* border,
                                            gfx::QuadF* margin) {
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return false;

  LocalFrameView* containing_view = layout_object->GetFrameView();
  if (!containing_view)
    return false;
  if (!layout_object->IsBox() && !layout_object->IsLayoutInline() &&
      !layout_object->IsText()) {
    return false;
  }

  PhysicalRect content_box;
  PhysicalRect padding_box;
  PhysicalRect border_box;
  PhysicalRect margin_box;

  if (layout_object->IsText()) {
    auto* layout_text = To<LayoutText>(layout_object);
    PhysicalRect text_rect = layout_text->VisualOverflowRect();
    content_box = text_rect;
    padding_box = text_rect;
    border_box = text_rect;
    margin_box = text_rect;
  } else if (layout_object->IsBox()) {
    auto* layout_box = To<LayoutBox>(layout_object);
    content_box = layout_box->PhysicalContentBoxRect();

    // Include scrollbars and gutters in the padding highlight.
    padding_box = layout_box->PhysicalPaddingBoxRect();
    PhysicalBoxStrut scrollbars = layout_box->ComputeScrollbars();
    padding_box.SetX(padding_box.X() - scrollbars.left);
    padding_box.SetY(padding_box.Y() - scrollbars.top);
    padding_box.SetWidth(padding_box.Width() + scrollbars.HorizontalSum());
    padding_box.SetHeight(padding_box.Height() + scrollbars.VerticalSum());

    border_box = layout_box->PhysicalBorderBoxRect();

    margin_box = PhysicalRect(border_box.X() - layout_box->MarginLeft(),
                              border_box.Y() - layout_box->MarginTop(),
                              border_box.Width() + layout_box->MarginWidth(),
                              border_box.Height() + layout_box->MarginHeight());
  } else {
    auto* layout_inline = To<LayoutInline>(layout_object);

    // LayoutInline's bounding box includes paddings and borders, excludes
    // margins.
    border_box = layout_inline->PhysicalLinesBoundingB
"""


```