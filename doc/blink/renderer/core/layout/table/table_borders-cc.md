Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

**1. Understanding the Core Task:**

The fundamental goal is to understand the functionality of `table_borders.cc` within the Chromium Blink rendering engine, particularly its role in handling table borders. The prompt also specifically asks about connections to web technologies (HTML, CSS, JavaScript), logical reasoning (input/output), and potential user/programming errors.

**2. Initial Code Scan and Keyword Recognition:**

I'd start by quickly scanning the code, looking for key terms and patterns. This helps establish the general domain:

* **`// Copyright 2020 The Chromium Authors`**: Confirms it's Chromium code.
* **`#include` directives**:  These point to related classes and concepts. I'd pay attention to:
    * `table_borders.h`: The header file for this class, likely containing its declaration.
    * `css/properties/longhands.h`: Indicates interaction with CSS properties.
    * `layout/...`:  Suggests this code is part of the layout engine.
    * `table/...`:  Specifically related to table layout.
    * `style/computed_style.h`:  Deals with the final, computed CSS styles.
* **Class Name: `TableBorders`**:  The central focus.
* **Methods like `ComputeTableBorders`, `MergeBorders`, `GetCellBorders`, `UpdateTableBorder`**: These suggest the core operations of the class.
* **Enums like `EBorderStyle`, `EdgeSide`, `EdgeSource`**:  Define the types of borders and their origins.
* **Constants like `kCollapse` (from `EBorderCollapse`)**: Indicate how different border models are handled.

**3. Deciphering the Core Functionality: `ComputeTableBorders`**

This function seems crucial. I'd examine it step-by-step:

* **Input:** A `BlockNode` representing the table.
* **`table_style.BorderCollapse()`**:  The first key decision point – whether borders are collapsed or separated. This immediately tells me there are two distinct models to handle.
* **`ComputeNonCollapsedTableBorders`**: This suggests a separate (though not shown in this code) mechanism for the `separate` border model.
* **`TableGroupedChildren`**:  Indicates the code is processing different parts of the table structure (`<colgroup>`, `<tr>`, `<td>`, etc.).
* **Nested Loops**:  Iterating through sections, rows, and cells suggests the code is analyzing the table's structure to determine border contributions.
* **`MergeBorders`**: This function is called repeatedly with different `EdgeSource` values (cell, row, section, column, table), revealing the order of precedence in collapsed borders.
* **`VisitLayoutTableColumn`**: This suggests a specific way of processing `<col>` and `<colgroup>` elements.
* **`UpdateTableBorder`**:  Likely calculates the final border of the entire table element in the collapsed model.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The code directly relates to HTML table elements (`<table>`, `<tr>`, `<td>`, `<colgroup>`, `<col>`). The structure of the code reflects the nesting of these elements.
* **CSS:**  The code heavily relies on `ComputedStyle`. This directly links to CSS border properties (`border-top`, `border-right`, `border-collapse`, etc.). The `IsSourceMoreSpecificThanEdge` function embodies the CSS border conflict resolution rules.
* **JavaScript:** While this specific C++ file doesn't *directly* interact with JavaScript, the layout and rendering it performs are triggered by changes to the DOM and CSS styles, often manipulated by JavaScript. For instance, a JavaScript animation that changes a cell's border style would eventually lead to this C++ code being re-executed.

**5. Logical Reasoning (Input/Output Examples):**

To illustrate the logic, I'd consider simple scenarios:

* **Basic Table with Borders:** Input: A simple HTML table with `border: 1px solid black;` CSS. Output: The `TableBorders` object would store information indicating a 1px solid black border on all sides.
* **Collapsed Borders with Different Styles:** Input: A table with `border-collapse: collapse;` and individual cells with different border styles. Output: The `MergeBorders` logic, especially `IsSourceMoreSpecificThanEdge`, determines which border style wins at each edge.
* **`colspan` and `rowspan`:** Input: A table with cells using `colspan` and `rowspan`. Output:  The `MarkInnerBordersAsDoNotFill` function would be invoked to prevent overlapping borders and ensure correct rendering.

**6. Identifying Potential Errors:**

* **User Errors (CSS):** Incorrect or conflicting CSS border rules can lead to unexpected rendering. For instance, setting `border-collapse: collapse` but then expecting separated borders to be visible.
* **Programming Errors (C++):**  The code itself handles many edge cases (like empty table parts). However, potential errors could arise from incorrect indexing or boundary conditions within the loops, or if the `ComputedStyle` data is somehow invalid. The `DCHECK` statements are there to catch some of these developer errors during debugging. Overlapping cells (mentioned in the code comments) are another potential source of rendering issues.

**7. Structuring the Answer:**

Finally, I'd organize the information clearly, following the prompt's structure:

* **Functionality:** Provide a high-level overview and then delve into specific aspects like collapsed vs. separated borders, precedence rules, and handling of `colspan`/`rowspan`.
* **Relationship to Web Technologies:** Explicitly connect the C++ code to HTML elements and CSS properties. Explain the indirect link to JavaScript.
* **Logical Reasoning (Input/Output):** Provide concrete examples to illustrate the behavior of the code.
* **User/Programming Errors:**  Give practical examples of common mistakes that could interact with this code.

This structured approach, combining code analysis, knowledge of web technologies, and logical reasoning, allows for a comprehensive understanding and explanation of the given C++ source file.
好的， 让我们来分析一下 `blink/renderer/core/layout/table/table_borders.cc` 这个文件。

**功能概述:**

`table_borders.cc` 文件的主要职责是计算和管理 HTML 表格的边框。  具体来说，它负责：

1. **确定表格的边框样式和宽度:**  根据 CSS 样式规则，计算表格自身、行、列、单元格的边框样式 (如 solid, dashed, dotted 等) 和宽度。
2. **处理 `border-collapse` 属性:**  这是表格边框处理的核心。
    * **`border-collapse: separate` (分隔边框模型):**  计算每个单元格和表格自身的独立边框。虽然代码中主要关注 `border-collapse: collapse`，但它也需要考虑非折叠情况下的表格边框。
    * **`border-collapse: collapse` (合并边框模型):**  这是此文件重点处理的情况。它实现了 W3C CSS 表格规范中定义的边框冲突解决规则，以确定共享边框的最终样式和宽度。
3. **存储和管理边框信息:**  它使用 `TableBorders` 类来存储计算出的边框信息，例如每个边框的样式、宽度、颜色以及其来源（表格、行、列、单元格）。
4. **提供访问边框信息的接口:**  其他布局模块可以查询 `TableBorders` 对象来获取特定单元格或表格边缘的最终边框样式和宽度。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件与 HTML 和 CSS 的关系非常密切，而与 JavaScript 的关系是间接的。

* **HTML:**
    * **功能关系:**  `table_borders.cc` 处理的是 HTML `<table>`, `<tr>`, `<th>`, `<td>`, `<colgroup>`, `<col>` 等元素生成的布局对象（LayoutObject）的边框。
    * **举例说明:** 当浏览器解析到以下 HTML 代码时，`table_borders.cc` 会被调用来计算表格的边框。

      ```html
      <table>
        <tr>
          <td>Cell 1</td>
          <td>Cell 2</td>
        </tr>
        <tr>
          <td>Cell 3</td>
          <td>Cell 4</td>
        </tr>
      </table>
      ```

* **CSS:**
    * **功能关系:**  `table_borders.cc` 的核心功能是解析和应用与表格边框相关的 CSS 属性，例如：
        * `border-top`, `border-right`, `border-bottom`, `border-left`: 设置单个边框的样式、宽度和颜色。
        * `border`:  简写属性，设置所有边框。
        * `border-collapse`:  决定边框是否合并。
        * `border-spacing`:  用于分隔边框模型，虽然此文件重点在合并边框。
    * **举例说明:**  考虑以下 CSS 样式：

      ```css
      table {
        border-collapse: collapse;
        border: 2px solid black;
      }
      td {
        border: 1px solid red;
      }
      ```

      当应用到上面的 HTML 时，`table_borders.cc` 会计算出合并后的边框，根据冲突解决规则，表格边框（黑色 2px）会覆盖单元格边框（红色 1px）。

* **JavaScript:**
    * **功能关系:**  JavaScript 自身不直接参与表格边框的计算。但是，JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会触发浏览器的重新布局和渲染过程，从而间接地影响 `table_borders.cc` 的执行。
    * **举例说明:**  以下 JavaScript 代码会修改表格的边框样式，导致浏览器重新计算边框：

      ```javascript
      const table = document.querySelector('table');
      table.style.border = '3px dashed blue';
      ```

**逻辑推理 (假设输入与输出):**

假设我们有一个简单的表格和一些 CSS 样式：

**假设输入:**

* **HTML:**
  ```html
  <table>
    <tr>
      <td style="border: 1px solid red;">Cell A</td>
      <td style="border: 2px dotted green;">Cell B</td>
    </tr>
  </table>
  ```
* **CSS:**
  ```css
  table {
    border-collapse: collapse;
    border: 3px solid blue;
  }
  ```

**逻辑推理过程:**

1. **读取 CSS 属性:** `table_borders.cc` 会读取表格和单元格的 `border-collapse` 和 `border` 属性。
2. **应用 `border-collapse: collapse`:** 由于表格设置了 `border-collapse: collapse`，因此会使用合并边框模型。
3. **处理边框冲突:**  对于单元格之间的共享边框：
    * 表格的边框样式是 `3px solid blue`。
    * Cell A 的右边框样式是 `1px solid red`。
    * Cell B 的左边框样式是 `2px dotted green`。
    * 根据 CSS 边框冲突解决规则（宽度大的优先，宽度相同时，`solid > dashed > dotted`），表格的边框样式会胜出。
4. **计算最终边框:**  表格的所有边框都会是 `3px solid blue`。

**假设输出 (TableBorders 对象中存储的边框信息 - 简化表示):**

* 表格顶部边框: 样式: `solid`, 宽度: `3px`, 颜色: `blue`, 来源: `table`
* 表格底部边框: 样式: `solid`, 宽度: `3px`, 颜色: `blue`, 来源: `table`
* 表格左侧边框: 样式: `solid`, 宽度: `3px`, 颜色: `blue`, 来源: `table`
* 表格右侧边框: 样式: `solid`, 宽度: `3px`, 颜色: `blue`, 来源: `table`
* 单元格 A 右侧/单元格 B 左侧共享边框: 样式: `solid`, 宽度: `3px`, 颜色: `blue`, 来源: `table`

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **误解 `border-collapse` 的作用:** 用户可能会认为在 `border-collapse: collapse` 的情况下，所有单元格的边框都会显示出来。但实际上，会根据冲突解决规则选择一个边框。

   ```html
   <table style="border-collapse: collapse;">
     <tr>
       <td style="border: 1px solid red;">Cell 1</td>
       <td style="border: 2px dashed blue;">Cell 2</td>
     </tr>
   </table>
   ```

   用户可能期望看到红色和蓝色的边框，但实际看到的可能是蓝色边框（因为 dashed 比 solid 的优先级低）。

2. **忘记设置表格的边框:**  在 `border-collapse: collapse` 的情况下，如果表格自身没有设置边框，那么单元格的边框可能不会显示出来。

   ```html
   <table style="border-collapse: collapse;">
     <tr>
       <td style="border: 1px solid red;">Cell 1</td>
     </tr>
   </table>
   ```

   用户可能会疑惑为什么单元格有边框样式却没有显示。

3. **在 JavaScript 中动态修改样式时出现意外结果:**  如果 JavaScript 代码不小心移除了表格的 `border-collapse: collapse` 样式，那么边框的渲染方式会突然改变，可能会导致布局错乱。

   ```javascript
   const table = document.querySelector('table');
   // 错误地移除了 border-collapse 属性
   table.style.borderCollapse = '';
   ```

4. **编程错误 -  对 `TableBorders` 对象的使用不当:**  开发者如果错误地使用 `TableBorders` 提供的接口，例如传递错误的行号或列号，可能会导致程序崩溃或返回错误的边框信息。 虽然这个文件本身不太会直接被外部调用，但其内部的逻辑如果出错，会导致布局错误。

**总结:**

`table_borders.cc` 是 Chromium Blink 引擎中负责处理 HTML 表格边框计算的核心组件，尤其专注于 `border-collapse: collapse` 模型的实现。它深入理解 CSS 边框属性和冲突解决规则，并为布局模块提供准确的边框信息，确保网页表格的正确渲染。理解其功能有助于我们更好地理解浏览器如何处理表格边框，并避免在使用 HTML、CSS 和 JavaScript 创建表格时出现常见的错误。

### 提示词
```
这是目录为blink/renderer/core/layout/table/table_borders.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/table/table_borders.h"

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column_visitor.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_algorithm_types.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

// https://www.w3.org/TR/css-tables-3/#conflict-resolution-for-collapsed-borders
bool IsSourceMoreSpecificThanEdge(EBorderStyle source_style,
                                  LayoutUnit source_width,
                                  const TableBorders::Edge& edge) {
  if (edge.edge_side == TableBorders::EdgeSide::kDoNotFill) {
    return false;
  }

  if (!edge.style || source_style == EBorderStyle::kHidden)
    return true;

  EBorderStyle edge_border_style =
      TableBorders::BorderStyle(edge.style.Get(), edge.edge_side);
  if (edge_border_style == EBorderStyle::kHidden)
    return false;

  LayoutUnit edge_width =
      TableBorders::BorderWidth(edge.style.Get(), edge.edge_side);
  if (source_width < edge_width)
    return false;
  if (source_width > edge_width)
    return true;
  return source_style > edge_border_style;
}

class ColBordersMarker {
  STACK_ALLOCATED();

 public:
  void VisitCol(const LayoutInputNode& column,
                wtf_size_t start_column_index,
                wtf_size_t span) {
    for (wtf_size_t i = 0; i < span; ++i) {
      wtf_size_t current_column_index = start_column_index + i;
      borders.MergeBorders(0, current_column_index, table_row_count, 1,
                           column.Style(), TableBorders::EdgeSource::kColumn,
                           box_order, table_writing_direction);
    }
  }
  void EnterColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index) {}
  void LeaveColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index,
                     wtf_size_t span,
                     bool has_children) {}
  ColBordersMarker(wtf_size_t table_row_count,
                   wtf_size_t box_order,
                   WritingDirectionMode table_writing_direction,
                   TableBorders& borders)
      : table_row_count(table_row_count),
        box_order(box_order),
        table_writing_direction(table_writing_direction),
        borders(borders) {}
  const wtf_size_t table_row_count;
  const wtf_size_t box_order;
  const WritingDirectionMode table_writing_direction;
  TableBorders& borders;
};

class ColgroupBordersMarker {
  STACK_ALLOCATED();

 public:
  void VisitCol(const LayoutInputNode& column,
                wtf_size_t start_column_index,
                wtf_size_t span) {}
  void EnterColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index) {}
  void LeaveColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index,
                     wtf_size_t span,
                     bool has_children) {
    borders.MergeBorders(0, start_column_index, table_row_count, span,
                         colgroup.Style(), TableBorders::EdgeSource::kColumn,
                         box_order, table_writing_direction);
  }
  ColgroupBordersMarker(wtf_size_t table_row_count,
                        wtf_size_t box_order,
                        WritingDirectionMode table_writing_direction,
                        TableBorders& borders)
      : table_row_count(table_row_count),
        box_order(box_order),
        table_writing_direction(table_writing_direction),
        borders(borders) {}
  const wtf_size_t table_row_count;
  const wtf_size_t box_order;
  const WritingDirectionMode table_writing_direction;
  TableBorders& borders;
};

}  // namespace

const TableBorders* TableBorders::ComputeTableBorders(const BlockNode& table) {
  const ComputedStyle& table_style = table.Style();
  const bool is_collapsed =
      table_style.BorderCollapse() == EBorderCollapse::kCollapse;
  TableBorders* table_borders = MakeGarbageCollected<TableBorders>(
      ComputeNonCollapsedTableBorders(table_style), is_collapsed);

  if (!is_collapsed)
    return table_borders;

  TableGroupedChildren grouped_children(table);
  WritingDirectionMode table_writing_direction =
      table.Style().GetWritingDirection();

  wtf_size_t box_order = 0;
  wtf_size_t table_column_count = ComputeMaximumNonMergeableColumnCount(
      grouped_children.columns, table.Style().IsFixedTableLayout());
  wtf_size_t table_row_index = 0;
  // Mark cell borders.
  bool found_multispan_cells = false;
  for (const BlockNode section : grouped_children) {
    wtf_size_t section_start_row = table_row_index;
    ColspanCellTabulator tabulator;
    for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
         row = To<BlockNode>(row.NextSibling())) {
      tabulator.StartRow();
      for (BlockNode cell = To<BlockNode>(row.FirstChild()); cell;
           cell = To<BlockNode>(cell.NextSibling())) {
        tabulator.FindNextFreeColumn();
        wtf_size_t cell_colspan = cell.TableCellColspan();
        found_multispan_cells |=
            cell.TableCellRowspan() > 1 || cell_colspan > 1;
        // Rowspan has to be limited by section size. Since we do not know
        // section size, we have to rerun cell distribution with limited
        // rowspans.
        table_column_count =
            std::max(table_column_count,
                     ComputeMaxColumn(tabulator.CurrentColumn(), cell_colspan,
                                      table.Style().IsFixedTableLayout()));
        if (!found_multispan_cells) {
          table_borders->MergeBorders(
              table_row_index, tabulator.CurrentColumn(),
              cell.TableCellRowspan(), cell_colspan, cell.Style(),
              TableBorders::EdgeSource::kCell, ++box_order,
              table_writing_direction);
        }
        tabulator.ProcessCell(cell);
      }
      tabulator.EndRow();
      ++table_row_index;
    }
    table_borders->AddSection(section_start_row,
                              table_row_index - section_start_row);
  }

  table_borders->SetLastColumnIndex(table_column_count);
  wtf_size_t table_row_count = table_row_index;
  table_row_index = 0;

  // Mark cell borders again with limited rowspan.
  // If any cells have rowspan, need to redistribute cell borders.
  if (found_multispan_cells) {
    wtf_size_t section_index = 0;
    for (BlockNode section : grouped_children) {
      ColspanCellTabulator tabulator;
      for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
           row = To<BlockNode>(row.NextSibling())) {
        tabulator.StartRow();
        for (BlockNode cell = To<BlockNode>(row.FirstChild()); cell;
             cell = To<BlockNode>(cell.NextSibling())) {
          tabulator.FindNextFreeColumn();
          table_borders->MergeBorders(
              table_row_index, tabulator.CurrentColumn(),
              cell.TableCellRowspan(), cell.TableCellColspan(), cell.Style(),
              TableBorders::EdgeSource::kCell, ++box_order,
              table_writing_direction, section_index);
          tabulator.ProcessCell(cell);
        }
        tabulator.EndRow();
        ++table_row_index;
      }
      ++section_index;
    }
  }

  // Mark row borders.
  table_row_index = 0;
  for (BlockNode section : grouped_children) {
    for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
         row = To<BlockNode>(row.NextSibling())) {
      table_borders->MergeBorders(table_row_index, 0, 1, table_column_count,
                                  row.Style(), TableBorders::EdgeSource::kRow,
                                  ++box_order, table_writing_direction);
      ++table_row_index;
    }
  }

  // Mark section borders.
  // It is tempting to traverse sections at the same time as rows,
  // but it would cause precedence errors.
  wtf_size_t section_index = 0;
  for (BlockNode section : grouped_children) {
    TableBorders::Section section_info =
        table_borders->GetSection(section_index);
    table_borders->MergeBorders(
        section_info.start_row, 0, section_info.row_count, table_column_count,
        section.Style(), TableBorders::EdgeSource::kSection, ++box_order,
        table_writing_direction);
    ++section_index;
  }

  // Mark column borders.
  // COL borders have precedence over COLGROUP borders.
  // We have to traverse COL first, then COLGROUP.
  ColBordersMarker col_borders_marker(table_row_count, ++box_order,
                                      table_writing_direction, *table_borders);
  VisitLayoutTableColumn(
      const_cast<HeapVector<BlockNode>&>(grouped_children.columns),
      table_column_count, &col_borders_marker);
  ColgroupBordersMarker colgroup_borders_marker(
      table_row_count, ++box_order, table_writing_direction, *table_borders);
  VisitLayoutTableColumn(
      const_cast<HeapVector<BlockNode>&>(grouped_children.columns),
      table_column_count, &colgroup_borders_marker);

  // Mark table borders.
  table_borders->MergeBorders(0, 0, table_row_count, table_column_count,
                              table_style, TableBorders::EdgeSource::kTable,
                              ++box_order, table_writing_direction);

  table_borders->UpdateTableBorder(table_row_count, table_column_count);

  return table_borders;
}

TableBorders::TableBorders(const BoxStrut& table_border,
                           const bool is_collapsed)
    : table_border_(table_border), is_collapsed_(is_collapsed) {}

Color TableBorders::BorderColor(const ComputedStyle* style,
                                EdgeSide edge_side) {
  switch (edge_side) {
    case EdgeSide::kLeft:
      return style->VisitedDependentColor(GetCSSPropertyBorderLeftColor());
    case EdgeSide::kRight:
      return style->VisitedDependentColor(GetCSSPropertyBorderRightColor());
    case EdgeSide::kTop:
      return style->VisitedDependentColor(GetCSSPropertyBorderTopColor());
    case EdgeSide::kBottom:
      return style->VisitedDependentColor(GetCSSPropertyBorderBottomColor());
    case EdgeSide::kDoNotFill:
      NOTREACHED();
  }
}

#if DCHECK_IS_ON()
String TableBorders::DumpEdges() {
  if (edges_per_row_ == 0)
    return "No edges";

  StringBuilder edge_string;
  wtf_size_t row_count = edges_.size() / edges_per_row_;
  for (wtf_size_t row = 0; row < row_count; ++row) {
    for (wtf_size_t i = 0; i < edges_per_row_; ++i) {
      const auto& edge = edges_[edges_per_row_ * row + i];
      if (edge.style) {
        switch (edge.edge_side) {
          case EdgeSide::kTop:
            edge_string.Append('-');
            break;
          case EdgeSide::kBottom:
            edge_string.Append('_');
            break;
          case EdgeSide::kLeft:
            edge_string.Append('[');
            break;
          case EdgeSide::kRight:
            edge_string.Append(']');
            break;
          case EdgeSide::kDoNotFill:
            edge_string.Append('?');
            break;
        }
      } else {  // no style.
        if (edge.edge_side == EdgeSide::kDoNotFill)
          edge_string.Append('X');
        else
          edge_string.Append('.');
      }
      if (i & 1)  // i is odd.
        edge_string.Append(' ');
    }
    edge_string.Append('\n');
  }
  return edge_string.ToString();
}

void TableBorders::ShowEdges() {
  LOG(INFO) << "\n" << DumpEdges().Utf8();
}

bool TableBorders::operator==(const TableBorders& other) const {
  // Compare by traversal, because we must call edge comparison function.
  if (edges_.size() != other.edges_.size())
    return false;
  for (unsigned i = 0; i < edges_.size(); i++) {
    if (edges_[i].edge_side != other.edges_[i].edge_side)
      return false;
    if (edges_[i].box_order != other.edges_[i].box_order)
      return false;
  }
  return sections_ == other.sections_ &&
         edges_per_row_ == other.edges_per_row_ &&
         table_border_ == other.table_border_ &&
         last_column_index_ == other.last_column_index_ &&
         is_collapsed_ == other.is_collapsed_;
}

#endif

BoxStrut TableBorders::GetCellBorders(wtf_size_t row,
                                      wtf_size_t column,
                                      wtf_size_t rowspan,
                                      wtf_size_t colspan) const {
  BoxStrut border_strut;
  if (edges_per_row_ == 0)
    return border_strut;
  DCHECK_EQ(edges_.size() % edges_per_row_, 0u);
  if (column * 2 >= edges_per_row_ || row >= edges_.size() / edges_per_row_)
    return border_strut;

  // Compute inline border widths.
  wtf_size_t first_inline_start_edge = row * edges_per_row_ + column * 2;
  wtf_size_t first_inline_end_edge = first_inline_start_edge + colspan * 2;
  for (wtf_size_t i = 0; i < rowspan; ++i) {
    wtf_size_t start_edge_index = first_inline_start_edge + i * edges_per_row_;
    border_strut.inline_start =
        std::max(border_strut.inline_start, CanPaint(start_edge_index)
                                                ? BorderWidth(start_edge_index)
                                                : LayoutUnit());
    if (start_edge_index >= edges_.size())
      break;
    wtf_size_t end_edge_index = first_inline_end_edge + i * edges_per_row_;
    border_strut.inline_end = std::max(
        border_strut.inline_end,
        CanPaint(end_edge_index) ? BorderWidth(end_edge_index) : LayoutUnit());
  }
  // Compute block border widths.
  wtf_size_t start_edge_column_index = column * 2 + 1;
  for (wtf_size_t i = 0; i < colspan; ++i) {
    wtf_size_t current_column_index = start_edge_column_index + i * 2;
    if (current_column_index >= edges_per_row_)
      break;
    wtf_size_t start_edge_index = row * edges_per_row_ + current_column_index;
    border_strut.block_start =
        std::max(border_strut.block_start, CanPaint(start_edge_index)
                                               ? BorderWidth(start_edge_index)
                                               : LayoutUnit());
    wtf_size_t end_edge_index = start_edge_index + rowspan * edges_per_row_;
    border_strut.block_end = std::max(
        border_strut.block_end,
        CanPaint(end_edge_index) ? BorderWidth(end_edge_index) : LayoutUnit());
  }
  DCHECK(is_collapsed_);
  // If borders are not divisible by 2, two half borders will not add up
  // to original border size (off by 1/64px). This is ok, because
  // pixel snapping will round to physical pixels.
  border_strut.block_start /= 2;
  border_strut.block_end /= 2;
  border_strut.inline_start /= 2;
  border_strut.inline_end /= 2;
  return border_strut;
}

void TableBorders::UpdateTableBorder(wtf_size_t table_row_count,
                                     wtf_size_t table_column_count) {
  DCHECK(is_collapsed_);
  if (edges_per_row_ == 0) {
    table_border_ = BoxStrut();
    return;
  }
  DCHECK_GE((table_column_count + 1) * 2, edges_per_row_);
  table_border_ = GetCellBorders(0, 0, table_row_count, table_column_count);
}

BoxStrut TableBorders::CellBorder(
    const BlockNode& cell,
    wtf_size_t row,
    wtf_size_t column,
    wtf_size_t section,
    WritingDirectionMode table_writing_direction) const {
  if (is_collapsed_) {
    return GetCellBorders(row, column,
                          ClampRowspan(section, row, cell.TableCellRowspan()),
                          ClampColspan(column, cell.TableCellColspan()));
  }
  return ComputeBorders(
      ConstraintSpaceBuilder(table_writing_direction.GetWritingMode(),
                             table_writing_direction, /* is_new_fc */ false)
          .ToConstraintSpace(),
      cell);
}

// As we are determining the intrinsic size of the table at this stage,
// %-padding resolves against an indefinite size.
BoxStrut TableBorders::CellPaddingForMeasure(
    const ComputedStyle& cell_style,
    WritingDirectionMode table_writing_direction) const {
  if (!cell_style.MayHavePadding())
    return BoxStrut();
  return ComputePadding(
      ConstraintSpaceBuilder(table_writing_direction.GetWritingMode(),
                             table_writing_direction,
                             /* is_new_fc */ false)
          .ToConstraintSpace(),
      cell_style);
}

void TableBorders::MergeBorders(wtf_size_t cell_start_row,
                                wtf_size_t cell_start_column,
                                wtf_size_t rowspan,
                                wtf_size_t colspan,
                                const ComputedStyle& source_style,
                                EdgeSource source,
                                const wtf_size_t box_order,
                                WritingDirectionMode table_writing_direction,
                                wtf_size_t section_index) {
  DCHECK(is_collapsed_);
  // Can be 0 in empty table parts.
  if (rowspan == 0 || colspan == 0)
    return;

  wtf_size_t clamped_colspan = ClampColspan(cell_start_column, colspan);
  wtf_size_t clamped_rowspan =
      source == EdgeSource::kCell
          ? ClampRowspan(section_index, cell_start_row, rowspan)
          : rowspan;
  bool mark_inner_borders = source == EdgeSource::kCell &&
                            (clamped_rowspan > 1 || clamped_colspan > 1);

  if (mark_inner_borders) {
    EnsureCellColumnFits(cell_start_column + clamped_colspan - 1);
    EnsureCellRowFits(cell_start_row + clamped_rowspan - 1);
  } else {
    PhysicalToLogical<EBorderStyle> border_style(
        table_writing_direction, source_style.BorderTopStyle(),
        source_style.BorderRightStyle(), source_style.BorderBottomStyle(),
        source_style.BorderLeftStyle());
    if (border_style.InlineStart() == EBorderStyle::kNone &&
        border_style.InlineEnd() == EBorderStyle::kNone &&
        border_style.BlockStart() == EBorderStyle::kNone &&
        border_style.BlockEnd() == EBorderStyle::kNone) {
      return;
    }
    // Only need to ensure edges that will be assigned exist.
    if (border_style.InlineEnd() == EBorderStyle::kNone &&
        border_style.BlockStart() == EBorderStyle::kNone &&
        border_style.BlockEnd() == EBorderStyle::kNone) {
      EnsureCellColumnFits(cell_start_column);
    } else {
      EnsureCellColumnFits(cell_start_column + clamped_colspan - 1);
    }
    if (border_style.InlineStart() == EBorderStyle::kNone &&
        border_style.InlineEnd() == EBorderStyle::kNone &&
        border_style.BlockEnd() == EBorderStyle::kNone) {
      EnsureCellRowFits(cell_start_row);
    } else {
      EnsureCellRowFits(cell_start_row + clamped_rowspan - 1);
    }
  }

  PhysicalToLogical<EdgeSide> edge_side(table_writing_direction, EdgeSide::kTop,
                                        EdgeSide::kRight, EdgeSide::kBottom,
                                        EdgeSide::kLeft);
  MergeRowAxisBorder(cell_start_row, cell_start_column, clamped_colspan,
                     source_style, box_order, edge_side.BlockStart());
  MergeRowAxisBorder(cell_start_row + clamped_rowspan, cell_start_column,
                     clamped_colspan, source_style, box_order,
                     edge_side.BlockEnd());
  MergeColumnAxisBorder(cell_start_row, cell_start_column, clamped_rowspan,
                        source_style, box_order, edge_side.InlineStart());
  MergeColumnAxisBorder(cell_start_row, cell_start_column + clamped_colspan,
                        clamped_rowspan, source_style, box_order,
                        edge_side.InlineEnd());
  if (mark_inner_borders) {
    MarkInnerBordersAsDoNotFill(cell_start_row, cell_start_column,
                                clamped_rowspan, clamped_colspan);
  }
}

void TableBorders::MergeRowAxisBorder(wtf_size_t start_row,
                                      wtf_size_t start_column,
                                      wtf_size_t colspan,
                                      const ComputedStyle& source_style,
                                      const wtf_size_t box_order,
                                      EdgeSide physical_side) {
  EBorderStyle source_border_style = BorderStyle(&source_style, physical_side);
  if (source_border_style == EBorderStyle::kNone)
    return;
  LayoutUnit source_border_width = BorderWidth(&source_style, physical_side);
  wtf_size_t start_edge = edges_per_row_ * start_row + start_column * 2 + 1;
  wtf_size_t end_edge = start_edge + colspan * 2;
  for (wtf_size_t current_edge = start_edge; current_edge < end_edge;
       current_edge += 2) {
    // https://www.w3.org/TR/css-tables-3/#border-specificity
    if (IsSourceMoreSpecificThanEdge(source_border_style, source_border_width,
                                     edges_[current_edge])) {
      edges_[current_edge].style = &source_style;
      edges_[current_edge].edge_side = physical_side;
      edges_[current_edge].box_order = box_order;
    }
  }
}

void TableBorders::MergeColumnAxisBorder(wtf_size_t start_row,
                                         wtf_size_t start_column,
                                         wtf_size_t rowspan,
                                         const ComputedStyle& source_style,
                                         const wtf_size_t box_order,
                                         EdgeSide physical_side) {
  EBorderStyle source_border_style = BorderStyle(&source_style, physical_side);
  if (source_border_style == EBorderStyle::kNone)
    return;
  LayoutUnit source_border_width = BorderWidth(&source_style, physical_side);
  wtf_size_t start_edge = edges_per_row_ * start_row + start_column * 2;
  wtf_size_t end_edge = start_edge + (rowspan * edges_per_row_);
  for (wtf_size_t current_edge = start_edge; current_edge < end_edge;
       current_edge += edges_per_row_) {
    // https://www.w3.org/TR/css-tables-3/#border-specificity
    if (IsSourceMoreSpecificThanEdge(source_border_style, source_border_width,
                                     edges_[current_edge])) {
      edges_[current_edge].style = &source_style;
      edges_[current_edge].edge_side = physical_side;
      edges_[current_edge].box_order = box_order;
    }
  }
}

// Rowspanned/colspanned cells need to mark inner edges as do-not-fill to
// prevent tables parts from drawing into them.
void TableBorders::MarkInnerBordersAsDoNotFill(wtf_size_t start_row,
                                               wtf_size_t start_column,
                                               wtf_size_t rowspan,
                                               wtf_size_t colspan) {
  // Mark block axis edges.
  wtf_size_t start_edge = (start_column * 2) + 2;
  wtf_size_t end_edge = start_edge + (colspan - 1) * 2;
  for (wtf_size_t row = start_row;
       row < start_row + rowspan && start_edge != end_edge; ++row) {
    wtf_size_t row_offset = row * edges_per_row_;
    for (wtf_size_t edge = row_offset + start_edge;
         edge < row_offset + end_edge; edge += 2) {
      // DCHECK(!edges_[edge].style) is true in most tables. But,
      // when two cells overlap each other, (really an error)
      // style might already be assigned.
      if (!edges_[edge].style)
        edges_[edge].edge_side = EdgeSide::kDoNotFill;
    }
  }
  // Mark inline axis edges.
  start_edge = start_column * 2 + 1;
  end_edge = start_edge + colspan * 2;
  for (wtf_size_t row = start_row + 1; row < start_row + rowspan; ++row) {
    wtf_size_t row_offset = row * edges_per_row_;
    for (wtf_size_t edge = row_offset + start_edge;
         edge < row_offset + end_edge; edge += 2) {
      if (!edges_[edge].style)
        edges_[edge].edge_side = EdgeSide::kDoNotFill;
    }
  }
}

// Inline edges are edges between columns.
void TableBorders::EnsureCellColumnFits(wtf_size_t cell_column) {
  wtf_size_t desired_edges_per_row = (cell_column + 2) * 2;
  if (desired_edges_per_row <= edges_per_row_)
    return;

  // When number of columns changes, all rows have to be resized.
  // Edges must be copied to new positions. This can be expensive.
  // Most tables do not change number of columns after the 1st row.
  wtf_size_t row_count =
      edges_per_row_ == 0 ? 1 : edges_.size() / edges_per_row_;
  edges_.resize(row_count * desired_edges_per_row);
  for (wtf_size_t row_index = row_count - 1; row_index > 0; --row_index) {
    wtf_size_t new_edge = desired_edges_per_row - 1;
    bool done = false;
    // while loop is necessary to count down with unsigned.
    do {
      wtf_size_t new_edge_index = row_index * desired_edges_per_row + new_edge;
      if (new_edge < edges_per_row_) {
        wtf_size_t old_edge_index = row_index * edges_per_row_ + new_edge;
        DCHECK_LT(row_index * edges_per_row_ + new_edge, edges_.size());
        edges_[new_edge_index] = edges_[old_edge_index];
      } else {
        edges_[new_edge_index].style = nullptr;
        edges_[new_edge_index].edge_side = EdgeSide::kTop;
      }
      done = new_edge-- == 0;
    } while (!done);
  }
  // Previous loop does not clear out new cells in the first row.
  for (wtf_size_t edge_index = edges_per_row_;
       edge_index < desired_edges_per_row; ++edge_index) {
    edges_[edge_index].style = nullptr;
    edges_[edge_index].edge_side = EdgeSide::kTop;
  }
  edges_per_row_ = desired_edges_per_row;
}

// Block edges are edges between rows.
void TableBorders::EnsureCellRowFits(wtf_size_t cell_row) {
  DCHECK_NE(edges_per_row_, 0u);
  wtf_size_t current_block_edges = edges_.size() / edges_per_row_;
  wtf_size_t desired_block_edges = cell_row + 2;
  if (desired_block_edges <= current_block_edges)
    return;
  edges_.resize(desired_block_edges * edges_per_row_);
}

}  // namespace blink
```