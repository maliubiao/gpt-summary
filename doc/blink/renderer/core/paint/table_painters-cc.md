Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes through several stages:

1. **Understanding the Goal:** The user wants to understand the functionality of the `table_painters.cc` file in the Chromium Blink rendering engine. Specifically, they are interested in its relationship to HTML, CSS, and JavaScript, potential logic, common errors, and how a user's actions might lead to this code being executed. The request explicitly asks for a breakdown of the file's functions and a summary of its overall purpose.

2. **Initial Code Scan and Keyword Identification:** I begin by quickly scanning the code, looking for key terms and structures. I notice:
    *  Includes related to layout (`layout_box.h`, `layout_table.h`, etc.)
    *  Includes related to painting (`box_painter.h`, `paint_info.h`, `graphics_context.h`, etc.)
    *  The namespace `blink`
    *  Class names like `TablePainter`, `TableSectionPainter`, `TableRowPainter`, `TableCellPainter`, `TableCollapsedEdge`.
    *  Functions with names like `PaintBoxDecorationBackground`, `PaintCollapsedBorders`.
    *  The concept of "fragmentation."
    *  The `TableBorders` class.

3. **Inferring Core Functionality from Names and Includes:** Based on the keywords and includes, I can infer that this file is responsible for *painting* various parts of an HTML table. The "painters" suffix in the class names strongly suggests this. The layout-related includes indicate that the painting process relies on the computed layout of the table elements. The presence of `GraphicsContext` means this code interacts directly with the graphics system to draw things on the screen.

4. **Analyzing Key Classes and Functions:** I then delve deeper into the key classes and functions:
    * **`TableCollapsedEdge`:** This class appears to represent and manage the borders of table cells when the `border-collapse: collapse` CSS property is used. The logic within it, like `CompareForPaint`, suggests it handles resolving conflicts between adjacent borders.
    * **`ComputeEdgeJoints`:** This function likely calculates how the corners of collapsed borders should be drawn, considering different border styles and widths.
    * **`ComputeColumnsRect`:**  This seems to determine the rectangular area occupied by table columns, likely used for painting column backgrounds.
    * **`TablePainter::PaintBoxDecorationBackground`:** This handles painting the background of the table itself, including column backgrounds.
    * **`TablePainter::PaintCollapsedBorders`:**  This is the core function for drawing the collapsed borders, iterating through the edges and determining which ones to paint.
    * **The `PaintBoxDecorationBackground` functions in `TableSectionPainter`, `TableRowPainter`, and `TableCellPainter`:** These handle background painting for the respective table elements, with special considerations for collapsed borders and fragmentation.
    * **`TableCellBackgroundClipper`:** This class addresses a specific problem where painting cell backgrounds in certain scenarios can overlap collapsed borders, and it provides a mechanism to clip the background.

5. **Connecting to HTML, CSS, and JavaScript:**  I start linking the code's functionality to web technologies:
    * **HTML:** The code directly deals with the rendering of HTML table elements (`<table>`, `<tr>`, `<td>`, `<th>`, `<colgroup>`, `<col>`).
    * **CSS:**  The code respects various CSS properties related to tables, such as `border-collapse`, `border-style`, `border-width`, and background properties. The `BoxDecorationData` class hints at the handling of background images, colors, and gradients.
    * **JavaScript:** While this specific C++ file doesn't directly execute JavaScript, the *effects* of JavaScript manipulations on the DOM and CSS styles will eventually lead to this rendering code being executed. For example, JavaScript might dynamically add/remove table rows or change CSS classes affecting table appearance.

6. **Considering Logic and Assumptions:**  I look for logical operations and assumptions made in the code:
    * The code handles table border collapsing logic based on priorities and styles.
    * It accounts for table fragmentation, where a table might be split across multiple pages or regions.
    * The `ComputeEdgeJoints` function makes assumptions about the order of border precedence at intersections.

7. **Identifying Potential User Errors and Debugging:** I consider how user actions or incorrect code could lead to issues and how this code helps in debugging:
    * **User Errors:**  Incorrect or conflicting CSS rules for table borders can lead to unexpected rendering results, which this code aims to resolve according to CSS specifications.
    * **Debugging:**  The code includes debugging checks (e.g., `DCHECK`) that can help developers identify issues during the rendering process. Understanding the flow of execution through these painter classes is crucial for debugging table rendering problems.

8. **Tracing User Actions (Debugging Clues):** I think about a sequence of user actions that would eventually trigger this code:
    1. The user opens a web page containing an HTML table.
    2. The browser parses the HTML and CSS.
    3. The Blink layout engine calculates the positions and sizes of the table elements.
    4. The paint phase begins, and the `TablePainter`, `TableSectionPainter`, etc., are invoked to draw the table on the screen.

9. **Structuring the Answer:** Finally, I organize my findings into a clear and structured answer, addressing each part of the user's request:
    * **Functionality:**  Provide a high-level overview and then detail the responsibilities of the key classes and functions.
    * **Relationship to Web Technologies:** Give specific examples of how the code interacts with HTML, CSS, and JavaScript.
    * **Logic and Assumptions:** Explain any important logical operations or assumptions made in the code.
    * **User Errors:**  Illustrate potential user errors and how they relate to the code.
    * **Debugging Clues:**  Describe how a user's actions lead to the execution of this code, providing a debugging context.
    * **Summary:**  Provide a concise summary of the file's purpose.

By following these steps, I can effectively analyze the provided C++ code snippet and provide a comprehensive and informative answer to the user's request. The key is to combine code analysis with knowledge of web technologies and the overall rendering pipeline of a browser.
这是 `blink/renderer/core/paint/table_painters.cc` 文件的第一部分，主要负责实现 Chromium Blink 引擎中渲染 HTML 表格时与绘制相关的逻辑。它包含了用于绘制表格及其各个组成部分（如表格本身、表格行、表格单元格等）的类和函数。

以下是该部分代码功能的归纳：

**主要功能:**

1. **定义用于绘制表格元素的类:**  定义了 `TablePainter`，`TableSectionPainter`，`TableRowPainter` 和 `TableCellPainter` 这些类，每个类负责绘制表格的不同层级结构。

2. **处理表格边框的绘制 (特别是 `border-collapse: collapse`):**
   - 引入了 `TableCollapsedEdge` 类，用于表示和比较折叠边框的边缘，以决定哪个边框应该被绘制，以及如何绘制边框的交汇点。
   - 包含 `ComputeEdgeJoints` 函数，用于计算折叠边框交汇处的几何形状和绘制优先级。
   - `TablePainter::PaintCollapsedBorders` 函数实现了折叠边框的绘制逻辑，包括处理跨片段的情况。

3. **处理表格背景的绘制:**
   - `TablePainter::PaintBoxDecorationBackground` 函数负责绘制表格的背景，包括处理 `<colgroup>` 和 `<col>` 元素的背景。
   - `TableSectionPainter::PaintBoxDecorationBackground` 和 `TableRowPainter::PaintBoxDecorationBackground` 分别处理表格节（`<thead>`, `<tbody>`, `<tfoot>`）和表格行的背景绘制。
   - `TableCellPainter::PaintBackgroundForTablePart` 用于绘制属于表格特定部分的单元格背景（例如，属于 `<thead>` 的单元格背景）。
   - `TableCellBackgroundClipper` 类用于在某些情况下裁剪单元格背景，防止其覆盖折叠的边框。

4. **处理表格的片段 (Fragmentation):**  代码中多次提到 "fragmentation"，这指的是当表格内容太多，需要跨多个页面或区域显示时的情况。代码逻辑需要处理跨片段的边框和背景绘制，以确保正确渲染。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 这些类和函数直接负责渲染 HTML 中的表格元素：`<table>`, `<thead>`, `<tbody>`, `<tfoot>`, `<tr>`, `<th>`, `<td>`, `<colgroup>`, `<col>`. 例如，当浏览器遇到 `<table>` 标签时，会创建相应的布局对象，并在绘制阶段调用 `TablePainter` 及其相关类的函数来将其渲染到屏幕上。

* **CSS:**  代码的渲染逻辑会读取和应用 CSS 样式，例如：
    * `border-collapse`: `TableCollapsedEdge` 和 `PaintCollapsedBorders` 负责处理 `collapse` 值的情况。
    * `border-style`, `border-width`, `border-color`: `TableCollapsedEdge` 用于获取这些属性值来决定如何绘制边框。
    * `background-color`, `background-image`: `PaintBoxDecorationBackground` 函数会考虑这些属性来绘制背景。
    * CSS Fragmentation 属性（例如 `break-inside`，`break-after`）：代码中对表格片段的处理确保在分页或分列等情况下，边框和背景能正确绘制。

* **JavaScript:**  JavaScript 可以动态修改 HTML 结构和 CSS 样式。例如，JavaScript 可以动态添加或删除表格行，或者修改表格的 CSS 类。这些修改最终会触发浏览器的重新布局和重绘，从而调用到 `table_painters.cc` 中的代码来更新表格的渲染结果。

**逻辑推理及假设输入与输出:**

* **假设输入:** 一个 HTML 表格，其 CSS 样式设置了 `border-collapse: collapse`，并且相邻单元格设置了不同的边框样式和宽度。
* **逻辑推理:** `TableCollapsedEdge::CompareForPaint` 函数会被调用来比较相邻边框的属性，根据宽度、样式和出现的顺序（由 `BoxOrder` 决定）来判断哪个边框应该被绘制。`ComputeEdgeJoints` 会根据获胜的边框计算交汇处的绘制形状。
* **输出:** 屏幕上会显示一个合并后的边框，其样式和宽度由优先级最高的边框决定。交汇处的连接也会根据计算结果进行平滑处理。

**用户或编程常见的使用错误及举例说明:**

* **CSS 边框样式冲突:** 用户可能在相邻的单元格上设置了不兼容的边框样式（例如，一个设置为 `solid`，另一个设置为 `dashed`），并且期望浏览器能智能地合并它们。`TableCollapsedEdge` 的逻辑会按照 CSS 规范来解决这些冲突，但结果可能不是用户期望的（例如，优先级高的样式会覆盖其他样式）。
* **表格结构错误:**  虽然 `table_painters.cc` 主要关注渲染，但如果 HTML 表格结构不正确（例如，`<td>` 元素不在 `<tr>` 元素内），可能会导致布局和渲染出现问题，虽然这个文件本身不负责处理这些结构错误，但最终的渲染结果会受到影响。
* **JavaScript 动态修改样式导致意外渲染:**  JavaScript 代码可能在运行时修改表格的 CSS 样式，但由于对 CSS 优先级和层叠规则理解不足，可能导致表格渲染出现意外的效果。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个包含 HTML 表格的网页。**
2. **浏览器解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 样式，构建 CSSOM 树，并将 CSS 规则应用到 DOM 树，生成 Render 树 (或 Layout 树)。**  对于表格元素，会创建 `LayoutTable`, `LayoutTableRow`, `LayoutTableCell` 等布局对象。
4. **布局阶段计算每个元素的大小和位置。**  `LayoutTable` 及其相关类会计算表格的布局。
5. **进入绘制阶段。**  当需要绘制表格时，Blink 引擎会根据布局信息创建绘制记录。
6. **`TablePainter` 类被创建，并调用其 `Paint` 方法（虽然在这个代码片段中没有直接展示 `Paint` 方法，但这是其父类或相关机制的一部分）。**
7. **在 `TablePainter::Paint` 或其调用的函数中，会根据需要调用 `PaintBoxDecorationBackground` 来绘制背景。**
8. **如果表格设置了 `border-collapse: collapse`，则会调用 `PaintCollapsedBorders`，其中会用到 `TableCollapsedEdge` 和 `ComputeEdgeJoints` 来处理边框的绘制。**
9. **对于表格的每个部分（section, row, cell），会创建相应的 Painter 类 (`TableSectionPainter`, `TableRowPainter`, `TableCellPainter`)，并调用它们的 `PaintBoxDecorationBackground` 等方法进行绘制。**

**作为调试线索:** 如果开发者发现网页上的表格边框或背景渲染不正确，可以断点调试到 `table_painters.cc` 中的相关函数，查看边框属性的计算过程，或者背景绘制的区域是否正确。例如，可以检查 `TableCollapsedEdge::CompareForPaint` 的返回值，以了解边框冲突是如何解决的。

**归纳一下它的功能 (针对第 1 部分):**

这部分代码主要负责 Blink 引擎中 HTML 表格的**背景和折叠边框的绘制**。它定义了用于管理和绘制这些视觉元素的类和函数，并考虑了表格片段的情况。核心功能集中在处理 `border-collapse: collapse` 时的边框绘制逻辑，以及确保表格及其组成部分的背景能正确渲染。

### 提示词
```
这是目录为blink/renderer/core/paint/table_painters.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/table_painters.h"

#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_fragment_link.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column.h"
#include "third_party/blink/renderer/core/layout/table/table_borders.h"
#include "third_party/blink/renderer/core/paint/box_background_paint_context.h"
#include "third_party/blink/renderer/core/paint/box_border_painter.h"
#include "third_party/blink/renderer/core/paint/box_decoration_data.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/box_model_object_painter.h"
#include "third_party/blink/renderer/core/paint/box_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/scoped_paint_state.h"
#include "third_party/blink/renderer/core/paint/theme_painter.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"

namespace blink {

namespace {

// TableCollapsedEdge represents collapsed border edge for painting.
class TableCollapsedEdge {
  STACK_ALLOCATED();

 public:
  TableCollapsedEdge(const TableBorders& borders, wtf_size_t edge_index)
      : borders_(borders) {
    edge_index_ = edge_index < borders_.EdgeCount() ? edge_index : UINT_MAX;
    InitCachedProps();
  }
  TableCollapsedEdge(const TableCollapsedEdge& source, int offset)
      : borders_(source.borders_) {
    // If edge index would have been negative.
    if (offset < 0 &&
        source.edge_index_ < static_cast<wtf_size_t>(std::abs(offset))) {
      edge_index_ = UINT_MAX;
    } else {
      edge_index_ = source.edge_index_ + offset;
      if (edge_index_ >= borders_.EdgeCount())
        edge_index_ = UINT_MAX;
    }
    InitCachedProps();
  }

  TableCollapsedEdge(const TableCollapsedEdge& edge)
      : TableCollapsedEdge(edge, 0) {}

  TableCollapsedEdge& operator=(const TableCollapsedEdge& edge) {
    edge_index_ = edge.edge_index_;
    border_width_ = edge.border_width_;
    border_style_ = edge.border_style_;
    return *this;
  }

  bool Exists() const { return edge_index_ != UINT_MAX; }

  bool CanPaint() const {
    if (!Exists())
      return false;
    if (border_style_ == EBorderStyle::kNone ||
        border_style_ == EBorderStyle::kHidden)
      return false;
    if (border_width_ == 0)
      return false;
    return true;
  }

  EBorderStyle BorderStyle() const { return border_style_; }

  LayoutUnit BorderWidth() const { return border_width_; }

  Color BorderColor() const { return borders_.BorderColor(edge_index_); }

  int CompareBoxOrder(wtf_size_t other_edge_index) const {
    wtf_size_t box_order = borders_.BoxOrder(edge_index_);
    wtf_size_t other_box_order = borders_.BoxOrder(other_edge_index);
    if (box_order < other_box_order)
      return 1;
    if (box_order > other_box_order)
      return -1;
    return 0;
  }

  bool IsInlineAxis() const {
    DCHECK(Exists());
    DCHECK_NE(edge_index_, UINT_MAX);
    return edge_index_ % borders_.EdgesPerRow() % 2 != 0;
  }

  wtf_size_t TableColumn() const {
    DCHECK(Exists());
    return edge_index_ % borders_.EdgesPerRow() / 2;
  }

  wtf_size_t TableRow() const {
    DCHECK(Exists());
    return edge_index_ / borders_.EdgesPerRow();
  }

  // Which edge gets to paint the joint intersection?
  // Returns -1 if this edge wins, 1 if other edge wins, 0 if tie.
  static int CompareForPaint(const TableCollapsedEdge& lhs,
                             const TableCollapsedEdge& rhs) {
    if (lhs.edge_index_ == rhs.edge_index_)
      return 0;
    bool lhs_paints = lhs.CanPaint();
    bool rhs_paints = rhs.CanPaint();
    if (lhs_paints && rhs_paints) {
      // Compare widths.
      if (lhs.border_width_ > rhs.border_width_) {
        return 1;
      } else if (lhs.border_width_ < rhs.border_width_) {
        return -1;
      } else {  // Compare styles.
        // Paint border style comparison for paint has different
        // rules than for winning edge border (hidden does not win).
        if (lhs.border_style_ == rhs.border_style_)
          return lhs.CompareBoxOrder(rhs.edge_index_);
        if (rhs.border_style_ == EBorderStyle::kHidden)
          return 1;
        if (lhs.border_style_ == EBorderStyle::kHidden)
          return -1;
        if (lhs.border_style_ > rhs.border_style_)
          return 1;
        return -1;
      }
    }
    if (!lhs_paints && !rhs_paints)
      return 0;
    if (!lhs_paints)
      return -1;
    DCHECK(!rhs_paints);
    return 1;
  }

  // Returns logical neighbor edges around edge intersections.
  TableCollapsedEdge EdgeBeforeStartIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, -2);
    } else {
      return TableCollapsedEdge(*this, -1);
    }
  }
  TableCollapsedEdge EdgeAfterStartIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, 0);
    } else {
      return TableCollapsedEdge(*this, 1);
    }
  }
  TableCollapsedEdge EdgeOverStartIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, -(borders_.EdgesPerRow() + 1));
    } else {
      return TableCollapsedEdge(*this, -borders_.EdgesPerRow());
    }
  }
  TableCollapsedEdge EdgeUnderStartIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, -1);
    } else {
      return TableCollapsedEdge(*this, 0);
    }
  }
  TableCollapsedEdge EdgeBeforeEndIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, 0);
    } else {
      return TableCollapsedEdge(*this, borders_.EdgesPerRow() - 1);
    }
  }
  TableCollapsedEdge EdgeAfterEndIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, 2);
    } else {
      return TableCollapsedEdge(*this, borders_.EdgesPerRow() + 1);
    }
  }
  TableCollapsedEdge EdgeOverEndIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, -(borders_.EdgesPerRow() - 1));
    } else {
      return TableCollapsedEdge(*this, 0);
    }
  }
  TableCollapsedEdge EdgeUnderEndIntersection() const {
    if (IsInlineAxis()) {
      return TableCollapsedEdge(*this, 1);
    } else {
      return TableCollapsedEdge(*this, borders_.EdgesPerRow());
    }
  }
  TableCollapsedEdge EmptyEdge() const {
    return TableCollapsedEdge(borders_, UINT_MAX);
  }

  TableCollapsedEdge& operator++() {
    DCHECK_NE(edge_index_, UINT_MAX);
    if (++edge_index_ >= borders_.EdgeCount())
      edge_index_ = UINT_MAX;
    InitCachedProps();
    return *this;
  }
  bool operator==(const TableCollapsedEdge& rhs) const {
    return edge_index_ == rhs.edge_index_;
  }
  bool operator!=(const TableCollapsedEdge& rhs) const {
    return !(*this == rhs);
  }

 private:
  void InitCachedProps() {
    if (edge_index_ == UINT_MAX) {
      border_width_ = LayoutUnit();
      border_style_ = EBorderStyle::kNone;
    } else {
      border_width_ = borders_.BorderWidth(edge_index_);
      border_style_ = borders_.BorderStyle(edge_index_);
    }
  }

  const TableBorders& borders_;
  wtf_size_t edge_index_;  // UINT_MAX means end.
  // cache paint properties
  LayoutUnit border_width_;
  EBorderStyle border_style_;
};

// Computes a rectangle for start/end joint.
// start/end_wins is set to true if examined edge won.
// Examined edge should shrink/expand its size to fill the joints.
void ComputeEdgeJoints(const TableBorders& collapsed_borders,
                       const TableCollapsedEdge& edge,
                       bool is_over_edge_fragmentation_boundary,
                       bool is_under_edge_fragmentation_boundary,
                       LogicalSize& start_joint,
                       LogicalSize& end_joint,
                       bool& start_wins,
                       bool& end_wins) {
  // Interesting question:
  // Should multiple edges ever paint inside the same joint?
  // - if one edge clearly wins, it should occupy the entire joint.
  // - if edge equals another edge, we have a choice:
  //   a) both edges can win.
  //      If edges are transparent, multiple paint will be visible.
  //   b) pick winners by edge orders. This results in ugly staggered borders.
  //  I've picked a), which is how Legacy does it.

  // Border precedence around the joint. Highest priority is after, then
  // clockwise: after, under, before, over.
  start_wins = false;
  end_wins = false;
  // Find winner for the start of the inline edge.
  TableCollapsedEdge before_edge = edge.EdgeBeforeStartIntersection();
  TableCollapsedEdge after_edge = edge.EdgeAfterStartIntersection();
  TableCollapsedEdge over_edge = is_over_edge_fragmentation_boundary
                                     ? edge.EmptyEdge()
                                     : edge.EdgeOverStartIntersection();
  TableCollapsedEdge under_edge =
      is_under_edge_fragmentation_boundary && edge.IsInlineAxis()
          ? edge.EmptyEdge()
          : edge.EdgeUnderStartIntersection();

  int inline_compare =
      TableCollapsedEdge::CompareForPaint(before_edge, after_edge);
  start_joint.block_size = inline_compare == 1 ? before_edge.BorderWidth()
                                               : after_edge.BorderWidth();
  if (is_over_edge_fragmentation_boundary ||
      (is_under_edge_fragmentation_boundary && edge.IsInlineAxis())) {
    start_joint.block_size = LayoutUnit();
  }

  // Compare over and under edges.
  int block_compare =
      TableCollapsedEdge::CompareForPaint(over_edge, under_edge);
  start_joint.inline_size =
      block_compare == 1 ? over_edge.BorderWidth() : under_edge.BorderWidth();
  int inline_vs_block = TableCollapsedEdge::CompareForPaint(
      inline_compare == 1 ? before_edge : after_edge,
      block_compare == 1 ? over_edge : under_edge);

  if (edge.IsInlineAxis()) {
    if (inline_vs_block != -1 && inline_compare != 1)
      start_wins = true;
  } else {
    if (inline_vs_block != 1 && block_compare != 1)
      start_wins = true;
  }
  // Find the winner for the end joint of the inline edge.
  before_edge = edge.EdgeBeforeEndIntersection();
  after_edge = edge.EdgeAfterEndIntersection();
  over_edge = is_over_edge_fragmentation_boundary && edge.IsInlineAxis()
                  ? edge.EmptyEdge()
                  : edge.EdgeOverEndIntersection();
  under_edge = is_under_edge_fragmentation_boundary
                   ? edge.EmptyEdge()
                   : edge.EdgeUnderEndIntersection();

  inline_compare = TableCollapsedEdge::CompareForPaint(before_edge, after_edge);
  end_joint.block_size = inline_compare == 1 ? before_edge.BorderWidth()
                                             : after_edge.BorderWidth();
  if ((is_over_edge_fragmentation_boundary && edge.IsInlineAxis()) ||
      is_under_edge_fragmentation_boundary) {
    end_joint.block_size = LayoutUnit();
  }

  block_compare = TableCollapsedEdge::CompareForPaint(over_edge, under_edge);
  end_joint.inline_size =
      block_compare == 1 ? over_edge.BorderWidth() : under_edge.BorderWidth();
  inline_vs_block = TableCollapsedEdge::CompareForPaint(
      inline_compare == 1 ? before_edge : after_edge,
      block_compare == 1 ? over_edge : under_edge);

  if (edge.IsInlineAxis()) {
    if (inline_vs_block != -1 && inline_compare != -1)
      end_wins = true;
  } else {
    if (inline_vs_block != 1 && block_compare != -1)
      end_wins = true;
  }
}

// Computes the stitched columns-rect relative to the current fragment.
// The columns-rect is the union of all the sections in the table.
PhysicalRect ComputeColumnsRect(const PhysicalBoxFragment& fragment) {
  const auto writing_direction = fragment.Style().GetWritingDirection();
  LogicalRect columns_rect;
  LayoutUnit stitched_block_size;
  LayoutUnit fragment_block_offset;

  bool is_first_section = true;
  for (const PhysicalBoxFragment& walker :
       To<LayoutBox>(fragment.GetLayoutObject())->PhysicalFragments()) {
    if (&walker == &fragment)
      fragment_block_offset = stitched_block_size;

    WritingModeConverter converter(writing_direction, walker.Size());
    for (const auto& child : walker.Children()) {
      if (!child->IsTableSection()) {
        continue;
      }

      LogicalRect section_rect =
          converter.ToLogical({child.offset, child->Size()});
      section_rect.offset.block_offset += stitched_block_size;

      if (is_first_section) {
        columns_rect = section_rect;
        is_first_section = false;
      } else {
        columns_rect.UniteEvenIfEmpty(section_rect);
      }
    }

    stitched_block_size +=
        LogicalFragment(writing_direction, walker).BlockSize();
  }

  // Make the rect relative to the fragment we are currently painting.
  columns_rect.offset.block_offset -= fragment_block_offset;

  WritingModeConverter converter(writing_direction, fragment.Size());
  return converter.ToPhysical(columns_rect);
}

// When painting background in a cell (for the cell or its ancestor table part),
// if any ancestor table part has a layer and the table collapses borders, the
// background is painted after the collapsed borders. We need to clip the
// background to prevent it from covering the collapsed borders around the cell.
// TODO(crbug.com/1181813): Investigate other methods.
class TableCellBackgroundClipper {
  STACK_ALLOCATED();

 public:
  TableCellBackgroundClipper(
      GraphicsContext& context,
      const LayoutTableCell& table_cell,
      const PhysicalRect& cell_rect,
      bool is_painting_background_in_contents_space = false)
      : context_(context),
        needs_clip_(!is_painting_background_in_contents_space &&
                    (table_cell.HasLayer() || table_cell.Parent()->HasLayer() ||
                     table_cell.Parent()->Parent()->HasLayer()) &&
                    table_cell.Table()->HasCollapsedBorders()) {
    if (!needs_clip_)
      return;

    PhysicalRect clip_rect = cell_rect;
    clip_rect.Contract(table_cell.BorderOutsets());
    context.Save();
    context.Clip(ToPixelSnappedRect(clip_rect));
  }

  ~TableCellBackgroundClipper() {
    if (needs_clip_)
      context_.Restore();
  }

 private:
  GraphicsContext& context_;
  bool needs_clip_;
};

}  // namespace

bool TablePainter::WillCheckColumnBackgrounds() {
  return fragment_.TableColumnGeometries();
}

void TablePainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const BoxDecorationData& box_decoration_data) {
  WritingModeConverter converter(fragment_.Style().GetWritingDirection(),
                                 fragment_.Size());
  PhysicalRect grid_paint_rect =
      converter.ToPhysical(fragment_.TableGridRect());
  grid_paint_rect.offset += paint_rect.offset;

  // Paint the table background on the grid-rect.
  if (box_decoration_data.ShouldPaint()) {
    BoxFragmentPainter(fragment_).PaintBoxDecorationBackgroundWithRectImpl(
        paint_info, grid_paint_rect, box_decoration_data);
  }

  // Optimization: only traverse colgroups with backgrounds.
  const TableFragmentData::ColumnGeometries* column_geometries_original =
      fragment_.TableColumnGeometries();
  TableFragmentData::ColumnGeometries column_geometries_with_background;
  if (column_geometries_original) {
    for (const auto& column_geometry : *column_geometries_original) {
      if (column_geometry.node.Style().HasBoxDecorationBackground()) {
        column_geometries_with_background.push_back(column_geometry);
      }
    }
  }

  if (column_geometries_with_background.empty())
    return;

  // Paint <colgroup>/<col> backgrounds.
  PhysicalRect columns_paint_rect = ComputeColumnsRect(fragment_);
  columns_paint_rect.offset += paint_rect.offset;
  for (const PhysicalFragmentLink& child : fragment_.Children()) {
    if (!child.fragment->IsTableSection()) {
      continue;
    }
    TableSectionPainter(To<PhysicalBoxFragment>(*child.fragment))
        .PaintColumnsBackground(paint_info, paint_rect.offset + child.offset,
                                columns_paint_rect,
                                column_geometries_with_background);
  }
}

namespace {

const PhysicalFragment* StartSection(const PhysicalBoxFragment& table) {
  for (const auto& child : table.Children()) {
    if (!child->IsTableSection()) {
      continue;
    }
    return child.get();
  }
  return nullptr;
}

const PhysicalFragment* EndSection(const PhysicalBoxFragment& table) {
  const auto children = table.Children();
  for (auto it = children.rbegin(); it != children.rend(); ++it) {
    const auto& child = *it;
    if (!child->IsTableSection()) {
      continue;
    }
    return child.get();
  }
  return nullptr;
}

bool IsStartRowFragmented(const PhysicalBoxFragment& section) {
  for (const auto& child : section.Children()) {
    if (!child->IsTableRow()) {
      continue;
    }

    return IsBreakInside(
        FindPreviousBreakToken(To<PhysicalBoxFragment>(*child)));
  }

  return false;
}

bool IsEndRowFragmented(const PhysicalBoxFragment& section) {
  const auto children = section.Children();
  for (auto it = children.rbegin(); it != children.rend(); ++it) {
    const auto& child = *it;
    if (!child->IsTableRow()) {
      continue;
    }
    const auto* break_token = To<BlockBreakToken>(child->GetBreakToken());
    return IsBreakInside(break_token) && !break_token->IsAtBlockEnd();
  }
  return false;
}

}  // namespace

void TablePainter::PaintCollapsedBorders(const PaintInfo& paint_info,
                                         const PhysicalOffset& paint_offset,
                                         const gfx::Rect& visual_rect) {
  const TableBorders* collapsed_borders = fragment_.TableCollapsedBorders();
  if (!collapsed_borders)
    return;
  const TableFragmentData::CollapsedBordersGeometry*
      collapsed_borders_geometry = fragment_.TableCollapsedBordersGeometry();
  CHECK(collapsed_borders_geometry);

  const auto& layout_table = *To<LayoutTable>(fragment_.GetLayoutObject());
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          paint_info.context, layout_table, paint_info.phase))
    return;
  DrawingRecorder recorder(paint_info.context, layout_table, paint_info.phase,
                           visual_rect);
  AutoDarkMode auto_dark_mode(PaintAutoDarkMode(
      fragment_.Style(), DarkModeFilter::ElementRole::kBorder));

  const wtf_size_t edges_per_row = collapsed_borders->EdgesPerRow();
  const wtf_size_t total_row_count =
      collapsed_borders->EdgeCount() / edges_per_row;

  const auto* start_section = StartSection(fragment_);
  const auto* end_section = EndSection(fragment_);

  // We paint collapsed-borders section-by-section for fragmentation purposes.
  // This means that we need to track the final row we've painted in each
  // section to avoid double painting.
  std::optional<wtf_size_t> previous_painted_row_index;

  for (const auto& child : fragment_.Children()) {
    if (!child->IsTableSection()) {
      continue;
    }

    const auto& section = To<PhysicalBoxFragment>(*child);
    const std::optional<wtf_size_t> section_start_row_index =
        section.TableSectionStartRowIndex();
    if (!section_start_row_index)
      continue;

    const auto& section_row_offsets = *section.TableSectionRowOffsets();
    const wtf_size_t start_edge_index =
        *section_start_row_index * edges_per_row;

    // Determine if we have (table) content in the next/previous fragmentainer.
    // We'll use this information to paint "half" borders if required.
    bool has_content_in_previous_fragmentainer =
        (start_section == &section) && (*section_start_row_index > 0u);
    bool has_content_in_next_fragmentainer =
        (end_section == &section) &&
        (*section_start_row_index + section_row_offsets.size() <
         total_row_count);

    // If our row was fragmented we skip painting the borders at that edge.
    bool is_start_row_fragmented = IsStartRowFragmented(section);
    bool is_end_row_fragmented = IsEndRowFragmented(section);

    WritingModeConverter converter(fragment_.Style().GetWritingDirection(),
                                   section.Size());

    for (auto edge = TableCollapsedEdge(*collapsed_borders, start_edge_index);
         edge.Exists(); ++edge) {
      const wtf_size_t table_row = edge.TableRow();
      const wtf_size_t table_column = edge.TableColumn();
      const wtf_size_t fragment_table_row =
          table_row - *section_start_row_index;

      // Check if we've exhausted the rows in this section.
      if (fragment_table_row >= section_row_offsets.size()) {
        // Store the final row which we painted (if it wasn't fragmented).
        if (is_end_row_fragmented)
          previous_painted_row_index = std::nullopt;
        else
          previous_painted_row_index = table_row - 1;
        break;
      }

      if (!edge.CanPaint())
        continue;

      bool is_start_row = fragment_table_row == 0u;
      bool is_start_fragmented = is_start_row && is_start_row_fragmented;
      bool is_start_at_fragmentation_boundary =
          is_start_row && has_content_in_previous_fragmentainer;

      const LayoutUnit row_start_offset =
          section_row_offsets[fragment_table_row];
      const LayoutUnit column_start_offset =
          collapsed_borders_geometry->columns[table_column];

      LayoutUnit inline_start;
      LayoutUnit block_start;
      LayoutUnit inline_size;
      LayoutUnit block_size;

      if (edge.IsInlineAxis()) {
        // NOTE: This crash has been observed, but we aren't able to find a
        // reproducible testcase. See: crbug.com/1179369.
        if (table_column + 1 >= collapsed_borders_geometry->columns.size()) {
          NOTREACHED();
        }

        // Check if we have painted this inline border in a previous section.
        if (previous_painted_row_index &&
            *previous_painted_row_index == table_row) {
          continue;
        }

        bool is_end_row = fragment_table_row == section_row_offsets.size() - 1u;
        bool is_end_fragmented = is_end_row && is_end_row_fragmented;
        bool is_end_at_fragmentation_boundary =
            is_end_row && has_content_in_next_fragmentainer;

        // If the current row has been fragmented, omit the inline border.
        if (is_start_fragmented || is_end_fragmented)
          continue;

        inline_start = column_start_offset;
        inline_size = collapsed_borders_geometry->columns[table_column + 1] -
                      column_start_offset;
        block_start = is_start_at_fragmentation_boundary
                          ? row_start_offset
                          : row_start_offset - edge.BorderWidth() / 2;
        block_size = is_start_at_fragmentation_boundary ||
                             is_end_at_fragmentation_boundary
                         ? edge.BorderWidth() / 2
                         : edge.BorderWidth();

        LogicalSize start_joint;
        LogicalSize end_joint;
        bool start_wins;
        bool end_wins;
        ComputeEdgeJoints(*collapsed_borders, edge,
                          is_start_at_fragmentation_boundary,
                          is_end_at_fragmentation_boundary, start_joint,
                          end_joint, start_wins, end_wins);
        if (start_wins) {
          inline_start -= start_joint.inline_size / 2;
          inline_size += start_joint.inline_size / 2;
        } else {
          inline_start += start_joint.inline_size / 2;
          inline_size -= start_joint.inline_size / 2;
        }
        if (end_wins) {
          inline_size += end_joint.inline_size / 2;
        } else {
          inline_size -= end_joint.inline_size / 2;
        }
      } else {  // block_axis
        // Check if this block border exists in this section.
        if (fragment_table_row + 1 >= section_row_offsets.size())
          continue;

        bool is_end_row =
            fragment_table_row + 1u == section_row_offsets.size() - 1u;
        bool is_end_fragmented = is_end_row && is_end_row_fragmented;
        bool is_end_at_fragmentation_boundary =
            is_end_row && has_content_in_next_fragmentainer;

        block_start = row_start_offset;
        block_size =
            section_row_offsets[fragment_table_row + 1] - row_start_offset;
        inline_start = column_start_offset - edge.BorderWidth() / 2;
        inline_size = edge.BorderWidth();

        LogicalSize start_joint;
        LogicalSize end_joint;
        bool start_wins;
        bool end_wins;
        ComputeEdgeJoints(*collapsed_borders, edge,
                          is_start_at_fragmentation_boundary,
                          is_end_at_fragmentation_boundary, start_joint,
                          end_joint, start_wins, end_wins);
        if (is_start_fragmented) {
          // We don't need to perform any adjustment if we've been start
          // fragmented as there isn't a joint here.
        } else if (start_wins) {
          block_start -= start_joint.block_size / 2;
          block_size += start_joint.block_size / 2;
        } else {
          block_start += start_joint.block_size / 2;
          block_size -= start_joint.block_size / 2;
        }
        if (is_end_fragmented) {
          // We don't need to perform any adjustment if we've been end
          // fragmented as there isn't a joint here.
        } else if (end_wins) {
          block_size += end_joint.block_size / 2;
        } else {
          block_size -= end_joint.block_size / 2;
        }
      }
      const LogicalRect logical_border_rect(inline_start, block_start,
                                            inline_size, block_size);
      PhysicalRect physical_border_rect =
          converter.ToPhysical(logical_border_rect);
      physical_border_rect.offset += child.offset + paint_offset;

      BoxSide box_side;
      if (fragment_.Style().IsHorizontalWritingMode()) {
        box_side = edge.IsInlineAxis() ? BoxSide::kTop : BoxSide::kLeft;
      } else {
        box_side = edge.IsInlineAxis() ? BoxSide::kLeft : BoxSide::kTop;
      }
      BoxBorderPainter::DrawBoxSide(
          paint_info.context, ToPixelSnappedRect(physical_border_rect),
          box_side, edge.BorderColor(), edge.BorderStyle(), auto_dark_mode);
    }
  }
}

void TableSectionPainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const BoxDecorationData& box_decoration_data) {
  DCHECK(box_decoration_data.ShouldPaint());
  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintNormalBoxShadow(
        paint_info, paint_rect, fragment_.Style(), PhysicalBoxSides(),
        !box_decoration_data.ShouldPaintBackground());
  }

  // If we are fragmented - determine the total part size, relative to the
  // current fragment.
  PhysicalRect part_rect = paint_rect;
  if (!fragment_.IsOnlyForNode())
    part_rect.offset -= OffsetInStitchedFragments(fragment_, &part_rect.size);

  for (const PhysicalFragmentLink& child : fragment_.Children()) {
    const auto& child_fragment = *child;
    DCHECK(child_fragment.IsBox());
    if (!child_fragment.IsTableRow()) {
      continue;
    }
    TableRowPainter(To<PhysicalBoxFragment>(child_fragment))
        .PaintTablePartBackgroundIntoCells(
            paint_info, *To<LayoutBox>(fragment_.GetLayoutObject()), part_rect,
            paint_rect.offset + child.offset);
  }
  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintInsetBoxShadowWithInnerRect(paint_info, paint_rect,
                                                     fragment_.Style());
  }
}

void TableSectionPainter::PaintColumnsBackground(
    const PaintInfo& paint_info,
    const PhysicalOffset& section_paint_offset,
    const PhysicalRect& columns_paint_rect,
    const TableFragmentData::ColumnGeometries& column_geometries) {
  for (const PhysicalFragmentLink& row : fragment_.Children()) {
    if (!row.fragment->IsTableRow()) {
      continue;
    }
    TableRowPainter(To<PhysicalBoxFragment>(*row.fragment))
        .PaintColumnsBackground(paint_info, section_paint_offset + row.offset,
                                columns_paint_rect, column_geometries);
  }
}

void TableRowPainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const BoxDecorationData& box_decoration_data) {
  DCHECK(box_decoration_data.ShouldPaint());
  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintNormalBoxShadow(
        paint_info, paint_rect, fragment_.Style(), PhysicalBoxSides(),
        !box_decoration_data.ShouldPaintBackground());
  }

  // If we are fragmented - determine the total part size, relative to the
  // current fragment.
  PhysicalRect part_rect = paint_rect;
  if (!fragment_.IsOnlyForNode())
    part_rect.offset -= OffsetInStitchedFragments(fragment_, &part_rect.size);

  PaintTablePartBackgroundIntoCells(paint_info,
                                    *To<LayoutBox>(fragment_.GetLayoutObject()),
                                    part_rect, paint_rect.offset);
  if (box_decoration_data.ShouldPaintShadow()) {
    BoxPainterBase::PaintInsetBoxShadowWithInnerRect(paint_info, paint_rect,
                                                     fragment_.Style());
  }
}

void TableRowPainter::PaintTablePartBackgroundIntoCells(
    const PaintInfo& paint_info,
    const LayoutBox& table_part,
    const PhysicalRect& table_part_paint_rect,
    const PhysicalOffset& row_paint_offset) {
  for (const PhysicalFragmentLink& child : fragment_.Children()) {
    DCHECK(child.fragment->IsBox());
    DCHECK(child.fragment->GetLayoutObject()->IsTableCell() ||
           child.fragment->GetLayoutObject()->IsOutOfFlowPositioned());
    const auto& child_fragment = *child;
    if (!child_fragment.IsTableCell()) {
      continue;
    }
    TableCellPainter(To<PhysicalBoxFragment>(child_fragment))
        .PaintBackgroundForTablePart(paint_info, table_part,
                                     table_part_paint_rect,
                                     row_paint_offset + child.offset);
  }
}

void TableRowPainter::PaintColumnsBackground(
    const PaintInfo& paint_info,
    const PhysicalOffset& row_paint_offset,
    const PhysicalRect& columns_paint_rect,
    const TableFragmentData::ColumnGeometries& column_geometries) {
  WritingModeConverter converter(fragment_.Style().GetWritingDirection(),
                                 columns_paint_rect.size);
  for (const PhysicalFragmentLink& child : fragment_.Children()) {
    if (!child.fragment->IsTableCell()) {
      continue;
    }
    const wtf_size_t cell_column =
        To<PhysicalBoxFragment>(child.fragment.Get())->TableCellColumnIndex();
    for (const auto& column_geometry : column_geometries) {
      wtf_size_t current_start = column_geometry.start_column;
      wtf_size_t current_end =
          column_geometry.start_column + column_geometry.span - 1;
      if (cell_column < current_start || cell_column > current_end)
        continue;

      LogicalSize column_size = converter.ToLogical(columns_paint_rect.size);
      column_size.inline_size = column_geometry.inline_size;

      PhysicalRect column_paint_rect;
      column_paint_rect.size = converter.ToPhysical(column_size);
      column_paint_rect.offset =
          columns_paint_rect.offset +
          converter.ToPhysical({column_geometry.inline_offset, LayoutUnit()},
                               column_paint_rect.size);

      TableCellPainter(To<PhysicalBoxFragment>(*child.fragment))
          .PaintBackgroundForTablePart(
              paint_info, *column_geometry.node.GetLayoutBox(),
              column_paint_rect, row_paint_offset + child.offset);
    }
  }
}

void TableCellPainter::PaintBoxDecorationBackground(
    const PaintInfo& paint_info,
    const PhysicalRect& paint_rect,
    const BoxDecorationData& box_decoration_data) {
  DCHECK(box_decoration_data.ShouldPaint());
  TableCellBackgroundClipper c
```