Response:
The user wants to understand the functionality of the `layout_table.cc` file in the Chromium Blink engine. I need to go through the code and identify its purpose and how it interacts with other parts of the rendering engine, specifically JavaScript, HTML, and CSS. I also need to consider potential usage errors.

Here's a breakdown of the steps:

1. **Identify the class:** The file defines the `LayoutTable` class.
2. **Determine its role:**  Based on the class name and included headers, it's responsible for the layout of HTML `<table>` elements.
3. **Analyze methods:** Go through each method and understand its function. Pay attention to how these methods relate to the table layout algorithm.
4. **Identify relationships with HTML, CSS, and JavaScript:**
    * **HTML:** The class represents the layout of the `<table>` element and its children (`<caption>`, `<thead>`, `<tbody>`, `<tfoot>`, `<tr>`, `<th>`, `<td>`, `<colgroup>`, `<col>`).
    * **CSS:**  The class interacts heavily with CSS properties related to tables, such as `display: table`, `display: inline-table`, `border-collapse`, `border-spacing`, `empty-cells`, and background properties on table elements.
    * **JavaScript:** While the file itself doesn't directly interact with JavaScript, changes to the DOM or CSS via JavaScript will trigger layout recalculations involving this class.
5. **Look for logical reasoning:**  Identify methods that make decisions or perform calculations based on input. Formulate hypothetical inputs and outputs for these methods.
6. **Identify potential usage errors:** Consider common mistakes developers might make when working with tables in HTML and CSS that this class might be involved in handling (or where its behavior might be unexpected).
7. **Structure the answer:**  Organize the findings into clear categories: Functionality, Relationship with HTML/CSS/JavaScript, Logical Reasoning, and Common Usage Errors.
`blink/renderer/core/layout/table/layout_table.cc` 文件定义了 `LayoutTable` 类，它是 Chromium Blink 渲染引擎中负责处理 HTML `<table>` 元素布局的核心组件。它的主要功能是计算和管理表格的几何结构，包括单元格、行、列和边框的位置和大小，并处理相关的 CSS 样式。

以下是 `LayoutTable` 类的功能列表，以及它与 JavaScript、HTML 和 CSS 的关系，逻辑推理示例和常见使用错误：

**功能列表:**

1. **表示 HTML `<table>` 元素:** `LayoutTable` 类是 `<table>` 元素在渲染过程中的内部表示。
2. **处理表格布局算法:**  它实现了 CSS 表格布局规范，负责确定表格中各个元素的最终位置和尺寸。
3. **管理表格子元素:** 它维护了表格的子元素，如 `<caption>` (表格标题), `<colgroup>` 和 `<col>` (列组和列), `<thead>` (表头), `<tbody>` (表体), `<tfoot>` (表尾) 和 `<tr>` (行)。
4. **处理匿名表格元素:**  当 HTML 中出现不符合表格结构的子元素时，`LayoutTable` 可以创建匿名的表格部分（例如匿名的 `<tbody>`）来包裹这些元素，以符合表格的渲染模型。
5. **处理 `display: table` 和 `display: inline-table`:**  根据 CSS 的 `display` 属性，决定表格是块级元素 (`display: table`) 还是行内级元素 (`display: inline-table`)。
6. **缓存表格边框信息:** 它缓存了表格的边框信息 (`TableBorders`)，以优化渲染性能。当边框样式改变时，会使缓存失效。
7. **缓存列约束信息:** 它缓存了表格列的约束信息 (`TableTypes::Columns`)，用于列宽计算。
8. **处理 `border-collapse` 属性:**  根据 `border-collapse` 属性的值（`collapse` 或 `separate`），采用不同的边框绘制和布局策略。
9. **处理表格背景:** 负责绘制表格自身的背景以及列的背景。
10. **处理表格结构的修改:** 当表格的子元素添加或删除时，会触发相应的布局更新。
11. **提供访问表格结构信息的方法:**  提供了 `FirstSection()`, `LastSection()`, `NextSection()`, `PreviousSection()`, `ColumnCount()` 等方法来访问表格的结构信息。
12. **计算溢出裁剪区域:**  确定表格内容的溢出裁剪区域，但需要注意的是，对于包含标题的表格，当前的实现可能无法正确地裁剪溢出内容。
13. **处理表格边框和内边距:**  根据 `border-collapse` 的值，返回正确的边框和内边距大小。
14. **处理可合并列:**  用于辅助功能 (Accessibility)，计算非合并列的有效列索引。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    * `LayoutTable` 直接对应于 HTML 的 `<table>` 元素。
    * 它负责布局 `<table>` 元素及其子元素 (`<caption>`, `<colgroup>`, `<col>`, `<thead>`, `<tbody>`, `<tfoot>`, `<tr>`, `<th>`, `<td>`)。
    * **举例:** 当 HTML 中有 `<table id="myTable"><tr><td>Data</td></tr></table>` 时，Blink 引擎会创建一个 `LayoutTable` 对象来表示这个 `<table>` 元素。

* **CSS:**
    * `LayoutTable` 的行为和布局方式受到多种 CSS 属性的影响，特别是与表格相关的属性：
        * `display: table` 或 `display: inline-table`:  决定了 `LayoutTable` 的基本布局模型。
        * `border-collapse`: 决定了是否合并表格边框。
        * `border-spacing`:  当 `border-collapse: separate` 时，设置单元格之间的间距。
        * `empty-cells`:  当 `border-collapse: separate` 时，控制是否显示没有内容的单元格的边框和背景。
        * `table-layout`:  决定了表格的布局算法是自动的还是固定的。
        * 背景相关的属性 (`background-color`, `background-image`, 等) 会影响表格及其列的背景绘制。
    * **举例:**  如果 CSS 中设置了 `table { border-collapse: collapse; border: 1px solid black; }`, `LayoutTable` 会根据这些样式来计算和绘制表格的边框，并进行合并。

* **JavaScript:**
    * JavaScript 可以通过 DOM API 操作 HTML 结构和 CSS 样式，这些操作会间接地影响 `LayoutTable` 的行为。
    * 当 JavaScript 添加、删除或修改表格元素或其样式时，Blink 引擎会重新计算布局，`LayoutTable` 会参与这个过程。
    * **举例:**  如果 JavaScript 使用 `document.getElementById('myTable').style.borderCollapse = 'separate';` 修改了表格的 `border-collapse` 属性，`LayoutTable` 的 `GridBordersChanged()` 方法会被调用，导致缓存的边框信息失效，并在后续的布局计算中采用新的边框模型。

**逻辑推理示例:**

* **假设输入:**  一个 `<div>` 元素内部包含一些文本节点，这些文本节点没有被任何表格相关的标签包裹。
* **`NeedsTableSection()` 函数:** 该函数用于判断一个 `LayoutObject` 是否需要被包裹在一个匿名的表格 section 中。
* **逻辑:** 如果文本节点（或其他某些类型的 `LayoutObject`）的 `display` 属性不是 `table-caption`, `table-column-group` 或 `table-column`， 那么 `NeedsTableSection()` 将返回 `true`。
* **输出:**  `LayoutTable` 的 `AddChild()` 方法会检查 `NeedsTableSection()` 的返回值。如果返回 `true`，它会创建一个匿名的 `LayoutTableSection` 来包裹这些文本节点。

* **假设输入:**  一个 `LayoutTable` 对象，其 `border-collapse` 样式为 `collapse`。
* **`BorderLeft()` 函数:** 该函数用于获取表格的左边框宽度。
* **逻辑:**  如果 `HasCollapsedBorders()` 返回 `true` (因为 `border-collapse` 是 `collapse`) 并且缓存的边框信息 `cached_table_borders_` 存在，那么 `BorderLeft()` 将返回缓存的表格边框的左侧宽度。否则，它将调用父类 `LayoutBlock` 的 `BorderLeft()` 方法。
* **输出:**  返回计算出的左边框宽度。

**常见使用错误示例:**

1. **在非表格父元素下直接添加表格行 (`<tr>`) 或单元格 (`<td>`):**  HTML 规范要求 `<tr>` 必须是 `<thead>`, `<tbody>` 或 `<tfoot>` 的子元素，而 `<td>` 或 `<th>` 必须是 `<tr>` 的子元素。如果直接在 `<div>` 下添加这些元素，Blink 引擎会尝试修复这种错误，可能会创建匿名的表格结构来包裹这些元素。这可能会导致意想不到的布局结果。
    * **错误 HTML:**
      ```html
      <div id="container">
        <tr><td>Invalid Table Cell</td></tr>
      </div>
      ```
    * **Blink 的处理:**  `LayoutTable` 的 `AddChild()` 方法会检测到这种情况，并可能创建一个匿名的 `<table>` 和 `<tbody>` 来包裹这个 `<tr>`。

2. **误解 `border-collapse: collapse` 对内边距的影响:**  当 `border-collapse: collapse` 时，表格本身以及单元格的 `padding` 属性仍然会影响布局，但单元格之间的间距是由边框合并规则决定的，而不是由 `border-spacing` 属性控制。开发者可能会认为设置了表格的 `padding` 后，单元格之间会有间距，但这只有在 `border-collapse: separate` 时才生效。
    * **错误理解:** 认为当 `table { border-collapse: collapse; padding: 10px; }` 时，单元格之间会有 10px 的间距。
    * **`LayoutTable` 的处理:**  `PaddingTop()`, `PaddingBottom()`, `PaddingLeft()`, `PaddingRight()` 方法会根据 `HasCollapsedBorders()` 的返回值来决定是否返回内边距的值。当 `border-collapse: collapse` 时，这些方法会返回 0。

3. **依赖 JavaScript 动态修改表格结构后立即获取准确的布局信息:**  修改 DOM 结构（包括表格结构）后，浏览器的渲染引擎可能不会立即更新布局。如果 JavaScript 在修改后立即尝试获取表格的尺寸或位置信息，可能会得到旧的或不准确的值。应该等待浏览器完成布局更新后再进行相关操作。

总而言之，`layout_table.cc` 文件中的 `LayoutTable` 类是 Blink 渲染引擎中至关重要的组件，它负责将 HTML `<table>` 元素和相关的 CSS 样式转化为可视化的布局结构。理解其功能和与 HTML、CSS、JavaScript 的交互方式对于开发和调试涉及表格布局的 Web 页面至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/table/layout_table.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/table/layout_table.h"

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_caption.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/layout/table/table_borders.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/table_painters.h"
#include "third_party/blink/renderer/platform/geometry/infinite_int_rect.h"

namespace blink {

namespace {

inline bool NeedsTableSection(const LayoutObject& object) {
  // Return true if 'object' can't exist in an anonymous table without being
  // wrapped in a table section box.
  EDisplay display = object.StyleRef().Display();
  return display != EDisplay::kTableCaption &&
         display != EDisplay::kTableColumnGroup &&
         display != EDisplay::kTableColumn;
}

}  // namespace

LayoutTable::LayoutTable(Element* element) : LayoutBlock(element) {}

LayoutTable::~LayoutTable() = default;

void LayoutTable::Trace(Visitor* visitor) const {
  visitor->Trace(cached_table_borders_);
  LayoutBlock::Trace(visitor);
}

// https://drafts.csswg.org/css-tables-3/#fixup-algorithm
// 3.2. If the box’s parent is an inline, run-in, or ruby box (or any box that
// would perform inlinification of its children), then an inline-table box must
// be generated; otherwise it must be a table box.
bool LayoutTable::ShouldCreateInlineAnonymous(const LayoutObject& parent) {
  return parent.IsLayoutInline();
}

LayoutTable* LayoutTable::CreateAnonymousWithParent(
    const LayoutObject& parent) {
  const ComputedStyle& parent_style = parent.StyleRef();
  const ComputedStyle* new_style =
      parent.GetDocument().GetStyleResolver().CreateAnonymousStyleWithDisplay(
          parent_style, ShouldCreateInlineAnonymous(parent)
                            ? EDisplay::kInlineTable
                            : EDisplay::kTable);
  auto* new_table = MakeGarbageCollected<LayoutTable>(nullptr);
  new_table->SetDocumentForAnonymous(&parent.GetDocument());
  new_table->SetStyle(new_style);
  return new_table;
}

bool LayoutTable::IsFirstCell(const LayoutTableCell& cell) const {
  NOT_DESTROYED();
  const LayoutTableRow* row = cell.Row();
  if (row->FirstCell() != &cell) {
    return false;
  }
  const LayoutTableSection* section = row->Section();
  if (section->FirstRow() != row) {
    return false;
  }
  TableGroupedChildren grouped_children(
      BlockNode(const_cast<LayoutTable*>(this)));
  auto first_section = grouped_children.begin();
  return first_section != grouped_children.end() &&
         (*first_section).GetLayoutBox() == section;
}

LayoutTableSection* LayoutTable::FirstSection() const {
  NOT_DESTROYED();
  TableGroupedChildren grouped_children(
      BlockNode(const_cast<LayoutTable*>(this)));
  auto first_section = grouped_children.begin();
  if (first_section != grouped_children.end()) {
    auto* section_object =
        To<LayoutTableSection>((*first_section).GetLayoutBox());
    if ((*first_section).IsEmptyTableSection()) {
      return NextSection(section_object);
    }
    return section_object;
  }
  return nullptr;
}

LayoutTableSection* LayoutTable::LastSection() const {
  NOT_DESTROYED();
  TableGroupedChildren grouped_children(
      BlockNode(const_cast<LayoutTable*>(this)));
  auto last_section = --grouped_children.end();
  if (last_section != grouped_children.end()) {
    auto* section_object =
        To<LayoutTableSection>((*last_section).GetLayoutBox());
    if ((*last_section).IsEmptyTableSection()) {
      return PreviousSection(section_object);
    }
    return section_object;
  }
  return nullptr;
}

LayoutTableSection* LayoutTable::NextSection(
    const LayoutTableSection* current) const {
  NOT_DESTROYED();
  TableGroupedChildren grouped_children(
      BlockNode(const_cast<LayoutTable*>(this)));
  bool found = false;
  for (BlockNode section : grouped_children) {
    if (found && !section.IsEmptyTableSection()) {
      return To<LayoutTableSection>(section.GetLayoutBox());
    }
    if (current == To<LayoutTableSection>(section.GetLayoutBox())) {
      found = true;
    }
  }
  return nullptr;
}

LayoutTableSection* LayoutTable::PreviousSection(
    const LayoutTableSection* current) const {
  NOT_DESTROYED();
  TableGroupedChildren grouped_children(
      BlockNode(const_cast<LayoutTable*>(this)));
  auto stop = --grouped_children.begin();
  bool found = false;
  for (auto it = --grouped_children.end(); it != stop; --it) {
    BlockNode section = *it;
    if (found && !section.IsEmptyTableSection()) {
      return To<LayoutTableSection>(section.GetLayoutBox());
    }
    if (current == To<LayoutTableSection>(section.GetLayoutBox())) {
      found = true;
    }
  }
  return nullptr;
}

wtf_size_t LayoutTable::ColumnCount() const {
  NOT_DESTROYED();
  const LayoutResult* cached_layout_result = GetCachedLayoutResult(nullptr);
  if (!cached_layout_result)
    return 0;
  return cached_layout_result->TableColumnCount();
}

void LayoutTable::SetCachedTableBorders(const TableBorders* table_borders) {
  NOT_DESTROYED();
  cached_table_borders_ = table_borders;
}

void LayoutTable::InvalidateCachedTableBorders() {
  NOT_DESTROYED();
  // TODO(layout-dev) When cached borders are invalidated, we could do a
  // special kind of relayout where fragments can replace only TableBorders,
  // keep the geometry, and repaint.
  cached_table_borders_ = nullptr;
}

const TableTypes::Columns* LayoutTable::GetCachedTableColumnConstraints() {
  NOT_DESTROYED();
  if (IsTableColumnsConstraintsDirty())
    cached_table_columns_.reset();
  return cached_table_columns_.get();
}

void LayoutTable::SetCachedTableColumnConstraints(
    scoped_refptr<const TableTypes::Columns> columns) {
  NOT_DESTROYED();
  cached_table_columns_ = std::move(columns);
  SetTableColumnConstraintDirty(false);
}

void LayoutTable::GridBordersChanged() {
  NOT_DESTROYED();
  InvalidateCachedTableBorders();
  if (StyleRef().BorderCollapse() == EBorderCollapse::kCollapse) {
    SetShouldDoFullPaintInvalidationWithoutLayoutChange(
        PaintInvalidationReason::kStyle);
    // If borders change, table fragment must be regenerated.
    SetNeedsLayoutAndIntrinsicWidthsRecalc(
        layout_invalidation_reason::kTableChanged);
  }
}

void LayoutTable::TableGridStructureChanged() {
  NOT_DESTROYED();
  // Callers must ensure table layout gets invalidated.
  InvalidateCachedTableBorders();
  if (StyleRef().BorderCollapse() == EBorderCollapse::kCollapse)
    SetShouldDoFullPaintInvalidation();
}

bool LayoutTable::HasBackgroundForPaint() const {
  NOT_DESTROYED();
  if (StyleRef().HasBackground())
    return true;
  DCHECK_GT(PhysicalFragmentCount(), 0u);
  const TableFragmentData::ColumnGeometries* column_geometries =
      GetPhysicalFragment(0)->TableColumnGeometries();
  if (column_geometries) {
    for (const auto& column_geometry : *column_geometries) {
      if (column_geometry.node.Style().HasBackground())
        return true;
    }
  }
  return false;
}

void LayoutTable::AddChild(LayoutObject* child, LayoutObject* before_child) {
  NOT_DESTROYED();
  TableGridStructureChanged();
  // Only TablesNG table parts are allowed.
  // TODO(1229581): Change this DCHECK to caption || column || section.
  DCHECK(child->IsLayoutNGObject() ||
         (!child->IsTableCaption() && !child->IsLayoutTableCol() &&
          !child->IsTableSection()));
  bool wrap_in_anonymous_section = !child->IsTableCaption() &&
                                   !child->IsLayoutTableCol() &&
                                   !child->IsTableSection();

  if (!wrap_in_anonymous_section) {
    if (before_child && before_child->Parent() != this)
      before_child = SplitAnonymousBoxesAroundChild(before_child);
    LayoutBox::AddChild(child, before_child);
    return;
  }

  if (!before_child && LastChild() && LastChild()->IsTableSection() &&
      LastChild()->IsAnonymous() && !LastChild()->IsBeforeContent()) {
    LastChild()->AddChild(child);
    return;
  }

  if (before_child && !before_child->IsAnonymous() &&
      before_child->Parent() == this) {
    auto* section =
        DynamicTo<LayoutTableSection>(before_child->PreviousSibling());
    if (section && section->IsAnonymous()) {
      section->AddChild(child);
      return;
    }
  }

  LayoutObject* last_box = before_child;
  while (last_box && last_box->Parent()->IsAnonymous() &&
         !last_box->IsTableSection() && NeedsTableSection(*last_box))
    last_box = last_box->Parent();
  if (last_box && last_box->IsAnonymous() && last_box->IsTablePart() &&
      !IsAfterContent(last_box)) {
    if (before_child == last_box)
      before_child = last_box->SlowFirstChild();
    last_box->AddChild(child, before_child);
    return;
  }

  if (before_child && !before_child->IsTableSection() &&
      NeedsTableSection(*before_child))
    before_child = nullptr;

  auto* section = LayoutTableSection::CreateAnonymousWithParent(*this);
  AddChild(section, before_child);
  section->AddChild(child);
}

void LayoutTable::RemoveChild(LayoutObject* child) {
  NOT_DESTROYED();
  TableGridStructureChanged();
  LayoutBlock::RemoveChild(child);
}

void LayoutTable::StyleDidChange(StyleDifference diff,
                                 const ComputedStyle* old_style) {
  NOT_DESTROYED();
  // StyleDifference handles changes in table-layout, border-spacing.
  if (old_style) {
    bool borders_changed =
        !old_style->BorderVisuallyEqual(StyleRef()) ||
        old_style->GetWritingDirection() != StyleRef().GetWritingDirection() ||
        old_style->IsFixedTableLayout() != StyleRef().IsFixedTableLayout() ||
        old_style->EmptyCells() != StyleRef().EmptyCells();
    bool collapse_changed =
        StyleRef().BorderCollapse() != old_style->BorderCollapse();
    if (borders_changed || collapse_changed)
      GridBordersChanged();
  }
  LayoutBlock::StyleDidChange(diff, old_style);
}

LayoutBox* LayoutTable::CreateAnonymousBoxWithSameTypeAs(
    const LayoutObject* parent) const {
  NOT_DESTROYED();
  return CreateAnonymousWithParent(*parent);
}

PhysicalRect LayoutTable::OverflowClipRect(
    const PhysicalOffset& location,
    OverlayScrollbarClipBehavior overlay_scrollbar_clip_behavior) const {
  NOT_DESTROYED();
  PhysicalRect clip_rect;
  if (StyleRef().BorderCollapse() == EBorderCollapse::kCollapse) {
    clip_rect = PhysicalRect(location, Size());
    const auto overflow_clip = GetOverflowClipAxes();
    gfx::Rect infinite_rect = InfiniteIntRect();
    if ((overflow_clip & kOverflowClipX) == kNoOverflowClip) {
      clip_rect.offset.left = LayoutUnit(infinite_rect.x());
      clip_rect.size.width = LayoutUnit(infinite_rect.width());
    }
    if ((overflow_clip & kOverflowClipY) == kNoOverflowClip) {
      clip_rect.offset.top = LayoutUnit(infinite_rect.y());
      clip_rect.size.height = LayoutUnit(infinite_rect.height());
    }
  } else {
    clip_rect = LayoutBlock::OverflowClipRect(location,
                                              overlay_scrollbar_clip_behavior);
  }
  // TODO(1142929)
  // We cannot handle table hidden overflow with captions correctly.
  // Correct handling would clip table grid content to grid content rect,
  // but not clip the captions.
  // Since we are not generating table's grid fragment, this is not
  // possible.
  // The current solution is to not clip if we have captions.
  // Maybe a fix is to do an additional clip in table painter?
  const LayoutBox* child = FirstChildBox();
  while (child) {
    if (child->IsTableCaption()) {
      // If there are captions, we cannot clip to content box.
      clip_rect.Unite(PhysicalRect(location, Size()));
      break;
    }
    child = child->NextSiblingBox();
  }
  return clip_rect;
}

LayoutUnit LayoutTable::BorderLeft() const {
  NOT_DESTROYED();
  // DCHECK(cached_table_borders_.get())
  // ScrollAnchoring fails this DCHECK.
  if (HasCollapsedBorders() && cached_table_borders_) {
    return cached_table_borders_->TableBorder()
        .ConvertToPhysical(Style()->GetWritingDirection())
        .left;
  }
  return LayoutBlock::BorderLeft();
}

LayoutUnit LayoutTable::BorderRight() const {
  NOT_DESTROYED();
  // DCHECK(cached_table_borders_.get())
  // ScrollAnchoring fails this DCHECK.
  if (HasCollapsedBorders() && cached_table_borders_) {
    return cached_table_borders_->TableBorder()
        .ConvertToPhysical(Style()->GetWritingDirection())
        .right;
  }
  return LayoutBlock::BorderRight();
}

LayoutUnit LayoutTable::BorderTop() const {
  NOT_DESTROYED();
  // DCHECK(cached_table_borders_.get())
  // ScrollAnchoring fails this DCHECK.
  if (HasCollapsedBorders() && cached_table_borders_) {
    return cached_table_borders_->TableBorder()
        .ConvertToPhysical(Style()->GetWritingDirection())
        .top;
  }
  return LayoutBlock::BorderTop();
}

LayoutUnit LayoutTable::BorderBottom() const {
  NOT_DESTROYED();
  // DCHECK(cached_table_borders_.get())
  // ScrollAnchoring fails this DCHECK.
  if (HasCollapsedBorders() && cached_table_borders_) {
    return cached_table_borders_->TableBorder()
        .ConvertToPhysical(Style()->GetWritingDirection())
        .bottom;
  }
  return LayoutBlock::BorderBottom();
}

LayoutUnit LayoutTable::PaddingTop() const {
  NOT_DESTROYED();
  return HasCollapsedBorders() ? LayoutUnit() : LayoutBlock::PaddingTop();
}

LayoutUnit LayoutTable::PaddingBottom() const {
  NOT_DESTROYED();
  return HasCollapsedBorders() ? LayoutUnit() : LayoutBlock::PaddingBottom();
}

LayoutUnit LayoutTable::PaddingLeft() const {
  NOT_DESTROYED();
  return HasCollapsedBorders() ? LayoutUnit() : LayoutBlock::PaddingLeft();
}

LayoutUnit LayoutTable::PaddingRight() const {
  NOT_DESTROYED();
  return HasCollapsedBorders() ? LayoutUnit() : LayoutBlock::PaddingRight();
}

// Effective column index is index of columns with mergeable
// columns skipped. Used in a11y.
unsigned LayoutTable::AbsoluteColumnToEffectiveColumn(
    unsigned absolute_column_index) const {
  NOT_DESTROYED();
  if (!cached_table_columns_) {
    NOTREACHED();
  }
  unsigned effective_column_index = 0;
  unsigned column_count = cached_table_columns_.get()->data.size();
  for (unsigned current_column_index = 0; current_column_index < column_count;
       ++current_column_index) {
    if (current_column_index != 0 &&
        !cached_table_columns_.get()->data[current_column_index].is_mergeable)
      ++effective_column_index;
    if (current_column_index == absolute_column_index)
      return effective_column_index;
  }
  return effective_column_index;
}

unsigned LayoutTable::EffectiveColumnCount() const {
  NOT_DESTROYED();
  const wtf_size_t column_count = ColumnCount();
  if (column_count == 0) {
    return 0;
  }
  return AbsoluteColumnToEffectiveColumn(column_count - 1) + 1;
}

}  // namespace blink
```