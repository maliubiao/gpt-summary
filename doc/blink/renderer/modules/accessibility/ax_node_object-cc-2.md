Response:
The user wants a summary of the functionalities of the C++ code snippet from the `ax_node_object.cc` file in the Chromium Blink engine. They also want to know about the relationships with web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user/programming errors, and how a user interaction might lead to this code being executed. This is the third part of a ten-part request.

Here's a plan to address these points:

1. **Core Functionality:** Analyze the code to understand its main purpose. It seems to be primarily concerned with determining if an HTML table should be treated as a "data table" for accessibility purposes.

2. **Relationship with Web Technologies:** Identify how HTML elements and attributes, and CSS properties influence the logic.

3. **Logical Reasoning:** Examine the conditions used to classify a table as a data table. Formulate hypothetical inputs (HTML table structures) and predict the output (whether it's classified as a data table).

4. **User/Programming Errors:**  Consider common mistakes developers might make when creating tables that could affect how this code functions.

5. **User Interaction as a Debugging Clue:** Describe the sequence of user actions that would lead to this code being executed (rendering a web page with a table).

6. **Summary of Functionality:** Provide a concise summary of the code's purpose based on the analysis.
好的，根据提供的代码片段，我们可以归纳出以下功能：

**主要功能：判断一个 HTML `<table>` 元素是否应该被视为“数据表格 (data table)” 用于可访问性 (Accessibility) 的目的。**

这个代码片段隶属于 `AXNodeObject` 类（代表可访问性树中的一个节点），其中的 `IsDataTable()` 方法通过一系列复杂的规则来判断一个 `<table>` 元素是用于布局 (layout) 还是用于展示数据 (data)。这是因为辅助技术（例如屏幕阅读器）对数据表格和布局表格的处理方式不同。

**与 Javascript, HTML, CSS 的功能关系及举例说明:**

* **HTML:**  代码直接检查 HTML 元素的属性和结构来做出判断。
    * **例子：**
        * `table_element->Summary()`: 检查 `<table>` 元素的 `summary` 属性。如果存在，则很可能是数据表格。
        * `table_element->tHead()`, `table_element->tFoot()`, `table_element->caption()`: 检查 `<thead>`, `<tfoot>`, `<caption>` 标签是否存在，这些通常用于数据表格。
        * `table_element->Rules()`: 检查 `<table>` 的 `rules` 属性。
        * `Traversal<HTMLTableColElement>::FirstChild(*table_element)`: 检查是否存在 `<colgroup>` 或 `<col>` 元素。
        * `row_element->cells()->item(col)->HasTagName(html_names::kThTag)`: 检查单元格是否是 `<th>` 标签。
        * `cell_elem->Headers()`, `cell_elem->Abbr()`, `cell_elem->Axis()`, `cell_elem->FastGetAttribute(html_names::kScopeAttr)`: 检查 `<td>` 元素的 `headers`, `abbr`, `axis`, 和 `scope` 属性，这些都是数据表格的特性。

* **CSS:** 代码会检查元素的计算样式 (ComputedStyle) 来判断表格的呈现方式。
    * **例子：**
        * `GetLayoutObject()->Style()`: 获取表格的布局对象样式。
        * `table_style->VisitedDependentColor(GetCSSPropertyBackgroundColor())`: 获取表格的背景颜色。
        * `table_style->HorizontalBorderSpacing()`, `table_style->VerticalBorderSpacing()`: 获取单元格间距。
        * `computed_style->EmptyCells() == EEmptyCells::kHide`: 检查 `empty-cells` CSS 属性是否设置为 `hide`。
        * `cell_layout_block->BorderTop()`, `cell_layout_block->BorderBottom()`, etc.: 检查单元格的边框宽度。
        * `computed_style->VisitedDependentColor(GetCSSPropertyBackgroundColor())`: 获取单元格的背景颜色。

* **Javascript:** 虽然这段代码本身是 C++，但 JavaScript 可以动态地修改 HTML 结构、属性和 CSS 样式。这些修改会影响 `IsDataTable()` 的判断结果。
    * **例子：** JavaScript 可以使用 DOM API 来添加或移除 `summary` 属性，添加 `<th>` 标签，修改 CSS 的 `border` 或 `background-color` 属性，从而影响表格是否被识别为数据表格。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

```html
<table>
  <tr><td>Item 1</td><td>Description 1</td></tr>
  <tr><td>Item 2</td><td>Description 2</td></tr>
</table>
```

**输出 1:**  `true` (很可能被判断为数据表格，因为有多个行和列)

**假设输入 2:**

```html
<table style="display: grid; grid-template-columns: 50% 50%;">
  <div>Navigation Link 1</div>
  <div>Navigation Link 2</div>
</table>
```

**输出 2:** `false` (很可能被判断为布局表格，因为使用了 CSS Grid 布局，且内容看起来像导航链接)

**假设输入 3:**

```html
<table summary="This table shows product prices.">
  <tr><th>Product</th><th>Price</th></tr>
  <tr><td>Apple</td><td>$1</td></tr>
</table>
```

**输出 3:** `true` (明确的 `summary` 属性使其被判断为数据表格)

**涉及用户或者编程常见的使用错误，举例说明:**

1. **开发者错误地使用 `<table>` 进行布局:**  这是最常见的情况。开发者可能为了实现某种布局效果而使用 `<table>`，但实际上应该使用 `<div>` 和 CSS 布局技术（如 Flexbox 或 Grid）。这会导致屏幕阅读器错误地将布局元素识别为数据表格。
2. **缺少必要的语义化 HTML 标签和属性:**  对于数据表格，应该使用 `<th>` 定义表头，并使用 `scope`, `headers`, `abbr` 等属性来增强表格的可访问性。如果缺少这些，即使是真正的数据表格也可能难以被辅助技术正确理解。
3. **CSS 样式干扰判断:**  过度复杂的 CSS 样式，例如完全移除边框和间距，可能导致代码难以区分数据表格和布局表格。
4. **动态内容加载不当:**  如果表格内容是通过 JavaScript 动态加载的，并且在加载完成之前可访问性树就已经构建，那么最初的判断可能不准确。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含 `<table>` 元素的网页:**  这是最基本的前提。
2. **浏览器的渲染引擎 (Blink) 解析 HTML 和 CSS:** 当浏览器加载网页时，Blink 会解析 HTML 结构并应用 CSS 样式。
3. **辅助功能服务请求可访问性信息:** 当屏幕阅读器等辅助技术启动并尝试访问网页内容时，它会向浏览器请求可访问性信息。
4. **Blink 构建可访问性树 (Accessibility Tree):**  为了响应辅助功能的请求，Blink 会构建一个可访问性树，这个树代表了页面的语义结构，并用于向辅助技术提供信息。
5. **创建 `AXNodeObject` 对象:**  对于每个需要暴露给辅助技术的 DOM 节点（包括 `<table>` 元素），Blink 会创建一个对应的 `AXNodeObject` 对象。
6. **调用 `IsDataTable()` 方法:**  在创建 `AXNodeObject` 对象或更新其属性时，可能会调用 `IsDataTable()` 方法来确定 `<table>` 元素的角色 (role)。

作为调试线索，如果发现屏幕阅读器错误地将一个布局表格识别为数据表格，那么可以检查以下内容：

* **HTML 结构:** 是否使用了不必要的表格标签？是否存在 `summary`, `caption`, `thead`, `tfoot` 等标签？
* **CSS 样式:** 是否有类似表格的样式应用于非表格元素？是否有明确的表格样式？
* **JavaScript 代码:** 是否有 JavaScript 代码动态修改了表格的结构或样式？
* **断点调试:**  可以在 `IsDataTable()` 方法中设置断点，查看在特定情况下哪些条件被满足，从而判断为什么表格被识别为数据表格。

**归纳一下它的功能 (第3部分):**

总而言之，这段代码片段的核心功能是 **启发式地判断一个 HTML `<table>` 元素是否应被视为用于展示数据的“数据表格”，以便辅助技术能够正确理解和呈现表格内容。** 它通过检查 HTML 结构、属性和 CSS 样式等多种因素来进行判断，力求在各种网页设计模式下都能做出合理的推断。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
no reason to use the table
    // for layout. Treat as a data table by default as there is not enough
    // information to decide otherwise.
    // One useful result of this is that a table inside a canvas fallback is
    // treated as a data table.
    return true;
  }

  // If it has an ARIA role, it's definitely a data table.
  if (HasAriaAttribute(html_names::kRoleAttr)) {
    return true;
  }

  // When a section of the document is contentEditable, all tables should be
  // treated as data tables, otherwise users may not be able to work with rich
  // text editors that allow creating and editing tables.
  if (GetNode() && blink::IsEditable(*GetNode())) {
    return true;
  }

  // If there is a caption element, summary, THEAD, or TFOOT section, it's most
  // certainly a data table
  if (!table_element->Summary().empty() || table_element->tHead() ||
      table_element->tFoot() || table_element->caption()) {
    return true;
  }

  // if someone used "rules" attribute than the table should appear
  if (!table_element->Rules().empty()) {
    return true;
  }

  // if there's a colgroup or col element, it's probably a data table.
  if (Traversal<HTMLTableColElement>::FirstChild(*table_element)) {
    return true;
  }

  // If there are at least 20 rows, we'll call it a data table.
  HTMLTableRowsCollection* rows = table_element->rows();
  int num_rows = rows->length();
  if (num_rows >= AXObjectCacheImpl::kDataTableHeuristicMinRows) {
    return true;
  }
  if (num_rows <= 0) {
    return false;
  }

  int num_cols_in_first_body = rows->Item(0)->cells()->length();
  // If there's only one cell, it's not a good AXTable candidate.
  if (num_rows == 1 && num_cols_in_first_body == 1) {
    return false;
  }

  // Store the background color of the table to check against cell's background
  // colors.
  const ComputedStyle* table_style = GetLayoutObject()->Style();
  if (!table_style) {
    return false;
  }

  Color table_bg_color =
      table_style->VisitedDependentColor(GetCSSPropertyBackgroundColor());
  bool has_cell_spacing = table_style->HorizontalBorderSpacing() &&
                          table_style->VerticalBorderSpacing();

  // check enough of the cells to find if the table matches our criteria
  // Criteria:
  //   1) must have at least one valid cell (and)
  //   2) at least half of cells have borders (or)
  //   3) at least half of cells have different bg colors than the table, and
  //      there is cell spacing
  unsigned valid_cell_count = 0;
  unsigned bordered_cell_count = 0;
  unsigned background_difference_cell_count = 0;
  unsigned cells_with_top_border = 0;
  unsigned cells_with_bottom_border = 0;
  unsigned cells_with_left_border = 0;
  unsigned cells_with_right_border = 0;

  std::array<Color, 5> alternating_row_colors;
  int alternating_row_color_count = 0;
  for (int row = 0; row < num_rows; ++row) {
    HTMLTableRowElement* row_element = rows->Item(row);
    int n_cols = row_element->cells()->length();
    for (int col = 0; col < n_cols; ++col) {
      const Element* cell = row_element->cells()->item(col);
      if (!cell) {
        continue;
      }
      // Any <th> tag -> treat as data table.
      if (cell->HasTagName(html_names::kThTag)) {
        return true;
      }

      // Check for an explicitly assigned a "data" table attribute.
      auto* cell_elem = DynamicTo<HTMLTableCellElement>(*cell);
      if (cell_elem) {
        if (!cell_elem->Headers().empty() || !cell_elem->Abbr().empty() ||
            !cell_elem->Axis().empty() ||
            !cell_elem->FastGetAttribute(html_names::kScopeAttr).empty()) {
          return true;
        }
      }

      LayoutObject* cell_layout_object = cell->GetLayoutObject();
      if (!cell_layout_object || !cell_layout_object->IsLayoutBlock()) {
        continue;
      }

      const LayoutBlock* cell_layout_block =
          To<LayoutBlock>(cell_layout_object);
      if (cell_layout_block->Size().width < 1 ||
          cell_layout_block->Size().height < 1) {
        continue;
      }

      valid_cell_count++;

      const ComputedStyle* computed_style = cell_layout_block->Style();
      if (!computed_style) {
        continue;
      }

      // If the empty-cells style is set, we'll call it a data table.
      if (computed_style->EmptyCells() == EEmptyCells::kHide) {
        return true;
      }

      // If a cell has matching bordered sides, call it a (fully) bordered cell.
      if ((cell_layout_block->BorderTop() > 0 &&
           cell_layout_block->BorderBottom() > 0) ||
          (cell_layout_block->BorderLeft() > 0 &&
           cell_layout_block->BorderRight() > 0)) {
        bordered_cell_count++;
      }

      // Also keep track of each individual border, so we can catch tables where
      // most cells have a bottom border, for example.
      if (cell_layout_block->BorderTop() > 0) {
        cells_with_top_border++;
      }
      if (cell_layout_block->BorderBottom() > 0) {
        cells_with_bottom_border++;
      }
      if (cell_layout_block->BorderLeft() > 0) {
        cells_with_left_border++;
      }
      if (cell_layout_block->BorderRight() > 0) {
        cells_with_right_border++;
      }

      // If the cell has a different color from the table and there is cell
      // spacing, then it is probably a data table cell (spacing and colors take
      // the place of borders).
      Color cell_color = computed_style->VisitedDependentColor(
          GetCSSPropertyBackgroundColor());
      if (has_cell_spacing && table_bg_color != cell_color &&
          !cell_color.IsFullyTransparent()) {
        background_difference_cell_count++;
      }

      // If we've found 10 "good" cells, we don't need to keep searching.
      if (bordered_cell_count >= 10 || background_difference_cell_count >= 10) {
        return true;
      }

      // For the first 5 rows, cache the background color so we can check if
      // this table has zebra-striped rows.
      if (row < 5 && row == alternating_row_color_count) {
        LayoutObject* layout_row = cell_layout_block->Parent();
        if (!layout_row || !layout_row->IsBoxModelObject() ||
            !layout_row->IsTableRow()) {
          continue;
        }
        const ComputedStyle* row_computed_style = layout_row->Style();
        if (!row_computed_style) {
          continue;
        }
        Color row_color = row_computed_style->VisitedDependentColor(
            GetCSSPropertyBackgroundColor());
        alternating_row_colors[alternating_row_color_count] = row_color;
        alternating_row_color_count++;
      }
    }
  }

  // if there is less than two valid cells, it's not a data table
  if (valid_cell_count <= 1) {
    return false;
  }

  // half of the cells had borders, it's a data table
  unsigned needed_cell_count = valid_cell_count / 2;
  if (bordered_cell_count >= needed_cell_count ||
      cells_with_top_border >= needed_cell_count ||
      cells_with_bottom_border >= needed_cell_count ||
      cells_with_left_border >= needed_cell_count ||
      cells_with_right_border >= needed_cell_count) {
    return true;
  }

  // half had different background colors, it's a data table
  if (background_difference_cell_count >= needed_cell_count) {
    return true;
  }

  // Check if there is an alternating row background color indicating a zebra
  // striped style pattern.
  if (alternating_row_color_count > 2) {
    Color first_color = alternating_row_colors[0];
    for (int k = 1; k < alternating_row_color_count; k++) {
      // If an odd row was the same color as the first row, its not alternating.
      if (k % 2 == 1 && alternating_row_colors[k] == first_color) {
        return false;
      }
      // If an even row is not the same as the first row, its not alternating.
      if (!(k % 2) && alternating_row_colors[k] != first_color) {
        return false;
      }
    }
    return true;
  }

  return false;
}

// TODO(accessibility) Consider combining with NativeRoleIgnoringAria().
ax::mojom::blink::Role AXNodeObject::RoleFromLayoutObjectOrNode() const {
  if (!GetLayoutObject()) {
    return ax::mojom::blink::Role::kGenericContainer;
  }

  DCHECK(GetLayoutObject());

  if (GetLayoutObject()->IsListMarker()) {
    Node* list_item = GetLayoutObject()->GeneratingNode();
    if (list_item && ShouldIgnoreListItem(list_item)) {
      return ax::mojom::blink::Role::kNone;
    }
    return ax::mojom::blink::Role::kListMarker;
  }

  if (GetLayoutObject()->IsListItem()) {
    return ax::mojom::blink::Role::kListItem;
  }
  if (GetLayoutObject()->IsBR()) {
    return ax::mojom::blink::Role::kLineBreak;
  }
  if (GetLayoutObject()->IsText()) {
    return ax::mojom::blink::Role::kStaticText;
  }

  Node* node = GetNode();  // Can be null in the case of pseudo content.

  // Chrome exposes both table markup and table CSS as a tables, letting
  // the screen reader determine what to do for CSS tables. If this line
  // is reached, then it is not an HTML table, and therefore will only be
  // considered a data table if ARIA markup indicates it is a table.
  // Additionally, as pseudo elements don't have any structure it doesn't make
  // sense to report their table-related layout roles that could be set via the
  // display property.
  if (node && !node->IsPseudoElement()) {
    if (GetLayoutObject()->IsTable()) {
      return ax::mojom::blink::Role::kLayoutTable;
    }
    if (GetLayoutObject()->IsTableSection()) {
      return DetermineTableSectionRole();
    }
    if (GetLayoutObject()->IsTableRow()) {
      return DetermineTableRowRole();
    }
    if (GetLayoutObject()->IsTableCell()) {
      return DetermineTableCellRole();
    }
  }

  if (IsImageOrAltText(GetLayoutObject(), node)) {
    if (IsA<HTMLInputElement>(node)) {
      return ButtonRoleType();
    }
    return ax::mojom::blink::Role::kImage;
  }

  if (IsA<HTMLCanvasElement>(node)) {
    return ax::mojom::blink::Role::kCanvas;
  }

  if (IsA<LayoutView>(GetLayoutObject())) {
    return ParentObject() ? ax::mojom::blink::Role::kGroup
                          : ax::mojom::blink::Role::kRootWebArea;
  }

  if (node && node->IsSVGElement()) {
    if (GetLayoutObject()->IsSVGImage()) {
      return ax::mojom::blink::Role::kImage;
    }
    if (IsA<SVGSVGElement>(node)) {
      // Exposing a nested <svg> as a group (rather than a generic container)
      // increases the likelihood that an author-provided name will be presented
      // by assistive technologies. Note that this mapping is not yet in the
      // SVG-AAM, which currently maps all <svg> elements as graphics-document.
      // See https://github.com/w3c/svg-aam/issues/18.
      return GetLayoutObject()->IsSVGRoot() ? ax::mojom::blink::Role::kSvgRoot
                                            : ax::mojom::blink::Role::kGroup;
    }
    if (GetLayoutObject()->IsSVGShape()) {
      return ax::mojom::blink::Role::kGraphicsSymbol;
    }
    if (GetLayoutObject()->IsSVGForeignObject()) {
      return ax::mojom::blink::Role::kGroup;
    }
    if (IsA<SVGUseElement>(node)) {
      return ax::mojom::blink::Role::kGraphicsObject;
    }
  }

  if (GetLayoutObject()->IsHR()) {
    return ax::mojom::blink::Role::kSplitter;
  }

  // Minimum role:
  // TODO(accessibility) if (AXObjectCache().IsInternalUICheckerOn()) assert,
  // because it is a bad code smell and usually points to other problems.
  if (GetElement() && !HasAriaAttribute(html_names::kRoleAttr)) {
    if (IsPopup() != ax::mojom::blink::IsPopup::kNone ||
        GetElement()->FastHasAttribute(html_names::kAutofocusAttr) ||
        GetElement()->FastHasAttribute(html_names::kDraggableAttr)) {
      return ax::mojom::blink::Role::kGroup;
    }
    if (RuntimeEnabledFeatures::AccessibilityMinRoleTabbableEnabled()) {
      if (GetElement()->tabIndex() >= 0) {
        return ax::mojom::blink::Role::kGroup;
      }
    }
  }

  if (IsA<HTMLPermissionElement>(node)) {
    return ax::mojom::blink::Role::kButton;
  }

  // Anything that needs to be exposed but doesn't have a more specific role
  // should be considered a generic container. Examples are layout blocks with
  // no node, in-page link targets, and plain elements such as a <span> with
  // an aria- property.
  return ax::mojom::blink::Role::kGenericContainer;
}

// Does not check ARIA role, but does check some ARIA properties, specifically
// @aria-haspopup/aria-pressed via ButtonType().
ax::mojom::blink::Role AXNodeObject::NativeRoleIgnoringAria() const {
  if (!GetNode()) {
    // Can be null in the case of pseudo content.
    return RoleFromLayoutObjectOrNode();
  }

  if (GetNode()->IsPseudoElement() && GetCSSAltText(GetElement())) {
    const ComputedStyle* style = GetElement()->GetComputedStyle();
    ContentData* content_data = style->GetContentData();
    // We just check the first item of the content list to determine the
    // appropriate role, should only ever be image or text.
    // TODO(accessibility) Is it possible to use CSS alt text on an HTML tag
    // with strong semantics? If so, why are we overriding the role here?
    // We only need to ensure the accessible name gets the CSS alt text.
    // Note: by doing this, we are often hiding child pseudo element content
    // because IsRelevantPseudoElementDescendant() returns false when an
    // ancestor has CSS alt text.
    if (content_data->IsImage())
      return ax::mojom::blink::Role::kImage;

    return ax::mojom::blink::Role::kStaticText;
  }

  if (GetNode()->IsTextNode())
    return ax::mojom::blink::Role::kStaticText;

  if (IsA<HTMLImageElement>(GetNode()))
    return ax::mojom::blink::Role::kImage;

  // <a> or <svg:a>.
  if (IsA<HTMLAnchorElement>(GetNode()) || IsA<SVGAElement>(GetNode())) {
    // Assume that an anchor element is a Role::kLink if it has an href or a
    // click event listener.
    if (GetNode()->IsLink() ||
        GetNode()->HasAnyEventListeners(event_util::MouseButtonEventTypes())) {
      return ax::mojom::blink::Role::kLink;
    }

    // According to the SVG-AAM, a non-link 'a' element should be exposed like
    // a 'g' if it does not descend from a 'text' element and like a 'tspan'
    // if it does. This is consistent with the SVG spec which states that an
    // 'a' within 'text' acts as an inline element, whereas it otherwise acts
    // as a container element.
    if (IsA<SVGAElement>(GetNode()) &&
        !Traversal<SVGTextElement>::FirstAncestor(*GetNode())) {
      return ax::mojom::blink::Role::kGroup;
    }

    return ax::mojom::blink::Role::kGenericContainer;
  }

  if (IsA<SVGGElement>(*GetNode())) {
    return ax::mojom::blink::Role::kGroup;
  }

  if (IsA<HTMLButtonElement>(*GetNode()))
    return ButtonRoleType();

  if (IsA<HTMLDetailsElement>(*GetNode()))
    return ax::mojom::blink::Role::kDetails;

  if (IsA<HTMLSummaryElement>(*GetNode())) {
    ContainerNode* parent = LayoutTreeBuilderTraversal::Parent(*GetNode());
    if (ToHTMLSlotElementIfSupportsAssignmentOrNull(parent))
      parent = LayoutTreeBuilderTraversal::Parent(*parent);
    if (HTMLDetailsElement* parent_details =
            DynamicTo<HTMLDetailsElement>(parent)) {
      if (parent_details->GetName().empty()) {
        return ax::mojom::blink::Role::kDisclosureTriangle;
      } else {
        return ax::mojom::blink::Role::kDisclosureTriangleGrouped;
      }
    }
    return ax::mojom::blink::Role::kGenericContainer;
  }

  // Chrome exposes both table markup and table CSS as a table, letting
  // the screen reader determine what to do for CSS tables.
  if (IsA<HTMLTableElement>(*GetNode())) {
    if (IsDataTable())
      return ax::mojom::blink::Role::kTable;
    else
      return ax::mojom::blink::Role::kLayoutTable;
  }
  if (IsA<HTMLTableRowElement>(*GetNode()))
    return DetermineTableRowRole();
  if (IsA<HTMLTableCellElement>(*GetNode()))
    return DetermineTableCellRole();
  if (IsA<HTMLTableSectionElement>(*GetNode()))
    return DetermineTableSectionRole();

  if (const auto* input = DynamicTo<HTMLInputElement>(*GetNode())) {
    FormControlType type = input->FormControlType();
    if (input->DataList() && type != FormControlType::kInputColor) {
      return ax::mojom::blink::Role::kTextFieldWithComboBox;
    }
    switch (type) {
      case FormControlType::kInputButton:
      case FormControlType::kInputReset:
      case FormControlType::kInputSubmit:
        return ButtonRoleType();
      case FormControlType::kInputCheckbox:
        return ax::mojom::blink::Role::kCheckBox;
      case FormControlType::kInputDate:
        return ax::mojom::blink::Role::kDate;
      case FormControlType::kInputDatetimeLocal:
      case FormControlType::kInputMonth:
      case FormControlType::kInputWeek:
        return ax::mojom::blink::Role::kDateTime;
      case FormControlType::kInputFile:
        return ax::mojom::blink::Role::kButton;
      case FormControlType::kInputRadio:
        return ax::mojom::blink::Role::kRadioButton;
      case FormControlType::kInputNumber:
        return ax::mojom::blink::Role::kSpinButton;
      case FormControlType::kInputRange:
        return ax::mojom::blink::Role::kSlider;
      case FormControlType::kInputSearch:
        return ax::mojom::blink::Role::kSearchBox;
      case FormControlType::kInputColor:
        return ax::mojom::blink::Role::kColorWell;
      case FormControlType::kInputTime:
        return ax::mojom::blink::Role::kInputTime;
      case FormControlType::kInputImage:
        return ax::mojom::blink::Role::kButton;
      default:
        return ax::mojom::blink::Role::kTextField;
    }
  }

  if (auto* select_element = DynamicTo<HTMLSelectElement>(*GetNode())) {
    if (select_element->UsesMenuList() && !select_element->IsMultiple()) {
      return ax::mojom::blink::Role::kComboBoxSelect;
    } else {
      return ax::mojom::blink::Role::kListBox;
    }
  }

  if (ParentObjectIfPresent() && ParentObjectIfPresent()->RoleValue() ==
                                     ax::mojom::blink::Role::kComboBoxSelect) {
    return ax::mojom::blink::Role::kMenuListPopup;
  }

  if (auto* option = DynamicTo<HTMLOptionElement>(*GetNode())) {
    HTMLSelectElement* select_element = option->OwnerSelectElement();
    if (select_element && select_element->UsesMenuList() &&
        !select_element->IsMultiple()) {
      return ax::mojom::blink::Role::kMenuListOption;
    } else {
      return ax::mojom::blink::Role::kListBoxOption;
    }
  }

  if (IsA<HTMLOptGroupElement>(GetNode())) {
    return ax::mojom::blink::Role::kGroup;
  }

  if (IsA<HTMLTextAreaElement>(*GetNode()))
    return ax::mojom::blink::Role::kTextField;

  if (HeadingLevel())
    return ax::mojom::blink::Role::kHeading;

  if (IsA<HTMLDivElement>(*GetNode()))
    return RoleFromLayoutObjectOrNode();

  if (IsA<HTMLMenuElement>(*GetNode()) || IsA<HTMLUListElement>(*GetNode()) ||
      IsA<HTMLOListElement>(*GetNode())) {
    // <menu> is a deprecated feature of HTML 5, but is included for semantic
    // compatibility with HTML3, and may contain list items. Exposing it as an
    // unordered list works better than the current HTML-AAM recommendaton of
    // exposing as a role=menu, because if it's just used semantically, it won't
    // be interactive. If used as a widget, the author must provide role=menu.
    return ax::mojom::blink::Role::kList;
  }

  if (IsA<HTMLLIElement>(*GetNode())) {
    if (ShouldIgnoreListItem(GetNode())) {
      return ax::mojom::blink::Role::kNone;
    }
    return ax::mojom::blink::Role::kListItem;
  }

  if (IsA<HTMLMeterElement>(*GetNode()))
    return ax::mojom::blink::Role::kMeter;

  if (IsA<HTMLProgressElement>(*GetNode()))
    return ax::mojom::blink::Role::kProgressIndicator;

  if (IsA<HTMLOutputElement>(*GetNode()))
    return ax::mojom::blink::Role::kStatus;

  if (IsA<HTMLParagraphElement>(*GetNode()))
    return ax::mojom::blink::Role::kParagraph;

  if (IsA<HTMLLabelElement>(*GetNode()))
    return ax::mojom::blink::Role::kLabelText;

  if (IsA<HTMLLegendElement>(*GetNode()))
    return ax::mojom::blink::Role::kLegend;

  if (GetNode()->HasTagName(html_names::kRubyTag)) {
    return ax::mojom::blink::Role::kRuby;
  }

  if (IsA<HTMLDListElement>(*GetNode()))
    return ax::mojom::blink::Role::kDescriptionList;

  if (IsA<HTMLDirectoryElement>(*GetNode())) {
    return ax::mojom::blink::Role::kList;
  }

  if (IsA<HTMLAudioElement>(*GetNode()))
    return ax::mojom::blink::Role::kAudio;
  if (IsA<HTMLVideoElement>(*GetNode()))
    return ax::mojom::blink::Role::kVideo;

  if (GetNode()->HasTagName(html_names::kDdTag))
    return ax::mojom::blink::Role::kDefinition;

  if (GetNode()->HasTagName(html_names::kDfnTag))
    return ax::mojom::blink::Role::kTerm;

  if (GetNode()->HasTagName(html_names::kDtTag))
    return ax::mojom::blink::Role::kTerm;

  // Mapping of MathML elements. See https://w3c.github.io/mathml-aam/
  if (auto* element = DynamicTo<MathMLElement>(GetNode())) {
    if (element->HasTagName(mathml_names::kMathTag)) {
      return ax::mojom::blink::Role::kMathMLMath;
    }
    if (element->HasTagName(mathml_names::kMfracTag))
      return ax::mojom::blink::Role::kMathMLFraction;
    if (element->HasTagName(mathml_names::kMiTag))
      return ax::mojom::blink::Role::kMathMLIdentifier;
    if (element->HasTagName(mathml_names::kMmultiscriptsTag))
      return ax::mojom::blink::Role::kMathMLMultiscripts;
    if (element->HasTagName(mathml_names::kMnTag))
      return ax::mojom::blink::Role::kMathMLNumber;
    if (element->HasTagName(mathml_names::kMoTag))
      return ax::mojom::blink::Role::kMathMLOperator;
    if (element->HasTagName(mathml_names::kMoverTag))
      return ax::mojom::blink::Role::kMathMLOver;
    if (element->HasTagName(mathml_names::kMunderTag))
      return ax::mojom::blink::Role::kMathMLUnder;
    if (element->HasTagName(mathml_names::kMunderoverTag))
      return ax::mojom::blink::Role::kMathMLUnderOver;
    if (element->HasTagName(mathml_names::kMrootTag))
      return ax::mojom::blink::Role::kMathMLRoot;
    if (element->HasTagName(mathml_names::kMrowTag) ||
        element->HasTagName(mathml_names::kAnnotationXmlTag) ||
        element->HasTagName(mathml_names::kMactionTag) ||
        element->HasTagName(mathml_names::kMerrorTag) ||
        element->HasTagName(mathml_names::kMpaddedTag) ||
        element->HasTagName(mathml_names::kMphantomTag) ||
        element->HasTagName(mathml_names::kMstyleTag) ||
        element->HasTagName(mathml_names::kSemanticsTag)) {
      return ax::mojom::blink::Role::kMathMLRow;
    }
    if (element->HasTagName(mathml_names::kMprescriptsTag))
      return ax::mojom::blink::Role::kMathMLPrescriptDelimiter;
    if (element->HasTagName(mathml_names::kNoneTag))
      return ax::mojom::blink::Role::kMathMLNoneScript;
    if (element->HasTagName(mathml_names::kMsqrtTag))
      return ax::mojom::blink::Role::kMathMLSquareRoot;
    if (element->HasTagName(mathml_names::kMsTag))
      return ax::mojom::blink::Role::kMathMLStringLiteral;
    if (element->HasTagName(mathml_names::kMsubTag))
      return ax::mojom::blink::Role::kMathMLSub;
    if (element->HasTagName(mathml_names::kMsubsupTag))
      return ax::mojom::blink::Role::kMathMLSubSup;
    if (element->HasTagName(mathml_names::kMsupTag))
      return ax::mojom::blink::Role::kMathMLSup;
    if (element->HasTagName(mathml_names::kMtableTag))
      return ax::mojom::blink::Role::kMathMLTable;
    if (element->HasTagName(mathml_names::kMtdTag))
      return ax::mojom::blink::Role::kMathMLTableCell;
    if (element->HasTagName(mathml_names::kMtrTag))
      return ax::mojom::blink::Role::kMathMLTableRow;
    if (element->HasTagName(mathml_names::kMtextTag) ||
        element->HasTagName(mathml_names::kAnnotationTag)) {
      return ax::mojom::blink::Role::kMathMLText;
    }
  }

  if (GetNode()->HasTagName(html_names::kRpTag) ||
      GetNode()->HasTagName(html_names::kRtTag)) {
    return ax::mojom::blink::Role::kRubyAnnotation;
  }

  if (IsA<HTMLFormElement>(*GetNode())) {
    // Only treat <form> as role="form" when it has an accessible name, which
    // can only occur when the name is assigned by the author via aria-label,
    // aria-labelledby, or title. Otherwise, treat as a <section>.
    return IsNameFromAuthorAttribute() ? ax::mojom::blink::Role::kForm
                                       : ax::mojom::blink::Role::kSection;
  }

  if (GetNode()->HasTagName(html_names::kAbbrTag))
    return ax::mojom::blink::Role::kAbbr;

  if (GetNode()->HasTagName(html_names::kArticleTag))
    return ax::mojom::blink::Role::kArticle;

  if (GetNode()->HasTagName(html_names::kCodeTag))
    return ax::mojom::blink::Role::kCode;

  if (GetNode()->HasTagName(html_names::kEmTag))
    return ax::mojom::blink::Role::kEmphasis;

  if (GetNode()->HasTagName(html_names::kStrongTag))
    return ax::mojom::blink::Role::kStrong;

  if (GetNode()->HasTagName(html_names::kSearchTag)) {
    return ax::mojom::blink::Role::kSearch;
  }

  if (GetNode()->HasTagName(html_names::kDelTag) ||
      GetNode()->HasTagName(html_names::kSTag)) {
    return ax::mojom::blink::Role::kContentDeletion;
  }

  if (GetNode()->HasTagName(html_names::kInsTag))
    return ax::mojom::blink::Role::kContentInsertion;

  if (GetNode()->HasTagName(html_names::kSubTag))
    return ax::mojom::blink::Role::kSubscript;

  if (GetNode()->HasTagName(html_names::kSupTag))
    return ax::mojom::blink::Role::kSuperscript;

  if (GetNode()->HasTagName(html_names::kMainTag))
    return ax::mojom::blink::Role::kMain;

  if (GetNode()->HasTagName(html_names::kMarkTag))
    return ax::mojom::blink::Role::kMark;

  if (GetNode()->HasTagName(html_names::kNavTag))
    return ax::mojom::blink::Role::kNavigation;

  if (GetNode()->HasTagName(html_names::kAsideTag))
    return ax::mojom::blink::Role::kComplementary;

  if (GetNode()->HasTagName(html_names::kSectionTag)) {
    return ax::mojom::blink::Role::kSection;
  }

  if (GetNode()->HasTagName(html_names::kAddressTag))
    return ax::mojom::blink::Role::kGroup;

  if (GetNode()->HasTagName(html_names::kHgroupTag)) {
    return ax::mojom::blink::Role::kGroup;
  }

  if (IsA<HTMLDialogElement>(*GetNode()))
    return ax::mojom::blink::Role::kDialog;

  // The HTML element.
  if (IsA<HTMLHtmlElement>(GetNode()))
    return ax::mojom::blink::Role::kGenericContainer;

  // Treat <iframe>, <frame> and <fencedframe> the same.
  if (IsFrame(GetNode()))
    return ax::mojom::blink::Role::kIframe;

  if (GetNode()->HasTagName(html_names::kHeaderTag)) {
    return ax::mojom::blink::Role::kHeader;
  }

  if (GetNode()->HasTagName(html_names::kFooterTag)) {
    return ax::mojom::blink::Role::kFooter;
  }

  if (GetNode()->HasTagName(html_names::kBlockquoteTag))
    return ax::mojom::blink::Role::kBlockquote;

  if (IsA<HTMLTableCaptionElement>(GetNode()))
    return ax::mojom::blink::Role::kCaption;

  if (GetNode()->HasTagName(html_names::kFigcaptionTag))
    return ax::mojom::blink::Role::kFigcaption;

  if (GetNode()->HasTagName(html_names::kFigureTag))
    return ax::mojom::blink::Role::kFigure;

  if (IsA<HTMLTimeElement>(GetNode()))
    return ax::mojom::blink::Role::kTime;

  if (IsA<HTMLPlugInElement>(GetNode())) {
    if (IsA<HTMLEmbedElement>(GetNode()))
      return ax::mojom::blink::Role::kEmbeddedObject;
    return ax::mojom::blink::Role::kPluginObject;
  }

  if (IsA<HTMLHRElement>(*GetNode()))
    return ax::mojom::blink::Role::kSplitter;

  if (IsFieldset())
    return ax::mojom::blink::Role::kGroup;

  return RoleFromLayoutObjectOrNode();
}

ax::mojom::blink::Role AXNodeObject::DetermineRoleValue() {
#if DCHECK_IS_ON()
  base::AutoReset<bool> reentrancy_protector(&is_computing_role_, true);
#endif

  if (IsDetached()) {
    NOTREACHED() << "Do not compute role on detached object: " << this;
  }

  native_role_ = NativeRoleIgnoringAria();

  aria_role_ = DetermineAriaRole();

  return aria_role_ == ax::mojom::blink::Role::kUnknown ? native_role_
                                                        : aria_role_;
}

static Element* SiblingWithAriaRole(String role, Node* node) {
  Node* parent = LayoutTreeBuilderTraversal::Parent(*node);
  if (!parent)
    return nullptr;

  for (Node* sibling = LayoutTreeBuilderTraversal::FirstChild(*parent); sibling;
       sibling = LayoutTreeBuilderTraversal::NextSibling(*sibling)) {
    auto* element = DynamicTo<Element>(sibling);
    if (!element)
      continue;
    const AtomicString& sibling_aria_role =
        blink::AXObject::AriaAttribute(*element, html_names::kRoleAttr);
    if (EqualIgnoringASCIICase(sibling_aria_role, role))
      return element;
  }

  return nullptr;
}

Element* AXNodeObject::MenuItemElementForMenu() const {
  if (RawAriaRole() != ax::mojom::blink::Role::kMenu) {
    return nullptr;
  }

  return SiblingWithAriaRole("menuitem", GetNode());
}

void AXNodeObject::Init(AXObject* parent) {
#if DCHECK_IS_ON()
  DCHECK(!initialized_);
  initialized_ = true;
#endif
  AXObject::Init(parent);

  DCHECK(role_ == native_role_ || role_ == aria_role_)
      << "Role must be either the cached native role or cached aria role: "
      << "\n* Final role: " << role_ << "\n* Native role: " << native_role_
      << "\n* Aria role: " << aria_role_ << "\n* Node: " << GetNode();

  DCHECK(node_ || (GetLayoutObject() &&
                   AXObjectCacheImpl::IsRelevantPseudoElementDescendant(
                       *GetLayoutObject())))
      << "Nodeless AXNodeObject can only exist inside a pseudo element: "
      << GetLayoutObject();
}

void AXNodeObject::Detach() {
#if defined(AX_FAIL_FAST_BUILD)
  SANITIZER_CHECK(!is_adding_children_)
      << "Cannot detach |this| during AddChildren(): " << GetNode();
#endif
  AXObject::Detach();
  node_ = nullptr;
#if DCHECK_IS_ON()
  if (layout_object_) {
    layout_object_->SetHasAXObject(false);
  }
#endif
  layout_object_ = nullptr;
}

bool AXNodeObject::IsAXNodeObject() const {
  return true;
}

bool AXNodeObject::IsControl() const {
  Node* node = GetNode();
  if (!node)
    return false;

  auto* element = DynamicTo<Element>(node);
  return ((element && element->IsFormControlElement()) ||
          ui::IsControl(RawAriaRole()));
}

bool AXNodeObject::IsAutofillAvailable() const {
  // Autofill suggestion availability is stored in AXObjectCache.
  WebAXAutofillSuggestionAvailability suggestion_availability =
      AXObjectCache().GetAutofillSuggestionAvailability(AXObjectID());
  return suggestion_availability ==
         WebAXAutofillSuggestionAvailability::kAutofillAvailable;
}

bool AXNodeObject::IsDefault() const {
  if (IsDetached())
    return false;

  // Checks for any kind of disabled, including aria-disabled.
  if (Restriction() == kRestrictionDisabled ||
      RoleValue() != ax::mojom::blink::Role::kButton) {
    return false;
  }

  // Will only match :default pseudo class if it's the first default button in
  // a form.
  return GetElement()->MatchesDefaultPseudoClass();
}

bool AXNodeObject::IsFieldset() const {
  return IsA<HTMLFieldSetElement>(GetNode());
}

bool AXNodeObject::IsHovered() const {
  if (Node* node = GetNode())
    return node->IsHovered();
  return false;
}

bool AXNodeObject::IsImageButton() const {
  return IsNativeImage() && IsButton();
}

bool AXNodeObject::IsInputImage() const {
  auto* html_input_element = DynamicTo<HTMLInputElement>(GetNode());
  if (html_input_element && RoleValue() == ax::mojom::blink::Role::kButton) {
    return html_input_element->FormControlType() ==
           FormControlType::kInputImage;
  }

  return false;
}

bool AXNodeObject::IsLineBreakingObject() const {
  // According to Blink Editing, objects without an associated DOM node such as
  // pseudo-elements and list bullets, are never considered as paragraph
  // boundaries.
  if (IsDetached() || !GetNode())
    return false;

  // Presentational objects should not contribute any of their semantic meaning
  // to the accessibility tree, including to its text representation.
  if (IsPresentational())
    return false;

  // `IsEnclosingBlock` includes all elements with display block, inline block,
  // table related, flex, grid, list item, flow-root, webkit-box, and display
  // contents. This is the same function used by Blink > Editing for determining
  // paragraph boundaries, i.e. line breaking objects.
  if (IsEnclosingBlock(GetNode()))
    return true;

  // Not all <br> elements have an associated layout object. They might be
  // "visibility: hidden" or within a display locked region. We need to check
  // their DOM node first.
  if (IsA<HTMLBRElement>(GetNode()))
    return true;

  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object)
    return AXObject::IsLineBreakingObject();

  if (layout_object->IsBR())
    return true;

  // LayoutText objects could include a paragraph break in their text.
```