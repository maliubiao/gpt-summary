Response:
Let's break down the thought process for analyzing this C++ source file.

1. **Understand the Core Purpose:**  The file name `grid_focusgroup_structure_info.cc` and the namespace `blink` immediately suggest this is related to how focus works within grid-like structures in the Blink rendering engine (used by Chromium). The term "focusgroup" hints at accessibility and keyboard navigation.

2. **Identify Key Classes and Data Structures:** The presence of `AutomaticGridFocusgroupStructureInfo` as the main class is the first clue. The constructor takes a `LayoutObject*`, and the class members mention `LayoutTable* table_`. This points towards the layout tree representation of HTML elements. The inclusion of headers like `html_table_cell_element.h`, `html_table_element.h`, etc., confirms the focus is specifically on HTML tables.

3. **Analyze Public Methods:**  Reading through the public methods provides a good overview of the class's functionality:
    * `ColumnCount()`:  Gets the number of columns.
    * `PreviousCellInRow()`, `NextCellInRow()`, `FirstCellInRow()`, `LastCellInRow()`: Methods for navigating cells within a row.
    * `PreviousCellInColumn()`, `NextCellInColumn()`, `FirstCellInColumn()`, `LastCellInColumn()`: Methods for navigating cells within a column.
    * `PreviousRow()`, `NextRow()`, `FirstRow()`, `LastRow()`: Methods for navigating rows.
    * `RowForCell()`: Gets the row containing a specific cell.
    * `CellAtIndexInRow()`: Gets a cell at a specific index within a row.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, the crucial step is to link these methods to web technologies.
    * **HTML:** The class clearly deals with the structure of HTML tables (`<table>`, `<tr>`, `<td>`, `<th>`). The navigation functions directly relate to how a user would move focus within a table.
    * **CSS:**  While the file doesn't directly *process* CSS, it operates on the *layout* of elements, which is heavily influenced by CSS. CSS grid layout also comes to mind as a related, but distinct, technology. However, the presence of "grid" in the filename suggests it *might* handle both tables and CSS grids, although the included headers lean heavily towards tables. *Self-correction: Initially I might have overemphasized CSS Grid, but the headers and method names strongly point to HTML tables as the primary focus.*
    * **JavaScript:**  JavaScript can programmatically manipulate focus. This class provides the *underlying logic* that the browser uses when JavaScript calls methods like `element.focus()`. JavaScript event listeners can trigger focus changes that eventually utilize this code.

5. **Infer Logic and Assumptions:** The method implementations, especially `CellAtIndexInRowRecursive`, reveal the complexity of handling `colspan` and `rowspan`. The code needs to account for cells spanning multiple rows or columns when determining the "next" or "previous" cell. The `NoCellFoundAtIndexBehavior` enum shows different strategies for handling cases where the requested cell doesn't directly exist.

6. **Consider User and Programming Errors:**
    * **User Errors:** Incorrect HTML structure (e.g., missing `<td>` within a `<tr>`) could lead to unexpected behavior in focus navigation. Overlapping `colspan` or `rowspan` values might also cause issues.
    * **Programming Errors:**  A JavaScript developer might make incorrect assumptions about focus order and might not handle edge cases (e.g., tables with complex spanning). The debugging section highlights how a developer might step through this code to understand focus behavior.

7. **Construct Examples:**  Concrete HTML and CSS examples help illustrate the functionality. Showing tables with `colspan` and `rowspan` demonstrates the need for the complex logic in the C++ code.

8. **Explain the Debugging Process:**  Describe how a developer might arrive at this code. Tracing focus changes through browser developer tools and then stepping into the Blink source code are key steps. Mentioning the `// Copyright 2022` line provides context about the recency of the code.

9. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Start with the main function, then discuss relationships to web technologies, logic, errors, and finally debugging.

10. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I focused a lot on CSS Grid, but the code leans more towards HTML tables. Correcting this emphasis improves accuracy. Also ensuring a clear distinction between HTML table structure and CSS styling influence is important.
This C++ source file, `grid_focusgroup_structure_info.cc`, within the Chromium Blink rendering engine, is responsible for providing information about the structure of HTML tables to assist with **focus navigation** within those tables. Specifically, it helps determine the next or previous focusable element within a table when using keyboard navigation (like pressing Tab or Shift+Tab).

Here's a breakdown of its functionality:

**Core Functionality:**

* **Abstraction of Table Structure for Focus:**  The primary goal is to represent the logical grid structure of an HTML table (including `<table>`, `<tr>`, `<td>`/`<th>`) in a way that facilitates moving focus between cells. This involves understanding the impact of `colspan` and `rowspan` attributes.
* **Navigation Logic:** It provides methods to find the:
    * Previous/next cell within the same row.
    * First/last cell within a row.
    * Previous/next cell within the same column.
    * First/last cell within a column.
    * Previous/next row.
    * First/last row.
    * The row containing a specific cell.
    * A cell at a specific index within a row, taking into account `colspan` and `rowspan`.
* **Handling Spanning Cells:** A significant part of the logic deals with the complexities introduced by `colspan` and `rowspan`, ensuring that focus moves correctly even when cells occupy multiple rows or columns.

**Relationship to JavaScript, HTML, and CSS:**

* **HTML:** This file directly interacts with the underlying representation of HTML tables. It uses Blink's internal DOM structures (`Element`, `HTMLTableElement`, `HTMLTableRowElement`, `HTMLTableCellElement`) and layout objects (`LayoutTable`, `LayoutTableRow`, `LayoutTableCell`) to understand the table's structure.
    * **Example:** When `NextCellInRow` is called on a `<td>` element, this code examines the `colspan` attribute of that cell to determine how many columns to skip to find the next cell in the row.
* **CSS:** While this file doesn't directly parse or interpret CSS, it operates on the *layout* of the table, which is heavily influenced by CSS. CSS properties like `display: grid` are *not* the focus here; this code is specifically for HTML `<table>` elements. However, CSS can affect the *visibility* of elements, and focus behavior might be influenced by whether elements are visible or hidden (though this file primarily focuses on the structural aspect).
    * **Example:** If CSS is used to hide a `<td>` element (`display: none` or `visibility: hidden`), this code might still consider it part of the table structure, but the focus management logic *higher up* in the browser might skip over hidden elements.
* **JavaScript:** JavaScript can trigger focus changes and interact with the focus API. This C++ code provides the *underlying mechanism* that the browser uses when JavaScript code attempts to move focus within a table. For instance:
    * **Example:** If a JavaScript event listener is attached to a table cell and calls `nextElementSibling.focus()`, the browser's focus management system might utilize the logic in this file to determine the appropriate `nextElementSibling` within the table's grid structure.
    * **Example:** Accessibility libraries or custom JavaScript focus management might rely on the browser's ability to correctly navigate tables, which depends on code like this.

**Logic and Assumptions with Input/Output Examples:**

Let's consider the `NextCellInRow` function:

**Assumption:** The input `cell_element` is a valid `<td>` or `<th>` element within a table.

**Input:** A pointer to an `Element` representing a table cell.

**Logical Steps:**

1. **Get Layout Object:**  Retrieves the `LayoutTableCell` associated with the input `Element`.
2. **Check for Errors:** If it's not a `LayoutTableCell`, return `nullptr`.
3. **Get `colspan`:** Retrieves the `colspan` attribute value of the cell.
4. **Handle `colspan=0`:** If `colspan` is 0, it means the cell spans all remaining columns in the row, so there's no "next" cell within the row. Return `nullptr`.
5. **Get Row:** Retrieves the `LayoutTableRow` containing the cell.
6. **Check for Errors:** If there's no row, return `nullptr`.
7. **Get Row Element:** Retrieves the `Element` representing the row.
8. **Call `CellAtIndexInRow`:** Calls the `CellAtIndexInRow` function with the calculated index (`cell->AbsoluteColumnIndex() + col_span`) to find the next cell.

**Output:** A pointer to the `Element` representing the next cell in the row, or `nullptr` if there is no next cell.

**Example:**

```html
<table>
  <tr>
    <td id="cell1">Cell 1</td>
    <td id="cell2" colspan="2">Cell 2 (spans 2 columns)</td>
    <td id="cell4">Cell 4</td>
  </tr>
</table>
```

**Input:** The `Element` corresponding to `#cell1`.

**Processing in `NextCellInRow`:**

1. `cell` will be the `LayoutTableCell` for `#cell1`.
2. `col_span` for `#cell1` is implicitly 1.
3. `row` will be the `LayoutTableRow` for the first row.
4. `CellAtIndexInRow` will be called with index `0 + 1 = 1`.
5. `CellAtIndexInRow` will correctly identify the `Element` for `#cell2`.

**Output:** The `Element` corresponding to `#cell2`.

**User or Programming Common Usage Errors:**

* **Incorrect HTML Structure:** If the HTML table structure is invalid (e.g., `<td>` elements not within `<tr>`, missing closing tags), this code might produce unexpected results or even crash.
    * **Example:**  A `<td>` directly under a `<table>` without a `<tr>` would violate the expected structure.
* **JavaScript Assumptions about Focus Order:** Developers might make incorrect assumptions about how focus moves through tables, especially when `colspan` and `rowspan` are involved. Relying on simple `nextElementSibling` might not work correctly for table navigation.
    * **Example:** A developer might assume that after focusing on the first cell, calling `nextElementSibling.focus()` will always move to the visually adjacent cell, which isn't true if the first cell has a `colspan`.
* **CSS Interfering with Expected Structure:** While this code focuses on the underlying structure, overly complex CSS manipulations that visually reorder table elements could confuse users and potentially lead to unexpected focus behavior (though the core logic here would still operate on the DOM order).

**User Operations Leading to This Code (Debugging Clues):**

A user's interaction with a webpage containing a table can lead to this code being executed. Here's a possible sequence:

1. **Page Load:** The browser parses the HTML, including the `<table>` element.
2. **Layout:** The Blink rendering engine calculates the layout of the table, creating `LayoutTable`, `LayoutTableRow`, and `LayoutTableCell` objects.
3. **Focus Interaction:** The user interacts with the page, potentially by:
    * **Clicking on a table cell:** This sets the focus to that cell.
    * **Using the Tab key:**  The user presses the Tab key to move focus to the next focusable element. If the current focus is within a table, the browser will need to determine the next focusable element *within the table's grid structure*.
    * **Using the Shift+Tab key:** The user presses Shift+Tab to move focus to the previous focusable element.
    * **Using arrow keys (in some cases):**  Depending on the browser and the context, arrow keys might be used for navigation within certain table-like structures.
4. **Focus Management:** The browser's focus management system detects the focus change request.
5. **`GridFocusgroupStructureInfo` Invocation:** When the browser needs to determine the next or previous focusable element within a table, it will likely create an instance of `AutomaticGridFocusgroupStructureInfo` for that table.
6. **Navigation Method Calls:** Based on the user's action (Tab, Shift+Tab), the browser will call methods like `NextCellInRow`, `PreviousCellInColumn`, etc., on the `AutomaticGridFocusgroupStructureInfo` object.
7. **Calculation and Result:** This code performs the calculations described above to identify the next or previous focusable element.
8. **Focus Update:** The browser updates the focus to the determined element.

**Debugging Scenario:**

A web developer might encounter a situation where focus navigation within a complex table is not working as expected. To debug this, they might:

1. **Use Browser Developer Tools:** Inspect the HTML structure of the table and identify any potential issues with `colspan` or `rowspan`.
2. **Set Breakpoints in JavaScript:**  Place breakpoints in their JavaScript code that handles focus or interacts with the DOM around the table.
3. **Step Through Browser Source Code:** If the issue seems to be with the browser's internal focus management, they might delve into the Chromium source code (like `grid_focusgroup_structure_info.cc`) to understand how the browser is determining the next focusable element. They might set breakpoints within the C++ code to observe the values of variables and the execution flow.

The `// Copyright 2022` at the top indicates that this file has been recently updated, suggesting ongoing maintenance and development of this part of the Blink rendering engine.

Prompt: 
```
这是目录为blink/renderer/core/page/grid_focusgroup_structure_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/grid_focusgroup_structure_info.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focusgroup_flags.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"

namespace blink {

AutomaticGridFocusgroupStructureInfo::AutomaticGridFocusgroupStructureInfo(
    LayoutObject* root)
    : table_(root) {
  DCHECK(Table());
  DCHECK(Flags() & FocusgroupFlags::kGrid);
}

void AutomaticGridFocusgroupStructureInfo::Trace(Visitor* visitor) const {
  visitor->Trace(table_);
}

const LayoutTable* AutomaticGridFocusgroupStructureInfo::Table() {
  CHECK(table_->IsTable());
  return To<LayoutTable>(table_.Get());
}

Element* AutomaticGridFocusgroupStructureInfo::Root() {
  return DynamicTo<Element>(table_->GetNode());
}

FocusgroupFlags AutomaticGridFocusgroupStructureInfo::Flags() {
  return Root()->GetFocusgroupFlags();
}

unsigned AutomaticGridFocusgroupStructureInfo::ColumnCount() {
  // The actual column count of a table is not stored on an HTMLTableElement,
  // but it is on its associated layout object.
  return Table()->EffectiveColumnCount();
}

Element* AutomaticGridFocusgroupStructureInfo::PreviousCellInRow(
    const Element* cell_element) {
  DCHECK(cell_element);
  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell)
    return nullptr;

  auto* row = cell->Row();
  if (!row)
    return nullptr;

  Element* row_element = DynamicTo<Element>(row->GetNode());
  if (!row_element)
    return nullptr;

  return CellAtIndexInRow(cell->AbsoluteColumnIndex() - 1, row_element,
                          NoCellFoundAtIndexBehavior::kFindPreviousCellInRow);
}

Element* AutomaticGridFocusgroupStructureInfo::NextCellInRow(
    const Element* cell_element) {
  DCHECK(cell_element);
  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell)
    return nullptr;

  unsigned col_span = cell->ColSpan();
  if (col_span == 0) {
    // A colspan value of 0 means that all cells in the row are part of the same
    // cell. In this case, there can't be a next cell.
    return nullptr;
  }

  auto* row = cell->Row();
  if (!row)
    return nullptr;

  Element* row_element = DynamicTo<Element>(row->GetNode());
  if (!row_element)
    return nullptr;

  return CellAtIndexInRow(cell->AbsoluteColumnIndex() + col_span, row_element,
                          NoCellFoundAtIndexBehavior::kFindNextCellInRow);
}

Element* AutomaticGridFocusgroupStructureInfo::FirstCellInRow(Element* row) {
  DCHECK(row);
  if (!IsA<LayoutTableRow>(row->GetLayoutObject())) {
    return nullptr;
  }

  return CellAtIndexInRow(0, row,
                          NoCellFoundAtIndexBehavior::kFindNextCellInRow);
}

Element* AutomaticGridFocusgroupStructureInfo::LastCellInRow(Element* row) {
  DCHECK(row);
  if (!IsA<LayoutTableRow>(row->GetLayoutObject())) {
    return nullptr;
  }

  return CellAtIndexInRow(ColumnCount() - 1, row,
                          NoCellFoundAtIndexBehavior::kFindPreviousCellInRow);
}

unsigned AutomaticGridFocusgroupStructureInfo::ColumnIndexForCell(
    const Element* cell_element) {
  DCHECK(cell_element);

  // The actual column index takes into account the previous rowspan/colspan
  // values that might affect this cell's col index.
  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell)
    return 0;

  return cell->AbsoluteColumnIndex();
}

Element* AutomaticGridFocusgroupStructureInfo::PreviousCellInColumn(
    const Element* cell_element) {
  DCHECK(cell_element);
  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell) {
    return nullptr;
  }

  auto* row = cell->Row();
  if (!row)
    return nullptr;

  auto* previous_row = PreviousRow(row);
  if (!previous_row)
    return nullptr;

  auto* previous_row_element = DynamicTo<Element>(previous_row->GetNode());
  if (!previous_row_element)
    return nullptr;

  return CellAtIndexInRow(
      cell->AbsoluteColumnIndex(), previous_row_element,
      NoCellFoundAtIndexBehavior::kFindPreviousCellInColumn);
}

Element* AutomaticGridFocusgroupStructureInfo::NextCellInColumn(
    const Element* cell_element) {
  DCHECK(cell_element);

  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell)
    return nullptr;

  auto* row = cell->Row();
  if (!row)
    return nullptr;

  auto* next_row = row;
  const unsigned row_span = cell->ResolvedRowSpan();
  for (unsigned i = 0; i < row_span; i++) {
    next_row = NextRow(next_row);
    if (!next_row)
      return nullptr;
  }

  auto* next_row_element = DynamicTo<Element>(next_row->GetNode());
  if (!next_row_element)
    return nullptr;

  return CellAtIndexInRow(cell->AbsoluteColumnIndex(), next_row_element,
                          NoCellFoundAtIndexBehavior::kFindNextCellInColumn);
}

Element* AutomaticGridFocusgroupStructureInfo::FirstCellInColumn(
    unsigned index) {
  if (index >= ColumnCount())
    return nullptr;

  return CellAtIndexInRow(index, FirstRow(),
                          NoCellFoundAtIndexBehavior::kFindNextCellInColumn);
}

Element* AutomaticGridFocusgroupStructureInfo::LastCellInColumn(
    unsigned index) {
  if (index >= ColumnCount())
    return nullptr;

  return CellAtIndexInRow(
      index, LastRow(), NoCellFoundAtIndexBehavior::kFindPreviousCellInColumn);
}

Element* AutomaticGridFocusgroupStructureInfo::PreviousRow(
    Element* row_element) {
  DCHECK(row_element);
  auto* row = DynamicTo<LayoutTableRow>(row_element->GetLayoutObject());
  if (!row)
    return nullptr;

  auto* previous_row = PreviousRow(row);
  if (!previous_row)
    return nullptr;

  return DynamicTo<Element>(previous_row->GetNode());
}

Element* AutomaticGridFocusgroupStructureInfo::NextRow(Element* row_element) {
  DCHECK(row_element);
  auto* row = DynamicTo<LayoutTableRow>(row_element->GetLayoutObject());
  if (!row)
    return nullptr;

  auto* next_row = NextRow(row);
  if (!next_row)
    return nullptr;

  return DynamicTo<Element>(next_row->GetNode());
}

Element* AutomaticGridFocusgroupStructureInfo::FirstRow() {
  auto* first_section = Table()->FirstSection();
  auto* first_row = first_section->FirstRow();
  while (first_row) {
    // Layout rows can be empty (i.e., have no cells), so make sure that we
    // return the first row that has at least one cell.
    if (first_row->FirstCell()) {
      return DynamicTo<Element>(first_row->GetNode());
    }
    first_row = first_row->NextRow();
  }
  return nullptr;
}

Element* AutomaticGridFocusgroupStructureInfo::LastRow() {
  auto* last_section = Table()->LastSection();
  auto* last_row = last_section->LastRow();
  while (last_row) {
    // See comment in `PreviousRow()` to understand why we need to ensure this
    // functions returns a row that has cells.
    if (last_row->FirstCell()) {
      return DynamicTo<Element>(last_row->GetNode());
    }

    last_row = last_row->PreviousRow();
  }
  return nullptr;
}

Element* AutomaticGridFocusgroupStructureInfo::RowForCell(
    Element* cell_element) {
  auto* cell = DynamicTo<LayoutTableCell>(cell_element->GetLayoutObject());
  if (!cell) {
    return nullptr;
  }

  auto* row = cell->Row();
  if (!row)
    return nullptr;

  return DynamicTo<Element>(row->GetNode());
}

Element* AutomaticGridFocusgroupStructureInfo::CellAtIndexInRow(
    unsigned index,
    Element* row_element,
    NoCellFoundAtIndexBehavior behavior) {
  auto* row = DynamicTo<LayoutTableRow>(row_element->GetLayoutObject());
  if (!row) {
    return nullptr;
  }

  // This can happen when |row|'s nth previous sibling row has a rowspan value
  // of n + 1 and a colspan value equal to the table's column count. In that
  // case, |row| won't have any cell.
  if (!row->FirstCell()) {
    return nullptr;
  }

  unsigned total_col_count = ColumnCount();
  if (index >= total_col_count)
    return nullptr;

  auto* cell = TableCellAtIndexInRowRecursive(index, row);
  while (!cell) {
    switch (behavior) {
      case NoCellFoundAtIndexBehavior::kReturn:
        return nullptr;
      case NoCellFoundAtIndexBehavior::kFindPreviousCellInRow:
        if (index == 0) {
          // This shouldn't happen, since the row passed by parameter is
          // expected to always have at least one cell at this point.
          NOTREACHED();
        }
        cell = TableCellAtIndexInRowRecursive(--index, row);
        break;
      case NoCellFoundAtIndexBehavior::kFindNextCellInRow:
        if (index >= total_col_count)
          return nullptr;
        cell = TableCellAtIndexInRowRecursive(++index, row);
        break;
      case NoCellFoundAtIndexBehavior::kFindPreviousCellInColumn:
        row = PreviousRow(row);
        if (!row)
          return nullptr;
        cell = TableCellAtIndexInRowRecursive(index, row);
        break;
      case NoCellFoundAtIndexBehavior::kFindNextCellInColumn:
        row = NextRow(row);
        if (!row)
          return nullptr;
        cell = TableCellAtIndexInRowRecursive(index, row);
        break;
    }
  }

  if (!cell)
    return nullptr;

  return DynamicTo<Element>(cell->GetNode());
}

LayoutTableRow* AutomaticGridFocusgroupStructureInfo::PreviousRow(
    LayoutTableRow* current_row) {
  auto* current_section = current_row->Section();
  LayoutTableRow* previous_row = current_row->PreviousRow();

  // Here, it's possible the previous row has no cells at all if the nth
  // previous row has a rowspan attribute of value n + 1 and a colspan value
  // equal to the table's column count. Return the first previous row that
  // actually isn't just a continuation of another one.
  //
  // Also, it's possible that the previous row is actually located in the
  // previous section. When we can't find a previous row, get the last row from
  // the previous section.
  while (!previous_row || !previous_row->FirstCell()) {
    if (previous_row && previous_row->FirstCell()) {
      previous_row = previous_row->PreviousRow();
      continue;
    }

    auto* previous_section = Table()->PreviousSection(current_section);
    if (!previous_section)
      return nullptr;

    current_section = previous_section;
    previous_row = previous_section->LastRow();
  }

  return previous_row;
}

LayoutTableRow* AutomaticGridFocusgroupStructureInfo::NextRow(
    LayoutTableRow* current_row) {
  auto* current_section = current_row->Section();
  LayoutTableRow* next_row = current_row->NextRow();

  // Here, it's possible the next row has no cells at all if the current row (or
  // a previous sibling) has a rowspan attribute that encapsulates the next row
  // and a colspan value equal to the table's column count. Return the first
  // next row that actually isn't just a continuation of a previous one.
  //
  // Also, it's possible that the next row is actually located in the
  // next section. When we can't find a previous row, get the last row from
  // the previous section.
  while (!next_row || !next_row->FirstCell()) {
    if (next_row && next_row->FirstCell()) {
      next_row = next_row->NextRow();
      continue;
    }

    auto* next_section = Table()->NextSection(current_section);
    if (!next_section)
      return nullptr;

    current_section = next_section;
    next_row = next_section->FirstRow();
  }

  return next_row;
}

LayoutTableCell*
AutomaticGridFocusgroupStructureInfo::TableCellAtIndexInRowRecursive(
    unsigned index,
    LayoutTableRow* row,
    std::optional<unsigned> expected_rowspan) {
  if (!row)
    return nullptr;

  // 1. Define a starting point for the search. Start from the end.
  auto* cell = row->LastCell();
  if (auto* table_row = DynamicTo<HTMLTableRowElement>(row->GetNode())) {
    // This is a shortcut that allows us to get the cell at |index| in constant
    // time. This shortcut is only possible with HTML tables. If the table
    // contains rowspans/colspans that affect this cell, it might actually not
    // be the right one and require some adjustments. Anyway, when possible,
    // it's better performance-wise to start near a cell than to always start
    // the search on the first/last cell of a row.
    auto* table_cell =
        DynamicTo<HTMLTableCellElement>(table_row->cells()->item(index));
    if (table_cell) {
      cell = To<LayoutTableCell>(table_cell->GetLayoutObject());
    }
  }

  // 2. Get the cell's actual index. Its index might not be equal to |index|,
  // since a rowspan and/or colspan value set on a previous cell would have
  // affected the actual index.
  //
  // Example:
  // <tr>
  //   <td id=cell1 colspan=2></td>
  //   <td id=cell2></td>
  // </tr>
  //
  // |cell1|'s absolute column index would be 0, while |cell2|'s would be 2.
  // However, |cell2| would be found at index 1 of the row cells.
  unsigned actual_index = cell->AbsoluteColumnIndex();

  // 3. Find the cell at |index| by making the necessary adjustments to the
  // current |cell|.
  while (actual_index != index) {
    if (actual_index > index) {
      cell = cell->PreviousCell();
      if (cell) {
        actual_index = cell->AbsoluteColumnIndex();
        continue;
      }
    } else {
      unsigned col_span = cell->ColSpan();
      // When colspan equals 0 (meaning that the cell spans all columns), we
      // want to break since the cell most definitely contains the |index|.
      if (col_span == 0 || actual_index + col_span > index) {
        // This is only the case when the we are on a cell that spans multiple
        // columns.
        break;
      }
    }

    // We only reach this point when either:
    //    A. the cell at this |index| starts in another row because of a
    //       rowspan.
    //    B. there is no cell at this |index|. Although this is rare, it is
    //       possible to achieve when a row contains fewer columns than
    //       others.
    //
    // Here, we take care of scenario A. by getting the cell that spans multiple
    // rows by looking located in a previous row. This approach is recursive.
    unsigned rowspan_to_expect = expected_rowspan ? *expected_rowspan + 1 : 2;
    cell = TableCellAtIndexInRowRecursive(index, PreviousRow(row),
                                          rowspan_to_expect);

    if (cell)
      actual_index = cell->AbsoluteColumnIndex();

    // At this point, we either found a cell that spans multiple rows and
    // corresponds to the one we were looking for or we are in scenario B. Let
    // the caller deal with what to do next in this case.
    break;
  }

  if (!cell)
    return nullptr;

  // 4. Return early if the cell we found in in a previous doesn't span to
  // the row we started the search on. We use the |expected_rowspan| parameter
  // to determine if the cell we found can reach the row we were at.
  if (actual_index == index && expected_rowspan) {
    unsigned row_span = cell->ResolvedRowSpan();
    if (row_span == 0 || *expected_rowspan > row_span) {
      // This is to prevent going to a previous row that exist at index but
      // doesn't have rowspan. A rowspan value of 0 means "all rows".
      return nullptr;
    }
  }

  // 5. We reached a result. If |cell| is null, then no cell was found at
  // |index| in this specific row.
  return cell;
}

}  // namespace blink

"""

```