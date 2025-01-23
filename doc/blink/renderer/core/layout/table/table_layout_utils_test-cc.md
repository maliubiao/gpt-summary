Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the *functionality* of the provided C++ test file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Initial Scan and Key Observations:** Quickly read through the code. Notice the `#include` directives, especially `table_layout_utils.h`. This immediately suggests the file is testing utilities related to table layout. The `TEST_F` macros indicate Google Test is being used for unit testing. The `MakeColumn`, `MakeRow`, and `MakeSection` helper functions point to data structures used in table layout calculations.

3. **Focus on the `TEST_F` functions:** Each `TEST_F` block represents a specific test case. Analyze each one individually:

    * **`DistributeColspanAutoPercent`:**  Keywords: "Colspan", "Percent". This test seems to be about how a cell spanning multiple columns (colspan) with a percentage width is distributed among the underlying columns.

    * **`DistributeColspanAutoSizeUnconstrained`:** Keywords: "Colspan", "AutoSize", "Unconstrained". This likely tests how a colspan cell with an explicit size (min/max) is distributed among columns when the columns themselves don't have fixed sizes. "Unconstrained" suggests the columns are flexible.

    * **`DistributeColspanAutoSizeConstrained`:** Similar to the previous one, but "Constrained" suggests the underlying columns *do* have size constraints.

    * **`DistributeColspanAutoExactMaxSize`:**  Keywords: "Exact MaxSize". This seems to be a test for a specific edge case where the column widths perfectly match the table width, ensuring no redistribution occurs. The comment about floating-point rounding is a crucial detail.

    * **`ComputeGridInlineMinMax`:** Keywords: "Grid", "Inline", "MinMax". This test likely focuses on calculating the minimum and maximum width of a table based on its column constraints, considering percentages and fixed sizes. The `is_layout_pass` variable hints at different calculation logic during different layout phases.

    * **`DistributeRowspanCellToRows`:** Keywords: "Rowspan", "Rows". This tests how the height of a cell spanning multiple rows (rowspan) is distributed among those rows.

    * **`DistributeSectionFixedBlockSizeToRows`:** Keywords: "Section", "FixedBlockSize", "Rows". This tests how a fixed height assigned to a table section is distributed among the rows within that section, potentially considering percentage-based row heights.

    * **`DistributeTableBlockSizeToSections`:** Keywords: "Table", "BlockSize", "Sections". This tests how the overall height of a table is distributed among its different sections (e.g., `<thead>`, `<tbody>`, `<tfoot>`), considering percentage-based section heights and intrinsic content heights.

4. **Relate to Web Technologies:**  Now, connect the tested functionalities to HTML, CSS, and potentially JavaScript:

    * **HTML:**  The tests directly relate to how tables are structured using elements like `<table>`, `<tr>`, `<td>`, and the `colspan` and `rowspan` attributes.

    * **CSS:**  CSS properties like `width`, `height`, `min-width`, `max-width`, and the use of percentages for table and cell dimensions are directly relevant to the scenarios being tested. The concept of "fixed layout" is also a CSS table layout mode.

    * **JavaScript:** While this specific test file doesn't *directly* involve JavaScript, it tests the underlying layout engine that *interprets* CSS and renders HTML. JavaScript can dynamically manipulate table styles and content, making these layout calculations crucial for correct rendering.

5. **Identify Logical Reasoning and Examples:**  Look for the `EXPECT_EQ` calls within the tests. These are the core of the logical assertions. For each test, try to deduce the expected output based on the input parameters (the `MakeColumn`, `MakeRow` calls) and the function being tested.

    * **Example:** In `DistributeColspanAutoPercent`, the input is columns with max widths and a colspan cell with a percentage width. The logic being tested is how that percentage is distributed proportionally to the max widths of the underlying columns. The `EXPECT_EQ` lines verify this distribution. Formulate a simple hypothetical scenario to illustrate this.

6. **Consider Common Usage Errors:** Think about common mistakes web developers make when working with tables:

    * **Conflicting Widths/Heights:** Setting explicit widths on columns that also have percentage widths on spanning cells can lead to unexpected behavior.
    * **Incorrect `colspan`/`rowspan` Values:**  Using incorrect span values can cause cells to overlap or leave gaps.
    * **Forgetting `table-layout: fixed;`:**  Understanding the impact of `table-layout: fixed` vs. the automatic table layout algorithm is essential. The tests for constrained vs. unconstrained columns touch on this.
    * **Not accounting for borders and padding:** While not explicitly tested here, these are common factors that affect table layout.

7. **Structure the Answer:** Organize the findings into clear sections as requested:

    * **File Functionality:**  Provide a concise summary of the file's purpose.
    * **Relationship to Web Technologies:** Explain how the tests relate to HTML, CSS, and JavaScript with specific examples.
    * **Logical Reasoning Examples:** Choose a couple of tests and explain the input, the logic being tested, and the expected output.
    * **Common Usage Errors:** List typical mistakes developers make with tables that these underlying layout calculations aim to handle correctly.

8. **Refine and Review:**  Read through the generated answer. Ensure clarity, accuracy, and completeness. Check if all parts of the original request have been addressed. For instance, initially, I might have overlooked the subtle difference between `is_layout_pass = true` and `false` in `ComputeGridInlineMinMax`. A review would catch this and prompt further analysis of that specific test.
This C++ file, `table_layout_utils_test.cc`, is a **unit test file** for the `table_layout_utils.h` header file within the Chromium Blink rendering engine. Its primary function is to **verify the correctness of the algorithms and logic implemented in `table_layout_utils.h`**, which deals with the layout of HTML tables.

Here's a breakdown of its functionalities and relationships to web technologies:

**Core Functionality:**

* **Testing Table Layout Algorithms:** The file contains various test cases (using Google Test framework) that exercise different functions and scenarios related to table layout calculations. These scenarios include:
    * **Distributing colspan cell widths:**  How the width of a cell spanning multiple columns is allocated to those columns, especially when dealing with percentage widths and auto widths.
    * **Calculating minimum and maximum table widths:**  Determining the intrinsic width requirements of a table based on its content and column constraints.
    * **Distributing rowspan cell heights:** How the height of a cell spanning multiple rows is allocated to those rows.
    * **Distributing fixed block sizes to rows within a section:** How a fixed height for a table section is distributed among its rows.
    * **Distributing table block sizes to sections:** How the overall height of a table is distributed among its different sections (like `<thead>`, `<tbody>`, `<tfoot>`).

* **Helper Functions for Test Setup:** The file defines helper functions like `MakeColumn`, `MakeRow`, and `MakeSection` to create simplified representations of table elements (columns, rows, sections) for testing purposes. These functions allow for easy construction of various table configurations to test different layout scenarios.

**Relationship to JavaScript, HTML, and CSS:**

This C++ code is part of the **rendering engine** of a web browser. It directly implements the logic that interprets HTML and CSS related to tables and calculates their layout on the screen.

* **HTML:** The tests directly correspond to HTML table elements and their attributes:
    * `<table>`: The tests deal with the overall layout of the table.
    * `<tr>`: The `MakeRow` function and tests like `DistributeRowspanCellToRows` directly relate to the layout of table rows.
    * `<td>` and `<th>`:  While not explicitly represented as objects, the concept of cells with `colspan` and `rowspan` is central to tests like `DistributeColspanAutoPercent` and `DistributeRowspanCellToRows`. The content within these cells influences the minimum/maximum width calculations.
    * `<colgroup>` and `<col>`: While not explicitly tested with dedicated objects, the column constraints being manipulated in the tests reflect the influence of `<col>` elements on column widths.
    * `<thead>`, `<tbody>`, `<tfoot>`: The `MakeSection` function and `DistributeTableBlockSizeToSections` test directly relate to the layout of these table sections.

* **CSS:** The tests simulate the effects of various CSS properties on table layout:
    * `width`:  Tests involving percentage widths and fixed widths for columns and cells directly relate to the `width` CSS property.
    * `height`: Tests involving distributing block sizes to rows and sections relate to the `height` CSS property.
    * `min-width`, `max-width`: The `MakeColumn` function allows setting minimum and maximum widths for columns, and tests like `ComputeGridInlineMinMax` verify how these constraints are handled.
    * `table-layout: auto;` and `table-layout: fixed;`: The `is_fixed_layout` variable in `ComputeGridInlineMinMax` hints at testing the behavior of different table layout algorithms defined by this CSS property.
    * Box model properties (padding, border): While not explicitly tested as separate properties, the `border_padding` field in `MakeColumn` suggests that these factors are considered in the overall table layout logic.

* **JavaScript:** While this specific C++ file doesn't directly execute JavaScript, it provides the underlying layout functionality that JavaScript can interact with. For example:
    * JavaScript can dynamically modify the content of table cells, which would trigger the layout calculations tested here.
    * JavaScript can change CSS properties related to table layout, causing these C++ functions to be invoked to re-calculate the layout.
    * JavaScript might read layout properties of tables, which are calculated by this underlying C++ code.

**Examples of Logical Reasoning (with Assumptions and Input/Output):**

**Test Case:** `DistributeColspanAutoPercent`

**Assumption:** A colspan cell with a percentage width should distribute that percentage among the spanned columns proportionally to their available space (in this case, represented by their `max_width`).

**Input:**
* `colspan_cell`:  A cell spanning 3 columns with a `percent` of 60%.
* `column_constraints` (Scenario 1):
    * Column 0: `max_width` = 10px
    * Column 1: `max_width` = 20px
    * Column 2: `max_width` = (implicitly) some value, currently set to 30% (irrelevant for this distribution).
* `column_constraints` (Scenario 2):
    * Column 0: `max_width` = 0px
    * Column 1: `max_width` = 0px
    * Column 2: `max_width` = (implicitly) some value, currently set to 10%.

**Logic:** The `DistributeColspanCellsToColumns` function should calculate how to distribute the 60% width of the colspan cell.

**Output (Scenario 1):**
* `column_constraints->data[0].percent` should be 10% (proportional to 10px out of 10px + 20px).
* `column_constraints->data[1].percent` should be 20% (proportional to 20px out of 10px + 20px).

**Output (Scenario 2):**
* `column_constraints->data[0].percent` should be 25% (evenly distributed among the initially zero-width columns).
* `column_constraints->data[1].percent` should be 25%.

**Test Case:** `DistributeRowspanCellToRows`

**Assumption:** A rowspan cell with a fixed height should distribute that height among the spanned rows proportionally to their existing heights.

**Input:**
* `rowspan_cell`: A cell spanning 3 rows with a height of 300px.
* `rows` (Scenario 1):
    * Row 0: `block_size` = 10px
    * Row 1: `block_size` = 20px
    * Row 2: `block_size` = 30px

**Logic:** The `DistributeRowspanCellToRows` function should allocate the 300px height to the rows.

**Output (Scenario 1):**
* `rows[0].block_size` should be 50px (300 * 10/60).
* `rows[1].block_size` should be 100px (300 * 20/60).
* `rows[2].block_size` should be 150px (300 * 30/60).

**Common User or Programming Usage Errors (Illustrative Examples):**

While this test file doesn't directly *cause* user errors, it tests the underlying logic that prevents or handles potential issues developers might encounter when writing HTML and CSS for tables:

* **Conflicting Widths:** A developer might set a fixed width on a column and then have a colspan cell with a percentage width spanning that column. The layout engine needs to resolve this conflict. The `DistributeColspanAutoPercent` test helps ensure this resolution is correct.
    * **Example Error:** A table looks misaligned because a colspan cell's percentage width isn't being distributed as expected due to fixed column widths.

* **Incorrect `colspan`/`rowspan` Values:** A developer might accidentally set a `colspan` or `rowspan` value that causes cells to overlap or leave unexpected gaps. While this test file doesn't directly test for invalid span values, the layout algorithms it verifies are crucial for rendering the table correctly even with such errors.
    * **Example Error:** A cell with `colspan="3"` only appears to span two columns because of other layout constraints.

* **Misunderstanding Percentage Heights in Tables:** Developers might assume percentage heights on table rows work the same way as block elements, leading to unexpected results. The `DistributeSectionFixedBlockSizeToRows` test helps ensure that the engine correctly handles percentage row heights within a fixed-height section.
    * **Example Error:** A developer sets `height: 50%;` on a table row expecting it to be half the table's height, but it behaves differently due to the table layout algorithm.

* **Forgetting `table-layout: fixed;`:** Developers might not realize the difference between `table-layout: auto` (the default) and `table-layout: fixed`. The `ComputeGridInlineMinMax` test with `is_fixed_layout` hints at the different layout behavior in these scenarios.
    * **Example Error:** A table renders very wide because the browser is trying to fit the content of cells without respecting fixed column widths (when `table-layout: fixed` is not used).

In summary, `table_layout_utils_test.cc` is a crucial part of ensuring the correct and predictable layout of HTML tables in Chromium. It verifies the low-level algorithms that interpret HTML and CSS table properties, indirectly contributing to a better user experience by preventing layout bugs and inconsistencies.

### 提示词
```
这是目录为blink/renderer/core/layout/table/table_layout_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/layout/table/table_node.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class TableLayoutUtilsTest : public RenderingTest {
 public:
  TableTypes::Column MakeColumn(int min_width,
                                int max_width,
                                std::optional<float> percent = std::nullopt,
                                bool is_constrained = false) {
    return {LayoutUnit(min_width),
            LayoutUnit(max_width),
            percent,
            /* border_padding */ LayoutUnit(),
            is_constrained,
            /* is_collapsed */ false,
            /* is_table_fixed */ false,
            /* is_mergeable */ false};
  }

  TableTypes::Row MakeRow(int block_size,
                          bool is_constrained = false,
                          bool has_rowspan_start = false,
                          std::optional<float> percent = std::nullopt) {
    return {LayoutUnit(block_size), 0,       0,
            std::nullopt,           percent, is_constrained,
            has_rowspan_start,      false};
  }

  TableTypes::Section MakeSection(TableTypes::Rows* rows,
                                  int block_size,
                                  wtf_size_t rowspan = 1,
                                  std::optional<float> percent = std::nullopt) {
    wtf_size_t start_row = rows->size();
    for (wtf_size_t i = 0; i < rowspan; i++)
      rows->push_back(MakeRow(10));
    bool is_constrained = percent || block_size != 0;
    bool is_tbody = true;
    return TableTypes::Section{
        start_row, rowspan, LayoutUnit(block_size), percent, is_constrained,
        is_tbody,  false};
  }
};

TEST_F(TableLayoutUtilsTest, DistributeColspanAutoPercent) {
  TableTypes::ColspanCell colspan_cell(TableTypes::CellInlineConstraint(), 0,
                                       3);
  colspan_cell.start_column = 0;
  colspan_cell.span = 3;

  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();

  colspan_cell.cell_inline_constraint.percent = 60.0f;
  TableTypes::ColspanCells colspan_cells;
  colspan_cells.push_back(colspan_cell);

  // Distribute over non-percent columns proportial to max size.
  // Columns: 10px, 20px, 30%
  // Distribute 60%: 10% 20% 30%
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(0, 10));
  column_constraints->data.push_back(MakeColumn(0, 20));
  column_constraints->data.push_back(MakeColumn(0, 10, 30));
  DistributeColspanCellsToColumns(colspan_cells, LayoutUnit(), false,
                                  column_constraints.get());
  EXPECT_EQ(column_constraints->data[0].percent, 10);
  EXPECT_EQ(column_constraints->data[1].percent, 20);

  // Distribute evenly over empty columns.
  // Columns: 0px 0px 10%
  // Distribute 60%: 25% 25% 10%
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(0, 0));
  column_constraints->data.push_back(MakeColumn(0, 0));
  column_constraints->data.push_back(MakeColumn(0, 10, 10));
  DistributeColspanCellsToColumns(colspan_cells, LayoutUnit(), false,
                                  column_constraints.get());
  EXPECT_EQ(column_constraints->data[0].percent, 25);
  EXPECT_EQ(column_constraints->data[1].percent, 25);
}

TEST_F(TableLayoutUtilsTest, DistributeColspanAutoSizeUnconstrained) {
  TableTypes::ColspanCell colspan_cell(TableTypes::CellInlineConstraint(), 0,
                                       3);
  colspan_cell.start_column = 0;
  colspan_cell.span = 3;

  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();

  // Columns distributing over auto columns.
  colspan_cell.cell_inline_constraint.min_inline_size = LayoutUnit(100);
  colspan_cell.cell_inline_constraint.max_inline_size = LayoutUnit(100);
  TableTypes::ColspanCells colspan_cells;
  colspan_cells.push_back(colspan_cell);
  // Distribute over non-percent columns proportial to max size.
  // Columns min/max: 0/10, 0/10, 0/20
  // Distribute 25, 25, 50
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(0, 10));
  column_constraints->data.push_back(MakeColumn(0, 10));
  column_constraints->data.push_back(MakeColumn(0, 20));
  DistributeColspanCellsToColumns(colspan_cells, LayoutUnit(), false,
                                  column_constraints.get());
  EXPECT_EQ(column_constraints->data[0].min_inline_size, 25);
  EXPECT_EQ(column_constraints->data[1].min_inline_size, 25);
  EXPECT_EQ(column_constraints->data[2].min_inline_size, 50);
}

TEST_F(TableLayoutUtilsTest, DistributeColspanAutoSizeConstrained) {
  TableTypes::ColspanCell colspan_cell(TableTypes::CellInlineConstraint(), 0,
                                       3);
  colspan_cell.start_column = 0;
  colspan_cell.span = 3;

  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();

  // Columns distributing over auto columns.
  colspan_cell.cell_inline_constraint.min_inline_size = LayoutUnit(100);
  colspan_cell.cell_inline_constraint.max_inline_size = LayoutUnit(100);
  TableTypes::ColspanCells colspan_cells;
  colspan_cells.push_back(colspan_cell);
  // Distribute over fixed columns proportial to:
  // Columns min/max: 0/10, 0/10, 0/20
  // Distribute 25, 25, 50
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(0, 10, std::nullopt, true));
  column_constraints->data.push_back(MakeColumn(10, 10, std::nullopt, true));
  column_constraints->data.push_back(MakeColumn(0, 20, std::nullopt, true));
  DistributeColspanCellsToColumns(colspan_cells, LayoutUnit(), false,
                                  column_constraints.get());
  EXPECT_EQ(column_constraints->data[0].min_inline_size, 25);
  EXPECT_EQ(column_constraints->data[1].min_inline_size, 25);
  EXPECT_EQ(column_constraints->data[2].min_inline_size, 50);
}

TEST_F(TableLayoutUtilsTest, DistributeColspanAutoExactMaxSize) {
  // If column widths sum match table widths exactly, column widths
  // should not be redistributed at all.
  // The error occurs if widths are redistributed, and column widths
  // change due to floating point rounding.
  LayoutUnit column_widths[] = {LayoutUnit(0.1), LayoutUnit(22.123456),
                                LayoutUnit(33.789012), LayoutUnit(2000.345678)};
  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(
      TableTypes::Column{LayoutUnit(0), column_widths[0], std::nullopt,
                         LayoutUnit(), false, false, false, false});
  column_constraints->data.push_back(
      TableTypes::Column{LayoutUnit(3.33333), column_widths[1], std::nullopt,
                         LayoutUnit(), false, false, false, false});
  column_constraints->data.push_back(
      TableTypes::Column{LayoutUnit(3.33333), column_widths[2], std::nullopt,
                         LayoutUnit(), false, false, false, false});
  column_constraints->data.push_back(
      TableTypes::Column{LayoutUnit(0), column_widths[3], std::nullopt,
                         LayoutUnit(), false, false, false, false});

  LayoutUnit assignable_table_inline_size =
      column_widths[0] + column_widths[1] + column_widths[2] + column_widths[3];
  Vector<LayoutUnit> column_sizes =
      SynchronizeAssignableTableInlineSizeAndColumns(
          assignable_table_inline_size, false, *column_constraints);
  EXPECT_EQ(column_sizes[0], column_widths[0]);
  EXPECT_EQ(column_sizes[1], column_widths[1]);
  EXPECT_EQ(column_sizes[2], column_widths[2]);
  EXPECT_EQ(column_sizes[3], column_widths[3]);
}

TEST_F(TableLayoutUtilsTest, ComputeGridInlineMinMax) {
  SetBodyInnerHTML(R"HTML(
    <div style="display: flex;">
      <table id=target></table>
    <div>
  )HTML");
  TableNode node(To<LayoutBox>(GetLayoutObjectByElementId("target")));

  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();

  LayoutUnit undistributable_space;
  bool is_fixed_layout = false;
  bool is_layout_pass = true;

  // No percentages, just sums up min/max.
  column_constraints->data.push_back(MakeColumn(10, 100));
  column_constraints->data.push_back(MakeColumn(20, 200));
  column_constraints->data.push_back(MakeColumn(30, 300));

  MinMaxSizes minmax =
      ComputeGridInlineMinMax(node, *column_constraints, undistributable_space,
                              is_fixed_layout, is_layout_pass);
  EXPECT_EQ(minmax.min_size, LayoutUnit(60));
  EXPECT_EQ(minmax.max_size, LayoutUnit(600));

  // Percentage: 99px max size/10% cell =>
  // table max size of 100%/10% * 99px
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(10, 99, 10));
  column_constraints->data.push_back(MakeColumn(10, 10));
  column_constraints->data.push_back(MakeColumn(10, 10));
  minmax =
      ComputeGridInlineMinMax(node, *column_constraints, undistributable_space,
                              is_fixed_layout, is_layout_pass);
  EXPECT_EQ(minmax.min_size, LayoutUnit(30));
  EXPECT_EQ(minmax.max_size, LayoutUnit(990));

  is_layout_pass = false;
  minmax =
      ComputeGridInlineMinMax(node, *column_constraints, undistributable_space,
                              is_fixed_layout, is_layout_pass);
  EXPECT_EQ(minmax.min_size, LayoutUnit(30));
  EXPECT_EQ(minmax.max_size, LayoutUnit(119));

  // Percentage: total percentage of 20%, and non-percent width of 800 =>
  // table max size of 800 + (20% * 800/80%) = 1000
  is_layout_pass = true;
  column_constraints->data.Shrink(0);
  column_constraints->data.push_back(MakeColumn(10, 100, 10));
  column_constraints->data.push_back(MakeColumn(10, 10, 10));
  column_constraints->data.push_back(MakeColumn(10, 800));
  minmax =
      ComputeGridInlineMinMax(node, *column_constraints, undistributable_space,
                              is_fixed_layout, is_layout_pass);
  EXPECT_EQ(minmax.min_size, LayoutUnit(30));
  EXPECT_EQ(minmax.max_size, LayoutUnit(1000));
}

TEST_F(TableLayoutUtilsTest, DistributeRowspanCellToRows) {
  TableTypes::RowspanCell rowspan_cell = {0, 3, LayoutUnit(300)};
  TableTypes::Rows rows;

  // Distribute to regular rows, rows grow in proportion to size.
  rows.push_back(MakeRow(10));
  rows.push_back(MakeRow(20));
  rows.push_back(MakeRow(30));
  DistributeRowspanCellToRows(rowspan_cell, LayoutUnit(), &rows);
  EXPECT_EQ(rows[0].block_size, LayoutUnit(50));
  EXPECT_EQ(rows[1].block_size, LayoutUnit(100));
  EXPECT_EQ(rows[2].block_size, LayoutUnit(150));

  // If some rows are empty, non-empty row gets everything
  rows.Shrink(0);
  rows.push_back(MakeRow(0));
  rows.push_back(MakeRow(10));
  rows.push_back(MakeRow(0));
  DistributeRowspanCellToRows(rowspan_cell, LayoutUnit(), &rows);
  EXPECT_EQ(rows[0].block_size, LayoutUnit(0));
  EXPECT_EQ(rows[1].block_size, LayoutUnit(300));
  EXPECT_EQ(rows[2].block_size, LayoutUnit(0));

  // If all rows are empty,last row gets everything.
  rows.Shrink(0);
  rows.push_back(MakeRow(0));
  rows.push_back(MakeRow(0));
  rows.push_back(MakeRow(0));
  DistributeRowspanCellToRows(rowspan_cell, LayoutUnit(), &rows);
  EXPECT_EQ(rows[0].block_size, LayoutUnit(0));
  EXPECT_EQ(rows[1].block_size, LayoutUnit(0));
  EXPECT_EQ(rows[2].block_size, LayoutUnit(300));
}

TEST_F(TableLayoutUtilsTest, DistributeSectionFixedBlockSizeToRows) {
  TableTypes::Rows rows;

  // Percentage rows get percentage, rest is distributed evenly.
  rows.push_back(MakeRow(100));
  rows.push_back(MakeRow(100, true, false, 50));
  rows.push_back(MakeRow(100));
  DistributeSectionFixedBlockSizeToRows(0, 3, LayoutUnit(1000), LayoutUnit(),
                                        LayoutUnit(1000), &rows);
  EXPECT_EQ(rows[0].block_size, LayoutUnit(250));
  EXPECT_EQ(rows[1].block_size, LayoutUnit(500));
  EXPECT_EQ(rows[2].block_size, LayoutUnit(250));
}

TEST_F(TableLayoutUtilsTest, DistributeTableBlockSizeToSections) {
  TableTypes::Sections sections;
  TableTypes::Rows rows;

  // Empty sections only grow if there are no other growable sections.
  sections.push_back(MakeSection(&rows, 0));
  sections.push_back(MakeSection(&rows, 100));
  DistributeTableBlockSizeToSections(LayoutUnit(), LayoutUnit(500), &sections,
                                     &rows);
  EXPECT_EQ(sections[0].block_size, LayoutUnit(400));

  // Sections with % block size grow to percentage.
  sections.Shrink(0);
  rows.Shrink(0);
  sections.push_back(MakeSection(&rows, 100, 1, 90));
  sections.push_back(MakeSection(&rows, 100));
  DistributeTableBlockSizeToSections(LayoutUnit(), LayoutUnit(1000), &sections,
                                     &rows);
  EXPECT_EQ(sections[0].block_size, LayoutUnit(900));
  EXPECT_EQ(sections[1].block_size, LayoutUnit(100));

  // When table height is greater than sum of intrinsic heights,
  // intrinsic heights are computed, and then they grow in
  // proportion to intrinsic height.
  sections.Shrink(0);
  rows.Shrink(0);
  sections.push_back(MakeSection(&rows, 100, 1, 30));
  sections.push_back(MakeSection(&rows, 100));
  // 30% section grows to 300px.
  // Extra 600 px is distributed between 300 and 100 px proportionally.
  // TODO(atotic) Is this what we want? FF/Edge/Legacy all disagree.
  DistributeTableBlockSizeToSections(LayoutUnit(), LayoutUnit(1000), &sections,
                                     &rows);
  EXPECT_EQ(sections[0].block_size, LayoutUnit(300));
  EXPECT_EQ(sections[1].block_size, LayoutUnit(700));

  // If there is a constrained section, and an unconstrained section,
  // unconstrained section grows.
  sections.Shrink(0);
  rows.Shrink(0);
  TableTypes::Section section(MakeSection(&rows, 100));
  section.is_constrained = false;
  sections.push_back(section);
  sections.push_back(MakeSection(&rows, 100));
  DistributeTableBlockSizeToSections(LayoutUnit(), LayoutUnit(1000), &sections,
                                     &rows);
  EXPECT_EQ(sections[0].block_size, LayoutUnit(900));
  EXPECT_EQ(sections[1].block_size, LayoutUnit(100));
}

}  // namespace blink
```