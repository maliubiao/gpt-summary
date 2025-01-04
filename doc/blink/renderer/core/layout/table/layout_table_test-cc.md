Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Identify the Core Purpose:** The filename `layout_table_test.cc` immediately suggests this file contains unit tests for the `LayoutTable` class within the Blink rendering engine. The presence of `#include "third_party/blink/renderer/core/layout/table/layout_table.h"` confirms this.

2. **Recognize the Testing Framework:**  The code uses `TEST_F(LayoutTableTest, ...)` which is a strong indicator of the Google Test framework (or a very similar one). The `RenderingTest` base class suggests these tests involve rendering and layout aspects.

3. **Analyze Individual Test Cases (the `TEST_F` blocks):**  Go through each test function one by one and try to understand what it's testing.

    * **`OverflowViaOutline`:** The name hints at overflow caused by CSS `outline`. The HTML sets up a nested table structure and applies outlines. The `EXPECT_EQ` calls compare expected and actual visual overflow rectangles. The test modifies the outline and verifies the overflow updates.

    * **`OverflowWithCollapsedBorders`:** This name clearly points to testing overflow behavior with `border-collapse: collapse`. The HTML sets up a table with collapsed borders and various border and outline styles on cells and the table itself. The test calculates expected border box and overflow rects and compares them. It distinguishes between `SelfVisualOverflowRect` and `VisualOverflowRect`, which is a crucial detail.

    * **`CollapsedBorders`:** Focuses specifically on how `border-collapse: collapse` affects the final rendered borders of the table. It sets up multiple tables with varying border styles on the table and its cells. It then checks the calculated `BorderBlockStart`, `BorderBlockEnd`, `BorderInlineStart`, and `BorderInlineEnd` properties.

    * **`CollapsedBordersWithCol`:** Similar to the previous test but introduces `<col>` and `<colgroup>` elements to see how their borders interact with cell borders in a collapsed border scenario.

    * **`WidthPercentagesExceedHundred`:**  This test deals with a specific edge case: what happens when the sum of column widths specified in percentages exceeds 100%. The test sets a very large width on the parent and checks if the table's width is capped at a maximum value.

    * **`CloseToMaxWidth`:** Checks the behavior when the table's `width` attribute is set to a value very close to the maximum allowed width.

    * **`PaddingWithCollapsedBorder`:** Tests if padding is applied to a table when `border-collapse: collapse` is set. The expectation is that padding is effectively ignored in this scenario.

    * **`OutOfOrderHeadAndBody`**, **`OutOfOrderFootAndBody`**, **`OutOfOrderHeadFootAndBody`:** These tests explore how the `LayoutTable` handles `<thead>`, `<tbody>`, and `<tfoot>` elements when they are not in the standard order within the table. The tests verify the order of sections as determined by the layout engine.

    * **`VisualOverflowCleared`:** This test examines how visual overflow is updated when a style that causes overflow (like `box-shadow`) is removed.

4. **Identify Connections to Web Technologies:**  Once the purpose of each test is clear, it's easier to link them to HTML, CSS, and JavaScript.

    * **HTML:** The tests heavily rely on HTML table structures (`<table>`, `<tr>`, `<td>`, `<thead>`, `<tbody>`, `<tfoot>`, `<col>`, `<colgroup>`). The use of `SetBodyInnerHTML` directly manipulates the HTML structure.
    * **CSS:** The tests use inline styles and `<style>` blocks to apply CSS properties like `display: table`, `width`, `height`, `outline`, `border-collapse`, `border`, `padding`, `box-shadow`.
    * **JavaScript:** While this particular test file doesn't directly *execute* JavaScript, the *behavior* it tests is directly related to how the browser (specifically the Blink engine) interprets and renders tables according to CSS rules. A developer might use JavaScript to dynamically modify table styles or structure, and these tests ensure that the underlying layout engine handles those changes correctly.

5. **Look for Logic and Assumptions:**  The tests make implicit assumptions about how the layout engine *should* behave. For instance, the `OverflowWithCollapsedBorders` test assumes that outlines on descendant elements contribute to the table's overall visual overflow, but not the `SelfVisualOverflowRect`. The tests with out-of-order table sections assume a certain logic for how the engine determines the order of the sections. The width percentage test assumes a maximum table width.

6. **Consider Potential User/Programming Errors:**  Think about how a web developer might misuse tables or CSS, and how these tests might catch those errors. For example, setting `border-collapse: collapse` and expecting padding to be applied to the table itself is a common misconception that the `PaddingWithCollapsedBorder` test addresses. Relying on the order of `<thead>`, `<tbody>`, and `<tfoot>` might also lead to unexpected results if not handled correctly by the browser.

7. **Structure the Explanation:**  Organize the findings into logical categories (functionality, relationships to web technologies, logic/assumptions, user errors). Use clear and concise language, and provide specific examples from the test code to illustrate each point.

8. **Refine and Review:**  Read through the explanation to ensure accuracy and completeness. Are there any ambiguities?  Are the examples clear? Could anything be explained more effectively?  For example, initially, I might just say "tests table layout."  But refining it to say "tests the layout logic of HTML tables, focusing on aspects like border collapsing, overflow handling, and the ordering of table sections" is much more precise.

By following this systematic approach, we can thoroughly analyze the C++ test file and extract valuable information about the functionality it covers and its relationship to web technologies.
这个C++源代码文件 `layout_table_test.cc` 是 Chromium Blink 引擎中专门用于测试 `LayoutTable` 类的单元测试文件。`LayoutTable` 类负责处理 HTML `<table>` 元素的布局。

**功能列举:**

该文件包含多个独立的测试用例 (以 `TEST_F` 开头)，每个用例针对 `LayoutTable` 类的特定功能或行为进行测试。主要测试的功能包括：

1. **溢出 (Overflow) 处理:**
   - 测试当表格的子元素 (例如，嵌套的 div) 设置了 `outline` 属性时，表格如何计算自身的视觉溢出区域 (`SelfVisualOverflowRect`)。
   - 测试在 `border-collapse: collapse` 情况下，表格如何计算自身的视觉溢出区域，包括考虑边框宽度和子元素的 `outline`。

2. **折叠边框 (Collapsed Borders) 处理:**
   - 测试在 `border-collapse: collapse` 样式下，表格如何确定最终的边框宽度。这包括考虑表格自身、单元格 (`<td>`) 和列 (`<col>`) 上设置的边框样式和宽度优先级。
   - 测试在折叠边框模式下，表格的 `BorderBlockStart`, `BorderBlockEnd`, `BorderInlineStart`, `BorderInlineEnd` 属性的计算是否正确。

3. **宽度百分比处理:**
   - 测试当表格单元格的宽度设置为百分比，且总百分比超过 100% 时，表格的布局行为。它验证了表格宽度是否会被限制在一个最大值 (`TableLayoutAlgorithm::kMaxTableWidth`)。
   - 测试当表格的 `width` 属性设置为接近最大允许值时，布局是否正确。

4. **内边距 (Padding) 处理:**
   - 测试当表格设置了 `border-collapse: collapse` 样式时，表格自身的 `padding` 属性是否会被应用（预期是不会被应用）。

5. **表格节 (Table Sections) 顺序处理:**
   - 测试当 `<thead>`, `<tbody>`, `<tfoot>` 元素在 HTML 中以非标准顺序出现时，`LayoutTable` 类如何处理这些节的顺序。它验证了 `FirstSection`, `LastSection`, `NextSection`, `PreviousSection` 等方法的返回值是否符合预期。

6. **视觉溢出清除 (Visual Overflow Clearing):**
   - 测试当表格的样式属性导致视觉溢出 (例如 `box-shadow`) 被移除后，表格的视觉溢出区域是否能正确更新。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该测试文件直接测试了 Blink 引擎中负责处理 HTML 表格布局的 C++ 代码。其测试用例模拟了各种 HTML 结构和 CSS 样式，以验证布局引擎的行为是否符合规范。

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 方法设置不同的 HTML 结构，例如包含不同边框样式的单元格、列以及不同顺序的表格节 (`<thead>`, `<tbody>`, `<tfoot>`)。
    * **例子:**  `<table id='table'><tr><td>A</td></tr></table>`  这样的 HTML 代码片段被用来创建被测试的表格元素。
    * **例子:**  `<thead id='head'></thead><tbody id='body'></tbody>` 测试了表格头的定义。

* **CSS:** 测试用例通过内联样式 (`style` 属性) 或 `<style>` 标签来应用各种 CSS 属性，例如 `border-collapse`, `border`, `width`, `height`, `outline`, `padding`, `box-shadow`。
    * **例子:**  `<table style='border-collapse: collapse'>` 测试了折叠边框的效果。
    * **例子:**  `<td style='border-top-width: 2px;'>` 测试了单元格边框样式的应用。

* **JavaScript:** 虽然这个测试文件本身是用 C++ 写的，不直接包含 JavaScript 代码，但它测试的功能直接影响了 JavaScript 如何通过 DOM API 操作表格的样式和结构，以及这些操作最终如何在浏览器中渲染出来。例如，如果 JavaScript 代码动态地修改了表格的边框样式或添加了 `outline`，这些测试确保了 Blink 引擎能够正确地重新布局和渲染表格。

**逻辑推理、假设输入与输出:**

以下举例说明一些测试用例中的逻辑推理和假设输入与输出：

**测试用例: `OverflowViaOutline`**

* **假设输入 (HTML & CSS):**
  ```html
  <style>
    div { display: table; width: 100px; height: 200px; }
  </style>
  <div id=target>
    <div id=child></div>
  </div>
  ```
* **假设输入 (C++ 代码):**
  - 获取 id 为 "target" 的 `LayoutTable` 对象。
  - 初始断言：`EXPECT_EQ(PhysicalRect(0, 0, 100, 200), target->SelfVisualOverflowRect());`  (假设初始状态下，视觉溢出区域与元素自身大小相同)。
  - 修改 "target" 和 "child" 元素的 `outline` 样式。
  - 更新布局。
  - 最终断言：`EXPECT_EQ(PhysicalRect(-2, -2, 104, 204), target->SelfVisualOverflowRect());` (假设添加 2px 的 outline 会导致视觉溢出区域在四个方向都扩展 2px)。

* **逻辑推理:**  当元素设置了 `outline` 属性时，`outline` 会绘制在元素的边框边缘之外，从而导致视觉溢出。测试用例验证了 `LayoutTable` 能正确计算包含 `outline` 的视觉溢出区域。

**测试用例: `CollapsedBorders`**

* **假设输入 (HTML & CSS):**
  ```html
  <style>table { border-collapse: collapse }</style>
  <table id='table1'
      style='border-top: hidden; border-bottom: 8px solid;
             border-left: hidden; border-right: 10px solid'>
    <tr><td>A</td><td>B</td></tr>
  </table>
  ```
* **假设输入 (C++ 代码):**
  - 获取 id 为 "table1" 的 `LayoutTable` 对象。
  - 断言：`EXPECT_EQ(0, table1->BorderBlockStart());` (假设表格顶部边框被隐藏，所以起始块方向边框为 0)。
  - 断言：`EXPECT_EQ(4, table1->BorderBlockEnd());` (假设表格底部边框宽度为 8px，但由于边框折叠，可能需要除以 2)。
  - 断言：`EXPECT_EQ(0, table1->BorderInlineStart());` (假设表格左侧边框被隐藏，所以起始内联方向边框为 0)。
  - 断言：`EXPECT_EQ(5, table1->BorderInlineEnd());` (假设表格右侧边框宽度为 10px，但由于边框折叠，可能需要除以 2)。

* **逻辑推理:** 在折叠边框模式下，相邻单元格的边框会合并。测试用例验证了 `LayoutTable` 类能够根据边框样式优先级规则 (例如，`solid` 比 `hidden` 优先级高，宽度大的边框胜出) 计算出最终的表格边框宽度。

**用户或编程常见的使用错误举例:**

1. **混淆 `border-collapse: collapse` 和 `border-collapse: separate` 时的内边距行为:**
   - **错误使用:**  用户可能认为即使设置了 `border-collapse: collapse`，表格的 `padding` 属性仍然会像 `border-collapse: separate` 时一样在单元格内容和边框之间产生间距。
   - **测试用例覆盖:** `PaddingWithCollapsedBorder` 测试用例验证了在这种情况下，表格自身的 `padding` 不会被应用。

2. **错误地假设表格节的顺序不重要:**
   - **错误使用:** 用户可能在 HTML 中随意放置 `<thead>`, `<tbody>`, `<tfoot>` 元素，并期望浏览器能以某种特定的顺序渲染。
   - **测试用例覆盖:** `OutOfOrderHeadAndBody`, `OutOfOrderFootAndBody`, `OutOfOrderHeadFootAndBody` 等测试用例验证了即使表格节的顺序不标准，`LayoutTable` 类也能正确识别和处理它们，确保渲染顺序符合预期（通常是 `<thead>`, `<tbody>`, `<tfoot>` 的逻辑顺序）。

3. **对超过 100% 的单元格宽度百分比的错误预期:**
   - **错误使用:**  用户可能会将表格单元格的宽度百分比之和设置为超过 100%，期望表格能超出其父元素的宽度。
   - **测试用例覆盖:** `WidthPercentagesExceedHundred` 测试用例验证了 Blink 引擎会限制表格的宽度，防止其无限扩展。

总而言之，`layout_table_test.cc` 文件通过一系列精心设计的测试用例，确保了 Blink 引擎中的 `LayoutTable` 类能够正确地处理各种 HTML 表格结构和 CSS 样式，从而保证网页在不同浏览器上的布局一致性和正确性。这些测试覆盖了表格布局的多个关键方面，有助于开发者避免常见的错误使用，并确保浏览器的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/layout/table/layout_table_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/table/layout_table.h"

#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

namespace {

class LayoutTableTest : public RenderingTest {
 protected:
  LayoutTable* GetTableByElementId(const char* id) {
    return To<LayoutTable>(GetLayoutObjectByElementId(id));
  }
};

TEST_F(LayoutTableTest, OverflowViaOutline) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { display: table; width: 100px; height: 200px; }
    </style>
    <div id=target>
      <div id=child></div>
    </div>
  )HTML");
  auto* target = GetTableByElementId("target");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 200), target->SelfVisualOverflowRect());
  To<Element>(target->GetNode())
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("outline: 2px solid black"));

  auto* child = GetTableByElementId("child");
  To<Element>(child->GetNode())
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("outline: 2px solid black"));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-2, -2, 104, 204), target->SelfVisualOverflowRect());

  EXPECT_EQ(PhysicalRect(-2, -2, 104, 204), child->SelfVisualOverflowRect());
}

TEST_F(LayoutTableTest, OverflowWithCollapsedBorders) {
  SetBodyInnerHTML(R"HTML(
    <style>
      table { border-collapse: collapse }
      td { border: 0px solid blue; padding: 0; width: 100px; height: 100px }
    </style>
    <table id='table'>
      <tr>
        <td style='border-top-width: 2px; border-left-width: 2px;
            outline: 6px solid blue'></td>
        <td style='border-top-width: 4px; border-right-width: 10px'></td>
      </tr>
      <tr style='outline: 8px solid green'>
        <td style='border-left-width: 20px'></td>
        <td style='border-right-width: 20px'></td>
      </tr>
    </table>
  )HTML");

  auto* table = GetTableByElementId("table");

  auto expected_border_box_rect = table->PhysicalContentBoxRect();
  expected_border_box_rect.ExpandEdges(LayoutUnit(2), LayoutUnit(10),
                                       LayoutUnit(0), LayoutUnit(10));
  EXPECT_EQ(expected_border_box_rect, table->PhysicalBorderBoxRect());

  // The table's self visual overflow rect covers all collapsed borders, but
  // not visual overflows (outlines) from descendants.
  auto expected_self_visual_overflow = table->PhysicalContentBoxRect();
  expected_self_visual_overflow.ExpandEdges(LayoutUnit(2), LayoutUnit(10),
                                            LayoutUnit(0), LayoutUnit(10));
  EXPECT_EQ(expected_self_visual_overflow, table->SelfVisualOverflowRect());
  EXPECT_EQ(expected_self_visual_overflow, table->ScrollableOverflowRect());
  // The table's visual overflow covers self visual overflow and content visual
  // overflows.
  auto expected_visual_overflow = table->PhysicalContentBoxRect();
  expected_visual_overflow.ExpandEdges(LayoutUnit(6), LayoutUnit(10),
                                       LayoutUnit(8), LayoutUnit(10));
  EXPECT_EQ(expected_visual_overflow, table->VisualOverflowRect());
}

TEST_F(LayoutTableTest, CollapsedBorders) {
  SetBodyInnerHTML(
      "<style>table { border-collapse: collapse }</style>"
      "<table id='table1'"
      "    style='border-top: hidden; border-bottom: 8px solid;"
      "           border-left: hidden; border-right: 10px solid'>"
      "  <tr><td>A</td><td>B</td></tr>"
      "</table>"
      "<table id='table2' style='border: 10px solid'>"
      "  <tr>"
      "    <td style='border: hidden'>C</td>"
      "    <td style='border: hidden'>D</td>"
      "  </tr>"
      "</table>"
      "<table id='table3' style='border: 10px solid'>"
      "  <tr>"
      "    <td style='border-top: 15px solid;"
      "               border-left: 21px solid'>E</td>"
      "    <td style='border-right: 25px solid'>F</td>"
      "  </tr>"
      // The second row won't affect start and end borders of the table.
      "  <tr>"
      "    <td style='border: 30px solid'>G</td>"
      "    <td style='border: 40px solid'>H</td>"
      "  </tr>"
      "</table>");

  auto* table1 = GetTableByElementId("table1");
  EXPECT_EQ(0, table1->BorderBlockStart());
  EXPECT_EQ(4, table1->BorderBlockEnd());
  EXPECT_EQ(0, table1->BorderInlineStart());
  EXPECT_EQ(5, table1->BorderInlineEnd());

  // All cells have hidden border.
  auto* table2 = GetTableByElementId("table2");
  EXPECT_EQ(0, table2->BorderBlockStart());
  EXPECT_EQ(0, table2->BorderBlockEnd());
  EXPECT_EQ(0, table2->BorderInlineStart());
  EXPECT_EQ(0, table2->BorderInlineEnd());

  // Cells have wider borders.
  auto* table3 = GetTableByElementId("table3");
  // Cell E's border-top won.
  EXPECT_EQ(LayoutUnit(7.5), table3->BorderBlockStart());
  // Cell H's border-bottom won.
  EXPECT_EQ(20, table3->BorderBlockEnd());
  // Cell G's border-left won.
  EXPECT_EQ(LayoutUnit(15), table3->BorderInlineStart());
  // Cell H's border-right won.
  EXPECT_EQ(LayoutUnit(20), table3->BorderInlineEnd());
}

TEST_F(LayoutTableTest, CollapsedBordersWithCol) {
  SetBodyInnerHTML(R"HTML(
    <style>table { border-collapse: collapse }</style>
    <table id='table1' style='border: hidden'>
      <colgroup>
        <col span='2000' style='border: 10px solid'>
        <col span='2000' style='border: 20px solid'>
      </colgroup>
      <tr>
        <td colspan='2000'>A</td>
        <td colspan='2000'>B</td>
      </tr>
    </table>
    <table id='table2' style='border: 10px solid'>
      <colgroup>
        <col span='2000' style='border: 10px solid'>
        <col span='2000' style='border: 20px solid'>
      </colgroup>
      <tr>
        <td colspan='2000' style='border: hidden'>C</td>
        <td colspan='2000' style='border: hidden'>D</td>
      </tr>
    </table>
    <table id='table3'>
      <colgroup>
        <col span='2000' style='border: 10px solid'>
        <col span='2000' style='border: 20px solid'>
      </colgroup>
      <tr>
        <td colspan='2000' style='border: 12px solid'>E</td>
        <td colspan='2000' style='border: 16px solid'>F</td>
      </tr>
    </table>
  )HTML");

  // Table has hidden border.
  auto* table1 = GetTableByElementId("table1");
  EXPECT_EQ(0, table1->BorderBlockStart());
  EXPECT_EQ(0, table1->BorderBlockEnd());
  EXPECT_EQ(0, table1->BorderInlineStart());
  EXPECT_EQ(0, table1->BorderInlineEnd());

  // All cells have hidden border.
  auto* table2 = GetTableByElementId("table2");
  EXPECT_EQ(0, table2->BorderBlockStart());
  EXPECT_EQ(0, table2->BorderBlockEnd());
  EXPECT_EQ(0, table2->BorderInlineStart());
  EXPECT_EQ(0, table2->BorderInlineEnd());

  // Combined cell and col borders.
  auto* table3 = GetTableByElementId("table3");
  // The second col's border-top won.
  EXPECT_EQ(10, table3->BorderBlockStart());
  // The second col's border-bottom won.
  EXPECT_EQ(10, table3->BorderBlockEnd());
  // Cell E's border-left won.
  EXPECT_EQ(6, table3->BorderInlineStart());
  // The second col's border-right won.
  EXPECT_EQ(10, table3->BorderInlineEnd());
}

TEST_F(LayoutTableTest, WidthPercentagesExceedHundred) {
  SetBodyInnerHTML(R"HTML(
    <style>#outer { width: 2000000px; }
    table { border-collapse: collapse; }</style>
    <div id='outer'>
    <table id='onlyTable'>
      <tr>
        <td width='100%'>
          <div></div>
        </td>
        <td width='60%'>
          <div width='10px;'></div>
        </td>
      </tr>
    </table>
    </div>
  )HTML");

  // Table width should be TableLayoutAlgorithm::kMaxTableWidth
  auto* table = GetTableByElementId("onlyTable");
  EXPECT_EQ(1000000, table->OffsetWidth());
}

TEST_F(LayoutTableTest, CloseToMaxWidth) {
  SetBodyInnerHTML(R"HTML(
    <style>#outer { width: 2000000px; }
    table { border-collapse: collapse; }</style>
    <div id='outer'>
    <table id='onlyTable' width='999999px;'>
      <tr>
        <td>
          <div></div>
        </td>
      </tr>
    </table>
    </div>
  )HTML");

  // Table width should be 999999
  auto* table = GetTableByElementId("onlyTable");
  EXPECT_EQ(999999, table->OffsetWidth());
}

TEST_F(LayoutTableTest, PaddingWithCollapsedBorder) {
  SetBodyInnerHTML(R"HTML(
    <table id='table' style='padding: 20px; border-collapse: collapse'>
      <tr><td>TD</td</tr>
    </table>
  )HTML");

  auto* table = GetTableByElementId("table");
  EXPECT_EQ(0, table->PaddingLeft());
  EXPECT_EQ(0, table->PaddingRight());
  EXPECT_EQ(0, table->PaddingTop());
  EXPECT_EQ(0, table->PaddingBottom());
  EXPECT_EQ(0, table->PaddingInlineEnd());
  EXPECT_EQ(0, table->PaddingBlockStart());
  EXPECT_EQ(0, table->PaddingBlockEnd());
}

TEST_F(LayoutTableTest, OutOfOrderHeadAndBody) {
  SetBodyInnerHTML(R"HTML(
    <table id='table' style='border-collapse: collapse'>
      <tbody id='body'><tr><td>Body</td></tr></tbody>
      <thead id='head'></thead>
    <table>
  )HTML");
  auto* table = GetTableByElementId("table");
  auto* body_section =
      To<LayoutTableSection>(GetLayoutObjectByElementId("body"));
  ASSERT_TRUE(table);
  ASSERT_TRUE(body_section);

  EXPECT_EQ(body_section, table->FirstSection());
  EXPECT_EQ(body_section, table->LastSection());
  EXPECT_EQ(nullptr, table->NextSection(body_section));
  EXPECT_EQ(nullptr, table->PreviousSection(body_section));
}

TEST_F(LayoutTableTest, OutOfOrderFootAndBody) {
  SetBodyInnerHTML(R"HTML(
    <table id='table'>
      <tfoot id='foot'></tfoot>
      <tbody id='body'><tr><td>Body</td></tr></tbody>
    <table>
  )HTML");
  auto* table = GetTableByElementId("table");
  auto* body_section =
      To<LayoutTableSection>(GetLayoutObjectByElementId("body"));
  ASSERT_TRUE(table);
  ASSERT_TRUE(body_section);

  EXPECT_EQ(body_section, table->FirstSection());
  EXPECT_EQ(body_section, table->LastSection());
  EXPECT_EQ(nullptr, table->NextSection(body_section));
  EXPECT_EQ(nullptr, table->PreviousSection(body_section));
}

TEST_F(LayoutTableTest, OutOfOrderHeadFootAndBody) {
  SetBodyInnerHTML(R"HTML(
    <table id='table' style='border-collapse: collapse'>
      <tfoot id='foot'><tr><td>foot</td></tr></tfoot>
      <thead id='head'><tr><td>head</td></tr></thead>
      <tbody id='body'><tr><td>Body</td></tr></tbody>
    <table>
  )HTML");
  auto* table = GetTableByElementId("table");
  auto* head_section =
      To<LayoutTableSection>(GetLayoutObjectByElementId("head"));
  auto* body_section =
      To<LayoutTableSection>(GetLayoutObjectByElementId("body"));
  auto* foot_section =
      To<LayoutTableSection>(GetLayoutObjectByElementId("foot"));
  ASSERT_TRUE(table);
  ASSERT_TRUE(head_section);
  ASSERT_TRUE(body_section);
  ASSERT_TRUE(foot_section);

  EXPECT_EQ(head_section, table->FirstSection());
  EXPECT_EQ(foot_section, table->LastSection());

  EXPECT_EQ(body_section, table->NextSection(head_section));
  EXPECT_EQ(foot_section, table->NextSection(body_section));
  EXPECT_EQ(nullptr, table->NextSection(foot_section));

  EXPECT_EQ(body_section, table->PreviousSection(foot_section));
  EXPECT_EQ(head_section, table->PreviousSection(body_section));
  EXPECT_EQ(nullptr, table->PreviousSection(head_section));
}

TEST_F(LayoutTableTest, VisualOverflowCleared) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #table {
        width: 50px; height: 50px; box-shadow: 5px 5px 5px black;
      }
    </style>
    <table id='table' style='width: 50px; height: 50px'></table>
  )HTML");
  auto* table = GetTableByElementId("table");
  EXPECT_EQ(PhysicalRect(-3, -3, 66, 66), table->SelfVisualOverflowRect());
  To<Element>(table->GetNode())
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("box-shadow: initial"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(0, 0, 50, 50), table->SelfVisualOverflowRect());
}

}  // anonymous namespace

}  // namespace blink

"""

```