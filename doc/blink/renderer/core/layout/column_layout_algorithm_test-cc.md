Response:
The user wants a summary of the provided C++ code file. The request asks for:
1. **Functionality:** What does the code do?
2. **Relevance to web technologies:**  Does it relate to JavaScript, HTML, or CSS? If so, examples.
3. **Logical reasoning:** If there are logical inferences, provide input and output examples.
4. **Common errors:**  Are there typical mistakes users or programmers make when dealing with this?
5. **Concise summary:** A brief overview of the file's purpose.

Based on the filename `column_layout_algorithm_test.cc` and the included headers (`column_layout_algorithm.h`), I can infer that this file contains test cases for the column layout algorithm in the Blink rendering engine.

Let's break down the code section by section to confirm this and address the specific points:

* **Headers:**  Includes for the column layout algorithm, base layout test infrastructure, block layout algorithm, length utilities, and physical box fragments. This strongly indicates it's a testing file.
* **Namespace:** `blink::{anonymous}` indicates internal implementation details for testing.
* **Class `ColumnLayoutAlgorithmTest`:** Inherits from `BaseLayoutAlgorithmTest`, confirming it's part of the testing framework.
* **`RunBlockLayoutAlgorithm` method:**  Sets up a basic block layout context for testing. This suggests the tests will involve laying out elements within a block container.
* **`DumpFragmentTree` methods:** These functions are used to generate string representations of the layout fragments. This is a common practice in layout tests to verify the structure and properties of the rendered output.
* **`TEST_F` macros:**  These are standard Google Test macros for defining test cases. Each test function name (e.g., `EmptyEditable`, `EmptyMulticol`) hints at the specific scenario being tested.

Now, let's address the user's specific requests:

1. **Functionality:** The primary function of this file is to test the correctness of the `ColumnLayoutAlgorithm` in Blink. It sets up various HTML structures with CSS column properties and verifies the generated layout fragments.

2. **Relevance to web technologies:** The code directly relates to CSS multi-column layout (`columns` property). The tests verify how the engine handles different scenarios involving multi-column layouts.
    * **HTML:** The tests use HTML strings (like `R"HTML(...)HTML"`) to define the structure of the elements being laid out.
    * **CSS:** CSS styles (within `<style>` tags or inline styles) define the column properties (`columns`, `column-fill`, `column-gap`) and other layout-related properties (like `height`, `width`, `float`, `break-before`, `break-inside`, `margin`).
    * **JavaScript:** While this specific file doesn't contain JavaScript, the functionality it tests directly impacts how JavaScript interacts with and manipulates elements within multi-column layouts (e.g., getting element offsets and dimensions).

3. **Logical reasoning:**  The tests involve setting up specific HTML/CSS configurations (input) and then verifying the structure and properties of the resulting layout fragments (output). For example, the `EmptyMulticol` test checks that an empty multi-column container still creates at least one fragmentainer.
    * **Input (EmptyMulticol):**  A `div` with `columns: 2` and defined `height` and `width`, but no content.
    * **Output (EmptyMulticol):**  The fragment tree shows the multi-column container and its single empty column fragmentainer.

4. **Common errors:** Although this is a testing file, the scenarios it tests often reflect common user errors or edge cases in CSS multi-column layout:
    * **Incorrectly assuming content will always fill all columns:** The `EmptyMulticol` test shows even an empty container will have columns.
    * **Not understanding how floats interact with columns:** Tests involving floats demonstrate how floats are positioned within the column flow.
    * **Misunderstanding break properties:** Tests with `break-before` and `break-inside` highlight how these properties influence column breaks.
    * **Unexpected behavior with margins:** Tests with margins show how margins affect the layout of elements within and across columns.

5. **Concise summary:** This file tests the `ColumnLayoutAlgorithm` of the Blink rendering engine by creating various HTML structures with CSS multi-column properties and asserting the correctness of the generated layout fragments. It covers scenarios like empty containers, content spanning columns, interactions with floats, and the effects of break-related CSS properties.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/layout/column_layout_algorithm_test.cc` 的第一部分，共 6 部分。从代码内容来看，**这个文件的主要功能是测试 Blink 引擎中负责多列布局 (`ColumnLayoutAlgorithm`) 的算法是否正确**。

下面根据你的要求进行更详细的分析：

**1. 文件功能归纳:**

这个文件包含了一系列使用 Google Test 框架编写的单元测试，用于验证 `ColumnLayoutAlgorithm` 在各种场景下的行为。这些测试覆盖了以下方面：

* **空元素在多列布局中的处理:** 例如，可编辑的空元素或包含浮动元素的空元素在多列容器中的高度计算。
* **基本多列布局的构建:** 例如，一个没有任何内容的空多列容器会生成多少个布局片段（fragments）。
* **块级元素在多列布局中的分布:** 测试块级元素如何分布在不同的列中，包括占据单列、跨越多列以及高度超出容器的情况。
* **浮动元素在多列布局中的定位:** 测试浮动元素如何影响列的布局，以及多个浮动元素之间的相对位置。
* **换列 (`break-before`) 和避免换列 (`break-inside`) 属性的影响:**  测试这些 CSS 属性如何强制或阻止元素在列之间断开。
* **边距 (`margin`) 在多列布局中的处理:**  测试元素边距如何影响其在列中的位置和与其他元素的关系。
* **容器高度为零时的处理:** 测试当多列容器高度为零时，其内部元素的布局行为。
* **内容溢出时的处理:** 测试当元素内容超出列容器高度时，布局算法如何处理。

**2. 与 javascript, html, css 的功能关系及举例:**

这个文件直接测试了 CSS 的多列布局特性，因此与 HTML 和 CSS 关系密切。虽然没有直接涉及 JavaScript，但其测试的布局结果会影响 JavaScript 获取到的元素尺寸和位置信息。

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 函数动态生成 HTML 结构，模拟不同的布局场景。例如：

   ```c++
   SetBodyInnerHTML(R"HTML(
     <div id="parent">
       <div id="child" style="width:75%; height:150px"></div>
     </div>
   )HTML");
   ```
   这个 HTML 片段定义了一个父 `div` 元素和一个子 `div` 元素，用于测试子元素在多列布局中的分布。

* **CSS:** 测试用例通过 `InsertStyleElement` 函数或内联样式设置 CSS 属性，以触发多列布局并控制元素的样式。例如：

   ```c++
   InsertStyleElement(
       "body { font: 10px/20px Ahem; }"
       "#multicol1, #multicol2 { columns: 3; }");
   ```
   这段 CSS 代码设置了全局字体样式，并为 id 为 `multicol1` 和 `multicol2` 的元素设置了 3 列布局。

   内联样式也在测试中被广泛使用，例如：

   ```c++
   <div id="child" style="width:75%; height:150px"></div>
   ```
   这里使用内联样式设置了元素的宽度和高度。

* **JavaScript:**  虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 `ColumnLayoutAlgorithm` 最终会影响到 JavaScript 可以查询到的元素布局信息。例如，在浏览器中，如果有一个多列布局的容器，JavaScript 可以使用 `element.offsetWidth` 和 `element.offsetHeight` 来获取元素的宽度和高度，这些值的计算就依赖于 `ColumnLayoutAlgorithm` 的正确性。 假设一个场景：一个包含文本的 `div` 元素在一个两列的容器中，JavaScript 代码可能需要根据文本内容动态调整容器的高度或执行其他与布局相关的操作。`ColumnLayoutAlgorithm` 确保文本被正确地分布在两列中，使得 JavaScript 可以获取到准确的尺寸信息。

**3. 逻辑推理的假设输入与输出 (部分示例):**

考虑 `TEST_F(ColumnLayoutAlgorithmTest, EmptyMulticol)` 这个测试用例：

* **假设输入 (HTML/CSS):**
    ```html
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent"></div>
    </div>
    ```
* **预期输出 (部分 Fragment Tree):**
    ```
    offset:0,0 size:210x100
      offset:0,0 size:100x100
    ```
    这个输出表示父元素 (`#parent`) 生成了一个布局片段，其宽度为 210px，高度为 100px。由于设置了 `columns: 2`，它内部至少会创建一个列布局片段容器，宽度为 `(210 - 10) / 2 = 100` px（减去列间距）。

考虑 `TEST_F(ColumnLayoutAlgorithmTest, BlockInTwoColumns)` 这个测试用例：

* **假设输入 (HTML/CSS):**
    ```html
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="width:75%; height:150px"></div>
      </div>
    </div>
    ```
* **预期输出 (部分 Fragment Tree):**
    ```
    offset:0,0 size:210x100
      offset:0,0 size:100x100
        offset:0,0 size:75x100
      offset:110,0 size:100x100
        offset:0,0 size:75x50
    ```
    这个输出表示子元素 (`#child`) 由于高度超过了单列的高度，被分割成了两个布局片段，分别位于第一列和第二列。第一列的片段高度为 100px，第二列的片段高度为剩余的 50px。

**4. 涉及用户或编程常见的使用错误 (部分示例):**

虽然这是测试代码，但它覆盖的场景也反映了用户或开发者在使用 CSS 多列布局时可能遇到的问题：

* **未考虑内容高度超过容器高度的情况:** 测试用例如 `BlockInTwoColumns` 和 `BlockInThreeColumns` 演示了当内容高度超出容器高度时，元素会被分割到不同的列中。用户可能没有预料到这种行为。
* **对浮动元素在多列布局中的影响理解不足:** 测试用例如 `FloatInOneColumn` 和 `TwoFloatsInTwoColumns` 展示了浮动元素如何定位在列中。用户可能错误地认为浮动元素会脱离列布局。
* **错误使用 `break-inside: avoid` 导致内容溢出:** 测试用例如 `BreakInsideAvoidTallBlock` 演示了当一个设置了 `break-inside: avoid` 的元素高度过高无法放入单个列时的情况。
* **忽略边距对列布局的影响:** 测试用例如 `FloatWithMargin` 展示了边距如何影响元素在列中的位置。用户可能没有考虑到边距会占用列的可用空间。

**5. 本部分功能归纳:**

这部分代码定义了一个名为 `ColumnLayoutAlgorithmTest` 的测试类，并包含了多个独立的测试用例，用于验证 Blink 引擎的 `ColumnLayoutAlgorithm` 在处理各种基本的多列布局场景时的正确性。这些测试用例涵盖了空元素、块级元素在单列和多列中的分布、以及一些简单的 CSS 属性（如 `width`, `height`, `columns`, `column-gap`）对布局的影响。  它为后续更复杂的测试用例奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/column_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {
namespace {

class ColumnLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  const PhysicalBoxFragment* RunBlockLayoutAlgorithm(Element* element) {
    BlockNode container(element->GetLayoutBox());
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(1000), kIndefiniteSize));
    return BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  }

  String DumpFragmentTree(const PhysicalBoxFragment* fragment) {
    PhysicalFragment::DumpFlags flags =
        PhysicalFragment::DumpHeaderText | PhysicalFragment::DumpSubtree |
        PhysicalFragment::DumpIndentation | PhysicalFragment::DumpOffset |
        PhysicalFragment::DumpSize;

    return fragment->DumpFragmentTree(flags);
  }

  String DumpFragmentTree(Element* element) {
    auto* fragment = RunBlockLayoutAlgorithm(element);
    return DumpFragmentTree(fragment);
  }
};

TEST_F(ColumnLayoutAlgorithmTest, EmptyEditable) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/20px Ahem; }"
      "#multicol1, #multicol2 { columns: 3; }");
  SetBodyInnerHTML(
      "<div contenteditable id=single></div>"
      "<div contenteditable id=multicol1><br></div>"
      "<div contenteditable id=multicol2></div>");

  EXPECT_EQ(20, GetElementById("single")->OffsetHeight());
  EXPECT_EQ(20, GetElementById("multicol1")->OffsetHeight());
  EXPECT_EQ(20, GetElementById("multicol2")->OffsetHeight());
}

TEST_F(ColumnLayoutAlgorithmTest, EmptyEditableWithFloat) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/20px Ahem; }"
      "float { float:right; width: 50px; height: 50px; background:pink; }"
      "#multicol1, #multicol2 { columns: 3; }");
  SetBodyInnerHTML(
      "<div contenteditable id=single><float></float></div>"
      // Note: <float> spreads into all columns.
      "<div contenteditable id=multicol1><float></float><br></div>"
      "<div contenteditable id=multicol2><float></float></div>");

  EXPECT_EQ(20, GetElementById("single")->OffsetHeight());
  EXPECT_EQ(20, GetElementById("multicol1")->OffsetHeight());
  EXPECT_EQ(20, GetElementById("multicol2")->OffsetHeight());
}

TEST_F(ColumnLayoutAlgorithmTest, EmptyMulticol) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));
  const PhysicalBoxFragment* parent_fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  FragmentChildIterator iterator(parent_fragment);
  const auto* fragment = iterator.NextChild();
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalSize(210, 100), fragment->Size());
  EXPECT_EQ(1UL, fragment->Children().size());
  EXPECT_FALSE(iterator.NextChild());

  // A multicol container will always create at least one fragmentainer.
  fragment = FragmentChildIterator(fragment).NextChild();
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalSize(100, 100), fragment->Size());
  EXPECT_EQ(0UL, fragment->Children().size());

  EXPECT_FALSE(iterator.NextChild());
}

TEST_F(ColumnLayoutAlgorithmTest, EmptyBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child"></div>
      </div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));
  const PhysicalBoxFragment* parent_fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  FragmentChildIterator iterator(parent_fragment);
  const auto* fragment = iterator.NextChild();
  EXPECT_EQ(PhysicalSize(210, 100), fragment->Size());
  ASSERT_TRUE(fragment);
  EXPECT_FALSE(iterator.NextChild());
  iterator.SetParent(fragment);

  // first column fragment
  PhysicalOffset offset;
  fragment = iterator.NextChild(&offset);
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalOffset(), offset);
  EXPECT_EQ(PhysicalSize(100, 100), fragment->Size());
  EXPECT_FALSE(iterator.NextChild());

  // #child fragment in first column
  iterator.SetParent(fragment);
  fragment = iterator.NextChild(&offset);
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalOffset(), offset);
  EXPECT_EQ(PhysicalSize(100, 0), fragment->Size());
  EXPECT_EQ(0UL, fragment->Children().size());
  EXPECT_FALSE(iterator.NextChild());
}

TEST_F(ColumnLayoutAlgorithmTest, BlockInOneColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 310px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="width:60%; height:100%"></div>
      </div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));
  const PhysicalBoxFragment* parent_fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);

  FragmentChildIterator iterator(parent_fragment);
  const auto* fragment = iterator.NextChild();
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalSize(310, 100), fragment->Size());
  EXPECT_FALSE(iterator.NextChild());
  iterator.SetParent(fragment);

  // first column fragment
  PhysicalOffset offset;
  fragment = iterator.NextChild(&offset);
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalOffset(), offset);
  EXPECT_EQ(PhysicalSize(150, 100), fragment->Size());
  EXPECT_FALSE(iterator.NextChild());

  // #child fragment in first column
  iterator.SetParent(fragment);
  fragment = iterator.NextChild(&offset);
  ASSERT_TRUE(fragment);
  EXPECT_EQ(PhysicalOffset(), offset);
  EXPECT_EQ(PhysicalSize(90, 100), fragment->Size());
  EXPECT_EQ(0UL, fragment->Children().size());
  EXPECT_FALSE(iterator.NextChild());
}

TEST_F(ColumnLayoutAlgorithmTest, ZeroHeightBlockAtFragmentainerBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:33px; height:200px;"></div>
        <div style="width:44px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:210x100
      offset:0,0 size:100x100
        offset:0,0 size:33x100
      offset:110,0 size:100x100
        offset:0,0 size:33x100
        offset:0,100 size:44x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BlockInTwoColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="width:75%; height:150px"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:210x100
      offset:0,0 size:100x100
        offset:0,0 size:75x100
      offset:110,0 size:100x100
        offset:0,0 size:75x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BlockInThreeColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="width:75%; height:250px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x100
      offset:110,0 size:100x100
        offset:0,0 size:75x100
      offset:220,0 size:100x100
        offset:0,0 size:75x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ActualColumnCountGreaterThanSpecified) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 2;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 210px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="width:1px; height:250px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:210x100
      offset:0,0 size:100x100
        offset:0,0 size:1x100
      offset:110,0 size:100x100
        offset:0,0 size:1x100
      offset:220,0 size:100x100
        offset:0,0 size:1x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, TwoBlocksInTwoColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child1" style="width:75%; height:60px;"></div>
        <div id="child2" style="width:85%; height:60px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x60
        offset:0,60 size:85x40
      offset:110,0 size:100x100
        offset:0,0 size:85x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ZeroHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 0;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent"></div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x0
    offset:0,0 size:320x0
      offset:0,0 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ZeroHeightWithContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 0;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:20px; height:5px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x0
    offset:0,0 size:320x0
      offset:0,0 size:100x0
        offset:0,0 size:20x1
      offset:110,0 size:100x0
        offset:0,0 size:20x1
      offset:220,0 size:100x0
        offset:0,0 size:20x1
      offset:330,0 size:100x0
        offset:0,0 size:20x1
      offset:440,0 size:100x0
        offset:0,0 size:20x1
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, OverflowedBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child1" style="width:75%; height:60px;">
          <div id="grandchild1" style="width:50px; height:120px;"></div>
          <div id="grandchild2" style="width:40px; height:20px;"></div>
        </div>
        <div id="child2" style="width:85%; height:10px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x60
          offset:0,0 size:50x100
        offset:0,60 size:85x10
      offset:110,0 size:100x100
        offset:0,0 size:75x0
          offset:0,0 size:50x20
          offset:0,20 size:40x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, OverflowedBlock2) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:75%; height:10px;">
          <div style="width:50px; height:220px;"></div>
        </div>
        <div style="width:85%; height:10px;"></div>
        <div style="width:65%; height:10px;">
          <div style="width:51px; height:220px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x10
          offset:0,0 size:50x100
        offset:0,10 size:85x10
        offset:0,20 size:65x10
          offset:0,0 size:51x80
      offset:110,0 size:100x100
        offset:0,0 size:75x0
          offset:0,0 size:50x100
        offset:0,0 size:65x0
          offset:0,0 size:51x100
      offset:220,0 size:100x100
        offset:0,0 size:75x0
          offset:0,0 size:50x20
        offset:0,0 size:65x0
          offset:0,0 size:51x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, OverflowedBlock3) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:75%; height:60px;">
          <div style="width:50px; height:220px;"></div>
        </div>
        <div style="width:85%; height:10px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x60
          offset:0,0 size:50x100
        offset:0,60 size:85x10
      offset:110,0 size:100x100
        offset:0,0 size:75x0
          offset:0,0 size:50x100
      offset:220,0 size:100x100
        offset:0,0 size:75x0
          offset:0,0 size:50x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, UnusedSpaceInBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:300px;">
          <div style="width:20px; height:20px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:20x20
      offset:110,0 size:100x100
        offset:0,0 size:100x100
      offset:220,0 size:100x100
        offset:0,0 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatInOneColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        height: 100px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child" style="float:left; width:75%; height:100px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:75x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, TwoFloatsInOneColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child1" style="float:left; width:15%; height:100px;"></div>
        <div id="child2" style="float:right; width:16%; height:100px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:15x100
        offset:84,0 size:16x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, TwoFloatsInTwoColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div id="child1" style="float:left; width:15%; height:150px;"></div>
        <div id="child2" style="float:right; width:16%; height:150px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:15x100
        offset:84,0 size:16x100
      offset:110,0 size:100x100
        offset:0,0 size:15x50
        offset:84,0 size:16x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithForcedBreak) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:50px;"></div>
        <div style="float:left; width:77px;">
           <div style="width:66px; height:30px;"></div>
           <div style="break-before:column; width:55px; height:30px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x50
        offset:0,50 size:77x50
          offset:0,0 size:66x30
      offset:110,0 size:100x100
        offset:0,0 size:77x30
          offset:0,0 size:55x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithMargin) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="float:left; width:77px; margin-top:10px; height:140px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,10 size:77x90
      offset:110,0 size:100x100
        offset:0,0 size:77x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithMarginBelowFloat) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="float:left; width:66px; height:40px;"></div>
        <div style="float:left; width:77px; margin-top:10px; height:70px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:66x40
        offset:0,50 size:77x50
      offset:110,0 size:100x100
        offset:0,0 size:77x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithLastResortBreak) {
  // Breaking inside the line is not possible, and breaking between the
  // block-start content edge and the first child should be avoided.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:99px; height:90px;"></div>
        <div style="float:left; width:88px;">
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:99x90
      offset:110,0 size:100x100
        offset:0,0 size:88x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithAvoidBreak) {
  // We want to avoid breaking inside the float child, and breaking before it
  // should be avoided (not a valid breakpoint).
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:99px; height:90px;"></div>
        <div style="float:left; width:88px;">
          <div class="content" style="width:77px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:99x90
      offset:110,0 size:100x100
        offset:0,0 size:88x20
          offset:0,0 size:77x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatWithMarginAndAvoidBreak) {
  // We want to avoid breaking inside the float child, and breaking before it
  // should be avoided (not a valid breakpoint). The top margin should be kept
  // in the next column.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:99px; height:90px;"></div>
        <div style="float:left; width:88px; margin-top:5px;">
          <div class="content" style="width:77px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:99x90
      offset:110,0 size:100x100
        offset:0,5 size:88x20
          offset:0,0 size:77x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, UnbreakableFloatBeforeBreakable) {
  // https://www.w3.org/TR/CSS22/visuren.html#float-position
  //
  // "The outer top of a floating box may not be higher than the outer top of
  // any block or floated box generated by an element earlier in the source
  // document."
  //
  // This means that if we decide to break before one float, we also need to
  // break before all subsequent floats, even if such floats don't require that
  // on their own.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:99px; height:90px;"></div>
        <div style="float:left; width:22px; height:50px;">
          <div class="content" style="width:11px;"></div>
        </div>
        <div style="float:left; width:33px; height:50px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:99x90
      offset:110,0 size:100x100
        offset:0,0 size:22x50
          offset:0,0 size:11x20
        offset:22,0 size:33x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BlockWithTopMarginInThreeColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:70px;"></div>
        <div style="margin-top:10px; width:60px; height:150px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x70
        offset:0,80 size:60x20
      offset:110,0 size:100x100
        offset:0,0 size:60x100
      offset:220,0 size:100x100
        offset:0,0 size:60x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BlockStartAtColumnBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:100px;"></div>
        <div style="width:60px; height:100px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x100
      offset:110,0 size:100x100
        offset:0,0 size:60x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedBlockAfterBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:10px;"></div>
        <div>
          <div style="width:60px; height:120px;"></div>
          <div style="width:50px; height:20px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x10
        offset:0,10 size:100x90
          offset:0,0 size:60x90
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,0 size:60x30
          offset:0,30 size:50x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid; width:20px; height:70px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
      offset:110,0 size:100x100
        offset:0,0 size:20x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideAvoidColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid-column; width:20px; height:70px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
      offset:110,0 size:100x100
        offset:0,0 size:20x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideAvoidPage) {
  // break-inside:avoid-page has no effect, unless we're breaking into pages.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid-page; width:20px; height:70px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
        offset:0,50 size:20x50
      offset:110,0 size:100x100
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideAvoidTallBlock) {
  // The block that has break-inside:avoid is too tall to fit in one
  // fragmentainer. So a break is unavoidable. Let's check that:
  // 1. The block is still shifted to the start of the next fragmentainer
  // 2. We give up shifting it any further (would cause infinite an loop)
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
```