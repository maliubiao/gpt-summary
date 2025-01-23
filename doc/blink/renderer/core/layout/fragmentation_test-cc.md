Response:
Let's break down the thought process for analyzing the `fragmentation_test.cc` file.

1. **Understand the Core Purpose:** The filename immediately suggests testing related to "fragmentation."  Given the context of a browser rendering engine (Blink/Chromium), this most likely refers to how content is split and rendered across multiple columns, pages, or other fragmented layouts. The `#include` directives confirm this, referencing layout-related classes like `BlockLayoutAlgorithm`, `PhysicalBoxFragment`, etc. The namespace `blink` further solidifies this is part of the Blink rendering engine.

2. **Identify the Testing Framework:** The line `class FragmentationTest : public BaseLayoutAlgorithmTest` reveals that this file uses a testing framework. The naming convention `TEST_F` also strongly indicates a C++ testing framework, likely Google Test, commonly used within Chromium. This tells us the file contains individual test cases designed to verify specific aspects of fragmentation logic.

3. **Analyze Individual Test Cases:**  The next step is to go through each `TEST_F` function and understand what it's testing. Here's a breakdown of the thought process for each test:

    * **`MultipleFragments`:**  The HTML sets up a multicolumn layout (`columns:3`). The test then asserts the number of fragments created for different elements and the size of those fragments. This directly tests basic multicolumn fragmentation. The comments within the test provide valuable insights into *why* certain fragment counts are expected (e.g., the third fragment for `#outer1` to hold overflow).

    * **`MultipleFragmentsAndColumnSpanner`:** This builds on the previous test by adding elements with `column-span:all`. The assertions focus on how these spanning elements affect the fragmentation of their siblings and ancestors. The key takeaway here is understanding how elements that span multiple columns are handled in the fragmentation process.

    * **`MultipleFragmentsNestedMulticol`:** This introduces nested multicolumn layouts. The assertions check how fragmentation behaves when multicolumn containers are inside other multicolumn containers. This tests the interaction and correctness of nested fragmentation.

    * **`HasSeenAllChildrenIfc`:** The HTML sets up a multicolumn layout with an inline flow container (`ifc`). The test focuses on the `BlockBreakToken` associated with each fragment and checks the `HasSeenAllChildren()` flag. This indicates the test is verifying the logic that tracks whether all the content of an element has been processed and rendered within the current set of fragments. This is crucial for correct pagination and continuation of content.

    * **`InkOverflowInline`:**  This test focuses on "ink overflow" in an inline context within a multicolumn layout. The CSS uses `inline-block` elements and varying widths. The assertions check the `VisualOverflowRect` of both the flow thread and the container. This is testing how the rendering engine calculates and handles visual overflow, especially when inline content extends beyond column boundaries.

    * **`OffsetFromOwnerLayoutBoxFloat`:** This test involves a floated element within a multicolumn container. The assertions check the `OffsetFromOwnerLayoutBox()` of the fragments of the floated element. This verifies how the positioning and offset of fragmented floated elements are calculated relative to their containing block.

    * **`OffsetFromOwnerLayoutBoxNested`:**  Similar to the previous test, but with nested multicolumn layouts. The assertions again check `OffsetFromOwnerLayoutBox()` for an element within the nested structure. This confirms the correctness of offset calculations in more complex nested fragmentation scenarios.

4. **Identify Relationships with Web Technologies:**  As each test is analyzed, the connections to HTML, CSS, and JavaScript (indirectly through DOM manipulation) become apparent. The HTML structure defines the content and hierarchy, CSS styles the layout (including multicolumn properties), and the C++ code simulates the layout process that would normally be triggered by the browser when rendering these elements. JavaScript is not directly involved in the *execution* of these tests, but the DOM manipulation within the test setup (`SetBodyInnerHTML`, `GetElementById`) mimics actions that JavaScript could perform.

5. **Consider Logical Reasoning and Assumptions:**  The tests make assumptions about how the layout algorithm *should* work. For example, in `MultipleFragments`, the assumption is that the content will be distributed across the specified number of columns. The test then verifies if the actual output (number of fragments, fragment sizes) matches these expectations. The comments within the tests often explain the reasoning behind the expected outputs.

6. **Think About User and Developer Errors:** By understanding what the tests are verifying, it becomes possible to infer common mistakes users or developers might make. For instance, incorrect `column-width` or `column-gap` values might lead to unexpected fragmentation. Not accounting for the height of content when using `column-fill: auto` could also result in more columns than intended.

7. **Structure the Output:** Finally, organize the findings into a clear and structured response, covering the requested aspects: functionality, relationships with web technologies, logical reasoning, and potential errors. Use clear examples and code snippets where relevant.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe the tests are also directly testing pagination?  **Correction:** While fragmentation is related to pagination, these specific tests focus on *column* fragmentation within a single viewport. Pagination would involve different layout mechanisms.

* **Initial Thought:** How does JavaScript fit in? **Refinement:** JavaScript isn't *running* the layout algorithm here. However, JavaScript's ability to manipulate the DOM is the reason these layout calculations are necessary. The tests are simulating the layout process triggered by changes that JavaScript could initiate.

* **Missing Detail:**  Initially, I might focus too much on the high-level goal of fragmentation. **Refinement:**  The individual test cases reveal the specific *details* being tested: the number and size of fragments, how spanning elements are handled, the `HasSeenAllChildren` flag, ink overflow, and offset calculations. These details are crucial for a comprehensive understanding.

By following this systematic approach, one can effectively analyze the purpose and implications of a source code file like `fragmentation_test.cc`.
这个文件 `blink/renderer/core/layout/fragmentation_test.cc` 是 Chromium Blink 引擎中用于测试 **布局过程中关于内容分片 (fragmentation)** 功能的单元测试文件。

**它的主要功能是：**

1. **验证多列布局 (Multi-column Layout):** 测试在使用了 CSS 的 `columns`, `column-width`, `column-gap`, `column-fill` 等属性时，内容是否被正确地分割成多个列，以及这些列的尺寸和布局是否符合预期。
2. **验证跨列元素 (Column Spanners):** 测试当元素使用了 CSS 的 `column-span: all` 属性时，它是否能够正确地跨越所有列，以及这种跨越对其他元素的布局和分片产生的影响。
3. **验证嵌套多列布局:** 测试在一个多列容器内部嵌套另一个多列容器时，内容的分片是否正确，以及各个容器和元素的布局是否符合预期。
4. **验证分片状态跟踪:** 测试在内容被分割成多个片段后，引擎是否能正确跟踪哪些元素的所有内容已经被处理和布局完成。这涉及到 `BlockBreakToken` 和 `HasSeenAllChildren()` 等概念。
5. **验证溢出处理 (Overflow):**  测试在多列布局中，当内容超出列的范围时，引擎如何处理溢出，特别是 "ink overflow" (渲染产生的视觉溢出)。
6. **验证分片偏移 (Fragment Offset):** 测试在多列布局中，被分割成多个片段的元素，其各个片段相对于其父容器的偏移量是否计算正确，尤其是在存在浮动元素或嵌套多列布局的情况下。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联着 HTML 和 CSS 的功能，因为它测试的是 CSS 属性如何影响 HTML 元素的布局。JavaScript 在这里扮演的是 *间接* 的角色。开发者可以使用 JavaScript 来动态地修改 HTML 结构和 CSS 样式，从而触发布局计算。这个测试文件验证的就是 Blink 引擎在处理这些动态变化时，关于内容分片逻辑的正确性。

**举例说明：**

* **CSS 多列布局:**
  ```html
  <div style="columns:3; width:600px;">
    <div>内容一</div>
    <div>内容二</div>
    <div>内容三</div>
    <div>内容四</div>
  </div>
  ```
  `FragmentationTest` 中的 `MultipleFragments` 测试案例就验证了类似场景下，内容是否被正确分到三列，以及每列的高度和宽度是否符合预期。

* **CSS 跨列元素:**
  ```html
  <div style="columns:2; width:400px;">
    <div>普通内容</div>
    <div style="column-span:all;">跨列内容</div>
    <div>更多普通内容</div>
  </div>
  ```
  `MultipleFragmentsAndColumnSpanner` 测试案例验证了跨列元素是否占据了两列的宽度，以及它之前的和之后的元素如何布局。

* **JavaScript 动态修改:**
  虽然测试文件中没有直接执行 JavaScript 代码，但测试的场景模拟了 JavaScript 可能会触发的布局变化。例如，如果 JavaScript 代码动态地添加或删除了元素，或者修改了元素的 CSS 属性（如 `columns` 的值），那么这个测试文件中的逻辑就会被用来确保新的布局是正确的。

**逻辑推理与假设输入输出：**

以 `MultipleFragments` 测试案例为例：

**假设输入:**

```html
<div id="container">
  <div style="columns:3; width:620px; column-fill:auto; height:100px; column-gap:10px;">
    <div id="outer1" style="height:150px;">
      <div id="inner1" style="height:250px;"></div>
      <div id="inner2" style="height:10px;"></div>
    </div>
    <div id="outer2" style="height:90px;"></div>
  </div>
</div>
```

**逻辑推理:**

1. 容器 `#container > div` 设置了 3 列，宽度 620px，列间距 10px。因此每列的可用宽度是 (620 - 2 * 10) / 3 = 200px。容器的高度是 100px。
2. `#outer1` 的高度是 150px，超过了容器的高度，因此会占据多个列的片段。
3. `#inner1` 的高度是 250px，远超 `#outer1` 和容器的高度，会跨越多个列。
4. `#inner2` 的高度很小，理论上可以在一个列内显示完毕。
5. `#outer2` 的高度是 90px，会根据之前的元素布局，从合适的列开始布局。

**预期输出 (部分):**

* `#outer1` 将被分割成多个片段，因为其内容超出了单列的高度。由于 `#inner1` 的高度很高， `#outer1` 可能需要额外的片段来容纳其子元素。
* `#inner1` 将被分割成多个片段，因为它需要跨越多个列。
* `#inner2` 很可能只需要一个片段。
* `#outer2` 将根据之前的布局情况，可能会从第二列或第三列开始，并可能被分割成多个片段。

测试代码中的 `EXPECT_EQ` 断言就验证了这些预期，例如：

```c++
EXPECT_EQ(outer1->PhysicalFragmentCount(), 3u); // 预期 #outer1 有 3 个片段
EXPECT_EQ(outer1->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 100)); // 预期第一个片段的大小
```

**用户或编程常见的使用错误举例说明：**

1. **未考虑 `column-fill` 属性:** 用户可能期望内容均匀分布在所有列中，但如果 `column-fill` 设置为 `auto` (默认值)，浏览器可能会优先填充前面的列，导致内容分布不均。
   ```html
   <div style="columns:3; height:100px;">
     <div>很长的内容，只够填充第一列</div>
   </div>
   ```
   用户可能会惊讶地发现，只有第一列有内容，而其他列是空的。如果想要更均匀的分布，应该使用 `column-fill: balance;`。

2. **误解跨列元素的影响:** 开发者可能没有意识到 `column-span: all` 的元素会打断正常的列布局，并可能导致后续元素重新排列。
   ```html
   <div style="columns:2;">
     <div>第一列内容</div>
     <div style="column-span:all;">跨越两列的标题</div>
     <div>第二列内容，但可能因为标题占据了位置而跑到下方</div>
   </div>
   ```
   开发者可能会期望 "第二列内容" 出现在标题的右侧，但实际上它会被推到标题下方。

3. **忽略 `orphans` 和 `widows` 属性:** 在分页或分列的场景中，`orphans` 和 `widows` 用于控制段落开头和结尾在片段中的最小行数，以避免出现孤行或寡行的情况，影响阅读体验。开发者可能会忘记设置这些属性，导致出现不美观的断行。
   ```html
   <div style="columns:2; orphans:2; widows:2;">
     <p>一段很长的文字...</p>
   </div>
   ```
   如果段落末尾只剩一行在下一列的开头，而 `widows` 设置为 2，那么这段文字会被整体移到上一列，或者在当前列添加空白以满足最小行数的要求。

4. **对嵌套多列布局的复杂性估计不足:** 嵌套多列布局的行为可能比较复杂，开发者需要仔细考虑内外层容器的尺寸和属性，以及内容的高度，才能准确预测布局结果。错误地设置尺寸可能导致内容溢出或布局混乱。

总而言之，`fragmentation_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎在处理 CSS 分列布局时的正确性和稳定性，从而保证了网页在不同浏览器和平台上的渲染一致性。理解其功能有助于开发者更好地理解和使用 CSS 的分列相关属性，并避免常见的布局错误。

### 提示词
```
这是目录为blink/renderer/core/layout/fragmentation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {
namespace {

class FragmentationTest : public BaseLayoutAlgorithmTest {
 protected:
  const PhysicalBoxFragment* RunBlockLayoutAlgorithm(Element* element) {
    BlockNode container(element->GetLayoutBox());
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(1000), kIndefiniteSize));
    return BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  }
};

TEST_F(FragmentationTest, MultipleFragments) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div style="columns:3; width:620px; column-fill:auto; height:100px; column-gap:10px;">
        <div id="outer1" style="height:150px;">
          <div id="inner1" style="height:250px;"></div>
          <div id="inner2" style="height:10px;"></div>
        </div>
        <div id="outer2" style="height:90px;"></div>
      </div>
    </div>
  )HTML");

  RunBlockLayoutAlgorithm(GetElementById("container"));
  const LayoutBox* outer1 = GetLayoutBoxByElementId("outer1");
  const LayoutBox* outer2 = GetLayoutBoxByElementId("outer2");
  const LayoutBox* inner1 = GetLayoutBoxByElementId("inner1");
  const LayoutBox* inner2 = GetLayoutBoxByElementId("inner2");

  EXPECT_EQ(outer1->PhysicalFragmentCount(), 3u);
  EXPECT_EQ(outer2->PhysicalFragmentCount(), 2u);
  EXPECT_EQ(inner1->PhysicalFragmentCount(), 3u);
  EXPECT_EQ(inner2->PhysicalFragmentCount(), 1u);

  // While the #outer1 box itself only needs two fragments, we need to create a
  // third fragment to hold the overflowing children in the third column.
  EXPECT_EQ(outer1->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 100));
  EXPECT_EQ(outer1->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 50));
  EXPECT_EQ(outer1->GetPhysicalFragment(2)->Size(), PhysicalSize(200, 0));

  // #inner1 overflows its parent and uses three columns.
  EXPECT_EQ(inner1->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 100));
  EXPECT_EQ(inner1->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 100));
  EXPECT_EQ(inner1->GetPhysicalFragment(2)->Size(), PhysicalSize(200, 50));

  // #inner2 is tiny, and only needs some space in one column (the third one).
  EXPECT_EQ(inner2->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 10));

  // #outer2 starts in the second column and ends in the third.
  EXPECT_EQ(outer2->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 50));
  EXPECT_EQ(outer2->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 40));
}

TEST_F(FragmentationTest, MultipleFragmentsAndColumnSpanner) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="multicol" style="columns:3; width:620px; column-gap:10px; orphans:1; widows:1; line-height:20px;">
        <div id="outer">
          <div id="inner1"><br><br><br><br></div>
          <div id="spanner1" style="column-span:all;"></div>
          <div id="inner2"><br><br><br><br><br></div>
          <div id="spanner2" style="column-span:all;"></div>
          <div id="inner3"><br><br><br><br><br><br><br></div>
        </div>
      </div>
    </div>
  )HTML");

  RunBlockLayoutAlgorithm(GetElementById("container"));
  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  const LayoutBox* outer = GetLayoutBoxByElementId("outer");
  const LayoutBox* inner1 = GetLayoutBoxByElementId("inner1");
  const LayoutBox* inner2 = GetLayoutBoxByElementId("inner2");
  const LayoutBox* inner3 = GetLayoutBoxByElementId("inner3");
  const LayoutBox* spanner1 = GetLayoutBoxByElementId("spanner1");
  const LayoutBox* spanner2 = GetLayoutBoxByElementId("spanner2");

  EXPECT_EQ(multicol->PhysicalFragmentCount(), 1u);

  // #outer will create 8 fragments: 2 for the 2 columns before the first
  // spanner, 3 for the 3 columns between the two spanners, and 3 for the 3
  // columns after the last spanner.
  EXPECT_EQ(outer->PhysicalFragmentCount(), 8u);

  // #inner1 has 4 lines split into 2 columns.
  EXPECT_EQ(inner1->PhysicalFragmentCount(), 2u);

  // #inner2 has 5 lines split into 3 columns.
  EXPECT_EQ(inner2->PhysicalFragmentCount(), 3u);

  // #inner3 has 8 lines split into 3 columns.
  EXPECT_EQ(inner3->PhysicalFragmentCount(), 3u);

  EXPECT_EQ(spanner1->PhysicalFragmentCount(), 1u);
  EXPECT_EQ(spanner2->PhysicalFragmentCount(), 1u);

  EXPECT_EQ(multicol->GetPhysicalFragment(0)->Size(), PhysicalSize(620, 140));
  EXPECT_EQ(outer->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(outer->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(outer->GetPhysicalFragment(2)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(outer->GetPhysicalFragment(3)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(outer->GetPhysicalFragment(4)->Size(), PhysicalSize(200, 20));
  EXPECT_EQ(outer->GetPhysicalFragment(5)->Size(), PhysicalSize(200, 60));
  EXPECT_EQ(outer->GetPhysicalFragment(6)->Size(), PhysicalSize(200, 60));
  EXPECT_EQ(outer->GetPhysicalFragment(7)->Size(), PhysicalSize(200, 20));
  EXPECT_EQ(inner1->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(inner1->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(inner2->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(inner2->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 40));
  EXPECT_EQ(inner2->GetPhysicalFragment(2)->Size(), PhysicalSize(200, 20));
  EXPECT_EQ(inner3->GetPhysicalFragment(0)->Size(), PhysicalSize(200, 60));
  EXPECT_EQ(inner3->GetPhysicalFragment(1)->Size(), PhysicalSize(200, 60));
  EXPECT_EQ(inner3->GetPhysicalFragment(2)->Size(), PhysicalSize(200, 20));
  EXPECT_EQ(spanner1->GetPhysicalFragment(0)->Size(), PhysicalSize(620, 0));
  EXPECT_EQ(spanner2->GetPhysicalFragment(0)->Size(), PhysicalSize(620, 0));
}

TEST_F(FragmentationTest, MultipleFragmentsNestedMulticol) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="outer_multicol" style="columns:3; column-fill:auto; height:100px; width:620px; column-gap:10px;">
        <div id="inner_multicol" style="columns:2; column-fill:auto;">
          <div id="child1" style="width:11px; height:350px;"></div>
          <div id="child2" style="width:22px; height:350px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  RunBlockLayoutAlgorithm(GetElementById("container"));
  const LayoutBox* outer_multicol = GetLayoutBoxByElementId("outer_multicol");
  const LayoutBox* inner_multicol = GetLayoutBoxByElementId("inner_multicol");
  const LayoutBox* child1 = GetLayoutBoxByElementId("child1");
  const LayoutBox* child2 = GetLayoutBoxByElementId("child2");

  EXPECT_EQ(outer_multicol->PhysicalFragmentCount(), 1u);

  // The content is too tall (350px + 350px, column height 100px, 2*3 columns =
  // 600px) and will use one more column than we have specified.
  EXPECT_EQ(inner_multicol->PhysicalFragmentCount(), 4u);

  // 350px tall content with a column height of 100px will require 4 fragments.
  EXPECT_EQ(child1->PhysicalFragmentCount(), 4u);
  EXPECT_EQ(child2->PhysicalFragmentCount(), 4u);

  EXPECT_EQ(outer_multicol->GetPhysicalFragment(0)->Size(),
            PhysicalSize(620, 100));

  EXPECT_EQ(inner_multicol->GetPhysicalFragment(0)->Size(),
            PhysicalSize(200, 100));
  EXPECT_EQ(inner_multicol->GetPhysicalFragment(1)->Size(),
            PhysicalSize(200, 100));
  EXPECT_EQ(inner_multicol->GetPhysicalFragment(2)->Size(),
            PhysicalSize(200, 100));
  EXPECT_EQ(inner_multicol->GetPhysicalFragment(3)->Size(),
            PhysicalSize(200, 100));

  // #child1 starts at the beginning of a column, so the last fragment will be
  // shorter than the rest.
  EXPECT_EQ(child1->GetPhysicalFragment(0)->Size(), PhysicalSize(11, 100));
  EXPECT_EQ(child1->GetPhysicalFragment(1)->Size(), PhysicalSize(11, 100));
  EXPECT_EQ(child1->GetPhysicalFragment(2)->Size(), PhysicalSize(11, 100));
  EXPECT_EQ(child1->GetPhysicalFragment(3)->Size(), PhysicalSize(11, 50));

  // #child2 starts in the middle of a column, so the first fragment will be
  // shorter than the rest.
  EXPECT_EQ(child2->GetPhysicalFragment(0)->Size(), PhysicalSize(22, 50));
  EXPECT_EQ(child2->GetPhysicalFragment(1)->Size(), PhysicalSize(22, 100));
  EXPECT_EQ(child2->GetPhysicalFragment(2)->Size(), PhysicalSize(22, 100));
  EXPECT_EQ(child2->GetPhysicalFragment(3)->Size(), PhysicalSize(22, 100));
}

TEST_F(FragmentationTest, HasSeenAllChildrenIfc) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div style="columns:3; column-fill:auto; height:50px; line-height:20px; orphans:1; widows:1;">
        <div id="ifc" style="height:300px;">
          <br><br>
          <br><br>
          <br><br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  RunBlockLayoutAlgorithm(GetElementById("container"));

  const LayoutBox* ifc = GetLayoutBoxByElementId("ifc");
  ASSERT_EQ(ifc->PhysicalFragmentCount(), 6u);
  const PhysicalBoxFragment* fragment = ifc->GetPhysicalFragment(0);
  const BlockBreakToken* break_token = fragment->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_FALSE(break_token->HasSeenAllChildren());

  fragment = ifc->GetPhysicalFragment(1);
  break_token = fragment->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_FALSE(break_token->HasSeenAllChildren());

  fragment = ifc->GetPhysicalFragment(2);
  break_token = fragment->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_FALSE(break_token->HasSeenAllChildren());

  fragment = ifc->GetPhysicalFragment(3);
  break_token = fragment->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->HasSeenAllChildren());

  fragment = ifc->GetPhysicalFragment(4);
  break_token = fragment->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->HasSeenAllChildren());

  fragment = ifc->GetPhysicalFragment(5);
  break_token = fragment->GetBreakToken();
  EXPECT_FALSE(break_token);
}

TEST_F(FragmentationTest, InkOverflowInline) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #container {
      font-size: 10px;
      column-width: 100px;
      column-gap: 10px;
      width: 210px;
      line-height: 15px;
      height: 15px;
    }
    atomic {
      display: inline-block;
      width: 100px;
      height: 10px;
      background: blue;
    }
    .w15 {
      width: 150px;
      background: orange;
    }
    </style>
    <div id="container">
      <div>
        <!-- 1st column does not have ink overflow. -->
        <atomic></atomic>
        <!-- 2nd column has 50px ink overflow to right. -->
        <atomic><atomic class="w15"></atomic></atomic>
      </div>
    </div>
  )HTML");
  const auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  const auto* flow_thread = To<LayoutBlockFlow>(container->FirstChild());
  DCHECK(flow_thread->IsLayoutFlowThread());
  // |flow_thread| is in the stitched coordinate system.
  // Legacy had (0, 0, 150, 30), but NG doesn't compute for |LayoutFlowThread|.
  EXPECT_EQ(flow_thread->VisualOverflowRect(), PhysicalRect(0, 0, 100, 30));
  EXPECT_EQ(container->VisualOverflowRect(), PhysicalRect(0, 0, 260, 15));
}

TEST_F(FragmentationTest, OffsetFromOwnerLayoutBoxFloat) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #columns {
      column-width: 100px;
      column-gap: 10px;
      column-fill: auto;
      width: 320px;
      height: 500px;
    }
    #float {
      float: left;
      width: 50px;
      height: 500px;
      background: orange;
    }
    </style>
    <div id="columns" style="background: blue">
      <!-- A spacer to make `target` start at 2nd column. -->
      <div style="height: 800px"></div>
      <div id="float"></div>
      Text
    </div>
  )HTML");
  const auto* target = GetLayoutBoxByElementId("float");
  EXPECT_EQ(target->PhysicalFragmentCount(), 2u);
  const PhysicalBoxFragment* fragment0 = target->GetPhysicalFragment(0);
  EXPECT_EQ(fragment0->OffsetFromOwnerLayoutBox(), PhysicalOffset());
  const PhysicalBoxFragment* fragment1 = target->GetPhysicalFragment(1);
  EXPECT_EQ(fragment1->OffsetFromOwnerLayoutBox(), PhysicalOffset(110, -300));
}

TEST_F(FragmentationTest, OffsetFromOwnerLayoutBoxNested) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
    }
    #outer-columns {
      column-width: 100px;
      column-gap: 10px;
      column-fill: auto;
      width: 320px;
      height: 500px;
    }
    #inner-columns {
      column-width: 45px;
      column-gap: 10px;
      column-fill: auto;
      width: 100px;
      height: 800px;
    }
    </style>
    <div id="outer-columns" style="background: blue">
      <!-- A spacer to make `inner-columns` start at 2nd column. -->
      <div style="height: 700px"></div>
      <div id="inner-columns" style="height: 800px; background: purple">
        <!-- A spacer to make `target` start at 2nd column. -->
        <div style="height: 400px"></div>
        <div id="target" style="background: orange; height: 1000px"></div>
      </div>
    </div>
  )HTML");
  const auto* target = GetLayoutBoxByElementId("target");
  EXPECT_EQ(target->PhysicalFragmentCount(), 3u);
  const PhysicalBoxFragment* fragment0 = target->GetPhysicalFragment(0);
  EXPECT_EQ(fragment0->OffsetFromOwnerLayoutBox(), PhysicalOffset());
  const PhysicalBoxFragment* fragment1 = target->GetPhysicalFragment(1);
  EXPECT_EQ(fragment1->OffsetFromOwnerLayoutBox(), PhysicalOffset(55, -300));
  const PhysicalBoxFragment* fragment2 = target->GetPhysicalFragment(2);
  EXPECT_EQ(fragment2->OffsetFromOwnerLayoutBox(), PhysicalOffset(110, -300));
}

}  // anonymous namespace
}  // namespace blink
```