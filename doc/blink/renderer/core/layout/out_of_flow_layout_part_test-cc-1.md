Response:
The user wants a summary of the functionality of the provided C++ code file. This file seems to contain tests for out-of-flow (OOF) elements within the Blink rendering engine, specifically focusing on how these elements interact with multi-column layouts.

Here's a breakdown of the steps to achieve the desired output:

1. **Identify the core purpose:** The file `out_of_flow_layout_part_test.cc` contains C++ tests for the layout of out-of-flow elements, particularly in the context of multi-column layouts.

2. **List key functionalities:**  Based on the test names and code, identify the specific scenarios being tested. These include:
    - Basic OOF placement in multi-column layouts.
    - OOF elements spanning columns (`column-span: all`).
    - OOF elements causing the creation of new empty columns.
    - OOF elements with percentage-based height resolution.
    - OOF elements in nested multi-column layouts.
    - OOF elements positioned with the `bottom` property.
    - OOF elements within inline containing blocks in multi-column layouts.
    - Verification of the correct placement of positioned elements within multi-column containers.
    - Verification of fragmentainer break tokens.
    - Relayout scenarios involving nested multi-column layouts and OOF elements.
    - Use counters for specific out-of-flow scenarios.
    - Scenarios with multiple OOF elements, both fragmented and non-fragmented.

3. **Relate to web technologies:** Connect the C++ test scenarios to the corresponding HTML, CSS, and JavaScript concepts.
    - **HTML:** The test cases use HTML to create the structure of the elements being tested, like `<div>`, `<span>`.
    - **CSS:**  The tests heavily utilize CSS properties like `position: absolute`, `column-count`, `column-gap`, `column-span`, `height`, `width`, `top`, `bottom`, `justify-self`, `inset`.
    - **JavaScript:** While the test file itself is C++, it indirectly relates to JavaScript as the rendering engine will eventually render these layouts based on the HTML, CSS, which could be dynamically created or modified by JavaScript.

4. **Provide examples:**  For each functionality, give concise examples of the HTML and CSS being used in the tests. These examples are essentially the setup part of the test cases.

5. **Explain logic and assumptions:** For tests that involve logical reasoning (like checking the structure of the fragment tree), explicitly state the assumptions about the input HTML/CSS and the expected output of the fragment tree. This involves interpreting the `DumpFragmentTree` output.

6. **Identify potential user errors:**  Consider common mistakes developers might make when working with out-of-flow elements and multi-column layouts based on the test scenarios.

7. **Summarize overall function:** Provide a concise summary of the file's purpose, bringing together all the identified functionalities.

8. **Structure the output:**  Organize the information logically with clear headings and bullet points to enhance readability.

**Self-Correction/Refinement during the thought process:**

- **Initial thought:** Focus solely on describing the C++ code.
- **Correction:** Recognize the need to connect the C++ tests to web technologies (HTML, CSS, JavaScript) as requested in the prompt.
- **Initial thought:** Simply list the test names.
- **Correction:**  Instead of just listing names, analyze the test code to understand the underlying functionality being verified.
- **Initial thought:**  Provide generic examples of HTML/CSS.
- **Correction:**  Use the actual HTML/CSS snippets from the test cases to make the examples concrete and directly relevant.
- **Initial thought:** Describe the output as just "testing layout".
- **Correction:** Be more specific about what aspects of the layout are being tested (e.g., positioning, fragmentation, break tokens).
- **Initial thought:**  Ignore the "part 2" instruction.
- **Correction:**  Ensure the final summary addresses the "part 2" request by synthesizing the information from the detailed analysis.
这是对 `blink/renderer/core/layout/out_of_flow_layout_part_test.cc` 文件功能的归纳，基于你提供的代码片段。

**功能归纳:**

该测试文件主要负责测试 Blink 渲染引擎中 **out-of-flow (OOF)** 布局元素在 **多列布局 (multicolumn layout)** 中的渲染和布局行为。具体来说，它涵盖了以下几个关键方面：

1. **基本的 OOF 元素在多列容器中的定位和布局:**  测试绝对定位 (`position: absolute`) 的元素在多列容器中如何被放置，以及它们是否会影响多列的列分布。例如，测试 OOF 元素是否会与列内容重叠，或者占据新的列空间。

2. **OOF 元素与列跨越 (column-span: all) 的交互:**  测试具有 `column-span: all` 属性的元素与 OOF 元素同时存在时，渲染引擎如何处理布局。这包括 OOF 元素是否会影响跨列元素的布局，以及跨列元素是否会影响 OOF 元素的定位。

3. **OOF 元素导致创建新的空列:**  测试当 OOF 元素开始布局时，如果其定位超出了当前已有的列范围，渲染引擎是否会创建新的空列来容纳该元素。

4. **OOF 元素的尺寸计算，特别是百分比高度:**  测试 OOF 元素使用百分比高度 (`height: 100%`) 时，在多列布局中如何进行解析和计算。这涉及到 OOF 元素的包含块和其高度的确定。

5. **嵌套多列布局中的 OOF 元素:**  测试在嵌套的多列布局中，OOF 元素如何被定位和布局。这包括内层多列和外层多列的相互影响。

6. **使用 `bottom` 属性定位的 OOF 元素:**  测试使用 `bottom` 属性进行定位的 OOF 元素在多列布局中的渲染行为，以及当其高度设置为 `auto` 时的尺寸计算。

7. **内联包含块中的 OOF 元素:**  测试 OOF 元素的包含块是内联元素时（例如 `<span>`），在多列布局中的布局行为。

8. **验证多列布局中定位元素的父子关系:**  使用 `CheckMulticolumnPositionedObjects` 函数来验证在多列容器中，绝对定位的子元素是否正确地被标记为其父多列容器的 OOF 子元素。

9. **验证分段容器 (fragmentainer) 的中断令牌 (break token):**  测试在多列布局中，当存在 OOF 元素时，分段容器的 break token 是否正确设置，以指示列的结束和新列的开始。这对于正确地进行分页或分列渲染至关重要。

10. **多列布局和 OOF 元素的重排 (relayout):**  测试在动态修改多列容器的属性（例如宽度）后，包含 OOF 元素的嵌套多列布局是否能够正确地进行重排。

11. **统计特定 OOF 布局特性的使用情况 (Use Count):**  测试代码包含检查特定 OOF 布局特性是否被使用的逻辑，例如 `justify-self` 在没有或有 `inset` 属性时的使用情况。这有助于 Chromium 团队了解 Web 开发者如何使用这些特性。

12. **处理多个 OOF 元素:** 测试在同一多列容器中存在多个 OOF 元素时的布局情况，包括这些 OOF 元素是否会发生分段。

**总结来说，该文件全面测试了 out-of-flow 元素在各种多列布局场景下的渲染和布局行为，确保 Blink 渲染引擎能够正确地处理这些复杂的布局情况。** 它关注的是布局的正确性，包括元素的定位、尺寸计算、分段以及相关的元数据（如 break token）。

由于这是第二部分，是对前面部分测试功能的归纳总结，可以认为前面部分的代码提供了针对以上列出的各个功能的具体测试用例，而这部分代码是对这些测试用例结果的验证和分析。

Prompt: 
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 id="multicol">
          <div class="rel">
            <div class="abs"></div>
          </div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x2
    offset:0,0 size:1000x2
      offset:0,0 size:492x2
        offset:0,0 size:30x0
        offset:0,0 size:5x2
      offset:508,0 size:492x2
        offset:0,0 size:5x2
      offset:0,2 size:1000x0
      offset:0,2 size:1000x0
      offset:0,2 size:1000x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that empty column fragments are added if an OOF element begins layout
// in a fragmentainer that is more than one index beyond the last existing
// column fragmentainer in the presence of a spanner.
TEST_F(OutOfFlowLayoutPartTest, AbsposFragWithSpannerAndNewEmptyColumns) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative; width:30px;
        }
        .abs {
          position:absolute; top:80px; width:5px; height:120px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs"></div>
          </div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:30x0
      offset:508,0 size:492x40
      offset:1016,0 size:492x40
        offset:0,0 size:5x40
      offset:1524,0 size:492x40
        offset:0,0 size:5x40
      offset:2032,0 size:492x40
        offset:0,0 size:5x40
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF element with block-size percentage resolution.
TEST_F(OutOfFlowLayoutPartTest, AbsposFragmentationPctResolution) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative; width:30px;
        }
        .abs {
          position:absolute; top:30px; width:5px; height:100%;
        }
        .spanner {
          column-span:all; height:25%;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs"></div>
            <div style="width: 10px; height:30px;"></div>
          </div>
          <div class="spanner"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x30
        offset:0,0 size:30x30
          offset:0,0 size:10x30
      offset:508,0 size:492x30
        offset:0,0 size:5x30
      offset:0,30 size:1000x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF element with block-size percentage resolution and overflow.
TEST_F(OutOfFlowLayoutPartTest, AbsposFragmentationPctResolutionWithOverflow) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          columns:5; column-fill:auto; column-gap:0px; height:100px;
        }
        .rel {
          position: relative; width:55px;
        }
        .abs {
          position:absolute; top:0px; width:5px; height:100%;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="height:30px;"></div>
          <div class="rel">
            <div class="abs"></div>
            <div style="width:44px; height:200px;">
              <div style="width:33px; height:400px;"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:200x100
        offset:0,0 size:200x30
        offset:0,30 size:55x70
          offset:0,0 size:44x70
            offset:0,0 size:33x70
        offset:0,30 size:5x70
      offset:200,0 size:200x100
        offset:0,0 size:55x100
          offset:0,0 size:44x100
            offset:0,0 size:33x100
        offset:0,0 size:5x100
      offset:400,0 size:200x100
        offset:0,0 size:55x30
          offset:0,0 size:44x30
            offset:0,0 size:33x100
        offset:0,0 size:5x30
      offset:600,0 size:200x100
        offset:0,0 size:55x0
          offset:0,0 size:44x0
            offset:0,0 size:33x100
      offset:800,0 size:200x100
        offset:0,0 size:55x0
          offset:0,0 size:44x0
            offset:0,0 size:33x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF element inside a nested multi-column.
TEST_F(OutOfFlowLayoutPartTest, SimpleAbsposNestedFragmentation) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        .multicol {
          columns:2; column-fill:auto; column-gap:0px;
        }
        .rel {
          position: relative; width:55px; height:80px;
        }
        .abs {
          position:absolute; top:0px; width:5px; height:80px;
        }
      </style>
      <div id="container">
        <div class="multicol" id="outer" style="height:100px;">
          <div style="height:40px; width:40px;"></div>
          <div class="multicol" id="inner">
            <div class="rel">
              <div class="abs"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:500x100
        offset:0,0 size:40x40
        offset:0,40 size:500x60
          offset:0,0 size:250x60
            offset:0,0 size:55x60
            offset:0,0 size:5x60
          offset:250,0 size:250x60
            offset:0,0 size:55x20
            offset:0,0 size:5x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF element inside a nested multi-column with new columns.
TEST_F(OutOfFlowLayoutPartTest, AbsposNestedFragmentationNewColumns) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        .multicol {
          columns:2; column-fill:auto; column-gap:0px;
        }
        #inner {
          column-gap:16px; height:40px; padding:10px;
        }
        .rel {
          position: relative; width:55px; height:20px;
        }
        .abs {
          position:absolute; top:0px; width:5px; height:40px;
        }
      </style>
      <div id="container">
        <div class="multicol" id="outer" style="height:100px;">
          <div style="height:40px; width:40px;"></div>
          <div class="multicol" id="inner">
            <div class="rel">
              <div class="abs"></div>
            </div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:500x100
        offset:0,0 size:40x40
        offset:0,40 size:500x60
          offset:10,10 size:232x20
            offset:0,0 size:55x20
            offset:0,0 size:5x20
          offset:10,30 size:480x0
          offset:10,30 size:480x0
          offset:10,30 size:480x0
          offset:258,10 size:232x20
            offset:0,0 size:5x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF element inside a nested multi-column starting at a
// fragmentainer index beyond the last existing fragmentainer.
TEST_F(OutOfFlowLayoutPartTest, AbsposNestedFragmentationNewEmptyColumns) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        .multicol {
          columns:2; column-fill:auto; column-gap:0px;
        }
        .rel {
          position: relative; width:55px; height:80px;
        }
        .abs {
          position:absolute; top:120px; width:5px; height:120px;
        }
      </style>
      <div id="container">
        <div class="multicol" id="outer" style="height:100px;">
          <div style="height:40px; width:40px;"></div>
          <div class="multicol" id="inner" style="column-gap:16px;">
            <div class="rel">
              <div class="abs"></div>
            </div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  // Note that the two last inner fragmentainers (after the spanners) aren't
  // quite right. They just keep on using the same block-offset (and block-size)
  // of the preceding fragmentainers, since we don't let OOFs trigger creation
  // of new outer fragmentainers. This is being discussed in crbug.com/40775119
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:500x100
        offset:0,0 size:40x40
        offset:0,40 size:500x60
          offset:0,0 size:242x60
            offset:0,0 size:55x60
          offset:258,0 size:242x60
            offset:0,0 size:55x20
          offset:0,60 size:500x0
          offset:0,60 size:500x0
          offset:0,60 size:500x0
          offset:516,0 size:242x60
            offset:0,0 size:5x60
          offset:774,0 size:242x60
            offset:0,0 size:5x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Fragmented OOF with `height: auto` and positioned with the bottom property.
TEST_F(OutOfFlowLayoutPartTest,
       PositionedFragmentationWithBottomPropertyAndHeightAuto) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position:relative; height:60px; width:32px;
        }
        .abs {
          position:absolute; bottom:0; width:5px; height:auto;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs">
              <div style="width: 2px; height: 10px"></div>
              <div style="width: 3px; height: 20px"></div>
              <div style="width: 4px; height: 10px"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:32x40
        offset:0,20 size:5x20
          offset:0,0 size:2x10
          offset:0,10 size:3x10
      offset:508,0 size:492x40
        offset:0,0 size:32x20
        offset:0,0 size:5x20
          offset:0,0 size:3x10
          offset:0,10 size:4x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests an OOF element with an inline containing block inside a multicol
// with a column spanner.
TEST_F(OutOfFlowLayoutPartTest, AbsposFragWithInlineCBAndSpanner) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative; width:30px;
        }
        .abs {
          position:absolute; top:80px; width:5px; height:120px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div>
            <span class="rel">
              <div class="abs"></div>
            </span>
          </div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
          <div style="column-span:all;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:492x0
          offset:0,0 size:0x0
      offset:508,0 size:492x40
      offset:1016,0 size:492x40
        offset:0,0 size:5x40
      offset:1524,0 size:492x40
        offset:0,0 size:5x40
      offset:2032,0 size:492x40
        offset:0,0 size:5x40
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

static void CheckMulticolumnPositionedObjects(const LayoutBox* multicol,
                                              const LayoutBox* abspos) {
  for (const PhysicalBoxFragment& fragmentation_root :
       multicol->PhysicalFragments()) {
    EXPECT_TRUE(fragmentation_root.IsFragmentationContextRoot());
    EXPECT_FALSE(fragmentation_root.HasOutOfFlowFragmentChild());
    for (const PhysicalFragmentLink& fragmentainer :
         fragmentation_root.Children()) {
      EXPECT_TRUE(fragmentainer->IsFragmentainerBox());
      EXPECT_TRUE(fragmentainer->HasOutOfFlowFragmentChild());
      for (const PhysicalFragmentLink& child : fragmentainer->Children()) {
        if (child->GetLayoutObject() == abspos)
          return;
      }
    }
  }
  EXPECT_TRUE(false);
}

TEST_F(OutOfFlowLayoutPartTest, PositionedObjectsInMulticol) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        .multicol {
          column-count: 2; column-fill: auto; column-gap: 0px;
        }
      </style>
      <div class="multicol" id="outer">
        <div class="multicol" id="inner" style="position:relative;">
          <div id="abs1" style="position:absolute;"></div>
          <div id="rel" style="position:relative;">
            <div id="abs2" style="position:absolute;"></div>
          </div>
        </div>
      </div>
      )HTML");
  CheckMulticolumnPositionedObjects(GetLayoutBoxByElementId("outer"),
                                    GetLayoutBoxByElementId("abs1"));
  CheckMulticolumnPositionedObjects(GetLayoutBoxByElementId("inner"),
                                    GetLayoutBoxByElementId("abs2"));
}

TEST_F(OutOfFlowLayoutPartTest, PositionedObjectsInMulticolWithInline) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count: 2; column-fill: auto; column-gap: 0px;
        }
      </style>
      <div id="multicol">
        <div id="target">
          <span style="position: relative;">
            <div id="abs1" style="position:absolute;"></div>
            <div id="abs2" style="position:absolute;"></div>
          </span>
        </div>
      </div>
      )HTML");
  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  CheckMulticolumnPositionedObjects(multicol, GetLayoutBoxByElementId("abs1"));
  CheckMulticolumnPositionedObjects(multicol, GetLayoutBoxByElementId("abs2"));
}

// Make sure the fragmentainer break tokens are correct when OOFs are added to
// existing fragmentainers.
TEST_F(OutOfFlowLayoutPartTest, FragmentainerBreakTokens) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:0px;
          height:150px; width:100px;
        }
        .abs {
          position:absolute; width:50px; height:200px; top:0;
        }
      </style>
      <div id="multicol">
        <div style="position:relative;">
          <div style="height:200px;"></div>
          <div class="abs"></div>
          <div style="column-span:all;"></div>
          <div style="height:100px;"></div>
        </div>
      </div>
      )HTML");
  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  ASSERT_EQ(multicol->PhysicalFragmentCount(), 1u);
  const PhysicalBoxFragment* multicol_fragment =
      multicol->GetPhysicalFragment(0);
  const auto& children = multicol_fragment->Children();
  ASSERT_EQ(children.size(), 5u);

  const auto& column1 = To<PhysicalBoxFragment>(*children[0]);
  const BlockBreakToken* break_token = column1.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 0u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 100);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_FALSE(break_token->IsCausedByColumnSpanner());

  const auto& column2 = To<PhysicalBoxFragment>(*children[1]);
  break_token = column2.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 1u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 200);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_TRUE(break_token->IsCausedByColumnSpanner());

  const auto& spanner = To<PhysicalBoxFragment>(*children[2]);
  EXPECT_TRUE(spanner.IsColumnSpanAll());

  const auto& column3 = To<PhysicalBoxFragment>(*children[3]);
  break_token = column3.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 2u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 250);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_FALSE(break_token->IsCausedByColumnSpanner());

  const auto& column4 = To<PhysicalBoxFragment>(*children[4]);
  EXPECT_FALSE(column4.GetBreakToken());
}

// Make sure the fragmentainer break tokens are correct when a new column is
// created before a spanner for an OOF.
TEST_F(OutOfFlowLayoutPartTest, FragmentainerBreakTokenBeforeSpanner) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-gap:0px; width:100px;
        }
        .abs {
          position:absolute; width:50px; height:200px; top:0;
        }
      </style>
      <div id="multicol">
        <div style="position:relative;">
          <div style="height:100px;"></div>
          <div class="abs"></div>
        </div>
        <div style="column-span:all;"></div>
        <div style="height:100px;"></div>
      </div>
      )HTML");
  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  ASSERT_EQ(multicol->PhysicalFragmentCount(), 1u);
  const PhysicalBoxFragment* multicol_fragment =
      multicol->GetPhysicalFragment(0);
  const auto& children = multicol_fragment->Children();
  ASSERT_EQ(children.size(), 5u);

  const auto& column1 = To<PhysicalBoxFragment>(*children[0]);
  const BlockBreakToken* break_token = column1.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 0u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 100);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_TRUE(break_token->IsCausedByColumnSpanner());

  const auto& column2 = To<PhysicalBoxFragment>(*children[1]);
  break_token = column2.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 1u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 200);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_TRUE(break_token->IsCausedByColumnSpanner());

  const auto& spanner = To<PhysicalBoxFragment>(*children[2]);
  EXPECT_TRUE(spanner.IsColumnSpanAll());

  const auto& column3 = To<PhysicalBoxFragment>(*children[3]);
  break_token = column3.GetBreakToken();
  EXPECT_TRUE(break_token);
  EXPECT_EQ(break_token->SequenceNumber(), 2u);
  EXPECT_EQ(break_token->ConsumedBlockSize(), 250);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);
  EXPECT_FALSE(break_token->IsCausedByColumnSpanner());

  const auto& column4 = To<PhysicalBoxFragment>(*children[4]);
  EXPECT_FALSE(column4.GetBreakToken());
}

// crbug.com/1296900
TEST_F(OutOfFlowLayoutPartTest, RelayoutNestedMulticolWithOOF) {
  SetBodyInnerHTML(
      R"HTML(
      <div id="outer" style="columns:1; column-fill:auto; width:333px; height:100px;">
        <div style="width:50px;">
          <div id="inner" style="columns:1; column-fill:auto; height:50px;">
            <div style="position:relative; height:10px;">
              <div id="oof" style="position:absolute; width:1px; height:1px;"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");

  Element* outer = GetElementById("outer");
  const LayoutBox* inner = GetLayoutBoxByElementId("inner");

  auto GetInnerFragmentainer = [&inner]() -> const PhysicalBoxFragment* {
    if (inner->PhysicalFragmentCount() != 1u)
      return nullptr;
    if (inner->GetPhysicalFragment(0)->Children().size() != 1u)
      return nullptr;
    return To<PhysicalBoxFragment>(
        inner->GetPhysicalFragment(0)->Children()[0].fragment.Get());
  };

  const PhysicalBoxFragment* fragmentainer = GetInnerFragmentainer();
  ASSERT_TRUE(fragmentainer);
  // It should have two children: the relpos and the OOF.
  EXPECT_EQ(fragmentainer->Children().size(), 2u);

  outer->SetInlineStyleProperty(CSSPropertyID::kWidth, "334px");
  UpdateAllLifecyclePhasesForTest();

  fragmentainer = GetInnerFragmentainer();
  ASSERT_TRUE(fragmentainer);
  // It should still have two children: the relpos and the OOF.
  EXPECT_EQ(fragmentainer->Children().size(), 2u);

  outer->SetInlineStyleProperty(CSSPropertyID::kWidth, "335px");
  UpdateAllLifecyclePhasesForTest();

  fragmentainer = GetInnerFragmentainer();
  ASSERT_TRUE(fragmentainer);
  // It should still have two children: the relpos and the OOF.
  EXPECT_EQ(fragmentainer->Children().size(), 2u);
}

TEST_F(OutOfFlowLayoutPartTest, UseCountOutOfFlowNoInsets) {
  SetBodyInnerHTML(R"HTML(
    <div style="position: absolute; justify-self: center;"></div>
  )HTML");
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowJustifySelfNoInsets));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowAlignSelfNoInsets));
}

TEST_F(OutOfFlowLayoutPartTest, UseCountOutOfFlowSingleInset) {
  SetBodyInnerHTML(R"HTML(
    <div style="position: absolute; right: 0; bottom: 0; justify-self: center;"></div>
  )HTML");
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowJustifySelfSingleInset));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowAlignSelfSingleInset));
}

TEST_F(OutOfFlowLayoutPartTest, UseCountOutOfFlowBothInsets) {
  SetBodyInnerHTML(R"HTML(
    <div style="position: absolute; inset: 0; justify-self: center;"></div>
  )HTML");
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowJustifySelfBothInsets));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kOutOfFlowAlignSelfBothInsets));
}

TEST_F(OutOfFlowLayoutPartTest, EmptyFragmentainersBeforeOOF) {
  // There's an OOF in the fourth, fifth and sixth columns.
  SetBodyInnerHTML(
      R"HTML(
      <div id="multicol" style="columns:6; column-fill:auto; height:100px;">
        <div style="position:relative;">
          <div style="position:absolute; width:50px; top:300px; height:300px;"></div>
        </div>
      </div>
      )HTML");

  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  ASSERT_TRUE(multicol);
  const auto columns = multicol->GetPhysicalFragment(0)->Children();
  ASSERT_EQ(columns.size(), 6u);

  const auto* fragmentainer = To<PhysicalBoxFragment>(columns[0].get());
  const BlockBreakToken* break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->ChildBreakTokens().empty());

  fragmentainer = To<PhysicalBoxFragment>(columns[1].get());
  break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->ChildBreakTokens().empty());

  fragmentainer = To<PhysicalBoxFragment>(columns[2].get());
  break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->ChildBreakTokens().empty());

  fragmentainer = To<PhysicalBoxFragment>(columns[3].get());
  break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);

  fragmentainer = To<PhysicalBoxFragment>(columns[4].get());
  break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_EQ(break_token->ChildBreakTokens().size(), 1u);

  fragmentainer = To<PhysicalBoxFragment>(columns[5].get());
  break_token = fragmentainer->GetBreakToken();
  EXPECT_FALSE(break_token);
}

TEST_F(OutOfFlowLayoutPartTest, MultipleUnfragmentedOOFs) {
  // There's an OOF in every column, but none of them fragments. All columns but
  // the last should have break tokens nevertheless.
  SetBodyInnerHTML(
      R"HTML(
      <div id="multicol" style="columns:3; column-fill:auto; height:100px;">
        <div style="position:relative;">
          <div style="position:absolute; top:0; width:50px; height:10px;"></div>
          <div style="position:absolute; top:100px; width:50px; height:10px;"></div>
          <div style="position:absolute; top:200px; width:50px; height:10px;"></div>
        </div>
      </div>
      )HTML");

  const LayoutBox* multicol = GetLayoutBoxByElementId("multicol");
  ASSERT_TRUE(multicol);
  const auto columns = multicol->GetPhysicalFragment(0)->Children();
  ASSERT_EQ(columns.size(), 3u);

  const auto* fragmentainer = To<PhysicalBoxFragment>(columns[0].get());
  const BlockBreakToken* break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->ChildBreakTokens().empty());

  fragmentainer = To<PhysicalBoxFragment>(columns[1].get());
  break_token = fragmentainer->GetBreakToken();
  ASSERT_TRUE(break_token);
  EXPECT_TRUE(break_token->ChildBreakTokens().empty());

  fragmentainer = To<PhysicalBoxFragment>(columns[2].get());
  break_token = fragmentainer->GetBreakToken();
  EXPECT_FALSE(break_token);
}

}  // namespace
}  // namespace blink

"""


```