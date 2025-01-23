Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine.
Specifically, the file is `blink/renderer/core/layout/out_of_flow_layout_part_test.cc`.

I need to:
1. **Summarize the file's functionality.**  Based on the name and contents, it seems to be a test file for the `OutOfFlowLayoutPart` class. This likely means it tests how elements with `position: absolute` or `position: fixed` are laid out.
2. **Identify connections to HTML, CSS, and JavaScript.**  Layout is directly related to HTML structure and CSS styling. JavaScript could be involved if it dynamically modifies styles or the DOM.
3. **Provide examples of these connections.**  For HTML and CSS, I can point to the use of specific properties like `position`, `top`, `left`, `column-count`, etc. For JavaScript, I can imagine scenarios where JS changes these properties.
4. **Illustrate logical reasoning with input and output examples.** The test cases themselves provide examples of this. I can pick a simple test case and explain the expected output based on the input HTML and CSS.
5. **Highlight common user/programming errors.** These might involve incorrect CSS syntax for positioning, misunderstandings about how `absolute` and `fixed` positioning work, or issues with stacking contexts.
6. **Summarize the file's function as the first part of a two-part analysis.**
这是 `blink/renderer/core/layout/out_of_flow_layout_part_test.cc` 文件的功能归纳：

**功能：**

该文件包含了针对 Blink 渲染引擎中 `OutOfFlowLayoutPart` 类的单元测试。`OutOfFlowLayoutPart` 负责处理文档流之外的元素的布局，主要涉及 `position: absolute` 和 `position: fixed` 的元素。

**与 HTML, CSS 的关系及举例说明：**

这个测试文件主要通过构建 HTML 结构和应用 CSS 样式来验证 `OutOfFlowLayoutPart` 的布局逻辑是否正确。

* **HTML:** 文件中的每个 `TEST_F` 函数都通过 `SetBodyInnerHTML` 方法设置了一段 HTML 代码，用于创建需要进行布局测试的 DOM 结构。例如：
    ```html
    <div id='rel'>
      <div id='abs'>
        <div id='pad'></div>
        <div id='fixed1'>
          <p>fixed static</p>
        </div>
        <div id='fixed2'>
          <p>fixed plain</p>
        </div>
      </div>
    </div>
    ```
    这段 HTML 创建了一个相对定位的容器 (`#rel`)，内部包含一个绝对定位的元素 (`#abs`)，以及两个固定定位的元素 (`#fixed1`, `#fixed2`)。

* **CSS:**  每个测试用例通常也会包含一段 CSS 代码，定义了元素的定位方式、尺寸、边距等样式属性。例如：
    ```css
    <style>
      body{ padding:0px; margin:0px}
      #rel { position:relative }
      #abs {
        position: absolute;
        top:49px;
        left:0px;
      }
      #pad {
        width:100px;
        height:50px;
      }
      #fixed1 {
        position:fixed;
        width:50px;
      }
      #fixed2 {
        position:fixed;
        top:9px;
        left:7px;
      }
    </style>
    ```
    这段 CSS 代码设置了各个元素的 `position` 属性（`relative`, `absolute`, `fixed`），以及 `top`, `left`, `width`, `height` 等布局相关的属性。测试会验证在这些样式下，`OutOfFlowLayoutPart` 是否能正确计算出元素的最终位置和尺寸。

* **CSS 多列布局 (Multi-column Layout):** 很多测试用例涉及到 CSS 的多列布局 (`column-count`, `column-fill`, `column-gap`)，并测试在多列布局下，绝对定位元素的布局和分片是否正确。

**与 JavaScript 的关系：**

虽然这个测试文件本身不包含 JavaScript 代码，但它测试的功能直接影响到 JavaScript 操作布局的能力。例如，JavaScript 可以动态地修改元素的 CSS 属性（包括 `position`, `top`, `left` 等），或者动态地创建和删除带有绝对或固定定位的元素。`OutOfFlowLayoutPart` 的正确性保证了 JavaScript 对布局的修改能得到预期的结果。

**逻辑推理的假设输入与输出举例：**

以 `FixedInsideAbs` 这个测试用例为例：

* **假设输入 (HTML & CSS):**
    ```html
    <style>
      #abs { position: absolute; top:49px; left:0px; }
      #pad { width:100px; height:50px; }
      #fixed1 { position:fixed; width:50px; }
      #fixed2 { position:fixed; top:9px; left:7px; }
    </style>
    <div id='rel'>
      <div id='abs'>
        <div id='pad'></div>
        <div id='fixed1'><p>fixed static</p></div>
        <div id='fixed2'><p>fixed plain</p></div>
      </div>
    </div>
    ```

* **逻辑推理:**
    * `#fixed1` 的定位是 `fixed`，它的包含块是视口。由于没有显式设置 `top` 值，它的垂直位置会根据其在正常流中的位置计算，但会相对于视口固定。 在这个例子中，它会根据其父元素 `#abs` 的 `top` 值 (49px) 加上 `#pad` 的 `height` 值 (50px) 来确定其初始的静态位置，即 49 + 50 = 99px。
    * `#fixed2` 的定位也是 `fixed`，但显式设置了 `top: 9px` 和 `left: 7px`，因此它的位置会直接相对于视口顶部 9px，左侧 7px。

* **预期输出:**
    * `fixed_1->OffsetTop()` 应该等于 `LayoutUnit(99)`。
    * `fixed_2->OffsetTop()` 应该等于 `LayoutUnit(9)`。

**涉及用户或编程常见的使用错误举例：**

* **误解绝对定位的包含块:**  一个常见的错误是认为绝对定位的元素总是相对于 `<body>` 或视口定位。实际上，绝对定位元素会相对于其最近的已定位的祖先元素（`position: relative`, `absolute`, `fixed`, `sticky`）进行定位。如果找不到已定位的祖先元素，才会相对于初始包含块（通常是 `<html>` 元素）。

    ```html
    <div style="position: relative;">
      <div style="position: absolute; top: 10px;">This is absolutely positioned.</div>
    </div>
    <div style="position: static;">
      <div style="position: absolute; top: 10px;">This might be unexpectedly positioned.</div>
    </div>
    ```
    在第一个 `div` 中，绝对定位的元素会相对于其相对定位的父元素定位。在第二个 `div` 中，由于父元素是静态定位，绝对定位的元素会向上查找，直到找到已定位的祖先元素，或者最终相对于初始包含块定位。

* **忘记设置定位属性:**  如果一个元素的 `position` 属性被设置为 `absolute` 或 `fixed`，但没有设置 `top`, `bottom`, `left`, `right` 中的任何属性，它的位置可能会与预期不符，因为它会停留在其在正常文档流中的位置。

    ```html
    <div style="position: absolute;">This element needs top/left/bottom/right to be properly positioned.</div>
    ```

* **在多列布局中对绝对定位元素的理解偏差:**  在多列布局中，绝对定位的元素会相对于多列容器进行定位，并可能跨越不同的列。开发者可能没有考虑到这一点，导致布局错乱。

**文件功能归纳（第 1 部分总结）：**

`blink/renderer/core/layout/out_of_flow_layout_part_test.cc` 文件的主要功能是测试 Blink 引擎中 `OutOfFlowLayoutPart` 类处理绝对定位和固定定位元素布局的正确性。它通过创建包含不同 HTML 结构和 CSS 样式的测试用例，并断言布局结果（例如，元素的偏移量和尺寸）是否符合预期，从而确保了这部分布局逻辑的稳定性和准确性。 这个文件大量使用了 CSS 的多列布局特性来测试在复杂布局场景下绝对定位元素的行为。

### 提示词
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/out_of_flow_layout_part.h"

#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {
namespace {

class OutOfFlowLayoutPartTest : public BaseLayoutAlgorithmTest {
 protected:
  const PhysicalBoxFragment* RunBlockLayoutAlgorithm(Element* element) {
    BlockNode container(element->GetLayoutBox());
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(1000), kIndefiniteSize));
    return BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  }

  String DumpFragmentTree(Element* element) {
    auto* fragment = RunBlockLayoutAlgorithm(element);
    return DumpFragmentTree(fragment);
  }

  String DumpFragmentTree(const blink::PhysicalBoxFragment* fragment) {
    PhysicalFragment::DumpFlags flags =
        PhysicalFragment::DumpHeaderText | PhysicalFragment::DumpSubtree |
        PhysicalFragment::DumpIndentation | PhysicalFragment::DumpOffset |
        PhysicalFragment::DumpSize;

    return fragment->DumpFragmentTree(flags);
  }
};

// Fixed blocks inside absolute blocks trigger otherwise unused while loop
// inside OutOfFlowLayoutPart::Run.
// This test exercises this loop by placing two fixed elements inside abs.
TEST_F(OutOfFlowLayoutPartTest, FixedInsideAbs) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        body{ padding:0px; margin:0px}
        #rel { position:relative }
        #abs {
          position: absolute;
          top:49px;
          left:0px;
        }
        #pad {
          width:100px;
          height:50px;
        }
        #fixed1 {
          position:fixed;
          width:50px;
        }
        #fixed2 {
          position:fixed;
          top:9px;
          left:7px;
        }
      </style>
      <div id='rel'>
        <div id='abs'>
          <div id='pad'></div>
          <div id='fixed1'>
            <p>fixed static</p>
          </div>
          <div id='fixed2'>
            <p>fixed plain</p>
          </div>
        </div>
      </div>
      )HTML");

  // Test whether the oof fragments have been collected at NG->Legacy boundary.
  Element* rel = GetElementById("rel");
  auto* block_flow = To<LayoutBlockFlow>(rel->GetLayoutObject());
  const LayoutResult* result = block_flow->GetSingleCachedLayoutResult();
  EXPECT_TRUE(result);
  EXPECT_EQ(
      result->GetPhysicalFragment().OutOfFlowPositionedDescendants().size(),
      2u);

  // Test the final result.
  Element* fixed_1 = GetElementById("fixed1");
  Element* fixed_2 = GetElementById("fixed2");
  // fixed1 top is static: #abs.top + #pad.height
  EXPECT_EQ(fixed_1->OffsetTop(), LayoutUnit(99));
  // fixed2 top is positioned: #fixed2.top
  EXPECT_EQ(fixed_2->OffsetTop(), LayoutUnit(9));
}

// Tests non-fragmented positioned nodes inside a multi-column.
TEST_F(OutOfFlowLayoutPartTest, PositionedInMulticol) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count: 2; height: 40px; column-fill: auto; column-gap: 16px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position: absolute;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="width:100px; height:50px;"></div>
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:5px; top:10px; height:5px;">
            </div>
            <div class="rel" style="width:35px; padding-top:8px;">
              <div class="abs" style="width:10px; top:20px; height:10px;">
              </div>
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
        offset:0,0 size:100x40
      offset:508,0 size:492x40
        offset:0,0 size:100x10
        offset:0,10 size:30x8
          offset:0,0 size:35x8
        offset:0,30 size:10x10
        offset:0,20 size:5x5
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that positioned nodes fragment correctly.
TEST_F(OutOfFlowLayoutPartTest, SimplePositionedFragmentation) {
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
          position:absolute; top:0px; width:5px; height:50px;
          border:solid 2px; margin-top:5px; padding:5px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="width:100px; height:50px;"></div>
          <div class="rel">
            <div class="abs"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:100x40
      offset:508,0 size:492x40
        offset:0,0 size:100x10
        offset:0,10 size:30x0
        offset:0,15 size:19x25
      offset:1016,0 size:492x40
        offset:0,0 size:19x39
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests fragmentation when a positioned node's child overflows.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithOverflow) {
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
          position:absolute; top:10px; width:5px; height:10px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs">
              <div style="width:100px; height:50px;"></div>
            </div>
          </div>
          <div style="width:20px; height:100px;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:30x0
        offset:0,0 size:20x40
        offset:0,10 size:5x10
          offset:0,0 size:100x30
      offset:508,0 size:492x40
        offset:0,0 size:20x40
        offset:0,0 size:5x0
          offset:0,0 size:100x20
      offset:1016,0 size:492x40
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that new column fragments are added correctly if a positioned node
// fragments beyond the last fragmentainer in a context.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithNewColumns) {
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
          position:absolute; width:5px; height:120px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:30x0
        offset:0,0 size:5x40
      offset:508,0 size:492x40
        offset:0,0 size:5x40
      offset:1016,0 size:492x40
        offset:0,0 size:5x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that empty column fragments are added if an OOF element begins layout
// in a fragmentainer that is more than one index beyond the last existing
// column fragmentainer.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithNewEmptyColumns) {
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
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-inside does not apply to absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, BreakInsideAvoid) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position:relative;
        }
        .abs {
          position:absolute; break-inside:avoid;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="width:20px; height:10px;"></div>
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:40px; height:40px;"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:20x10
        offset:0,10 size:30x0
        offset:0,10 size:40x30
      offset:508,0 size:492x40
        offset:0,0 size:40x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-before does not apply to absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, BreakBeforeColumn) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute; break-before:column;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="width:10px; height:30px;"></div>
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:40px; height:30px;"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:10x30
        offset:0,30 size:30x0
        offset:0,30 size:40x10
      offset:508,0 size:492x40
        offset:0,0 size:40x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-after does not apply to absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, BreakAfterColumn) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute; break-after:column;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="width:10px; height:20px;"></div>
          <div class="rel" style="width:30px; height:10px;">
            <div class="abs" style="width:40px; height:10px;"></div>
          </div>
          <div style="width:20px; height:10px;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:10x20
        offset:0,20 size:30x10
        offset:0,30 size:20x10
        offset:0,20 size:40x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-inside should still apply to children of absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, ChildBreakInsideAvoid) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:100px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:40px; height:150px;">
              <div style="width:15px; height:50px;"></div>
              <div style="break-inside:avoid; width:20px; height:100px;"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:492x100
        offset:0,0 size:30x0
        offset:0,0 size:40x100
          offset:0,0 size:15x50
      offset:508,0 size:492x100
        offset:0,0 size:40x50
          offset:0,0 size:20x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-before should still apply to children of absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, ChildBreakBeforeAvoid) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:100px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:40px; height:150px;">
              <div style="width:15px; height:50px;"></div>
              <div style="width:20px; height:50px;"></div>
              <div style="break-before:avoid; width:10px; height:20px;"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:492x100
        offset:0,0 size:30x0
        offset:0,0 size:40x100
          offset:0,0 size:15x50
      offset:508,0 size:492x100
        offset:0,0 size:40x50
          offset:0,0 size:20x50
          offset:0,50 size:10x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Break-after should still apply to children of absolute positioned elements.
TEST_F(OutOfFlowLayoutPartTest, ChildBreakAfterAvoid) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:100px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel" style="width:30px;">
            <div class="abs" style="width:40px; height:150px;">
              <div style="width:15px; height:50px;"></div>
              <div style="break-after:avoid; width:20px; height:50px;"></div>
              <div style="width:10px; height:20px;"></div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:1000x100
      offset:0,0 size:492x100
        offset:0,0 size:30x0
        offset:0,0 size:40x100
          offset:0,0 size:15x50
      offset:508,0 size:492x100
        offset:0,0 size:40x50
          offset:0,0 size:20x50
          offset:0,50 size:10x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a positioned element with a negative top property moves the OOF
// node to the previous fragmentainer and spans 3 columns.
TEST_F(OutOfFlowLayoutPartTest,
       PositionedFragmentationWithNegativeTopPropertyAndNewEmptyColumn) {
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
          position:absolute; top:-40px; width:5px; height:80px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="height: 60px; width: 32px;"></div>
          <div class="rel">
            <div class="abs"></div>
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
      offset:508,0 size:492x40
        offset:0,0 size:32x20
        offset:0,20 size:30x0
        offset:0,0 size:5x40
      offset:1016,0 size:492x40
        offset:0,0 size:5x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithBottomProperty) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute; bottom:10px; width:5px; height:40px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel" style="height: 60px; width: 32px;">
            <div class="abs"></div>
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
        offset:0,10 size:5x30
      offset:508,0 size:492x40
        offset:0,0 size:32x20
        offset:0,0 size:5x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a positioned element without a top or bottom property stays in
// flow - even though it's treated as an OOF element.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationInFlowWithAddedColumns) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position:relative; width:30px;
        }
        .abs {
          position:absolute; width:5px; height:80px;
        }
       </style>
       <div id="container">
         <div id="multicol">
           <div class="rel">
             <div style="height: 60px; width: 32px;"></div>
             <div class="abs"></div>
           </div>
         </div>
       </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x40
        offset:0,0 size:30x40
          offset:0,0 size:32x40
      offset:508,0 size:492x40
        offset:0,0 size:30x20
          offset:0,0 size:32x20
        offset:0,20 size:5x20
      offset:1016,0 size:492x40
        offset:0,0 size:5x40
      offset:1524,0 size:492x40
        offset:0,0 size:5x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that the fragments of a positioned element are added to the right
// fragmentainer despite the presence of column spanners.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationAndColumnSpanners) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position:relative; width:30px;
        }
        .abs {
          position:absolute; width:5px; height:20px;
        }
       </style>
       <div id="container">
         <div id="multicol">
           <div class="rel">
             <div style="column-span:all;"></div>
             <div style="height: 60px; width: 32px;"></div>
             <div style="column-span:all;"></div>
             <div class="abs"></div>
           </div>
         </div>
       </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x0
        offset:0,0 size:30x0
      offset:0,0 size:1000x0
      offset:0,0 size:492x30
        offset:0,0 size:30x30
          offset:0,0 size:32x30
      offset:508,0 size:492x30
        offset:0,0 size:30x30
          offset:0,0 size:32x30
      offset:0,30 size:1000x0
      offset:0,30 size:492x10
        offset:0,0 size:30x0
        offset:0,0 size:5x10
      offset:508,30 size:492x10
        offset:0,0 size:5x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that column spanners are skipped over when laying out fragmented abspos
// elements.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithNestedSpanner) {
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
          position:absolute; width:5px; height:50px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div style="column-span:all;"></div>
            <div class="abs"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x0
        offset:0,0 size:30x0
      offset:0,0 size:1000x0
      offset:0,0 size:492x40
        offset:0,0 size:30x0
        offset:0,0 size:5x40
      offset:508,0 size:492x40
        offset:0,0 size:5x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that column spanners are skipped over when laying out fragmented abspos
// elements.
TEST_F(OutOfFlowLayoutPartTest, PositionedFragmentationWithNestedSpanners) {
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
          position:absolute; width:5px; height:50px;
        }
        .content { height:20px; }
      </style>
      <div id="container">
        <div id="multicol">
          <div style="column-span:all;"></div>
          <div class="rel">
            <div class="content"></div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
            <div style="column-span:all;"></div>
            <div class="abs"></div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x0
      offset:0,0 size:1000x0
      offset:0,0 size:492x10
        offset:0,0 size:30x10
          offset:0,0 size:30x10
      offset:508,0 size:492x10
        offset:0,0 size:30x10
          offset:0,0 size:30x10
      offset:0,10 size:1000x0
      offset:0,10 size:1000x0
      offset:0,10 size:1000x0
      offset:0,10 size:492x30
        offset:0,0 size:30x0
        offset:0,0 size:5x30
      offset:508,10 size:492x30
        offset:0,0 size:5x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that abspos elements bubble up to their containing block when nested
// inside of a spanner.
TEST_F(OutOfFlowLayoutPartTest, AbsposInSpanner) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute; width:5px; height:50px; top:5px;
        }
      </style>
      <div id="container">
        <div class="rel" style="width:50px;">
          <div id="multicol">
            <div class="rel" style="width:30px;">
              <div style="width:10px; height:30px;"></div>
              <div>
                <div style="column-span:all;">
                  <div class="abs"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:50x40
      offset:0,0 size:50x40
        offset:0,0 size:17x15
          offset:0,0 size:30x15
            offset:0,0 size:10x15
        offset:33,0 size:17x15
          offset:0,0 size:30x15
            offset:0,0 size:10x15
            offset:0,15 size:30x0
        offset:0,15 size:50x0
        offset:0,15 size:17x25
          offset:0,0 size:30x0
            offset:0,0 size:30x0
      offset:0,5 size:5x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that abspos elements bubble up to their containing block when nested
// inside of a spanner and get the correct static position.
TEST_F(OutOfFlowLayoutPartTest, AbsposInSpannerStaticPos) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px; height:40px;
        }
        .rel {
          position: relative;
        }
        .abs {
          position:absolute; width:5px; height:50px;
        }
      </style>
      <div id="container">
        <div class="rel" style="width:50px;">
          <div id="multicol">
            <div class="rel" style="width:30px;">
              <div style="width:10px; height:30px;"></div>
              <div style="column-span:all; margin-top:5px;">
                <div style="width:20px; height:5px;"></div>
                <div class="abs"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:50x40
      offset:0,0 size:50x40
        offset:0,0 size:17x15
          offset:0,0 size:30x15
            offset:0,0 size:10x15
        offset:33,0 size:17x15
          offset:0,0 size:30x15
            offset:0,0 size:10x15
        offset:0,20 size:50x5
          offset:0,0 size:20x5
        offset:0,25 size:17x15
          offset:0,0 size:30x0
      offset:0,25 size:5x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests fragmented abspos elements with a spanner nested inside.
TEST_F(OutOfFlowLayoutPartTest, SpannerInAbspos) {
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
          position:absolute; width:5px; height:50px;
        }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="abs">
              <div style="column-span:all;"></div>
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
        offset:0,0 size:30x0
        offset:0,0 size:5x40
          offset:0,0 size:5x0
      offset:508,0 size:492x40
        offset:0,0 size:5x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that new column fragments are added correctly if a positioned node
// fragments beyond the last fragmentainer in a context in the presence of a
// spanner.
TEST_F(OutOfFlowLayoutPartTest,
       PositionedFragmentationWithNewColumnsAndSpanners) {
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
          position:absolute; width:5px; height:120px; top:0px;
        }
        .content { height:20px; }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="content"></div>
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
        offset:0,0 size:30x20
          offset:0,0 size:30x20
        offset:0,0 size:5x40
      offset:508,0 size:492x40
        offset:0,0 size:5x40
      offset:1016,0 size:492x40
        offset:0,0 size:5x40
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
      offset:0,40 size:1000x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that new column fragments are added correctly if a positioned node
// fragments beyond the last fragmentainer in a context directly after a
// spanner.
TEST_F(OutOfFlowLayoutPartTest,
       PositionedFragmentationWithNewColumnsAfterSpanner) {
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
          position:absolute; width:5px; height:50px; top:25px;
        }
        .content { height:20px; }
      </style>
      <div id="container">
        <div id="multicol">
          <div class="rel">
            <div class="content"></div>
            <div class="abs"></div>
          </div>
          <div style="column-span:all;"></div>
        </div>
      </div>
      )HTML");
  String dump = DumpFragmentTree(GetElementById("container"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:1000x40
      offset:0,0 size:492x37.5
        offset:0,0 size:30x20
          offset:0,0 size:30x20
        offset:0,25 size:5x12.5
      offset:508,0 size:492x37.5
        offset:0,0 size:5x37.5
      offset:0,37.5 size:1000x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that new column fragments are added correctly if a positioned node
// fragments beyond the last fragmentainer in a context in the presence of a
// spanner.
TEST_F(OutOfFlowLayoutPartTest, AbsposFragWithSpannerAndNewColumnsAutoHeight) {
  SetBodyInnerHTML(
      R"HTML(
      <style>
        #multicol {
          column-count:2; column-fill:auto; column-gap:16px;
        }
        .rel {
          position: relative; width:30px;
        }
        .abs {
          position:absolute; width:5px; height:4px;
        }
      </style>
      <div id="container">
        <div
```