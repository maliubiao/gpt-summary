Response:
The user is asking for a summary of the provided C++ code file, which is a test file for the `FieldsetLayoutAlgorithm` in the Chromium Blink rendering engine. I need to identify the purpose of this test file and its connection to web technologies.

**Plan:**

1. **Identify the core functionality:**  The file name and the included headers clearly indicate this tests the layout of `<fieldset>` elements.
2. **Explain the relationship to web technologies:** `<fieldset>` is an HTML element used to group related form controls. Its visual presentation is affected by CSS. Javascript can interact with `<fieldset>` elements.
3. **Analyze the test cases:**  The `TEST_F` macros define individual test cases. I will go through some key examples and explain what they are testing (e.g., how legend elements affect the layout, handling of different sizing properties, fragmentation behavior).
4. **Identify assumptions and outputs:**  The tests rely on setting up HTML structures and then comparing the generated layout tree (fragment tree) against expected outputs.
5. **Consider common errors:**  Developers might make mistakes in CSS that affect the layout of fieldsets, and these tests likely help catch such errors.
6. **Summarize the overall function:** The file tests the correct implementation of the fieldset layout algorithm in the Blink engine.
```
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/forms/fieldset_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {
namespace {

class FieldsetLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  const PhysicalBoxFragment* RunBlockLayoutAlgorithm(Element* element) {
    BlockNode container(element->GetLayoutBox());
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(1000), kIndefiniteSize));
    return BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  }

  MinMaxSizes RunComputeMinMaxSizes(BlockNode node) {
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(), LayoutUnit()),
        /* stretch_inline_size_if_auto */ true,
        node.CreatesNewFormattingContext());
    FragmentGeometry fragment_geometry = CalculateInitialFragmentGeometry(
        space, node, /* break_token */ nullptr, /* is_intrinsic */ true);

    FieldsetLayoutAlgorithm algorithm({node, fragment_geometry, space});
    return algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  }

  MinMaxSizes RunComputeMinMaxSizes(const char* element_id) {
    BlockNode node(GetLayoutBoxByElementId(element_id));
    return RunComputeMinMaxSizes(node);
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

TEST_F(FieldsetLayoutAlgorithmTest, Empty) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset></fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x26
    offset:0,0 size:126x26
      offset:3,3 size:120x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, NoLegend) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:3,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, Legend) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:50px; height:200px;"></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x323
    offset:0,0 size:126x323
      offset:13,0 size:50x200
      offset:3,200 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, SmallLegendLargeBorder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:40px solid; padding:10px; width:100px; }
      legend { padding:0; width:10px; height:10px;
               margin-top:5px; margin-bottom:15px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:200x200
      offset:50,15 size:10x10
      offset:40,40 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendOrthogonalWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
      legend { writing-mode:vertical-rl; padding:0; margin:10px 15px 20px 30px;
               width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x193
    offset:0,0 size:126x193
      offset:43,0 size:10x50
      offset:3,70 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, VerticalLr) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { writing-mode:vertical-lr; margin:0; border:3px solid;
                 padding:10px; height:100px; }
      legend { padding:0; margin:10px 15px 20px 30px; width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="width:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:148x126
      offset:0,23 size:10x50
      offset:25,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, VerticalRl) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { writing-mode:vertical-rl; margin:0; border:3px solid;
                 padding:10px; height:100px; }
      legend { padding:0; margin:10px 15px 20px 30px; width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="width:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:163x126
      offset:153,23 size:10x50
      offset:3,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendAutoSize) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0;">
          <div style="float:left; width:25px; height:200px;"></div>
          <div style="float:left; width:25px; height:200px;"></div>
        </legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x323
    offset:0,0 size:126x323
      offset:13,0 size:50x200
        offset:0,0 size:25x200
        offset:25,0 size:25x200
      offset:3,200 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, PercentageHeightChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; height:100px;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:100%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:13,0 size:30x30
      offset:3,30 size:120x93
        offset:10,10 size:100x73
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, AbsposChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        position:relative; margin:0; border:3px solid; padding:10px;
        width:100px; height:100px;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="position:absolute; top:0; right:0; bottom:0; left:0;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:13,0 size:30x30
      offset:3,30 size:120x93
        offset:0,0 size:120x93
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Used height needs to be adjusted to encompass the legend, if specified height
// requests a lower height than that.
TEST_F(FieldsetLayoutAlgorithmTest, ZeroHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; height:0;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:200px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x53
    offset:0,0 size:126x53
      offset:13,0 size:30x30
      offset:3,30 size:120x20
        offset:10,10 size:100x200
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Used height needs to be adjusted to encompass the legend, if specified height
// requests a lower max-height than that.
TEST_F(FieldsetLayoutAlgorithmTest, ZeroMaxHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; max-height:0;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:200px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  // The fieldset height should be the legend height + padding-top +
  // padding-bottom + border-bottom == 53px.
  // The anonymous content block height should be 20px due to the padding
  // delegation.
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x53
    offset:0,0 size:126x53
      offset:13,0 size:30x30
      offset:3,30 size:120x20
        offset:10,10 size:100x200
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Things inside legends and fieldsets are treated as if there was no fieldsets
// and legends involved, as far as the percentage height quirk is concerned.
TEST_F(FieldsetLayoutAlgorithmTest, PercentHeightQuirks) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px;
      }
    </style>
    <div id="container" style="height:200px;">
      <fieldset>
        <legend style="padding:0;">
          <div style="width:100px; height:50%;"></div>
        </legend>
        <div style="width:40px; height:20%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:126x163
      offset:13,0 size:100x100
        offset:0,0 size:100x100
      offset:3,100 size:120x60
        offset:10,10 size:40x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Legends are treated as regular elements, as far as the percentage height
// quirk is concerned.
TEST_F(FieldsetLayoutAlgorithmTest, LegendPercentHeightQuirks) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px;
      }
    </style>
    <div id="container" style="height:200px;">
      <fieldset>
        <legend style="padding:0; width:100px; height:50%;"></legend>
        <div style="width:40px; height:20%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:126x163
      offset:13,0 size:100x100
      offset:3,100 size:120x60
        offset:10,10 size:40x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// This test makes sure that the fieldset content handles fieldset padding
// when the fieldset is expanded to encompass the legend.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetPaddingWithLegend) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:none; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 120px;
        }
        #child {
          width: 100px; height: 40px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div id="child"></div>
      </fieldset>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext());

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:170x140
    offset:10,0 size:50x120
    offset:0,120 size:170x20
      offset:10,10 size:100x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, MinMax) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:123px; border:3px solid; padding:10px; width:100px; }
      legend { margin:20px; border:11px solid; padding:7px; }
      .float { float:left; width:50px; height:50px; }
    </style>
    <div id="container">
      <fieldset id="fieldset1"></fieldset>
      <fieldset id="fieldset2">
        <legend></legend>
      </fieldset>
      <fieldset id="fieldset3">
        <legend></legend>
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset4">
        <legend>
          <div class="float"></div>
          <div class="float"></div>
        </legend>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset5">
        <legend>
          <div class="float"></div>
        </legend>
        <div class="float"></div>
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset6">
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
    </div>
  )HTML");

  MinMaxSizes sizes;

  sizes = RunComputeMinMaxSizes("fieldset1");
  EXPECT_EQ(sizes.min_size, LayoutUnit(26));
  EXPECT_EQ(sizes.max_size, LayoutUnit(26));

  sizes = RunComputeMinMaxSizes("fieldset2");
  EXPECT_EQ(sizes.min_size, LayoutUnit(102));
  EXPECT_EQ(sizes.max_size, LayoutUnit(102));

  sizes = RunComputeMinMaxSizes("fieldset3");
  EXPECT_EQ(sizes.min_size, LayoutUnit(102));
  EXPECT_EQ(sizes.max_size, LayoutUnit(126));

  sizes = RunComputeMinMaxSizes("fieldset4");
  EXPECT_EQ(sizes.min_size, LayoutUnit(152));
  EXPECT_EQ(sizes.max_size, LayoutUnit(202));

  sizes = RunComputeMinMaxSizes("fieldset5");
  EXPECT_EQ(sizes.min_size, LayoutUnit(152));
  EXPECT_EQ(sizes.max_size, LayoutUnit(176));

  sizes = RunComputeMinMaxSizes("fieldset6");
  EXPECT_EQ(sizes.min_size, LayoutUnit(76));
  EXPECT_EQ(sizes.max_size, LayoutUnit(126));
}

// Tests that a fieldset won't fragment if it doesn't reach the fragmentation
// line.
TEST_F(FieldsetLayoutAlgorithmTest, NoFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
      </style>
      <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  // We should only have one 176x126 fragment with no fragmentation.
  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(176, 126), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that a fieldset will fragment if it reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, SimpleFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 500px;
        }
      </style>
      <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(176, 200), fragment->Size());
  ASSERT_TRUE(fragment->GetBreakToken());

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(176, 200), fragment->Size());
  ASSERT_TRUE(fragment->GetBreakToken());

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(176, 126), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that a fieldset with no content or padding will fragment if it reaches
// the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FragmentationNoPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:10px solid; padding:0px; width:100px; }
    </style>
    <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(10);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:120x10
    offset:10,10 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:120x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with auto height will fragment when its content reaches
// the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetContentFragmentationAutoHeight) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px;
        }
        #child {
          margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x200
    offset:3,3 size:170x197
      offset:10,10 size:50x187
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x200
    offset:3,0 size:170x200
      offset:10,0 size:50x200
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x126
    offset:3,0 size:170x123
      offset:10,0 size:50x113
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a set height will fragment when its content
// reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetContentFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #child {
          margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x126
    offset:3,3 size:170x120
      offset:10,10 size:50x187
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176
### 提示词
```
这是目录为blink/renderer/core/layout/forms/fieldset_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/forms/fieldset_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {
namespace {

class FieldsetLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  const PhysicalBoxFragment* RunBlockLayoutAlgorithm(Element* element) {
    BlockNode container(element->GetLayoutBox());
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(1000), kIndefiniteSize));
    return BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(container, space);
  }

  MinMaxSizes RunComputeMinMaxSizes(BlockNode node) {
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(), LayoutUnit()),
        /* stretch_inline_size_if_auto */ true,
        node.CreatesNewFormattingContext());
    FragmentGeometry fragment_geometry = CalculateInitialFragmentGeometry(
        space, node, /* break_token */ nullptr, /* is_intrinsic */ true);

    FieldsetLayoutAlgorithm algorithm({node, fragment_geometry, space});
    return algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  }

  MinMaxSizes RunComputeMinMaxSizes(const char* element_id) {
    BlockNode node(GetLayoutBoxByElementId(element_id));
    return RunComputeMinMaxSizes(node);
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

TEST_F(FieldsetLayoutAlgorithmTest, Empty) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset></fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x26
    offset:0,0 size:126x26
      offset:3,3 size:120x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, NoLegend) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:3,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, Legend) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:50px; height:200px;"></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x323
    offset:0,0 size:126x323
      offset:13,0 size:50x200
      offset:3,200 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, SmallLegendLargeBorder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:40px solid; padding:10px; width:100px; }
      legend { padding:0; width:10px; height:10px;
               margin-top:5px; margin-bottom:15px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:200x200
      offset:50,15 size:10x10
      offset:40,40 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendOrthogonalWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
      legend { writing-mode:vertical-rl; padding:0; margin:10px 15px 20px 30px;
               width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x193
    offset:0,0 size:126x193
      offset:43,0 size:10x50
      offset:3,70 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, VerticalLr) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { writing-mode:vertical-lr; margin:0; border:3px solid;
                 padding:10px; height:100px; }
      legend { padding:0; margin:10px 15px 20px 30px; width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="width:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:148x126
      offset:0,23 size:10x50
      offset:25,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, VerticalRl) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { writing-mode:vertical-rl; margin:0; border:3px solid;
                 padding:10px; height:100px; }
      legend { padding:0; margin:10px 15px 20px 30px; width:10px; height:50px; }
    </style>
    <div id="container">
      <fieldset>
        <legend></legend>
        <div style="width:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:163x126
      offset:153,23 size:10x50
      offset:3,3 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendAutoSize) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:0; border:3px solid; padding:10px; width:100px; }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0;">
          <div style="float:left; width:25px; height:200px;"></div>
          <div style="float:left; width:25px; height:200px;"></div>
        </legend>
        <div style="height:100px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x323
    offset:0,0 size:126x323
      offset:13,0 size:50x200
        offset:0,0 size:25x200
        offset:25,0 size:25x200
      offset:3,200 size:120x120
        offset:10,10 size:100x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, PercentageHeightChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; height:100px;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:100%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:13,0 size:30x30
      offset:3,30 size:120x93
        offset:10,10 size:100x73
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, AbsposChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        position:relative; margin:0; border:3px solid; padding:10px;
        width:100px; height:100px;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="position:absolute; top:0; right:0; bottom:0; left:0;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x126
    offset:0,0 size:126x126
      offset:13,0 size:30x30
      offset:3,30 size:120x93
        offset:0,0 size:120x93
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Used height needs to be adjusted to encompass the legend, if specified height
// requests a lower height than that.
TEST_F(FieldsetLayoutAlgorithmTest, ZeroHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; height:0;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:200px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x53
    offset:0,0 size:126x53
      offset:13,0 size:30x30
      offset:3,30 size:120x20
        offset:10,10 size:100x200
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Used height needs to be adjusted to encompass the legend, if specified height
// requests a lower max-height than that.
TEST_F(FieldsetLayoutAlgorithmTest, ZeroMaxHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px; max-height:0;
      }
    </style>
    <div id="container">
      <fieldset>
        <legend style="padding:0; width:30px; height:30px;"></legend>
        <div style="height:200px;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  // The fieldset height should be the legend height + padding-top +
  // padding-bottom + border-bottom == 53px.
  // The anonymous content block height should be 20px due to the padding
  // delegation.
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x53
    offset:0,0 size:126x53
      offset:13,0 size:30x30
      offset:3,30 size:120x20
        offset:10,10 size:100x200
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Things inside legends and fieldsets are treated as if there was no fieldsets
// and legends involved, as far as the percentage height quirk is concerned.
TEST_F(FieldsetLayoutAlgorithmTest, PercentHeightQuirks) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px;
      }
    </style>
    <div id="container" style="height:200px;">
      <fieldset>
        <legend style="padding:0;">
          <div style="width:100px; height:50%;"></div>
        </legend>
        <div style="width:40px; height:20%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:126x163
      offset:13,0 size:100x100
        offset:0,0 size:100x100
      offset:3,100 size:120x60
        offset:10,10 size:40x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Legends are treated as regular elements, as far as the percentage height
// quirk is concerned.
TEST_F(FieldsetLayoutAlgorithmTest, LegendPercentHeightQuirks) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset {
        margin:0; border:3px solid; padding:10px; width:100px;
      }
    </style>
    <div id="container" style="height:200px;">
      <fieldset>
        <legend style="padding:0; width:100px; height:50%;"></legend>
        <div style="width:40px; height:20%;"></div>
      </fieldset>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:126x163
      offset:13,0 size:100x100
      offset:3,100 size:120x60
        offset:10,10 size:40x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// This test makes sure that the fieldset content handles fieldset padding
// when the fieldset is expanded to encompass the legend.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetPaddingWithLegend) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:none; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 120px;
        }
        #child {
          width: 100px; height: 40px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div id="child"></div>
      </fieldset>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext());

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:170x140
    offset:10,0 size:50x120
    offset:0,120 size:170x20
      offset:10,10 size:100x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, MinMax) {
  SetBodyInnerHTML(R"HTML(
    <style>
      fieldset { margin:123px; border:3px solid; padding:10px; width:100px; }
      legend { margin:20px; border:11px solid; padding:7px; }
      .float { float:left; width:50px; height:50px; }
    </style>
    <div id="container">
      <fieldset id="fieldset1"></fieldset>
      <fieldset id="fieldset2">
        <legend></legend>
      </fieldset>
      <fieldset id="fieldset3">
        <legend></legend>
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset4">
        <legend>
          <div class="float"></div>
          <div class="float"></div>
        </legend>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset5">
        <legend>
          <div class="float"></div>
        </legend>
        <div class="float"></div>
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
      <fieldset id="fieldset6">
        <div class="float"></div>
        <div class="float"></div>
      </fieldset>
    </div>
  )HTML");

  MinMaxSizes sizes;

  sizes = RunComputeMinMaxSizes("fieldset1");
  EXPECT_EQ(sizes.min_size, LayoutUnit(26));
  EXPECT_EQ(sizes.max_size, LayoutUnit(26));

  sizes = RunComputeMinMaxSizes("fieldset2");
  EXPECT_EQ(sizes.min_size, LayoutUnit(102));
  EXPECT_EQ(sizes.max_size, LayoutUnit(102));

  sizes = RunComputeMinMaxSizes("fieldset3");
  EXPECT_EQ(sizes.min_size, LayoutUnit(102));
  EXPECT_EQ(sizes.max_size, LayoutUnit(126));

  sizes = RunComputeMinMaxSizes("fieldset4");
  EXPECT_EQ(sizes.min_size, LayoutUnit(152));
  EXPECT_EQ(sizes.max_size, LayoutUnit(202));

  sizes = RunComputeMinMaxSizes("fieldset5");
  EXPECT_EQ(sizes.min_size, LayoutUnit(152));
  EXPECT_EQ(sizes.max_size, LayoutUnit(176));

  sizes = RunComputeMinMaxSizes("fieldset6");
  EXPECT_EQ(sizes.min_size, LayoutUnit(76));
  EXPECT_EQ(sizes.max_size, LayoutUnit(126));
}

// Tests that a fieldset won't fragment if it doesn't reach the fragmentation
// line.
TEST_F(FieldsetLayoutAlgorithmTest, NoFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
      </style>
      <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  // We should only have one 176x126 fragment with no fragmentation.
  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(176, 126), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that a fieldset will fragment if it reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, SimpleFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 500px;
        }
      </style>
      <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(176, 200), fragment->Size());
  ASSERT_TRUE(fragment->GetBreakToken());

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(176, 200), fragment->Size());
  ASSERT_TRUE(fragment->GetBreakToken());

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(176, 126), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that a fieldset with no content or padding will fragment if it reaches
// the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FragmentationNoPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:10px solid; padding:0px; width:100px; }
    </style>
    <fieldset id="fieldset"></fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(10);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:120x10
    offset:10,10 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:120x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with auto height will fragment when its content reaches
// the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetContentFragmentationAutoHeight) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px;
        }
        #child {
          margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x200
    offset:3,3 size:170x197
      offset:10,10 size:50x187
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x200
    offset:3,0 size:170x200
      offset:10,0 size:50x200
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x126
    offset:3,0 size:170x123
      offset:10,0 size:50x113
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a set height will fragment when its content
// reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, FieldsetContentFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #child {
          margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x126
    offset:3,3 size:170x120
      offset:10,10 size:50x187
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x0
    offset:3,0 size:170x0
      offset:10,0 size:50x200
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x0
    offset:3,0 size:170x0
      offset:10,0 size:50x113
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with auto height will not fragment when its legend
// reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, LegendFragmentationAutoHeight) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x500
    offset:13,0 size:50x500
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x23
    offset:3,0 size:170x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a set height will not fragment when its legend
// reaches the fragmentation line. The used height should also be extended to
// encompass the legend.
TEST_F(FieldsetLayoutAlgorithmTest, LegendFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 500px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x500
    offset:13,0 size:50x500
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x23
    offset:3,0 size:170x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with auto height will not fragment when its legend
// reaches the fragmentation line. The content of the fieldset should fragment
// when it reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, LegendAndContentFragmentationAutoHeight) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 500px;
        }
        #child {
          margin:0; width: 100px; height: 200px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x500
    offset:13,0 size:50x500
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());
  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x200
    offset:3,0 size:170x200
      offset:10,10 size:100x190
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x23
    offset:3,0 size:170x20
      offset:10,0 size:100x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a set height will fragment when its legend reaches
// the fragmentation line. The content of the fieldset should fragment when it
// reaches the fragmentation line.
TEST_F(FieldsetLayoutAlgorithmTest, LegendAndContentFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:3px solid; margin:0; padding:10px; width: 150px; height: 100px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 500px;
        }
        #child {
          margin:0; width: 100px; height: 200px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x500
    offset:13,0 size:50x500
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x23
    offset:3,0 size:170x20
      offset:10,10 size:100x190
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());
  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:176x0
    offset:3,0 size:170x0
```