Response:
My thinking process for summarizing the provided C++ code and addressing the prompt's requirements goes like this:

1. **Understand the Core Purpose:** The filename `grid_layout_algorithm_test.cc` immediately suggests that this code is about testing the grid layout algorithm in the Blink rendering engine. The presence of `#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"` confirms this. The `TEST_F` macros throughout the code reinforce that this is a unit test file.

2. **Identify Key Components:**  I scanned the code for important classes, functions, and macros. I noted:
    * `GridLayoutAlgorithmTest`: The main test fixture class.
    * `BaseLayoutAlgorithmTest`:  The base class, indicating this test builds upon a common testing framework.
    * `GridLayoutAlgorithm`: The class being tested.
    * `GridItemData`, `GridSizingTrackCollection`, `GridArea`, `GridRangeVector`: Data structures related to grid layout.
    * `BuildGridItemsAndTrackCollections`, `ComputeGridGeometry`:  Key functions within `GridLayoutAlgorithm` that are being tested indirectly.
    * Helper methods like `GridItem`, `TrackCollection`, `Ranges`, `BaseRowSizeForChild`, `GridItemCount`, `GridItemGridAreas`, etc.:  These are utility functions within the test fixture to make assertions easier.
    * `EXPECT_RANGE`, `EXPECT_GRID_AREA`: Custom macros for concise assertion checks.
    * Numerous `TEST_F` blocks: Each representing a specific test case.

3. **Infer Functionality from Test Names and Code:** I examined the names of the `TEST_F` functions and the code within them to understand what specific aspects of the grid layout algorithm are being tested. For example:
    * `GridLayoutAlgorithmBaseSetSizes`:  Likely tests the calculation of base sizes for grid items.
    * `GridLayoutAlgorithmRanges`: Tests the determination of grid line ranges.
    * `GridLayoutAlgorithmRangesWithAutoRepeater`: Tests ranges with `repeat(auto-fit, ...)` syntax.
    * `GridLayoutAlgorithmImplicit...`: Tests how implicit grid lines are handled.
    * `GridLayoutAlgorithmAutoGridPositions`, `GridLayoutAlgorithmAutoDense`: Tests auto-placement of grid items.
    * `GridLayoutAlgorithmGridPositions`: Tests explicit grid item placement.
    * `GridLayoutAlgorithmResolveFixedTrackSizes`: Tests the resolution of fixed-size grid tracks.
    * `GridLayoutAlgorithmDetermineGridItemsSpanningIntrinsicOrFlexTracks`: Tests the identification of items spanning intrinsic or flexible tracks.
    * `FixedSizePositioning`, `FixedSizePositioningAutoRows`: Tests the final positioning of grid items.
    * `SpecifiedPositionsOutOfOrder`:  Tests handling of out-of-order grid item declarations.

4. **Identify Relationships with Web Technologies (HTML, CSS, JavaScript):** Based on my understanding of web development and the code's focus on grid layout, I made the following connections:
    * **CSS Grid Layout:** This is the primary feature being tested. The test cases directly correspond to CSS grid properties like `display: grid`, `grid-template-columns`, `grid-template-rows`, `grid-gap`, `grid-column`, `grid-row`, `grid-auto-flow`, `grid-auto-columns`, `grid-auto-rows`, and the `repeat()` function.
    * **HTML Structure:** The tests use HTML to define the grid container and grid items. The structure of the HTML directly influences the layout being tested.
    * **JavaScript (Indirect):** While the test code is C++, the underlying grid layout algorithm is what enables JavaScript frameworks and developers to create dynamic and responsive layouts. JavaScript can manipulate the DOM and CSS properties, which in turn trigger the grid layout algorithm.

5. **Construct Examples:**  For each relationship, I created simple HTML/CSS examples to illustrate the corresponding functionality being tested. This involved taking concepts from the test names and code and translating them into common web development scenarios.

6. **Address Logic and Assumptions (Input/Output):**  For specific test cases that implied a clear logical flow, I created hypothetical input (CSS properties and HTML structure) and output (expected grid item placement or track sizes). This involved looking at the `EXPECT_EQ` assertions and working backward to understand the expected behavior.

7. **Identify Common Errors:** I thought about common mistakes developers make when using CSS Grid:
    * Incorrect `grid-column`/`grid-row` values (overlapping, out-of-bounds).
    * Confusing implicit and explicit grid lines.
    * Not understanding how `auto-fit`/`auto-fill` work.
    * Overlooking the impact of `grid-auto-flow`.

8. **Structure the Summary:** I organized the information into the requested sections: functionality, relationship with web technologies, logical reasoning, and common errors. I used clear and concise language.

9. **Review and Refine:**  I reread my summary to ensure accuracy, completeness, and clarity. I made sure the examples were relevant and easy to understand. I also double-checked that I addressed all parts of the prompt. For instance, ensuring the first part of the prompt specifically asks for a summary of the file's function.

This iterative process of code analysis, inference, and example construction allowed me to generate a comprehensive summary that addressed the prompt's requirements. The key was to connect the low-level C++ testing code to the high-level concepts of web development with CSS Grid.
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {

namespace {

#define EXPECT_RANGE(expected_start, expected_count, range) \
  EXPECT_EQ(expected_start, range.start_line);              \
  EXPECT_EQ(expected_count, range.track_count);             \
  EXPECT_FALSE(range.IsCollapsed());
#define EXPECT_GRID_AREA(area, expected_column_start, expected_column_end, \
                         expected_row_start, expected_row_end)             \
  EXPECT_EQ(area.columns.StartLine(), expected_column_start);              \
  EXPECT_EQ(area.columns.EndLine(), expected_column_end);                  \
  EXPECT_EQ(area.rows.StartLine(), expected_row_start);                    \
  EXPECT_EQ(area.rows.EndLine(), expected_row_end);

}  // namespace

class GridLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  void SetUp() override { BaseLayoutAlgorithmTest::SetUp(); }

  void BuildGridItemsAndTrackCollections(GridLayoutAlgorithm& algorithm) {
    LayoutUnit unused_intrinsic_block_size;
    auto grid_sizing_tree = algorithm.BuildGridSizingTree();

    algorithm.ComputeGridGeometry(grid_sizing_tree,
                                  &unused_intrinsic_block_size);

    auto& [grid_items, layout_data, tree_size] =
        grid_sizing_tree.TreeRootData();

    cached_grid_items_ = std::move(grid_items);
    layout_data_ = std::move(layout_data);
  }

  const GridItemData& GridItem(wtf_size_t index) {
    return cached_grid_items_.At(index);
  }

  const GridSizingTrackCollection& TrackCollection(
      GridTrackSizingDirection track_direction) {
    const auto& track_collection = (track_direction == kForColumns)
                                       ? layout_data_.Columns()
                                       : layout_data_.Rows();
    return To<GridSizingTrackCollection>(track_collection);
  }

  const GridRangeVector& Ranges(GridTrackSizingDirection track_direction) {
    return TrackCollection(track_direction).ranges_;
  }

  LayoutUnit BaseRowSizeForChild(const GridLayoutAlgorithm& algorithm,
                                 wtf_size_t index) {
    return algorithm.ComputeGridItemAvailableSize(GridItem(index),
                                                  layout_data_.Rows());
  }

  // Helper methods to access private data on GridLayoutAlgorithm. This class
  // is a friend of GridLayoutAlgorithm but the individual tests are not.
  wtf_size_t GridItemCount() { return cached_grid_items_.Size(); }

  Vector<GridArea> GridItemGridAreas() {
    Vector<GridArea> results;
    for (const auto& grid_item : cached_grid_items_)
      results.push_back(grid_item.resolved_position);
    return results;
  }

  Vector<wtf_size_t> GridItemsWithColumnSpanProperty(
      TrackSpanProperties::PropertyId property) {
    Vector<wtf_size_t> results;
    for (wtf_size_t i = 0; i < GridItemCount(); ++i) {
      if (GridItem(i).column_span_properties.HasProperty(property))
        results.push_back(i);
    }
    return results;
  }

  Vector<wtf_size_t> GridItemsWithRowSpanProperty(
      TrackSpanProperties::PropertyId property) {
    Vector<wtf_size_t> results;
    for (wtf_size_t i = 0; i < GridItemCount(); ++i) {
      if (GridItem(i).row_span_properties.HasProperty(property))
        results.push_back(i);
    }
    return results;
  }

  Vector<LayoutUnit> BaseSizes(GridTrackSizingDirection track_direction) {
    const auto& collection = TrackCollection(track_direction);

    Vector<LayoutUnit> base_sizes;
    for (auto set_iterator = collection.GetConstSetIterator();
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      base_sizes.push_back(set_iterator.CurrentSet().BaseSize());
    }
    return base_sizes;
  }

  Vector<LayoutUnit> GrowthLimits(GridTrackSizingDirection track_direction) {
    const auto& collection = TrackCollection(track_direction);

    Vector<LayoutUnit> growth_limits;
    for (auto set_iterator = collection.GetConstSetIterator();
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      growth_limits.push_back(set_iterator.CurrentSet().GrowthLimit());
    }
    return growth_limits;
  }

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

  GridItems cached_grid_items_;
  GridLayoutData layout_data_;
};

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmBaseSetSizes) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-gap: 10px;
      grid-template-columns: 100px;
      grid-template-rows: auto auto 100px 100px auto 100px;
    }
    </style>
    <div id="grid1">
      <div style="grid-row: 1/2;"></div>
      <div style="grid-row: 2/4;"></div>
      <div style="grid-row: 3/5;"></div>
      <div style="grid-row: 6/7;"></div>
      <div style="grid-row: 4/6;"></div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 0), LayoutUnit(0));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 1), LayoutUnit(110));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 2), LayoutUnit(210));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 3), LayoutUnit(100));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 4), LayoutUnit(110));
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-template-columns: repeat(2, 100px 100px 200px 200px);
      grid-template-rows: repeat(1000, 100px);
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 999u, row_ranges[1]);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(5u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 1u, column_ranges[2]);
  EXPECT_RANGE(3u, 1u, column_ranges[3]);
  EXPECT_RANGE(4u, 4u, column_ranges[4]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesWithAutoRepeater) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-template-columns: 5px repeat(auto-fit, 150px) repeat(3, 10px) 10px 10px;
      grid-template-rows: repeat(20, 100px) 10px 10px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(4u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 19u, row_ranges[1]);
  EXPECT_RANGE(20u, 1u, row_ranges[2]);
  EXPECT_RANGE(21u, 1u, row_ranges[3]);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(7u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 1u, column_ranges[2]);
  EXPECT_RANGE(3u, 1u, column_ranges[3]);
  EXPECT_RANGE(4u, 1u, column_ranges[4]);
  EXPECT_RANGE(5u, 1u, column_ranges[5]);
  EXPECT_RANGE(6u, 1u, column_ranges[6]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicit) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 1 / 2;
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-column: 2 / 3;
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell3 {
      grid-column: 1 / 2;
      grid-row: 2 / 3;
      width: 50px;
    }
    #cell4 {
      grid-column: 2 / 5;
      grid-row: 2 / 3;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(3u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 2u, column_ranges[2]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitAutoColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell3 {
      grid-row: 2 / 3;
      width: 50px;
    }
    #cell4 {
      grid-row: 2 / 3;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(2u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitAutoRows) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-column: 2 / 3;
      width: 50px;
    }
    #cell3 {
      grid-column: 1 / 2;
      width: 50px;
    }
    #cell4 {
      grid-column: 2 / 5;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(3u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 2u, column_ranges[2]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitMixed) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 2;
      grid-row: 1;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
      <div id="cell4">Cell 5</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 5U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(2u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(3u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
  EXPECT_RANGE(2u, 1u, row_ranges[2]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmAutoGridPositions) {
  SetBodyInnerHTML(R"HTML(
  <style>
      body {
        font: 10px/1 Ahem;
      }
      #grid {
        display: grid;
        width: 400px;
        height: 400px;
        grid-template-columns: 100px 100px;
        grid-template-rows: 100px 100px;
      }
      .grid_item1 {
        display: block;
        width: 100px;
        height: 100px;
        grid-row: 2;
        grid-column: 2;
      }
      .grid_item2 {
        display: block;
        width: 90px;
        height: 90px;
      }
      .grid_item3 {
        display: block;
        width: 80px;
        height: 80px;
      }
      .grid_item4 {
        display: block;
        width: 70px;
        height: 70px;
        grid-row: 1;
        grid-column: 1;
      }
    </style>
    <div id="wrapper">
      <div id="grid">
        <div class="grid_item1">1</div>
        <div class="grid_item2">2</div>
        <div class="grid_item3">3</div>
        <div class="grid_item4">4</div>
      </div>
    </div>

  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  Vector<GridArea> grid_positions = GridItemGridAreas();
  ASSERT_EQ(grid_positions.size(), 4U);

  EXPECT_GRID_AREA(grid_positions[0], 1U, 2U, 1U, 2U);
  EXPECT_GRID_AREA(grid_positions[1], 1U, 2U, 0U, 1U);
  EXPECT_GRID_AREA(grid_positions[2], 0U, 1U, 1U, 2U);
  EXPECT_GRID_AREA(grid_positions[3], 0U, 1U, 0U, 1U);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmAutoDense) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #grid {
        display: grid;
        grid-auto-flow: dense;
        grid-template-columns: repeat(10, 40px);
        grid-template-rows: repeat(10, 40px);
      }

      .item {
        display: block;
        font: 40px/1 Ahem;
        border: 2px solid black;
        width: 100%;
        height: 100%;
      }
      .auto-one {
        border: 2px solid red;
      }
      .auto-both {
        border: 2px solid blue;
      }
      .a {
        grid-column: 1 / 3;
        grid-row: 1 / 3;
      }
      .b {
        grid-column: 4 / 8;
        grid-row: 1 / 4;
      }
      .c {
        grid-column: 9 / 11;
        grid-row: 1 / 2;
      }
      .d {
        grid-column: 1 / 3;
        grid-row: 4 / 6;
      }
      .e {
        grid-column: 4 / 6;
        grid-row: 4 / 5;
      }
      .f {
        grid-column: 7 / 10;
        grid-row: 5 / 6;
      }
      .g {
        grid-column: 6 / 7;
        grid-row: 8 / 9;
      }
      .h {
        grid-column: 6 / 8;
        grid-row-end: span 2;
      }
      .i {
        grid-row: 4 / 5;
        grid-column-end: span 2;
      }
      .j {
        grid-column: 6 / 7;
      }
      .u {
        grid-column-end: span 5;
        grid-row-end: span 5;
      }
      .v {
        grid-row-end: span 9;
      }
      .w {
        grid-column-end: span 2;
        grid-row-end: span 3;
      }
      .x {
        grid-row-end: span 5;
      }

    </style>
    <div id="wrapper">
      <div id="grid">
        <div class="item a">a</div>
        <div class="item b">b</div>
        <div class="item c">c</div>
        <div class="item d">d</div>
        <div class="item e">e</div>
        <div class="item f">f</div>
        <div class="item g">g</div>
        <div class="auto-one item h">h</div>
        <div class="auto-one item i">i</div>
        <div class="auto-one item j">j</div>
        <div class="auto-both item u">u</div>
        <div class="auto-both item v">v</div>
        <div class="auto-both item w">w</div>
        <div class="auto-both item x">x</div>
        <div class="auto-both item y">y</div>
        <div class="auto-both item z">z</div>
      </div>
    </div>

  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)),
      /* stretch_inline_size_if_auto */ true,
      
### 提示词
```
这是目录为blink/renderer/core/layout/grid/grid_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"

namespace blink {

namespace {

#define EXPECT_RANGE(expected_start, expected_count, range) \
  EXPECT_EQ(expected_start, range.start_line);              \
  EXPECT_EQ(expected_count, range.track_count);             \
  EXPECT_FALSE(range.IsCollapsed());
#define EXPECT_GRID_AREA(area, expected_column_start, expected_column_end, \
                         expected_row_start, expected_row_end)             \
  EXPECT_EQ(area.columns.StartLine(), expected_column_start);              \
  EXPECT_EQ(area.columns.EndLine(), expected_column_end);                  \
  EXPECT_EQ(area.rows.StartLine(), expected_row_start);                    \
  EXPECT_EQ(area.rows.EndLine(), expected_row_end);

}  // namespace

class GridLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  void SetUp() override { BaseLayoutAlgorithmTest::SetUp(); }

  void BuildGridItemsAndTrackCollections(GridLayoutAlgorithm& algorithm) {
    LayoutUnit unused_intrinsic_block_size;
    auto grid_sizing_tree = algorithm.BuildGridSizingTree();

    algorithm.ComputeGridGeometry(grid_sizing_tree,
                                  &unused_intrinsic_block_size);

    auto& [grid_items, layout_data, tree_size] =
        grid_sizing_tree.TreeRootData();

    cached_grid_items_ = std::move(grid_items);
    layout_data_ = std::move(layout_data);
  }

  const GridItemData& GridItem(wtf_size_t index) {
    return cached_grid_items_.At(index);
  }

  const GridSizingTrackCollection& TrackCollection(
      GridTrackSizingDirection track_direction) {
    const auto& track_collection = (track_direction == kForColumns)
                                       ? layout_data_.Columns()
                                       : layout_data_.Rows();
    return To<GridSizingTrackCollection>(track_collection);
  }

  const GridRangeVector& Ranges(GridTrackSizingDirection track_direction) {
    return TrackCollection(track_direction).ranges_;
  }

  LayoutUnit BaseRowSizeForChild(const GridLayoutAlgorithm& algorithm,
                                 wtf_size_t index) {
    return algorithm.ComputeGridItemAvailableSize(GridItem(index),
                                                  layout_data_.Rows());
  }

  // Helper methods to access private data on GridLayoutAlgorithm. This class
  // is a friend of GridLayoutAlgorithm but the individual tests are not.
  wtf_size_t GridItemCount() { return cached_grid_items_.Size(); }

  Vector<GridArea> GridItemGridAreas() {
    Vector<GridArea> results;
    for (const auto& grid_item : cached_grid_items_)
      results.push_back(grid_item.resolved_position);
    return results;
  }

  Vector<wtf_size_t> GridItemsWithColumnSpanProperty(
      TrackSpanProperties::PropertyId property) {
    Vector<wtf_size_t> results;
    for (wtf_size_t i = 0; i < GridItemCount(); ++i) {
      if (GridItem(i).column_span_properties.HasProperty(property))
        results.push_back(i);
    }
    return results;
  }

  Vector<wtf_size_t> GridItemsWithRowSpanProperty(
      TrackSpanProperties::PropertyId property) {
    Vector<wtf_size_t> results;
    for (wtf_size_t i = 0; i < GridItemCount(); ++i) {
      if (GridItem(i).row_span_properties.HasProperty(property))
        results.push_back(i);
    }
    return results;
  }

  Vector<LayoutUnit> BaseSizes(GridTrackSizingDirection track_direction) {
    const auto& collection = TrackCollection(track_direction);

    Vector<LayoutUnit> base_sizes;
    for (auto set_iterator = collection.GetConstSetIterator();
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      base_sizes.push_back(set_iterator.CurrentSet().BaseSize());
    }
    return base_sizes;
  }

  Vector<LayoutUnit> GrowthLimits(GridTrackSizingDirection track_direction) {
    const auto& collection = TrackCollection(track_direction);

    Vector<LayoutUnit> growth_limits;
    for (auto set_iterator = collection.GetConstSetIterator();
         !set_iterator.IsAtEnd(); set_iterator.MoveToNextSet()) {
      growth_limits.push_back(set_iterator.CurrentSet().GrowthLimit());
    }
    return growth_limits;
  }

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

  GridItems cached_grid_items_;
  GridLayoutData layout_data_;
};

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmBaseSetSizes) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-gap: 10px;
      grid-template-columns: 100px;
      grid-template-rows: auto auto 100px 100px auto 100px;
    }
    </style>
    <div id="grid1">
      <div style="grid-row: 1/2;"></div>
      <div style="grid-row: 2/4;"></div>
      <div style="grid-row: 3/5;"></div>
      <div style="grid-row: 6/7;"></div>
      <div style="grid-row: 4/6;"></div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 0), LayoutUnit(0));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 1), LayoutUnit(110));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 2), LayoutUnit(210));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 3), LayoutUnit(100));
  EXPECT_EQ(BaseRowSizeForChild(algorithm, 4), LayoutUnit(110));
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-template-columns: repeat(2, 100px 100px 200px 200px);
      grid-template-rows: repeat(1000, 100px);
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 999u, row_ranges[1]);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(5u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 1u, column_ranges[2]);
  EXPECT_RANGE(3u, 1u, column_ranges[3]);
  EXPECT_RANGE(4u, 4u, column_ranges[4]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesWithAutoRepeater) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
      grid-template-columns: 5px repeat(auto-fit, 150px) repeat(3, 10px) 10px 10px;
      grid-template-rows: repeat(20, 100px) 10px 10px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(4u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 19u, row_ranges[1]);
  EXPECT_RANGE(20u, 1u, row_ranges[2]);
  EXPECT_RANGE(21u, 1u, row_ranges[3]);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(7u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 1u, column_ranges[2]);
  EXPECT_RANGE(3u, 1u, column_ranges[3]);
  EXPECT_RANGE(4u, 1u, column_ranges[4]);
  EXPECT_RANGE(5u, 1u, column_ranges[5]);
  EXPECT_RANGE(6u, 1u, column_ranges[6]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicit) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 1 / 2;
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-column: 2 / 3;
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell3 {
      grid-column: 1 / 2;
      grid-row: 2 / 3;
      width: 50px;
    }
    #cell4 {
      grid-column: 2 / 5;
      grid-row: 2 / 3;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(3u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 2u, column_ranges[2]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitAutoColumns) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-row: 1 / 2;
      width: 50px;
    }
    #cell3 {
      grid-row: 2 / 3;
      width: 50px;
    }
    #cell4 {
      grid-row: 2 / 3;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(2u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitAutoRows) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 1 / 2;
      width: 50px;
    }
    #cell2 {
      grid-column: 2 / 3;
      width: 50px;
    }
    #cell3 {
      grid-column: 1 / 2;
      width: 50px;
    }
    #cell4 {
      grid-column: 2 / 5;
      width: 50px;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(3u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);
  EXPECT_RANGE(2u, 2u, column_ranges[2]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(2u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmRangesImplicitMixed) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid1 {
      display: grid;
    }
    #cell1 {
      grid-column: 2;
      grid-row: 1;
    }
    </style>
    <div id="grid1">
      <div id="cell1">Cell 1</div>
      <div id="cell2">Cell 2</div>
      <div id="cell3">Cell 3</div>
      <div id="cell4">Cell 4</div>
      <div id="cell4">Cell 5</div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid1"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 5U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(2u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(3u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 1u, row_ranges[1]);
  EXPECT_RANGE(2u, 1u, row_ranges[2]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmAutoGridPositions) {
  SetBodyInnerHTML(R"HTML(
  <style>
      body {
        font: 10px/1 Ahem;
      }
      #grid {
        display: grid;
        width: 400px;
        height: 400px;
        grid-template-columns: 100px 100px;
        grid-template-rows: 100px 100px;
      }
      .grid_item1 {
        display: block;
        width: 100px;
        height: 100px;
        grid-row: 2;
        grid-column: 2;
      }
      .grid_item2 {
        display: block;
        width: 90px;
        height: 90px;
      }
      .grid_item3 {
        display: block;
        width: 80px;
        height: 80px;
      }
      .grid_item4 {
        display: block;
        width: 70px;
        height: 70px;
        grid-row: 1;
        grid-column: 1;
      }
    </style>
    <div id="wrapper">
      <div id="grid">
        <div class="grid_item1">1</div>
        <div class="grid_item2">2</div>
        <div class="grid_item3">3</div>
        <div class="grid_item4">4</div>
      </div>
    </div>

  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 4U);

  Vector<GridArea> grid_positions = GridItemGridAreas();
  ASSERT_EQ(grid_positions.size(), 4U);

  EXPECT_GRID_AREA(grid_positions[0], 1U, 2U, 1U, 2U);
  EXPECT_GRID_AREA(grid_positions[1], 1U, 2U, 0U, 1U);
  EXPECT_GRID_AREA(grid_positions[2], 0U, 1U, 1U, 2U);
  EXPECT_GRID_AREA(grid_positions[3], 0U, 1U, 0U, 1U);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmAutoDense) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #grid {
        display: grid;
        grid-auto-flow: dense;
        grid-template-columns: repeat(10, 40px);
        grid-template-rows: repeat(10, 40px);
      }

      .item {
        display: block;
        font: 40px/1 Ahem;
        border: 2px solid black;
        width: 100%;
        height: 100%;
      }
      .auto-one {
        border: 2px solid red;
      }
      .auto-both {
        border: 2px solid blue;
      }
      .a {
        grid-column: 1 / 3;
        grid-row: 1 / 3;
      }
      .b {
        grid-column: 4 / 8;
        grid-row: 1 / 4;
      }
      .c {
        grid-column: 9 / 11;
        grid-row: 1 / 2;
      }
      .d {
        grid-column: 1 / 3;
        grid-row: 4 / 6;
      }
      .e {
        grid-column: 4 / 6;
        grid-row: 4 / 5;
      }
      .f {
        grid-column: 7 / 10;
        grid-row: 5 / 6;
      }
      .g {
        grid-column: 6 / 7;
        grid-row: 8 / 9;
      }
      .h {
        grid-column: 6 / 8;
        grid-row-end: span 2;
      }
      .i {
        grid-row: 4 / 5;
        grid-column-end: span 2;
      }
      .j {
        grid-column: 6 / 7;
      }
      .u {
        grid-column-end: span 5;
        grid-row-end: span 5;
      }
      .v {
        grid-row-end: span 9;
      }
      .w {
        grid-column-end: span 2;
        grid-row-end: span 3;
      }
      .x {
        grid-row-end: span 5;
      }

    </style>
    <div id="wrapper">
      <div id="grid">
        <div class="item a">a</div>
        <div class="item b">b</div>
        <div class="item c">c</div>
        <div class="item d">d</div>
        <div class="item e">e</div>
        <div class="item f">f</div>
        <div class="item g">g</div>
        <div class="auto-one item h">h</div>
        <div class="auto-one item i">i</div>
        <div class="auto-one item j">j</div>
        <div class="auto-both item u">u</div>
        <div class="auto-both item v">v</div>
        <div class="auto-both item w">w</div>
        <div class="auto-both item x">x</div>
        <div class="auto-both item y">y</div>
        <div class="auto-both item z">z</div>
      </div>
    </div>

  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 16U);

  Vector<GridArea> grid_positions = GridItemGridAreas();
  ASSERT_EQ(grid_positions.size(), 16U);

  // Expected placements:
  //   0 1 2 3 4 5 6 7 8 9
  // 0 a a x b b b b y c c
  // 1 a a x b b b b w w v
  // 2 z * x b b b b w w v
  // 3 d d x e e i i w w v
  // 4 d d x * * j f f f v
  // 5 u u u u u h h * * v
  // 6 u u u u u h h * * v
  // 7 u u u u u g * * * v
  // 8 u u u u u * * * * v
  // 9 u u u u u * * * * v

  // Fixed positions: a-g
  EXPECT_GRID_AREA(grid_positions[0], 0U, 2U, 0U, 2U);
  EXPECT_GRID_AREA(grid_positions[1], 3U, 7U, 0U, 3U);
  EXPECT_GRID_AREA(grid_positions[2], 8U, 10U, 0U, 1U);
  EXPECT_GRID_AREA(grid_positions[3], 0U, 2U, 3U, 5U);
  EXPECT_GRID_AREA(grid_positions[4], 3U, 5U, 3U, 4U);
  EXPECT_GRID_AREA(grid_positions[5], 6U, 9U, 4U, 5U);
  EXPECT_GRID_AREA(grid_positions[6], 5U, 6U, 7U, 8U);

  // Fixed on single axis positions: h-j
  EXPECT_GRID_AREA(grid_positions[7], 5U, 7U, 5U, 7U);
  EXPECT_GRID_AREA(grid_positions[8], 5U, 7U, 3U, 4U);
  EXPECT_GRID_AREA(grid_positions[9], 5U, 6U, 4U, 5U);

  // Auto on both axis: u-z
  EXPECT_GRID_AREA(grid_positions[10], 0U, 5U, 5U, 10U);
  EXPECT_GRID_AREA(grid_positions[11], 9U, 10U, 1U, 10U);
  EXPECT_GRID_AREA(grid_positions[12], 7U, 9U, 1U, 4U);
  EXPECT_GRID_AREA(grid_positions[13], 2U, 3U, 0U, 5U);
  EXPECT_GRID_AREA(grid_positions[14], 7U, 8U, 0U, 1U);
  EXPECT_GRID_AREA(grid_positions[15], 0U, 1U, 2U, 3U);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmGridPositions) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #grid {
        display: grid;
        height: 200px;
        grid-template-columns: 200px;
        grid-template-rows: repeat(6, 1fr);
      }

      #item2 {
        background-color: yellow;
        grid-row: -2 / 4;
      }

      #item3 {
        background-color: blue;
        grid-row: span 2 / 7;
      }
    </style>
    <div id="grid">
      <div id="item1"></div>
      <div id="item2"></div>
      <div id="item3"></div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  EXPECT_EQ(GridItemCount(), 0U);
  BuildGridItemsAndTrackCollections(algorithm);
  EXPECT_EQ(GridItemCount(), 3U);

  const auto& column_ranges = Ranges(kForColumns);
  EXPECT_EQ(2u, column_ranges.size());
  EXPECT_RANGE(0u, 1u, column_ranges[0]);
  EXPECT_RANGE(1u, 1u, column_ranges[1]);

  const auto& row_ranges = Ranges(kForRows);
  EXPECT_EQ(5u, row_ranges.size());
  EXPECT_RANGE(0u, 1u, row_ranges[0]);
  EXPECT_RANGE(1u, 2u, row_ranges[1]);
  EXPECT_RANGE(3u, 1u, row_ranges[2]);
  EXPECT_RANGE(4u, 1u, row_ranges[3]);
  EXPECT_RANGE(5u, 1u, row_ranges[4]);
}

TEST_F(GridLayoutAlgorithmTest, GridLayoutAlgorithmResolveFixedTrackSizes) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid {
      width: 100px;
      height: 200px;
      display: grid;
      grid-template-columns: 25px repeat(3, 20px) minmax(15px, 10%);
      grid-template-rows: minmax(0px, 100px) 25% repeat(2, minmax(10%, 35px));
    }
    </style>
    <div id="grid"></div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  BuildGridItemsAndTrackCollections(algorithm);

  Vector<LayoutUnit> expected_column_base_sizes = {
      LayoutUnit(25), LayoutUnit(60), LayoutUnit(15)};
  Vector<LayoutUnit> expected_column_growth_limits = {
      LayoutUnit(25), LayoutUnit(60), LayoutUnit(15)};

  Vector<LayoutUnit> base_sizes = BaseSizes(kForColumns);
  EXPECT_EQ(expected_column_base_sizes.size(), base_sizes.size());
  for (wtf_size_t i = 0; i < base_sizes.size(); ++i)
    EXPECT_EQ(expected_column_base_sizes[i], base_sizes[i]);

  Vector<LayoutUnit> growth_limits = GrowthLimits(kForColumns);
  EXPECT_EQ(expected_column_growth_limits.size(), growth_limits.size());
  for (wtf_size_t i = 0; i < growth_limits.size(); ++i)
    EXPECT_EQ(expected_column_growth_limits[i], growth_limits[i]);

  Vector<LayoutUnit> expected_row_base_sizes = {LayoutUnit(80), LayoutUnit(50),
                                                LayoutUnit(70)};
  Vector<LayoutUnit> expected_row_growth_limits = {
      LayoutUnit(100), LayoutUnit(50), LayoutUnit(70)};

  base_sizes = BaseSizes(kForRows);
  EXPECT_EQ(expected_row_base_sizes.size(), base_sizes.size());
  for (wtf_size_t i = 0; i < base_sizes.size(); ++i)
    EXPECT_EQ(expected_row_base_sizes[i], base_sizes[i]);

  growth_limits = GrowthLimits(kForRows);
  EXPECT_EQ(expected_row_growth_limits.size(), growth_limits.size());
  for (wtf_size_t i = 0; i < growth_limits.size(); ++i)
    EXPECT_EQ(expected_row_growth_limits[i], growth_limits[i]);
}

TEST_F(GridLayoutAlgorithmTest,
       GridLayoutAlgorithmDetermineGridItemsSpanningIntrinsicOrFlexTracks) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #grid {
      display: grid;
      grid-template-columns: repeat(2, min-content 1fr 2px 3px);
      grid-template-rows: max-content 1fr 50px fit-content(100px);
    }
    #item0 {
      grid-column: 4 / 6;
      grid-row: -3 / -2;
    }
    #item1 {
      grid-column: 6 / 8;
      grid-row: -2 / -1;
    }
    #item2 {
      grid-column: 3 / 5;
      grid-row: -4 / -3;
    }
    #item3 {
      grid-column: 8 / 11;
      grid-row: -5 / -4;
    }
    </style>
    <div id="grid">
      <div id="item0"></div>
      <div id="item1"></div>
      <div id="item2"></div>
      <div id="item3"></div>
    </div>
  )HTML");

  BlockNode node(GetLayoutBoxByElementId("grid"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);

  GridLayoutAlgorithm algorithm({node, fragment_geometry, space});
  BuildGridItemsAndTrackCollections(algorithm);

  // Test grid items spanning intrinsic/flexible columns.
  Vector<wtf_size_t> expected_grid_items_spanning_intrinsic_track = {0, 1, 3};
  Vector<wtf_size_t> expected_grid_items_spanning_flex_track = {1};

  Vector<wtf_size_t> actual_items =
      GridItemsWithColumnSpanProperty(TrackSpanProperties::kHasIntrinsicTrack);
  EXPECT_EQ(expected_grid_items_spanning_intrinsic_track.size(),
            actual_items.size());
  for (wtf_size_t i = 0; i < actual_items.size(); ++i)
    EXPECT_EQ(expected_grid_items_spanning_intrinsic_track[i], actual_items[i]);

  actual_items =
      GridItemsWithColumnSpanProperty(TrackSpanProperties::kHasFlexibleTrack);
  EXPECT_EQ(expected_grid_items_spanning_flex_track.size(),
            actual_items.size());
  for (wtf_size_t i = 0; i < actual_items.size(); ++i)
    EXPECT_EQ(expected_grid_items_spanning_flex_track[i], actual_items[i]);

  // Test grid items spanning intrinsic/flexible rows.
  expected_grid_items_spanning_intrinsic_track = {1, 2, 3};
  expected_grid_items_spanning_flex_track = {2};

  actual_items =
      GridItemsWithRowSpanProperty(TrackSpanProperties::kHasIntrinsicTrack);
  EXPECT_EQ(expected_grid_items_spanning_intrinsic_track.size(),
            actual_items.size());
  for (wtf_size_t i = 0; i < actual_items.size(); ++i)
    EXPECT_EQ(expected_grid_items_spanning_intrinsic_track[i], actual_items[i]);

  actual_items =
      GridItemsWithRowSpanProperty(TrackSpanProperties::kHasFlexibleTrack);
  EXPECT_EQ(expected_grid_items_spanning_flex_track.size(),
            actual_items.size());
  for (wtf_size_t i = 0; i < actual_items.size(); ++i)
    EXPECT_EQ(expected_grid_items_spanning_flex_track[i], actual_items[i]);
}

TEST_F(GridLayoutAlgorithmTest, FixedSizePositioning) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        font: 10px/1 Ahem;
      }

      #grid {
        display: grid;
        width: 200px;
        height: 200px;
        grid-template-columns: 100px 100px;
        grid-template-rows: 100px 100px;
      }

      .grid_item {
        width: 100px;
        height: 100px;
        background-color: gray;
      }

    </style>
    <div id="wrapper">
      <div id="grid">
        <div class="grid_item">1</div>
        <div class="grid_item">2</div>
        <div class="grid_item">3</div>
        <div class="grid_item">4</div>
      </div>
    </div>
  )HTML");
  String dump = DumpFragmentTree(GetElementById("wrapper"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:200x200
      offset:0,0 size:100x100
        offset:0,0 size:10x10
      offset:100,0 size:100x100
        offset:0,0 size:10x10
      offset:0,100 size:100x100
        offset:0,0 size:10x10
      offset:100,100 size:100x100
        offset:0,0 size:10x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(GridLayoutAlgorithmTest, FixedSizePositioningAutoRows) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    body {
      font: 10px/1 Ahem;
    }

    #grid {
      display: grid;
      width: 200px;
      height: 200px;
      grid-auto-columns: 100px;
      grid-auto-rows: 100px;
    }

    .grid_item {
      width: 100px;
      height: 100px;
      background-color: gray;
    }

    .cell2 {
      width: 100px;
      height: 100px;
      grid-column: 2;
      background-color: gray;
    }

  </style>
  <div id="wrapper">
    <div id="grid">
      <div class="grid_item">1</div>
      <div class="cell2">2</div>
      <div class="grid_item">3</div>
      <div class="grid_item">4</div>
    </div>
  </div>

  )HTML");
  String dump = DumpFragmentTree(GetElementById("wrapper"));

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x200
    offset:0,0 size:200x200
      offset:0,0 size:100x100
        offset:0,0 size:10x10
      offset:100,0 size:100x100
        offset:0,0 size:10x10
      offset:0,100 size:100x100
        offset:0,0 size:10x10
      offset:100,100 size:100x100
        offset:0,0 size:10x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(GridLayoutAlgorithmTest, SpecifiedPositionsOutOfOrder) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        font: 10px/1 Ahem;
      }

      #grid {
        display: grid;
        width: 400px;
        height: 400px;
        grid-template-columns: 100px 100px;
        grid-template-rows: 100px 100px;
      }

      .grid_item1 {
        display: block;
        width: 100px;
        height: 100px;
        grid-row: 2;
        grid-column: 2;
      }

      .grid_item2
```