Response:
Let's break down the thought process for analyzing this code and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `FrameSetLayoutAlgorithm.cc` file in the Chromium Blink engine. Key aspects to identify are:

* **Primary Functionality:** What does this code *do*?
* **Relationship to Web Standards:** How does it relate to HTML, CSS, and JavaScript?
* **Logic and Algorithms:**  Are there specific steps or calculations being performed?  Can we provide examples?
* **Potential Errors:** What mistakes could developers or users make related to this code?

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code, paying attention to class names, function names, variable names, and comments. Keywords that stand out are:

* `FrameSetLayoutAlgorithm`:  The core class.
* `HTMLFrameSetElement`:  Indicates it deals with `<frameset>` tags.
* `LayoutAxis`:  Suggests handling the distribution of space along rows and columns.
* `LayoutChildren`, `LayoutChild`:  Implies arranging child elements (likely `<iframe>` or `<frame>`).
* `row_sizes`, `col_sizes`:  Store calculated dimensions.
* `fixed_indices`, `percent_indices`, `relative_indices`:  Relate to how row/column sizes are specified in HTML (`*, 100px, 50%`).
* `border_thickness`, `has_border_color`, `row_allow_border`, `col_allow_border`: Properties of the `<frameset>`.
* `LayoutUnit`: A Blink-specific type for layout dimensions.
* `MinMaxSizesResult`: Part of the layout process for determining element sizing.

**3. Deeper Dive into Key Functions:**

Next, analyze the purpose and logic of the most important functions:

* **`FrameSetLayoutAlgorithm::Layout()`:** This is the main entry point. It gathers information about the `<frameset>` element (borders, row/column definitions), calculates the sizes of rows and columns using `LayoutAxis`, lays out the children using `LayoutChildren`, and returns the layout result.

* **`FrameSetLayoutAlgorithm::LayoutAxis()`:**  This is crucial. The comments and code clearly show the step-by-step process of calculating row/column sizes based on fixed, percentage, and relative values. It also handles edge cases and adjustments for remaining space.

* **`FrameSetLayoutAlgorithm::LayoutChildren()`:**  Iterates through the child elements (`<frame>` or `<iframe>`), determines their position and size based on the pre-calculated row and column sizes, and calls `LayoutChild` for each.

* **`FrameSetLayoutAlgorithm::LayoutChild()`:**  Performs the actual layout of an individual child element, creating a new layout context for it.

* **`FrameSetLayoutAlgorithm::ComputeMinMaxSizes()`:**  Calculates the minimum and maximum sizes of the `<frameset>` element itself. The comment highlights a specific interaction with flexbox layout.

**4. Connecting to Web Standards:**

Now, link the code's functionality to HTML, CSS, and JavaScript:

* **HTML:**  The code directly manipulates information from the `<frameset>` element (rows, cols, border). It lays out `<frame>` and `<iframe>` elements, which are fundamental parts of HTML for creating separate browsing contexts within a single page.

* **CSS:** The code considers the `border` attribute of the `<frameset>` and uses the `Style()` object to access style information. While `<frameset>` has limited CSS styling, understanding its basic visual properties is important.

* **JavaScript:**  While this specific file doesn't directly execute JavaScript, the layout it produces affects how JavaScript interacts with the frames. For example, JavaScript might access content within a specific frame or manipulate the frameset's structure dynamically.

**5. Developing Examples and Scenarios:**

Based on the code analysis, construct concrete examples to illustrate the logic:

* **`LayoutAxis` Example:**  Create a simple `<frameset>` with different row/column definitions (`100px`, `*`, `50%`) and a specific available space to demonstrate how the algorithm calculates the actual sizes.

* **User/Programming Errors:** Think about common mistakes when using `<frameset>`:
    * Incorrect or conflicting row/col definitions.
    * Not accounting for borders.
    * Assuming `<frameset>` behaves like other layout models (it doesn't nest well).
    * Misunderstanding relative sizing (`*`).

**6. Structuring the Response:**

Organize the information logically:

* **Overall Function:** Start with a high-level summary.
* **Key Functions:** Detail the purpose and logic of the main functions.
* **Relationship to Web Technologies:** Explain the connections to HTML, CSS, and JavaScript with specific examples.
* **Logical Reasoning (with Examples):** Provide clear input/output scenarios for `LayoutAxis`.
* **Common Errors:** List and explain potential user/programming mistakes.

**7. Refinement and Review:**

Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too heavily on the pixel calculations in `LayoutAxis`. Reviewing the code prompted me to emphasize the *prioritization* of fixed, percentage, and relative sizing. Similarly, explicitly mentioning the historical nature and modern alternatives to `<frameset>` adds valuable context.

This iterative process of reading, analyzing, connecting, exemplifying, and refining leads to a comprehensive and accurate understanding of the code's functionality.
This C++ source code file, `frame_set_layout_algorithm.cc`, within the Chromium Blink rendering engine, is responsible for **laying out the content of an HTML `<frameset>` element**. The core function is to determine the size and position of the frames (represented by `<frame>` or `<iframe>` elements) contained within the `<frameset>`.

Here's a breakdown of its functionality:

**Core Function:**

* **Calculates Frame Dimensions:** The primary goal is to take the row and column definitions specified in the `<frameset>` element's `rows` and `cols` attributes (e.g., `"100,*,20%"`) and convert them into concrete pixel dimensions for each row and column.
* **Positions Child Frames:** Once the row and column dimensions are determined, it positions the child `<frame>` or `<iframe>` elements within the grid defined by the rows and columns.
* **Handles Borders:** It considers the `border` attribute of the `<frameset>` and the `frameborder` attributes of the individual frames when calculating layout.

**Relationship to Javascript, HTML, and CSS:**

* **HTML:** This code directly processes the structure and attributes of the `<frameset>` element and its children (`<frame>` or `<iframe>`). It reads the `rows` and `cols` attributes to understand how to divide the available space.
    * **Example:** If the HTML is `<frameset rows="50%,50%" cols="*,100"><frame src="a.html"><frame src="b.html"><frame src="c.html"></frameset>`, this code will parse the `"50%,50%"` and `"*,100"` to determine the height of the two rows and the width of the two columns.
* **CSS:** While `<frameset>` elements have limited CSS styling, this code does consider the `border` attribute (and potentially related border properties). It interacts with the `Style()` object to retrieve relevant style information.
    * **Example:** If the `<frameset>` has `border="5"`, this code will use that value to calculate the spacing between frames.
* **Javascript:** Although this C++ code doesn't directly execute JavaScript, the layout it produces directly affects how JavaScript within the frames operates. JavaScript running inside a frame will be bounded by the dimensions calculated by this algorithm. JavaScript can also dynamically manipulate the `rows` and `cols` attributes of the `<frameset>`, triggering a re-layout by this code.

**Logical Reasoning (with Assumptions):**

Let's focus on the `LayoutAxis` function, which is responsible for calculating the sizes of rows or columns.

**Assumption:** We have a `<frameset>` element with `cols="100,*,20%"` and an available width of 500 pixels.

**Input:**

* `count`: 3 (number of columns)
* `grid`: A vector of `HTMLDimension` objects representing "100", "*", and "20%".
* `deltas`:  Typically a vector of zeros in the initial layout. This is used for adjustments, which we'll ignore for simplicity.
* `available_length`: 500 pixels.

**Step-by-step Reasoning within `LayoutAxis`:**

1. **Categorize Dimensions:**
   - "100" is absolute (fixed).
   - "*" is relative.
   - "20%" is percentage.

2. **Calculate Fixed Sizes:**
   - The first column has a fixed size of 100 pixels. `sizes[0] = 100`.
   - `total_fixed = 100`.

3. **Calculate Percentage Sizes:**
   - The third column has a percentage size of 20% of the available width: `0.20 * 500 = 100` pixels. `sizes[2] = 100`.
   - `total_percent = 100`.

4. **Calculate Remaining Space:**
   - `remaining_length = 500 - total_fixed - total_percent = 500 - 100 - 100 = 300` pixels.

5. **Calculate Relative Sizes:**
   - The second column has a relative size of "*", which is treated as 1 unit.
   - `total_relative = 1`.
   - The size of the relative column is the remaining space divided by the total relative units: `300 / 1 = 300` pixels. `sizes[1] = 300`.

**Output:**

* `sizes`: A vector of `LayoutUnit` objects representing the calculated column widths: `[100, 300, 100]`.

**Another Example (Handling Insufficient Space for Fixed Columns):**

**Assumption:** `<frameset cols="300,400">` with an available width of 500 pixels.

**Input:**

* `count`: 2
* `grid`: ["300", "400"]
* `available_length`: 500

**Reasoning:**

1. **Fixed Sizes:** Initial calculation: `sizes[0] = 300`, `sizes[1] = 400`. `total_fixed = 700`.
2. **Insufficient Space:** `total_fixed` (700) is greater than `available_length` (500).
3. **Proportional Adjustment:** The code will proportionally reduce the sizes of the fixed columns based on the remaining space.
   - `remaining_fixed = 500`.
   - `sizes[0] = AdjustSizeToRemainingSize(300, 500, 700) = floor(300 * 500 / 700) = 214`.
   - `remaining_length` becomes `500 - 214 = 286`.
   - `sizes[1] = AdjustSizeToRemainingSize(400, 286, 700) = floor(400 * 286 / 700) = 163`.

**Output:**

* `sizes`: `[214, 163]` (approximately, due to integer rounding).

**User or Programming Common Usage Errors:**

1. **Incorrect Syntax in `rows` or `cols`:**
   - **Error:**  Providing invalid dimension values like `"100px, %, 20"` (missing unit for the last value).
   - **Consequence:** The layout might not be as expected, with the browser potentially ignoring or interpreting the invalid values in a default way.

2. **Over-specifying Dimensions Leading to Overflow:**
   - **Error:** Setting fixed or percentage sizes that, when combined, exceed the available space, without considering borders.
   - **Example:** `<frameset cols="50%, 60%">` within a viewport that isn't wide enough.
   - **Consequence:** The browser will need to adjust the sizes, potentially leading to unexpected shrinking or scrollbars. The `LayoutAxis` function tries to handle this proportionally, but the intent might be lost.

3. **Misunderstanding Relative Sizing (`*`)**:
   - **Error:** Assuming `*` allocates a fixed amount of space.
   - **Example:**  `<frameset cols="100,*">`. Users might think the second column always gets a large amount of space, but it only gets the *remaining* space after the fixed-size columns.
   - **Consequence:** Layout that doesn't adapt as expected to different viewport sizes.

4. **Not Accounting for Borders:**
   - **Error:** Defining frame sizes that completely fill the available space without considering the `border` attribute of the `<frameset>` or `frameborder` of individual frames.
   - **Example:** `<frameset border="10" cols="50%,50%">`. The two columns will each get 50% of the available width *minus* the space occupied by the border.
   - **Consequence:** Overlapping frames or unexpected scrollbars.

5. **Dynamic Manipulation of `rows` and `cols` with JavaScript leading to unexpected behavior:**
   - **Error:**  Changing the `rows` or `cols` attributes via JavaScript without fully understanding the layout recalculation process.
   - **Example:**  Setting `frameset.cols = "*,*"` when there were previously fixed-size columns.
   - **Consequence:**  The layout might jump or change unexpectedly, potentially breaking the user interface.

In summary, `frame_set_layout_algorithm.cc` is a crucial piece of the Blink rendering engine responsible for the fundamental task of laying out HTML framesets. It parses dimension specifications, calculates concrete sizes, and positions child frames, taking into account various factors like fixed, percentage, and relative sizing, as well as border considerations. Understanding its logic is essential for web developers working with framesets (though framesets are less common in modern web development).

### 提示词
```
这是目录为blink/renderer/core/layout/frame_set_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/frame_set_layout_algorithm.h"

#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/frame_set_layout_data.h"

namespace blink {

namespace {

// This function never produces fractional values.
// LayoutUnit(int) produces fractional values if the argument is greater
// than LayoutUnit::kIntMax or smaller than LayoutUnit::kIntMin.
// FrameSetLayoutAlgorithm always requires integers.
LayoutUnit IntLayoutUnit(double value) {
  if (value >= LayoutUnit::kIntMax) {
    return LayoutUnit(LayoutUnit::kIntMax);
  }
  if (value <= LayoutUnit::kIntMin) {
    return LayoutUnit(LayoutUnit::kIntMin);
  }
  return LayoutUnit(floor(value));
}

// Adjusts proportionally the size with remaining size.
LayoutUnit AdjustSizeToRemainingSize(LayoutUnit current,
                                     LayoutUnit remaining,
                                     int64_t total) {
  // Performs the math operations step by step to avoid the overflow.
  base::CheckedNumeric<int64_t> temp_product = current.ToInt();
  temp_product *= remaining.ToInt();
  temp_product /= total;
  return LayoutUnit(base::checked_cast<int>(temp_product.ValueOrDie()));
}

}  // namespace

FrameSetLayoutAlgorithm::FrameSetLayoutAlgorithm(
    const LayoutAlgorithmParams& params)
    : LayoutAlgorithm<BlockNode, BoxFragmentBuilder, BlockBreakToken>(params) {}

const LayoutResult* FrameSetLayoutAlgorithm::Layout() {
  auto& frame_set = *To<HTMLFrameSetElement>(Node().GetDOMNode());
  auto layout_data = std::make_unique<FrameSetLayoutData>();
  layout_data->border_thickness = frame_set.Border(Style());
  layout_data->has_border_color = frame_set.HasBorderColor();
  layout_data->row_allow_border = frame_set.AllowBorderRows();
  layout_data->col_allow_border = frame_set.AllowBorderColumns();

  PhysicalSize size = ToPhysicalSize(container_builder_.Size(),
                                     GetConstraintSpace().GetWritingMode());
  const wtf_size_t row_count = frame_set.TotalRows();
  layout_data->row_sizes =
      LayoutAxis(row_count, frame_set.RowLengths(), frame_set.RowDeltas(),
                 size.height - (row_count - 1) * layout_data->border_thickness);
  const wtf_size_t col_count = frame_set.TotalCols();
  layout_data->col_sizes =
      LayoutAxis(col_count, frame_set.ColLengths(), frame_set.ColDeltas(),
                 size.width - (col_count - 1) * layout_data->border_thickness);

  LayoutChildren(*layout_data);

  container_builder_.TransferFrameSetLayoutData(std::move(layout_data));
  return container_builder_.ToBoxFragment();
}

MinMaxSizesResult FrameSetLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  MinMaxSizes sizes;
  const auto& space = GetConstraintSpace();
  // This function needs to return a value which is >= border+padding in order
  // to pass a DCHECK in FlexLayoutAlgorithm::ConstructAndAppendFlexItems()
  // though <frameset> ignores border and padding.
  //
  // We can't use BorderPadding() here because FragmentGeometry for <frameset>
  // doesn't provide it.
  //
  // Test: external/wpt/css/css-flexbox/frameset-crash.html
  sizes += (ComputeBorders(space, Node()) + ComputePadding(space, Style()))
               .InlineSum();
  return MinMaxSizesResult(sizes, false);
}

// https://html.spec.whatwg.org/C/#convert-a-list-of-dimensions-to-a-list-of-pixel-values
Vector<LayoutUnit> FrameSetLayoutAlgorithm::LayoutAxis(
    wtf_size_t count,
    const Vector<HTMLDimension>& grid,
    const Vector<int>& deltas,
    LayoutUnit available_length) {
  DCHECK_GT(count, 0u);
  DCHECK_EQ(count, deltas.size());
  available_length = LayoutUnit(available_length.ToInt()).ClampNegativeToZero();
  Vector<LayoutUnit> sizes(count);

  if (grid.empty()) {
    sizes[0] = available_length;
    return sizes;
  }

  // First we need to investigate how many columns of each type we have and
  // how much space these columns are going to require.

  Vector<wtf_size_t, 4> fixed_indices;
  Vector<wtf_size_t, 4> percent_indices;
  Vector<wtf_size_t, 4> relative_indices;
  for (wtf_size_t i = 0; i < count; ++i) {
    if (grid[i].IsAbsolute())
      fixed_indices.push_back(i);
    else if (grid[i].IsPercentage())
      percent_indices.push_back(i);
    else if (grid[i].IsRelative())
      relative_indices.push_back(i);
  }

  int64_t total_relative = 0;
  int64_t total_fixed = 0;
  int64_t total_percent = 0;

  const float effective_zoom = Node().Style().EffectiveZoom();

  // Count the total length of all of the fixed columns/rows.
  for (auto i : fixed_indices) {
    sizes[i] =
        IntLayoutUnit(grid[i].Value() * effective_zoom).ClampNegativeToZero();
    DCHECK(sizes[i].IsInteger());
    total_fixed += sizes[i].ToInt();
  }

  // Count the total percentage of all of the percentage columns/rows.
  for (auto i : percent_indices) {
    sizes[i] = IntLayoutUnit(grid[i].Value() * available_length / 100.0)
                   .ClampNegativeToZero();
    DCHECK(sizes[i].IsInteger()) << sizes[i];
    total_percent += sizes[i].ToInt();
  }

  // Count the total relative of all the relative columns/rows.
  for (auto i : relative_indices)
    total_relative += ClampTo<int>(std::max(grid[i].Value(), 1.0));

  LayoutUnit remaining_length = available_length;

  // Fixed columns/rows are our first priority. If there is not enough space to
  // fit all fixed columns/rows we need to proportionally adjust their size.
  if (total_fixed > remaining_length.ToInt()) {
    LayoutUnit remaining_fixed = remaining_length;
    for (auto i : fixed_indices) {
      sizes[i] =
          AdjustSizeToRemainingSize(sizes[i], remaining_fixed, total_fixed);
      remaining_length -= sizes[i];
    }
  } else {
    remaining_length -= total_fixed;
  }

  // Percentage columns/rows are our second priority. Divide the remaining space
  // proportionally over all percentage columns/rows.
  // NOTE: the size of each column/row is not relative to 100%, but to the total
  // percentage. For example, if there are three columns, each of 75%, and the
  // available space is 300px, each column will become 100px in width.
  if (total_percent > remaining_length.ToInt()) {
    LayoutUnit remaining_percent = remaining_length;
    for (auto i : percent_indices) {
      sizes[i] =
          AdjustSizeToRemainingSize(sizes[i], remaining_percent, total_percent);
      remaining_length -= sizes[i];
    }
  } else {
    remaining_length -= total_percent;
  }

  // Relative columns/rows are our last priority. Divide the remaining space
  // proportionally over all relative columns/rows.
  // NOTE: the relative value of 0* is treated as 1*.
  if (!relative_indices.empty()) {
    wtf_size_t last_relative_index = WTF::kNotFound;
    int64_t remaining_relative = remaining_length.ToInt();
    for (auto i : relative_indices) {
      sizes[i] = IntLayoutUnit(
          (ClampTo<int>(std::max(grid[i].Value(), 1.)) * remaining_relative) /
          total_relative);
      remaining_length -= sizes[i];
      last_relative_index = i;
    }

    // If we could not evenly distribute the available space of all of the
    // relative columns/rows, the remainder will be added to the last column/
    // row. For example: if we have a space of 100px and three columns (*,*,*),
    // the remainder will be 1px and will be added to the last column: 33px,
    // 33px, 34px.
    if (remaining_length) {
      sizes[last_relative_index] += remaining_length;
      remaining_length = LayoutUnit();
    }
  }

  // If we still have some left over space we need to divide it over the already
  // existing columns/rows
  if (remaining_length) {
    // Our first priority is to spread if over the percentage columns. The
    // remaining space is spread evenly, for example: if we have a space of
    // 100px, the columns definition of 25%,25% used to result in two columns of
    // 25px. After this the columns will each be 50px in width.
    if (!percent_indices.empty() && total_percent) {
      LayoutUnit remaining_percent = remaining_length;
      for (auto i : percent_indices) {
        LayoutUnit change_percent = AdjustSizeToRemainingSize(
            sizes[i], remaining_percent, total_percent);
        sizes[i] += change_percent;
        remaining_length -= change_percent;
      }
    } else if (total_fixed) {
      // Our last priority is to spread the remaining space over the fixed
      // columns. For example if we have 100px of space and two column of each
      // 40px, both columns will become exactly 50px.
      LayoutUnit remaining_fixed = remaining_length;
      for (auto i : fixed_indices) {
        LayoutUnit change_fixed =
            AdjustSizeToRemainingSize(sizes[i], remaining_fixed, total_fixed);
        sizes[i] += change_fixed;
        remaining_length -= change_fixed;
      }
    }
  }

  // If we still have some left over space we probably ended up with a remainder
  // of a division. We cannot spread it evenly anymore. If we have any
  // percentage columns/rows simply spread the remainder equally over all
  // available percentage columns, regardless of their size.
  if (remaining_length && !percent_indices.empty()) {
    LayoutUnit remaining_percent = remaining_length;
    for (auto i : percent_indices) {
      int change_percent = (remaining_percent / percent_indices.size()).ToInt();
      sizes[i] += change_percent;
      remaining_length -= change_percent;
    }
  } else if (remaining_length && !fixed_indices.empty()) {
    // If we don't have any percentage columns/rows we only have fixed columns.
    // Spread the remainder equally over all fixed columns/rows.
    LayoutUnit remaining_fixed = remaining_length;
    for (auto i : fixed_indices) {
      int change_fixed = (remaining_fixed / fixed_indices.size()).ToInt();
      sizes[i] += change_fixed;
      remaining_length -= change_fixed;
    }
  }

  // Still some left over. Add it to the last column, because it is impossible
  // spread it evenly or equally.
  if (remaining_length)
    sizes[count - 1] += remaining_length;

  // Now we have the final layout, distribute the delta over it.
  bool worked = true;
  for (wtf_size_t i = 0; i < count; ++i) {
    if (sizes[i] && sizes[i] + deltas[i] <= 0)
      worked = false;
    sizes[i] += deltas[i];
  }
  // If the deltas broke something, undo them.
  if (!worked) {
    for (wtf_size_t i = 0; i < count; ++i)
      sizes[i] -= deltas[i];
  }

  return sizes;
}

void FrameSetLayoutAlgorithm::LayoutChildren(
    const FrameSetLayoutData& layout_data) {
  PhysicalOffset position;
  LayoutInputNode child = Node().FirstChild();
  if (!child)
    return;
  for (wtf_size_t row = 0; row < layout_data.row_sizes.size(); ++row) {
    position.left = LayoutUnit();
    const LayoutUnit row_size = layout_data.row_sizes[row];
    for (wtf_size_t col = 0; col < layout_data.col_sizes.size(); ++col) {
      const LayoutUnit col_size = layout_data.col_sizes[col];
      const LogicalSize available_size(
          Style().GetWritingDirection().IsHorizontal()
              ? LogicalSize(col_size, row_size)
              : LogicalSize(row_size, col_size));
      LayoutChild(child, available_size, position,
                  PhysicalSize(col_size, row_size));
      child = child.NextSibling();
      if (!child)
        return;
      position.left += col_size + layout_data.border_thickness;
    }
    position.top += row_size + layout_data.border_thickness;
  }
  // We have more children than what's defined by the frameset's grid. We want
  // those to generate fragments as well, so that LayoutBox traversal code can
  // generally assume that each box has at least one fragment. Give them zero
  // size and they'll show up nowhere.
  while (child) {
    LayoutChild(child, /* available_size */ LogicalSize(),
                /* position */ PhysicalOffset(),
                /* child_size */ PhysicalSize());
    child = child.NextSibling();
  }
}

void FrameSetLayoutAlgorithm::LayoutChild(const LayoutInputNode& child,
                                          LogicalSize available_size,
                                          PhysicalOffset position,
                                          PhysicalSize child_size) {
  const PhysicalSize frameset_size = ToPhysicalSize(
      container_builder_.Size(), GetConstraintSpace().GetWritingMode());
  const auto container_direction = Style().GetWritingDirection();
  const bool kNewFormattingContext = true;
  ConstraintSpaceBuilder space_builder(container_direction.GetWritingMode(),
                                       child.Style().GetWritingDirection(),
                                       kNewFormattingContext);
  space_builder.SetAvailableSize(available_size);
  space_builder.SetIsFixedInlineSize(true);
  space_builder.SetIsFixedBlockSize(true);
  const LayoutResult* result =
      To<BlockNode>(child).Layout(space_builder.ToConstraintSpace());
  container_builder_.AddResult(
      *result, position.ConvertToLogical(container_direction, frameset_size,
                                         child_size));
}

}  // namespace blink
```