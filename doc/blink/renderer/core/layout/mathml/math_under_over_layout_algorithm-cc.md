Response:
Let's break down the thought process for analyzing the provided C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze the `MathUnderOverLayoutAlgorithm.cc` file and explain its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning, and highlight potential usage errors.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for prominent keywords and patterns:

* **`MathUnderOverLayoutAlgorithm`:** This immediately tells us the file deals with the layout of math elements, specifically those with "under" and "over" scripts (like limits in mathematical expressions).
* **`MathMLUnderOverElement`:** Confirms the focus on MathML elements.
* **`Layout()`:** This is a crucial function in the Blink rendering engine, responsible for calculating the position and size of elements.
* **`GatherChildren()`:**  Indicates a process of identifying the base, overscript, and underscript components within the MathML structure.
* **`UnderOverVerticalParameters`:**  Suggests parameters controlling the vertical positioning of the under/over scripts.
* **`OpenTypeMathSupport`:** Points to the use of font metrics from the OpenType MATH table for precise layout.
* **`ComputedStyle`:** Implies the influence of CSS styling on the layout process.
* **`LogicalBoxFragment`, `PhysicalBoxFragment`:** These are fundamental layout building blocks in Blink, representing the dimensions and position of elements.
* **`accent_under`, `accent` attributes:**  Relates to how accents are handled in the layout.
* **`MinMaxSizesResult`, `ComputeMinMaxSizes()`:** Deals with calculating the minimum and maximum possible sizes of the element, important for layout constraints.

**3. Deciphering the Core Functionality (the `Layout()` function):**

The `Layout()` function is the heart of the algorithm. Here's a breakdown of how to approach understanding it:

* **Identify the Inputs:**  It doesn't explicitly take arguments beyond the class context, but it operates on the `Node()` (the MathML element being laid out) and uses information from `ComputedStyle`.
* **Trace the Steps:** Go through the code sequentially, understanding what each part does:
    * **Gathering Children:**  The `GatherChildren()` function separates the base, over, and under elements.
    * **Determining Parameters:** `GetUnderOverVerticalParameters()` fetches or calculates vertical spacing parameters based on the base element's properties (large operator, stretchy). This is where OpenType MATH table information comes in.
    * **Handling Inline Stretching:** The code has a section dealing with "stretchy" operators and how their width is determined. This is important for things like large summation symbols.
    * **Creating Constraint Spaces:** `CreateConstraintSpaceForUnderOverChild()` prepares layout constraints for each child element, considering potential stretching.
    * **Laying out the Base:** The base element is laid out first.
    * **Laying out Over/Under Scripts:** The overscript and underscript are laid out and positioned relative to the base, using the calculated parameters. Note the logic for handling accents and different spacing rules.
    * **Calculating Baselines and Sizes:**  The code calculates the ascent, descent, and overall block size of the element.
    * **Building the Layout Fragment:** `container_builder_` is used to assemble the layout fragments for the base and scripts.

**4. Identifying Relationships with Web Technologies:**

* **HTML:** The code directly deals with `MathMLUnderOverElement`, which originates from HTML's `<munderover>`, `<munder>`, and `<mover>` tags. *Example:* The code lays out the content of `<munderover><mo>∑</mo><mrow>n=1}</mrow><mrow>\infty</mrow></munderover>`.
* **CSS:** `ComputedStyle` is used extensively to get font information and potentially other style properties (though the example focuses on font metrics). CSS can affect the spacing, size, and even the font used, which directly impacts the calculations in this code. *Example:* CSS could set `font-size` which would affect the values retrieved from the OpenType MATH table or fallback values.
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript *within this file*, JavaScript code running in the browser can manipulate the DOM, adding, removing, or modifying MathML elements. This would trigger the layout process, including this algorithm. *Example:* A JavaScript library dynamically generating MathML equations.

**5. Logical Reasoning and Examples:**

The core logical reasoning is the step-by-step calculation of positions based on parameters and the dimensions of the constituent elements.

* **Assumptions:**  Assume a base element and an overscript element are present.
* **Input:** The layout dimensions of the base and overscript (after their individual layouts). The `UnderOverVerticalParameters`.
* **Output:** The vertical offset of the overscript relative to the base, ensuring proper spacing (`over_gap_min`) and potentially accounting for accents.

**6. Identifying Potential Usage Errors:**

These errors typically arise from incorrect usage of the underlying web technologies:

* **Malformed MathML:**  If the HTML structure doesn't conform to MathML standards (e.g., missing elements, incorrect nesting), the `GatherChildren()` function might not work as expected, leading to incorrect layout.
* **Missing Fonts:** If the required font (with the OpenType MATH table) is not available, the code falls back to default values. This might result in a less accurate or aesthetically pleasing layout.
* **Conflicting CSS:** While not directly an error *in the code*, conflicting CSS rules could indirectly affect the layout. For example, setting very large margins on the child elements could lead to unexpected spacing.

**7. Structuring the Answer:**

Finally, organize the findings into clear sections, as demonstrated in the provided good answer. Use headings and bullet points to make the information easy to read and understand. Provide specific examples to illustrate the connections to HTML, CSS, and JavaScript.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the `Layout()` function.
* **Correction:** Realize that `GatherChildren()` and `GetUnderOverVerticalParameters()` are crucial supporting functions that need explanation.
* **Initial thought:**  Only consider direct interaction with JavaScript.
* **Correction:**  Broaden the scope to include how JavaScript DOM manipulation can trigger this layout algorithm.
* **Initial thought:**  Overlook the importance of OpenType MATH table data.
* **Correction:** Emphasize the role of `OpenTypeMathSupport` and the fallback mechanisms.

By following these steps, combining code analysis with an understanding of the underlying web technologies, and considering potential errors, you can arrive at a comprehensive and accurate explanation of the C++ code's functionality.
好的，让我们来详细分析一下 `blink/renderer/core/layout/mathml/math_under_over_layout_algorithm.cc` 这个文件。

**文件功能概述**

这个 C++ 文件实现了 Blink 渲染引擎中用于布局 MathML 中带有上标和下标（或者上划线和下划线）元素的算法。这些元素主要是指 `<munder>`, `<mover>` 和 `<munderover>`。

简单来说，它的主要功能是：

1. **识别和分离子元素:**  确定基准元素（base）、上标/上划线元素（over）和下标/下划线元素（under）。
2. **获取布局参数:**  根据元素的样式（`ComputedStyle`）以及基准元素的一些特性（例如是否为大型运算符、是否可以沿内联轴拉伸），从 OpenType MATH 表中获取或计算出用于布局的各种垂直间距和偏移参数。
3. **布局子元素:**  分别对基准元素、上标/上划线元素和下标/下划线元素进行布局计算。
4. **定位子元素:**  根据计算出的参数，将上标/上划线元素放置在基准元素的上方，下标/下划线元素放置在基准元素的下方。会考虑对齐、间距以及是否带有重音符号等因素。
5. **计算整体尺寸:**  计算包含所有子元素的 MathML 容器的整体尺寸（宽度和高度），并设置基线位置。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个 C++ 文件虽然是用 C++ 编写的，但它直接服务于 Web 技术中的 MathML，因此与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **HTML:**
    * **功能关系:** 该算法处理的是在 HTML 中使用 MathML 标签创建的数学公式。具体来说，它负责布局像 `<munder>`, `<mover>`, `<munderover>` 这样的标签。
    * **举例说明:**  当浏览器解析到如下 HTML 代码时，这个 C++ 文件中的算法就会被调用来渲染这个公式：
      ```html
      <math>
        <munderover>
          <mo>∑</mo> <mrow> <mi>n</mi><mo>=</mo><mn>1</mn> </mrow> <mi>∞</mi> </munderover>
      </math>
      ```
      在这个例子中，`<mo>∑</mo>` 是基准元素，`<mrow> <mi>n</mo><mo>=</mo><mn>1</mn> </mrow>` 是下标元素，`<mi>∞</mi>` 是上标元素。该算法会计算它们各自的位置和整体公式的布局。

* **CSS:**
    * **功能关系:** CSS 样式会影响 MathML 元素的渲染。这个算法会读取元素的 `ComputedStyle` 来获取字体大小、行高、以及可能影响布局的其他 CSS 属性。
    * **举例说明:**  如果通过 CSS 设置了 MathML 元素的 `font-size`，例如：
      ```css
      math {
        font-size: 20px;
      }
      ```
      那么 `GetUnderOverVerticalParameters` 函数会使用这个字体大小来从 OpenType MATH 表中查找相应的布局参数。如果没有 OpenType MATH 表，则会使用回退值，而回退值的计算可能也会受到字体大小的影响。

* **JavaScript:**
    * **功能关系:** JavaScript 可以动态地创建、修改 HTML 结构，包括 MathML 元素。当 JavaScript 操作 MathML 中带有上标和下标的元素时，会导致浏览器的重新布局，从而触发该算法的执行。
    * **举例说明:**  以下 JavaScript 代码动态地创建了一个带有下标的 MathML 元素，并将其添加到文档中：
      ```javascript
      const mathElement = document.createElement('math');
      const munderElement = document.createElement('munder');
      const miElement = document.createElement('mi');
      miElement.textContent = 'lim';
      const mrowElement = document.createElement('mrow');
      const miElement2 = document.createElement('mi');
      miElement2.textContent = 'n';
      const moElement = document.createElement('mo');
      moElement.textContent = '→';
      const miElement3 = document.createElement('mi');
      miElement3.textContent = '∞';
      mrowElement.appendChild(miElement2);
      mrowElement.appendChild(moElement);
      mrowElement.appendChild(miElement3);
      munderElement.appendChild(miElement);
      munderElement.appendChild(mrowElement);
      mathElement.appendChild(munderElement);
      document.body.appendChild(mathElement);
      ```
      当这段代码执行时，浏览器会调用 `MathUnderOverLayoutAlgorithm` 来正确地放置 "n → ∞" 在 "lim" 的下方。

**逻辑推理的假设输入与输出**

假设输入一个简单的带有下标的 MathML 结构：

**假设输入:**

* **MathML 结构:**
  ```xml
  <math>
    <munder>
      <mi>x</mi>
      <mn>0</mn>
    </munder>
  </math>
  ```
* **CSS 样式 (部分):** 假设字体大小为默认值，没有额外的 CSS 样式影响布局。
* **OpenType MATH 表数据:**  假设字体中存在 OpenType MATH 表，并且包含 `kUnderbarVerticalGap` 等相关常量的值。

**逻辑推理过程 (简化):**

1. **`GatherChildren`:**  识别出基准元素 `<mi>x</mi>` 和下标元素 `<mn>0</mn>`.
2. **`GetUnderOverVerticalParameters`:**  由于是简单的下标，且基准元素不是大型运算符，将获取适用于一般情况的垂直参数，例如 `under_gap_min` (下标与基准元素的最小间距)。假设从 OpenType MATH 表中获取的 `kUnderbarVerticalGap` 的值为 2px。
3. **基准元素布局:** 先布局 `<mi>x</mi>`，假设其高度为 10px，基线位置在其顶部。
4. **下标元素布局:** 再布局 `<mn>0</mn>`，假设其高度为 8px，基线位置在其顶部。
5. **定位下标元素:**
   * 计算下标元素的垂直偏移量。根据 `parameters.under_gap_min` (2px) 和可能的其他因素（例如 `under_shift_min`），计算出下标元素顶部相对于基准元素基线的垂直距离。
   * 如果 `use_under_over_bar_fallback` 为 true (通常是这种情况对于简单的下划线)，则偏移量可能主要由 `under_gap_min` 决定。
   * 假设计算出的下标元素顶部的偏移量为 12px (基准元素基线以下 2px 的间距 + 下标元素自身的高度)。
6. **计算整体尺寸:**  计算包含基准元素和下标元素的整体高度。高度将是基准元素的基线到最高点的距离加上基准元素的基线到最低点的距离。下标会增加整体的高度。

**假设输出:**

* **下标元素的位置:** 相对于基准元素的偏移量，使其位于基准元素下方一定的距离。
* **整体容器的高度:**  大约为 基准元素高度 + 间距 + 下标元素高度 (可能需要考虑基线位置)。例如，可能是 10px (基准) + 2px (间距) + 8px (下标) = 20px。
* **基线位置:**  通常与基准元素的基线一致，或者根据具体的布局规则进行调整。

**用户或编程常见的使用错误举例说明**

1. **MathML 结构错误:**
   * **错误示例:**  在 `<munder>` 或 `<munderover>` 中缺少必要的子元素，或者子元素的顺序不正确。例如：
     ```html
     <math>
       <munder> <mi>x</mi> </munder>  <!-- 缺少下标元素 -->
     </math>
     ```
   * **后果:**  该算法可能无法正确识别基准元素和上标/下标元素，导致布局错误或渲染失败。

2. **字体缺失或不支持 MathML:**
   * **错误示例:**  使用的字体没有 OpenType MATH 表，或者浏览器不支持 MathML 渲染。
   * **后果:**  该算法会回退到默认的布局参数，可能导致公式的显示效果不佳，间距不合适，或者符号错位。

3. **CSS 样式冲突或不当使用:**
   * **错误示例:**  使用 CSS 强制设置了 MathML 元素的 `line-height` 或其他影响行盒模型的属性，导致与算法的计算结果冲突。
   * **后果:**  可能导致上标和下标的位置与预期不符，出现重叠或者间距过大的情况。

4. **动态修改 MathML 导致频繁重绘:**
   * **错误示例:**  使用 JavaScript 频繁地修改包含复杂上标和下标的 MathML 结构，例如在动画中动态更新公式。
   * **后果:**  每次修改都会触发布局计算，可能会导致性能问题和页面卡顿。应该尽量优化 MathML 的动态更新方式。

5. **假设所有字体都一致支持 MathML:**
   * **错误示例:**  开发者假设用户的所有字体都完美支持 MathML 的所有特性，包括 OpenType MATH 表。
   * **后果:**  在某些用户环境下，由于字体不支持，公式的显示效果可能与开发者预期不符。应该考虑提供备用字体或者进行兼容性处理。

总而言之，`MathUnderOverLayoutAlgorithm.cc` 是 Blink 渲染引擎中一个关键的组成部分，它负责精确地布局 MathML 中带有上标和下标的复杂结构，确保数学公式能够在网页上正确且美观地呈现。理解其功能和与 Web 技术的关系，有助于开发者更好地使用和调试 MathML。

### 提示词
```
这是目录为blink/renderer/core/layout/mathml/math_under_over_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/mathml/math_under_over_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/mathml/math_layout_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/mathml/mathml_operator_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_under_over_element.h"

namespace blink {
namespace {

// Describes the amount to shift to apply to the under/over boxes.
// Data is populated from the OpenType MATH table.
// If the OpenType MATH table is not present fallback values are used.
// https://w3c.github.io/mathml-core/#base-with-underscript
// https://w3c.github.io/mathml-core/#base-with-overscript
struct UnderOverVerticalParameters {
  bool use_under_over_bar_fallback;
  LayoutUnit under_gap_min;
  LayoutUnit over_gap_min;
  LayoutUnit under_shift_min;
  LayoutUnit over_shift_min;
  LayoutUnit under_extra_descender;
  LayoutUnit over_extra_ascender;
  LayoutUnit accent_base_height;
};

UnderOverVerticalParameters GetUnderOverVerticalParameters(
    const ComputedStyle& style,
    bool is_base_large_operator,
    bool is_base_stretchy_in_inline_axis) {
  UnderOverVerticalParameters parameters;
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  if (!font_data)
    return parameters;

  // https://w3c.github.io/mathml-core/#dfn-default-fallback-constant
  const float default_fallback_constant = 0;

  if (is_base_large_operator) {
    parameters.under_gap_min = LayoutUnit(
        MathConstant(style,
                     OpenTypeMathSupport::MathConstants::kLowerLimitGapMin)
            .value_or(default_fallback_constant));
    parameters.over_gap_min = LayoutUnit(
        MathConstant(style,
                     OpenTypeMathSupport::MathConstants::kUpperLimitGapMin)
            .value_or(default_fallback_constant));
    parameters.under_shift_min = LayoutUnit(
        MathConstant(
            style,
            OpenTypeMathSupport::MathConstants::kLowerLimitBaselineDropMin)
            .value_or(default_fallback_constant));
    parameters.over_shift_min = LayoutUnit(
        MathConstant(
            style,
            OpenTypeMathSupport::MathConstants::kUpperLimitBaselineRiseMin)
            .value_or(default_fallback_constant));
    parameters.under_extra_descender = LayoutUnit();
    parameters.over_extra_ascender = LayoutUnit();
    parameters.accent_base_height = LayoutUnit();
    parameters.use_under_over_bar_fallback = false;
    return parameters;
  }

  if (is_base_stretchy_in_inline_axis) {
    parameters.under_gap_min = LayoutUnit(
        MathConstant(
            style, OpenTypeMathSupport::MathConstants::kStretchStackGapBelowMin)
            .value_or(default_fallback_constant));
    parameters.over_gap_min = LayoutUnit(
        MathConstant(
            style, OpenTypeMathSupport::MathConstants::kStretchStackGapAboveMin)
            .value_or(default_fallback_constant));
    parameters.under_shift_min = LayoutUnit(
        MathConstant(
            style,
            OpenTypeMathSupport::MathConstants::kStretchStackBottomShiftDown)
            .value_or(default_fallback_constant));
    parameters.over_shift_min = LayoutUnit(
        MathConstant(
            style, OpenTypeMathSupport::MathConstants::kStretchStackTopShiftUp)
            .value_or(default_fallback_constant));
    parameters.under_extra_descender = LayoutUnit();
    parameters.over_extra_ascender = LayoutUnit();
    parameters.accent_base_height = LayoutUnit();
    parameters.use_under_over_bar_fallback = false;
    return parameters;
  }

  const float default_rule_thickness = RuleThicknessFallback(style);
  parameters.under_gap_min = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kUnderbarVerticalGap)
          .value_or(3 * default_rule_thickness));
  parameters.over_gap_min = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kOverbarVerticalGap)
          .value_or(3 * default_rule_thickness));
  parameters.under_shift_min = LayoutUnit();
  parameters.over_shift_min = LayoutUnit();
  parameters.under_extra_descender = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kUnderbarExtraDescender)
          .value_or(default_rule_thickness));
  parameters.over_extra_ascender = LayoutUnit(
      MathConstant(style,
                   OpenTypeMathSupport::MathConstants::kOverbarExtraAscender)
          .value_or(default_rule_thickness));
  parameters.accent_base_height = LayoutUnit(
      MathConstant(style, OpenTypeMathSupport::MathConstants::kAccentBaseHeight)
          .value_or(font_data->GetFontMetrics().XHeight() / 2));
  parameters.use_under_over_bar_fallback = true;
  return parameters;
}

// https://w3c.github.io/mathml-core/#underscripts-and-overscripts-munder-mover-munderover
bool HasAccent(const BlockNode& node, bool accent_under) {
  DCHECK(node);
  auto* underover = To<MathMLUnderOverElement>(node.GetDOMNode());
  auto script_type = underover->GetScriptType();
  DCHECK(script_type == MathScriptType::kUnderOver ||
         (accent_under && script_type == MathScriptType::kUnder) ||
         (!accent_under && script_type == MathScriptType::kOver));

  std::optional<bool> attribute_value =
      accent_under ? underover->AccentUnder() : underover->Accent();
  return attribute_value && *attribute_value;
}

}  // namespace

MathUnderOverLayoutAlgorithm::MathUnderOverLayoutAlgorithm(
    const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params) {
  DCHECK(params.space.IsNewFormattingContext());
}

void MathUnderOverLayoutAlgorithm::GatherChildren(BlockNode* base,
                                                  BlockNode* over,
                                                  BlockNode* under) {
  auto script_type = Node().ScriptType();
  for (LayoutInputNode child = Node().FirstChild(); child;
       child = child.NextSibling()) {
    BlockNode block_child = To<BlockNode>(child);
    if (child.IsOutOfFlowPositioned()) {
      container_builder_.AddOutOfFlowChildCandidate(
          block_child, BorderScrollbarPadding().StartOffset());
      continue;
    }
    if (!*base) {
      *base = block_child;
      continue;
    }
    switch (script_type) {
      case MathScriptType::kUnder:
        DCHECK(!*under);
        *under = block_child;
        break;
      case MathScriptType::kOver:
        DCHECK(!*over);
        *over = block_child;
        break;
      case MathScriptType::kUnderOver:
        if (!*under) {
          *under = block_child;
          continue;
        }
        DCHECK(!*over);
        *over = block_child;
        break;
      default:
        NOTREACHED();
    }
  }
}

const LayoutResult* MathUnderOverLayoutAlgorithm::Layout() {
  DCHECK(!GetBreakToken());
  DCHECK(IsValidMathMLScript(Node()));

  BlockNode base = nullptr;
  BlockNode over = nullptr;
  BlockNode under = nullptr;
  GatherChildren(&base, &over, &under);

  const LogicalSize border_box_size = container_builder_.InitialBorderBoxSize();

  const LogicalOffset content_start_offset =
      BorderScrollbarPadding().StartOffset();

  LayoutUnit ascent;
  LayoutUnit descent;

  const auto base_properties = GetMathMLEmbellishedOperatorProperties(base);
  const bool is_base_large_operator =
      base_properties && base_properties->is_large_op;
  const bool is_base_stretchy_in_inline_axis = base_properties &&
                                               base_properties->is_stretchy &&
                                               !base_properties->is_vertical;
  const auto& constraint_space = GetConstraintSpace();
  const bool base_inherits_block_stretch_size_constraint =
      constraint_space.TargetStretchBlockSizes().has_value();
  const bool base_inherits_inline_stretch_size_constraint =
      !base_inherits_block_stretch_size_constraint &&
      constraint_space.HasTargetStretchInlineSize();
  UnderOverVerticalParameters parameters = GetUnderOverVerticalParameters(
      Style(), is_base_large_operator, is_base_stretchy_in_inline_axis);

  // https://w3c.github.io/mathml-core/#dfn-algorithm-for-stretching-operators-along-the-inline-axis
  LayoutUnit inline_stretch_size;
  auto UpdateInlineStretchSize = [&](const LayoutResult* result) {
    LogicalFragment fragment(
        constraint_space.GetWritingDirection(),
        To<PhysicalBoxFragment>(result->GetPhysicalFragment()));
    inline_stretch_size = std::max(inline_stretch_size, fragment.InlineSize());
  };

  // "Perform layout without any stretch size constraint on all the items of
  // LNotToStretch"
  bool layout_remaining_items_with_zero_inline_stretch_size = true;
  for (LayoutInputNode child = Node().FirstChild(); child;
       child = child.NextSibling()) {
    if (child.IsOutOfFlowPositioned() ||
        IsInlineAxisStretchyOperator(To<BlockNode>(child))) {
      continue;
    }
    const auto child_constraint_space = CreateConstraintSpaceForMathChild(
        Node(), ChildAvailableSize(), constraint_space, child,
        LayoutResultCacheSlot::kMeasure);
    const auto* child_layout_result = To<BlockNode>(child).Layout(
        child_constraint_space, nullptr /* break_token */);
    UpdateInlineStretchSize(child_layout_result);
    layout_remaining_items_with_zero_inline_stretch_size = false;
  }

  if (layout_remaining_items_with_zero_inline_stretch_size) [[unlikely]] {
    // "If LNotToStretch is empty, perform layout with stretch size constraint 0
    // on all the items of LToStretch.
    for (LayoutInputNode child = Node().FirstChild(); child;
         child = child.NextSibling()) {
      if (child.IsOutOfFlowPositioned())
        continue;
      DCHECK(IsInlineAxisStretchyOperator(To<BlockNode>(child)));
      if (child == base && (base_inherits_block_stretch_size_constraint ||
                            base_inherits_inline_stretch_size_constraint))
        continue;
      LayoutUnit zero_stretch_size;
      const auto child_constraint_space = CreateConstraintSpaceForMathChild(
          Node(), ChildAvailableSize(), constraint_space, child,
          LayoutResultCacheSlot::kMeasure, std::nullopt, zero_stretch_size);
      const auto* child_layout_result = To<BlockNode>(child).Layout(
          child_constraint_space, nullptr /* break_token */);
      UpdateInlineStretchSize(child_layout_result);
    }
  }

  auto CreateConstraintSpaceForUnderOverChild = [&](const BlockNode child) {
    if (child == base && base_inherits_block_stretch_size_constraint &&
        IsBlockAxisStretchyOperator(To<BlockNode>(child))) {
      return CreateConstraintSpaceForMathChild(
          Node(), ChildAvailableSize(), constraint_space, child,
          LayoutResultCacheSlot::kLayout,
          *constraint_space.TargetStretchBlockSizes());
    }
    if (child == base && base_inherits_inline_stretch_size_constraint &&
        IsInlineAxisStretchyOperator(To<BlockNode>(child))) {
      return CreateConstraintSpaceForMathChild(
          Node(), ChildAvailableSize(), constraint_space, child,
          LayoutResultCacheSlot::kLayout, std::nullopt,
          constraint_space.TargetStretchInlineSize());
    }
    if ((child != base || (!base_inherits_block_stretch_size_constraint &&
                           !base_inherits_inline_stretch_size_constraint)) &&
        IsInlineAxisStretchyOperator(To<BlockNode>(child))) {
      return CreateConstraintSpaceForMathChild(
          Node(), ChildAvailableSize(), constraint_space, child,
          LayoutResultCacheSlot::kLayout, std::nullopt, inline_stretch_size);
    }
    return CreateConstraintSpaceForMathChild(Node(), ChildAvailableSize(),
                                             constraint_space, child,
                                             LayoutResultCacheSlot::kLayout);
  };

  // TODO(crbug.com/1125136): take into account italic correction.

  const auto baseline_type = Style().GetFontBaseline();
  const auto base_space = CreateConstraintSpaceForUnderOverChild(base);
  auto* base_layout_result = base.Layout(base_space);
  auto base_margins =
      ComputeMarginsFor(base_space, base.Style(), constraint_space);

  LogicalBoxFragment base_fragment(
      constraint_space.GetWritingDirection(),
      To<PhysicalBoxFragment>(base_layout_result->GetPhysicalFragment()));
  LayoutUnit base_ascent =
      base_fragment.FirstBaselineOrSynthesize(baseline_type);

  // All children are positioned centered relative to the container (and
  // therefore centered relative to themselves).
  if (over) {
    const auto over_space = CreateConstraintSpaceForUnderOverChild(over);
    const LayoutResult* over_layout_result = over.Layout(over_space);
    BoxStrut over_margins =
        ComputeMarginsFor(over_space, over.Style(), constraint_space);
    LogicalBoxFragment over_fragment(
        constraint_space.GetWritingDirection(),
        To<PhysicalBoxFragment>(over_layout_result->GetPhysicalFragment()));
    ascent += parameters.over_extra_ascender + over_margins.block_start;
    LogicalOffset over_offset = {
        content_start_offset.inline_offset + over_margins.inline_start +
            (ChildAvailableSize().inline_size -
             (over_fragment.InlineSize() + over_margins.InlineSum())) /
                2,
        BorderScrollbarPadding().block_start + ascent};
    container_builder_.AddResult(*over_layout_result, over_offset,
                                 over_margins);
    if (parameters.use_under_over_bar_fallback) {
      ascent += over_fragment.BlockSize();
      if (HasAccent(Node(), false)) {
        if (base_ascent < parameters.accent_base_height)
          ascent += parameters.accent_base_height - base_ascent;
      } else {
        ascent += parameters.over_gap_min;
      }
    } else {
      LayoutUnit over_ascent =
          over_fragment.FirstBaselineOrSynthesize(baseline_type);
      ascent += std::max(over_fragment.BlockSize() + parameters.over_gap_min,
                         over_ascent + parameters.over_shift_min);
    }
    ascent += over_margins.block_end;
  }

  ascent += base_margins.block_start;
  LogicalOffset base_offset = {
      content_start_offset.inline_offset + base_margins.inline_start +
          (ChildAvailableSize().inline_size -
           (base_fragment.InlineSize() + base_margins.InlineSum())) /
              2,
      BorderScrollbarPadding().block_start + ascent};
  container_builder_.AddResult(*base_layout_result, base_offset, base_margins);
  ascent += base_ascent;
  ascent = ascent.ClampNegativeToZero();
  ascent += BorderScrollbarPadding().block_start;
  descent = base_fragment.BlockSize() - base_ascent + base_margins.block_end;

  if (under) {
    const auto under_space = CreateConstraintSpaceForUnderOverChild(under);
    const LayoutResult* under_layout_result = under.Layout(under_space);
    BoxStrut under_margins =
        ComputeMarginsFor(under_space, under.Style(), constraint_space);
    LogicalBoxFragment under_fragment(
        constraint_space.GetWritingDirection(),
        To<PhysicalBoxFragment>(under_layout_result->GetPhysicalFragment()));
    descent += under_margins.block_start;
    if (parameters.use_under_over_bar_fallback) {
      if (!HasAccent(Node(), true))
        descent += parameters.under_gap_min;
    } else {
      LayoutUnit under_ascent =
          under_fragment.FirstBaselineOrSynthesize(baseline_type);
      descent += std::max(parameters.under_gap_min,
                          parameters.under_shift_min - under_ascent);
    }
    LogicalOffset under_offset = {
        content_start_offset.inline_offset + under_margins.inline_start +
            (ChildAvailableSize().inline_size -
             (under_fragment.InlineSize() + under_margins.InlineSum())) /
                2,
        ascent + descent};
    descent += under_fragment.BlockSize();
    descent += parameters.under_extra_descender;
    container_builder_.AddResult(*under_layout_result, under_offset,
                                 under_margins);
    descent += under_margins.block_end;
  }

  container_builder_.SetBaselines(ascent);
  descent = descent.ClampNegativeToZero();
  descent += BorderScrollbarPadding().block_end;

  LayoutUnit intrinsic_block_size = ascent + descent;
  LayoutUnit block_size = ComputeBlockSizeForFragment(
      constraint_space, Node(), BorderPadding(), intrinsic_block_size,
      border_box_size.inline_size);

  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size);
  container_builder_.SetFragmentsTotalBlockSize(block_size);

  container_builder_.HandleOofsAndSpecialDescendants();

  return container_builder_.ToBoxFragment();
}

MinMaxSizesResult MathUnderOverLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  DCHECK(IsValidMathMLScript(Node()));

  if (auto result = CalculateMinMaxSizesIgnoringChildren(
          Node(), BorderScrollbarPadding()))
    return *result;

  MinMaxSizes sizes;
  bool depends_on_block_constraints = false;

  for (LayoutInputNode child = Node().FirstChild(); child;
       child = child.NextSibling()) {
    if (child.IsOutOfFlowPositioned())
      continue;
    // TODO(crbug.com/1125136): take into account italic correction.
    const auto child_result = ComputeMinAndMaxContentContributionForMathChild(
        Style(), GetConstraintSpace(), To<BlockNode>(child),
        ChildAvailableSize().block_size);

    sizes.Encompass(child_result.sizes);
    depends_on_block_constraints |= child_result.depends_on_block_constraints;
  }

  sizes += BorderScrollbarPadding().InlineSum();
  return MinMaxSizesResult(sizes, depends_on_block_constraints);
}

}  // namespace blink
```