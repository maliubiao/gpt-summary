Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code snippet for the `block_node.cc` file in the Chromium Blink rendering engine and describe its functionality, relating it to web technologies (HTML, CSS, JavaScript) where possible, and provide examples, logical inferences, and potential usage errors. The request specifies this is Part 1 of 3, implying a need for a high-level summary in this part.

2. **Identify Key Components:**  I start by scanning the `#include` directives. These immediately tell me the core areas the file touches:
    * **Layout:** The presence of numerous files related to different layout algorithms (`BlockLayoutAlgorithm`, `FlexLayoutAlgorithm`, `GridLayoutAlgorithm`, etc.) strongly suggests this file is central to the layout process.
    * **DOM:**  Includes like `dom/column_pseudo_element.h`, `html/forms/...`, and `mathml/...` indicate interaction with the Document Object Model.
    * **CSS:**  `css/style_engine.h` shows a dependency on CSS styling.
    * **Frame:** `frame/local_frame_view.h` and `frame/web_feature.h` suggest involvement with the browser frame structure.
    * **Paint:**  `paint/paint_layer.h` implies connections to the painting stage of rendering.

3. **Focus on the Class Name:** The file name `block_node.cc` and the code starting with `namespace blink { ... const LayoutResult* BlockNode::Layout(...)` clearly indicate the primary subject is the `BlockNode` class and its `Layout` method. This method seems to be the core function.

4. **Analyze the `Layout` Method:** I examine the steps within the `Layout` method:
    * **Cache Handling:** The code checks for cached layout results (`box_->GetCachedLayoutResult`, `box_->CachedLayoutResult`). This is a performance optimization.
    * **Layout Algorithm Selection:** The code uses a series of `if-else if` statements and a `DetermineAlgorithmAndRun` function to choose the appropriate layout algorithm based on the element's type and CSS properties (flex, grid, table, etc.). This is a crucial responsibility.
    * **Fragment Geometry:** Calculation of `fragment_geometry` suggests the code deals with breaking content into fragments (e.g., for pagination or multi-column layouts).
    * **Simplified Layout:** The presence of `SimplifiedLayout` indicates an optimized layout path for minor changes.
    * **Scrollbar Handling:** The code explicitly addresses scrollbar computation and potential relayouts due to scrollbar changes.
    * **Shape Outside:** `UpdateShapeOutsideInfoIfNeeded` points to support for CSS shapes.

5. **Infer Functionality based on Includes and Method Logic:** Based on the components and the `Layout` method's steps, I can infer the following functionalities:
    * **Orchestrates layout:** The `BlockNode::Layout` method seems to be a central point for initiating the layout process for block-level elements.
    * **Selects layout algorithms:** It dynamically chooses the right algorithm based on the element's properties.
    * **Manages layout caching:** It utilizes a cache to avoid redundant layout calculations.
    * **Handles fragmentation:** It deals with breaking content into fragments.
    * **Optimizes layout:** It implements a "simplified layout" path for efficiency.
    * **Accounts for scrollbars:** It considers scrollbars' impact on layout.
    * **Supports CSS features:** It integrates with features like Flexbox, Grid, Tables, MathML, and CSS Shapes.

6. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The code interacts with HTML elements (e.g., `HTMLInputElement`, `HTMLSelectElement`, `HTMLMarqueeElement`) to determine their layout. The structure of the HTML document (DOM) directly influences how `BlockNode` instances are created and how layout is performed.
    * **CSS:**  CSS properties (e.g., `display`, `width`, `height`, `flex`, `grid`, `shape-outside`, `overflow`) are the primary drivers for selecting layout algorithms and determining element dimensions. The `ComputedStyle` object is heavily used.
    * **JavaScript:** While this specific file doesn't directly execute JavaScript, the layout process it manages is triggered by events and actions within the browser that are often initiated or manipulated by JavaScript. For example, dynamically adding or removing elements via JavaScript will require recalculating layout. JavaScript can also influence CSS properties through DOM manipulation, indirectly affecting the layout.

7. **Provide Examples (Hypothetical Inputs and Outputs):**  To illustrate the logic, I consider a simple scenario: a `<div>` element with some text.
    * **Input:** A `BlockNode` representing a `<div>` element, with CSS `width: 100px;`.
    * **Output:** The `Layout` method would calculate the position and dimensions of the `<div>` and its content within its parent container. This includes determining line breaks for the text if it exceeds the width.

8. **Consider Common User/Programming Errors:** I think about mistakes developers might make that would interact with this layout code. Examples include:
    * **Incorrect CSS:** Setting conflicting or impossible CSS properties can lead to unexpected layout results.
    * **JavaScript layout thrashing:**  Repeatedly modifying styles and forcing layout calculations in a loop can cause performance issues.

9. **Summarize Functionality (Part 1):** Finally, I synthesize the information gathered into a concise summary for Part 1, focusing on the core responsibilities of the `block_node.cc` file, especially the `BlockNode::Layout` method and its role in orchestrating layout for block-level elements in Blink.

**(Self-Correction/Refinement):** Initially, I might have focused too narrowly on just the layout algorithms themselves. However, reviewing the includes and the `Layout` method's code reveals the importance of cache management, fragmentation, and interaction with the DOM and CSS. Therefore, I broaden my analysis to include these aspects. I also make sure to explicitly connect the functionality to HTML, CSS, and JavaScript to answer that part of the prompt. I ensure the examples and error cases are concrete and relevant to web development.
好的，让我们来分析一下 `blink/renderer/core/layout/block_node.cc` 文件的功能。

**功能归纳：**

`block_node.cc` 文件是 Chromium Blink 引擎中负责处理块级盒模型（block-level box）布局的核心代码。它定义了 `BlockNode` 类，该类负责：

1. **协调和执行块级元素的布局过程:** `BlockNode::Layout` 方法是该文件的核心，它接收布局约束（`ConstraintSpace`）和其他布局相关的参数，并负责 orchestrating 块级元素的布局。
2. **选择合适的布局算法:**  根据元素的 CSS 属性（例如 `display: flex`, `display: grid`, `display: table` 等）以及元素类型（例如 `<input>`, `<select>`, `<math>`),  `BlockNode::Layout` 方法会动态地选择并调用相应的布局算法（例如 `FlexLayoutAlgorithm`, `GridLayoutAlgorithm`, `TableLayoutAlgorithm` 等）。
3. **处理布局缓存:** 为了提高性能，`BlockNode` 会尝试使用布局缓存 (`box_->GetCachedLayoutResult`) 来避免重复计算。
4. **处理分片 (Fragmentation):** 该文件涉及到处理内容如何跨越分片边界（例如分页、多列布局），并使用 `BlockBreakToken` 等机制来管理分片。
5. **支持多种 CSS 特性:**  代码中包含了对 Flexbox, Grid Layout, Multi-column Layout, Table Layout, MathML 等多种 CSS 布局特性的支持。
6. **管理和更新布局结果:**  `BlockNode` 负责创建和存储布局结果 (`LayoutResult`)，其中包含了元素的位置、尺寸等信息。
7. **处理滚动条:** 代码会考虑滚动条的存在，并在滚动条出现或消失时触发重新布局。
8. **支持 CSS Shapes (Shape Outside):**  文件中包含 `UpdateShapeOutsideInfoIfNeeded`，表明对 CSS Shapes 的支持。
9. **支持容器查询 (Container Queries):** 代码中包含对容器查询的支持 (`CanMatchSizeContainerQueries`, `UpdateStyleAndLayoutTreeForContainer`)。
10. **支持 MathML 布局:**  文件中包含多个 MathML 相关的布局算法，表明对 MathML 元素布局的支持。
11. **支持表单元素布局:**  文件中包含了对 `<input>`, `<select>` 等表单元素的特殊布局处理。
12. **支持伪元素布局:** 文件中涉及到对一些伪元素（例如 `::scroll-marker`, `::column`) 的布局处理。
13. **进行性能优化:** 例如，使用 "simplified layout" (`RunSimplifiedLayout`) 来优化小改动的布局。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `BlockNode` 负责布局 HTML 元素。例如：
    * 当浏览器解析到 `<div>` 标签时，会创建一个对应的 `BlockNode` 对象来处理该 `div` 的布局。
    * 对于 `<input type="text">` 元素，`BlockNode` 会选择合适的算法来布局这个输入框，包括其边框、内边距等。
    * 对于 `<table>` 元素，`BlockNode` 会调用 `TableLayoutAlgorithm` 来处理表格的布局，包括计算列宽、行高等。

* **CSS:** CSS 样式是 `BlockNode` 进行布局决策的关键输入。例如：
    * 如果 CSS 中设置了 `display: flex;`，`BlockNode` 会选择 `FlexLayoutAlgorithm` 来进行布局。
    * `width`, `height`, `margin`, `padding` 等 CSS 属性会直接影响 `BlockNode` 计算出的元素尺寸和位置。
    * CSS 的 `float` 属性会影响 `BlockNode` 如何布局周围的内容。
    * CSS 的多列属性 (`column-count`, `column-width`) 会触发 `ColumnLayoutAlgorithm`。
    * CSS 的 `shape-outside` 属性会影响 `UpdateShapeOutsideInfoIfNeeded` 的执行。

* **JavaScript:** JavaScript 通常不直接操作 `BlockNode` 对象，但 JavaScript 的操作会间接地影响 `BlockNode` 的行为。例如：
    * 当 JavaScript 修改了元素的 CSS 样式（例如通过 `element.style.width = '200px';`），会导致浏览器重新计算布局，并可能触发 `BlockNode` 的重新布局。
    * JavaScript 动态地添加或删除 DOM 元素也会触发布局的重新计算，相关的 `BlockNode` 对象会参与到新的布局过程中。
    * JavaScript 可以通过 `getBoundingClientRect()` 等方法获取元素的布局信息，这些信息是由 `BlockNode` 计算得出的。

**逻辑推理与假设输入/输出：**

假设有以下 HTML 和 CSS：

```html
<div id="container" style="width: 200px; display: flex;">
  <div id="item1" style="width: 50px;">Item 1</div>
  <div id="item2" style="width: 80px;">Item 2</div>
</div>
```

**假设输入:**  `BlockNode::Layout` 方法接收到一个代表 `#container` 元素的 `BlockNode` 对象，以及相关的 `ConstraintSpace` 信息（例如父容器的可用宽度）。

**逻辑推理:**

1. 由于 `#container` 的 CSS 样式中设置了 `display: flex;`，`BlockNode::Layout` 方法会选择 `FlexLayoutAlgorithm`。
2. `FlexLayoutAlgorithm` 会根据 flex 容器的属性（例如 `flex-direction`, `justify-content`, `align-items`，这里是默认值）以及 flex 项目的属性（例如 `width`）来计算子元素的布局。
3. `#item1` 的宽度被设置为 50px，`#item2` 的宽度被设置为 80px。
4. `FlexLayoutAlgorithm` 会将 `#item1` 和 `#item2` 水平排列在 `#container` 中。

**假设输出:** `BlockNode::Layout` 方法会生成一个 `LayoutResult` 对象，其中包含：

* `#container` 的宽度为 200px，高度根据内容确定。
* `#item1` 的位置可能为 `(0, 0)`，宽度为 50px，高度根据内容确定。
* `#item2` 的位置可能为 `(50, 0)`，宽度为 80px，高度根据内容确定。

**用户或编程常见的使用错误举例：**

1. **CSS 属性冲突导致意外布局:**  例如，同时设置了 `position: absolute` 和 `float: left`，可能会导致布局行为不符合预期，`BlockNode` 会按照 CSS 规范的优先级来处理。
2. **JavaScript 频繁修改样式导致性能问题:**  如果 JavaScript 代码在一个循环中频繁修改元素的样式，每次修改都可能触发 `BlockNode` 的重新布局，导致性能下降（布局抖动 - Layout Thrashing）。
3. **不理解不同 `display` 值的布局特性:**  错误地认为 `display: block` 的元素可以像 `display: flex` 的元素那样使用 flexbox 属性进行布局，这会导致布局失效。
4. **忘记考虑盒模型:**  在计算元素尺寸时，如果没有正确考虑 `box-sizing` 属性，可能会导致实际渲染的尺寸与预期不符，`BlockNode` 的计算会遵循设定的盒模型。
5. **在 JavaScript 中直接修改布局相关属性但没有触发重新布局:** 虽然 `BlockNode` 不直接暴露给 JavaScript，但如果开发者通过 JavaScript 修改了一些可能影响布局的属性，但浏览器由于某些原因没有立即进行重新布局，可能会导致视觉上的不一致。

**总结 `block_node.cc` 的功能 (针对第 1 部分):**

`block_node.cc` 的主要功能是定义了 `BlockNode` 类，它是 Blink 渲染引擎中处理块级元素布局的核心组件。它负责协调布局过程，选择合适的布局算法（如 Flexbox, Grid, Table 等），并利用布局缓存来优化性能。该文件是连接 HTML 结构和 CSS 样式的关键桥梁，决定了块级元素在页面上的最终呈现方式。它涉及到处理各种复杂的布局场景，包括分片、滚动条、CSS Shapes 和容器查询等特性。

Prompt: 
```
这是目录为blink/renderer/core/layout/block_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/block_node.h"

#include <memory>

#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_button_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_marquee_element.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/column_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/custom/layout_custom.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/flex/flex_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/forms/fieldset_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/forms/layout_fieldset.h"
#include "third_party/blink/renderer/core/layout/fragment_repeater.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/frame_set_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/geometry/fragment_geometry.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_input_node.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_set.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_utils.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/masonry/masonry_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_fraction_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_layout_utils.h"
#include "third_party/blink/renderer/core/layout/mathml/math_operator_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_padded_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_radical_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_row_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_scripts_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_space_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_token_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/mathml/math_under_over_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/min_max_sizes.h"
#include "third_party/blink/renderer/core/layout/paginated_root_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/replaced_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"
#include "third_party/blink/renderer/core/layout/simplified_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/table/table_row_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/table/table_section_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_fraction_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_padded_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_radical_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_scripts_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_space_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_token_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_under_over_element.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/transform_utils.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

inline bool HasInlineChildren(LayoutBlockFlow* block_flow) {
  auto* child = GetLayoutObjectForFirstChildNode(block_flow);
  return child && AreNGBlockFlowChildrenInline(block_flow);
}

inline LayoutMultiColumnFlowThread* GetFlowThread(
    const LayoutBlockFlow* block_flow) {
  if (!block_flow)
    return nullptr;
  return block_flow->MultiColumnFlowThread();
}

inline LayoutMultiColumnFlowThread* GetFlowThread(const LayoutBox& box) {
  return GetFlowThread(DynamicTo<LayoutBlockFlow>(box));
}

// The entire purpose of this function is to avoid allocating space on the stack
// for all layout algorithms for each node we lay out. Therefore it must not be
// inline.
template <typename Algorithm, typename Callback>
NOINLINE void CreateAlgorithmAndRun(const LayoutAlgorithmParams& params,
                                    const Callback& callback) {
  Algorithm algorithm(params);
  callback(&algorithm);
}

template <typename Callback>
NOINLINE void DetermineMathMLAlgorithmAndRun(
    const LayoutBox& box,
    const LayoutAlgorithmParams& params,
    const Callback& callback) {
  DCHECK(box.IsMathML());
  // Currently math layout algorithms can only apply to MathML elements.
  auto* element = box.GetNode();
  if (element) {
    if (IsA<MathMLSpaceElement>(element)) {
      CreateAlgorithmAndRun<MathSpaceLayoutAlgorithm>(params, callback);
      return;
    } else if (IsA<MathMLFractionElement>(element) &&
               IsValidMathMLFraction(params.node)) {
      CreateAlgorithmAndRun<MathFractionLayoutAlgorithm>(params, callback);
      return;
    } else if (IsA<MathMLRadicalElement>(element) &&
               IsValidMathMLRadical(params.node)) {
      CreateAlgorithmAndRun<MathRadicalLayoutAlgorithm>(params, callback);
      return;
    } else if (IsA<MathMLPaddedElement>(element)) {
      CreateAlgorithmAndRun<MathPaddedLayoutAlgorithm>(params, callback);
      return;
    } else if (IsA<MathMLTokenElement>(element)) {
      if (IsOperatorWithSpecialShaping(params.node))
        CreateAlgorithmAndRun<MathOperatorLayoutAlgorithm>(params, callback);
      else if (IsTextOnlyToken(params.node))
        CreateAlgorithmAndRun<MathTokenLayoutAlgorithm>(params, callback);
      else
        CreateAlgorithmAndRun<BlockLayoutAlgorithm>(params, callback);
      return;
    } else if (IsA<MathMLScriptsElement>(element) &&
               IsValidMathMLScript(params.node)) {
      if (IsA<MathMLUnderOverElement>(element) &&
          !IsUnderOverLaidOutAsSubSup(params.node)) {
        CreateAlgorithmAndRun<MathUnderOverLayoutAlgorithm>(params, callback);
      } else {
        CreateAlgorithmAndRun<MathScriptsLayoutAlgorithm>(params, callback);
      }
      return;
    }
  }
  CreateAlgorithmAndRun<MathRowLayoutAlgorithm>(params, callback);
}

template <typename Callback>
NOINLINE void DetermineAlgorithmAndRun(const LayoutAlgorithmParams& params,
                                       const Callback& callback) {
  const ComputedStyle& style = params.node.Style();
  const LayoutBox& box = *params.node.GetLayoutBox();
  if (box.IsFlexibleBox()) {
    CreateAlgorithmAndRun<FlexLayoutAlgorithm>(params, callback);
  } else if (box.IsTable()) {
    CreateAlgorithmAndRun<TableLayoutAlgorithm>(params, callback);
  } else if (box.IsTableRow()) {
    CreateAlgorithmAndRun<TableRowLayoutAlgorithm>(params, callback);
  } else if (box.IsTableSection()) {
    CreateAlgorithmAndRun<TableSectionLayoutAlgorithm>(params, callback);
  } else if (box.IsLayoutCustom()) {
    CreateAlgorithmAndRun<CustomLayoutAlgorithm>(params, callback);
  } else if (box.IsMathML()) {
    DetermineMathMLAlgorithmAndRun(box, params, callback);
  } else if (box.IsLayoutGrid()) {
    CreateAlgorithmAndRun<GridLayoutAlgorithm>(params, callback);
  } else if (box.IsLayoutMasonry()) {
    CreateAlgorithmAndRun<MasonryLayoutAlgorithm>(params, callback);
  } else if (box.IsLayoutReplaced()) {
    CreateAlgorithmAndRun<ReplacedLayoutAlgorithm>(params, callback);
  } else if (box.IsFieldset()) {
    CreateAlgorithmAndRun<FieldsetLayoutAlgorithm>(params, callback);
  } else if (box.IsFrameSet()) {
    CreateAlgorithmAndRun<FrameSetLayoutAlgorithm>(params, callback);
  }
  // If there's a legacy layout box, we can only do block fragmentation if
  // we would have done block fragmentation with the legacy engine.
  // Otherwise writing data back into the legacy tree will fail. Look for
  // the flow thread.
  else if (GetFlowThread(box) && style.SpecifiesColumns()) {
    CreateAlgorithmAndRun<ColumnLayoutAlgorithm>(params, callback);
  } else if (!box.Parent() && params.node.IsPaginatedRoot()) [[unlikely]] {
    CreateAlgorithmAndRun<PaginatedRootLayoutAlgorithm>(params, callback);
  } else {
    CreateAlgorithmAndRun<BlockLayoutAlgorithm>(params, callback);
  }
}

inline const LayoutResult* LayoutWithAlgorithm(
    const LayoutAlgorithmParams& params) {
  const LayoutResult* result = nullptr;
  DetermineAlgorithmAndRun(params,
                           [&result]<typename Algorithm>(Algorithm* algorithm) {
                             result = algorithm->Layout();
                           });
  return result;
}

inline MinMaxSizesResult ComputeMinMaxSizesWithAlgorithm(
    const LayoutAlgorithmParams& params,
    const MinMaxSizesFloatInput& float_input) {
  MinMaxSizesResult result;
  DetermineAlgorithmAndRun(params, [&result, &float_input]<typename Algorithm>(
                                       Algorithm* algorithm) {
    result = algorithm->ComputeMinMaxSizes(float_input);
  });
  return result;
}

bool CanUseCachedIntrinsicInlineSizes(const ConstraintSpace& constraint_space,
                                      const MinMaxSizesFloatInput& float_input,
                                      const BlockNode& node) {
  // Obviously can't use the cache if our intrinsic logical widths are dirty.
  if (node.GetLayoutBox()->IntrinsicLogicalWidthsDirty())
    return false;

  // We don't store the float inline sizes for comparison, always skip the
  // cache in this case.
  if (float_input.float_left_inline_size || float_input.float_right_inline_size)
    return false;

  // Check if we have any percentage padding.
  const auto& style = node.Style();
  if (style.MayHavePadding() &&
      (style.PaddingTop().HasPercent() || style.PaddingRight().HasPercent() ||
       style.PaddingBottom().HasPercent() ||
       style.PaddingLeft().HasPercent())) {
    return false;
  }

  if (node.IsTableCell() && To<LayoutTableCell>(node.GetLayoutBox())
                                    ->IntrinsicLogicalWidthsBorderSizes() !=
                                constraint_space.TableCellBorders()) {
    return false;
  }

  // We may have something like:
  // "grid-template-columns: repeat(auto-fill, 50px); min-width: 50%;"
  // In this specific case our min/max sizes are now dependent on what
  // "min-width" resolves to - which is unique to grid.
  if (node.IsGrid()) {
    if (style.LogicalMinWidth().HasPercentOrStretch() ||
        style.LogicalMaxWidth().HasPercentOrStretch()) {
      return false;
    }
    // Also consider transferred min/max sizes.
    if (node.HasAspectRatio() &&
        (style.LogicalMinHeight().HasPercentOrStretch() ||
         style.LogicalMaxHeight().HasPercentOrStretch())) {
      return false;
    }
  }

  return true;
}

std::optional<LayoutUnit> ContentMinimumInlineSize(
    const BlockNode& block_node,
    const BoxStrut& border_padding) {
  // Table layout is never allowed to go below the min-intrinsic size.
  if (block_node.IsTable())
    return std::nullopt;

  const auto* node = block_node.GetDOMNode();
  const auto* marquee_element = DynamicTo<HTMLMarqueeElement>(node);
  if (marquee_element && marquee_element->IsHorizontal())
    return border_padding.InlineSum();

  const auto& style = block_node.Style();
  const auto& main_inline_size = style.LogicalWidth();

  if (!main_inline_size.HasPercent()) {
    return std::nullopt;
  }

  // Manually resolve the main-length against zero. calc() expressions may
  // resolve to something greater than "zero".
  LayoutUnit inline_size =
      MinimumValueForLength(main_inline_size, LayoutUnit());
  if (style.BoxSizing() == EBoxSizing::kBorderBox)
    inline_size = std::max(border_padding.InlineSum(), inline_size);
  else
    inline_size += border_padding.InlineSum();

  const bool apply_form_sizing = style.ApplyControlFixedSize(node);
  if (block_node.IsTextControl() && apply_form_sizing) {
    return inline_size;
  }
  if (IsA<HTMLSelectElement>(node) && apply_form_sizing) {
    return inline_size;
  }
  if (const auto* input_element = DynamicTo<HTMLInputElement>(node)) {
    FormControlType type = input_element->FormControlType();
    if (type == FormControlType::kInputFile && apply_form_sizing) {
      return inline_size;
    }
    if (type == FormControlType::kInputRange) {
      return inline_size;
    }
  }
  return std::nullopt;
}

// Look for scroll markers inside `parent`, and attach them.
void AttachScrollMarkers(LayoutObject& parent,
                         Node::AttachContext& context,
                         bool has_absolute_containment = false,
                         bool has_fixed_containment = false) {
  if (parent.CanContainAbsolutePositionObjects()) {
    has_absolute_containment = true;
    if (parent.CanContainFixedPositionObjects()) {
      has_fixed_containment = true;
    }
  }

  for (LayoutObject* child = parent.SlowFirstChild(); child;
       child = child->NextSibling()) {
    if ((child->IsFixedPositioned() && !has_fixed_containment) ||
        (child->IsAbsolutePositioned() && !has_absolute_containment)) {
      continue;
    }
    if (auto* element = DynamicTo<Element>(child->GetNode())) {
      if (PseudoElement* marker =
              element->GetPseudoElement(kPseudoIdScrollMarker)) {
        marker->AttachLayoutTree(context);
      }
    }
    // Descend into the subtree of the child unless it is a scroll marker group,
    // or establishes one.
    //
    // TODO(layout-dev): Need to enter nested scrollable containers if an outer
    // scrollable container has "stronger" containment than the inner one. E.g.
    // if the outer one is position:relative, and the inner one has a scroll
    // marker in an absolutely positioned subtree, the marker belongs in the
    // outermost scroll marker group.
    if (!child->IsScrollMarkerGroup() && !child->GetScrollMarkerGroup()) {
      AttachScrollMarkers(*child, context, has_absolute_containment,
                          has_fixed_containment);
    }
  }

  const LayoutBox* parent_box = DynamicTo<LayoutBox>(&parent);
  // If this is a multicol container, look for ::column::scroll-marker pseudo
  // elements, and attach them.
  if (parent_box && parent_box->IsFragmentationContextRoot()) {
    if (const ColumnPseudoElementsVector* column_pseudos =
            To<Element>(parent.EnclosingNode())->GetColumnPseudoElements()) {
      for (const auto& column_pseudo : *column_pseudos) {
        if (PseudoElement* scroll_marker =
                column_pseudo->GetPseudoElement(kPseudoIdScrollMarker)) {
          scroll_marker->AttachLayoutTree(context);
        }
      }
    }
  }
}

}  // namespace

const LayoutResult* BlockNode::Layout(
    const ConstraintSpace& constraint_space,
    const BlockBreakToken* break_token,
    const EarlyBreak* early_break,
    const ColumnSpannerPath* column_spanner_path) const {
  // The exclusion space internally is a pointer to a shared vector, and
  // equality of exclusion spaces is performed using pointer comparison on this
  // internal shared vector.
  // In order for the caching logic to work correctly we need to set the
  // pointer to the value previous shared vector.
  if (const LayoutResult* previous_result =
          box_->GetCachedLayoutResult(break_token)) {
    constraint_space.GetExclusionSpace().PreInitialize(
        previous_result->GetConstraintSpaceForCaching().GetExclusionSpace());
  }

  LayoutCacheStatus cache_status;

  // We may be able to hit the cache without calculating fragment geometry
  // (calculating that isn't necessarily very cheap). So, start off without it.
  std::optional<FragmentGeometry> fragment_geometry;

  // CachedLayoutResult() might clear flags, so remember the need for layout
  // before attempting to hit the cache.
  bool needed_layout = box_->NeedsLayout();
  if (needed_layout)
    box_->GetFrameView()->IncBlockLayoutCount();

  const LayoutResult* layout_result = box_->CachedLayoutResult(
      constraint_space, break_token, early_break, column_spanner_path,
      &fragment_geometry, &cache_status);

  if ((cache_status == LayoutCacheStatus::kHit ||
       cache_status == LayoutCacheStatus::kNeedsSimplifiedLayout) &&
      needed_layout &&
      constraint_space.CacheSlot() == LayoutResultCacheSlot::kLayout &&
      box_->HasBrokenSpine() && !ChildLayoutBlockedByDisplayLock()) {
    // If we're not guaranteed to discard the old fragment (which we're only
    // guaranteed to do if we have decided to perform full layout), we need to
    // clone the result to pick the most recent fragments from the LayoutBox
    // children, because we stopped rebuilding the fragment spine right here
    // after performing subtree layout.
    layout_result = LayoutResult::CloneWithPostLayoutFragments(*layout_result);
    const auto& new_fragment =
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
    // If we have fragment items, and we're not done (more fragments to follow),
    // be sure to miss the cache for any subsequent fragments, lest finalization
    // be missed (which could cause trouble for InlineCursor when walking the
    // items).
    bool clear_trailing_results =
        new_fragment.GetBreakToken() && new_fragment.HasItems();
    StoreResultInLayoutBox(layout_result, break_token, clear_trailing_results);
    box_->ClearHasBrokenSpine();
  }

  if (cache_status == LayoutCacheStatus::kHit) {
    DCHECK(layout_result);

    // We may have to update the margins on box_; we reuse the layout result
    // even if a percentage margin may have changed.
    UpdateMarginPaddingInfoIfNeeded(constraint_space,
                                    layout_result->GetPhysicalFragment());

    UpdateShapeOutsideInfoIfNeeded(*layout_result, constraint_space);

    // Return the cached result unless we're marked for layout. We may have
    // added or removed scrollbars during overflow recalculation, which may have
    // marked us for layout. In that case the cached result is unusable, and we
    // need to re-lay out now.
    if (!box_->NeedsLayout())
      return layout_result;
  }

  if (!fragment_geometry) {
    fragment_geometry =
        CalculateInitialFragmentGeometry(constraint_space, *this, break_token);
  }

  // Only consider the size of the first container fragment.
  if (!IsBreakInside(break_token) && CanMatchSizeContainerQueries()) {
    if (auto* element = DynamicTo<Element>(GetDOMNode())) {
      // Consider scrollbars if they are stable (reset any auto scrollbars).
      BoxStrut scrollbar = fragment_geometry->scrollbar;
      {
        const auto& style = Style();
        if (style.IsScrollbarGutterAuto() &&
            style.OverflowBlockDirection() == EOverflow::kAuto) {
          scrollbar.inline_start = LayoutUnit();
          scrollbar.inline_end = LayoutUnit();
        }
        if (style.OverflowInlineDirection() == EOverflow::kAuto) {
          scrollbar.block_start = LayoutUnit();
          scrollbar.block_end = LayoutUnit();
        }
      }

      const LogicalSize available_size = CalculateChildAvailableSize(
          constraint_space, *this, fragment_geometry->border_box_size,
          fragment_geometry->border + scrollbar + fragment_geometry->padding);
      GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
          *element, available_size, ContainedAxes());

      // Try the cache again. Container query matching may have affected
      // elements in the subtree, so that we need full layout instead of
      // simplified layout, for instance.
      layout_result = box_->CachedLayoutResult(
          constraint_space, break_token, early_break, column_spanner_path,
          &fragment_geometry, &cache_status);
    }
  }

  TextAutosizer::NGLayoutScope text_autosizer_layout_scope(
      box_, fragment_geometry->border_box_size.inline_size);

  PrepareForLayout();

  LayoutAlgorithmParams params(*this, *fragment_geometry, constraint_space,
                               break_token, early_break);
  params.column_spanner_path = column_spanner_path;

  auto* block_flow = DynamicTo<LayoutBlockFlow>(box_.Get());

  // Try to perform "simplified" layout, unless it's a fragmentation context
  // root (the simplified layout algorithm doesn't support fragmentainers).
  if (cache_status == LayoutCacheStatus::kNeedsSimplifiedLayout &&
      (!block_flow || !block_flow->IsFragmentationContextRoot())) {
    DCHECK(layout_result);
#if DCHECK_IS_ON()
    const LayoutResult* previous_result = layout_result;
#endif

    // A child may have changed size while performing "simplified" layout (it
    // may have gained or removed scrollbars, changing its size). In these
    // cases "simplified" layout will return a null layout-result, indicating
    // we need to perform a full layout.
    layout_result = RunSimplifiedLayout(params, *layout_result);

#if DCHECK_IS_ON()
    if (layout_result) {
      layout_result->CheckSameForSimplifiedLayout(
          *previous_result, /* check_same_block_size */ !block_flow);
    }
#endif
  } else if (cache_status == LayoutCacheStatus::kCanReuseLines) {
    params.previous_result = layout_result;
    layout_result = nullptr;
  } else {
    layout_result = nullptr;
  }

  // All these variables may change after layout due to scrollbars changing.
  BoxStrut scrollbars_before = ComputeScrollbars(constraint_space, *this);
  const LayoutUnit inline_size_before =
      fragment_geometry->border_box_size.inline_size;
  const bool intrinsic_logical_widths_dirty_before =
      box_->IntrinsicLogicalWidthsDirty();

  if (!layout_result)
    layout_result = LayoutWithAlgorithm(params);

  // PaintLayerScrollableArea::UpdateAfterLayout() may remove the vertical
  // scrollbar. In vertical-rl or RTL, the vertical scrollbar is on the
  // block-start edge or the inline-start edge, it produces a negative
  // MaximumScrollOffset(), and can cause a wrong clamping. So we delay
  // clamping the offset.
  PaintLayerScrollableArea::DelayScrollOffsetClampScope delay_clamp_scope;

  std::optional<PhysicalSize> optional_old_box_size;
  if (layout_result->Status() == LayoutResult::kSuccess &&
      !layout_result->GetPhysicalFragment().GetBreakToken()) {
    optional_old_box_size = box_->Size();
  }

  FinishLayout(block_flow, constraint_space, break_token, layout_result,
               optional_old_box_size);

  // We may be intrinsicly sized (shrink-to-fit), if our intrinsic logical
  // widths are now dirty, re-calculate our inline-size for comparison.
  if (!intrinsic_logical_widths_dirty_before &&
      box_->IntrinsicLogicalWidthsDirty()) {
    fragment_geometry =
        CalculateInitialFragmentGeometry(constraint_space, *this, break_token);
  }

  // We may need to relayout if:
  // - Our scrollbars have changed causing our size to change (shrink-to-fit)
  //   or the available space to our children changing.
  // - A child changed scrollbars causing our size to change (shrink-to-fit).
  //
  // Skip this part if side-effects aren't allowed, though. Also skip it if we
  // are resuming layout after a fragmentainer break. Changing the intrinsic
  // inline-size halfway through layout of a node doesn't make sense.
  BoxStrut scrollbars_after = ComputeScrollbars(constraint_space, *this);
  if ((scrollbars_before != scrollbars_after ||
       inline_size_before != fragment_geometry->border_box_size.inline_size) &&
      !DisableLayoutSideEffectsScope::IsDisabled() &&
      !IsBreakInside(break_token)) {
    bool freeze_horizontal = false, freeze_vertical = false;
    // If we're in a measure pass, freeze both scrollbars right away, to avoid
    // quadratic time complexity for deeply nested flexboxes.
    if (constraint_space.CacheSlot() == LayoutResultCacheSlot::kMeasure) {
      freeze_horizontal = freeze_vertical = true;
    }
    do {
      // Freeze any scrollbars that appeared, and relayout. Repeat until both
      // have appeared, or until the scrollbar situation doesn't change,
      // whichever comes first.
      AddScrollbarFreeze(scrollbars_before, scrollbars_after,
                         constraint_space.GetWritingDirection(),
                         &freeze_horizontal, &freeze_vertical);
      scrollbars_before = scrollbars_after;
      PaintLayerScrollableArea::FreezeScrollbarsRootScope freezer(
          *box_, freeze_horizontal, freeze_vertical);

      // We need to clear any previous results when scrollbars change. For
      // example - we may have stored a "measure" layout result which will be
      // incorrect if we try and reuse it.
      PhysicalSize old_box_size = box_->Size();
      params.previous_result = nullptr;
      box_->SetShouldSkipLayoutCache(true);

#if DCHECK_IS_ON()
      // Ensure turning on/off scrollbars only once at most, when we call
      // |LayoutWithAlgorithm| recursively.
      DEFINE_STATIC_LOCAL(
          Persistent<HeapHashSet<WeakMember<LayoutBox>>>, scrollbar_changed,
          (MakeGarbageCollected<HeapHashSet<WeakMember<LayoutBox>>>()));
      DCHECK(scrollbar_changed->insert(box_.Get()).is_new_entry);
#endif

      // Scrollbar changes are hard to detect. Make sure everyone gets the
      // message.
      box_->SetNeedsLayout(layout_invalidation_reason::kScrollbarChanged,
                           kMarkOnlyThis);

      if (auto* view = DynamicTo<LayoutView>(GetLayoutBox())) {
        view->InvalidateSvgRootsWithRelativeLengthDescendents();
      }
      fragment_geometry = CalculateInitialFragmentGeometry(constraint_space,
                                                           *this, break_token);
      layout_result = LayoutWithAlgorithm(params);
      FinishLayout(block_flow, constraint_space, break_token, layout_result,
                   old_box_size);

#if DCHECK_IS_ON()
      scrollbar_changed->erase(box_);
#endif

      scrollbars_after = ComputeScrollbars(constraint_space, *this);
      DCHECK(!freeze_horizontal || !freeze_vertical ||
             scrollbars_after == scrollbars_before);
    } while (scrollbars_after != scrollbars_before);
  }

  // We always need to update the ShapeOutsideInfo even if the layout is
  // intermediate (e.g. called during a min/max pass).
  //
  // If a shape-outside float is present in an orthogonal flow, when
  // calculating the min/max-size (by performing an intermediate layout), we
  // might calculate this incorrectly, as the layout won't take into account the
  // shape-outside area.
  //
  // TODO(ikilpatrick): This should be fixed by moving the shape-outside data
  // to the LayoutResult, removing this "side" data-structure.
  UpdateShapeOutsideInfoIfNeeded(*layout_result, constraint_space);

  return layout_result;
}

const LayoutResult* BlockNode::SimplifiedLayout(
    const PhysicalFragment& previous_fragment) const {
  const LayoutResult* previous_result = box_->GetSingleCachedLayoutResult();
  DCHECK(previous_result);

  // We might be be trying to perform simplfied layout on a fragment in the
  // "measure" cache slot, abort if this is the case.
  if (&previous_result->GetPhysicalFragment() != &previous_fragment) {
    return nullptr;
  }

  if (!box_->NeedsLayout())
    return previous_result;

  DCHECK(box_->NeedsSimplifiedLayoutOnly() ||
         box_->ChildLayoutBlockedByDisplayLock());

  // Perform layout on ourselves using the previous constraint space.
  const ConstraintSpace space(previous_result->GetConstraintSpaceForCaching());
  const LayoutResult* result = Layout(space, /* break_token */ nullptr);

  if (result->Status() != LayoutResult::kSuccess) {
    // TODO(crbug.com/1297864): The optimistic BFC block-offsets aren't being
    // set correctly for block-in-inline causing these layouts to fail.
    return nullptr;
  }

  const auto& old_fragment =
      To<PhysicalBoxFragment>(previous_result->GetPhysicalFragment());
  const auto& new_fragment =
      To<PhysicalBoxFragment>(result->GetPhysicalFragment());

  // Simplified layout has the ability to add/remove scrollbars, this can cause
  // a couple (rare) edge-cases which will make the fragment different enough
  // that the parent should perform a full layout.
  //  - The size has changed.
  //  - The alignment baseline has shifted.
  // We return a nullptr in these cases indicating to our parent that it needs
  // to perform a full layout.
  if (old_fragment.Size() != new_fragment.Size())
    return nullptr;
  if (old_fragment.FirstBaseline() != new_fragment.FirstBaseline())
    return nullptr;
  if (old_fragment.LastBaseline() != new_fragment.LastBaseline())
    return nullptr;

#if DCHECK_IS_ON()
  result->CheckSameForSimplifiedLayout(*previous_result);
#endif

  return result;
}

const LayoutResult* BlockNode::LayoutRepeatableRoot(
    const ConstraintSpace& constraint_space,
    const BlockBreakToken* break_token) const {
  // We read and write the physical fragments vector in LayoutBox here, which
  // isn't allowed if side-effects are disabled. Call-sites must make sure that
  // we don't attempt to repeat content if side-effects are disabled.
  DCHECK(!DisableLayoutSideEffectsScope::IsDisabled());

  // When laying out repeatable content, we cannot at the same time allow it to
  // break inside.
  DCHECK(!constraint_space.HasBlockFragmentation());

  // We can't both resume and repeat!
  DCHECK(!IsBreakInside(break_token));

  bool is_first = !break_token || !break_token->IsRepeated();
  const LayoutResult* result;
  if (is_first) {
    // We're generating the first fragment for repeated content. Perform regular
    // layout.
    result = Layout(constraint_space, break_token);
    DCHECK(!result->GetPhysicalFragment().GetBreakToken());
  } else {
    // We're repeating. Create a shallow clone of the first result. Once we're
    // at the last fragment, we'll actually create 
"""


```