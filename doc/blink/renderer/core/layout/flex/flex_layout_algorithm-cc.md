Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The request asks for a functional breakdown of the provided C++ code snippet from Chromium's Blink rendering engine. It specifically requests connections to HTML, CSS, and JavaScript, examples of logical reasoning (input/output), common usage errors (although for low-level code, this is more about potential for misuse or incorrect configuration), and a high-level summary of the code's purpose. The "Part 1 of 4" suggests there will be more context later.

**2. Initial Skim and Keyword Recognition:**

The first step is to quickly read through the code, looking for recognizable keywords and patterns. Terms like:

* `FlexLayoutAlgorithm` (prominent in the class name)
* `flex` (repeatedly used in variable and class names)
* `ComputedStyle`
* `LayoutBox`
* `ConstraintSpace`
* `NGFlexLine`, `NGFlexItem`
* `Baseline`
* `margin`, `padding`, `border`
* `width`, `height`
* `flex-direction`, `flex-wrap`, `justify-content`, `align-items` (though these are resolved through `ComputedStyle`)
* `OutOfFlowPositioned`
* `ReadingFlow`
* `Stretch`
* `IntrinsicSize`
* `FlexBasis`

These keywords immediately signal that this code is responsible for the layout of flexbox containers and their items.

**3. Identifying Core Functionality Blocks:**

After the skim, we can start to group the code into functional blocks. This involves observing method names and the data they manipulate:

* **`FlexLayoutAlgorithm` Constructor and Setup:** Initializes the algorithm, determines flex direction, etc.
* **`MainAxisContentExtent`:** Calculates the available space along the main axis.
* **`MainAxisStaticPositionEdge`, `CrossAxisStaticPositionEdge`:**  These functions, along with the `AxisEdge` enum, are clearly involved in positioning items based on `justify-content` and `align-items` (CSS properties).
* **`HandleOutOfFlowPositionedItems`:** Deals with absolutely positioned children within the flex container.
* **`SetReadingFlowElements`:**  Relates to the order in which elements are read, potentially for accessibility or other purposes.
* **`IsContainerCrossSizeDefinite`:** Determines if the container has a fixed size along the cross axis.
* **`DoesItemStretch`, `DoesItemComputedCrossSizeHaveAuto`, `WillChildCrossSizeBeContainerCrossSize`:**  These functions are responsible for determining how flex items should be sized along the cross axis when using `align-items: stretch`.
* **`BuildSpaceFor...` Methods:** These are crucial. They create `ConstraintSpace` objects, which are likely used to provide the necessary context for laying out individual flex items. Notice the different scenarios: intrinsic inline size, intrinsic block size, flex basis, and final layout.
* **`ConstructAndAppendFlexItems`:**  This is a major function. It iterates through the children, calculates their sizes and margins, and uses the `FlexibleBoxAlgorithm` (likely another class) to do the core flex layout. The different `Phase` enum values suggest different stages of the layout process (e.g., calculating intrinsic sizes before final layout).

**4. Connecting to HTML, CSS, and JavaScript:**

Based on the identified functionality blocks, we can now make connections to web technologies:

* **HTML:** The code operates on `LayoutBox` objects, which represent HTML elements in the render tree. The structure of the HTML will influence the order of children and their relationships.
* **CSS:**  The `ComputedStyle` object is central. This object holds the computed values of CSS properties, including those crucial for flexbox layout (`display: flex`, `flex-direction`, `justify-content`, `align-items`, `flex-basis`, `flex-grow`, `flex-shrink`, `width`, `height`, `margin`).
* **JavaScript:** While this specific C++ code doesn't directly interact with JavaScript, the layout it performs is triggered by changes in the DOM or CSS, which are often initiated by JavaScript interactions. Furthermore, the DevTools integration mentioned suggests that JavaScript in the DevTools can access and display information about the flex layout process.

**5. Logical Reasoning and Examples (Input/Output):**

For logical reasoning, focus on the functions that make decisions based on input:

* **`MainAxisStaticPositionEdge` and `CrossAxisStaticPositionEdge`:**
    * **Input:** A `ComputedStyle` object representing the flex container's styles.
    * **Output:** An `AxisEdge` enum value (`kStart`, `kCenter`, `kEnd`).
    * **Logic:** Maps CSS `justify-content` and `align-items` values to the corresponding alignment edges. Consider different `justify-content` values like `flex-start`, `center`, `flex-end`, `space-between`, `space-around`, and how they translate to the `AxisEdge`. The same applies to `align-items`.

* **`DoesItemStretch`:**
    * **Input:** A `BlockNode` (representing a flex item) and the container's `ComputedStyle`.
    * **Output:** `true` if the item should stretch, `false` otherwise.
    * **Logic:** Checks if the item's cross-axis size is `auto`, and if the `align-items` (or `align-self`) property allows stretching.

* **`BuildSpaceForLayout`:**
    * **Input:**  Various parameters like the `BlockNode`, item main-axis size, potential overrides, etc.
    * **Output:** A `ConstraintSpace` object configured for layout.
    * **Logic:**  Sets up the `ConstraintSpace` based on whether the item is stretching, whether it's part of a fragmented layout, and other factors.

**6. Common Usage Errors:**

Since this is low-level code, "usage errors" are more about incorrect configurations or misunderstandings of flexbox behavior:

* **Not understanding `flex-basis: auto`:**  The code explicitly handles the `flex-basis: auto` case, showing that it's a common scenario that needs careful handling. A developer might mistakenly assume `flex-basis: auto` always means "take the content size."
* **Misunderstanding stretching:**  The `DoesItemStretch` logic highlights the conditions under which an item stretches. A common mistake is assuming an item will stretch even if its cross-axis size isn't `auto` or if the container's `align-items` prevents it.
* **Forgetting about margins with `align-items: stretch`:** The code explicitly checks for auto margins when determining stretch. A developer might be surprised that an item doesn't fully stretch if it has auto margins.

**7. Summarizing the Functionality:**

Finally, synthesize the information into a concise summary. Focus on the core responsibility: implementing the flexbox layout algorithm according to the CSS specification. Mention the key aspects like handling sizing, alignment, out-of-flow elements, and intrinsic size calculations.

**Self-Correction/Refinement during the Process:**

* **Initial Over-Simplification:**  Initially, one might just say "it does flexbox layout."  However, the request demands more detail. Going through the code line by line forces a deeper understanding.
* **Focusing on High-Level Concepts:**  While analyzing, it's easy to get bogged down in the details of specific data structures or internal logic. The key is to keep the connection to the higher-level CSS concepts in mind.
* **Connecting the Dots:**  Realizing that functions like `MainAxisStaticPositionEdge` directly map to CSS properties is crucial for answering the "relationship to CSS" part of the request.
* **Iterative Refinement of Examples:**  The initial examples might be too generic. Thinking about specific CSS values and how they affect the output of the functions leads to more concrete and helpful examples.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive answer that addresses all aspects of the request.
好的，让我们来分析一下 `blink/renderer/core/layout/flex/flex_layout_algorithm.cc` 文件的功能。

**文件功能归纳**

`flex_layout_algorithm.cc` 文件是 Chromium Blink 引擎中负责 **Flexbox 布局算法** 实现的核心组件。它的主要职责是根据 CSS 属性 `display: flex` 或 `display: inline-flex` 应用于容器时，计算并确定其子元素（flex items）的大小和位置。

**更详细的功能列表：**

1. **初始化和准备数据:**
   - 在构造函数中，根据容器的样式信息（`ComputedStyle`）确定主轴方向 (`is_column_`)、是否是水平流 (`is_horizontal_flow_`)、交叉轴尺寸是否确定 (`is_cross_size_definite_`) 等关键属性。
   - 计算子元素的百分比尺寸解析的基准 (`child_percentage_size_`)。
   - 初始化 `FlexibleBoxAlgorithm` 类的实例 (`algorithm_`)，该类包含更底层的 Flexbox 计算逻辑。
   - 为 DevTools 创建 Flexbox 信息对象 (`layout_info_for_devtools_`)，用于调试和检查布局。

2. **计算主轴可用空间:**
   - `MainAxisContentExtent` 函数用于计算 Flex 容器在主轴方向上的可用内容空间。对于列方向的 Flex 容器，它会考虑滚动条的大小。

3. **处理对齐方式:**
   - `MainAxisStaticPositionEdge` 和 `CrossAxisStaticPositionEdge` 函数根据容器和子元素的 `justify-content` 和 `align-items` 属性，将对齐方式映射到静态位置边缘（开始、中心、结束）。

4. **处理脱离文档流的元素:**
   - `HandleOutOfFlowPositionedItems` 函数处理绝对定位 (`position: absolute` 或 `position: fixed`) 的子元素在 Flex 容器中的定位。它会根据 `justify-content` 和 `align-items` 将这些元素放置在容器的相应位置。

5. **设置阅读顺序元素:**
   - `SetReadingFlowElements` 函数根据 CSS 属性 `reading-flow` 的值（`flex-visual` 或 `flex-flow`），确定 Flex 容器中元素的阅读顺序。这对于辅助功能 (accessibility) 和某些特定的内容呈现需求很重要。

6. **判断容器交叉轴尺寸是否确定:**
   - `IsContainerCrossSizeDefinite` 函数判断 Flex 容器在交叉轴方向上的尺寸是否是确定的（非 `auto`）。

7. **判断子元素是否需要拉伸:**
   - `DoesItemStretch` 函数根据子元素的 `align-items` 或 `align-self` 属性以及交叉轴尺寸是否为 `auto` 来判断子元素是否应该在交叉轴方向上拉伸以填充可用空间。
   - `DoesItemComputedCrossSizeHaveAuto` 判断子元素计算后的交叉轴尺寸是否为 `auto`。
   - `WillChildCrossSizeBeContainerCrossSize` 判断子元素的交叉轴尺寸是否会等于容器的交叉轴尺寸（通常发生在单行且子元素需要拉伸的情况下）。

8. **构建约束空间 (`ConstraintSpace`):**
   - 提供多个 `BuildSpaceFor...` 函数，用于为 Flex 子元素的布局计算构建不同的约束空间。约束空间包含了布局所需的各种信息，例如可用空间、百分比解析的基准、是否允许自动尺寸等。这些函数针对不同的布局阶段（例如，计算内联尺寸、块级尺寸、flex-basis 或最终布局）创建不同的约束空间。

9. **构造和追加 Flex 项目:**
   - `ConstructAndAppendFlexItems` 函数是核心的迭代逻辑，用于遍历 Flex 容器的子元素，并为每个子元素执行以下操作：
     - 处理脱离文档流的子元素。
     - 在 `kColumnWrapIntrinsicSize` 阶段计算子元素的最大内容贡献值 (`max_content_contribution`).
     - 计算子元素的边距 (`physical_child_margins`) 和内边距边框 (`physical_border_padding`).
     - 定义 lambda 函数 `MinMaxSizesFunc`，用于获取子元素的最小和最大尺寸。
     - 定义 lambda 函数 `InlineSizeFunc` 和 `BlockSizeFunc`，用于获取子元素的内联尺寸和块级尺寸。
     - 解析子元素的 `flex-basis` 属性，并根据其值和上下文计算 `flex_base_border_box` (flex 基础尺寸，包含边框)。这涉及到处理 `flex-basis: auto` 的情况，以及考虑 `box-sizing` 属性。
     - 将计算好的 Flex 项目信息 (`NGFlexItem`) 添加到 `algorithm_` 中，以便后续的 Flexbox 算法进行布局计算。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件是浏览器渲染引擎的核心部分，它直接影响着网页的布局呈现，因此与 HTML、CSS 和 JavaScript 都有着密切的关系：

* **HTML:**  `FlexLayoutAlgorithm` 处理的是 `LayoutBox` 对象，这些对象是 HTML 元素在渲染树中的表示。该算法根据 HTML 结构和元素的样式来确定布局。
    * **示例:** 当一个 `<div>` 元素设置了 `display: flex`，`FlexLayoutAlgorithm` 就会被调用来布局其子元素。

* **CSS:**  该文件的核心功能是解析和应用 CSS Flexbox 相关的属性，例如：
    * `display: flex` / `display: inline-flex`：触发 Flexbox 布局。
    * `flex-direction`:  决定主轴方向 (`row`, `column`, `row-reverse`, `column-reverse`)。
        * **示例:**  `flex-direction: column` 会导致 `is_column_` 为 true。
    * `justify-content`:  定义项目在主轴上的对齐方式 (`flex-start`, `center`, `flex-end`, `space-between`, `space-around`, `space-evenly`)。
        * **示例:** `justify-content: center` 会影响 `MainAxisStaticPositionEdge` 函数的输出，使得项目在主轴上居中。
    * `align-items`: 定义项目在交叉轴上的对齐方式 (`stretch`, `flex-start`, `center`, `flex-end`, `baseline`)。
        * **示例:** `align-items: stretch` 且子元素的交叉轴尺寸为 `auto` 时，`DoesItemStretch` 会返回 true。
    * `flex-wrap`:  定义是否允许项目换行 (`nowrap`, `wrap`, `wrap-reverse`)。
    * `flex-basis`: 定义项目在主轴上的初始大小。
        * **示例:** `flex-basis: 100px` 会影响 `ConstructAndAppendFlexItems` 中 `flex_base_border_box` 的计算。
    * `flex-grow`: 定义项目在主轴上如何伸展以填充可用空间。
    * `flex-shrink`: 定义项目在主轴上如何收缩以适应空间不足。
    * `align-self`: 允许单个项目覆盖 `align-items` 的设置。
    * `order`:  控制项目的排列顺序。
    * `margin` (在 Flexbox 布局中可能影响自动边距的行为)。
    * `width`, `height` (特别是当 `flex-basis` 为 `auto` 时)。
    * `box-sizing`: 影响 `flex-basis` 的计算。
    * `reading-flow`: 影响元素的阅读顺序。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地触发 `FlexLayoutAlgorithm` 的执行。
    * **示例:**  JavaScript 代码通过修改元素的 `className` 或 `style` 属性来改变 `display` 属性，会导致浏览器重新进行布局计算，包括 Flexbox 布局。
    * **示例:** JavaScript 动画效果可能涉及到元素尺寸或位置的改变，这会触发重新布局，`FlexLayoutAlgorithm` 会参与其中。

**逻辑推理的假设输入与输出**

假设有以下简单的 HTML 和 CSS：

**HTML:**

```html
<div style="display: flex; width: 300px; height: 200px; justify-content: center;">
  <div style="width: 50px; height: 50px;"></div>
</div>
```

**假设输入 (传递给 `FlexLayoutAlgorithm` 的相关信息):**

* **容器样式 (`ComputedStyle`):**
    * `display: flex`
    * `width: 300px`
    * `height: 200px`
    * `justify-content: center`
    * ... (其他默认样式)
* **子元素 (`LayoutBox`):**
    * `width: 50px`
    * `height: 50px`
    * ... (其他默认样式)
* **`is_column_`: `false`** (默认为 row)
* **`is_horizontal_flow_`: `true`**
* **`is_cross_size_definite_`: `true`** (容器高度已定义)

**逻辑推理过程 (部分):**

1. **`MainAxisStaticPositionEdge(container_style)`:**  由于 `justify-content` 是 `center`，此函数将返回 `AxisEdge::kCenter`。
2. **`ConstructAndAppendFlexItems`:**
   - 计算子元素的 `flex_base_border_box`。由于没有设置 `flex-basis`，且宽度已定义，它可能会使用子元素的 `width` (50px) 作为初始大小。
3. **Flexbox 算法执行 (在 `FlexibleBoxAlgorithm` 中):**
   - 由于 `justify-content` 是 `center`，算法会计算主轴上的剩余空间 (300px - 50px = 250px)，然后将子元素放置在中心位置，左右两侧各有 125px 的空间。

**假设输出 (部分布局结果):**

* 子元素在其父容器中的水平偏移量 (inline offset) 大约为 125px。
* 子元素的尺寸保持为 50px x 50px (因为没有 `flex-grow` 或 `flex-shrink`)。

**用户或编程常见的使用错误示例**

1. **未设置容器的 `display: flex` 或 `display: inline-flex`:** 这是最常见的错误，子元素不会按照 Flexbox 规则布局。
    * **示例:**  忘记在 CSS 中为父元素添加 `display: flex;`，导致子元素仍然按照块级元素或内联元素的默认方式排列。

2. **误解 `flex-direction` 的影响:**  开发者可能忘记更改交叉轴相关的属性（例如 `align-items`）来适应 `flex-direction` 的变化。
    * **示例:**  当 `flex-direction: column` 时，`align-items: center` 会在水平方向上居中，而不是垂直方向。

3. **`flex-grow` 和 `flex-shrink` 的误用:**  不理解这两个属性如何分配剩余空间或收缩空间，导致布局不符合预期。
    * **示例:**  给所有子元素设置相同的 `flex-grow` 值，但期望它们拥有不同的大小。

4. **忘记考虑 `flex-basis: auto` 的行为:**  当 `flex-basis: auto` 时，项目的大小会根据其 `width` 或 `height` 属性确定，这可能与预期不符。

5. **在 Flex 容器中使用绝对定位时没有充分理解其影响:** 绝对定位的元素会脱离正常的 Flexbox 布局流，其定位是相对于最近的已定位祖先元素，而不是按照 Flexbox 规则排列。

**总结 (针对第 1 部分)**

`flex_layout_algorithm.cc` 文件的第 1 部分主要负责 **初始化 Flexbox 布局过程**，包括：

* **识别 Flex 容器和子元素。**
* **获取和解析相关的 CSS 样式属性。**
* **计算容器和子元素的基本尺寸和约束。**
* **处理对齐方式和脱离文档流的元素。**
* **为后续的 Flexbox 算法计算准备必要的数据结构 (`NGFlexItem`)。**

总而言之，这是 Flexbox 布局计算的起点，它为后续更复杂的尺寸调整和位置计算奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/layout/flex/flex_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/flex/flex_layout_algorithm.h"

#include <memory>
#include <optional>

#include "base/not_fatal_until.h"
#include "base/types/optional_util.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/baseline_utils.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/flex/devtools_flex_info.h"
#include "third_party/blink/renderer/core/layout/flex/flex_child_iterator.h"
#include "third_party/blink/renderer/core/layout/flex/flex_item_iterator.h"
#include "third_party/blink/renderer/core/layout/flex/flexible_box_algorithm.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/flex/ng_flex_line.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_input_node.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/table/table_node.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

class BaselineAccumulator {
  STACK_ALLOCATED();

 public:
  explicit BaselineAccumulator(const ComputedStyle& style)
      : font_baseline_(style.GetFontBaseline()) {}

  void AccumulateItem(const LogicalBoxFragment& fragment,
                      const LayoutUnit block_offset,
                      bool is_first_line,
                      bool is_last_line) {
    if (is_first_line) {
      if (!first_fallback_baseline_) {
        first_fallback_baseline_ =
            block_offset + fragment.FirstBaselineOrSynthesize(font_baseline_);
      }
    }

    if (is_last_line) {
      last_fallback_baseline_ =
          block_offset + fragment.LastBaselineOrSynthesize(font_baseline_);
    }
  }

  void AccumulateLine(const NGFlexLine& line,
                      bool is_first_line,
                      bool is_last_line) {
    if (is_first_line) {
      if (line.major_baseline != LayoutUnit::Min()) {
        first_major_baseline_ = line.cross_axis_offset + line.major_baseline;
      }
      if (line.minor_baseline != LayoutUnit::Min()) {
        first_minor_baseline_ =
            line.cross_axis_offset + line.line_cross_size - line.minor_baseline;
      }
    }

    if (is_last_line) {
      if (line.major_baseline != LayoutUnit::Min()) {
        last_major_baseline_ = line.cross_axis_offset + line.major_baseline;
      }
      if (line.minor_baseline != LayoutUnit::Min()) {
        last_minor_baseline_ =
            line.cross_axis_offset + line.line_cross_size - line.minor_baseline;
      }
    }
  }

  std::optional<LayoutUnit> FirstBaseline() const {
    if (first_major_baseline_)
      return *first_major_baseline_;
    if (first_minor_baseline_)
      return *first_minor_baseline_;
    return first_fallback_baseline_;
  }
  std::optional<LayoutUnit> LastBaseline() const {
    if (last_minor_baseline_)
      return *last_minor_baseline_;
    if (last_major_baseline_)
      return *last_major_baseline_;
    return last_fallback_baseline_;
  }

 private:
  FontBaseline font_baseline_;

  std::optional<LayoutUnit> first_major_baseline_;
  std::optional<LayoutUnit> first_minor_baseline_;
  std::optional<LayoutUnit> first_fallback_baseline_;

  std::optional<LayoutUnit> last_major_baseline_;
  std::optional<LayoutUnit> last_minor_baseline_;
  std::optional<LayoutUnit> last_fallback_baseline_;
};

}  // anonymous namespace

FlexLayoutAlgorithm::FlexLayoutAlgorithm(
    const LayoutAlgorithmParams& params,
    const HashMap<wtf_size_t, LayoutUnit>* cross_size_adjustments)
    : LayoutAlgorithm(params),
      is_column_(Style().ResolvedIsColumnFlexDirection()),
      is_horizontal_flow_(FlexibleBoxAlgorithm::IsHorizontalFlow(Style())),
      is_cross_size_definite_(IsContainerCrossSizeDefinite()),
      child_percentage_size_(
          CalculateChildPercentageSize(GetConstraintSpace(),
                                       Node(),
                                       ChildAvailableSize())),
      algorithm_(&Style(),
                 MainAxisContentExtent(LayoutUnit::Max()),
                 child_percentage_size_,
                 &Node().GetDocument()),
      cross_size_adjustments_(cross_size_adjustments) {
  // TODO(layout-dev): Devtools support when there are multiple fragments.
  if (Node().GetLayoutBox()->NeedsDevtoolsInfo() &&
      !InvolvedInBlockFragmentation(container_builder_))
    layout_info_for_devtools_ = std::make_unique<DevtoolsFlexInfo>();
}

void FlexLayoutAlgorithm::SetupRelayoutData(const FlexLayoutAlgorithm& previous,
                                            RelayoutType relayout_type) {
  LayoutAlgorithm::SetupRelayoutData(previous, relayout_type);

  if (relayout_type == kRelayoutIgnoringChildScrollbarChanges) {
    ignore_child_scrollbar_changes_ = true;
  } else {
    ignore_child_scrollbar_changes_ = previous.ignore_child_scrollbar_changes_;
  }
}

LayoutUnit FlexLayoutAlgorithm::MainAxisContentExtent(
    LayoutUnit sum_hypothetical_main_size) const {
  if (is_column_) {
    // Even though we only pass border_padding in the third parameter, the
    // return value includes scrollbar, so subtract scrollbar to get content
    // size.
    // We add |border_scrollbar_padding| to the fourth parameter because
    // |content_size| needs to be the size of the border box. We've overloaded
    // the term "content".
    const LayoutUnit border_scrollbar_padding =
        BorderScrollbarPadding().BlockSum();
    return ComputeBlockSizeForFragment(
               GetConstraintSpace(), Node(), BorderPadding(),
               sum_hypothetical_main_size.ClampNegativeToZero() +
                   border_scrollbar_padding,
               container_builder_.InlineSize()) -
           border_scrollbar_padding;
  }
  return ChildAvailableSize().inline_size;
}

namespace {

enum AxisEdge { kStart, kCenter, kEnd };

// Maps the resolved justify-content value to a static-position edge.
AxisEdge MainAxisStaticPositionEdge(const ComputedStyle& style) {
  const StyleContentAlignmentData justify =
      FlexibleBoxAlgorithm::ResolvedJustifyContent(style);
  const ContentPosition content_position = justify.GetPosition();
  const bool is_reverse = style.ResolvedIsReverseFlexDirection();

  DCHECK_NE(content_position, ContentPosition::kLeft);
  DCHECK_NE(content_position, ContentPosition::kRight);
  if (content_position == ContentPosition::kFlexEnd)
    return is_reverse ? AxisEdge::kStart : AxisEdge::kEnd;

  if (content_position == ContentPosition::kCenter ||
      justify.Distribution() == ContentDistributionType::kSpaceAround ||
      justify.Distribution() == ContentDistributionType::kSpaceEvenly)
    return AxisEdge::kCenter;

  if (content_position == ContentPosition::kStart)
    return AxisEdge::kStart;
  if (content_position == ContentPosition::kEnd)
    return AxisEdge::kEnd;

  return is_reverse ? AxisEdge::kEnd : AxisEdge::kStart;
}

// Maps the resolved alignment value to a static-position edge.
AxisEdge CrossAxisStaticPositionEdge(const ComputedStyle& style,
                                     const ComputedStyle& child_style) {
  ItemPosition alignment =
      FlexibleBoxAlgorithm::AlignmentForChild(style, child_style);
  // AlignmentForChild already accounted for wrap-reverse for kFlexStart and
  // kFlexEnd, but not kStretch. kStretch is supposed to act like kFlexStart.
  if (style.FlexWrap() == EFlexWrap::kWrapReverse &&
      alignment == ItemPosition::kStretch) {
    return AxisEdge::kEnd;
  }

  if (alignment == ItemPosition::kFlexEnd ||
      alignment == ItemPosition::kLastBaseline)
    return AxisEdge::kEnd;

  if (alignment == ItemPosition::kCenter)
    return AxisEdge::kCenter;

  return AxisEdge::kStart;
}

}  // namespace

void FlexLayoutAlgorithm::HandleOutOfFlowPositionedItems(
    HeapVector<Member<LayoutBox>>& oof_children) {
  if (oof_children.empty())
    return;

  HeapVector<Member<LayoutBox>> oofs;
  std::swap(oofs, oof_children);

  bool should_process_block_end = true;
  bool should_process_block_center = true;
  const LayoutUnit previous_consumed_block_size =
      GetBreakToken() ? GetBreakToken()->ConsumedBlockSize() : LayoutUnit();

  // We will attempt to add OOFs in the fragment in which their static
  // position belongs. However, the last fragment has the most up-to-date flex
  // size information (e.g. any expanded rows, etc), so for center aligned
  // items, we could end up with an incorrect static position.
  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    should_process_block_end = !container_builder_.DidBreakSelf() &&
                               !container_builder_.ShouldBreakInside();
    if (should_process_block_end) {
      // Recompute the total block size in case |total_intrinsic_block_size_|
      // changed as a result of fragmentation.
      total_block_size_ = ComputeBlockSizeForFragment(
          GetConstraintSpace(), Node(), BorderPadding(),
          total_intrinsic_block_size_, container_builder_.InlineSize());
    } else {
      LayoutUnit center = total_block_size_ / 2;
      should_process_block_center = center - previous_consumed_block_size <=
                                    FragmentainerCapacityForChildren();
    }
  }

  using InlineEdge = LogicalStaticPosition::InlineEdge;
  using BlockEdge = LogicalStaticPosition::BlockEdge;

  BoxStrut border_scrollbar_padding = BorderScrollbarPadding();
  border_scrollbar_padding.block_start =
      OriginalBorderScrollbarPaddingBlockStart();

  LogicalSize total_fragment_size = {container_builder_.InlineSize(),
                                     total_block_size_};
  total_fragment_size =
      ShrinkLogicalSize(total_fragment_size, border_scrollbar_padding);

  for (LayoutBox* oof_child : oofs) {
    BlockNode child(oof_child);

    AxisEdge main_axis_edge = MainAxisStaticPositionEdge(Style());
    AxisEdge cross_axis_edge =
        CrossAxisStaticPositionEdge(Style(), child.Style());

    AxisEdge inline_axis_edge = is_column_ ? cross_axis_edge : main_axis_edge;
    AxisEdge block_axis_edge = is_column_ ? main_axis_edge : cross_axis_edge;

    InlineEdge inline_edge;
    BlockEdge block_edge;
    LogicalOffset offset = border_scrollbar_padding.StartOffset();

    // Determine the static-position based off the axis-edge.
    if (block_axis_edge == AxisEdge::kStart) {
      DCHECK(!IsBreakInside(GetBreakToken()));
      block_edge = BlockEdge::kBlockStart;
    } else if (block_axis_edge == AxisEdge::kCenter) {
      if (!should_process_block_center) {
        oof_children.emplace_back(oof_child);
        continue;
      }
      block_edge = BlockEdge::kBlockCenter;
      offset.block_offset += total_fragment_size.block_size / 2;
    } else {
      if (!should_process_block_end) {
        oof_children.emplace_back(oof_child);
        continue;
      }
      block_edge = BlockEdge::kBlockEnd;
      offset.block_offset += total_fragment_size.block_size;
    }

    if (inline_axis_edge == AxisEdge::kStart) {
      inline_edge = InlineEdge::kInlineStart;
    } else if (inline_axis_edge == AxisEdge::kCenter) {
      inline_edge = InlineEdge::kInlineCenter;
      offset.inline_offset += total_fragment_size.inline_size / 2;
    } else {
      inline_edge = InlineEdge::kInlineEnd;
      offset.inline_offset += total_fragment_size.inline_size;
    }

    // Make the child offset relative to our fragment.
    offset.block_offset -= previous_consumed_block_size;

    container_builder_.AddOutOfFlowChildCandidate(child, offset, inline_edge,
                                                  block_edge);
  }
}

void FlexLayoutAlgorithm::SetReadingFlowElements(
    const HeapVector<NGFlexLine>& flex_line_outputs) {
  const auto& style = Style();
  const EReadingFlow reading_flow = style.ReadingFlow();
  if (reading_flow != EReadingFlow::kFlexVisual &&
      reading_flow != EReadingFlow::kFlexFlow) {
    return;
  }
  HeapVector<Member<Element>> reading_flow_elements;
  // Add flex item if it is a DOM element
  auto AddItemIfNeeded = [&](const NGFlexItem& item) {
    if (Element* element =
            DynamicTo<Element>(item.ng_input_node.GetDOMNode())) {
      reading_flow_elements.push_back(element);
    }
  };
  // Given CSS reading-flow, flex-flow, flex-direction; read values
  // in correct order.
  auto AddFlexItems = [&](const NGFlexLine& line) {
    if (reading_flow == EReadingFlow::kFlexFlow &&
        style.ResolvedIsReverseFlexDirection()) {
      for (const auto& item : base::Reversed(line.line_items)) {
        AddItemIfNeeded(item);
      }
    } else {
      for (const auto& item : line.line_items) {
        AddItemIfNeeded(item);
      }
    }
  };
  if (reading_flow == EReadingFlow::kFlexFlow &&
      style.FlexWrap() == EFlexWrap::kWrapReverse) {
    for (const auto& line : base::Reversed(flex_line_outputs)) {
      AddFlexItems(line);
    }
  } else {
    for (const auto& line : flex_line_outputs) {
      AddFlexItems(line);
    }
  }
  container_builder_.SetReadingFlowElements(std::move(reading_flow_elements));
}

bool FlexLayoutAlgorithm::IsContainerCrossSizeDefinite() const {
  // A column flexbox's cross axis is an inline size, so is definite.
  if (is_column_)
    return true;

  return ChildAvailableSize().block_size != kIndefiniteSize;
}

bool FlexLayoutAlgorithm::DoesItemStretch(const BlockNode& child) const {
  // Note: Unresolvable % cross size doesn't count as auto for stretchability.
  // As discussed in https://github.com/w3c/csswg-drafts/issues/4312.
  if (!DoesItemComputedCrossSizeHaveAuto(child)) {
    return false;
  }
  const ComputedStyle& child_style = child.Style();
  // https://drafts.csswg.org/css-flexbox/#valdef-align-items-stretch
  // If the cross size property of the flex item computes to auto, and neither
  // of the cross-axis margins are auto, the flex item is stretched.
  if (is_horizontal_flow_ &&
      (child_style.MarginTop().IsAuto() || child_style.MarginBottom().IsAuto()))
    return false;
  if (!is_horizontal_flow_ &&
      (child_style.MarginLeft().IsAuto() || child_style.MarginRight().IsAuto()))
    return false;
  return FlexibleBoxAlgorithm::AlignmentForChild(Style(), child_style) ==
         ItemPosition::kStretch;
}

bool FlexLayoutAlgorithm::DoesItemComputedCrossSizeHaveAuto(
    const BlockNode& child) const {
  const ComputedStyle& child_style = child.Style();
  if (is_horizontal_flow_) {
    return child_style.Height().HasAuto();
  }
  return child_style.Width().HasAuto();
}

bool FlexLayoutAlgorithm::WillChildCrossSizeBeContainerCrossSize(
    const BlockNode& child) const {
  return !algorithm_.IsMultiline() && is_cross_size_definite_ &&
         DoesItemStretch(child);
}

ConstraintSpace FlexLayoutAlgorithm::BuildSpaceForIntrinsicInlineSize(
    const BlockNode& child) const {
  MinMaxConstraintSpaceBuilder builder(GetConstraintSpace(), Style(), child,
                                       /* is_new_fc */ true);
  builder.SetAvailableBlockSize(ChildAvailableSize().block_size);
  builder.SetPercentageResolutionBlockSize(child_percentage_size_.block_size);
  builder.SetReplacedPercentageResolutionBlockSize(
      child_percentage_size_.block_size);
  if (!is_column_ && WillChildCrossSizeBeContainerCrossSize(child))
    builder.SetBlockAutoBehavior(AutoSizeBehavior::kStretchExplicit);
  return builder.ToConstraintSpace();
}

ConstraintSpace FlexLayoutAlgorithm::BuildSpaceForIntrinsicBlockSize(
    const BlockNode& flex_item,
    std::optional<LayoutUnit> override_inline_size) const {
  const ComputedStyle& child_style = flex_item.Style();
  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       child_style.GetWritingDirection(),
                                       /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(Style(), flex_item, &space_builder);
  space_builder.SetCacheSlot(LayoutResultCacheSlot::kMeasure);
  space_builder.SetIsPaintedAtomically(true);

  if (WillChildCrossSizeBeContainerCrossSize(flex_item)) {
    if (is_column_)
      space_builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchExplicit);
    else
      space_builder.SetBlockAutoBehavior(AutoSizeBehavior::kStretchExplicit);
  }

  // For determining the intrinsic block-size we make %-block-sizes resolve
  // against an indefinite size.
  LogicalSize child_percentage_size = child_percentage_size_;
  if (is_column_) {
    child_percentage_size.block_size = kIndefiniteSize;
    space_builder.SetIsInitialBlockSizeIndefinite(true);
  }
  if (override_inline_size.has_value()) {
    LogicalSize available_size = ChildAvailableSize();
    available_size.inline_size = *override_inline_size;
    space_builder.SetIsFixedInlineSize(true);
    space_builder.SetAvailableSize(available_size);
  } else {
    space_builder.SetAvailableSize(ChildAvailableSize());
  }
  space_builder.SetPercentageResolutionSize(child_percentage_size);
  // TODO(dgrogan): The SetReplacedPercentageResolutionSize calls in this file
  // may be untested. Write a test or determine why they're unnecessary.
  space_builder.SetReplacedPercentageResolutionSize(child_percentage_size);
  return space_builder.ToConstraintSpace();
}

ConstraintSpace FlexLayoutAlgorithm::BuildSpaceForFlexBasis(
    const BlockNode& flex_item) const {
  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       flex_item.Style().GetWritingDirection(),
                                       /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(Style(), flex_item, &space_builder);

  // This space is only used for resolving lengths, not for layout. We only
  // need the available and percentage sizes.
  space_builder.SetAvailableSize(ChildAvailableSize());
  space_builder.SetPercentageResolutionSize(child_percentage_size_);
  space_builder.SetReplacedPercentageResolutionSize(child_percentage_size_);
  return space_builder.ToConstraintSpace();
}

ConstraintSpace FlexLayoutAlgorithm::BuildSpaceForLayout(
    const BlockNode& flex_item_node,
    LayoutUnit item_main_axis_final_size,
    bool is_initial_block_size_indefinite,
    std::optional<LayoutUnit> override_inline_size,
    std::optional<LayoutUnit> line_cross_size_for_stretch,
    std::optional<LayoutUnit> block_offset_for_fragmentation,
    bool min_block_size_should_encompass_intrinsic_size) const {
  const ComputedStyle& child_style = flex_item_node.Style();
  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       child_style.GetWritingDirection(),
                                       /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(Style(), flex_item_node,
                                          &space_builder);
  space_builder.SetIsPaintedAtomically(true);

  LogicalSize available_size;
  if (is_column_) {
    available_size.inline_size = line_cross_size_for_stretch
                                     ? *line_cross_size_for_stretch
                                     : ChildAvailableSize().inline_size;

    if (override_inline_size) {
      DCHECK(!line_cross_size_for_stretch.has_value())
          << "We only override inline size when we are calculating intrinsic "
             "width of multiline column flexboxes, and we don't do any "
             "stretching during the intrinsic width calculation.";
      available_size.inline_size = *override_inline_size;
      space_builder.SetIsFixedInlineSize(true);
    }
    available_size.block_size = item_main_axis_final_size;
    space_builder.SetIsFixedBlockSize(true);
    if (line_cross_size_for_stretch ||
        WillChildCrossSizeBeContainerCrossSize(flex_item_node))
      space_builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchExplicit);
  } else {
    DCHECK(!override_inline_size.has_value());
    available_size.inline_size = item_main_axis_final_size;
    available_size.block_size = line_cross_size_for_stretch
                                    ? *line_cross_size_for_stretch
                                    : ChildAvailableSize().block_size;
    space_builder.SetIsFixedInlineSize(true);
    if (line_cross_size_for_stretch ||
        WillChildCrossSizeBeContainerCrossSize(flex_item_node))
      space_builder.SetBlockAutoBehavior(AutoSizeBehavior::kStretchExplicit);
  }
  if (is_initial_block_size_indefinite) {
    space_builder.SetIsInitialBlockSizeIndefinite(true);
  }
  if (!line_cross_size_for_stretch && DoesItemStretch(flex_item_node)) {
    // For the first layout pass of stretched items, the goal is to determine
    // the post-flexed, pre-stretched cross-axis size. Stretched items will
    // later get a final layout with a potentially different cross size so use
    // the "measure" slot for this layout. We will use the "layout" cache slot
    // for the item's final layout.
    //
    // Setting the "measure" cache slot on the space writes the result
    // into both the "measure" and "layout" cache slots. So the stretch
    // layout will reuse this "measure" result if it can.
    space_builder.SetCacheSlot(LayoutResultCacheSlot::kMeasure);
  } else if (block_offset_for_fragmentation &&
             GetConstraintSpace().HasBlockFragmentation()) {
    if (min_block_size_should_encompass_intrinsic_size)
      space_builder.SetMinBlockSizeShouldEncompassIntrinsicSize();
    SetupSpaceBuilderForFragmentation(container_builder_, flex_item_node,
                                      *block_offset_for_fragmentation,
                                      &space_builder);
  }

  space_builder.SetAvailableSize(available_size);
  space_builder.SetPercentageResolutionSize(child_percentage_size_);
  space_builder.SetReplacedPercentageResolutionSize(child_percentage_size_);
  return space_builder.ToConstraintSpace();
}

void FlexLayoutAlgorithm::ConstructAndAppendFlexItems(
    Phase phase,
    HeapVector<Member<LayoutBox>>* oof_children) {
  const bool is_wrap_reverse = Style().FlexWrap() == EFlexWrap::kWrapReverse;

  FlexChildIterator iterator(Node());
  for (BlockNode child = iterator.NextChild(); child;
       child = iterator.NextChild()) {
    if (child.IsOutOfFlowPositioned()) {
      if (phase == Phase::kLayout) {
        DCHECK(oof_children);
        oof_children->emplace_back(child.GetLayoutBox());
      }
      continue;
    }

    std::optional<LayoutUnit> max_content_contribution;
    if (phase == Phase::kColumnWrapIntrinsicSize) {
      auto space = BuildSpaceForIntrinsicInlineSize(child);
      MinMaxSizesResult child_contributions =
          ComputeMinAndMaxContentContribution(Style(), child, space);
      max_content_contribution = child_contributions.sizes.max_size;
      BoxStrut child_margins =
          ComputeMarginsFor(space, child.Style(), GetConstraintSpace());
      child_contributions.sizes += child_margins.InlineSum();

      largest_min_content_contribution_ =
          std::max(child_contributions.sizes.min_size,
                   largest_min_content_contribution_);
    }

    const ComputedStyle& child_style = child.Style();
    const auto child_writing_mode = child_style.GetWritingMode();
    const bool is_main_axis_inline_axis =
        IsHorizontalWritingMode(child_writing_mode) == is_horizontal_flow_;

    ConstraintSpace flex_basis_space = BuildSpaceForFlexBasis(child);

    PhysicalBoxStrut physical_child_margins =
        ComputePhysicalMargins(flex_basis_space, child_style);

    BoxStrut border_padding_in_child_writing_mode =
        ComputeBorders(flex_basis_space, child) +
        ComputePadding(flex_basis_space, child_style);

    PhysicalBoxStrut physical_border_padding(
        border_padding_in_child_writing_mode.ConvertToPhysical(
            child_style.GetWritingDirection()));

    const LayoutUnit main_axis_border_padding =
        is_horizontal_flow_ ? physical_border_padding.HorizontalSum()
                            : physical_border_padding.VerticalSum();

    bool depends_on_min_max_sizes = false;
    auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
      depends_on_min_max_sizes = true;
      // We want the child's intrinsic inline sizes in its writing mode, so
      // pass child's writing mode as the first parameter, which is nominally
      // |container_writing_mode|.
      const auto child_space =
          BuildSpaceForIntrinsicBlockSize(child, max_content_contribution);
      return child.ComputeMinMaxSizes(child_writing_mode, type, child_space);
    };

    auto InlineSizeFunc = [&]() -> LayoutUnit {
      const ConstraintSpace child_space =
          BuildSpaceForIntrinsicBlockSize(child, max_content_contribution);
      return CalculateInitialFragmentGeometry(child_space, child,
                                              /* break_token */ nullptr)
          .border_box_size.inline_size;
    };

    const LayoutResult* layout_result = nullptr;
    auto BlockSizeFunc = [&](SizeType type) -> LayoutUnit {
      // This function mirrors the logic within `BlockNode::ComputeMinMaxSizes`.
      const ConstraintSpace child_space =
          BuildSpaceForIntrinsicBlockSize(child, max_content_contribution);

      // Don't apply any special aspect-ratio treatment for replaced elements.
      if (child.IsReplaced()) {
        return ComputeReplacedSize(child, child_space,
                                   border_padding_in_child_writing_mode,
                                   ReplacedSizeMode::kIgnoreBlockLengths)
            .block_size;
      }

      const bool has_aspect_ratio = !child_style.AspectRatio().IsAuto();
      if (has_aspect_ratio && type == SizeType::kContent) {
        const LayoutUnit inline_size = InlineSizeFunc();
        if (inline_size != kIndefiniteSize) {
          return BlockSizeFromAspectRatio(
              border_padding_in_child_writing_mode, child.GetAspectRatio(),
              child_style.BoxSizingForAspectRatio(), inline_size);
        }
      }

      LayoutUnit intrinsic_size;
      if (child.ShouldApplyBlockSizeContainment()) {
        // If we have block-size containment we can avoid layout for
        // determining the intrinsic size.
        intrinsic_size = ClampIntrinsicBlockSize(
            child_space, child, /* break_token */ nullptr,
            border_padding_in_child_writing_mode,
            /* current_intrinsic_block_size */ LayoutUnit());
      } else {
        if (!layout_result) {
          std::optional<DisableLayoutSideEffectsScope> disable_side_effects;
          if (phase != Phase::kLayout &&
              !Node().GetLayoutBox()->NeedsLayout()) {
            disable_side_effects.emplace();
          }
          layout_result = child.Layout(child_space, /* break_token */ nullptr);
          DCHECK(layout_result);
        }
        intrinsic_size = layout_result->IntrinsicBlockSize();
      }

      // Constrain the intrinsic-size by the transferred min/max constraints.
      if (has_aspect_ratio) {
        const MinMaxSizes inline_min_max = ComputeMinMaxInlineSizes(
            flex_basis_space, child, border_padding_in_child_writing_mode,
            /* auto_min_length */ nullptr, MinMaxSizesFunc,
            TransferredSizesMode::kIgnore);
        const MinMaxSizes min_max = ComputeTransferredMinMaxBlockSizes(
            child_style.LogicalAspectRatio(), inline_min_max,
            border_padding_in_child_writing_mode,
            child_style.BoxSizingForAspectRatio());
        return min_max.ClampSizeToMinAndMax(intrinsic_size);
      }

      return intrinsic_size;
    };

    const Length& flex_basis = child_style.FlexBasis();
    if (is_column_ && flex_basis.MayHavePercentDependence()) {
      has_column_percent_flex_basis_ = true;
    }

    // This bool is set to true while calculating the base size, the flex-basis
    // is "content" based (e.g. dependent on the child's content).
    bool is_used_flex_basis_indefinite = false;

    // An auto value for flex-basis says to defer to width or height.
    // Those might in turn have an auto value.  And in either case the
    // value might be calc-size(auto, ...).  Because of this, we might
    // need to handle resolving the length in the main axis twice.
    auto resolve_main_length = [&](const Length& used_flex_basis_length,
                                   const Length* auto_length) -> LayoutUnit {
      if (is_main_axis_inline_axis) {
        const LayoutUnit inline_size = ResolveMainInlineLength(
            flex_basis_space, child_style, border_padding_in_child_writing_mode,
            [&](SizeType type) -> MinMaxSizesResult {
              is_used_flex_basis_indefinite = true;
              return MinMaxSizesFunc(type);
            },
            used_flex_basis_length, auto_length);

        if (inline_size != kIndefiniteSize) {
          return inline_size;
        }

        // We weren't able to resolve the length (i.e. we were a unresolvable
        // %-age or similar), fallback to the max-content size.
        is_used_flex_basis_indefinite = true;
        return MinMaxSizesFunc(SizeType::kContent).sizes.max_size;
      }

      return ResolveMainBlockLength(
          flex_basis_space, child_style, border_padding_in_child_writing_mode,
          used_flex_basis_length, auto_length, [&](SizeType type) {
            is_used_flex_basis_indefinite = true;
            return BlockSizeFunc(type);
          });
    };

    const LayoutUnit flex_base_border_box = ([&]() -> LayoutUnit {
      std::optional<Length> auto_flex_basis_length;

      if (flex_basis.HasAuto()) {
        const Length& specified_length_in_main_axis =
            is_horizontal_flow_ ? child_style.Width() : child_style.Height();

        // 'auto' for items within a -webkit-box resolve as 'fit-content'.
        const Length& auto_size_length =
            (Style().IsDeprecatedWebkitBox() &&
             (Style().BoxOrient() == EBoxOrient::kHorizontal ||
              Style().BoxAlign() != EBoxAlignment::kStretch))
                ? Length::FitContent()
                : Length::MaxContent();

        LayoutUnit auto_flex_basis_size = resolve_main_length(
            specified_length_in_main_axis, &auto_size_length);
        if (child_style.BoxSizing() == EBoxSizing::kContentBox) {
          auto_flex_basis_size -= main_axis_border_padding;
        }
        DCHECK_GE(auto_flex_basis_size, LayoutUnit());
        auto_flex_basis_length = Length::Fixed(auto_flex_basis_size);
      }

      LayoutUnit main_size = resolve_main_length(
          flex_basis, base::OptionalToPtr(auto_flex_basis_length));

      // Add the caption block-size only to sizes that are not content-based.
      if (!is_main_axis_inline_axis && !is_used_flex_basis_indefinite) {
        // 1. A table interprets forced block-size as the block-size of its
        //    captions and rows.
        // 2. The specified block-size of a table only applies to its rows.
        // 3. If the block-size resolved, add the caption block-size so that
        //    the forced block-size works correctly.
        if (const auto* table_child = DynamicTo<TableNode>(&child)) {
          main_size += table_child->ComputeCaptionBlockSize(
              BuildSpaceForIntrinsicBlockSize(*table_child,
                                              max_content_cont
"""


```