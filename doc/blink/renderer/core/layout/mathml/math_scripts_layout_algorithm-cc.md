Response:
The user wants to understand the functionality of the `math_scripts_layout_algorithm.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose:** This file seems to handle the layout of math elements with subscripts and superscripts.
2. **Explain its function:** Detail how it arranges these elements, considering factors like font metrics and OpenType MATH table data.
3. **Connect to web technologies:** Explain the relationship with HTML (MathML), CSS (styling), and potentially JavaScript (dynamic manipulation, though this file primarily focuses on layout).
4. **Illustrate with examples:** Provide hypothetical input and output scenarios to demonstrate the layout process.
5. **Highlight potential errors:** Point out common mistakes users or programmers might make when working with MathML scripts.
这个文件 `math_scripts_layout_algorithm.cc` 的主要功能是**负责处理 MathML 中带有上标、下标的数学公式的布局**。更具体地说，它实现了 `<msub>`, `<msup>`, `<msubsup>`, `<munder>`, `<mover>`, `<munderover>`, 和 `<mmultiscripts>` 等标签的布局逻辑。

以下是其功能的详细说明以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能：**

1. **收集子元素 (GatherChildren):**
   - 识别并分离出基线元素 (base)、上标 (superscript)、下标 (subscript) 和前置标 (prescripts)。
   - 对于 `<mmultiscripts>` 标签，它会识别使用 `<mprescripts>` 分隔的前置上下标对。
   - 将上标和下标组合成 `SubSupPair` 结构，以便后续处理。

2. **计算垂直方向的度量 (GetVerticalMetrics):**
   - 根据元素的 `ComputedStyle` 和 OpenType MATH 表（如果存在），计算上标和下标的垂直偏移量。
   - 这些偏移量包括：
     - `subscript_shift_down`: 下标相对于基线的向下偏移量。
     - `superscript_shift_up`: 上标相对于基线的向上偏移量。
     - `superscript_shift_up_cramped`: 在紧凑模式下的上标向上偏移量。
     - 以及其他与基线、最小/最大间隙等相关的参数。
   - 如果 OpenType MATH 表中没有相应的数据，则使用默认的fallback值，这些值通常基于字体大小和 x-height。

3. **布局子元素并获取度量 (LayoutAndGetMetrics):**
   - 为每个子元素（基线、上标、下标等）创建一个约束空间 (constraint space)。
   - 调用子元素的 `Layout` 方法进行布局计算。
   - 从布局结果中提取关键的度量信息，如内联大小 (inline size)、外边距 (margins)、基线位置 (ascent) 和下部高度 (descent)。

4. **执行布局 (Layout):**
   - 调用 `GatherChildren` 收集子元素。
   - 对每个子元素调用 `LayoutAndGetMetrics` 进行布局并获取度量信息。
   - 调用 `GetVerticalMetrics` 计算垂直方向的布局参数。
   - 根据计算出的参数，确定每个子元素的最终位置（偏移量）。
   - 使用 `BoxFragmentBuilder` 将布局结果添加到父元素的布局片段中。
   - 计算并设置元素的基线 (baselines)。
   - 计算元素的固有块大小 (intrinsic block size) 和最终块大小 (block size)。
   - 处理溢出内容和特殊后代元素。

5. **计算最小/最大尺寸 (ComputeMinMaxSizes):**
   - 计算元素在不同约束下的最小和最大尺寸，这对于布局引擎的尺寸调整至关重要。
   - 它会递归地计算子元素的最小/最大尺寸，并考虑上标、下标和间距的影响。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML (MathML):** 这个文件直接服务于 MathML 规范中定义的上标和下标元素的布局。当浏览器解析包含 `<msub>`, `<msup>` 等 MathML 标签的 HTML 文档时，Blink 渲染引擎会调用这个文件中的算法来确定这些元素的最终渲染位置和大小。

  **举例：** 当 HTML 中包含 `<msub><mi>a</mi><mn>1</mn></msub>` 时，`MathScriptsLayoutAlgorithm` 会负责将 `<a>` 作为基线，将 `<mn>1</mn>` 作为下标，并根据字体样式和规范将其正确地排列。

* **CSS:** CSS 样式会影响 `MathScriptsLayoutAlgorithm` 的行为。
   - **字体相关属性 (font-size, font-family 等):**  字体的大小和类型会直接影响脚本的偏移量和间距的计算。例如，更大的 `font-size` 通常会导致更大的偏移量。
   - **`math-shift` 属性:**  这个 CSS 属性 (目前在 MathML Core 中定义) 可以影响上标的垂直位置。例如，设置为 `compact` 时，上标可能会更靠近基线。`GetVerticalMetrics` 函数中可以看到对 `Style().MathShift()` 的使用。
   - **其他布局相关的 CSS 属性 (margin, padding 等):** 这些属性会影响元素的外部间距，也会被布局算法考虑在内。

  **举例：** 如果一个 MathML 元素的 CSS 中设置了 `font-size: 20px;`，那么 `GetScriptsVerticalParameters` 函数在计算默认的偏移量时，会使用这个字体大小。如果设置了 `math-shift: compact;`，则 `GetVerticalMetrics` 会使用 `superscript_shift_up_cramped` 而不是 `superscript_shift_up`。

* **JavaScript:** JavaScript 可以动态地创建、修改和操作包含 MathML 的 HTML 结构。当 JavaScript 修改了 MathML 元素的结构或样式时，Blink 渲染引擎会重新运行布局过程，包括调用 `MathScriptsLayoutAlgorithm`。

  **举例：**  一个 JavaScript 脚本可能会创建一个新的 MathML 公式，其中包含上标和下标，并将其添加到 DOM 中。浏览器会触发布局，`MathScriptsLayoutAlgorithm` 会负责正确地排列新添加的元素。另一个例子是，JavaScript 可以动态修改 MathML 元素的 CSS 样式，例如改变字体大小，这将导致布局引擎重新计算上标和下标的位置。

**逻辑推理的假设输入与输出：**

假设有以下 MathML 代码片段和一些简化的样式：

**假设输入 (MathML):**

```html
<math>
  <mi>x</mi>
  <msubsup>
    <mi>y</mi>
    <mn>2</mn>
    <mn>3</mn>
  </msubsup>
</math>
```

**假设样式 (CSS，简化):**

```css
math { font-size: 16px; }
```

**逻辑推理和假设输出:**

1. **GatherChildren:**
   - 基线元素 (base): `<mi>x</mi>`
   - 带上下标的元素: `<msubsup>`
     - 基线元素 (inner base): `<mi>y</mi>`
     - 下标 (sub): `<mn>2</mn>`
     - 上标 (sup): `<mn>3</mn>`

2. **LayoutAndGetMetrics (针对 `<msubsup>` 及其子元素):**
   - 分别布局 `<mi>y</mi>`, `<mn>2</mn>`, `<mn>3</mn>`，得到它们的尺寸、基线等信息。

3. **GetVerticalMetrics (针对 `<msubsup>`):**
   - 根据字体大小 (16px) 和可能的 OpenType MATH 表信息，计算出 `subscript_shift_down`，`superscript_shift_up` 等参数。
   - 计算下标 `<mn>2</mn>` 相对于 `<mi>y</mi>` 的向下偏移量。
   - 计算上标 `<mn>3</mn>` 相对于 `<mi>y</mi>` 的向上偏移量。
   - 确保上下标之间有足够的间距 (`sub_superscript_gap_min`)。

4. **Layout (针对 `<msubsup>`):**
   - 将下标 `<mn>2</mn>` 放置在 `<mi>y</mi>` 的下方，向下偏移 `metrics.sub_shift`。
   - 将上标 `<mn>3</mn>` 放置在 `<mi>y</mi>` 的上方，向上偏移 `metrics.sup_shift`。
   - 确定 `<msubsup>` 元素的整体高度和宽度，包括基线位置。

5. **Layout (针对 `<math>`):**
   - 将 `<mi>x</mi>` 和 `<msubsup>` 水平排列。

**假设输出 (简化的布局结果):**

- `<mi>x` 的位置: (0, 假设的基线位置)
- `<msubsup>` 的位置: (width of `<mi>x>`, 假设的基线位置)
  - `<mi>y` 的位置 (相对于 `<msubsup>`): (0, 0)
  - `<mn>2` 的位置 (相对于 `<msubsup>`): (取决于 `<mi>y>` 的宽度，向下偏移 `metrics.sub_shift`)
  - `<mn>3` 的位置 (相对于 `<msubsup>`): (取决于 `<mi>y>` 的宽度，向上偏移 `metrics.sup_shift`)

**用户或编程常见的使用错误：**

1. **不正确的 MathML 结构:**  例如，`<msub>` 标签应该只有两个子元素（基线和下标）。如果提供了更多或更少的子元素，可能会导致布局错误或未定义的行为。

   **举例：** `<msub><mi>a</mi><mn>1</mn><mn>2</mn></msub>` 是错误的，因为它有三个子元素。浏览器可能会忽略多余的子元素，导致只显示 `a` 的下标为 `1`。

2. **依赖于错误的 CSS 属性来定位脚本:**  开发者可能尝试使用 `vertical-align` 等 CSS 属性来直接控制上标和下标的位置，但这通常不是 MathML 中处理脚本的正确方式。应该依赖于浏览器内置的 MathML 布局机制。

   **举例：** 尝试对 `<mn>1</mn>` (作为下标) 设置 `vertical-align: sub;` 可能不会产生预期的效果，因为 MathML 的布局已经定义了脚本的位置。

3. **动态修改 MathML 结构时未考虑布局影响:** 当使用 JavaScript 动态添加或删除 MathML 的上标或下标时，如果没有触发正确的布局更新，可能会导致显示错误。

   **举例：**  如果使用 JavaScript 动态地将一个元素添加为现有 `<mi>` 元素的子元素，并期望它自动成为下标，这不会发生。需要将其包装在 `<msub>` 标签中，并确保触发了布局更新。

4. **忽略字体对布局的影响:** 不同的字体有不同的度量值，这会影响上标和下标的布局。在不同的字体下，相同的 MathML 公式可能看起来略有不同。

   **举例：**  一个公式在一个字体下看起来间距良好，但在另一个字体下可能显得拥挤或过于分散。这是因为不同字体的 x-height、基线位置等参数不同。

理解 `math_scripts_layout_algorithm.cc` 的功能有助于开发者更好地理解 MathML 的布局机制，从而避免常见的错误，并能更有效地使用 HTML、CSS 和 JavaScript 来创建和操作数学公式。

Prompt: 
```
这是目录为blink/renderer/core/layout/mathml/math_scripts_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/mathml/math_scripts_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/mathml/math_layout_utils.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {
namespace {

using MathConstants = OpenTypeMathSupport::MathConstants;

static bool IsPrescriptDelimiter(const BlockNode& blockNode) {
  auto* node = blockNode.GetDOMNode();
  return node && IsA<MathMLElement>(node) &&
         node->HasTagName(mathml_names::kMprescriptsTag);
}

LayoutUnit GetSpaceAfterScript(const ComputedStyle& style) {
  return LayoutUnit(MathConstant(style, MathConstants::kSpaceAfterScript)
                        .value_or(style.FontSize() / 5));
}

// Describes the amount of shift to apply to the sub/sup boxes.
// Data is populated from the OpenType MATH table.
// If the OpenType MATH table is not present fallback values are used.
// https://w3c.github.io/mathml-core/#base-with-subscript
// https://w3c.github.io/mathml-core/#base-with-superscript
// https://w3c.github.io/mathml-core/#base-with-subscript-and-superscript
struct ScriptsVerticalParameters {
  STACK_ALLOCATED();

 public:
  LayoutUnit subscript_shift_down;
  LayoutUnit superscript_shift_up;
  LayoutUnit superscript_shift_up_cramped;
  LayoutUnit subscript_baseline_drop_min;
  LayoutUnit superscript_baseline_drop_max;
  LayoutUnit sub_superscript_gap_min;
  LayoutUnit superscript_bottom_min;
  LayoutUnit subscript_top_max;
  LayoutUnit superscript_bottom_max_with_subscript;
};

ScriptsVerticalParameters GetScriptsVerticalParameters(
    const ComputedStyle& style) {
  ScriptsVerticalParameters parameters;
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  if (!font_data)
    return parameters;
  auto x_height = font_data->GetFontMetrics().XHeight();
  parameters.subscript_shift_down =
      LayoutUnit(MathConstant(style, MathConstants::kSubscriptShiftDown)
                     .value_or(x_height / 3));
  parameters.superscript_shift_up =
      LayoutUnit(MathConstant(style, MathConstants::kSuperscriptShiftUp)
                     .value_or(x_height));
  parameters.superscript_shift_up_cramped =
      LayoutUnit(MathConstant(style, MathConstants::kSuperscriptShiftUpCramped)
                     .value_or(x_height));
  parameters.subscript_baseline_drop_min =
      LayoutUnit(MathConstant(style, MathConstants::kSubscriptBaselineDropMin)
                     .value_or(x_height / 2));
  parameters.superscript_baseline_drop_max =
      LayoutUnit(MathConstant(style, MathConstants::kSuperscriptBaselineDropMax)
                     .value_or(x_height / 2));
  parameters.sub_superscript_gap_min =
      LayoutUnit(MathConstant(style, MathConstants::kSubSuperscriptGapMin)
                     .value_or(style.FontSize() / 5));
  parameters.superscript_bottom_min =
      LayoutUnit(MathConstant(style, MathConstants::kSuperscriptBottomMin)
                     .value_or(x_height / 4));
  parameters.subscript_top_max =
      LayoutUnit(MathConstant(style, MathConstants::kSubscriptTopMax)
                     .value_or(4 * x_height / 5));
  parameters.superscript_bottom_max_with_subscript = LayoutUnit(
      MathConstant(style, MathConstants::kSuperscriptBottomMaxWithSubscript)
          .value_or(4 * x_height / 5));
  return parameters;
}

}  // namespace

MathScriptsLayoutAlgorithm::MathScriptsLayoutAlgorithm(
    const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params) {
  DCHECK(params.space.IsNewFormattingContext());
}

void MathScriptsLayoutAlgorithm::GatherChildren(
    BlockNode* base,
    HeapVector<SubSupPair>* sub_sup_pairs,
    BlockNode* prescripts,
    unsigned* first_prescript_index,
    BoxFragmentBuilder* container_builder) const {
  auto script_type = Node().ScriptType();
  bool number_of_scripts_is_even = true;
  sub_sup_pairs->resize(1);
  for (LayoutInputNode child = Node().FirstChild(); child;
       child = child.NextSibling()) {
    BlockNode block_child = To<BlockNode>(child);
    if (child.IsOutOfFlowPositioned()) {
      if (container_builder) {
        container_builder->AddOutOfFlowChildCandidate(
            block_child, BorderScrollbarPadding().StartOffset());
      }
      continue;
    }
    if (!*base) {
      // All scripted elements must have at least one child.
      // The first child is the base.
      *base = block_child;
      continue;
    }
    switch (script_type) {
      case MathScriptType::kSub:
      case MathScriptType::kUnder:
        // These elements must have exactly two children.
        // The second child is a postscript and there are no prescripts.
        // <msub> base subscript </msub>
        // <msup> base superscript </msup>
        DCHECK(!sub_sup_pairs->at(0).sub);
        sub_sup_pairs->at(0).sub = block_child;
        continue;
      case MathScriptType::kSuper:
      case MathScriptType::kOver:
        DCHECK(!sub_sup_pairs->at(0).sup);
        sub_sup_pairs->at(0).sup = block_child;
        continue;
      case MathScriptType::kUnderOver:
      case MathScriptType::kSubSup:
        // These elements must have exactly three children.
        // The second and third children are postscripts and there are no
        // prescripts. <msubsup> base subscript superscript </msubsup>
        if (!sub_sup_pairs->at(0).sub) {
          sub_sup_pairs->at(0).sub = block_child;
        } else {
          DCHECK(!sub_sup_pairs->at(0).sup);
          sub_sup_pairs->at(0).sup = block_child;
        }
        continue;
      case MathScriptType::kMultiscripts: {
        // The structure of mmultiscripts is specified here:
        // https://w3c.github.io/mathml-core/#prescripts-and-tensor-indices-mmultiscripts
        if (IsPrescriptDelimiter(block_child)) {
          if (!number_of_scripts_is_even || *prescripts) {
            NOTREACHED();
          }
          *first_prescript_index = sub_sup_pairs->size() - 1;
          *prescripts = block_child;
          continue;
        }
        if (!sub_sup_pairs->back().sub) {
          sub_sup_pairs->back().sub = block_child;
        } else {
          DCHECK(!sub_sup_pairs->back().sup);
          sub_sup_pairs->back().sup = block_child;
        }
        number_of_scripts_is_even = !number_of_scripts_is_even;
        if (number_of_scripts_is_even)
          sub_sup_pairs->resize(sub_sup_pairs->size() + 1);
        continue;
      }
      default:
        NOTREACHED();
    }
  }
  DCHECK(number_of_scripts_is_even);
}

// Determines ascent/descent and shift metrics depending on script type.
MathScriptsLayoutAlgorithm::VerticalMetrics
MathScriptsLayoutAlgorithm::GetVerticalMetrics(
    const ChildAndMetrics& base_metrics,
    const ChildrenAndMetrics& sub_metrics,
    const ChildrenAndMetrics& sup_metrics) const {
  ScriptsVerticalParameters parameters = GetScriptsVerticalParameters(Style());
  VerticalMetrics metrics;

  MathScriptType type = Node().ScriptType();
  if (type == MathScriptType::kSub || type == MathScriptType::kSubSup ||
      type == MathScriptType::kMultiscripts || type == MathScriptType::kUnder ||
      type == MathScriptType::kMultiscripts) {
    metrics.sub_shift =
        std::max(parameters.subscript_shift_down,
                 base_metrics.descent + parameters.subscript_baseline_drop_min);
  }
  LayoutUnit shift_up = parameters.superscript_shift_up;
  if (type == MathScriptType::kSuper || type == MathScriptType::kSubSup ||
      type == MathScriptType::kMultiscripts || type == MathScriptType::kOver ||
      type == MathScriptType::kMultiscripts) {
    if (Style().MathShift() == EMathShift::kCompact)
      shift_up = parameters.superscript_shift_up_cramped;
    metrics.sup_shift =
        std::max(shift_up, base_metrics.ascent -
                               parameters.superscript_baseline_drop_max);
  }

  switch (type) {
    case MathScriptType::kSub:
    case MathScriptType::kUnder: {
      metrics.descent = sub_metrics[0].descent;
      metrics.sub_shift =
          std::max(metrics.sub_shift,
                   sub_metrics[0].ascent - parameters.subscript_top_max);
    } break;
    case MathScriptType::kSuper:
    case MathScriptType::kOver: {
      metrics.ascent = sup_metrics[0].ascent;
      metrics.sup_shift =
          std::max(metrics.sup_shift,
                   parameters.superscript_bottom_min + sup_metrics[0].descent);
    } break;
    case MathScriptType::kMultiscripts:
    case MathScriptType::kUnderOver:
    case MathScriptType::kSubSup: {
      for (wtf_size_t idx = 0; idx < sub_metrics.size(); ++idx) {
        metrics.ascent = std::max(metrics.ascent, sup_metrics[idx].ascent);
        metrics.descent = std::max(metrics.descent, sub_metrics[idx].descent);
        LayoutUnit sub_script_shift = std::max(
            parameters.subscript_shift_down,
            base_metrics.descent + parameters.subscript_baseline_drop_min);
        sub_script_shift =
            std::max(sub_script_shift,
                     sub_metrics[idx].ascent - parameters.subscript_top_max);
        LayoutUnit sup_script_shift =
            std::max(shift_up, base_metrics.ascent -
                                   parameters.superscript_baseline_drop_max);
        sup_script_shift =
            std::max(sup_script_shift, parameters.superscript_bottom_min +
                                           sup_metrics[idx].descent);

        LayoutUnit sub_super_script_gap =
            (sub_script_shift - sub_metrics[idx].ascent) +
            (sup_script_shift - sup_metrics[idx].descent);
        if (sub_super_script_gap < parameters.sub_superscript_gap_min) {
          // First, we try and push the superscript up.
          LayoutUnit delta = parameters.superscript_bottom_max_with_subscript -
                             (sup_script_shift - sup_metrics[idx].descent);
          if (delta > 0) {
            delta = std::min(delta, parameters.sub_superscript_gap_min -
                                        sub_super_script_gap);
            sup_script_shift += delta;
            sub_super_script_gap += delta;
          }
          // If that is not enough, we push the subscript down.
          if (sub_super_script_gap < parameters.sub_superscript_gap_min) {
            sub_script_shift +=
                parameters.sub_superscript_gap_min - sub_super_script_gap;
          }
        }

        metrics.sub_shift = std::max(metrics.sub_shift, sub_script_shift);
        metrics.sup_shift = std::max(metrics.sup_shift, sup_script_shift);
      }
    } break;
  }

  return metrics;
}

MathScriptsLayoutAlgorithm::ChildAndMetrics
MathScriptsLayoutAlgorithm::LayoutAndGetMetrics(BlockNode child) const {
  ChildAndMetrics child_and_metrics;
  auto constraint_space = CreateConstraintSpaceForMathChild(
      Node(), ChildAvailableSize(), GetConstraintSpace(), child);
  child_and_metrics.result =
      child.Layout(constraint_space, nullptr /*break_token*/);
  LogicalBoxFragment fragment(
      GetConstraintSpace().GetWritingDirection(),
      To<PhysicalBoxFragment>(child_and_metrics.result->GetPhysicalFragment()));
  child_and_metrics.inline_size = fragment.InlineSize();
  child_and_metrics.margins =
      ComputeMarginsFor(constraint_space, child.Style(), GetConstraintSpace());
  child_and_metrics.ascent =
      fragment.FirstBaselineOrSynthesize(Style().GetFontBaseline());
  child_and_metrics.descent = fragment.BlockSize() - child_and_metrics.ascent +
                              child_and_metrics.margins.block_end;
  child_and_metrics.ascent += child_and_metrics.margins.block_start;
  child_and_metrics.node = child;
  return child_and_metrics;
}

const LayoutResult* MathScriptsLayoutAlgorithm::Layout() {
  DCHECK(!GetBreakToken());

  BlockNode base = nullptr;
  BlockNode prescripts = nullptr;
  wtf_size_t first_prescript_index = 0;

  HeapVector<SubSupPair> sub_sup_pairs;
  ClearCollectionScope<HeapVector<SubSupPair>> scope(&sub_sup_pairs);

  GatherChildren(&base, &sub_sup_pairs, &prescripts, &first_prescript_index,
                 &container_builder_);
  ChildrenAndMetrics sub_metrics, sup_metrics;
  ChildAndMetrics prescripts_metrics;
  if (prescripts)
    prescripts_metrics = LayoutAndGetMetrics(prescripts);
  for (auto sub_sup_pair : sub_sup_pairs) {
    if (sub_sup_pair.sub)
      sub_metrics.emplace_back(LayoutAndGetMetrics(sub_sup_pair.sub));
    if (sub_sup_pair.sup)
      sup_metrics.emplace_back(LayoutAndGetMetrics(sub_sup_pair.sup));
  }

  ChildAndMetrics base_metrics = LayoutAndGetMetrics(base);
  VerticalMetrics metrics =
      GetVerticalMetrics(base_metrics, sub_metrics, sup_metrics);

  const LayoutUnit ascent =
      std::max(base_metrics.ascent, metrics.ascent + metrics.sup_shift)
          .ClampNegativeToZero() +
      BorderScrollbarPadding().block_start;
  const LayoutUnit descent =
      std::max(base_metrics.descent, metrics.descent + metrics.sub_shift)
          .ClampNegativeToZero() +
      BorderScrollbarPadding().block_end;

  LayoutUnit base_italic_correction = std::min(
      base_metrics.inline_size, base_metrics.result->MathItalicCorrection());
  LayoutUnit inline_offset = BorderScrollbarPadding().inline_start;

  LayoutUnit space = GetSpaceAfterScript(Style());
  // Position pre scripts if needed.
  if (prescripts) {
    for (wtf_size_t idx = first_prescript_index; idx < sub_metrics.size();
         ++idx) {
      auto& sub_metric = sub_metrics[idx];
      auto& sup_metric = sup_metrics[idx];
      LayoutUnit sub_sup_pair_inline_size =
          std::max(sub_metric.inline_size, sup_metric.inline_size);
      inline_offset += space + sub_sup_pair_inline_size;
      LogicalOffset sub_offset(inline_offset - sub_metric.inline_size +
                                   sub_metric.margins.inline_start,
                               ascent + metrics.sub_shift - sub_metric.ascent +
                                   sub_metric.margins.block_start);
      container_builder_.AddResult(*sub_metric.result, sub_offset,
                                   sub_metric.margins);
      LogicalOffset sup_offset(inline_offset - sup_metric.inline_size +
                                   sup_metric.margins.inline_start,
                               ascent - metrics.sup_shift - sup_metric.ascent +
                                   sup_metric.margins.block_start);
      container_builder_.AddResult(*sup_metric.result, sup_offset,
                                   sup_metric.margins);
    }
  } else {
    first_prescript_index = std::max(sub_metrics.size(), sup_metrics.size());
  }
  inline_offset += base_metrics.margins.inline_start;
  LogicalOffset base_offset(
      inline_offset,
      ascent - base_metrics.ascent + base_metrics.margins.block_start);
  container_builder_.AddResult(*base_metrics.result, base_offset,
                               base_metrics.margins);
  if (prescripts) {
    LogicalOffset prescripts_offset(inline_offset,
                                    ascent - prescripts_metrics.ascent +
                                        prescripts_metrics.margins.block_start);
    container_builder_.AddResult(*prescripts_metrics.result, prescripts_offset,
                                 prescripts_metrics.margins);
  }
  inline_offset += base_metrics.inline_size + base_metrics.margins.inline_end;

  // Position post scripts if needed.
  for (unsigned idx = 0; idx < first_prescript_index; ++idx) {
    ChildAndMetrics sub_metric, sup_metric;
    if (idx < sub_metrics.size())
      sub_metric = sub_metrics[idx];
    if (idx < sup_metrics.size())
      sup_metric = sup_metrics[idx];

    if (sub_metric.node) {
      LogicalOffset sub_offset(
          LayoutUnit(inline_offset + sub_metric.margins.inline_start -
                     base_italic_correction)
              .ClampNegativeToZero(),
          ascent + metrics.sub_shift - sub_metric.ascent +
              sub_metric.margins.block_start);
      container_builder_.AddResult(*sub_metric.result, sub_offset,
                                   sub_metric.margins);
    }
    if (sup_metric.node) {
      LogicalOffset sup_offset(inline_offset + sup_metric.margins.inline_start,
                               ascent - metrics.sup_shift - sup_metric.ascent +
                                   sup_metric.margins.block_start);
      container_builder_.AddResult(*sup_metric.result, sup_offset,
                                   sup_metric.margins);
    }
    LayoutUnit sub_sup_pair_inline_size =
        std::max(sub_metric.inline_size, sup_metric.inline_size);
    inline_offset += space + sub_sup_pair_inline_size;
  }

  container_builder_.SetBaselines(ascent);

  LayoutUnit intrinsic_block_size = ascent + descent;

  LayoutUnit block_size = ComputeBlockSizeForFragment(
      GetConstraintSpace(), Node(), BorderPadding(), intrinsic_block_size,
      container_builder_.InitialBorderBoxSize().inline_size);

  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size);
  container_builder_.SetFragmentsTotalBlockSize(block_size);

  container_builder_.HandleOofsAndSpecialDescendants();

  return container_builder_.ToBoxFragment();
}

MinMaxSizesResult MathScriptsLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  if (auto result = CalculateMinMaxSizesIgnoringChildren(
          Node(), BorderScrollbarPadding()))
    return *result;

  BlockNode base = nullptr;
  BlockNode prescripts = nullptr;
  unsigned first_prescript_index = 0;

  HeapVector<SubSupPair> sub_sup_pairs;
  ClearCollectionScope<HeapVector<SubSupPair>> scope(&sub_sup_pairs);

  GatherChildren(&base, &sub_sup_pairs, &prescripts, &first_prescript_index);
  DCHECK_GE(sub_sup_pairs.size(), 1ul);

  MinMaxSizes sizes;
  bool depends_on_block_constraints = false;

  // TODO(layout-dev): Determine the italic-correction without calling layout
  // within ComputeMinMaxSizes, (or setup in an interoperable constraint-space).
  LayoutUnit base_italic_correction;
  const auto base_result = ComputeMinAndMaxContentContributionForMathChild(
      Style(), GetConstraintSpace(), base, ChildAvailableSize().block_size);

  sizes = base_result.sizes;
  depends_on_block_constraints |= base_result.depends_on_block_constraints;

  LayoutUnit space = GetSpaceAfterScript(Style());
  switch (Node().ScriptType()) {
    case MathScriptType::kSub:
    case MathScriptType::kUnder:
    case MathScriptType::kOver:
    case MathScriptType::kSuper: {
      const BlockNode sub = sub_sup_pairs[0].sub;
      const BlockNode sup = sub_sup_pairs[0].sup;
      const auto first_post_script = sub ? sub : sup;
      const auto first_post_script_result =
          ComputeMinAndMaxContentContributionForMathChild(
              Style(), GetConstraintSpace(), first_post_script,
              ChildAvailableSize().block_size);

      sizes += first_post_script_result.sizes;
      if (sub)
        sizes -= base_italic_correction;
      sizes += space;
      depends_on_block_constraints |=
          first_post_script_result.depends_on_block_constraints;
      break;
    }
    case MathScriptType::kSubSup:
    case MathScriptType::kUnderOver:
    case MathScriptType::kMultiscripts: {
      MinMaxSizes sub_sup_pair_size;
      unsigned index = 0;
      do {
        const auto sub = sub_sup_pairs[index].sub;
        if (!sub)
          continue;
        auto sub_result = ComputeMinAndMaxContentContributionForMathChild(
            Style(), GetConstraintSpace(), sub,
            ChildAvailableSize().block_size);
        sub_result.sizes -= base_italic_correction;
        sub_sup_pair_size.Encompass(sub_result.sizes);

        const auto sup = sub_sup_pairs[index].sup;
        if (!sup)
          continue;
        const auto sup_result = ComputeMinAndMaxContentContributionForMathChild(
            Style(), GetConstraintSpace(), sup,
            ChildAvailableSize().block_size);
        sub_sup_pair_size.Encompass(sup_result.sizes);

        sizes += sub_sup_pair_size;
        sizes += space;
        depends_on_block_constraints |= sub_result.depends_on_block_constraints;
        depends_on_block_constraints |= sup_result.depends_on_block_constraints;
      } while (++index < sub_sup_pairs.size());
      break;
    }
  }

  sizes += BorderScrollbarPadding().InlineSum();
  return MinMaxSizesResult(sizes, depends_on_block_constraints);
}

}  // namespace blink

"""

```