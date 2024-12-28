Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. I need to:

1. **Identify the core purpose:** Analyze the code to understand its primary responsibility. The file name and included headers strongly suggest it's about laying out inline content (text, inline elements, etc.) within a line.
2. **List specific functionalities:** Detail the various tasks performed by the code, referencing key classes and methods. This includes line breaking, handling floats, relative positioning, text alignment, and more.
3. **Explain relationships to web technologies:**  Connect the code's functions to how they impact HTML, CSS, and JavaScript rendering. Provide concrete examples of how CSS properties influence the layout process.
4. **Infer logical flow:**  Where possible, deduce the sequence of operations and provide hypothetical inputs and outputs to illustrate the logic.
5. **Highlight potential errors:** Identify common pitfalls or mistakes that developers might encounter related to the functionalities implemented in this code.
6. **Focus on the provided snippet:**  Since this is "part 1",  I should only analyze the functionality present in this specific excerpt and avoid speculating about what might be in "part 2".
7. **Conclude with a concise summary:**  Reiterate the main functions of the code based on the analysis.
```
功能概述：

这段 C++ 代码文件 `inline_layout_algorithm.cc` 是 Chromium Blink 引擎中负责处理 **内联布局（inline layout）** 的核心部分。其主要功能是：

1. **将内联内容格式化成行（Line Formation）：** 它决定如何将一系列内联元素（例如文本、`<span>`、`<img>` 等）排列成一行或多行。这涉及到考虑可用宽度、换行规则、浮动元素、以及 CSS 属性的影响。

2. **处理各种内联元素：** 它可以处理不同类型的内联元素，包括普通文本、可替换元素（如图片）、行内块级元素（block-in-inline）、以及 Ruby 注释等。

3. **处理 CSS 属性对内联布局的影响：**  它解析并应用与内联布局相关的 CSS 属性，例如 `text-align`、`text-indent`、`white-space`、`float`、`line-height`、`vertical-align`、`text-overflow`、`text-wrap` 和 `text-box-trim` 等。

4. **处理浮动元素（Floats）：**  它负责将浮动元素放置在合适的位置，并确保后续的内联内容能够正确地环绕浮动元素。

5. **处理相对定位元素（Relative Positioning）：** 它会根据元素的 `position: relative` 属性及其 `top`、`right`、`bottom`、`left` 值来调整元素的位置。

6. **处理行内块级元素（Block-in-inline）：** 它能够将设置了 `display: inline-block` 或某些弹性/网格布局属性的元素作为内联元素处理，并在必要时创建独立的布局上下文。

7. **处理文本溢出（Text Overflow）：**  当一行文本超出可用宽度时，它会根据 `text-overflow` 属性的值（例如 `ellipsis`）来截断文本并显示省略号。

8. **处理 `text-wrap` 属性:** 支持 `text-wrap: balance` 和 `text-wrap: pretty` 两种更精细的换行控制，尝试生成更美观的文本布局。

9. **处理 `text-box-trim` 属性:** 允许裁剪行框的顶部或底部空白区域，以更精确地控制文本行的垂直对齐。

10. **处理 `line-clamp` 属性:**  限制文本显示的行数，并在超出限制时显示省略号。

11. **处理 Initial Letter (首字母放大):**  支持 CSS 的 `initial-letter` 属性，将段落的第一个字母放大显示。

与 JavaScript, HTML, CSS 的功能关系及举例说明：

* **HTML:**  `inline_layout_algorithm.cc` 处理的是 HTML 结构中内联元素的排列和渲染。
    * **举例：**  考虑以下 HTML 片段： `<p>This is <span>some</span> text.</p>`。该算法负责将 "This is "、`<span>some</span>` 和 " text." 这些内联内容排列在同一行（或多行，如果宽度不够）。

* **CSS:** CSS 属性直接影响 `inline_layout_algorithm.cc` 的行为。
    * **`text-align` (CSS):**  决定一行内联内容在水平方向上的对齐方式。
        * **举例：** 如果 CSS 设置 `p { text-align: center; }`，则 `ApplyTextAlign` 函数会将该行中的内联元素居中放置。
    * **`float` (CSS):**  使元素脱离正常的文档流并向左或向右浮动，其他内容会环绕它。
        * **举例：** 如果 HTML 中有 `<img style="float: left;" ...>`，`PlaceFloatingObjects` 函数会将该图片放置在左侧，并调整后续文本的位置以避免与图片重叠。
    * **`line-height` (CSS):**  设置文本行的基线之间的最小距离。
        * **举例：** `box_states_->LineBoxState().EnsureTextMetrics` 会根据 `line-height` 的值来计算行盒的高度。
    * **`text-overflow: ellipsis` (CSS):** 当文本超出容器宽度时，显示省略号。
        * **举例：** 如果一行文本太长，`LineTruncator::TruncateLine` 函数会根据此属性截断文本并添加省略号。
    * **`text-wrap: balance` (CSS):**  尝试生成行数更少且宽度更均衡的文本行。
        * **举例：** `LineBreakStrategy::Balance` 方法会被调用来尝试优化换行点，使得各行长度更接近。
    * **`text-indent` (CSS):**  设置文本块首行的缩进。
        * **举例：** `container_builder_.SetBfcLineOffset` 会根据 `text-indent` 的值调整行的起始位置。
    * **`initial-letter` (CSS):** 设置首字母的样式和大小。
        * **举例：** `PostPlaceInitialLetterBox` 函数负责放置和布局首字母放大的元素。

* **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式，从而间接地影响 `inline_layout_algorithm.cc` 的执行结果。
    * **举例：** JavaScript 可以通过修改元素的 `style` 属性来改变 `text-align` 或 `float` 的值，导致页面重新布局，并触发 `inline_layout_algorithm.cc` 重新计算内联元素的排列。

逻辑推理的假设输入与输出：

假设输入以下 HTML 和 CSS：

```html
<div style="width: 100px;">This is a long text that needs to wrap.</div>
```

* **假设输入:**
    * 可用宽度 (ConstraintSpace): 100px
    * 内联内容: 文本 "This is a long text that needs to wrap."
    * 默认字体和字号

* **逻辑推理:**
    1. `LineBreaker` 会根据可用宽度和换行规则，将文本分割成多行。
    2. `CreateLine` 会为每一行创建一个 `LogicalLineItems` 容器。
    3. `ApplyTextAlign` (假设默认 `text-align: left`) 不会做额外的水平偏移。
    4. 内联元素（文本节点）会被放置到对应的 `LogicalLineItems` 中。
    5. `box_states_->ComputeInlinePositions` 会计算每个文本片段的水平位置。
    6. 由于宽度限制，文本会被分成多行。

* **可能的输出 (部分):**
    * 第一行 `LogicalLineItems` 包含 "This is a "，inline_size 可能为 80px。
    * 第二行 `LogicalLineItems` 包含 "long text "，inline_size 可能为 70px。
    * 第三行 `LogicalLineItems` 包含 "that needs"，inline_size 可能为 75px。
    * 第四行 `LogicalLineItems` 包含 " to wrap."，inline_size 可能为 60px。

涉及用户或者编程常见的使用错误：

1. **误解 `white-space` 属性：** 开发者可能不清楚 `white-space: nowrap` 会阻止文本换行，即使容器宽度不足。这会导致文本溢出，而开发者可能期望文本自动换行。

    * **举例：** 设置了 `white-space: nowrap` 的元素，其内部的文本即使超出容器宽度也不会换行，这与默认的自动换行行为不同。

2. **浮动元素导致的布局问题：**  不正确地使用 `float` 可能会导致后续元素环绕方式不符合预期，或者父容器高度塌陷。

    * **举例：** 如果一个容器内部的所有元素都设置了 `float`，那么该容器的高度可能会变成 0，因为浮动元素脱离了正常的文档流。

3. **行高（`line-height`）设置不当：**  不合适的 `line-height` 值可能导致文本行过于拥挤或过于分散，影响可读性。

    * **举例：** 设置 `line-height: 0.8` 可能会导致文本行之间重叠。

4. **`text-overflow: ellipsis` 但没有设置 `overflow: hidden` 或 `overflow: scroll`：**  `text-overflow` 只有在元素设置了 `overflow` 且值为 `hidden` 或 `scroll` 时才生效。

    * **举例：** 如果只设置了 `text-overflow: ellipsis` 而没有设置 `overflow: hidden`，即使文本溢出也不会显示省略号。

5. **过度依赖精确的像素值进行布局：**  由于不同浏览器、不同字体和不同缩放级别可能导致渲染结果略有不同，过度依赖精确的像素值可能会导致在某些情况下布局错乱。

归纳一下它的功能：

总而言之，`blink/renderer/core/layout/inline/inline_layout_algorithm.cc` 的核心功能是**将 HTML 中的内联内容按照 CSS 规则格式化成可见的文本行**，并处理各种与内联布局相关的复杂情况，例如浮动、相对定位、文本溢出、特殊的换行需求以及 `text-box-trim` 等高级特性。它是 Blink 引擎渲染引擎中至关重要的一个组成部分，负责将文档的逻辑结构转化为可视化的布局。
```
Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_layout_algorithm.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/containers/adapters.h"
#include "base/metrics/histogram_macros.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/floats_utils.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/inline/initial_letter_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_child_layout_context.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/justification_utils.h"
#include "third_party/blink/renderer/core/layout/inline/line_box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/inline/line_breaker.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/inline/line_truncator.h"
#include "third_party/blink/renderer/core/layout/inline/line_widths.h"
#include "third_party/blink/renderer/core/layout/inline/logical_line_builder.h"
#include "third_party/blink/renderer/core/layout/inline/logical_line_container.h"
#include "third_party/blink/renderer/core/layout/inline/paragraph_line_breaker.h"
#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"
#include "third_party/blink/renderer/core/layout/inline/score_line_breaker.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/list/layout_outside_list_marker.h"
#include "third_party/blink/renderer/core/layout/list/unpositioned_list_marker.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

// This class provides hooks to switch between the default line breaker,
// `text-wrap: balance`, and `text-wrap: pretty`.
class LineBreakStrategy {
  STACK_ALLOCATED();

 public:
  LineBreakStrategy(InlineChildLayoutContext* context,
                    const InlineNode& node,
                    const ComputedStyle& block_style,
                    const InlineBreakToken* break_token,
                    const ColumnSpannerPath* column_spanner_path) {
    if (!column_spanner_path) {
      const TextWrapStyle text_wrap = block_style.GetTextWrapStyle();
      if (text_wrap == TextWrapStyle::kBalance) [[unlikely]] {
        score_line_break_context_ = context->GetScoreLineBreakContext();
        initiate_balancing_ = !break_token;
        if (initiate_balancing_) {
          DCHECK(!score_line_break_context_ ||
                 score_line_break_context_->IsActive());
          use_score_line_break_ = score_line_break_context_;
        }
      } else if (text_wrap == TextWrapStyle::kPretty) [[unlikely]] {
        score_line_break_context_ = context->GetScoreLineBreakContext();
        use_score_line_break_ =
            score_line_break_context_ && score_line_break_context_->IsActive();
      } else {
        DCHECK(ShouldWrapLineGreedy(text_wrap));
      }
    }
#if EXPENSIVE_DCHECKS_ARE_ON()
    // `ScoreLineBreakContext()` must be null if `IsScoreLineBreakDisabled()`,
    // see `NeedsOptimalInlineChildLayoutContext()`, but the opposite may not be
    // true because some callsites such as MathML don't setup the context for
    // the score line breaker.
    DCHECK(!context->GetScoreLineBreakContext() ||
           !node.IsScoreLineBreakDisabled());
    DCHECK(!use_score_line_break_ || !node.IsScoreLineBreakDisabled());
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
  }

  bool NeedsToPrepare() const {
    return initiate_balancing_ || use_score_line_break_;
  }

  void Prepare(InlineChildLayoutContext* context,
               const InlineNode& node,
               const ConstraintSpace& space,
               base::span<const LayoutOpportunity> opportunities,
               const LineLayoutOpportunity& line_opportunity,
               const LeadingFloats& leading_floats,
               const InlineBreakToken* break_token,
               ExclusionSpace* exclusion_space) {
    if (initiate_balancing_) {
      Balance(context, node, space, opportunities, line_opportunity,
              leading_floats, break_token, exclusion_space);
    } else if (use_score_line_break_) {
      Optimize(node, space, opportunities, leading_floats, break_token,
               exclusion_space);
    }
  }

  void SetupLineBreaker(InlineChildLayoutContext* context,
                        LineBreaker& line_breaker) {
    if (const std::optional<LayoutUnit>& balanced_available_width =
            context->BalancedAvailableWidth()) [[unlikely]] {
      DCHECK(!score_line_break_context_ ||
             !score_line_break_context_->CurrentLineBreakPoint());
      line_breaker.OverrideAvailableWidth(*balanced_available_width);
    } else if (score_line_break_context_) [[unlikely]] {
      if (const LineBreakPoint* break_point =
              score_line_break_context_->CurrentLineBreakPoint()) {
        line_breaker.SetBreakAt(*break_point);
      }
    }
  }

  void DidCreateLine(bool is_end_paragraph) {
    if (score_line_break_context_) [[unlikely]] {
      score_line_break_context_->DidCreateLine(is_end_paragraph);
    }
  }

 private:
  void Balance(InlineChildLayoutContext* context,
               const InlineNode& node,
               const ConstraintSpace& space,
               const base::span<const LayoutOpportunity>& opportunities,
               const LineLayoutOpportunity& line_opportunity,
               const LeadingFloats& leading_floats,
               const InlineBreakToken* break_token,
               ExclusionSpace* exclusion_space) {
    // `initiate_balancing` should have checked these conditions.
    DCHECK(!context->BalancedAvailableWidth());
    DCHECK_GT(opportunities.size(), 0u);
    DCHECK(!opportunities.back().HasShapeExclusions());
    const base::ElapsedTimer timer;

    // Try `ScoreLineBreaker` first if it's applicable.
    if (use_score_line_break_ && score_line_break_context_->IsActive()) {
      DCHECK(score_line_break_context_->GetLineBreakPoints().empty());
      DCHECK_EQ(score_line_break_context_->LineBreakPointsIndex(), 0u);
      LineWidths line_widths;
      if (line_widths.Set(node, opportunities)) {
        ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                                   exclusion_space);
        optimizer.BalanceBreakPoints(leading_floats,
                                     *score_line_break_context_);
        if (!score_line_break_context_->GetLineBreakPoints().empty()) {
          UMA_HISTOGRAM_TIMES("Renderer.Layout.TextWrapBalance",
                              timer.Elapsed());
          return;
        }
      }
      // Fallback to the bisection if `ScoreLineBreaker` failed.
    }

    // Then try the bisection algorithm.
    // Exclusions and negative inline sizes are not supported.
    if (opportunities.size() == 1 &&
        line_opportunity.AvailableInlineSize() > LayoutUnit()) {
      if (const std::optional<LayoutUnit> balanced_available_width =
              ParagraphLineBreaker::AttemptParagraphBalancing(
                  node, space, line_opportunity)) {
        context->SetBalancedAvailableWidth(balanced_available_width);
        if (score_line_break_context_) {
          score_line_break_context_->GetLineInfoList().Clear();
        }
        UMA_HISTOGRAM_TIMES("Renderer.Layout.TextWrapBalance", timer.Elapsed());
        return;
      }
    }
  }

  void Optimize(const InlineNode& node,
                const ConstraintSpace& space,
                const base::span<const LayoutOpportunity>& opportunities,
                const LeadingFloats& leading_floats,
                const InlineBreakToken* break_token,
                ExclusionSpace* exclusion_space) {
    DCHECK(score_line_break_context_->GetLineBreakPoints().empty());
    DCHECK_EQ(score_line_break_context_->LineBreakPointsIndex(), 0u);
    if (!score_line_break_context_->IsActive()) [[unlikely]] {
      return;
    }
    const base::ElapsedTimer timer;
    LineWidths line_widths;
    if (!line_widths.Set(node, opportunities, break_token)) [[unlikely]] {
      // The next line may have less opportunities that keep running, without
      // suspending the context.
      return;
    }
    ScoreLineBreaker optimizer(node, space, line_widths, break_token,
                               exclusion_space);
    optimizer.OptimalBreakPoints(leading_floats, *score_line_break_context_);
    if (score_line_break_context_->IsActive()) {
      // There are more lines until the end of a paragraph, keep looking.
      return;
    }
    if (!score_line_break_context_->GetLineBreakPoints().empty()) {
      UMA_HISTOGRAM_TIMES("Renderer.Layout.TextWrapPretty", timer.Elapsed());
    }
  }

  bool initiate_balancing_ = false;
  bool use_score_line_break_ = false;
  ScoreLineBreakContext* score_line_break_context_ = nullptr;
};

void PlaceRelativePositionedItems(const ConstraintSpace& constraint_space,
                                  LogicalLineItems* line_box) {
  for (auto& child : *line_box) {
    const auto* physical_fragment = child.GetPhysicalFragment();
    if (!physical_fragment) {
      continue;
    }
    child.rect.offset += ComputeRelativeOffsetForInline(
        constraint_space, physical_fragment->Style());
  }
}

}  // namespace

InlineLayoutAlgorithm::InlineLayoutAlgorithm(
    InlineNode inline_node,
    const ConstraintSpace& space,
    const InlineBreakToken* break_token,
    const ColumnSpannerPath* column_spanner_path,
    InlineChildLayoutContext* context)
    : LayoutAlgorithm(inline_node,
                      &inline_node.Style(),
                      space,
                      // Use LTR direction since inline layout handles bidi by
                      // itself and lays out in visual order.
                      TextDirection::kLtr,
                      break_token),
      box_states_(nullptr),
      context_(context),
      column_spanner_path_(column_spanner_path),
      baseline_type_(inline_node.Style().GetFontBaseline()),
      quirks_mode_(inline_node.GetDocument().InLineHeightQuirksMode()) {
  DCHECK(context);
}

// Define the destructor here, so that we can forward-declare more in the
// header.
InlineLayoutAlgorithm::~InlineLayoutAlgorithm() = default;

// Prepare InlineLayoutStateStack for a new line.
void InlineLayoutAlgorithm::PrepareBoxStates(
    const LineInfo& line_info,
    const InlineBreakToken* break_token) {
#if EXPENSIVE_DCHECKS_ARE_ON()
  is_box_states_from_context_ = false;
#endif

  // Use the initial box states if no break token; i.e., a line from the start.
  if (!break_token) {
    box_states_ = context_->ResetBoxStates();
    return;
  }

  // Check if the box states in InlineChildLayoutContext is valid for this line.
  // If the previous line was ::first-line, always rebuild because box states
  // have ::first-line styles.
  const HeapVector<InlineItem>& items = line_info.ItemsData().items;
  if (!break_token->UseFirstLineStyle()) {
    box_states_ = context_->BoxStatesIfValidForItemIndex(
        items, break_token->StartItemIndex());
    if (box_states_) {
#if EXPENSIVE_DCHECKS_ARE_ON()
      is_box_states_from_context_ = true;
#endif
      return;
    }
  }

  // If not, rebuild the box states for the break token.
  box_states_ = context_->ResetBoxStates();
  LogicalLineBuilder(Node(), GetConstraintSpace(), nullptr, box_states_,
                     context_)
      .RebuildBoxStates(line_info, 0u, break_token->StartItemIndex());
}

static LayoutUnit AdjustLineOffsetForHanging(LineInfo* line_info,
                                             LayoutUnit& line_offset) {
  if (IsLtr(line_info->BaseDirection()))
    return LayoutUnit();

  // If !line_info->ShouldHangTrailingSpaces(), the hang width is not considered
  // in ApplyTextAlign, and so line_offset points to where the left edge of the
  // hanging spaces should be. Since the line box rect has to start at the left
  // edge of the text instead (needed for caret positioning), we increase
  // line_offset.
  LayoutUnit hang_width = line_info->HangWidth();
  if (!line_info->ShouldHangTrailingSpaces()) {
    line_offset += hang_width;
  }

  // Now line_offset always points to where the left edge of the text should be.
  // If there are any hanging spaces, the starting position of the line must be
  // offset by the width of the hanging spaces so that the text starts at
  // line_offset.
  return -hang_width;
}

#if EXPENSIVE_DCHECKS_ARE_ON()
void InlineLayoutAlgorithm::CheckBoxStates(const LineInfo& line_info) const {
  if (!is_box_states_from_context_) {
    return;
  }
  InlineLayoutStateStack rebuilt;
  LogicalLineBuilder(Node(), GetConstraintSpace(), nullptr, &rebuilt, context_)
      .RebuildBoxStates(line_info, 0u, GetBreakToken()->StartItemIndex());
  LogicalLineItems& line_box = context_->AcquireTempLogicalLineItems();
  rebuilt.OnBeginPlaceItems(Node(), line_info.LineStyle(), baseline_type_,
                            quirks_mode_, &line_box);
  DCHECK(box_states_);
  box_states_->CheckSame(rebuilt);
  context_->ReleaseTempLogicalLineItems(line_box);
}
#endif

ALWAYS_INLINE InlineLayoutAlgorithm::LineClampState
InlineLayoutAlgorithm::GetLineClampState(const LineInfo* line_info,
                                         LayoutUnit line_box_height) const {
  const ConstraintSpace& space = GetConstraintSpace();
  LineClampData line_clamp_data = space.GetLineClampData();
  if (line_clamp_data.IsLineClampContext()) {
    if (!line_info->IsBlockInInline() && line_clamp_data.IsAtClampPoint()) {
      return LineClampState::kEllipsize;
    }
    if (line_clamp_data.ShouldHideForPaint()) {
      return LineClampState::kHide;
    }
  } else if (!line_info->IsBlockInInline() && line_info->HasOverflow() &&
             node_.GetLayoutBlockFlow()->ShouldTruncateOverflowingText()) {
    return LineClampState::kEllipsize;
  }

  return LineClampState::kShow;
}

void InlineLayoutAlgorithm::CreateLine(const LineLayoutOpportunity& opportunity,
                                       LineInfo* line_info,
                                       LogicalLineContainer* line_container) {
  LogicalLineItems* line_box = &line_container->BaseLine();
  // Apply justification before placing items, because it affects size/position
  // of items, which are needed to compute inline static positions.
  LayoutUnit line_offset_for_text_align = ApplyTextAlign(line_info);

  // Clear the current line without releasing the buffer.
  line_container->Shrink();

  LogicalLineBuilder line_builder(Node(), GetConstraintSpace(), GetBreakToken(),
                                  box_states_, context_);
  line_builder.CreateLine(line_info, line_box, this);

  const LayoutUnit hang_width = line_info->HangWidth();
  const LayoutUnit position =
      AdjustLineOffsetForHanging(line_info, line_offset_for_text_align);
  LayoutUnit inline_size = box_states_->ComputeInlinePositions(
      line_box, position, line_info->IsBlockInInline());
  if (hang_width) [[unlikely]] {
    // If we've shifted the line items the inline-size is already correct.
    if (position == LayoutUnit())
      inline_size -= hang_width;
    container_builder_.SetHangInlineSize(hang_width);
  }

  // Force an editable empty line or a line with ruby annotations to have
  // metrics, so that is has a height.
  if (line_info->HasLineEvenIfEmpty() || !box_states_->RubyColumnList().empty())
      [[unlikely]] {
    box_states_->LineBoxState().EnsureTextMetrics(
        line_info->LineStyle(), *box_states_->LineBoxState().font,
        baseline_type_);
  } else if (line_builder.InitialLetterItemResult() &&
             box_states_->LineBoxState().metrics.IsEmpty()) [[unlikely]] {
    box_states_->LineBoxState().metrics = FontHeight();
  }

  const FontHeight& line_box_metrics = box_states_->LineBoxState().metrics;

  if (Node().HasRuby() && !line_info->IsEmptyLine()) [[unlikely]] {
    std::optional<FontHeight> annotation_metrics;
    if (!box_states_->RubyColumnList().empty()) {
      HeapVector<Member<LogicalRubyColumn>>& column_list =
          box_states_->RubyColumnList();
      UpdateRubyColumnInlinePositions(*line_box, inline_size, column_list);
      RubyBlockPositionCalculator calculator;
      calculator.GroupLines(column_list)
          .PlaceLines(*line_box, line_box_metrics)
          .AddLinesTo(*line_container);
      annotation_metrics = calculator.AnnotationMetrics();
    }
    line_info->SetAnnotationBlockStartAdjustment(SetAnnotationOverflow(
        *line_info, *line_box, line_box_metrics, annotation_metrics));
  }

  // Truncate the line if:
  //  - 'text-overflow: ellipsis' is set and we *aren't* a line-clamp context.
  //  - If we've reached the line-clamp limit.
  const LineClampState line_clamp_state =
      GetLineClampState(line_info, line_box_metrics.LineHeight());
  if (line_clamp_state == LineClampState::kEllipsize) [[unlikely]] {
    DCHECK(!line_info->IsBlockInInline());
    LineTruncator truncator(*line_info);
    auto* input =
        DynamicTo<HTMLInputElement>(node_.GetLayoutBlockFlow()->GetNode());
    if (input && input->ShouldApplyMiddleEllipsis()) {
      inline_size =
          truncator.TruncateLineInTheMiddle(inline_size, line_box, box_states_);
    } else {
      inline_size = truncator.TruncateLine(inline_size, line_box, box_states_);
    }
  }

  // With the CSSLineClamp feature, if we're past the clamp point, we mark every
  // inline item in the line as hidden for paint.
  if (line_clamp_state == LineClampState::kHide) [[unlikely]] {
    container_builder_.SetIsHiddenForPaint(true);
    for (auto& child : *line_box) {
      child.is_hidden_for_paint = true;
    }
  }

  // Negative margins can make the position negative, but the inline size is
  // always positive or 0.
  inline_size = inline_size.ClampNegativeToZero();

  if (line_info->IsBlockInInline()) {
    container_builder_.SetBfcLineOffset(
        GetConstraintSpace().GetBfcOffset().line_offset);
  } else {
    // Other 'text-align' values than 'justify' move line boxes as a whole, but
    // indivisual items do not change their relative position to the line box.
    LayoutUnit bfc_line_offset =
        line_info->GetBfcOffset().line_offset + line_offset_for_text_align;

    if (IsLtr(line_info->BaseDirection()))
      bfc_line_offset += line_info->TextIndent();

    container_builder_.SetBfcLineOffset(bfc_line_offset);
  }

  if (line_builder.InitialLetterItemResult()) [[unlikely]] {
    DCHECK(!line_info->IsEmptyLine());
    // `container_builder_.BfcLineOffset()` holds left edge of current line
    // after applying `text-align` and `text-indent`.
    //
    //       *                                  *
    //       |                                  |
    //      +V------------------+          +----V---------------+
    //  LTR | this is line 1.   |     RTL  |     this is line 1.|
    //
    // Margins should be `BoxStrut` instead of `LineBoxStrut` for calculating
    // block offset. Test[1], for flipped line writing mode, verifies
    // differences between them.
    // [1]
    // https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-margins-vlr.html
    const ExclusionArea* exclusion = PostPlaceInitialLetterBox(
        line_box_metrics,
        BoxStrut(line_builder.InitialLetterItemResult()->margins,
                 line_info->LineStyle().IsFlippedLinesWritingMode()),
        line_box,
        BfcOffset(container_builder_.BfcLineOffset(),
                  line_info->GetBfcOffset().block_offset),
        line_info);
    GetExclusionSpace().Add(exclusion);
  }

  // Place out-of-flow positioned objects.
  // This adjusts the LogicalLineItem::offset member to contain
  // the static position of the OOF positioned children relative to the linebox.
  if (line_builder.HasOutOfFlowPositionedItems()) {
    DCHECK(!line_info->IsBlockInInline());
    PlaceOutOfFlowObjects(*line_info, line_box_metrics, line_box);
  }

  // Place floating objects.
  // This adjusts the  LogicalLineItem::offset member to
  // contain the position of the float relative to the linebox.
  // Additionally it will perform layout on any unpositioned floats which
  // needed the line height to correctly determine their final position.
  if (line_builder.HasFloatingItems()) {
    DCHECK(!line_info->IsBlockInInline());
    // Test[1] has a float to be pushed down to next line.
    // [1]
    // https://wpt.live/css/css-inline/initial-letter/initial-letter-floats-005.html
    PlaceFloatingObjects(line_box_metrics, opportunity,
                         line_info->ComputeBlockStartAdjustment(), line_info,
                         line_box);
  }

  // Apply any relative positioned offsets to *items* which have relative
  // positioning, (atomic-inlines, and floats). This will only move the
  // individual item.
  if (line_builder.HasRelativePositionedItems()) {
    PlaceRelativePositionedItems(GetConstraintSpace(), line_box);
  }
  for (auto annotation_line : line_container->AnnotationLineList()) {
    PlaceRelativePositionedItems(GetConstraintSpace(),
                                 annotation_line.line_items);
  }

  // Apply any relative positioned offsets to any boxes (and their children).
  box_states_->ApplyRelativePositioning(GetConstraintSpace(), line_box,
                                        nullptr);

  // Create box fragments if needed. After this point forward, |line_box| is a
  // tree structure.
  // The individual children don't move position within the |line_box|, rather
  // the children have their layout_result, fragment, (or similar) set to null,
  // creating a "hole" in the array.
  box_states_->CreateBoxFragments(GetConstraintSpace(), line_box,
                                  line_info->IsBlockInInline());
  box_states_->ClearRubyColumnList();

  // Update item index of the box states in the context.
  context_->SetItemIndex(line_info->ItemsData().items,
                         line_info->EndItemIndex());

  if (line_info->UseFirstLineStyle())
    container_builder_.SetStyleVariant(StyleVariant::kFirstLine);

  // Even if we have something in-flow, it may just be empty items that
  // shouldn't trigger creation of a line. Exit now if that's the case.
  if (line_info->IsEmptyLine())
    return;

  if (!line_box_metrics.IsEmpty())
    container_builder_.SetMetrics(line_box_metrics);

  const ConstraintSpace& space = GetConstraintSpace();
  if (space.ShouldTextBoxTrimNodeStart() || space.ShouldTextBoxTrimNodeEnd() ||
      space.ShouldTextBoxTrimFragmentainerStart() ||
      space.ShouldTextBoxTrimFragmentainerEnd() ||
      space.ShouldTextBoxTrimInsideWhenLineClamp()) [[unlikely]] {
    bool is_truncated = line_clamp_state == LineClampState::kEllipsize ||
                        space.GetLineClampData().state ==
                            LineClampData::kMeasureLinesUntilBfcOffset;
    ApplyTextBoxTrim(*line_info, is_truncated);
  }

  // |container_builder_| is already set up by |PlaceBlockInInline|.
  if (line_info->IsBlockInInline())
    return;

  // Up until this point, children are placed so that the dominant baseline is
  // at 0. Move them to the final baseline position, and set the logical top of
  // the line box to the line top.
  //
  // For SVG <text>, the block offset of the initial 'current text position'
  // should be 0. As for the inline offset, see
  // SvgTextLayoutAttributesBuilder::Build().
  //
  // For text-combine-upright:all, the block offset should be zero to make
  // combined text in 1em x 1em box.
  if (Node().IsTextCombine()) [[unlikely]] {
    // The effective size of combined text is 1em square[1]
    // [1] https://drafts.csswg.org/css-writing-modes-3/#text-combine-layout
    const auto one_em = Node().Style().ComputedFontSizeAsFixed();
    inline_size = std::min(inline_size, one_em);
  } else if (Node().IsInitialLetterBox()) [[unlikely]] {
    const FontHeight& adjusted_metrics =
        AdjustInitialLetterInTextPosition(line_box_metrics, line_box);
    if (!adjusted_metrics.IsEmpty()) {
      container_builder_.SetMetrics(adjusted_metrics);
      line_container->MoveInBlockDirection(adjusted_metrics.ascent);
    }
  } else if (!Node().IsSvgText()) [[likely]] {
    // Convert baseline relative block offset of `LogicalLineItem::rect` to
    // to line box relative block offset.
    line_container->MoveInBlockDirection(line_box_metrics.ascent);
  }

  container_builder_.SetInlineSize(inline_size);
}

void InlineLayoutAlgorithm::ApplyTextBoxTrim(LineInfo& line_info,
                                             bool is_truncated) {
  const ConstraintSpace& space = GetConstraintSpace();
  if (line_info.BlockInInlineLayoutResult()) {
    // If this is a wrapper line of a block-in-inline, any trimming takes place
    // on a line box inside that block. Nothing to do here.
    return;
  }

  const bool should_apply_start = (space.ShouldTextBoxTrimNodeStart() &&
                                   line_info.IsFirstFormattedLine()) ||
                                  space.ShouldTextBoxTrimFragmentainerStart();
  const bool should_apply_end =
      (space.ShouldTextBoxTrimNodeEnd() && !line_info.GetBreakToken()) ||
      (space.ShouldTextBoxTrimInsideWhenLineClamp() && is_truncated) ||
      space.ShouldForceTextBoxTrimEnd();
  if (!should_apply_start && !should_apply_end) {
    return;
  }

  const ComputedStyle& line_style = line_info.LineStyle();
  const bool is_flipped_line = line_style.IsFlippedLinesWritingMode();
  bool should_apply_over = should_apply_start;
  bool should_apply_under = should_apply_end;
  if (is_flipped_line) [[unlikely]] {
    should_apply_over = should_apply_end;
    should_apply_under = should_apply_start;
  }

  const FontHeight line_box_metrics = container_builder_.Metrics();
  FontHeight intrinsic_metrics = line_box_metrics;
  InlineBoxState::AdjustEdges(
      space.EffectiveTextBoxEdge(), line_style.GetFont(), baseline_type_,
      should_apply_over, should_apply_under, intrinsic_metrics);

  if (should_apply_start) {
    // Apply `text-box-trim: start` if this is the first formatted line.
    LayoutUnit offset_for_trimming_box;
    if (is_flipped_line) [[unlikely]] {
      offset_for_trimming_box =
          intrinsic_metrics.descent - line_box_metrics.descent;
    } else {
      offset_for_trimming_box =
          intrinsic_metrics.ascent - line_box_metrics.ascent;
    }
    container_builder_.SetLineBoxBfcBlockOffset(
        container_builder_.LineBoxBfcBlockOffset()
            ? offset_for_trimming_box +
                  container_builder_.LineBoxBfcBlockOffset().value()
            : offset_for_trimming_box);

    // Cancel adjusting the block start for the initial letters and Ruby
    // annotation. The use of the `text-box-trim` accepts the risk of collisions
    // for the finer control of the alignment of the body text in the block
    // direction.
    line_info.SetAnnotationBlockStartAdjustment(LayoutUnit());
    line_info.SetInitialLetterBlockStartAdjustment(LayoutUnit());
  }

  if (should_apply_end) {
    container_builder_.SetIsBlockEndTrimmableLine();
    // Ask the block layout algorithm to trim the end of the line box.
    LayoutUnit block_end_to_be_trimmed;
    if (is_flipped_line) [[unlikely]] {
      block_end_to_be_trimmed =
          line_box_metrics.ascent - intrinsic_metrics.ascent;
    } else {
      block_end_to_be_trimmed =
          line_box_metrics.descent - intrinsic_metrics.descent;
    }
    container_builder_.SetTrimBlockEndBy(block_end_to_be_trimmed);
  }
}

void InlineLayoutAlgorithm::PlaceBlockInInline(const InlineItem& item,
                                               InlineItemResult* item_result,
                                               LogicalLineItems* line_box) {
  DCHECK_EQ(item.Type(), InlineItem::kBlockInInline);
  LayoutObject* layout_object = item.GetLayoutObject();
  DCHECK(layout_object);
  DCHECK(layout_object->IsAnonymous());
  DCHECK(!layout_object->IsInline());
  DCHECK(item_result->layout_result);
  const LayoutResult& result = *item_result->layout_result;
  const auto& box_fragment =
      To<PhysicalBoxFragment>(result.GetPhysicalFragment());
  LogicalBoxFragment fragment(GetConstraintSpace().GetWritingDirection(),
                              box_fragment);

  // Setup |container_builder_|. Set it up here instead of in |CreateLine|,
  // because there should be only one block-in-inline, and we need data from the
  // |LayoutResult|.
  container_builder_.SetIsBlockInInline();
  container_builder_.SetInlineSize(fragment.InlineSize());

  container_builder_.ClampBreakAppeal(result.GetBreakAppeal());

  if (!result.IsSelfCollapsing()) {
    // Block-in-inline is wrapped in an anonymous block that has no margins.
    const FontHeight metrics = fragment.BaselineMetrics(
        /* margins */ LineBoxStrut(), baseline_type_);
    box_states_->OnBlockInInline(metrics, line_box);
  }

  end_margin_strut_ = result.EndMarginStrut();
  container_builder_.SetExclusionSpace(result.GetExclusionSpace());
  container_builder_.SetAdjoiningObjectTypes(result.GetAdjoiningObjectTypes());
  lines_until_clamp_ = result.LinesUntilClamp();
  if (box_fragment.MayHaveDescendantAboveBlockStart()) [[unlikely]] {
    container_builder_.SetMayHaveDescendantAboveBlockStart(true);
  }

  line_box->AddChild(std::move(item_result->layout_result),
                     /* offset */ LogicalOffset(), item_result->inline_size,
                     /* children_count */ 0, item.BidiLevel());
}

// Place all out-of-flow objects in |line_box_|.
void InlineLayoutAlgorithm::PlaceOutOfFlowObjects(
    const LineInfo& line_info,
    const FontHeight& line_box_metrics,
    LogicalLineItems* line_box) {
  DCHECK(line_info.IsEmptyLine() || !line_box_metrics.IsEmpty())
      << "Non-empty lines must have a valid set of linebox metrics.";

  // All children within the linebox are positioned relative to the baseline,
  // then shifted later using LineBoxFragmentBuilder::MoveInBlockDirection.
  LayoutUnit baseline_adjustment =
      line_info.IsEmptyLine() ? LayoutUnit() : -line_box_metrics.ascent;

  LayoutUnit line_height =
      line_info.IsEmptyLine() ? LayoutUnit() : line_box_metrics.LineHeight();

  // The location of the "next" line.
  //
  // This uses ConstraintSpace::Direction rather than
  // LineInfo::BaseDirection as this is for a block-level object rather than
  // an inline-level object.
  //
  // Similarly this uses the available size to determine which edge to align
  // to, and *does not* avoid floats.
  LayoutUnit block_level_line_location =
      IsLtr(GetConstraintSpace().Direction())
          ? LayoutUnit()
          : GetConstraintSpace().AvailableSize().inline_size;

  // This offset represents the position of the "next" line, relative to the
  // line we are currently creating, (this takes into account text-indent, etc).
  LayoutUnit block_level_inline_offset =
      block_level_line_location -
      (container_builder_.BfcLineOffset() -
       GetConstraintSpace().GetBfcOffset().line_offset);

  // To correctly determine which "
"""


```