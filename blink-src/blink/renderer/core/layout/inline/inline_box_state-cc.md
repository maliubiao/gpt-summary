Response:
My thought process to analyze the given C++ code snippet and answer the user's request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `inline_box_state.cc` file within the Chromium Blink rendering engine. They specifically want to know its relation to HTML, CSS, and JavaScript, see examples of logical reasoning, and identify common usage errors. The prompt also indicates this is part 1 of 2, so I need to focus on summarizing the functionality in this part.

2. **Identify Key Data Structures and Classes:** I scan the code for prominent class and struct definitions. The most important ones appear to be:
    * `InlineBoxState`: This seems to be the central class, holding information about an inline box.
    * `InlineLayoutStateStack`:  This likely manages a stack of `InlineBoxState` objects, reflecting the nesting of inline elements.
    * `LogicalRubyColumn`:  Seems related to ruby annotations.
    * `BoxData`:  Appears to store finalized information about inline boxes after layout.
    * `LogicalLineItems`: Likely represents the items within a line of text.

3. **Analyze the `InlineBoxState` Class:** I examine the members and methods of `InlineBoxState` to understand its purpose:
    * **Members:**  I see members related to:
        * Styling (`style`, `scaled_font`, `font`, `scaling_factor`)
        * Metrics (`metrics`, `text_metrics`, `text_top`, `text_height`)
        * Positioning (`fragment_start`)
        * Box properties (`margins`, `borders`, `padding`, `has_start_edge`, `has_end_edge`, `needs_box_fragment`)
        * SVG specific (`is_svg_text`)
        * Pending descendants (`pending_descendants`) -  Suggests handling nested elements.
    * **Methods:** I note methods for:
        * Initialization and Resetting (`InlineBoxState`, `ResetStyle`, `ResetTextMetrics`)
        * Computing text metrics (`ComputeTextMetrics`, `EnsureTextMetrics`)
        * Adjusting edges based on `text-box-edge` (`AdjustEdges`)
        * Handling font usage (`AccumulateUsedFonts`)
        * Determining text top position (`TextTop`)
        * Checking style compatibility (`CanAddTextOfStyle`)

4. **Analyze the `InlineLayoutStateStack` Class:** I look at the members and methods to understand how it manages `InlineBoxState` objects:
    * **Members:**
        * `stack_`: A vector of `InlineBoxState`, clearly the stack.
        * `box_data_list_`: Stores finalized `BoxData`.
        * `ruby_column_list_`: Manages ruby column information.
    * **Methods:** I see methods for:
        * Starting and ending the placement of inline items (`OnBeginPlaceItems`, `OnEndPlaceItems`)
        * Opening and closing tags, creating and managing `InlineBoxState` (`OnOpenTag`, `OnCloseTag`)
        * Handling block-level elements within inline context (`OnBlockInInline`)
        * Creating placeholders for box fragments (`AddBoxFragmentPlaceholder`)
        * Adding finalized box data (`AddBoxData`)
        * Handling reordering of inline items (due to bidirectional text) (`PrepareForReorder`, `UpdateAfterReorder`, `UpdateBoxDataFragmentRange`, `UpdateFragmentedBoxDataEdges`)
        * Computing inline positions (`ComputeInlinePositions`)
        * Applying baseline shifts (`ApplyBaselineShift`)

5. **Connect to HTML, CSS, and JavaScript:** Based on the identified functionalities:
    * **CSS:** The code directly deals with CSS properties like `font`, `line-height`, `text-emphasis`, `vertical-align`, `box-decoration-break`, `direction`, `margin`, `border`, `padding`, `text-box-edge`, and ruby-related properties. The `ComputedStyle` object is used extensively.
    * **HTML:** The code processes inline items, which directly correspond to inline HTML elements (like `<span>`, `<a>`, `<em>`, etc.) and text nodes. The opening and closing tag methods relate to the structure of HTML.
    * **JavaScript:**  While this particular file doesn't *directly* interact with JavaScript, it's part of the rendering pipeline that *reacts* to changes made by JavaScript. If JavaScript modifies the DOM or CSS styles, this code will be involved in re-laying out the inline content.

6. **Identify Logical Reasoning Points:**  I look for specific algorithms or decision-making processes within the code:
    * The logic in `ComputeEmphasisMarkOutsets` to calculate the space needed for emphasis marks.
    * The `ResetStyle` method's logic for handling SVG text and different `alignment-baseline` values.
    * The `ComputeTextMetrics` function's detailed calculation of font metrics, including handling emphasis marks and leading space.
    * The complex logic in `InlineLayoutStateStack` for managing the stack of boxes, handling reordering, and calculating positions.

7. **Identify Potential User/Programming Errors:** I consider common mistakes developers might make that this code handles or is affected by:
    * Incorrect CSS values for font properties or line height.
    * Mixing inline and block-level elements in ways that lead to unexpected layout.
    * Not understanding how `vertical-align` affects inline elements.
    * Issues with bidirectional text and the complexities it introduces.
    * Errors in specifying ruby annotations.

8. **Formulate Examples:** I create concrete examples to illustrate the connections to HTML, CSS, and the logical reasoning:
    * **HTML/CSS:** A simple `<span>` with CSS styling demonstrating how `InlineBoxState` stores and uses style information.
    * **Logical Reasoning:** The `ComputeEmphasisMarkOutsets` example with specific font and emphasis mark settings to show the input and output.

9. **Address the "Part 1" Constraint:**  Since this is only part 1, I focus on summarizing the *overall functionality* of the file without going into extreme detail about every single method. I leave the more detailed analysis and potential errors for part 2.

10. **Structure the Answer:**  I organize the answer into clear sections as requested by the prompt: "功能", "与javascript, html, css 的关系", "逻辑推理", "用户或者编程常见的使用错误", and "功能归纳". This makes the information easy to understand.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer to the user's request.
```c++
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/inline/line_box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/inline/line_utils.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

FontHeight ComputeEmphasisMarkOutsets(const ComputedStyle& style,
                                      const Font& font) {
  if (style.GetTextEmphasisMark() == TextEmphasisMark::kNone)
    return FontHeight::Empty();

  LayoutUnit emphasis_mark_height =
      LayoutUnit(font.EmphasisMarkHeight(style.TextEmphasisMarkString()));
  DCHECK_GE(emphasis_mark_height, LayoutUnit());
  return style.GetTextEmphasisLineLogicalSide() == LineLogicalSide::kOver
             ? FontHeight(emphasis_mark_height, LayoutUnit())
             : FontHeight(LayoutUnit(), emphasis_mark_height);
}

}  // namespace

void LogicalRubyColumn::Trace(Visitor* visitor) const {
  visitor->Trace(annotation_items);
  visitor->Trace(state_stack);
}

InlineBoxState::InlineBoxState(const InlineBoxState&& state)
    : fragment_start(state.fragment_start),
      item(state.item),
      style(state.style),
      scaled_font(state.scaled_font),
      has_scaled_font(state.has_scaled_font),
      scaling_factor(state.scaling_factor),
      metrics(state.metrics),
      text_metrics(state.text_metrics),
      text_top(state.text_top),
      text_height(state.text_height),
      alignment_type(state.alignment_type),
      has_start_edge(state.has_start_edge),
      has_end_edge(state.has_end_edge),
      margins(state.margins),
      borders(state.borders),
      padding(state.padding),
      pending_descendants(std::move(state.pending_descendants)),
      include_used_fonts(state.include_used_fonts),
      has_box_placeholder(state.has_box_placeholder),
      needs_box_fragment(state.needs_box_fragment),
      is_svg_text(state.is_svg_text) {
  font = has_scaled_font ? &scaled_font : state.font;
}

void InlineBoxState::ResetStyle(const ComputedStyle& style_ref,
                                bool is_svg,
                                const LayoutObject& layout_object) {
  style = &style_ref;
  is_svg_text = is_svg;
  if (!is_svg_text) {
    scaling_factor = 1.0f;
    has_scaled_font = false;
    font = &style->GetFont();
    return;
  }
  has_scaled_font = true;
  LayoutSVGInlineText::ComputeNewScaledFontForStyle(
      layout_object, scaling_factor, scaled_font);
  font = &scaled_font;
  switch (style_ref.AlignmentBaseline()) {
    case EAlignmentBaseline::kAuto:
    case EAlignmentBaseline::kBaseline:
      alignment_type = style_ref.GetFontBaseline();
      break;
    case EAlignmentBaseline::kBeforeEdge:
    case EAlignmentBaseline::kTextBeforeEdge:
      alignment_type = FontBaseline::kTextOverBaseline;
      break;
    case EAlignmentBaseline::kMiddle:
      alignment_type = FontBaseline::kXMiddleBaseline;
      break;
    case EAlignmentBaseline::kCentral:
      alignment_type = FontBaseline::kCentralBaseline;
      break;
    case EAlignmentBaseline::kAfterEdge:
    case EAlignmentBaseline::kTextAfterEdge:
      alignment_type = FontBaseline::kTextUnderBaseline;
      break;
    case EAlignmentBaseline::kIdeographic:
      alignment_type = FontBaseline::kIdeographicUnderBaseline;
      break;
    case EAlignmentBaseline::kAlphabetic:
      alignment_type = FontBaseline::kAlphabeticBaseline;
      break;
    case EAlignmentBaseline::kHanging:
      alignment_type = FontBaseline::kHangingBaseline;
      break;
    case EAlignmentBaseline::kMathematical:
      alignment_type = FontBaseline::kMathBaseline;
      break;
  }
}

void InlineBoxState::ComputeTextMetrics(const ComputedStyle& styleref,
                                        const Font& fontref,
                                        FontBaseline ifc_baseline) {
  const auto baseline_type =
      styleref.CssDominantBaseline() == EDominantBaseline::kAuto
          ? ifc_baseline
          : styleref.GetFontBaseline();
  if (const SimpleFontData* font_data = fontref.PrimaryFont()) {
    if (is_svg_text) {
      text_metrics =
          font_data->GetFontMetrics().GetFloatFontHeight(baseline_type);
    } else {
      text_metrics = font_data->GetFontMetrics().GetFontHeight(baseline_type);
    }
  } else {
    text_metrics = FontHeight();
  }
  text_top = -text_metrics.ascent;
  text_height = text_metrics.LineHeight();

  FontHeight emphasis_marks_outsets =
      ComputeEmphasisMarkOutsets(styleref, fontref);
  FontHeight leading_space = CalculateLeadingSpace(
      styleref.ComputedLineHeightAsFixed(fontref), text_metrics);
  if (emphasis_marks_outsets.IsEmpty()) {
    text_metrics.AddLeading(leading_space);
  } else {
    FontHeight emphasis_marks_metrics = text_metrics;
    emphasis_marks_metrics += emphasis_marks_outsets;
    text_metrics.AddLeading(leading_space);
    text_metrics.Unite(emphasis_marks_metrics);
    // TODO: Is this correct to include into text_metrics? How do we use
    // text_metrics after this point?
  }

  metrics.Unite(text_metrics);

  include_used_fonts = styleref.LineHeight().IsAuto();
}

void InlineBoxState::AdjustEdges(const TextBoxEdge text_box_edge,
                                 const Font& font,
                                 FontBaseline baseline_type,
                                 bool should_apply_over,
                                 bool should_apply_under,
                                 FontHeight& metrics) {
  DCHECK(should_apply_over || should_apply_under);
  const SimpleFontData* font_data = font.PrimaryFont();
  if (!font_data) [[unlikely]] {
    return;
  }
  const FontMetrics& font_metrics = font_data->GetFontMetrics();
  if (should_apply_over) {
    switch (text_box_edge.Over()) {
      case TextBoxEdge::Type::kAuto:
        // `text-box-edge: auto` copies the value from `line-fit-edge`, which
        // isn't implemented yet. Behaves the same as `text` when
        // `line-fit-edge` has the initial value.
      case TextBoxEdge::Type::kText:
        metrics.ascent = font_metrics.FixedAscent(baseline_type);
        break;
      case TextBoxEdge::Type::kCap:
        metrics.ascent = font_metrics.FixedCapHeight(baseline_type);
        break;
      case TextBoxEdge::Type::kEx:
        metrics.ascent = font_metrics.FixedXHeight(baseline_type);
        break;
      case TextBoxEdge::Type::kAlphabetic:
        NOTREACHED();
    }
  }

  if (should_apply_under) {
    switch (text_box_edge.Under()) {
      case TextBoxEdge::Type::kAuto:
        // `text-box-edge: auto` copies the value from `line-fit-edge`, which
        // isn't implemented yet. Behaves the same as `text` when
        // `line-fit-edge` has the initial value.
      case TextBoxEdge::Type::kText:
        metrics.descent = font_metrics.FixedDescent(baseline_type);
        break;
      case TextBoxEdge::Type::kAlphabetic:
        // `FixedAlphabetic()` returns a value in the ascent coordinates. Negate
        // it when applying to descent.
        metrics.descent = -font_metrics.FixedAlphabetic(baseline_type);
        break;
      case TextBoxEdge::Type::kCap:
      case TextBoxEdge::Type::kEx:
        NOTREACHED();
    }
  }
}

void InlineBoxState::ResetTextMetrics() {
  metrics = text_metrics = FontHeight::Empty();
  text_top = text_height = LayoutUnit();
}

void InlineBoxState::EnsureTextMetrics(const ComputedStyle& styleref,
                                       const Font& fontref,
                                       FontBaseline ifc_baseline) {
  if (text_metrics.IsEmpty())
    ComputeTextMetrics(styleref, fontref, ifc_baseline);
}

void InlineBoxState::AccumulateUsedFonts(const ShapeResultView* shape_result) {
  const auto baseline_type = style->GetFontBaseline();
  HeapHashSet<Member<const SimpleFontData>> used_fonts =
      shape_result->UsedFonts();
  ClearCollectionScope clear_scope(&used_fonts);
  for (const auto& used_font : used_fonts) {
    FontHeight used_metrics =
        used_font->GetFontMetrics().GetFontHeight(baseline_type);
    FontHeight leading_space = CalculateLeadingSpace(
        used_font->GetFontMetrics().FixedLineSpacing(), used_metrics);
    used_metrics.AddLeading(leading_space);
    metrics.Unite(used_metrics);
  }
}

LayoutUnit InlineBoxState::TextTop(FontBaseline baseline_type) const {
  if (!text_metrics.IsEmpty())
    return text_top;
  if (const SimpleFontData* font_data = font->PrimaryFont())
    return -font_data->GetFontMetrics().FixedAscent(baseline_type);
  NOTREACHED();
}

bool InlineBoxState::CanAddTextOfStyle(const ComputedStyle& text_style) const {
  if (text_style.VerticalAlign() != EVerticalAlign::kBaseline)
    return false;
  DCHECK(style);
  if (style == &text_style || &style->GetFont() == &text_style.GetFont() ||
      style->GetFont().PrimaryFont() == text_style.GetFont().PrimaryFont())
    return true;
  return false;
}

void InlineLayoutStateStack::Trace(Visitor* visitor) const {
  visitor->Trace(stack_);
  visitor->Trace(box_data_list_);
  visitor->Trace(ruby_column_list_);
}

InlineBoxState* InlineLayoutStateStack::OnBeginPlaceItems(
    const InlineNode node,
    const ComputedStyle& line_style,
    FontBaseline baseline_type,
    bool line_height_quirk,
    LogicalLineItems* line_box) {
  has_block_in_inline_ = false;
  is_svg_text_ = node.IsSvgText();
  if (stack_.empty()) {
    // For the first line, push a box state for the line itself.
    stack_.resize(1);
    InlineBoxState* box = &stack_.back();
    box->fragment_start = 0;
  } else {
    // For the following lines, clear states that are not shared across lines.
    for (InlineBoxState& box : stack_) {
      box.fragment_start = line_box->size();
      if (box.needs_box_fragment) {
        DCHECK_NE(&box, stack_.data());
        AddBoxFragmentPlaceholder(&box, line_box, baseline_type);
      }
      if (!line_height_quirk)
        box.metrics = box.text_metrics;
      else
        box.ResetTextMetrics();
      if (box.has_start_edge) {
        // Existing box states are wrapped before they were closed, and hence
        // they do not have start edges, unless 'box-decoration-break: clone'.
        box.has_start_edge =
            box.needs_box_fragment &&
            box.style->BoxDecorationBreak() == EBoxDecorationBreak::kClone;
      }
      DCHECK(box.pending_descendants.empty());
    }
  }

  DCHECK(box_data_list_.empty());

  // Initialize the box state for the line box.
  InlineBoxState& line_box_state = LineBoxState();
  if (line_box_state.style != &line_style) {
    line_box_state.ResetStyle(line_style, node.IsSvgText(),
                              *node.GetLayoutBox());

    // Use a "strut" (a zero-width inline box with the element's font and
    // line height properties) as the initial metrics for the line box.
    // https://drafts.csswg.org/css2/visudet.html#strut
    if (!line_height_quirk) {
      line_box_state.ComputeTextMetrics(line_style, *line_box_state.font,
                                        baseline_type);
    }
  }

  return &stack_.back();
}

InlineBoxState* InlineLayoutStateStack::OnOpenTag(
    const ConstraintSpace& space,
    const InlineItem& item,
    const InlineItemResult& item_result,
    FontBaseline baseline_type,
    LogicalLineItems* line_box) {
  InlineBoxState* box =
      OnOpenTag(space, item, item_result, baseline_type, *line_box);
  box->needs_box_fragment = item.ShouldCreateBoxFragment();
  if (box->needs_box_fragment)
    AddBoxFragmentPlaceholder(box, line_box, baseline_type);
  return box;
}

InlineBoxState* InlineLayoutStateStack::OnOpenTag(
    const ConstraintSpace& space,
    const InlineItem& item,
    const InlineItemResult& item_result,
    FontBaseline baseline_type,
    const LogicalLineItems& line_box) {
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();
  stack_.resize(stack_.size() + 1);
  InlineBoxState* box = &stack_.back();
  box->fragment_start = line_box.size();
  box->ResetStyle(style, is_svg_text_, *item.GetLayoutObject());
  box->item = &item;
  box->has_start_edge = true;
  box->margins = item_result.margins;
  box->borders = item_result.borders;
  box->padding = item_result.padding;
  if (space.IsInsideRepeatableContent()) {
    // Avoid culled inlines when inside repeatable content (fixed-positioned
    // elements when printing and fragmented tables with headers and footers).
    // We cannot represent them correctly as culled.
    if (auto* layout_inline = DynamicTo<LayoutInline>(item.GetLayoutObject()))
      layout_inline->SetShouldCreateBoxFragment();
  }
  return box;
}

InlineBoxState* InlineLayoutStateStack::OnCloseTag(const ConstraintSpace& space,
                                                   LogicalLineItems* line_box,
                                                   InlineBoxState* box,
                                                   FontBaseline baseline_type) {
  DCHECK_EQ(box, &stack_.back());
  box->has_end_edge = true;
  EndBoxState(space, box, line_box, baseline_type);
  // TODO(kojii): When the algorithm restarts from a break token, the stack may
  // underflow. We need either synthesize a missing box state, or push all
  // parents on initialize.
  stack_.pop_back();
  return &stack_.back();
}

void InlineLayoutStateStack::OnEndPlaceItems(const ConstraintSpace& space,
                                             LogicalLineItems* line_box,
                                             FontBaseline baseline_type) {
  for (auto& box : base::Reversed(stack_)) {
    if (!box.has_end_edge && box.needs_box_fragment &&
        box.style->BoxDecorationBreak() == EBoxDecorationBreak::kClone)
      box.has_end_edge = true;
    EndBoxState(space, &box, line_box, baseline_type);
  }

  // Up to this point, the offset of inline boxes are stored in placeholder so
  // that |ApplyBaselineShift()| can compute offset for both children and boxes.
  // Copy the final offset to |box_data_list_|.
  for (BoxData& box_data : box_data_list_) {
    const LogicalLineItem& placeholder = (*line_box)[box_data.fragment_start];
    DCHECK(placeholder.IsPlaceholder());
    box_data.rect.offset = placeholder.rect.offset;
  }
}

void InlineLayoutStateStack::EndBoxState(const ConstraintSpace& space,
                                         InlineBoxState* box,
                                         LogicalLineItems* line_box,
                                         FontBaseline baseline_type) {
  if (box->needs_box_fragment)
    AddBoxData(space, box, line_box);

  PositionPending position_pending =
      ApplyBaselineShift(box, line_box, baseline_type);

  // We are done here if there is no parent box.
  if (box == stack_.data()) {
    return;
  }
  InlineBoxState& parent_box = *std::prev(box);

  // Unite the metrics to the parent box.
  if (position_pending == kPositionNotPending)
    parent_box.metrics.Unite(box->metrics);
}

void InlineLayoutStateStack::OnBlockInInline(const FontHeight& metrics,
                                             LogicalLineItems* line_box) {
  DCHECK(!has_block_in_inline_);
  has_block_in_inline_ = true;

  for (InlineBoxState& box : stack_) {
    box.metrics = metrics;
  }

  // Update the metrics in placeholders.
  const LayoutUnit line_height = metrics.LineHeight();
  for (LogicalLineItem& item : *line_box) {
    DCHECK(item.IsPlaceholder());
    item.rect.offset.block_offset = LayoutUnit();
    item.rect.size.block_size = line_height;
  }
}

// Crete a placeholder for a box fragment.
// We keep a flat list of fragments because it is more suitable for operations
// such as ApplyBaselineShift. Later, CreateBoxFragments() creates box fragments
// from placeholders.
void InlineLayoutStateStack::AddBoxFragmentPlaceholder(
    InlineBoxState* box,
    LogicalLineItems* line_box,
    FontBaseline baseline_type) {
  DCHECK(box != stack_.data() &&
         box->item->Type() != InlineItem::kAtomicInline);
  box->has_box_placeholder = true;

  LayoutUnit block_offset;
  LayoutUnit block_size;
  if (!is_empty_line_) {
    // The inline box should have the height of the font metrics without the
    // line-height property. Compute from style because |box->metrics| includes
    // the line-height property.
    FontHeight metrics;
    if (const auto* font_data = box->font->PrimaryFont()) {
      metrics =
          is_svg_text_
              ? font_data->GetFontMetrics().GetFloatFontHeight(baseline_type)
              : font_data->GetFontMetrics().GetFontHeight(baseline_type);
    }

    // Extend the block direction of the box by borders and paddings. Inline
    // direction is already included into positions in LineBreaker.
    block_offset =
        -metrics.ascent - (box->borders.line_over + box->padding.line_over);
    block_size = metrics.LineHeight() + box->borders.BlockSum() +
                 box->padding.BlockSum();
  }
  line_box->AddChild(block_offset, block_size);
  DCHECK((*line_box)[line_box->size() - 1].IsPlaceholder());
}

// Add a |BoxData|, for each close-tag that needs a box fragment.
void InlineLayoutStateStack::AddBoxData(const ConstraintSpace& space,
                                        InlineBoxState* box,
                                        LogicalLineItems* line_box) {
  DCHECK(box->needs_box_fragment);
  DCHECK(box->style);
  const ComputedStyle& style = *box->style;
  LogicalLineItem& placeholder = (*line_box)[box->fragment_start];
  DCHECK(placeholder.IsPlaceholder());
  const unsigned fragment_end = line_box->size();
  DCHECK(box->item);
  BoxData& box_data = box_data_list_.emplace_back(
      box->fragment_start, fragment_end, box->item, placeholder.Size());
  box_data.borders = box->borders;
  box_data.padding = box->padding;
  box_data.margin_line_over = box->margins.line_over;
  box_data.margin_line_under = box->margins.line_under;
  if (box->has_start_edge) {
    box_data.has_line_left_edge = true;
    box_data.margin_line_left = box->margins.inline_start;
    box_data.margin_border_padding_line_left = box->margins.inline_start +
                                               box->borders.inline_start +
                                               box->padding.inline_start;
  } else {
    box_data.borders.inline_start = LayoutUnit();
    box->padding.inline_start = LayoutUnit();
  }
  if (box->has_end_edge) {
    box_data.has_line_right_edge = true;
    box_data.margin_line_right = box->margins.inline_end;
    box_data.margin_border_padding_line_right = box->margins.inline_end +
                                                box->borders.inline_end +
                                                box->padding.inline_end;
  } else {
    box_data.borders.inline_end = LayoutUnit();
    box->padding.inline_end = LayoutUnit();
  }
  if (IsRtl(style.Direction())) {
    std::swap(box_data.has_line_left_edge, box_data.has_line_right_edge);
    std::swap(box_data.margin_line_left, box_data.margin_line_right);
    std::swap(box_data.margin_border_padding_line_left,
              box_data.margin_border_padding_line_right);
  }

  for (const auto& logical_column : ruby_column_list_) {
    // Skip a LogicalRubyColumn for which PlaceRubyAnnotation() is not done yet.
    if (!logical_column->annotation_items) {
      continue;
    }
    if (box->fragment_start <= logical_column->start_index &&
        logical_column->EndIndex() <= fragment_end) {
      if (!box_data.ruby_column_list) {
        box_data.ruby_column_list =
            MakeGarbageCollected<HeapVector<Member<LogicalRubyColumn>>>();
      }
      box_data.ruby_column_list->push_back(logical_column);
    }
  }

  DCHECK((*line_box)[box->fragment_start].IsPlaceholder());
  DCHECK_GT(fragment_end, box->fragment_start);
  if (fragment_end > box->fragment_start + 1)
    return;

  // Do not defer creating a box fragment if this is an empty inline box.
  // An empty box fragment is still flat that we do not have to defer.
  // Also, placeholders cannot be reordred if empty.
  placeholder.rect.offset.inline_offset += box_data.margin_line_left;
  placeholder.rect.offset +=
      ComputeRelativeOffsetForInline(space, *box_data.item->Style());
  LayoutUnit advance = box_data.margin_border_padding_line_left +
                       box_data.margin_border_padding_line_right;
  box_data.rect.size.inline_size =
      advance - box_data.margin_line_left - box_data.margin_line_right;
  placeholder.layout_result = box_data.CreateBoxFragment(space, line_box);
  placeholder.inline_size = advance;
  DCHECK(!placeholder.children_count);
  box_data_list_.pop_back();
}

std::optional<std::pair<LayoutUnit, LayoutUnit>>
InlineLayoutStateStack::AnnotationBoxBlockAxisMargins() const {
  if (!HasBoxFragments() || box_data_list_[0].fragment_start != 0) {
    return std::nullopt;
  }
  const BoxData& data = box_data_list_[0];
  if (data.padding.BlockSum() == LayoutUnit() &&
      data.borders.BlockSum() == LayoutUnit() &&
      data.margin_line_over == LayoutUnit() &&
      data.margin_line_under == LayoutUnit()) {
    return std::nullopt;
  }
  return std::make_pair(data.margin_line_over, data.margin_line_under);
}

void InlineLayoutStateStack::ChildInserted(unsigned index) {
  for (InlineBoxState& state : stack_) {
    if (state.fragment_start >= index)
      ++state.fragment_start;
    DCHECK(state.pending_descendants.empty());
  }
  for (BoxData& box_data : box_data_list_) {
    if (box_data.fragment_start >= index)
      ++box_data.fragment_start;
    if (box_data.fragment_end >= index)
      ++box_data.fragment_end;
  }
}

void InlineLayoutStateStack::PrepareForReorder(LogicalLineItems* line_box) {
  // There's nothing to do if no boxes.
  if (box_data_list_.empty())
    return;

  // Set indexes of BoxData to the children of the line box.
  unsigned box_data_index = 0;
  for (const BoxData& box_data : box_data_list_) {
    box_data_index++;
    DCHECK((*line_box)[box_data.fragment_start].IsPlaceholder());
    for (unsigned i = box_data.fragment_start; i < box_data.fragment_end; i++) {
      LogicalLineItem& child = (*line_box)[i];
      unsigned child_box_data_index = child.box_data_index;
      
Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_box_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/inline/line_box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/inline/line_utils.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/relative_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

FontHeight ComputeEmphasisMarkOutsets(const ComputedStyle& style,
                                      const Font& font) {
  if (style.GetTextEmphasisMark() == TextEmphasisMark::kNone)
    return FontHeight::Empty();

  LayoutUnit emphasis_mark_height =
      LayoutUnit(font.EmphasisMarkHeight(style.TextEmphasisMarkString()));
  DCHECK_GE(emphasis_mark_height, LayoutUnit());
  return style.GetTextEmphasisLineLogicalSide() == LineLogicalSide::kOver
             ? FontHeight(emphasis_mark_height, LayoutUnit())
             : FontHeight(LayoutUnit(), emphasis_mark_height);
}

}  // namespace

void LogicalRubyColumn::Trace(Visitor* visitor) const {
  visitor->Trace(annotation_items);
  visitor->Trace(state_stack);
}

InlineBoxState::InlineBoxState(const InlineBoxState&& state)
    : fragment_start(state.fragment_start),
      item(state.item),
      style(state.style),
      scaled_font(state.scaled_font),
      has_scaled_font(state.has_scaled_font),
      scaling_factor(state.scaling_factor),
      metrics(state.metrics),
      text_metrics(state.text_metrics),
      text_top(state.text_top),
      text_height(state.text_height),
      alignment_type(state.alignment_type),
      has_start_edge(state.has_start_edge),
      has_end_edge(state.has_end_edge),
      margins(state.margins),
      borders(state.borders),
      padding(state.padding),
      pending_descendants(std::move(state.pending_descendants)),
      include_used_fonts(state.include_used_fonts),
      has_box_placeholder(state.has_box_placeholder),
      needs_box_fragment(state.needs_box_fragment),
      is_svg_text(state.is_svg_text) {
  font = has_scaled_font ? &scaled_font : state.font;
}

void InlineBoxState::ResetStyle(const ComputedStyle& style_ref,
                                bool is_svg,
                                const LayoutObject& layout_object) {
  style = &style_ref;
  is_svg_text = is_svg;
  if (!is_svg_text) {
    scaling_factor = 1.0f;
    has_scaled_font = false;
    font = &style->GetFont();
    return;
  }
  has_scaled_font = true;
  LayoutSVGInlineText::ComputeNewScaledFontForStyle(
      layout_object, scaling_factor, scaled_font);
  font = &scaled_font;
  switch (style_ref.AlignmentBaseline()) {
    case EAlignmentBaseline::kAuto:
    case EAlignmentBaseline::kBaseline:
      alignment_type = style_ref.GetFontBaseline();
      break;
    case EAlignmentBaseline::kBeforeEdge:
    case EAlignmentBaseline::kTextBeforeEdge:
      alignment_type = FontBaseline::kTextOverBaseline;
      break;
    case EAlignmentBaseline::kMiddle:
      alignment_type = FontBaseline::kXMiddleBaseline;
      break;
    case EAlignmentBaseline::kCentral:
      alignment_type = FontBaseline::kCentralBaseline;
      break;
    case EAlignmentBaseline::kAfterEdge:
    case EAlignmentBaseline::kTextAfterEdge:
      alignment_type = FontBaseline::kTextUnderBaseline;
      break;
    case EAlignmentBaseline::kIdeographic:
      alignment_type = FontBaseline::kIdeographicUnderBaseline;
      break;
    case EAlignmentBaseline::kAlphabetic:
      alignment_type = FontBaseline::kAlphabeticBaseline;
      break;
    case EAlignmentBaseline::kHanging:
      alignment_type = FontBaseline::kHangingBaseline;
      break;
    case EAlignmentBaseline::kMathematical:
      alignment_type = FontBaseline::kMathBaseline;
      break;
  }
}

void InlineBoxState::ComputeTextMetrics(const ComputedStyle& styleref,
                                        const Font& fontref,
                                        FontBaseline ifc_baseline) {
  const auto baseline_type =
      styleref.CssDominantBaseline() == EDominantBaseline::kAuto
          ? ifc_baseline
          : styleref.GetFontBaseline();
  if (const SimpleFontData* font_data = fontref.PrimaryFont()) {
    if (is_svg_text) {
      text_metrics =
          font_data->GetFontMetrics().GetFloatFontHeight(baseline_type);
    } else {
      text_metrics = font_data->GetFontMetrics().GetFontHeight(baseline_type);
    }
  } else {
    text_metrics = FontHeight();
  }
  text_top = -text_metrics.ascent;
  text_height = text_metrics.LineHeight();

  FontHeight emphasis_marks_outsets =
      ComputeEmphasisMarkOutsets(styleref, fontref);
  FontHeight leading_space = CalculateLeadingSpace(
      styleref.ComputedLineHeightAsFixed(fontref), text_metrics);
  if (emphasis_marks_outsets.IsEmpty()) {
    text_metrics.AddLeading(leading_space);
  } else {
    FontHeight emphasis_marks_metrics = text_metrics;
    emphasis_marks_metrics += emphasis_marks_outsets;
    text_metrics.AddLeading(leading_space);
    text_metrics.Unite(emphasis_marks_metrics);
    // TODO: Is this correct to include into text_metrics? How do we use
    // text_metrics after this point?
  }

  metrics.Unite(text_metrics);

  include_used_fonts = styleref.LineHeight().IsAuto();
}

void InlineBoxState::AdjustEdges(const TextBoxEdge text_box_edge,
                                 const Font& font,
                                 FontBaseline baseline_type,
                                 bool should_apply_over,
                                 bool should_apply_under,
                                 FontHeight& metrics) {
  DCHECK(should_apply_over || should_apply_under);
  const SimpleFontData* font_data = font.PrimaryFont();
  if (!font_data) [[unlikely]] {
    return;
  }
  const FontMetrics& font_metrics = font_data->GetFontMetrics();
  if (should_apply_over) {
    switch (text_box_edge.Over()) {
      case TextBoxEdge::Type::kAuto:
        // `text-box-edge: auto` copies the value from `line-fit-edge`, which
        // isn't implemented yet. Behaves the same as `text` when
        // `line-fit-edge` has the initial value.
      case TextBoxEdge::Type::kText:
        metrics.ascent = font_metrics.FixedAscent(baseline_type);
        break;
      case TextBoxEdge::Type::kCap:
        metrics.ascent = font_metrics.FixedCapHeight(baseline_type);
        break;
      case TextBoxEdge::Type::kEx:
        metrics.ascent = font_metrics.FixedXHeight(baseline_type);
        break;
      case TextBoxEdge::Type::kAlphabetic:
        NOTREACHED();
    }
  }

  if (should_apply_under) {
    switch (text_box_edge.Under()) {
      case TextBoxEdge::Type::kAuto:
        // `text-box-edge: auto` copies the value from `line-fit-edge`, which
        // isn't implemented yet. Behaves the same as `text` when
        // `line-fit-edge` has the initial value.
      case TextBoxEdge::Type::kText:
        metrics.descent = font_metrics.FixedDescent(baseline_type);
        break;
      case TextBoxEdge::Type::kAlphabetic:
        // `FixedAlphabetic()` returns a value in the ascent coordinates. Negate
        // it when applying to descent.
        metrics.descent = -font_metrics.FixedAlphabetic(baseline_type);
        break;
      case TextBoxEdge::Type::kCap:
      case TextBoxEdge::Type::kEx:
        NOTREACHED();
    }
  }
}

void InlineBoxState::ResetTextMetrics() {
  metrics = text_metrics = FontHeight::Empty();
  text_top = text_height = LayoutUnit();
}

void InlineBoxState::EnsureTextMetrics(const ComputedStyle& styleref,
                                       const Font& fontref,
                                       FontBaseline ifc_baseline) {
  if (text_metrics.IsEmpty())
    ComputeTextMetrics(styleref, fontref, ifc_baseline);
}

void InlineBoxState::AccumulateUsedFonts(const ShapeResultView* shape_result) {
  const auto baseline_type = style->GetFontBaseline();
  HeapHashSet<Member<const SimpleFontData>> used_fonts =
      shape_result->UsedFonts();
  ClearCollectionScope clear_scope(&used_fonts);
  for (const auto& used_font : used_fonts) {
    FontHeight used_metrics =
        used_font->GetFontMetrics().GetFontHeight(baseline_type);
    FontHeight leading_space = CalculateLeadingSpace(
        used_font->GetFontMetrics().FixedLineSpacing(), used_metrics);
    used_metrics.AddLeading(leading_space);
    metrics.Unite(used_metrics);
  }
}

LayoutUnit InlineBoxState::TextTop(FontBaseline baseline_type) const {
  if (!text_metrics.IsEmpty())
    return text_top;
  if (const SimpleFontData* font_data = font->PrimaryFont())
    return -font_data->GetFontMetrics().FixedAscent(baseline_type);
  NOTREACHED();
}

bool InlineBoxState::CanAddTextOfStyle(const ComputedStyle& text_style) const {
  if (text_style.VerticalAlign() != EVerticalAlign::kBaseline)
    return false;
  DCHECK(style);
  if (style == &text_style || &style->GetFont() == &text_style.GetFont() ||
      style->GetFont().PrimaryFont() == text_style.GetFont().PrimaryFont())
    return true;
  return false;
}

void InlineLayoutStateStack::Trace(Visitor* visitor) const {
  visitor->Trace(stack_);
  visitor->Trace(box_data_list_);
  visitor->Trace(ruby_column_list_);
}

InlineBoxState* InlineLayoutStateStack::OnBeginPlaceItems(
    const InlineNode node,
    const ComputedStyle& line_style,
    FontBaseline baseline_type,
    bool line_height_quirk,
    LogicalLineItems* line_box) {
  has_block_in_inline_ = false;
  is_svg_text_ = node.IsSvgText();
  if (stack_.empty()) {
    // For the first line, push a box state for the line itself.
    stack_.resize(1);
    InlineBoxState* box = &stack_.back();
    box->fragment_start = 0;
  } else {
    // For the following lines, clear states that are not shared across lines.
    for (InlineBoxState& box : stack_) {
      box.fragment_start = line_box->size();
      if (box.needs_box_fragment) {
        DCHECK_NE(&box, stack_.data());
        AddBoxFragmentPlaceholder(&box, line_box, baseline_type);
      }
      if (!line_height_quirk)
        box.metrics = box.text_metrics;
      else
        box.ResetTextMetrics();
      if (box.has_start_edge) {
        // Existing box states are wrapped before they were closed, and hence
        // they do not have start edges, unless 'box-decoration-break: clone'.
        box.has_start_edge =
            box.needs_box_fragment &&
            box.style->BoxDecorationBreak() == EBoxDecorationBreak::kClone;
      }
      DCHECK(box.pending_descendants.empty());
    }
  }

  DCHECK(box_data_list_.empty());

  // Initialize the box state for the line box.
  InlineBoxState& line_box_state = LineBoxState();
  if (line_box_state.style != &line_style) {
    line_box_state.ResetStyle(line_style, node.IsSvgText(),
                              *node.GetLayoutBox());

    // Use a "strut" (a zero-width inline box with the element's font and
    // line height properties) as the initial metrics for the line box.
    // https://drafts.csswg.org/css2/visudet.html#strut
    if (!line_height_quirk) {
      line_box_state.ComputeTextMetrics(line_style, *line_box_state.font,
                                        baseline_type);
    }
  }

  return &stack_.back();
}

InlineBoxState* InlineLayoutStateStack::OnOpenTag(
    const ConstraintSpace& space,
    const InlineItem& item,
    const InlineItemResult& item_result,
    FontBaseline baseline_type,
    LogicalLineItems* line_box) {
  InlineBoxState* box =
      OnOpenTag(space, item, item_result, baseline_type, *line_box);
  box->needs_box_fragment = item.ShouldCreateBoxFragment();
  if (box->needs_box_fragment)
    AddBoxFragmentPlaceholder(box, line_box, baseline_type);
  return box;
}

InlineBoxState* InlineLayoutStateStack::OnOpenTag(
    const ConstraintSpace& space,
    const InlineItem& item,
    const InlineItemResult& item_result,
    FontBaseline baseline_type,
    const LogicalLineItems& line_box) {
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();
  stack_.resize(stack_.size() + 1);
  InlineBoxState* box = &stack_.back();
  box->fragment_start = line_box.size();
  box->ResetStyle(style, is_svg_text_, *item.GetLayoutObject());
  box->item = &item;
  box->has_start_edge = true;
  box->margins = item_result.margins;
  box->borders = item_result.borders;
  box->padding = item_result.padding;
  if (space.IsInsideRepeatableContent()) {
    // Avoid culled inlines when inside repeatable content (fixed-positioned
    // elements when printing and fragmented tables with headers and footers).
    // We cannot represent them correctly as culled.
    if (auto* layout_inline = DynamicTo<LayoutInline>(item.GetLayoutObject()))
      layout_inline->SetShouldCreateBoxFragment();
  }
  return box;
}

InlineBoxState* InlineLayoutStateStack::OnCloseTag(const ConstraintSpace& space,
                                                   LogicalLineItems* line_box,
                                                   InlineBoxState* box,
                                                   FontBaseline baseline_type) {
  DCHECK_EQ(box, &stack_.back());
  box->has_end_edge = true;
  EndBoxState(space, box, line_box, baseline_type);
  // TODO(kojii): When the algorithm restarts from a break token, the stack may
  // underflow. We need either synthesize a missing box state, or push all
  // parents on initialize.
  stack_.pop_back();
  return &stack_.back();
}

void InlineLayoutStateStack::OnEndPlaceItems(const ConstraintSpace& space,
                                             LogicalLineItems* line_box,
                                             FontBaseline baseline_type) {
  for (auto& box : base::Reversed(stack_)) {
    if (!box.has_end_edge && box.needs_box_fragment &&
        box.style->BoxDecorationBreak() == EBoxDecorationBreak::kClone)
      box.has_end_edge = true;
    EndBoxState(space, &box, line_box, baseline_type);
  }

  // Up to this point, the offset of inline boxes are stored in placeholder so
  // that |ApplyBaselineShift()| can compute offset for both children and boxes.
  // Copy the final offset to |box_data_list_|.
  for (BoxData& box_data : box_data_list_) {
    const LogicalLineItem& placeholder = (*line_box)[box_data.fragment_start];
    DCHECK(placeholder.IsPlaceholder());
    box_data.rect.offset = placeholder.rect.offset;
  }
}

void InlineLayoutStateStack::EndBoxState(const ConstraintSpace& space,
                                         InlineBoxState* box,
                                         LogicalLineItems* line_box,
                                         FontBaseline baseline_type) {
  if (box->needs_box_fragment)
    AddBoxData(space, box, line_box);

  PositionPending position_pending =
      ApplyBaselineShift(box, line_box, baseline_type);

  // We are done here if there is no parent box.
  if (box == stack_.data()) {
    return;
  }
  InlineBoxState& parent_box = *std::prev(box);

  // Unite the metrics to the parent box.
  if (position_pending == kPositionNotPending)
    parent_box.metrics.Unite(box->metrics);
}

void InlineLayoutStateStack::OnBlockInInline(const FontHeight& metrics,
                                             LogicalLineItems* line_box) {
  DCHECK(!has_block_in_inline_);
  has_block_in_inline_ = true;

  for (InlineBoxState& box : stack_) {
    box.metrics = metrics;
  }

  // Update the metrics in placeholders.
  const LayoutUnit line_height = metrics.LineHeight();
  for (LogicalLineItem& item : *line_box) {
    DCHECK(item.IsPlaceholder());
    item.rect.offset.block_offset = LayoutUnit();
    item.rect.size.block_size = line_height;
  }
}

// Crete a placeholder for a box fragment.
// We keep a flat list of fragments because it is more suitable for operations
// such as ApplyBaselineShift. Later, CreateBoxFragments() creates box fragments
// from placeholders.
void InlineLayoutStateStack::AddBoxFragmentPlaceholder(
    InlineBoxState* box,
    LogicalLineItems* line_box,
    FontBaseline baseline_type) {
  DCHECK(box != stack_.data() &&
         box->item->Type() != InlineItem::kAtomicInline);
  box->has_box_placeholder = true;

  LayoutUnit block_offset;
  LayoutUnit block_size;
  if (!is_empty_line_) {
    // The inline box should have the height of the font metrics without the
    // line-height property. Compute from style because |box->metrics| includes
    // the line-height property.
    FontHeight metrics;
    if (const auto* font_data = box->font->PrimaryFont()) {
      metrics =
          is_svg_text_
              ? font_data->GetFontMetrics().GetFloatFontHeight(baseline_type)
              : font_data->GetFontMetrics().GetFontHeight(baseline_type);
    }

    // Extend the block direction of the box by borders and paddings. Inline
    // direction is already included into positions in LineBreaker.
    block_offset =
        -metrics.ascent - (box->borders.line_over + box->padding.line_over);
    block_size = metrics.LineHeight() + box->borders.BlockSum() +
                 box->padding.BlockSum();
  }
  line_box->AddChild(block_offset, block_size);
  DCHECK((*line_box)[line_box->size() - 1].IsPlaceholder());
}

// Add a |BoxData|, for each close-tag that needs a box fragment.
void InlineLayoutStateStack::AddBoxData(const ConstraintSpace& space,
                                        InlineBoxState* box,
                                        LogicalLineItems* line_box) {
  DCHECK(box->needs_box_fragment);
  DCHECK(box->style);
  const ComputedStyle& style = *box->style;
  LogicalLineItem& placeholder = (*line_box)[box->fragment_start];
  DCHECK(placeholder.IsPlaceholder());
  const unsigned fragment_end = line_box->size();
  DCHECK(box->item);
  BoxData& box_data = box_data_list_.emplace_back(
      box->fragment_start, fragment_end, box->item, placeholder.Size());
  box_data.borders = box->borders;
  box_data.padding = box->padding;
  box_data.margin_line_over = box->margins.line_over;
  box_data.margin_line_under = box->margins.line_under;
  if (box->has_start_edge) {
    box_data.has_line_left_edge = true;
    box_data.margin_line_left = box->margins.inline_start;
    box_data.margin_border_padding_line_left = box->margins.inline_start +
                                               box->borders.inline_start +
                                               box->padding.inline_start;
  } else {
    box_data.borders.inline_start = LayoutUnit();
    box_data.padding.inline_start = LayoutUnit();
  }
  if (box->has_end_edge) {
    box_data.has_line_right_edge = true;
    box_data.margin_line_right = box->margins.inline_end;
    box_data.margin_border_padding_line_right = box->margins.inline_end +
                                                box->borders.inline_end +
                                                box->padding.inline_end;
  } else {
    box_data.borders.inline_end = LayoutUnit();
    box_data.padding.inline_end = LayoutUnit();
  }
  if (IsRtl(style.Direction())) {
    std::swap(box_data.has_line_left_edge, box_data.has_line_right_edge);
    std::swap(box_data.margin_line_left, box_data.margin_line_right);
    std::swap(box_data.margin_border_padding_line_left,
              box_data.margin_border_padding_line_right);
  }

  for (const auto& logical_column : ruby_column_list_) {
    // Skip a LogicalRubyColumn for which PlaceRubyAnnotation() is not done yet.
    if (!logical_column->annotation_items) {
      continue;
    }
    if (box->fragment_start <= logical_column->start_index &&
        logical_column->EndIndex() <= fragment_end) {
      if (!box_data.ruby_column_list) {
        box_data.ruby_column_list =
            MakeGarbageCollected<HeapVector<Member<LogicalRubyColumn>>>();
      }
      box_data.ruby_column_list->push_back(logical_column);
    }
  }

  DCHECK((*line_box)[box->fragment_start].IsPlaceholder());
  DCHECK_GT(fragment_end, box->fragment_start);
  if (fragment_end > box->fragment_start + 1)
    return;

  // Do not defer creating a box fragment if this is an empty inline box.
  // An empty box fragment is still flat that we do not have to defer.
  // Also, placeholders cannot be reordred if empty.
  placeholder.rect.offset.inline_offset += box_data.margin_line_left;
  placeholder.rect.offset +=
      ComputeRelativeOffsetForInline(space, *box_data.item->Style());
  LayoutUnit advance = box_data.margin_border_padding_line_left +
                       box_data.margin_border_padding_line_right;
  box_data.rect.size.inline_size =
      advance - box_data.margin_line_left - box_data.margin_line_right;
  placeholder.layout_result = box_data.CreateBoxFragment(space, line_box);
  placeholder.inline_size = advance;
  DCHECK(!placeholder.children_count);
  box_data_list_.pop_back();
}

std::optional<std::pair<LayoutUnit, LayoutUnit>>
InlineLayoutStateStack::AnnotationBoxBlockAxisMargins() const {
  if (!HasBoxFragments() || box_data_list_[0].fragment_start != 0) {
    return std::nullopt;
  }
  const BoxData& data = box_data_list_[0];
  if (data.padding.BlockSum() == LayoutUnit() &&
      data.borders.BlockSum() == LayoutUnit() &&
      data.margin_line_over == LayoutUnit() &&
      data.margin_line_under == LayoutUnit()) {
    return std::nullopt;
  }
  return std::make_pair(data.margin_line_over, data.margin_line_under);
}

void InlineLayoutStateStack::ChildInserted(unsigned index) {
  for (InlineBoxState& state : stack_) {
    if (state.fragment_start >= index)
      ++state.fragment_start;
    DCHECK(state.pending_descendants.empty());
  }
  for (BoxData& box_data : box_data_list_) {
    if (box_data.fragment_start >= index)
      ++box_data.fragment_start;
    if (box_data.fragment_end >= index)
      ++box_data.fragment_end;
  }
}

void InlineLayoutStateStack::PrepareForReorder(LogicalLineItems* line_box) {
  // There's nothing to do if no boxes.
  if (box_data_list_.empty())
    return;

  // Set indexes of BoxData to the children of the line box.
  unsigned box_data_index = 0;
  for (const BoxData& box_data : box_data_list_) {
    box_data_index++;
    DCHECK((*line_box)[box_data.fragment_start].IsPlaceholder());
    for (unsigned i = box_data.fragment_start; i < box_data.fragment_end; i++) {
      LogicalLineItem& child = (*line_box)[i];
      unsigned child_box_data_index = child.box_data_index;
      if (!child_box_data_index) {
        child.box_data_index = box_data_index;
        continue;
      }

      // This |box_data| has child boxes. Set up |parent_box_data_index| to
      // represent the box nesting structure.
      while (child_box_data_index != box_data_index) {
        BoxData* child_box_data = &box_data_list_[child_box_data_index - 1];
        child_box_data_index = child_box_data->parent_box_data_index;
        if (!child_box_data_index) {
          child_box_data->parent_box_data_index = box_data_index;
          break;
        }
      }
    }
  }
}

void InlineLayoutStateStack::UpdateAfterReorder(LogicalLineItems* line_box) {
  // There's nothing to do if no boxes.
  if (box_data_list_.empty())
    return;

  // Compute start/end of boxes from the children of the line box.
  // Clear start/end first.
  for (BoxData& box_data : box_data_list_)
    box_data.fragment_start = box_data.fragment_end = 0;

  // Scan children and update start/end from their box_data_index.
  HeapVector<BoxData> fragmented_boxes;
  for (unsigned index = 0; index < line_box->size();)
    index = UpdateBoxDataFragmentRange(line_box, index, &fragmented_boxes);

  // If any inline fragmentation occurred due to BiDi reorder, append them and
  // adjust box edges.
  if (!fragmented_boxes.empty()) [[unlikely]] {
    UpdateFragmentedBoxDataEdges(&fragmented_boxes);
  }

#if DCHECK_IS_ON()
  // Check all BoxData have ranges.
  for (const BoxData& box_data : box_data_list_) {
    DCHECK_NE(box_data.fragment_end, 0u);
    DCHECK_GT(box_data.fragment_end, box_data.fragment_start);
  }
  // Check all |box_data_index| were migrated to BoxData.
  for (const LogicalLineItem& child : *line_box) {
    DCHECK_EQ(child.box_data_index, 0u);
  }
#endif
}

unsigned InlineLayoutStateStack::UpdateBoxDataFragmentRange(
    LogicalLineItems* line_box,
    unsigned index,
    HeapVector<BoxData>* fragmented_boxes) {
  // Find the first line box item that should create a box fragment.
  for (; index < line_box->size(); index++) {
    LogicalLineItem* start = &(*line_box)[index];
    const unsigned box_data_index = start->box_data_index;
    if (!box_data_index)
      continue;
    // |box_data_list_[box_data_index - 1]| is the box for |start| child.
    // Avoid keeping a pointer to the |BoxData| because it maybe invalidated as
    // we add to |box_data_list_|.

    // As |box_data_index| is converted to start/end of BoxData, update
    // |box_data_index| to the parent box, or to 0 if no parent boxes.
    // This allows including this box to the nested parent box.
    start->box_data_index =
        box_data_list_[box_data_index - 1].parent_box_data_index;

    // Find the end line box item.
    const unsigned start_index = index;
    for (index++; index < line_box->size(); index++) {
      LogicalLineItem* end = &(*line_box)[index];

      // If we found another box that maybe included in this box, update it
      // first. Updating will change |end->box_data_index| so that we can
      // determine if it should be included into this box or not.
      // It also changes other BoxData, but not the one we're dealing with here
      // because the update is limited only when its |box_data_index| is lower.
      while (end->box_data_index && end->box_data_index < box_data_index) {
        UpdateBoxDataFragmentRange(line_box, index, fragmented_boxes);
      }

      if (box_data_index != end->box_data_index)
        break;
      end->box_data_index =
          box_data_list_[box_data_index - 1].parent_box_data_index;
    }

    // If this is the first range for this BoxData, set it.
    if (!box_data_list_[box_data_index - 1].fragment_end) {
      box_data_list_[box_data_index - 1].SetFragmentRange(start_index, index);
    } else {
      // This box is fragmented by BiDi reordering. Add a new BoxData for the
      // fragmented range.
      BoxData& fragmented_box = fragmented_boxes->emplace_back(
          box_data_list_[box_data_index - 1], start_index, index);
      fragmented_box.fragmented_box_data_index = box_data_index;
    }
    // If this box has parent boxes, we need to process it again.
    if (box_data_list_[box_data_index - 1].parent_box_data_index)
      return start_index;
    return index;
  }
  return index;
}

void InlineLayoutStateStack::UpdateFragmentedBoxDataEdges(
    HeapVector<BoxData>* fragmented_boxes) {
  DCHECK(!fragmented_boxes->empty());
  // Append in the descending order of |fragmented_box_data_index| because the
  // indices will change as boxes are inserted into |box_data_list_|.
  std::sort(fragmented_boxes->begin(), fragmented_boxes->end(),
            [](const BoxData& a, const BoxData& b) {
              if (a.fragmented_box_data_index != b.fragmented_box_data_index) {
                return a.fragmented_box_data_index <
                       b.fragmented_box_data_index;
              }
              DCHECK_NE(a.fragment_start, b.fragment_start);
              return a.fragment_start < b.fragment_start;
            });
  for (BoxData& fragmented_box : base::Reversed(*fragmented_boxes)) {
    // Insert the fragmented box to right after the box it was fragmented from.
    // The order in the |box_data_list_| is critical when propagating child
    // fragment data such as OOF to ancestors.
    const unsigned insert_at = fragmented_box.fragmented_box_data_index;
    DCHECK_GT(insert_at, 0u);
    fragmented_box.fragmented_box_data_index = 0;
    box_data_list_.insert(insert_at, fragmented_box);

    // Adjust box data indices by the insertion.
    for (BoxData& box_data : box_data_list_) {
      if (box_data.fragmented_box_data_index >= insert_at)
        ++box_data.fragmented_box_data_index;
    }

    // Set the index of the last fragment to the original box. This is needed to
    // update fragment edges.
    const unsigned fragmented_from = insert_at - 1;
    if (!box_data_list_[fragmented_from].fragmented_box_data_index)
      box_data_list_[fragmented_from].fragmented_box_data_index = insert_at;
  }

  // Move the line-right edge to the last fragment.
  for (BoxData& box_data : box_data_list_) {
    if (box_data.fragmented_box_data_index)
      box_data.UpdateFragmentEdges(box_data_list_);
  }
}

void InlineLayoutStateStack::BoxData::UpdateFragmentEdges(
    HeapVector<BoxData, 4>& list) {
  DCHECK(fragmented_box_data_index);

  // If this box has the right edge, move it to the last fragment.
  if (has_line_right_edge) {
    BoxData& last = list[fragmented_box_data_index];
    last.has_line_right_edge = true;
    last.margin_line_right = margin_line_right;
    last.margin_border_padding_line_right = margin_border_padding_line_right;
    last.padding.inline_end = padding.inline_end;

    has_line_right_edge = false;
    margin_line_right = margin_border_padding_line_right = padding.inline_end =
        LayoutUnit();
  }
}

LayoutUnit InlineLayoutStateStack::ComputeInlinePositions(
    LogicalLineItems* line_box,
    LayoutUnit position,
    bool ignore_box_margin_border_padding) {
  // At this point, children are in the visual order, and they have their
  // origins at (0, 0). Accumulate inline offset from left to right.
  for (LogicalLineItem& child : *line_box) {
    child.margin_line_left = child.rect.offset.inline_offset;
    child.rect.offset.inline_offset += position;
    // Box margins/boders/paddings will be processed later.
    // TODO(kojii): we could optimize this if the reordering did not occur.
    if (!child.HasFragment() && !child.IsRubyLinePlaceholder()) {
      continue;
    }
    position += child.inline_size;
  }

  if (box_data_list_.empty())
    return position;

  if (!ignore_box_margin_border_padding) {
    // Adjust child offsets for margin/border/padding of inline boxes.
    for (BoxData& box_data : box_data_list_) {
      unsigned start = box_data.fragment_start;
      unsigned end = box_data.fragment_end;
      DCHECK_GT(end, start);

      if (box_data.margin_border_padding_line_left) {
        line_box->MoveInInlineDirection(
            box_data.margin_border_padding_line_left, start, line_box->size());
        position += box_data.margin_border_padding_line_left;
      }

      if (box_data.margin_border_padding_line_right) {
        line_box->MoveInInlineDirection(
            box_data.margin_border_padding_line_right, end, line_box->size());
        position += box_data.margin_border_padding_line_right;
      }
    }
  }

  // Compute positions and sizes of inline boxes.
  //
  // Accumulate margin/border/padding of boxes for each child, to place nested
  // parent boxes relative to the leaf (text or atomic inline) child.
  struct LinePadding {
    LayoutUnit line_left;
    LayoutUnit line_right;
  };
  Vector<LinePadding, 32> accumulated_padding(line_box->size());
  for (BoxData& box_data : box_data_list_) {
    // Compute line-left and line-right edge of this box by accomodating
    // border/padding of this box and margin/border/padding of descendants
    // boxes, while accumulating its margin/border/padding.
    unsigned start = box_data.fragment_start;
    LogicalLineItem& start_child = (*line_box)[start];
    LayoutUnit line_left_offset =
        start_child.rect.offset.inline_offset - start_child.margin_line_left;
    LinePadding& start_padding = accumulated_padding[start];

    DCHECK_GT(box_data.fragment_end, start);
    unsigned last = box_data.fragment_end - 1;
    LogicalLineItem& last_child = (*line_box)[la
"""


```