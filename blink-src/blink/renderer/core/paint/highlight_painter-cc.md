Response:
My thinking process for analyzing the provided code snippet and generating the response involved several steps:

1. **Understanding the Request:** I first parsed the request to identify the core task: analyze the `highlight_painter.cc` file in the Chromium Blink engine and explain its functionality, especially its relation to web technologies (JavaScript, HTML, CSS), its internal logic (including assumptions and outputs), potential usage errors, and debugging information. The request also specified that this is the first of a two-part analysis, requiring a concluding summary of its functionality.

2. **Initial Code Scan and Keyword Identification:** I scanned the `#include` directives and the namespace declaration (`blink`) to get a high-level understanding of the code's dependencies and context within the Blink rendering engine. I noted key terms like "highlight," "paint," "selection," "marker," "text," "style," "decoration," "overlay," "cursor," and "fragment."  These keywords strongly suggested the code is responsible for visually representing highlighted text and related elements on the web page.

3. **Decomposition by Functionality:**  I started dissecting the code by looking at the defined classes and their methods. The presence of `HighlightPainter`, `SelectionPaintState`, and the various helper functions like `PaintRect` and `HasNonTrivialSpellingGrammarStyles` pointed towards different aspects of the highlighting process.

4. **Focusing on Key Classes:**

    * **`HighlightPainter`:** This is clearly the central class. I noted its constructor takes many parameters related to text rendering, styling, and selection. I observed methods like `PaintNonCssMarkers`, `PaintCase`, `ComputePaintCase`, `FastPaintSpellingGrammarDecorations`, and others. This suggested it orchestrates the painting of highlights based on different conditions.

    * **`SelectionPaintState`:**  This class seemed responsible for managing the state related to text selection, including calculating selection rectangles and applying styles. The methods like `ComputeSelectionStyle`, `PaintSelectionBackground`, and `PaintSelectedText` confirmed this.

5. **Analyzing Helper Functions:** I examined the smaller functions to understand their specific roles:

    * **`PaintRect`:**  A simple utility for drawing filled rectangles, likely for background highlights.
    * **`HasNonTrivialSpellingGrammarStyles`:** This function's complexity and specific checks against CSS properties indicated it's an optimization to avoid full overlay painting when the styles for spelling/grammar errors are simple.
    * **`TextPaintStyleForTextMatch`:** This function generates a `TextPaintStyle` for search matches, potentially overriding default text colors.
    * **`MergedHighlightPart`:**  This template suggests a mechanism for optimizing the painting of contiguous highlight sections with similar properties.

6. **Mapping to Web Technologies:** I started connecting the code elements to concepts in HTML, CSS, and JavaScript:

    * **HTML:** The code operates on `Node` objects, which represent HTML elements. The concept of text fragments directly relates to the text content within HTML elements.
    * **CSS:** The code heavily relies on `ComputedStyle` to determine how highlights should be rendered. It specifically deals with pseudo-elements like `::selection`, `::spelling-error`, and `::grammar-error`. Properties like `background-color`, `text-shadow`, `color`, `text-decoration`, etc., are explicitly mentioned.
    * **JavaScript:** While this specific file doesn't directly interact with JavaScript code, the highlighting functionality is often triggered or influenced by JavaScript actions, such as user selection, find-in-page functionality, or custom highlighting implemented through JavaScript APIs.

7. **Inferring Logic and Assumptions:** I looked for conditional statements and logic flow within the methods. For example, the `ComputePaintCase` method uses several `if` conditions to determine the optimal painting strategy based on the presence of different types of highlights and selection. I also noted the assumptions, such as the handling of SVG text and the optimizations for simple spelling/grammar error highlighting.

8. **Considering Potential Errors:** I thought about scenarios where things might go wrong. For example, incorrect or conflicting CSS styles could lead to unexpected highlight rendering. Issues with text node boundaries or incorrect offset calculations could also cause problems.

9. **Debugging Perspective:** I considered how a developer might use this code for debugging. Understanding the different painting cases and the data structures involved (like `HighlightOverlay::Layers` and `HighlightPart`) would be crucial. Tracing the flow through `ComputePaintCase` and the painting methods would help identify issues. User actions like selecting text, using the find function, or encountering spelling errors would be the starting points for debugging.

10. **Structuring the Response:** I organized the information into the categories requested: functionality, relation to web technologies, logic and assumptions, potential errors, debugging, and a summary. I used examples to illustrate the connections to HTML, CSS, and JavaScript. I provided hypothetical input and output for the logical reasoning sections.

11. **Drafting and Refining:** I wrote a first draft of the response, focusing on clarity and accuracy. I then reviewed and refined the text, ensuring that the explanations were easy to understand and that all aspects of the request were addressed. I paid attention to the distinction between different highlighting mechanisms (selection, spelling/grammar, find-in-page, custom highlights). I ensured the summary accurately reflected the detailed analysis.

This iterative process of code analysis, keyword identification, functional decomposition, mapping to web technologies, logical inference, error consideration, and structured explanation allowed me to generate a comprehensive and informative response to the request.
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/highlight_painter.h"

// ... (rest of the includes)

namespace blink {

namespace {

// ... (anonymous namespace with helper functions)

}  // namespace

HighlightPainter::SelectionPaintState::SelectionPaintState(
    const InlineCursor& containing_block,
    const PhysicalOffset& box_offset,
    const std::optional<AffineTransform> writing_mode_rotation)
    : SelectionPaintState(containing_block,
                          box_offset,
                          writing_mode_rotation,
                          containing_block.Current()
                              .GetLayoutObject()
                              ->GetDocument()
                              ->GetFrame()
                              ->Selection()) {}
HighlightPainter::SelectionPaintState::SelectionPaintState(
    const InlineCursor& containing_block,
    const PhysicalOffset& box_offset,
    const std::optional<AffineTransform> writing_mode_rotation,
    const FrameSelection& frame_selection)
    : selection_status_(
          frame_selection.ComputeLayoutSelectionStatus(containing_block)),
      state_(frame_selection.ComputePaintingSelectionStateForCursor(
          containing_block.Current())),
      containing_block_(containing_block),
      box_offset_(box_offset),
      writing_mode_rotation_(writing_mode_rotation) {}

void HighlightPainter::SelectionPaintState::ComputeSelectionStyle(
    const Document& document,
    const ComputedStyle& style,
    Node* node,
    const PaintInfo& paint_info,
    const TextPaintStyle& text_style) {
  const ComputedStyle* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
      node, style, kPseudoIdSelection);
  selection_style_ = HighlightStyleUtils::HighlightPaintingStyle(
      document, style, pseudo_style, node, kPseudoIdSelection, text_style,
      paint_info, SearchTextIsActiveMatch::kNo);
  paint_selected_text_only_ =
      (paint_info.phase == PaintPhase::kSelectionDragImage);
}

void HighlightPainter::SelectionPaintState::ComputeSelectionRectIfNeeded() {
  if (!selection_rect_) {
    PhysicalRect physical =
        containing_block_.CurrentLocalSelectionRectForText(selection_status_);
    physical.offset += box_offset_;
    LineRelativeRect rotated =
        LineRelativeRect::Create(physical, writing_mode_rotation_);
    selection_rect_.emplace(SelectionRect{physical, rotated});
  }
}

const PhysicalRect&
HighlightPainter::SelectionPaintState::PhysicalSelectionRect() {
  ComputeSelectionRectIfNeeded();
  return selection_rect_->physical;
}

const LineRelativeRect&
HighlightPainter::SelectionPaintState::LineRelativeSelectionRect() {
  ComputeSelectionRectIfNeeded();
  return selection_rect_->rotated;
}

// |selection_start| and |selection_end| should be between
// [text_fragment.StartOffset(), text_fragment.EndOffset()].
void HighlightPainter::SelectionPaintState::PaintSelectionBackground(
    GraphicsContext& context,
    Node* node,
    const Document& document,
    const ComputedStyle& style,
    const std::optional<AffineTransform>& rotation) {
  const Color color = HighlightStyleUtils::HighlightBackgroundColor(
      document, style, node, selection_style_.style.current_color,
      kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
  HighlightPainter::PaintHighlightBackground(context, style, color,
                                             PhysicalSelectionRect(), rotation);
}

// Paint the selected text only.
void HighlightPainter::SelectionPaintState::PaintSelectedText(
    TextPainter& text_painter,
    const TextFragmentPaintInfo& fragment_paint_info,
    const TextPaintStyle& text_style,
    DOMNodeId node_id,
    const AutoDarkMode& auto_dark_mode) {
  text_painter.PaintSelectedText(fragment_paint_info, selection_status_.start,
                                 selection_status_.end, text_style,
                                 selection_style_.style, LineRelativeSelectionRect(),
                                 node_id, auto_dark_mode);
}

// Paint the given text range in the given style, suppressing the text proper
// (painting shadows only) where selected.
void HighlightPainter::SelectionPaintState::
    PaintSuppressingTextProperWhereSelected(
        TextPainter& text_painter,
        const TextFragmentPaintInfo& fragment_paint_info,
        const TextPaintStyle& text_style,
        DOMNodeId node_id,
        const AutoDarkMode& auto_dark_mode) {
  // First paint the shadows for the whole range.
  if (text_style.shadow) {
    text_painter.Paint(fragment_paint_info, text_style, node_id, auto_dark_mode,
                       TextPainter::kShadowsOnly);
  }

  // Then paint the text proper for any unselected parts in storage order, so
  // that they’re always on top of the shadows.
  if (fragment_paint_info.from < selection_status_.start) {
    text_painter.Paint(
        fragment_paint_info.WithEndOffset(selection_status_.start), text_style,
        node_id, auto_dark_mode, TextPainter::kTextProperOnly);
  }
  if (selection_status_.end < fragment_paint_info.to) {
    text_painter.Paint(
        fragment_paint_info.WithStartOffset(selection_status_.end), text_style,
        node_id, auto_dark_mode, TextPainter::kTextProperOnly);
  }
}

// GetNode() for first-letter fragment returns null because it is anonymous.
// Use AssociatedTextNode() of LayoutTextFragment to get the associated node.
static Node* AssociatedNode(const LayoutObject* layout_object) {
  if (RuntimeEnabledFeatures::PaintHighlightsForFirstLetterEnabled()) {
    if (auto* layout_text_fragment =
            DynamicTo<LayoutTextFragment>(layout_object)) {
      return layout_text_fragment->AssociatedTextNode();
    }
  }
  return layout_object->GetNode();
}

HighlightPainter::HighlightPainter(
    const TextFragmentPaintInfo& fragment_paint_info,
    TextPainter& text_painter,
    TextDecorationPainter& decoration_painter,
    const PaintInfo& paint_info,
    const InlineCursor& cursor,
    const FragmentItem& fragment_item,
    const PhysicalOffset& box_origin,
    const ComputedStyle& style,
    const TextPaintStyle& text_style,
    SelectionPaintState* selection)
    : fragment_paint_info_(fragment_paint_info),
      text_painter_(text_painter),
      decoration_painter_(decoration_painter),
      paint_info_(paint_info),
      cursor_(cursor),
      root_inline_cursor_(cursor),
      fragment_item_(fragment_item),
      box_origin_(box_origin),
      originating_style_(style),
      originating_text_style_(text_style),
      selection_(selection),
      layout_object_(fragment_item_.GetLayoutObject()),
      node_(AssociatedNode(layout_object_)),
      foreground_auto_dark_mode_(
          PaintAutoDarkMode(originating_style_,
                            DarkModeFilter::ElementRole::kForeground)),
      background_auto_dark_mode_(
          PaintAutoDarkMode(originating_style_,
                            DarkModeFilter::ElementRole::kBackground)) {
  root_inline_cursor_.ExpandRootToContainingBlock();

  // Custom highlights and marker-based highlights are defined in terms of
  // DOM ranges in a Text node. Generated text either has no Text node or does
  // not derive its content from the Text node (e.g. ellipsis, soft hyphens).
  // TODO(crbug.com/17528) handle ::first-letter
  if (!fragment_item_.IsGeneratedText()) {
    const auto* text_node = DynamicTo<Text>(node_);
    if (text_node) {
      DocumentMarkerController& controller = node_->GetDocument().Markers();
      if (controller.HasAnyMarkersForText(*text_node)) {
        fragment_dom_offsets_ = GetFragmentDOMOffsets(
            *text_node, fragment_paint_info_.from, fragment_paint_info_.to);
        DCHECK(fragment_dom_offsets_);
        markers_ = controller.ComputeMarkersToPaint(*text_node);
        if (RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled() &&
            !fragment_item_.IsSvgText()) {
          search_ = controller.MarkersFor(
              *text_node, DocumentMarker::kTextMatch,
              fragment_dom_offsets_->start, fragment_dom_offsets_->end);
        }
        target_ = controller.MarkersFor(
            *text_node, DocumentMarker::kTextFragment,
            fragment_dom_offsets_->start, fragment_dom_offsets_->end);
        spelling_ = controller.MarkersFor(*text_node, DocumentMarker::kSpelling,
                                          fragment_dom_offsets_->start,
                                          fragment_dom_offsets_->end);
        grammar_ = controller.MarkersFor(*text_node, DocumentMarker::kGrammar,
                                         fragment_dom_offsets_->start,
                                         fragment_dom_offsets_->end);
        custom_ = controller.MarkersFor(
            *text_node, DocumentMarker::kCustomHighlight,
            fragment_dom_offsets_->start, fragment_dom_offsets_->end);
      } else if (selection) {
        fragment_dom_offsets_ = GetFragmentDOMOffsets(
            *text_node, fragment_paint_info_.from, fragment_paint_info_.to);
      }
    }
  }

  paint_case_ = ComputePaintCase();

  // |layers_| and |parts_| are only needed when using the full overlay
  // painting algorithm, otherwise we can leave them empty.
  if (paint_case_ == kOverlay) {
    auto* selection_status = GetSelectionStatus(selection_);
    layers_ = HighlightOverlay::ComputeLayers(
        layout_object_->GetDocument(), node_, originating_style_,
        originating_text_style_, paint_info_, selection_status, custom_,
        grammar_, spelling_, target_, search_);
    Vector<HighlightEdge> edges = HighlightOverlay::ComputeEdges(
        node_, fragment_item_.IsGeneratedText(), fragment_dom_offsets_, layers_,
        selection_status, custom_, grammar_, spelling_, target_, search_);
    parts_ =
        HighlightOverlay::ComputeParts(fragment_paint_info_, layers_, edges);

    if (!parts_.empty()) {
      if (const ShapeResultView* shape_result_view =
              fragment_item_->TextShapeResult()) {
        const ShapeResult* shape_result =
            shape_result_view->CreateShapeResult();
        unsigned start_offset = fragment_item_->StartOffset();
        edges_info_.push_back(HighlightEdgeInfo{
            parts_[0].range.from,
            shape_result->CaretPositionForOffset(
                parts_[0].range.from - start_offset, cursor_.CurrentText())});
        for (const HighlightPart& part : parts_) {
          edges_info_.push_back(HighlightEdgeInfo{
              part.range.to,
              shape_result->CaretPositionForOffset(part.range.to - start_offset,
                                                   cursor_.CurrentText())});
        }
      } else {
        edges_info_.push_back(HighlightEdgeInfo{
            parts_[0].range.from,
            fragment_item_
                .CaretInlinePositionForOffset(cursor_.CurrentText(),
                                              parts_[0].range.from)
                .ToFloat()});
        for (const HighlightPart& part : parts_) {
          edges_info_.push_back(HighlightEdgeInfo{
              part.range.to, fragment_item_
                                 .CaretInlinePositionForOffset(
                                     cursor_.CurrentText(), part.range.to)
                                 .ToFloat()});
        }
      }
    }
  }
}

void HighlightPainter::PaintNonCssMarkers(Phase phase) {
  if (markers_.empty())
    return;

  CHECK(node_);
  const StringView text = cursor_.CurrentText();

  const auto* text_node = DynamicTo<Text>(node_);
  const MarkerRangeMappingContext mapping_context(*text_node,
                                                  *fragment_dom_offsets_);
  for (const DocumentMarker* marker : markers_) {
    std::optional<TextOffsetRange> marker_offsets =
        mapping_context.GetTextContentOffsets(*marker);
    if (!marker_offsets || (marker_offsets->start == marker_offsets->end)) {
      continue;
    }
    const unsigned paint_start_offset = marker_offsets->start;
    const unsigned paint_end_offset = marker_offsets->end;

    DCHECK(!DocumentMarker::MarkerTypes::HighlightPseudos().Contains(
        marker->GetType()));

    switch (marker->GetType()) {
      case DocumentMarker::kTextMatch: {
        if (RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled() &&
            !fragment_item_->IsSvgText()) {
          break;
        }
        const Document& document = node_->GetDocument();
        const auto& text_match_marker = To<TextMatchMarker>(*marker);
        if (phase == kBackground) {
          Color color =
              LayoutTheme::GetTheme().PlatformTextSearchHighlightColor(
                  text_match_marker.IsActiveMatch(),
                  document.InForcedColorsMode(),
                  originating_style_.UsedColorScheme(),
                  document.GetColorProviderForPainting(
                      originating_style_.UsedColorScheme()),
                  document.IsInWebAppScope());
          PaintRect(
              paint_info_.context,
              ComputeBackgroundRect(text, paint_start_offset, paint_end_offset),
              color, background_auto_dark_mode_);
          break;
        }

        const TextPaintStyle text_style =
            TextPaintStyleForTextMatch(text_match_marker, originating_style_,
                                       document, fragment_item_->IsSvgText());
        if (fragment_item_->IsSvgText()) {
          text_painter_.SetSvgState(
              *To<LayoutSVGInlineText>(fragment_item_->GetLayoutObject()),
              originating_style_, text_style.fill_color);
        }
        text_painter_.Paint(
            fragment_paint_info_.Slice(paint_start_offset, paint_end_offset),
            text_style, kInvalidDOMNodeId, foreground_auto_dark_mode_);
      } break;

      case DocumentMarker::kComposition:
      case DocumentMarker::kActiveSuggestion:
      case DocumentMarker::kSuggestion: {
        const auto& styleable_marker = To<StyleableMarker>(*marker);
        if (phase == kBackground) {
          PaintRect(
              paint_info_.context,
              ComputeBackgroundRect(text, paint_start_offset, paint_end_offset),
              styleable_marker.BackgroundColor(), background_auto_dark_mode_);
          break;
        }
        if (StyleableMarkerPainter::ShouldPaintUnderline(styleable_marker)) {
          const SimpleFontData* font_data =
              originating_style_.GetFont().PrimaryFont();
          StyleableMarkerPainter::PaintUnderline(
              styleable_marker, paint_info_.context, box_origin_,
              originating_style_,
              LineRelativeLocalRect(fragment_item_, text, paint_start_offset,
                                    paint_end_offset),
              LayoutUnit(font_data->GetFontMetrics().Height()),
              node_->GetDocument().InDarkMode());
        }
        if (marker->GetType() == DocumentMarker::kComposition &&
            !styleable_marker.TextColor().IsFullyTransparent() &&
            RuntimeEnabledFeatures::CompositionForegroundMarkersEnabled()) {
          PaintTextForCompositionMarker(text, styleable_marker.TextColor(),
                                        paint_start_offset, paint_end_offset);
        }
        break;
      }
      case DocumentMarker::kSpelling:
      case DocumentMarker::kGrammar:
      case DocumentMarker::kTextFragment:
      case DocumentMarker::kCustomHighlight:
        NOTREACHED();
    }
  }
}

HighlightPainter::Case HighlightPainter::PaintCase() const {
  return paint_case_;
}

HighlightPainter::Case HighlightPainter::ComputePaintCase() const {
  if (selection_ && selection_->ShouldPaintSelectedTextOnly())
    return kSelectionOnly;

  // This can yield false positives (weakening the optimisations below) if all
  // non-spelling/grammar/selection highlights are outside the text fragment.
  if (!target_.empty() || !search_.empty() || !custom_.empty()) {
    return kOverlay;
  }

  if (selection_ && spelling_.empty() && grammar_.empty()) {
    const ComputedStyle* pseudo_style =
        HighlightStyleUtils::HighlightPseudoStyle(node_, originating_style_,
                                                  kPseudoIdSelection);

    // If we only have a selection, and there are no selection or originating
    // decorations, we don’t need the expense of overlay painting.
    return !originating_style_.HasAppliedTextDecorations() &&
                   (!pseudo_style || !pseudo_style->HasAppliedTextDecorations())
               ? kFastSelection
               : kOverlay;
  }

  if (!spelling_.empty() || !grammar_.empty()) {
    // If there is a selection too, we must use the overlay painting algorithm.
    if (selection_)
      return kOverlay;

    // If there are only spelling and/or grammar highlights, and they use the
    // default style that only adds decorations without adding a background or
    // changing the text color, we don’t need the expense of overlay painting.
    bool spelling_ok =
        spelling_.empty() ||
        !HasNonTrivialSpellingGrammarStyles(
            fragment_item_, node_, originating_style_, kPseudoIdSpellingError);
    bool grammar_ok =
        grammar_.empty() ||
        !HasNonTrivialSpellingGrammarStyles(
            fragment_item_, node_, originating_style_, kPseudoIdGrammarError);
    return spelling_ok && grammar_ok ? kFastSpellingGrammar : kOverlay;
  }

  DCHECK(!selection_ && target_.empty() && spelling_.empty() &&
         grammar_.empty() && custom_.empty());
  return kNoHighlights;
}

void HighlightPainter::FastPaintSpellingGrammarDecorations() {
  DCHECK_EQ(paint_case_, kFastSpellingGrammar);
  CHECK(node_);
  const auto& text_node = To<Text>(*node_);
  const StringView text = cursor_.CurrentText();

  // ::spelling-error overlay is drawn on top of ::grammar-error overlay.
  // https://drafts.csswg.org/css-pseudo-4/#highlight-backgrounds
  FastPaintSpellingGrammarDecorations(text_node, text, grammar_);
  FastPaintSpellingGrammarDecorations(text_node, text, spelling_);
}

void HighlightPainter::FastPaintSpellingGrammarDecorations(
    const Text& text_node,
    const StringView& text,
    const DocumentMarkerVector& markers) {
  const MarkerRangeMappingContext mapping_context(text_node,
                                                  *fragment_dom_offsets_);
  for (const DocumentMarker* marker : markers) {
    std::optional<TextOffsetRange> marker_offsets =
        mapping_context.GetTextContentOffsets(*marker);
    if (!marker_offsets || (marker_offsets->start == marker_offsets->end)) {
      continue;
    }
    PaintOneSpellingGrammarDecoration(
        marker->GetType(), text, marker_offsets->start, marker_offsets->end);
  }
}

void HighlightPainter::PaintOneSpellingGrammarDecoration(
    DocumentMarker::MarkerType type,
    const StringView& text,
    unsigned paint_start_offset,
    unsigned paint_end_offset) {
  if (node_->GetDocument().Printing()) {
    return;
  }

  if (!text_painter_.GetSvgState()) {
    if (const auto* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
            node_, originating_style_, PseudoFor(type))) {
      const TextPaintStyle text_style =
          HighlightStyleUtils::HighlightPaintingStyle(
              node_->GetDocument(), originating_style_, pseudo_style, node_,
              PseudoFor(type), originating_text_style_, paint_info_,
              SearchTextIsActiveMatch::kNo)
              .style;
      PaintOneSpellingGrammarDecoration(type, text, paint_start_offset,
                                        paint_end_offset, *pseudo_style,
                                        text_style, nullptr);
      return;
    }
  }

  // If they are not yet implemented (as is the case for SVG), or they have no
  // styles (as there can be for non-HTML content or for HTML content with the
  // wrong root), use the originating style with the decorations override set
  // to a synthesised AppliedTextDecoration.
  //
  // For the synthesised decoration, just like with our real spelling/grammar
  // decorations, the ‘text-decoration-style’, ‘text-decoration-thickness’, and
  // ‘text-underline-offset’ are irrelevant.
  //
  // SVG painting currently ignores ::selection styles, and will malfunction
  // or crash if asked to paint decorations introduced by highlight pseudos.
  // TODO(crbug.com/1147859) is SVG spec ready for highlight decorations?
  // TODO(crbug.com/1147859) https://github.com/w3c/svgwg/issues/894
  const AppliedTextDecoration synthesised{
      LineFor(type), {}, ColorFor(type),
```

## `blink/renderer/core/paint/highlight_painter.cc` 的功能归纳 (第 1 部分)

这个 C++ 源代码文件 `highlight_painter.cc` 是 Chromium Blink 渲染引擎的一部分，其主要功能是**负责在网页上绘制各种文本高亮效果**。 这包括但不限于：

* **用户选择文本时的默认高亮:**  当用户通过鼠标或键盘选中网页上的文本时，该文件负责绘制选中文本的背景色和可能的文本颜色变化。
* **拼写和语法错误高亮:**  当检测到拼写或语法错误时，该文件会根据样式规则绘制相应的下划线或其他标记。
* **查找 (Find in Page) 功能高亮:** 当用户在页面中查找特定文本时，该文件会高亮显示所有匹配的文本。
* **`::target-text` 伪元素高亮:**  当 URL 中包含指向特定文本片段的锚点时，该文件负责高亮显示该文本片段。
* **自定义高亮 (Custom Highlights):**  通过 JavaScript API 或浏览器扩展添加的自定义高亮效果的绘制。
* **文本输入框中的 Composition 高亮:**  在输入法编辑器 (IME) 中输入文本时，尚未最终确定的文本可能会被高亮显示。
* **建议 (Suggestions) 高亮:** 例如在文本输入框中提供的自动完成建议可能会被高亮显示。

**主要职责可以概括为：**

1. **确定需要绘制哪些高亮:**  根据当前的选择状态、文档标记（例如拼写错误、查找结果）、以及自定义高亮等信息，判断在给定的文本片段上需要绘制哪些高亮效果。
2. **获取高亮样式:**  根据 CSS 样式规则，包括默认样式、`::selection` 伪元素样式、`::spelling-error`、`::grammar-error` 等伪元素样式，确定高亮的颜色、背景、下划线等绘制属性。
3. **绘制高亮背景和装饰:**  使用 `GraphicsContext` 对象，根据计算出的位置和样式，绘制高亮的背景色和各种装饰（例如下划线）。
4. **绘制高亮文本 (可选):**  在某些情况下，高亮也可能涉及到改变文本自身的颜色或样式。
5. **优化绘制性能:**  通过判断不同的高亮情况，采用不同的绘制策略，例如对于简单的拼写和语法错误高亮，可以采用更快速的绘制方法，避免复杂的 overlay 绘制。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**  `HighlightPainter` 接收 `Node` 对象作为输入，这些 `Node` 对象代表了 HTML 元素。它处理文本节点 (`Text`) 的高亮。例如，当 HTML 中有一个 `<p>` 元素包含一些文本，用户选中了其中的一部分，`HighlightPainter` 就会被调用来绘制这部分文本的高亮。
* **CSS:**  `HighlightPainter` 依赖于 `ComputedStyle` 对象来获取元素的样式信息。它特别关注与高亮相关的 CSS 伪元素，例如：
    * **`::selection`:**  用户选择文本时的默认高亮样式可以通过 `::selection` 伪元素来定义。例如，以下 CSS 会将选中文本的背景色设置为黄色，文本颜色设置为黑色：
      ```css
      ::selection {
        background-color: yellow;
        color: black;
      }
      ```
    * **`::spelling-error` 和 `::grammar-error`:**  可以自定义拼写和语法错误的显示方式。例如，以下 CSS 会将拼写错误的文本下划线设置为红色波浪线：
      ```css
      ::-webkit-grammar-error:nth-of-type(1) { /* 兼容性前缀 */
        text-decoration: red wavy underline;
      }
      ```
    * **`::target-text`:**  用于高亮显示 URL 片段标识符指向的文本。例如：
      ```css
      :target-text {
        background-color: lightblue;
      }
      ```
* **JavaScript:** JavaScript 代码可以通过 Selection API 来获取和操作用户的文本选择，从而间接地触发 `HighlightPainter` 的工作。此外，一些 JavaScript API 允许开发者自定义高亮效果，例如使用 `CSS.registerProperty()` 和相关的 Houdini API 可以创建更复杂的高亮效果，这些最终也会由渲染引擎的绘画机制来执行。

**逻辑推理的假设输入与输出:**

**假设输入:**

* **文本片段:** "这是一个**加粗**的文本。"
* **用户操作:**  用户选中了 "加粗" 这两个字。
* **CSS 样式:**
    ```css
    ::selection {
      background-color: lightgreen;
      color: darkgreen;
    }
    ```

**逻辑推理:**  `HighlightPainter` 会接收到 "加粗" 这部分文本的起始和结束位置信息，以及应用于该文本的计算样式。由于用户进行了选择操作，并且定义了 `::selection` 伪元素样式，`HighlightPainter` 会使用 `lightgreen` 作为背景色，`darkgreen` 作为文本颜色来绘制高亮。

**输出:**  "加粗" 两个字会以浅绿色背景和深绿色文字显示。

**用户或编程常见的使用错误举例:**

* **CSS 样式冲突导致高亮显示不符合预期:**  例如，同时定义了多个高亮相关的样式，但优先级设置不当，导致最终显示的样式不是开发者期望的。例如，同时定义了 `::selection` 和自定义高亮样式，但自定义高亮的优先级较低，导致用户选择文本时只显示默认的 `::selection` 样式。
* **JavaScript 操作 Selection API 时出现错误，导致高亮状态不正确:**  例如，在使用 JavaScript 设置文本选择范围时，起始和结束位置计算错误，导致高亮范围错误或无法高亮。
* **错误地理解或使用自定义高亮 API:**  例如，在使用自定义高亮 API 时，提供的 Range 对象不正确，或者关联的样式没有正确应用，导致自定义高亮无法正常显示。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载包含文本的网页:** 浏览器开始解析 HTML、CSS 并构建 DOM 树和渲染树。
2. **用户进行交互，触发高亮:**  这可以是以下几种操作：
    * **鼠标拖拽选择文本:** 用户按下鼠标左键并拖动，浏览器会计算选中文本的范围。
    * **键盘操作选择文本:** 用户使用 Shift 键配合方向键来选择文本。
    * **使用浏览器的查找功能 (Ctrl+F 或 Cmd+F):**  用户输入查找关键词后，浏览器会在页面中搜索匹配的文本。
    * **点击包含 URL 片段标识符的链接:** 例如，点击 `index.html#section2` 会尝试滚动到并高亮显示页面中 id 为 `section2` 的元素或其包含的特定文本。
    * **文本输入框中输入文本，触发拼写/语法检查或输入法建议:**  浏览器或操作系统会进行拼写和语法检查，或者输入法会提供候选词。
    * **JavaScript 代码调用 Selection API 或自定义高亮 API:** 网页上的 JavaScript 代码可能会通过编程方式选择文本或添加自定义高亮。
3. **渲染引擎计算高亮:**  当上述用户操作发生时，浏览器的渲染引擎会根据当前的文档状态和样式规则，确定需要高亮显示的文本范围和样式。
4. **`HighlightPainter` 被调用:**  渲染引擎会调用 `HighlightPainter` 类的相关方法，并将需要绘制的文本片段、样式信息等作为参数传递给它。
5. **`HighlightPainter` 执行绘制操作:**  `HighlightPainter` 内部会进行一系列计算和判断，最终调用底层的图形绘制接口 (例如 `GraphicsContext`) 来在屏幕上绘制高亮效果。

**总结 (第 1 部分):**

`highlight_painter.cc` 文件的核心功能是**负责在 Chromium Blink 引擎中渲染各种文本高亮效果**。 它与 HTML 结构、CSS 样式以及 JavaScript 的交互密切相关，根据不同的触发条件和样式规则，绘制用户选择、拼写/语法错误、查找结果以及自定义的高亮，并努力优化绘制性能。理解其工作原理对于调试网页高亮显示问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/highlight_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/highlight_painter.h"

#include "base/not_fatal_until.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/custom_highlight_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/styleable_marker.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/highlight/highlight.h"
#include "third_party/blink/renderer/core/highlight/highlight_registry.h"
#include "third_party/blink/renderer/core/highlight/highlight_style_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/text_offset_range.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/text_decoration_offset.h"
#include "third_party/blink/renderer/core/paint/highlight_overlay.h"
#include "third_party/blink/renderer/core/paint/line_relative_rect.h"
#include "third_party/blink/renderer/core/paint/marker_range_mapping_context.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/styleable_marker_painter.h"
#include "third_party/blink/renderer/core/paint/text_decoration_painter.h"
#include "third_party/blink/renderer/core/paint/text_painter.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

using HighlightLayerType = HighlightOverlay::HighlightLayerType;
using HighlightRange = HighlightOverlay::HighlightRange;
using HighlightEdge = HighlightOverlay::HighlightEdge;
using HighlightDecoration = HighlightOverlay::HighlightDecoration;
using HighlightBackground = HighlightOverlay::HighlightBackground;
using HighlightTextShadow = HighlightOverlay::HighlightTextShadow;

LineRelativeRect LineRelativeLocalRect(const FragmentItem& text_fragment,
                                       StringView text,
                                       unsigned start_offset,
                                       unsigned end_offset) {
  LayoutUnit start_position, end_position;
  std::tie(start_position, end_position) =
      text_fragment.LineLeftAndRightForOffsets(text, start_offset, end_offset);

  const LayoutUnit height = text_fragment.InkOverflowRect().Height();
  return {{start_position, LayoutUnit()},
          {end_position - start_position, height}};
}

void PaintRect(GraphicsContext& context,
               const PhysicalRect& rect,
               const Color color,
               const AutoDarkMode& auto_dark_mode) {
  if (color.IsFullyTransparent()) {
    return;
  }
  if (rect.size.IsEmpty())
    return;
  const gfx::Rect pixel_snapped_rect = ToPixelSnappedRect(rect);
  if (!pixel_snapped_rect.IsEmpty())
    context.FillRect(pixel_snapped_rect, color, auto_dark_mode);
}

const LayoutSelectionStatus* GetSelectionStatus(
    const HighlightPainter::SelectionPaintState* selection) {
  if (!selection)
    return nullptr;
  return &selection->Status();
}

// Returns true if the styles for the given spelling or grammar pseudo require
// the full overlay painting algorithm.
bool HasNonTrivialSpellingGrammarStyles(const FragmentItem& fragment_item,
                                        Node* node,
                                        const ComputedStyle& originating_style,
                                        PseudoId pseudo) {
  DCHECK(pseudo == kPseudoIdSpellingError || pseudo == kPseudoIdGrammarError);
  if (const ComputedStyle* pseudo_style =
          HighlightStyleUtils::HighlightPseudoStyle(node, originating_style,
                                                    pseudo)) {
    const Document& document = node->GetDocument();
    // If the ‘color’, ‘-webkit-text-fill-color’, ‘-webkit-text-stroke-color’,
    // or ‘-webkit-text-stroke-width’ differs from the originating style.
    Color pseudo_color = HighlightStyleUtils::ResolveColor(
        document, originating_style, pseudo_style, pseudo,
        GetCSSPropertyColor(), {}, SearchTextIsActiveMatch::kNo);
    if (pseudo_color !=
        originating_style.VisitedDependentColor(GetCSSPropertyColor())) {
      return true;
    }
    if (HighlightStyleUtils::ResolveColor(document, originating_style,
                                          pseudo_style, pseudo,
                                          GetCSSPropertyWebkitTextFillColor(),
                                          {}, SearchTextIsActiveMatch::kNo) !=
        originating_style.VisitedDependentColor(
            GetCSSPropertyWebkitTextFillColor())) {
      return true;
    }
    if (HighlightStyleUtils::ResolveColor(document, originating_style,
                                          pseudo_style, pseudo,
                                          GetCSSPropertyWebkitTextStrokeColor(),
                                          {}, SearchTextIsActiveMatch::kNo) !=
        originating_style.VisitedDependentColor(
            GetCSSPropertyWebkitTextStrokeColor())) {
      return true;
    }
    if (pseudo_style->TextStrokeWidth() != originating_style.TextStrokeWidth())
      return true;
    // If there is a background color.
    if (!HighlightStyleUtils::ResolveColor(
             document, originating_style, pseudo_style, pseudo,
             GetCSSPropertyBackgroundColor(), {}, SearchTextIsActiveMatch::kNo)
             .IsFullyTransparent()) {
      return true;
    }
    // If the ‘text-shadow’ is not ‘none’.
    if (pseudo_style->TextShadow())
      return true;

    // If the ‘text-decoration-line’ is not ‘spelling-error’ or ‘grammar-error’,
    // depending on the pseudo. ‘text-decoration-color’ can vary without hurting
    // the optimisation, and for these line types, we ignore all other text
    // decoration related properties anyway.
    if (pseudo_style->TextDecorationsInEffect() !=
        (pseudo == kPseudoIdSpellingError
             ? TextDecorationLine::kSpellingError
             : TextDecorationLine::kGrammarError)) {
      return true;
    }
    // If any of the originating line decorations would need to be recolored.
    for (const AppliedTextDecoration& decoration :
         originating_style.AppliedTextDecorations()) {
      if (decoration.GetColor() != pseudo_color) {
        return true;
      }
    }
    // ‘text-emphasis-color’ should be meaningless for highlight pseudos, but
    // in our current impl, it sets the color of originating emphasis marks.
    // This means we can only use kFastSpellingGrammar if the color is the same
    // as in the originating style, or there are no emphasis marks.
    // TODO(crbug.com/1147859) clean up when spec issue is resolved again
    // https://github.com/w3c/csswg-drafts/issues/7101
    if (originating_style.GetTextEmphasisMark() != TextEmphasisMark::kNone &&
        HighlightStyleUtils::ResolveColor(document, originating_style,
                                          pseudo_style, pseudo,
                                          GetCSSPropertyTextEmphasisColor(), {},
                                          SearchTextIsActiveMatch::kNo) !=
            originating_style.VisitedDependentColor(
                GetCSSPropertyTextEmphasisColor())) {
      return true;
    }
    // If the SVG-only fill- and stroke-related properties differ from their
    // values in the originating style. These checks must be skipped outside of
    // SVG content, because the initial ‘fill’ is ‘black’, not ‘currentColor’.
    if (fragment_item.IsSvgText()) {
      // If the ‘fill’ is ‘currentColor’, assume that it differs from the
      // originating style, even if the current color actually happens to
      // match. This simplifies the logic until we know it performs poorly.
      if (pseudo_style->FillPaint().HasCurrentColor())
        return true;
      // If the ‘fill’ differs from the originating style.
      if (pseudo_style->FillPaint() != originating_style.FillPaint())
        return true;
      // If the ‘stroke’ is ‘currentColor’, assume that it differs from the
      // originating style, even if the current color actually happens to
      // match. This simplifies the logic until we know it performs poorly.
      if (pseudo_style->StrokePaint().HasCurrentColor())
        return true;
      // If the ‘stroke’ differs from the originating style.
      if (pseudo_style->StrokePaint() != originating_style.StrokePaint())
        return true;
      // If the ‘stroke-width’ differs from the originating style.
      if (pseudo_style->StrokeWidth() != originating_style.StrokeWidth())
        return true;
    }
  }
  return false;
}

TextPaintStyle TextPaintStyleForTextMatch(const TextMatchMarker& marker,
                                          const ComputedStyle& style,
                                          const Document& document,
                                          bool ignore_current_color) {
  const mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const Color platform_text_color =
      LayoutTheme::GetTheme().PlatformTextSearchColor(
          marker.IsActiveMatch(), document.InForcedColorsMode(), color_scheme,
          document.GetColorProviderForPainting(color_scheme),
          document.IsInWebAppScope());
  // Comparing against the value of the 'color' property doesn't always make
  // sense (for example for SVG <text> which paints using 'fill' and 'stroke').
  if (!ignore_current_color) {
    const Color text_color = style.VisitedDependentColor(GetCSSPropertyColor());
    if (platform_text_color == text_color) {
      return {};
    }
  }

  TextPaintStyle text_style;
  text_style.current_color = text_style.fill_color = text_style.stroke_color =
      text_style.emphasis_mark_color = platform_text_color;
  text_style.stroke_width = style.TextStrokeWidth();
  text_style.color_scheme = color_scheme;
  text_style.shadow = nullptr;
  text_style.paint_order = style.PaintOrder();
  return text_style;
}

// A contiguous run of parts that can have ‘background-color’ or ‘text-shadow’
// of some active overlay painted at once.
//
// These properties can often be painted a whole highlighted range at a time,
// and only need to be split into parts when affected by ‘currentColor’. By
// merging parts where possible, we avoid creating unnecessary “seams” in
// ‘background-color’, and avoid splitting ligatures in ‘text-shadow’.
//
// Inner’s operator== must return true iff the two operands come from the same
// layer and can be painted at once.
template <typename Inner>
struct MergedHighlightPart {
 public:
  struct Merged {
   public:
    const Inner& inner;
    unsigned from;
    unsigned to;
  };

  // Merge |next| and |next_part| into |merged| if possible, otherwise start a
  // new run and return the old |merged| if any.
  std::optional<Merged> Merge(const Inner& next,
                              const HighlightPart& next_part) {
    std::optional<Merged> result{};
    if (merged.has_value()) {
      if (merged->inner == next && merged->to == next_part.range.from) {
        merged->to = next_part.range.to;
        return {};
      } else {
        result.emplace(*merged);
      }
    }
    merged.emplace(Merged{next, next_part.range.from, next_part.range.to});
    return result;
  }

  // Take and return the last |merged| if any, leaving it empty.
  std::optional<Merged> Take() {
    if (!merged.has_value()) {
      return {};
    }
    std::optional<Merged> result{};
    result.emplace(*merged);
    merged.reset();
    return result;
  }

  std::optional<Merged> merged;
};

}  // namespace

HighlightPainter::SelectionPaintState::SelectionPaintState(
    const InlineCursor& containing_block,
    const PhysicalOffset& box_offset,
    const std::optional<AffineTransform> writing_mode_rotation)
    : SelectionPaintState(containing_block,
                          box_offset,
                          writing_mode_rotation,
                          containing_block.Current()
                              .GetLayoutObject()
                              ->GetDocument()
                              .GetFrame()
                              ->Selection()) {}
HighlightPainter::SelectionPaintState::SelectionPaintState(
    const InlineCursor& containing_block,
    const PhysicalOffset& box_offset,
    const std::optional<AffineTransform> writing_mode_rotation,
    const FrameSelection& frame_selection)
    : selection_status_(
          frame_selection.ComputeLayoutSelectionStatus(containing_block)),
      state_(frame_selection.ComputePaintingSelectionStateForCursor(
          containing_block.Current())),
      containing_block_(containing_block),
      box_offset_(box_offset),
      writing_mode_rotation_(writing_mode_rotation) {}

void HighlightPainter::SelectionPaintState::ComputeSelectionStyle(
    const Document& document,
    const ComputedStyle& style,
    Node* node,
    const PaintInfo& paint_info,
    const TextPaintStyle& text_style) {
  const ComputedStyle* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
      node, style, kPseudoIdSelection);
  selection_style_ = HighlightStyleUtils::HighlightPaintingStyle(
      document, style, pseudo_style, node, kPseudoIdSelection, text_style,
      paint_info, SearchTextIsActiveMatch::kNo);
  paint_selected_text_only_ =
      (paint_info.phase == PaintPhase::kSelectionDragImage);
}

void HighlightPainter::SelectionPaintState::ComputeSelectionRectIfNeeded() {
  if (!selection_rect_) {
    PhysicalRect physical =
        containing_block_.CurrentLocalSelectionRectForText(selection_status_);
    physical.offset += box_offset_;
    LineRelativeRect rotated =
        LineRelativeRect::Create(physical, writing_mode_rotation_);
    selection_rect_.emplace(SelectionRect{physical, rotated});
  }
}

const PhysicalRect&
HighlightPainter::SelectionPaintState::PhysicalSelectionRect() {
  ComputeSelectionRectIfNeeded();
  return selection_rect_->physical;
}

const LineRelativeRect&
HighlightPainter::SelectionPaintState::LineRelativeSelectionRect() {
  ComputeSelectionRectIfNeeded();
  return selection_rect_->rotated;
}

// |selection_start| and |selection_end| should be between
// [text_fragment.StartOffset(), text_fragment.EndOffset()].
void HighlightPainter::SelectionPaintState::PaintSelectionBackground(
    GraphicsContext& context,
    Node* node,
    const Document& document,
    const ComputedStyle& style,
    const std::optional<AffineTransform>& rotation) {
  const Color color = HighlightStyleUtils::HighlightBackgroundColor(
      document, style, node, selection_style_.style.current_color,
      kPseudoIdSelection, SearchTextIsActiveMatch::kNo);
  HighlightPainter::PaintHighlightBackground(context, style, color,
                                             PhysicalSelectionRect(), rotation);
}

// Paint the selected text only.
void HighlightPainter::SelectionPaintState::PaintSelectedText(
    TextPainter& text_painter,
    const TextFragmentPaintInfo& fragment_paint_info,
    const TextPaintStyle& text_style,
    DOMNodeId node_id,
    const AutoDarkMode& auto_dark_mode) {
  text_painter.PaintSelectedText(fragment_paint_info, selection_status_.start,
                                 selection_status_.end, text_style,
                                 selection_style_.style, LineRelativeSelectionRect(),
                                 node_id, auto_dark_mode);
}

// Paint the given text range in the given style, suppressing the text proper
// (painting shadows only) where selected.
void HighlightPainter::SelectionPaintState::
    PaintSuppressingTextProperWhereSelected(
        TextPainter& text_painter,
        const TextFragmentPaintInfo& fragment_paint_info,
        const TextPaintStyle& text_style,
        DOMNodeId node_id,
        const AutoDarkMode& auto_dark_mode) {
  // First paint the shadows for the whole range.
  if (text_style.shadow) {
    text_painter.Paint(fragment_paint_info, text_style, node_id, auto_dark_mode,
                       TextPainter::kShadowsOnly);
  }

  // Then paint the text proper for any unselected parts in storage order, so
  // that they’re always on top of the shadows.
  if (fragment_paint_info.from < selection_status_.start) {
    text_painter.Paint(
        fragment_paint_info.WithEndOffset(selection_status_.start), text_style,
        node_id, auto_dark_mode, TextPainter::kTextProperOnly);
  }
  if (selection_status_.end < fragment_paint_info.to) {
    text_painter.Paint(
        fragment_paint_info.WithStartOffset(selection_status_.end), text_style,
        node_id, auto_dark_mode, TextPainter::kTextProperOnly);
  }
}

// GetNode() for first-letter fragment returns null because it is anonymous.
// Use AssociatedTextNode() of LayoutTextFragment to get the associated node.
static Node* AssociatedNode(const LayoutObject* layout_object) {
  if (RuntimeEnabledFeatures::PaintHighlightsForFirstLetterEnabled()) {
    if (auto* layout_text_fragment =
            DynamicTo<LayoutTextFragment>(layout_object)) {
      return layout_text_fragment->AssociatedTextNode();
    }
  }
  return layout_object->GetNode();
}

HighlightPainter::HighlightPainter(
    const TextFragmentPaintInfo& fragment_paint_info,
    TextPainter& text_painter,
    TextDecorationPainter& decoration_painter,
    const PaintInfo& paint_info,
    const InlineCursor& cursor,
    const FragmentItem& fragment_item,
    const PhysicalOffset& box_origin,
    const ComputedStyle& style,
    const TextPaintStyle& text_style,
    SelectionPaintState* selection)
    : fragment_paint_info_(fragment_paint_info),
      text_painter_(text_painter),
      decoration_painter_(decoration_painter),
      paint_info_(paint_info),
      cursor_(cursor),
      root_inline_cursor_(cursor),
      fragment_item_(fragment_item),
      box_origin_(box_origin),
      originating_style_(style),
      originating_text_style_(text_style),
      selection_(selection),
      layout_object_(fragment_item_.GetLayoutObject()),
      node_(AssociatedNode(layout_object_)),
      foreground_auto_dark_mode_(
          PaintAutoDarkMode(originating_style_,
                            DarkModeFilter::ElementRole::kForeground)),
      background_auto_dark_mode_(
          PaintAutoDarkMode(originating_style_,
                            DarkModeFilter::ElementRole::kBackground)) {
  root_inline_cursor_.ExpandRootToContainingBlock();

  // Custom highlights and marker-based highlights are defined in terms of
  // DOM ranges in a Text node. Generated text either has no Text node or does
  // not derive its content from the Text node (e.g. ellipsis, soft hyphens).
  // TODO(crbug.com/17528) handle ::first-letter
  if (!fragment_item_.IsGeneratedText()) {
    const auto* text_node = DynamicTo<Text>(node_);
    if (text_node) {
      DocumentMarkerController& controller = node_->GetDocument().Markers();
      if (controller.HasAnyMarkersForText(*text_node)) {
        fragment_dom_offsets_ = GetFragmentDOMOffsets(
            *text_node, fragment_paint_info_.from, fragment_paint_info_.to);
        DCHECK(fragment_dom_offsets_);
        markers_ = controller.ComputeMarkersToPaint(*text_node);
        if (RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled() &&
            !fragment_item_.IsSvgText()) {
          search_ = controller.MarkersFor(
              *text_node, DocumentMarker::kTextMatch,
              fragment_dom_offsets_->start, fragment_dom_offsets_->end);
        }
        target_ = controller.MarkersFor(
            *text_node, DocumentMarker::kTextFragment,
            fragment_dom_offsets_->start, fragment_dom_offsets_->end);
        spelling_ = controller.MarkersFor(*text_node, DocumentMarker::kSpelling,
                                          fragment_dom_offsets_->start,
                                          fragment_dom_offsets_->end);
        grammar_ = controller.MarkersFor(*text_node, DocumentMarker::kGrammar,
                                         fragment_dom_offsets_->start,
                                         fragment_dom_offsets_->end);
        custom_ = controller.MarkersFor(
            *text_node, DocumentMarker::kCustomHighlight,
            fragment_dom_offsets_->start, fragment_dom_offsets_->end);
      } else if (selection) {
        fragment_dom_offsets_ = GetFragmentDOMOffsets(
            *text_node, fragment_paint_info_.from, fragment_paint_info_.to);
      }
    }
  }

  paint_case_ = ComputePaintCase();

  // |layers_| and |parts_| are only needed when using the full overlay
  // painting algorithm, otherwise we can leave them empty.
  if (paint_case_ == kOverlay) {
    auto* selection_status = GetSelectionStatus(selection_);
    layers_ = HighlightOverlay::ComputeLayers(
        layout_object_->GetDocument(), node_, originating_style_,
        originating_text_style_, paint_info_, selection_status, custom_,
        grammar_, spelling_, target_, search_);
    Vector<HighlightEdge> edges = HighlightOverlay::ComputeEdges(
        node_, fragment_item_.IsGeneratedText(), fragment_dom_offsets_, layers_,
        selection_status, custom_, grammar_, spelling_, target_, search_);
    parts_ =
        HighlightOverlay::ComputeParts(fragment_paint_info_, layers_, edges);

    if (!parts_.empty()) {
      if (const ShapeResultView* shape_result_view =
              fragment_item_->TextShapeResult()) {
        const ShapeResult* shape_result =
            shape_result_view->CreateShapeResult();
        unsigned start_offset = fragment_item_->StartOffset();
        edges_info_.push_back(HighlightEdgeInfo{
            parts_[0].range.from,
            shape_result->CaretPositionForOffset(
                parts_[0].range.from - start_offset, cursor_.CurrentText())});
        for (const HighlightPart& part : parts_) {
          edges_info_.push_back(HighlightEdgeInfo{
              part.range.to,
              shape_result->CaretPositionForOffset(part.range.to - start_offset,
                                                   cursor_.CurrentText())});
        }
      } else {
        edges_info_.push_back(HighlightEdgeInfo{
            parts_[0].range.from,
            fragment_item_
                .CaretInlinePositionForOffset(cursor_.CurrentText(),
                                              parts_[0].range.from)
                .ToFloat()});
        for (const HighlightPart& part : parts_) {
          edges_info_.push_back(HighlightEdgeInfo{
              part.range.to, fragment_item_
                                 .CaretInlinePositionForOffset(
                                     cursor_.CurrentText(), part.range.to)
                                 .ToFloat()});
        }
      }
    }
  }
}

void HighlightPainter::PaintNonCssMarkers(Phase phase) {
  if (markers_.empty())
    return;

  CHECK(node_);
  const StringView text = cursor_.CurrentText();

  const auto* text_node = DynamicTo<Text>(node_);
  const MarkerRangeMappingContext mapping_context(*text_node,
                                                  *fragment_dom_offsets_);
  for (const DocumentMarker* marker : markers_) {
    std::optional<TextOffsetRange> marker_offsets =
        mapping_context.GetTextContentOffsets(*marker);
    if (!marker_offsets || (marker_offsets->start == marker_offsets->end)) {
      continue;
    }
    const unsigned paint_start_offset = marker_offsets->start;
    const unsigned paint_end_offset = marker_offsets->end;

    DCHECK(!DocumentMarker::MarkerTypes::HighlightPseudos().Contains(
        marker->GetType()));

    switch (marker->GetType()) {
      case DocumentMarker::kTextMatch: {
        if (RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled() &&
            !fragment_item_->IsSvgText()) {
          break;
        }
        const Document& document = node_->GetDocument();
        const auto& text_match_marker = To<TextMatchMarker>(*marker);
        if (phase == kBackground) {
          Color color =
              LayoutTheme::GetTheme().PlatformTextSearchHighlightColor(
                  text_match_marker.IsActiveMatch(),
                  document.InForcedColorsMode(),
                  originating_style_.UsedColorScheme(),
                  document.GetColorProviderForPainting(
                      originating_style_.UsedColorScheme()),
                  document.IsInWebAppScope());
          PaintRect(
              paint_info_.context,
              ComputeBackgroundRect(text, paint_start_offset, paint_end_offset),
              color, background_auto_dark_mode_);
          break;
        }

        const TextPaintStyle text_style =
            TextPaintStyleForTextMatch(text_match_marker, originating_style_,
                                       document, fragment_item_->IsSvgText());
        if (fragment_item_->IsSvgText()) {
          text_painter_.SetSvgState(
              *To<LayoutSVGInlineText>(fragment_item_->GetLayoutObject()),
              originating_style_, text_style.fill_color);
        }
        text_painter_.Paint(
            fragment_paint_info_.Slice(paint_start_offset, paint_end_offset),
            text_style, kInvalidDOMNodeId, foreground_auto_dark_mode_);
      } break;

      case DocumentMarker::kComposition:
      case DocumentMarker::kActiveSuggestion:
      case DocumentMarker::kSuggestion: {
        const auto& styleable_marker = To<StyleableMarker>(*marker);
        if (phase == kBackground) {
          PaintRect(
              paint_info_.context,
              ComputeBackgroundRect(text, paint_start_offset, paint_end_offset),
              styleable_marker.BackgroundColor(), background_auto_dark_mode_);
          break;
        }
        if (StyleableMarkerPainter::ShouldPaintUnderline(styleable_marker)) {
          const SimpleFontData* font_data =
              originating_style_.GetFont().PrimaryFont();
          StyleableMarkerPainter::PaintUnderline(
              styleable_marker, paint_info_.context, box_origin_,
              originating_style_,
              LineRelativeLocalRect(fragment_item_, text, paint_start_offset,
                                    paint_end_offset),
              LayoutUnit(font_data->GetFontMetrics().Height()),
              node_->GetDocument().InDarkMode());
        }
        if (marker->GetType() == DocumentMarker::kComposition &&
            !styleable_marker.TextColor().IsFullyTransparent() &&
            RuntimeEnabledFeatures::CompositionForegroundMarkersEnabled()) {
          PaintTextForCompositionMarker(text, styleable_marker.TextColor(),
                                        paint_start_offset, paint_end_offset);
        }
        break;
      }
      case DocumentMarker::kSpelling:
      case DocumentMarker::kGrammar:
      case DocumentMarker::kTextFragment:
      case DocumentMarker::kCustomHighlight:
        NOTREACHED();
    }
  }
}

HighlightPainter::Case HighlightPainter::PaintCase() const {
  return paint_case_;
}

HighlightPainter::Case HighlightPainter::ComputePaintCase() const {
  if (selection_ && selection_->ShouldPaintSelectedTextOnly())
    return kSelectionOnly;

  // This can yield false positives (weakening the optimisations below) if all
  // non-spelling/grammar/selection highlights are outside the text fragment.
  if (!target_.empty() || !search_.empty() || !custom_.empty()) {
    return kOverlay;
  }

  if (selection_ && spelling_.empty() && grammar_.empty()) {
    const ComputedStyle* pseudo_style =
        HighlightStyleUtils::HighlightPseudoStyle(node_, originating_style_,
                                                  kPseudoIdSelection);

    // If we only have a selection, and there are no selection or originating
    // decorations, we don’t need the expense of overlay painting.
    return !originating_style_.HasAppliedTextDecorations() &&
                   (!pseudo_style || !pseudo_style->HasAppliedTextDecorations())
               ? kFastSelection
               : kOverlay;
  }

  if (!spelling_.empty() || !grammar_.empty()) {
    // If there is a selection too, we must use the overlay painting algorithm.
    if (selection_)
      return kOverlay;

    // If there are only spelling and/or grammar highlights, and they use the
    // default style that only adds decorations without adding a background or
    // changing the text color, we don’t need the expense of overlay painting.
    bool spelling_ok =
        spelling_.empty() ||
        !HasNonTrivialSpellingGrammarStyles(
            fragment_item_, node_, originating_style_, kPseudoIdSpellingError);
    bool grammar_ok =
        grammar_.empty() ||
        !HasNonTrivialSpellingGrammarStyles(
            fragment_item_, node_, originating_style_, kPseudoIdGrammarError);
    return spelling_ok && grammar_ok ? kFastSpellingGrammar : kOverlay;
  }

  DCHECK(!selection_ && target_.empty() && spelling_.empty() &&
         grammar_.empty() && custom_.empty());
  return kNoHighlights;
}

void HighlightPainter::FastPaintSpellingGrammarDecorations() {
  DCHECK_EQ(paint_case_, kFastSpellingGrammar);
  CHECK(node_);
  const auto& text_node = To<Text>(*node_);
  const StringView text = cursor_.CurrentText();

  // ::spelling-error overlay is drawn on top of ::grammar-error overlay.
  // https://drafts.csswg.org/css-pseudo-4/#highlight-backgrounds
  FastPaintSpellingGrammarDecorations(text_node, text, grammar_);
  FastPaintSpellingGrammarDecorations(text_node, text, spelling_);
}

void HighlightPainter::FastPaintSpellingGrammarDecorations(
    const Text& text_node,
    const StringView& text,
    const DocumentMarkerVector& markers) {
  const MarkerRangeMappingContext mapping_context(text_node,
                                                  *fragment_dom_offsets_);
  for (const DocumentMarker* marker : markers) {
    std::optional<TextOffsetRange> marker_offsets =
        mapping_context.GetTextContentOffsets(*marker);
    if (!marker_offsets || (marker_offsets->start == marker_offsets->end)) {
      continue;
    }
    PaintOneSpellingGrammarDecoration(
        marker->GetType(), text, marker_offsets->start, marker_offsets->end);
  }
}

void HighlightPainter::PaintOneSpellingGrammarDecoration(
    DocumentMarker::MarkerType type,
    const StringView& text,
    unsigned paint_start_offset,
    unsigned paint_end_offset) {
  if (node_->GetDocument().Printing()) {
    return;
  }

  if (!text_painter_.GetSvgState()) {
    if (const auto* pseudo_style = HighlightStyleUtils::HighlightPseudoStyle(
            node_, originating_style_, PseudoFor(type))) {
      const TextPaintStyle text_style =
          HighlightStyleUtils::HighlightPaintingStyle(
              node_->GetDocument(), originating_style_, pseudo_style, node_,
              PseudoFor(type), originating_text_style_, paint_info_,
              SearchTextIsActiveMatch::kNo)
              .style;
      PaintOneSpellingGrammarDecoration(type, text, paint_start_offset,
                                        paint_end_offset, *pseudo_style,
                                        text_style, nullptr);
      return;
    }
  }

  // If they are not yet implemented (as is the case for SVG), or they have no
  // styles (as there can be for non-HTML content or for HTML content with the
  // wrong root), use the originating style with the decorations override set
  // to a synthesised AppliedTextDecoration.
  //
  // For the synthesised decoration, just like with our real spelling/grammar
  // decorations, the ‘text-decoration-style’, ‘text-decoration-thickness’, and
  // ‘text-underline-offset’ are irrelevant.
  //
  // SVG painting currently ignores ::selection styles, and will malfunction
  // or crash if asked to paint decorations introduced by highlight pseudos.
  // TODO(crbug.com/1147859) is SVG spec ready for highlight decorations?
  // TODO(crbug.com/1147859) https://github.com/w3c/svgwg/issues/894
  const AppliedTextDecoration synthesised{
      LineFor(type), {}, ColorFor(type), 
"""


```