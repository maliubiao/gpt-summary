Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of a file named `highlight_painter.cc`. The summary should also cover the relationships to Javascript, HTML, and CSS, provide examples with hypothetical inputs and outputs if logical reasoning is involved, discuss potential user/programming errors, and explain how a user action might lead to this code being executed.

Here's a breakdown of the code's main parts and their functions:

1. **`PaintOneSpellingGrammarDecoration` (overloaded):** Paints decorations (like wavy underlines) for spelling or grammar errors.
2. **`PaintOriginatingShadow`:** Paints text shadows for the "originating" content.
3. **`GetHighlights`:**  Retrieves the ranges of text that need to be highlighted for different highlight layers (custom, grammar, spelling, search, selection, etc.). This involves mapping document markers to text offsets.
4. **`GetFragmentDOMOffsets`:** Converts text offsets within a fragment to offsets within the containing DOM node.
5. **`ComputeBackgroundRect` and `ComputeBackgroundRectForSelection`:** Calculate the rectangular area for highlight backgrounds. The "selection" version likely handles line wrapping and full-line highlights.
6. **`PaintHighlightOverlays`:**  The core function for painting highlights. It iterates through highlight layers and parts, painting background colors, text shadows, and the text itself. It also handles clipping and text decorations.
7. **`PaintHighlightBackground`:** Paints a single highlight background rectangle, considering dark mode and potential transformations.
8. **Helper functions (`PseudoFor`, `LineFor`, `ColorFor`):**  Map `DocumentMarker::MarkerType` to corresponding CSS pseudo-elements, text decoration lines, and colors.
9. **`LineRelativeWorldRect` and `LocalRectInWritingModeSpace`:** Calculate the position and size of highlight areas in different coordinate spaces, considering writing modes.
10. **`ClipToPartRect`:** Sets a clipping region for painting.
11. **`PaintDecorationsExceptLineThrough` (overloaded) and `PaintDecorationsOnlyLineThrough`:** Paint text decorations (underlines, overlines, line-throughs, spelling/grammar underlines), taking into account highlight layers and clipping.
12. **`PaintTextForCompositionMarker`:**  Specifically paints text for composition markers (used for IME input).

**Relationships to Javascript, HTML, and CSS:**

* **HTML:** The code operates on the rendered representation of HTML content. Highlighting is applied to elements within the HTML document. The text content itself comes from HTML text nodes.
* **CSS:**  CSS styles (like `background-color`, `text-shadow`, `text-decoration-line`, and custom highlight pseudo-elements like `::spelling-error`, `::grammar-error`, `::selection`) directly influence how highlights are painted. The code uses `ComputedStyle` to access these styles.
* **Javascript:** Javascript can trigger actions that lead to highlighting, such as:
    * Selecting text.
    * Using the Find in Page functionality.
    * Implementing custom text editing or annotation features.
    * Interacting with the browser's spellcheck/grammar check functionality.

**Logical Reasoning Examples:**

* **`GetHighlights`:** Given a list of `DocumentMarker` objects (which represent spelling/grammar errors, search matches, etc.) and the type of highlight layer requested, the function filters the markers and converts their ranges into text offsets within the current text fragment.
* **`PaintHighlightOverlays`:**  The code needs to iterate through the different highlight layers and then through the individual "parts" of each layer. It needs to determine the correct drawing order (background, shadow, text, decorations) and apply appropriate clipping to avoid overdrawing.

**User/Programming Errors:**

* **Incorrect marker ranges:** If the `DocumentMarker` objects have incorrect start and end offsets, the highlighting will be applied to the wrong text.
* **Mismatched highlight layers:** If the requested `HighlightLayerType` in `GetHighlights` doesn't match the actual markers present, no highlights might be returned.
* **Incorrect style information:** If the `ComputedStyle` object passed to the painting functions is incorrect, the highlights might have the wrong colors, shadows, or decorations.

**User Actions Leading to this Code:**

* **Selecting text:**  Dragging the mouse cursor over text triggers the selection highlighting.
* **Typing text in an input field:** This can trigger spellcheck or grammar check, leading to the painting of error decorations.
* **Using "Find in Page" (Ctrl+F/Cmd+F):** This highlights the search matches.
* **Navigating to a text fragment URL:** URLs with `#text=...` will highlight the specified text.
* **Custom Javascript highlighting:**  Javascript code can programmatically add or modify highlights.

**Summary of Functionality (Part 2):**

This part of `highlight_painter.cc` focuses on the actual **painting** of the various highlight elements (backgrounds, text shadows, text decorations) onto the canvas. It handles:

* **Painting decorations for spelling and grammar errors.**
* **Painting text shadows for highlighted regions.**
* **Retrieving the text ranges that need to be highlighted for different purposes (selection, search, spelling, etc.).**
* **Calculating the precise rectangular areas where highlights should be drawn.**
* **The core logic for iterating through highlight layers and parts, and drawing the background, shadow, text, and decorations for each part.**
* **Painting highlight backgrounds, considering transformations and dark mode.**
* **Mapping internal marker types to CSS pseudo-elements, decoration lines, and colors.**
* **Converting between different coordinate systems to position highlights correctly.**
* **Clipping the drawing area to optimize performance and prevent overdraw.**
* **Painting text decorations (underlines, overlines, line-throughs) for highlighted text.**
* **Specifically painting the text content for composition markers (used during text input).**

Essentially, this section takes the information about what *should* be highlighted and *how* it should be styled and translates it into actual drawing commands on the graphics context.
这是 `blink/renderer/core/paint/highlight_painter.cc` 源代码文件的第二部分，延续了第一部分的功能，主要负责实现高亮效果的绘制。

**本部分的功能归纳如下:**

* **绘制拼写和语法错误装饰:**  `PaintOneSpellingGrammarDecoration` 函数负责在指定的文本范围内绘制拼写或语法错误的装饰线（通常是波浪线）。它会根据错误的类型获取相应的样式，并使用 `decoration_painter_` 进行绘制。

* **绘制原始文本的阴影:** `PaintOriginatingShadow` 函数用于绘制原始文本的阴影效果，这通常用于非高亮状态的文本。

* **获取需要高亮的区域:** `GetHighlights` 函数根据不同的高亮图层类型 (`HighlightLayerType`)，从相应的标记列表中提取出需要高亮的文本范围。这些标记可能来自拼写检查、语法检查、自定义高亮、搜索结果或用户选择等。它会将这些范围转换为 `LayoutSelectionStatus` 对象。

* **转换文本偏移量:** `GetFragmentDOMOffsets` 函数将文本片段内的偏移量转换为在整个 DOM 节点中的偏移量。这对于理解高亮范围在文档中的位置非常重要。

* **计算背景高亮的矩形区域:** `ComputeBackgroundRect` 和 `ComputeBackgroundRectForSelection` 函数用于计算高亮背景的矩形区域。`ComputeBackgroundRectForSelection` 专门用于用户选择的情况，可能需要考虑行高和换行符等。

* **绘制高亮覆盖层:** `PaintHighlightOverlays` 是核心函数，负责绘制各种高亮效果。它会遍历不同的高亮图层，并为每个图层中的每个部分绘制背景颜色、文本阴影和文本本身。它还处理文本装饰（如下划线等）的绘制，并尝试合并相邻的同类型高亮部分以优化绘制性能。

* **绘制单个高亮背景:** `PaintHighlightBackground` 函数负责绘制一个单独的高亮背景矩形，它可以处理旋转变换和暗黑模式。

* **辅助函数:**  `PseudoFor`, `LineFor`, `ColorFor` 等函数是辅助函数，用于根据 `DocumentMarker::MarkerType` 获取相应的 CSS 伪元素 ID、文本装饰线类型和颜色。

* **计算行相对的世界坐标矩形:** `LineRelativeWorldRect` 函数计算相对于行的世界坐标系下的矩形范围，用于高亮绘制。

* **计算书写模式下的局部矩形:** `LocalRectInWritingModeSpace` 函数计算在特定书写模式下的局部矩形范围。

* **裁剪绘制区域:** `ClipToPartRect` 函数用于裁剪绘制区域，以确保高亮效果只绘制在需要绘制的区域内。

* **绘制文本装饰（除了删除线）:** `PaintDecorationsExceptLineThrough` 函数负责绘制文本装饰，但不包括删除线。它可以根据不同的装饰线类型进行绘制，并考虑高亮图层。

* **仅绘制删除线:** `PaintDecorationsOnlyLineThrough` 函数专门用于绘制删除线。

* **绘制输入法组合标记的文本:** `PaintTextForCompositionMarker` 函数用于绘制输入法组合输入时的文本，具有特定的颜色和样式。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:** 代码中大量使用了 CSS 的概念，例如：
    * **CSS 伪元素:**  `PseudoFor` 函数将 `DocumentMarker` 类型映射到 CSS 伪元素，例如 `::spelling-error`, `::grammar-error`, `::target-text`。这些伪元素可以通过 CSS 进行样式定制，例如修改拼写错误下划线的颜色。
    * **CSS 文本装饰:** `LineFor` 函数将 `DocumentMarker` 类型映射到 CSS 文本装饰线类型，例如 `text-decoration-line: underline wavy red;` 可以通过 CSS 设置拼写错误下划线的样式。
    * **背景颜色和文本阴影:**  `PaintHighlightOverlays` 函数会根据 CSS 样式中的 `background-color` 和 `text-shadow` 属性来绘制高亮背景和文本阴影。例如，用户可以通过 CSS 设置选中文本的背景颜色。
    * **currentColor:** 代码中使用了 `current_color`，这意味着高亮的颜色可以继承自父元素的文本颜色。

    **例子:**

    ```css
    /* 设置拼写错误高亮的样式 */
    ::-webkit-spelling-error {
      text-decoration: underline wavy red;
    }

    /* 设置选中文本的背景色 */
    ::selection {
      background-color: yellow;
    }
    ```

* **HTML:**  高亮 Painter 最终是在 HTML 元素的内容上进行绘制的。它会遍历文本节点，根据需要高亮的范围进行绘制。

    **例子:**  在一个包含拼写错误的 `<p>` 元素中，`HighlightPainter` 会识别出错误单词的范围，并根据 CSS 样式在其下方绘制波浪线。

* **JavaScript:** JavaScript 可以触发高亮的绘制，例如：
    * **用户选择文本:**  当用户使用鼠标在网页上选择一段文本时，浏览器会触发相应的事件，最终导致 `HighlightPainter` 绘制选中文本的背景高亮。
    * **使用 JavaScript API 进行文本搜索或高亮:** JavaScript 可以使用 `window.find()` 或自定义的文本搜索算法找到匹配的文本，并使用相应的 API 来添加高亮效果。
    * **编辑文本内容:** 当用户在可编辑的 HTML 元素中输入文本时，浏览器可能会进行拼写或语法检查，如果发现错误，会调用 `HighlightPainter` 来绘制错误标记。

**逻辑推理的假设输入与输出:**

假设输入：

* `marker_type` 为 `DocumentMarker::kSpelling`
* `text` 为 "worng"
* `paint_start_offset` 为 0
* `paint_end_offset` 为 5
* `originating_style_` 包含默认的拼写错误下划线样式

输出：

`PaintOneSpellingGrammarDecoration` 函数会在 "worng" 这个词的下方绘制一条红色的波浪线。

**用户或编程常见的使用错误:**

* **CSS 样式覆盖问题:** 用户可能会通过 CSS 将高亮伪元素的样式设置为 `display: none;` 或其他导致无法显示的效果，从而导致高亮功能失效。
* **JavaScript 操作错误:**  开发者可能在使用 JavaScript API 添加高亮时，计算的文本范围不正确，导致高亮位置错误或高亮了不应该高亮的文本。
* **浏览器兼容性问题:** 某些 CSS 高亮相关的伪元素或属性可能在不同的浏览器中支持程度不同，导致在某些浏览器上高亮效果不正确。
* **错误的 Marker 数据:** 如果传递给 `HighlightPainter` 的 `DocumentMarker` 数据中的偏移量不正确，会导致高亮位置错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

以拼写检查高亮为例：

1. **用户在可编辑的文本区域 (例如 `<textarea>` 或设置了 `contenteditable="true"` 的元素) 中输入文本。**
2. **浏览器内置的拼写检查器 (或操作系统提供的拼写检查服务) 检测到拼写错误，例如输入了 "worng"。**
3. **拼写检查器会创建一个 `DocumentMarker` 对象，标记错误的位置和类型 (例如 `DocumentMarker::kSpelling`)。**
4. **布局引擎 (Layout Engine) 在进行渲染时，会识别出这些 `DocumentMarker`。**
5. **在绘制阶段，当需要绘制包含拼写错误的文本片段时，会调用 `HighlightPainter`。**
6. **`HighlightPainter` 会根据 `DocumentMarker` 的信息，调用 `PaintOneSpellingGrammarDecoration` 函数。**
7. **`PaintOneSpellingGrammarDecoration` 函数会获取与拼写错误相关的 CSS 样式，并使用 `decoration_painter_` 在文本下方绘制波浪线。**

**总结 `HighlightPainter` 的功能 (结合第一部分):**

`HighlightPainter` 类在 Chromium Blink 引擎中扮演着至关重要的角色，负责在网页上绘制各种高亮效果。它能够：

1. **管理和存储需要高亮的信息:**  包括用户选择、拼写/语法错误、搜索结果、自定义高亮等。
2. **根据 CSS 样式和高亮类型，计算出需要绘制的高亮区域和样式。**
3. **高效地绘制各种高亮效果，包括背景颜色、文本阴影和文本装饰。**
4. **处理各种复杂情况，例如文本方向、换行、SVG 文本等。**
5. **与浏览器的其他组件 (例如布局引擎、文本渲染器、拼写检查器) 协同工作，确保高亮效果的正确显示。**

总而言之，`HighlightPainter` 是 Blink 引擎中负责实现网页视觉反馈的重要组成部分，它将抽象的高亮需求转化为具体的像素绘制操作。

### 提示词
```
这是目录为blink/renderer/core/paint/highlight_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
{}, {}};
  PaintOneSpellingGrammarDecoration(type, text, paint_start_offset,
                                    paint_end_offset, originating_style_,
                                    originating_text_style_, &synthesised);
}

void HighlightPainter::PaintOneSpellingGrammarDecoration(
    DocumentMarker::MarkerType marker_type,
    const StringView& text,
    unsigned paint_start_offset,
    unsigned paint_end_offset,
    const ComputedStyle& style,
    const TextPaintStyle& text_style,
    const AppliedTextDecoration* decoration_override) {
  // When painting decorations on the spelling/grammar fast path, the part and
  // the decoration have the same range, so we can use the same rect for both
  // clipping the canvas and painting the decoration.
  const HighlightRange range{paint_start_offset, paint_end_offset};
  const LineRelativeRect rect = LineRelativeWorldRect(range);

  std::optional<TextDecorationInfo> decoration_info{};
  decoration_painter_.UpdateDecorationInfo(decoration_info, fragment_item_,
                                           style, rect, decoration_override);

  GraphicsContextStateSaver saver{paint_info_.context};
  ClipToPartRect(rect);

  decoration_painter_.PaintExceptLineThrough(
      *decoration_info, text_style,
      fragment_paint_info_.Slice(paint_start_offset, paint_end_offset),
      LineFor(marker_type));
}

void HighlightPainter::PaintOriginatingShadow(const TextPaintStyle& text_style,
                                              DOMNodeId node_id) {
  DCHECK_EQ(paint_case_, kOverlay);

  // First paint the shadows for the whole range.
  if (text_style.shadow) {
    text_painter_.Paint(fragment_paint_info_, text_style, node_id,
                        foreground_auto_dark_mode_, TextPainter::kShadowsOnly);
  }
}

Vector<LayoutSelectionStatus> HighlightPainter::GetHighlights(
    const HighlightLayer& layer) {
  Vector<LayoutSelectionStatus> result{};
  const auto* text_node = DynamicTo<Text>(node_);
  switch (layer.type) {
    case HighlightLayerType::kOriginating:
      NOTREACHED();
    case HighlightLayerType::kCustom: {
      DCHECK(text_node);
      const MarkerRangeMappingContext mapping_context(*text_node,
                                                      *fragment_dom_offsets_);
      for (const auto& marker : custom_) {
        // Filter custom highlight markers to one highlight at a time.
        auto* custom = To<CustomHighlightMarker>(marker.Get());
        if (custom->GetHighlightName() != layer.PseudoArgument()) {
          continue;
        }
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (marker_offsets && (marker_offsets->start != marker_offsets->end)) {
          result.push_back(
              LayoutSelectionStatus{marker_offsets->start, marker_offsets->end,
                                    SelectSoftLineBreak::kNotSelected});
        }
      }
      break;
    }
    case HighlightLayerType::kGrammar: {
      DCHECK(text_node);
      const MarkerRangeMappingContext mapping_context(*text_node,
                                                      *fragment_dom_offsets_);
      for (const auto& marker : grammar_) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (marker_offsets && (marker_offsets->start != marker_offsets->end)) {
          result.push_back(
              LayoutSelectionStatus{marker_offsets->start, marker_offsets->end,
                                    SelectSoftLineBreak::kNotSelected});
        }
      }
      break;
    }
    case HighlightLayerType::kSpelling: {
      DCHECK(text_node);
      const MarkerRangeMappingContext mapping_context(*text_node,
                                                      *fragment_dom_offsets_);
      for (const auto& marker : spelling_) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (marker_offsets && (marker_offsets->start != marker_offsets->end)) {
          result.push_back(
              LayoutSelectionStatus{marker_offsets->start, marker_offsets->end,
                                    SelectSoftLineBreak::kNotSelected});
        }
      }
      break;
    }
    case HighlightLayerType::kTargetText: {
      DCHECK(text_node);
      const MarkerRangeMappingContext mapping_context(*text_node,
                                                      *fragment_dom_offsets_);
      for (const auto& marker : target_) {
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (marker_offsets && (marker_offsets->start != marker_offsets->end)) {
          result.push_back(
              LayoutSelectionStatus{marker_offsets->start, marker_offsets->end,
                                    SelectSoftLineBreak::kNotSelected});
        }
      }
      break;
    }
    case HighlightLayerType::kSearchText:
    case HighlightLayerType::kSearchTextActiveMatch: {
      DCHECK(text_node);
      const MarkerRangeMappingContext mapping_context(*text_node,
                                                      *fragment_dom_offsets_);
      for (const auto& marker : search_) {
        auto* text_match_marker = To<TextMatchMarker>(marker.Get());
        bool is_current =
            layer.type == HighlightLayerType::kSearchTextActiveMatch;
        if (text_match_marker->IsActiveMatch() != is_current) {
          continue;
        }
        std::optional<TextOffsetRange> marker_offsets =
            mapping_context.GetTextContentOffsets(*marker);
        if (marker_offsets && (marker_offsets->start != marker_offsets->end)) {
          result.push_back(
              LayoutSelectionStatus{marker_offsets->start, marker_offsets->end,
                                    SelectSoftLineBreak::kNotSelected});
        }
      }
      break;
    }
    case HighlightLayerType::kSelection:
      result.push_back(*GetSelectionStatus(selection_));
      break;
  }
  return result;
}

TextOffsetRange HighlightPainter::GetFragmentDOMOffsets(const Text& text,
                                                        unsigned from,
                                                        unsigned to) {
  const OffsetMapping* mapping = OffsetMapping::GetFor(text.GetLayoutObject());
  unsigned last_from = mapping->GetLastPosition(from).OffsetInContainerNode();
  unsigned first_to = mapping->GetFirstPosition(to).OffsetInContainerNode();
  return {last_from, first_to};
}

const PhysicalRect HighlightPainter::ComputeBackgroundRect(
    StringView text,
    unsigned start_offset,
    unsigned end_offset) {
  return fragment_item_.LocalRect(text, start_offset, end_offset) + box_origin_;
}

const PhysicalRect HighlightPainter::ComputeBackgroundRectForSelection(
    unsigned start_offset,
    unsigned end_offset) {
  LayoutSelectionStatus selection_status{selection_->Status()};
  selection_status.start = start_offset;
  selection_status.end = end_offset;
  return root_inline_cursor_.CurrentLocalSelectionRectForText(
             selection_status) +
         box_origin_;
}

void HighlightPainter::PaintHighlightOverlays(
    const TextPaintStyle& originating_text_style,
    DOMNodeId node_id,
    bool paint_marker_backgrounds,
    std::optional<AffineTransform> rotation) {
  DCHECK_EQ(paint_case_, kOverlay);

  // |node_| might not be a Text node (e.g. <br>), or it might be nullptr (e.g.
  // ::first-letter). In both cases, we should still try to paint kOriginating
  // and kSelection if necessary, but we can’t paint marker-based highlights,
  // because GetTextContentOffset requires a Text node. Markers are defined and
  // stored in terms of Text nodes anyway, so this should never be a problem.

  // For each overlay, paint ‘background-color’ and ‘text-shadow’ one part at a
  // time, since both of them may vary in color when ‘color’ is ‘currentColor’.
  for (wtf_size_t i = 0; i < layers_.size(); i++) {
    const HighlightLayer& layer = layers_[i];

    if (layer.type == HighlightLayerType::kOriginating) {
      continue;
    }

    if (layer.type == HighlightLayerType::kSelection &&
        !paint_marker_backgrounds) {
      continue;
    }

    // Paint ‘background-color’ while trying to merge parts if possible,
    // to avoid creating unnecessary “seams”.
    MergedHighlightPart<HighlightBackground> merged_background{};
    const auto& paint_background =
        [&](const MergedHighlightPart<HighlightBackground>::Merged& merged) {
          if (merged.inner.color.IsFullyTransparent()) {
            return;
          }
          // TODO(crbug.com/40281215) ComputeBackgroundRect should use the same
          // logic as ComputeBackgroundRectForSelection, that is, it should
          // expand selection to the line height and extend for line breaks.
          PhysicalRect part_rect =
              layer.type == HighlightLayerType::kSelection
                  ? ComputeBackgroundRectForSelection(merged.from, merged.to)
                  : ComputeBackgroundRect(cursor_.CurrentText(), merged.from,
                                          merged.to);
          PaintHighlightBackground(paint_info_.context, originating_style_,
                                   merged.inner.color, part_rect, rotation);
        };
    for (const HighlightPart& part : parts_) {
      for (const HighlightBackground& background : part.backgrounds) {
        if (background.layer_index == i) {
          if (const auto& merged = merged_background.Merge(background, part)) {
            paint_background(*merged);
          }
          break;
        }
      }
    }
    if (const auto& merged = merged_background.Take()) {
      paint_background(*merged);
    }

    // Paint ‘text-shadow’ while trying to merge parts if possible,
    // to avoid unnecessarily splitting ligatures.
    MergedHighlightPart<HighlightTextShadow> merged_text_shadow{};
    const auto& paint_text_shadow =
        [&](const MergedHighlightPart<HighlightTextShadow>::Merged& merged) {
          if (!layer.text_style.style.shadow) {
            return;
          }
          TextPaintStyle text_shadow_style{};
          text_shadow_style.shadow = layer.text_style.style.shadow;
          text_shadow_style.current_color = merged.inner.current_color;
          text_painter_.Paint(
              fragment_paint_info_.Slice(merged.from, merged.to),
              text_shadow_style, node_id, foreground_auto_dark_mode_,
              TextPainter::kShadowsOnly);
        };
    for (const HighlightPart& part : parts_) {
      for (const HighlightTextShadow& text_shadow : part.text_shadows) {
        if (text_shadow.layer_index == i) {
          if (const auto& merged =
                  merged_text_shadow.Merge(text_shadow, part)) {
            paint_text_shadow(*merged);
          }
          break;
        }
      }
    }
    if (const auto& merged = merged_text_shadow.Take()) {
      paint_text_shadow(*merged);
    }
  }

  // For each part, paint the text proper over every highlighted range,
  for (auto& part : parts_) {
    LineRelativeRect part_rect = LineRelativeWorldRect(part.range);

    PaintDecorationsExceptLineThrough(part, part_rect);

    // Only paint text if we have a shape result. See TextPainter::Paint().
    if (fragment_paint_info_.shape_result) {
      std::optional<base::AutoReset<bool>> is_painting_selection_reset;
      GraphicsContextStateSaver state_saver(paint_info_.context);
      // SVG text may have transforms that defeat clipping. The clipping
      // is only required for ligatures, so we will accept potential
      // double painting of ligatures for SVG so as to correctly handle
      // transformed text (include text paths). This might be fixable by
      // transforming the ink overflow before using it to expamd the clip.
      TextPainter::SvgTextPaintState* svg_state = text_painter_.GetSvgState();
      if (svg_state && part.type == HighlightLayerType::kSelection)
          [[unlikely]] {
        // SVG text painting needs to know it is painting selection.
        is_painting_selection_reset.emplace(&svg_state->is_painting_selection_,
                                            true);
      } else {
        LineRelativeRect clip_rect = part_rect;
        if (part.stroke_width > 0) {
          clip_rect.Inflate(
              LayoutUnit::FromFloatCeil(part.stroke_width / 2.0f));
        }
        // If we're at the far left or right end of a fragment, expand the clip
        // to avoid clipping characters (italics and some antialiasing).
        if (part.range.from == fragment_paint_info_.from) {
          clip_rect.AdjustLineStartToInkOverflow(fragment_item_);
        }
        if (part.range.to == fragment_paint_info_.to) {
          clip_rect.AdjustLineEndToInkOverflow(fragment_item_);
        }
        ClipToPartRect(clip_rect.EnclosingLineRelativeRect());
      }

      // Adjust start/end offset when they are in the middle of a ligature.
      // e.g., when |start_offset| is between a ligature of "fi", it needs to
      // be adjusted to before "f".
      unsigned start = part.range.from;
      unsigned end = part.range.to;
      fragment_paint_info_.shape_result->ExpandRangeToIncludePartialGlyphs(
          &start, &end);

      text_painter_.Paint(fragment_paint_info_.Slice(start, end),
                          part.style, node_id, foreground_auto_dark_mode_,
                          TextPainter::kTextProperOnly);
    }

    PaintDecorationsOnlyLineThrough(part, part_rect);
  }
}

void HighlightPainter::PaintHighlightBackground(
    GraphicsContext& context,
    const ComputedStyle& style,
    Color color,
    const PhysicalRect& rect,
    const std::optional<AffineTransform>& rotation) {
  AutoDarkMode auto_dark_mode(
      PaintAutoDarkMode(style, DarkModeFilter::ElementRole::kSelection));

  if (!rotation) {
    PaintRect(context, rect, color, auto_dark_mode);
    return;
  }

  // PaintRect tries to pixel-snap the given rect, but if we’re painting in a
  // non-horizontal writing mode, our context has been transformed, regressing
  // tests like <paint/invalidation/repaint-across-writing-mode-boundary>. To
  // fix this, we undo the transformation temporarily, then use the original
  // physical coordinates (before MapSelectionRectIntoRotatedSpace).
  context.ConcatCTM(rotation->Inverse());
  PaintRect(context, rect, color, auto_dark_mode);
  context.ConcatCTM(*rotation);
}

PseudoId HighlightPainter::PseudoFor(DocumentMarker::MarkerType type) {
  switch (type) {
    case DocumentMarker::kSpelling:
      return kPseudoIdSpellingError;
    case DocumentMarker::kGrammar:
      return kPseudoIdGrammarError;
    case DocumentMarker::kTextFragment:
      return kPseudoIdTargetText;
    default:
      NOTREACHED();
  }
}

TextDecorationLine HighlightPainter::LineFor(DocumentMarker::MarkerType type) {
  switch (type) {
    case DocumentMarker::kSpelling:
      return TextDecorationLine::kSpellingError;
    case DocumentMarker::kGrammar:
      return TextDecorationLine::kGrammarError;
    default:
      NOTREACHED();
  }
}

Color HighlightPainter::ColorFor(DocumentMarker::MarkerType type) {
  switch (type) {
    case DocumentMarker::kSpelling:
      return LayoutTheme::GetTheme().PlatformSpellingMarkerUnderlineColor();
    case DocumentMarker::kGrammar:
      return LayoutTheme::GetTheme().PlatformGrammarMarkerUnderlineColor();
    default:
      NOTREACHED();
  }
}

LineRelativeRect HighlightPainter::LineRelativeWorldRect(
    const HighlightOverlay::HighlightRange& range) {
  return LocalRectInWritingModeSpace(range.from, range.to) +
         LineRelativeOffset::CreateFromBoxOrigin(box_origin_);
}

LineRelativeRect HighlightPainter::LocalRectInWritingModeSpace(
    unsigned from,
    unsigned to) const {
  if (paint_case_ != kOverlay) {
    const StringView text = cursor_.CurrentText();
    return LineRelativeLocalRect(fragment_item_, text, from, to);
  }

  auto from_info =
      std::lower_bound(edges_info_.begin(), edges_info_.end(), from,
                       [](const HighlightEdgeInfo& info, unsigned offset) {
                         return info.offset < offset;
                       });
  auto to_info =
      std::lower_bound(from_info, edges_info_.end(), to,
                       [](const HighlightEdgeInfo& info, unsigned offset) {
                         return info.offset < offset;
                       });
  CHECK_NE(from_info, edges_info_.end(), base::NotFatalUntil::M130);
  CHECK_NE(to_info, edges_info_.end(), base::NotFatalUntil::M130);

  // This rect is used for 2 purposes: To set the offset and width for
  // text decoration painting, and the set the clip. The former uses the
  // offset and width, but not height, and the offset should be the
  // fragment offset. The latter uses offset and size, but the offset should
  // be the corner of the painted region. Return the origin for text decorations
  // and the height for clipping, then update the offset for clipping in the
  // calling code.
  const LayoutUnit height = fragment_item_.InkOverflowRect().Height();
  LayoutUnit left;
  LayoutUnit right;
  if (from_info->x > to_info->x) {
    left = LayoutUnit::FromFloatFloor(to_info->x);
    right = LayoutUnit::FromFloatCeil(from_info->x);
  } else {
    left = LayoutUnit::FromFloatFloor(from_info->x);
    right = LayoutUnit::FromFloatCeil(to_info->x);
  }
  return {{left, LayoutUnit{}}, {right - left, height}};
}

void HighlightPainter::ClipToPartRect(const LineRelativeRect& part_rect) {
  gfx::RectF clip_rect{part_rect};
  if (fragment_item_.IsSvgText()) [[unlikely]] {
    clip_rect = TextDecorationPainter::ExpandRectForSVGDecorations(part_rect);
  } else {
    clip_rect.Offset(0, fragment_item_.InkOverflowRect().Y());
  }
  paint_info_.context.Clip(clip_rect);
}

void HighlightPainter::PaintDecorationsExceptLineThrough(
    const HighlightPart& part,
    const LineRelativeRect& part_rect) {
  // Line decorations in highlight pseudos are ordered first by the kind of line
  // (underlines before overlines), then by the highlight layer they came from.
  // https://github.com/w3c/csswg-drafts/issues/6022
  PaintDecorationsExceptLineThrough(part, part_rect,
                                    TextDecorationLine::kUnderline);
  PaintDecorationsExceptLineThrough(part, part_rect,
                                    TextDecorationLine::kOverline);
  PaintDecorationsExceptLineThrough(
      part, part_rect,
      TextDecorationLine::kSpellingError | TextDecorationLine::kGrammarError);
}

void HighlightPainter::PaintDecorationsExceptLineThrough(
    const HighlightPart& part,
    const LineRelativeRect& part_rect,
    TextDecorationLine lines_to_paint) {
  GraphicsContextStateSaver state_saver(paint_info_.context, false);
  for (const HighlightDecoration& decoration : part.decorations) {
    HighlightLayer& decoration_layer = layers_[decoration.layer_index];

    // Clipping the canvas unnecessarily is expensive, so avoid doing it if
    // there are no decorations of the given |lines_to_paint|.
    if (!EnumHasFlags(decoration_layer.decorations_in_effect, lines_to_paint)) {
      continue;
    }

    // SVG painting currently ignores ::selection styles, and will malfunction
    // or crash if asked to paint decorations introduced by highlight pseudos.
    // TODO(crbug.com/1147859) is SVG spec ready for highlight decorations?
    // TODO(crbug.com/1147859) https://github.com/w3c/svgwg/issues/894
    if (text_painter_.GetSvgState() &&
        decoration.type != HighlightLayerType::kOriginating) {
      continue;
    }

    // Paint the decoration over the range of the originating fragment or active
    // highlight, but clip it to the range of the part.
    const LineRelativeRect decoration_rect =
        LineRelativeWorldRect(decoration.range);

    std::optional<TextDecorationInfo> decoration_info{};
    decoration_painter_.UpdateDecorationInfo(decoration_info, fragment_item_,
                                             *decoration_layer.style,
                                             decoration_rect);

    if (part.type != HighlightLayerType::kOriginating) {
      if (decoration.type == HighlightLayerType::kOriginating) {
        decoration_info->SetHighlightOverrideColor(part.style.current_color);
      } else {
        decoration_info->SetHighlightOverrideColor(
            decoration.highlight_override_color);
      }
    }

    if (!state_saver.Saved()) {
      state_saver.Save();
      const LineRelativeRect clip_rect =
          part.range != decoration.range ? part_rect : decoration_rect;
      ClipToPartRect(clip_rect);
    }

    decoration_painter_.PaintExceptLineThrough(
        *decoration_info, decoration_layer.text_style.style,
        fragment_paint_info_.Slice(part.range.from, part.range.to),
        lines_to_paint);
  }
}

void HighlightPainter::PaintDecorationsOnlyLineThrough(
    const HighlightPart& part,
    const LineRelativeRect& part_rect) {
  GraphicsContextStateSaver state_saver(paint_info_.context, false);
  for (const HighlightDecoration& decoration : part.decorations) {
    HighlightLayer& decoration_layer = layers_[decoration.layer_index];

    // Clipping the canvas unnecessarily is expensive, so avoid doing it if
    // there are no ‘line-through’ decorations.
    if (!EnumHasFlags(decoration_layer.decorations_in_effect,
                      TextDecorationLine::kLineThrough)) {
      continue;
    }

    // SVG painting currently ignores ::selection styles, and will malfunction
    // or crash if asked to paint decorations introduced by highlight pseudos.
    // TODO(crbug.com/1147859) is SVG spec ready for highlight decorations?
    // TODO(crbug.com/1147859) https://github.com/w3c/svgwg/issues/894
    if (text_painter_.GetSvgState() &&
        decoration.type != HighlightLayerType::kOriginating) {
      continue;
    }

    // Paint the decoration over the range of the originating fragment or active
    // highlight, but clip it to the range of the part.
    const LineRelativeRect decoration_rect =
        LineRelativeWorldRect(decoration.range);

    std::optional<TextDecorationInfo> decoration_info{};
    decoration_painter_.UpdateDecorationInfo(decoration_info, fragment_item_,
                                             *decoration_layer.style,
                                             decoration_rect);

    if (part.type != HighlightLayerType::kOriginating) {
      if (decoration.type == HighlightLayerType::kOriginating) {
        decoration_info->SetHighlightOverrideColor(part.style.current_color);
      } else {
        decoration_info->SetHighlightOverrideColor(
            decoration.highlight_override_color);
      }
    }

    if (!state_saver.Saved()) {
      state_saver.Save();
      const LineRelativeRect clip_rect =
          part.range != decoration.range ? part_rect : decoration_rect;
      ClipToPartRect(clip_rect);
    }

    decoration_painter_.PaintOnlyLineThrough(*decoration_info,
                                             decoration_layer.text_style.style);
  }
}

void HighlightPainter::PaintTextForCompositionMarker(
    const StringView& text,
    const Color& text_color,
    unsigned paint_start_offset,
    unsigned paint_end_offset) {
  TextPaintStyle text_style;
  text_style.current_color = text_style.fill_color = text_style.stroke_color =
      text_style.emphasis_mark_color = text_color;
  text_style.stroke_width = originating_style_.TextStrokeWidth();
  text_style.color_scheme = originating_style_.UsedColorScheme();
  text_style.shadow = nullptr;
  text_style.paint_order = originating_style_.PaintOrder();

  LineRelativeRect decoration_rect = LineRelativeLocalRect(
      fragment_item_, text, paint_start_offset, paint_end_offset);
  decoration_rect.Move(LineRelativeOffset::CreateFromBoxOrigin(box_origin_));
  TextDecorationPainter decoration_painter(
      text_painter_, decoration_painter_.InlineContext(), paint_info_,
      originating_style_, text_style, decoration_rect, selection_);

  decoration_painter.Begin(fragment_item_, TextDecorationPainter::kOriginating);
  decoration_painter.PaintExceptLineThrough(
      fragment_paint_info_.Slice(paint_start_offset, paint_end_offset));

  text_painter_.Paint(
      fragment_paint_info_.Slice(paint_start_offset, paint_end_offset),
      text_style, kInvalidDOMNodeId, foreground_auto_dark_mode_);

  decoration_painter.PaintOnlyLineThrough();
}

}  // namespace blink
```