Response:
The user wants me to analyze the provided C++ code snippet from the Chromium Blink engine, specifically the `inline_node.cc` file. I need to:

1. **Summarize its functionality:** What does this file do in the context of the Blink rendering engine?
2. **Relate it to web technologies (JavaScript, HTML, CSS):** How does this code contribute to the rendering of web pages?  Provide concrete examples.
3. **Explain logic through input/output examples:** If the code performs logical reasoning or processing, illustrate it with hypothetical inputs and their corresponding outputs.
4. **Highlight common user/programming errors:** Identify potential mistakes users or developers might make related to the functionality of this code.
5. **Focus on summarizing the functionality for this first part.**

**Thinking Process:**

1. **High-level understanding:** The file name `inline_node.cc` and the included headers suggest this code is responsible for handling inline elements during the layout process. It deals with text, boxes, and their arrangement within a line.

2. **Key components identified:**  Scanning the includes and the code itself reveals several important concepts:
    * **Inline Items:** The code frequently manipulates `InlineItem` objects, which likely represent individual pieces of inline content (text, atomic elements, etc.).
    * **Shaping:**  References to HarfBuzz and shaping results indicate this code is heavily involved in the process of converting text into glyphs based on the font and language.
    * **Line Breaking:** The presence of `LineBreaker` suggests responsibility for determining where lines of text should wrap.
    * **Offset Mapping:** This likely involves mapping character offsets in the underlying text to the corresponding `InlineItem` structure.
    * **Layout Objects:** The code interacts with various layout objects like `LayoutText`, `LayoutInline`, `LayoutBlockFlow`, etc.

3. **Relating to web technologies:**
    * **HTML:** The structure of the HTML document, specifically inline elements like `<span>`, `<a>`, `<em>`, is what this code processes.
    * **CSS:** CSS properties related to text rendering (font, color, line height, white-space, text-combine-upright, vertical-align), box model properties (padding, margin, border), and list markers directly influence the behavior of this code.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, changes made by JavaScript to the DOM (e.g., adding/removing text, changing styles) will trigger this layout code to re-run.

4. **Logic and Input/Output (for later parts):** I'll need to analyze specific functions like `Mismatch`, `ReusingTextShaper::Shape`, and `CollectInlinesInternal` to provide concrete examples of their logic and how inputs transform into outputs.

5. **Common errors (for later parts):** These might involve incorrect CSS styling that leads to unexpected layout, issues with font loading, or problems with complex text rendering scenarios like bi-directional text.

6. **Focusing on the summary for this part:**  The core functionality revolves around preparing inline content for layout. This involves collecting inline elements, segmenting text, shaping it (converting text to glyphs), and associating these shaped items with their corresponding layout objects. The code optimizes for performance by reusing previous shaping results when possible.
这是 `blink/renderer/core/layout/inline/inline_node.cc` 文件的第一部分，其主要功能是**为块级盒（LayoutBlockFlow）中的内联内容准备布局数据**。  更具体地说，它负责以下几个关键步骤：

**核心功能归纳：**

1. **收集内联项 (Collecting Inline Items):**  遍历块级盒的子节点，识别并收集所有参与内联布局的元素，例如文本节点、内联元素、原子内联元素（如 `<img>`）、浮动元素和定位元素。
2. **文本分段 (Segmenting Text):**  将收集到的文本内容进行分段，这可能涉及到处理换行符或其他分隔符。
3. **文本塑形 (Shaping Text):**  将文本内容转换为可用于渲染的字形（glyphs）。这个过程涉及到字体选择、语言处理、以及复杂的排版算法（例如使用 HarfBuzz 库）。
4. **关联内联项与布局对象 (Associating Items with Layout Objects):**  将生成的内联项与它们对应的布局对象关联起来，以便后续的布局计算可以访问这些信息。
5. **优化和缓存 (Optimization and Caching):**  尝试重用之前布局计算的文本塑形结果，以提高性能，特别是在文本内容只有少量修改时。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** 该代码处理的是 HTML 结构中的内联元素。
    * **例子:**  当浏览器解析如下 HTML 代码时，`inline_node.cc` 会处理 `<span>` 标签内的文本 "This is inline text"。
      ```html
      <div>
        <span>This is inline text</span>
      </div>
      ```
* **CSS:** CSS 样式会直接影响 `inline_node.cc` 的行为，特别是与文本渲染相关的属性。
    * **例子:**
        * **`font-family`, `font-size`, `color`:** 这些属性会影响文本塑形过程中使用的字体和颜色。
        * **`white-space`:**  `white-space: pre` 会阻止文本自动换行，`inline_node.cc` 会根据这个属性来决定如何分段和布局文本。
        * **`direction`:**  `direction: rtl` 会影响文本的阅读方向，`inline_node.cc` 需要处理从右到左的文本布局。
        * **`text-combine-upright: all`:**  这个 CSS 属性会导致文本垂直排列，`inline_node.cc` 需要特殊处理并调整字体大小以适应。
* **JavaScript:**  JavaScript 可以动态修改 HTML 结构和 CSS 样式，这些修改会触发 Blink 重新进行布局计算，包括 `inline_node.cc` 的执行。
    * **例子:**  如果 JavaScript 代码修改了 `<span>` 标签内的文本内容，或者修改了 `<span>` 的 CSS `font-size` 属性，`inline_node.cc` 将会被调用来重新生成内联布局数据。

**逻辑推理的假设输入与输出 (将在后续部分更详细):**

这个第一部分主要关注数据的准备阶段，逻辑推理更多体现在如何高效地收集和处理内联项以及如何重用之前的计算结果。

* **假设输入:**  一个包含文本节点和内联 `<span>` 元素的 `LayoutBlockFlow` 对象。
* **输出:**  `InlineNodeData` 对象，其中包含：
    * `text_content`:  所有内联文本内容的组合字符串。
    * `items`:  一个 `InlineItem` 对象的向量，每个对象代表一个独立的内联片段（例如，一段文本具有相同的样式）。每个 `InlineItem` 可能包含指向 `ShapeResult` 的指针，存储了文本塑形的结果。

**涉及用户或者编程常见的使用错误 (将在后续部分更详细):**

* **CSS 样式冲突:**  不合理的 CSS 样式可能会导致 `inline_node.cc` 产生意想不到的布局结果。例如，设置一个过大的 `font-size` 可能导致文本溢出容器。
* **错误的 HTML 结构:**  不正确的 HTML 结构可能会影响内联元素的排列和布局。
* **字体加载失败:** 如果指定的字体无法加载，`inline_node.cc` 会使用备用字体，可能导致布局不一致。

**总结（针对第一部分）：**

`inline_node.cc` 文件的这一部分的核心功能是为块级元素中的内联内容准备必要的布局数据，包括收集内联元素、分段文本、进行文本塑形以及将这些信息组织到 `InlineNodeData` 结构中。这个过程是 Blink 渲染引擎进行后续内联布局计算的关键基础。它与 HTML 结构和 CSS 样式密切相关，并对 JavaScript 引起的 DOM 变化做出响应。 该代码也体现了对性能的关注，通过尝试重用之前的文本塑形结果来优化布局过程。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_node.h"

#include <memory>
#include <numeric>

#include "base/containers/adapters.h"
#include "base/debug/dump_without_crashing.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/dom/text_diff_range.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/initial_letter_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/inline_items_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/inline/inline_text_auto_space.h"
#include "third_party/blink/renderer/core/layout/inline/line_breaker.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/list/layout_inline_list_item.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/svg_inline_node_data.h"
#include "third_party/blink/renderer/core/layout/svg/svg_text_layout_attributes_builder.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/platform/fonts/font_performance.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/ng_shape_cache.h"
#include "third_party/blink/renderer/platform/fonts/shaping/run_segmenter.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"

namespace blink {

namespace {

template <typename Span1, typename Span2>
unsigned MismatchInternal(const Span1& span1, const Span2& span2) {
  const auto old_new = base::ranges::mismatch(span1, span2);
  return static_cast<unsigned>(old_new.first - span1.begin());
}

unsigned Mismatch(const String& old_text, const String& new_text) {
  if (old_text.Is8Bit()) {
    const auto old_span8 = old_text.Span8();
    if (new_text.Is8Bit()) {
      return MismatchInternal(old_span8, new_text.Span8());
    }
    return MismatchInternal(old_span8, new_text.Span16());
  }
  const auto old_span16 = old_text.Span16();
  if (new_text.Is8Bit()) {
    return MismatchInternal(old_span16, new_text.Span8());
  }
  return MismatchInternal(old_span16, new_text.Span16());
}

template <typename Span1, typename Span2>
unsigned MismatchFromEnd(const Span1& span1, const Span2& span2) {
  const auto old_new =
      base::ranges::mismatch(base::Reversed(span1), base::Reversed(span2));
  return static_cast<unsigned>(old_new.first - span1.rbegin());
}

unsigned MismatchFromEnd(StringView old_text, StringView new_text) {
  if (old_text.Is8Bit()) {
    if (new_text.Is8Bit()) {
      return MismatchFromEnd(old_text.Span8(), new_text.Span8());
    }
    return MismatchFromEnd(old_text.Span8(), new_text.Span16());
  }
  if (new_text.Is8Bit()) {
    return MismatchFromEnd(old_text.Span16(), new_text.Span8());
  }
  return MismatchFromEnd(old_text.Span16(), new_text.Span16());
}

// Returns sum of |ShapeResult::Width()| in |data.items|. Note: All items
// should be text item other type of items are not allowed.
float CalculateWidthForTextCombine(const InlineItemsData& data) {
  return std::accumulate(
      data.items.begin(), data.items.end(), 0.0f,
      [](float sum, const InlineItem& item) {
        DCHECK(item.Type() == InlineItem::kText ||
               item.Type() == InlineItem::kBidiControl ||
               item.Type() == InlineItem::kControl)
            << item.Type();
        if (auto* const shape_result = item.TextShapeResult())
          return shape_result->Width() + sum;
        return 0.0f;
      });
}

// Estimate the number of InlineItem to minimize the vector expansions.
unsigned EstimateInlineItemsCount(const LayoutBlockFlow& block) {
  unsigned count = 0;
  for (LayoutObject* child = block.FirstChild(); child;
       child = child->NextSibling()) {
    ++count;
  }
  return count * 4;
}

// Estimate the number of units and ranges in OffsetMapping to minimize vector
// and hash map expansions.
unsigned EstimateOffsetMappingItemsCount(const LayoutBlockFlow& block) {
  // Cancels out the factor 4 in EstimateInlineItemsCount() to get the number of
  // LayoutObjects.
  // TODO(layout-dev): Unify the two functions and make them less hacky.
  return EstimateInlineItemsCount(block) / 4;
}

// Wrapper over ShapeText that re-uses existing shape results for items that
// haven't changed.
class ReusingTextShaper final {
  STACK_ALLOCATED();

 public:
  ReusingTextShaper(InlineItemsData* data,
                    const HeapVector<InlineItem>* reusable_items,
                    const bool allow_shape_cache)
      : data_(*data),
        reusable_items_(reusable_items),
        shaper_(data->text_content),
        allow_shape_cache_(allow_shape_cache) {}

  void SetOptions(ShapeOptions options) { options_ = options; }

  const ShapeResult* Shape(const InlineItem& start_item,
                           const Font& font,
                           unsigned end_offset) {
    auto ShapeFunc = [&]() -> const ShapeResult* {
      return ShapeWithoutCache(start_item, font, end_offset);
    };
    if (allow_shape_cache_) {
      DCHECK(RuntimeEnabledFeatures::LayoutNGShapeCacheEnabled());
      return font.GetNGShapeCache().GetOrCreate(
          shaper_.GetText(), start_item.Direction(), ShapeFunc);
    }
    return ShapeFunc();
  }

 private:
  const ShapeResult* ShapeWithoutCache(const InlineItem& start_item,
                                       const Font& font,
                                       unsigned end_offset) {
    const unsigned start_offset = start_item.StartOffset();
    DCHECK_LT(start_offset, end_offset);

    if (!reusable_items_)
      return Reshape(start_item, font, start_offset, end_offset);

    // TODO(yosin): We should support segment text
    if (data_.segments)
      return Reshape(start_item, font, start_offset, end_offset);

    HeapVector<Member<const ShapeResult>> reusable_shape_results =
        CollectReusableShapeResults(start_offset, end_offset, font,
                                    start_item.Direction());
    ClearCollectionScope clear_scope(&reusable_shape_results);

    if (reusable_shape_results.empty())
      return Reshape(start_item, font, start_offset, end_offset);

    ShapeResult* shape_result =
        ShapeResult::CreateEmpty(*reusable_shape_results.front());
    unsigned offset = start_offset;
    for (const ShapeResult* reusable_shape_result : reusable_shape_results) {
      // In case of pre-wrap having break opportunity after leading space,
      // |offset| can be greater than |reusable_shape_result->StartIndex()|.
      // e.g. <div style="white-space:pre">&nbsp; abc</div>, deleteChar(0, 1)
      // See xternal/wpt/editing/run/delete.html?993-993
      if (offset < reusable_shape_result->StartIndex()) {
        AppendShapeResult(*Reshape(start_item, font, offset,
                                   reusable_shape_result->StartIndex()),
                          shape_result);
        offset = shape_result->EndIndex();
        options_.han_kerning_start = false;
      }
      DCHECK_LT(offset, reusable_shape_result->EndIndex());
      DCHECK(shape_result->NumCharacters() == 0 ||
             shape_result->EndIndex() == offset);
      reusable_shape_result->CopyRange(
          offset, std::min(reusable_shape_result->EndIndex(), end_offset),
          shape_result);
      offset = shape_result->EndIndex();
      if (offset == end_offset)
        return shape_result;
    }
    DCHECK_LT(offset, end_offset);
    AppendShapeResult(*Reshape(start_item, font, offset, end_offset),
                      shape_result);
    return shape_result;
  }

  void AppendShapeResult(const ShapeResult& shape_result, ShapeResult* target) {
    DCHECK(target->NumCharacters() == 0 ||
           target->EndIndex() == shape_result.StartIndex());
    shape_result.CopyRange(shape_result.StartIndex(), shape_result.EndIndex(),
                           target);
  }

  HeapVector<Member<const ShapeResult>> CollectReusableShapeResults(
      unsigned start_offset,
      unsigned end_offset,
      const Font& font,
      TextDirection direction) {
    DCHECK_LT(start_offset, end_offset);
    HeapVector<Member<const ShapeResult>> shape_results;
    if (!reusable_items_)
      return shape_results;
    for (auto item = std::lower_bound(
             reusable_items_->begin(), reusable_items_->end(), start_offset,
             [](const InlineItem& item, unsigned offset) {
               return item.EndOffset() <= offset;
             });
         item != reusable_items_->end(); ++item) {
      if (end_offset <= item->StartOffset())
        break;
      if (item->EndOffset() < start_offset)
        continue;
      // This is trying to reuse `ShapeResult` only by the string match. Check
      // if it's reusable for the given style. crbug.com/40879986
      const ShapeResult* const shape_result = item->TextShapeResult();
      if (!shape_result || item->Direction() != direction)
        continue;
      if (RuntimeEnabledFeatures::ReuseShapeResultsByFontsEnabled()) {
        if (item->Style()->GetFont() != font) {
          continue;
        }
      } else {
        if (shape_result->PrimaryFont() != font.PrimaryFont()) {
          continue;
        }
      }
      if (shape_result->IsAppliedSpacing())
        continue;
      shape_results.push_back(shape_result);
    }
    return shape_results;
  }

  const ShapeResult* Reshape(const InlineItem& start_item,
                             const Font& font,
                             unsigned start_offset,
                             unsigned end_offset) {
    DCHECK_LT(start_offset, end_offset);
    const TextDirection direction = start_item.Direction();
    if (data_.segments) {
      return data_.segments->ShapeText(&shaper_, &font, direction, start_offset,
                                       end_offset,
                                       data_.ToItemIndex(start_item), options_);
    }
    RunSegmenter::RunSegmenterRange range =
        start_item.CreateRunSegmenterRange();
    range.end = end_offset;
    return shaper_.Shape(&font, direction, start_offset, end_offset, range,
                         options_);
  }

  InlineItemsData& data_;
  const HeapVector<InlineItem>* const reusable_items_;
  HarfBuzzShaper shaper_;
  ShapeOptions options_;
  const bool allow_shape_cache_;
};

const Font& ScaledFont(const LayoutText& layout_text) {
  if (const auto* svg_text = DynamicTo<LayoutSVGInlineText>(layout_text)) {
    return svg_text->ScaledFont();
  }
  return layout_text.StyleRef().GetFont();
}

// The function is templated to indicate the purpose of collected inlines:
// - With EmptyOffsetMappingBuilder: updating layout;
// - With OffsetMappingBuilder: building offset mapping on clean layout.
//
// This allows code sharing between the two purposes with slightly different
// behaviors. For example, we clear a LayoutObject's need layout flags when
// updating layout, but don't do that when building offset mapping.
//
// There are also performance considerations, since template saves the overhead
// for condition checking and branching.
template <typename ItemsBuilder>
void CollectInlinesInternal(ItemsBuilder* builder,
                            const InlineNodeData* previous_data) {
  LayoutBlockFlow* const block = builder->GetLayoutBlockFlow();
  builder->EnterBlock(block->Style());
  LayoutObject* node = GetLayoutObjectForFirstChildNode(block);

  const LayoutObject* symbol =
      LayoutListItem::FindSymbolMarkerLayoutText(block);
  const LayoutObject* inline_list_item_marker = nullptr;
  while (node) {
    if (auto* counter = DynamicTo<LayoutCounter>(node)) {
      // TODO(crbug.com/561873): PrimaryFont should not be nullptr.
      if (counter->Style()->GetFont().PrimaryFont()) {
        // According to
        // https://w3c.github.io/csswg-drafts/css-counter-styles/#simple-symbolic,
        // disclosure-* should have special rendering paths.
        if (counter->IsDirectionalSymbolMarker()) {
          const String& text = counter->TransformedText();
          // We assume the text representation length for a predefined symbol
          // marker is always 1.
          if (text.length() <= 1) {
            builder->AppendText(counter, previous_data);
            builder->SetIsSymbolMarker();
          } else {
            // The text must be in the following form:
            // Symbol, separator, symbol, separator, symbol, ...
            builder->AppendText(text.Substring(0, 1), counter);
            builder->SetIsSymbolMarker();
            const AtomicString& separator = counter->Separator();
            for (wtf_size_t i = 1; i < text.length();) {
              if (separator.length() > 0) {
                DCHECK_EQ(separator, text.Substring(i, separator.length()));
                builder->AppendText(separator, counter);
                i += separator.length();
                DCHECK_LT(i, text.length());
              }
              builder->AppendText(text.Substring(i, 1), counter);
              builder->SetIsSymbolMarker();
              ++i;
            }
          }
        } else {
          builder->AppendText(counter, previous_data);
        }
      }
      builder->ClearNeedsLayout(counter);
    } else if (auto* layout_text = DynamicTo<LayoutText>(node)) {
      // TODO(crbug.com/561873): PrimaryFont should not be nullptr.
      if (ScaledFont(*layout_text).PrimaryFont()) {
        builder->AppendText(layout_text, previous_data);
        if (symbol == layout_text || inline_list_item_marker == layout_text) {
          builder->SetIsSymbolMarker();
        }
      }
      builder->ClearNeedsLayout(layout_text);
    } else if (node->IsFloating()) {
      builder->AppendFloating(node);
      if (builder->ShouldAbort())
        return;

      builder->ClearInlineFragment(node);
    } else if (node->IsOutOfFlowPositioned()) {
      builder->AppendOutOfFlowPositioned(node);
      if (builder->ShouldAbort())
        return;

      builder->ClearInlineFragment(node);
    } else if (node->IsAtomicInlineLevel()) {
      if (node->IsLayoutOutsideListMarker()) {
        // LayoutListItem produces the 'outside' list marker as an inline
        // block. This is an out-of-flow item whose position is computed
        // automatically.
        builder->AppendOpaque(InlineItem::kListMarker, node);
      } else if (node->IsInitialLetterBox()) [[unlikely]] {
        builder->AppendOpaque(InlineItem::kInitialLetterBox,
                              kObjectReplacementCharacter, node);
        builder->SetHasInititialLetterBox();
      } else {
        // For atomic inlines add a unicode "object replacement character" to
        // signal the presence of a non-text object to the unicode bidi
        // algorithm.
        builder->AppendAtomicInline(node);
      }
      builder->ClearInlineFragment(node);
    } else if (auto* layout_inline = DynamicTo<LayoutInline>(node)) {
      if (auto* inline_list_item = DynamicTo<LayoutInlineListItem>(node)) {
        inline_list_item->UpdateMarkerTextIfNeeded();
        inline_list_item_marker =
            LayoutListItem::FindSymbolMarkerLayoutText(inline_list_item);
      }
      builder->UpdateShouldCreateBoxFragment(layout_inline);

      builder->EnterInline(layout_inline);

      // Traverse to children if they exist.
      if (LayoutObject* child = layout_inline->FirstChild()) {
        node = child;
        continue;
      }

      // An empty inline node.
      builder->ExitInline(layout_inline);
      builder->ClearNeedsLayout(layout_inline);
    } else {
      DCHECK(!node->IsInline());
      builder->AppendBlockInInline(node);
      builder->ClearInlineFragment(node);
    }

    // Find the next sibling, or parent, until we reach |block|.
    while (true) {
      if (LayoutObject* next = node->NextSibling()) {
        node = next;
        break;
      }
      node = GetLayoutObjectForParentNode(node);
      if (node == block || !node) {
        // Set |node| to |nullptr| to break out of the outer loop.
        node = nullptr;
        break;
      }
      DCHECK(node->IsInline());
      builder->ExitInline(node);
      builder->ClearNeedsLayout(node);
    }
  }
  builder->ExitBlock();
}

// Returns whether this text should break shaping. Even within a box, text runs
// that have different shaping properties need to break shaping.
inline bool ShouldBreakShapingBeforeText(const InlineItem& item,
                                         const InlineItem& start_item,
                                         const ComputedStyle& start_style,
                                         const Font& start_font,
                                         TextDirection start_direction) {
  DCHECK_EQ(item.Type(), InlineItem::kText);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();
  if (&style != &start_style) {
    const Font& font = style.GetFont();
    if (&font != &start_font && font != start_font)
      return true;
  }

  // The resolved direction and run segment properties must match to shape
  // across for HarfBuzzShaper.
  return item.Direction() != start_direction ||
         !item.EqualsRunSegment(start_item);
}

// Returns whether the start of this box should break shaping.
inline bool ShouldBreakShapingBeforeBox(const InlineItem& item) {
  DCHECK_EQ(item.Type(), InlineItem::kOpenTag);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();

  // These properties values must break shaping.
  // https://drafts.csswg.org/css-text-3/#boundary-shaping
  if ((style.MayHavePadding() && !style.PaddingInlineStart().IsZero()) ||
      (style.MayHaveMargin() && !style.MarginInlineStart().IsZero()) ||
      style.BorderInlineStartWidth() ||
      style.VerticalAlign() != EVerticalAlign::kBaseline) {
    return true;
  }

  return false;
}

// Returns whether the end of this box should break shaping.
inline bool ShouldBreakShapingAfterBox(const InlineItem& item) {
  DCHECK_EQ(item.Type(), InlineItem::kCloseTag);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();

  // These properties values must break shaping.
  // https://drafts.csswg.org/css-text-3/#boundary-shaping
  if ((style.MayHavePadding() && !style.PaddingInlineEnd().IsZero()) ||
      (style.MayHaveMargin() && !style.MarginInlineEnd().IsZero()) ||
      style.BorderInlineEndWidth() ||
      style.VerticalAlign() != EVerticalAlign::kBaseline) {
    return true;
  }

  return false;
}

inline bool NeedsShaping(const InlineItem& item) {
  if (item.Type() != InlineItem::kText) {
    return false;
  }
  // Text item with length==0 exists to maintain LayoutObject states such as
  // ClearNeedsLayout, but not needed to shape.
  if (!item.Length()) {
    return false;
  }
  if (item.IsUnsafeToReuseShapeResult()) {
    return true;
  }
  const ShapeResult* shape_result = item.TextShapeResult();
  if (!shape_result)
    return true;
  // |StartOffset| is usually safe-to-break, but it is not when we shape across
  // elements and split the |ShapeResult|. Such |ShapeResult| is not safe to
  // reuse.
  DCHECK_EQ(item.StartOffset(), shape_result->StartIndex());
  if (!shape_result->IsStartSafeToBreak())
    return true;
  return false;
}

// Determine if reshape is needed for ::first-line style.
bool FirstLineNeedsReshape(const ComputedStyle& first_line_style,
                           const ComputedStyle& base_style) {
  const Font& base_font = base_style.GetFont();
  const Font& first_line_font = first_line_style.GetFont();
  return &base_font != &first_line_font && base_font != first_line_font;
}

// Make a string to the specified length, either by truncating if longer, or
// appending space characters if shorter.
void TruncateOrPadText(String* text, unsigned length) {
  if (text->length() > length) {
    *text = text->Substring(0, length);
  } else if (text->length() < length) {
    StringBuilder builder;
    builder.ReserveCapacity(length);
    builder.Append(*text);
    while (builder.length() < length)
      builder.Append(kSpaceCharacter);
    *text = builder.ToString();
  }
}

bool SetParagraphTo(const String& text,
                    const ComputedStyle& block_style,
                    BidiParagraph& bidi) {
  if (block_style.GetUnicodeBidi() == UnicodeBidi::kPlaintext) [[unlikely]] {
    return bidi.SetParagraph(text, std::nullopt);
  }
  return bidi.SetParagraph(text, block_style.Direction());
}

}  // namespace

InlineNode::InlineNode(LayoutBlockFlow* block)
    : LayoutInputNode(block, kInline) {
  DCHECK(block);
  DCHECK(block->IsLayoutNGObject());
  if (!block->GetInlineNodeData()) {
    block->ResetInlineNodeData();
  }
}

bool InlineNode::IsPrepareLayoutFinished() const {
  const InlineNodeData* data =
      To<LayoutBlockFlow>(box_.Get())->GetInlineNodeData();
  return data && !data->text_content.IsNull();
}

void InlineNode::PrepareLayoutIfNeeded() const {
  InlineNodeData* previous_data = nullptr;
  LayoutBlockFlow* block_flow = GetLayoutBlockFlow();
  if (IsPrepareLayoutFinished()) {
    if (!block_flow->NeedsCollectInlines())
      return;

    // Note: For "text-combine-upright:all", we use a font calculated from
    // text width, so we can't reuse previous data.
    if (!IsTextCombine()) [[likely]] {
      previous_data = block_flow->TakeInlineNodeData();
    }
    block_flow->ResetInlineNodeData();
  }

  PrepareLayout(previous_data);

  if (previous_data) {
    // previous_data is not used from now on but exists until GC happens, so it
    // is better to eagerly clear HeapVector to improve memory utilization.
    previous_data->items.clear();
  }
}

void InlineNode::PrepareLayout(InlineNodeData* previous_data) const {
  // Scan list of siblings collecting all in-flow non-atomic inlines. A single
  // InlineNode represent a collection of adjacent non-atomic inlines.
  InlineNodeData* data = MutableData();
  DCHECK(data);
  CollectInlines(data, previous_data);
  SegmentText(data, previous_data);
  ShapeTextIncludingFirstLine(
      data, previous_data ? &previous_data->text_content : nullptr, nullptr);

  AssociateItemsWithInlines(data);
  DCHECK_EQ(data, MutableData());

  LayoutBlockFlow* block_flow = GetLayoutBlockFlow();
  block_flow->ClearNeedsCollectInlines();

  if (IsTextCombine()) [[unlikely]] {
    // To use |LayoutTextCombine::UsersScaleX()| in |FragmentItemsBuilder|,
    // we adjust font here instead in |Layout()|,
    AdjustFontForTextCombineUprightAll();
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  // ComputeOffsetMappingIfNeeded() runs some integrity checks as part of
  // creating offset mapping. Run the check, and discard the result.
  DCHECK(!data->offset_mapping);
  ComputeOffsetMappingIfNeeded();
  DCHECK(data->offset_mapping);
  data->offset_mapping.Clear();
#endif
}

// Building |InlineNodeData| for |LayoutText::SetTextWithOffset()| with
// reusing data.
class InlineNodeDataEditor final {
  STACK_ALLOCATED();

 public:
  explicit InlineNodeDataEditor(const LayoutText& layout_text)
      : block_flow_(layout_text.FragmentItemsContainer()),
        layout_text_(layout_text) {
    DCHECK(layout_text_.HasValidInlineItems());
  }
  InlineNodeDataEditor(const InlineNodeDataEditor&) = delete;
  InlineNodeDataEditor& operator=(const InlineNodeDataEditor&) = delete;

  LayoutBlockFlow* GetLayoutBlockFlow() const { return block_flow_; }

  // Note: We can't use |Position| for |layout_text_.GetNode()| because |Text|
  // node is already changed.
  InlineNodeData* Prepare() {
    if (!block_flow_ || block_flow_->NeedsCollectInlines() ||
        block_flow_->NeedsLayout() ||
        block_flow_->GetDocument().NeedsLayoutTreeUpdate() ||
        !block_flow_->GetInlineNodeData() ||
        block_flow_->GetInlineNodeData()->text_content.IsNull() ||
        block_flow_->GetInlineNodeData()->items.empty()) {
      return nullptr;
    }

    // For "text-combine-upright:all", we choose font to fit layout result in
    // 1em, so font can be different than original font.
    if (IsA<LayoutTextCombine>(block_flow_)) [[unlikely]] {
      return nullptr;
    }

    // Because of current text content has secured text, e.g. whole text is
    // "***", all characters including collapsed white spaces are marker, and
    // new text is original text, we can't reuse shape result.
    if (layout_text_.StyleRef().TextSecurity() != ETextSecurity::kNone)
      return nullptr;

    // It is hard to figure differences of bidi control codes before/after
    // editing. See http://crbug.com/1039143
    if (layout_text_.HasBidiControlInlineItems())
      return nullptr;

    // Note: We should compute offset mapping before calling
    // |LayoutBlockFlow::TakeInlineNodeData()|
    const OffsetMapping* const offset_mapping =
        InlineNode::GetOffsetMapping(block_flow_);
    DCHECK(offset_mapping);
    if (data_) {
      // data_ is not used from now on but exists until GC happens, so it is
      // better to eagerly clear HeapVector to improve memory utilization.
      data_->items.clear();
    }
    data_ = block_flow_->TakeInlineNodeData();
    return data_;
  }

  void Run() {
    const InlineNodeData& new_data = *block_flow_->GetInlineNodeData();
    const String& old_text = data_->text_content;
    const String& new_text = new_data.text_content;
    const auto [start_offset, end_match_length] =
        MatchedLengths(old_text, new_text);
    const unsigned old_length = old_text.length();
    const unsigned new_length = new_text.length();
    DCHECK_LE(start_offset, old_length - end_match_length);
    DCHECK_LE(start_offset, new_length - end_match_length);
    const unsigned end_offset = old_length - end_match_length;
    DCHECK_LE(start_offset, end_offset);
    HeapVector<InlineItem> items;
    ClearCollectionScope clear_scope(&items);

    // +3 for before and after replaced text.
    items.ReserveInitialCapacity(data_->items.size() + 3);

    // Copy items before replaced range
    auto end = data_->items.end();
    auto it = data_->items.begin();
    for (; it != end && it->end_offset_ < start_offset; ++it) {
      CHECK(it != data_->items.end(), base::NotFatalUntil::M130);
      items.push_back(*it);
    }

    while (it != end) {
      // Copy part of item before replaced range.
      if (it->start_offset_ < start_offset) {
        const InlineItem& new_item = CopyItemBefore(*it, start_offset);
        items.push_back(new_item);
        if (new_item.EndOffset() < start_offset) {
          items.push_back(
              InlineItem(*it, new_item.EndOffset(), start_offset, nullptr));
        }
      }

      // Skip items in replaced range.
      while (it != end && it->end_offset_ < end_offset)
        ++it;

      if (it == end)
        break;

      // Inserted text
      const int diff = new_length - old_length;
      const unsigned inserted_end = AdjustOffset(end_offset, diff);
      if (start_offset < inserted_end)
        items.push_back(InlineItem(*it, start_offset, inserted_end, nullptr));

      // Copy part of item after replaced range.
      if (end_offset < it->end_offset_) {
        const InlineItem& new_item = CopyItemAfter(*it, end_offset);
        if (end_offset < new_item.StartOffset()) {
          items.push_back(
              InlineItem(*it, end_offset, new_item.StartOffset(), nullptr));
          ShiftItem(&items.back(), diff);
        }
        items.push_back(new_item);
        ShiftItem(&items.back(), diff);
      }

      // Copy items after replaced range
      ++it;
      while (it != end) {
        DCHECK_LE(end_offset, it->start_offset_);
        items.push_back(*it);
        ShiftItem(&items.back(), diff);
        ++it;
      }
      break;
    }

    if (items.empty()) {
      items.push_back(InlineItem(data_->items.front(), 0,
                                 new_data.text_content.length(), nullptr));
    } else if (items.back().end_offset_ < new_data.text_content.length()) {
      items.push_back(InlineItem(data_->items.back(), items.back().end_offset_,
                                 new_data.text_content.length(), nullptr));
    }

    VerifyItems(items);
    // eagerly clear HeapVector to improve memory utilization.
    data_->items.clear();
    data_->items = std::move(items);
    data_->text_content = new_data.text_content;
  }

 private:
  // Find the number of characters that match in the two strings, from the start
  // and from the end.
  std::pair<unsigned, unsigned> MatchedLengths(const String& old_text,
                                               const String& new_text) const {
    // Find how many characters match from the start.
    const unsigned start_match_length = Mismatch(old_text, new_text);

    // Find from the end, excluding the `start_match_length` characters.
    const unsigned old_length = old_text.length();
    const unsigned new_length = new_text.length();
    const unsigned max_end_length = std::min(old_length - start_match_length,
                                             new_length - start_match_length);
    const unsigned end_match_length =
        MismatchFromEnd(StringView(old_text, old_length - max_end_length),
                        StringView(new_text, new_length - max_end_length));
    DCHECK_LE(start_match_length, old_length - end_match_length);
    DCHECK_LE(start_match_length, new_length - end_match_length);
    return {start_match_length, end_match_length};
  }

  static unsigned AdjustOffset(unsigned offset, int delta) {
    if (delta > 0)
      return offset + delta;
    return offset - (-delta);
  }

  // Returns copy of |item| after |start_offset| (inclusive).
  InlineItem CopyItemAfter(const InlineItem& item,
                           unsigned start_offset) const {
    DCHECK_LE(item.start_offset_, start_offset);
    DCHECK_LT(start_offset, item.end_offset_);
    const unsigned safe_start_offset = GetFirstSafeToReuse(item, start_offset);
    const unsigned end_offset = item.end_offset_;
    if (end_offset == safe_start_offset)
      return InlineItem(item, start_offset, end_offset, nullptr);
    // To handle kerning, e.g
```