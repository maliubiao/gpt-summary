Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. The code is part of `inline_items_builder.cc`. I need to identify the main purpose of this class and its methods. Specifically, I need to look for connections to HTML, CSS, and JavaScript concepts, and provide illustrative examples. If the code contains conditional logic, I should create hypothetical inputs and outputs to demonstrate its behavior. I also need to watch for common user/programming errors that this code might be involved in preventing or handling. Finally, since this is the first of three parts, the summary should focus on the core functionality established in this initial segment.

Based on the code, the `InlineItemsBuilderTemplate` class appears to be responsible for constructing a sequence of `InlineItem` objects. These items represent segments of inline content within a block of text. The code manages whitespace collapsing, line breaking, and interaction with BiDi (bidirectional text) contexts.

Here's a breakdown of the key elements and their functionalities:

1. **`InlineItemsBuilderTemplate` class:** The central component responsible for building the inline items list.
2. **Constructor:** Initializes the builder with the layout block, the list to store inline items, the previous text content (for potential optimization), and SVG text chunk offsets.
3. **`NeedsBoxInfo()`:** Determines if the builder needs to track box-related information, which is not necessary when only building offset mappings.
4. **Destructor:**  Performs assertions to ensure the builder's state is consistent.
5. **`ToString()`:** Returns the accumulated text content.
6. **Whitespace Handling:**  Functions like `ShouldRemoveNewline`, `MoveToEndOfCollapsibleSpaces`, `AppendCollapseWhitespace`, `AppendPreserveWhitespace`, and `AppendPreserveNewline` manage the complex rules of whitespace collapsing and preservation as defined by CSS.
7. **Item Creation:** Functions like `AppendItem`, `AppendTextItem`, `AppendEmptyTextItem`, and `AppendBreakOpportunity` create different types of inline items representing text, control characters, and potential line breaks.
8. **Text Reusing Optimization:** The `AppendTextReusing` function attempts to reuse existing `InlineItem` objects from a previous layout if the underlying text content hasn't significantly changed, improving performance.
9. **SVG Text Chunking:** The `AppendTextChunks` function seems to handle specific segmentation requirements for SVG text elements.
10. **BiDi Context Management:** The `bidi_context_` member suggests involvement in handling bidirectional text.
11. **Transformed String Handling:** The `TransformedString` class and related functions manage text transformations and their corresponding offset mappings.
12. **East Asian Width Handling:**  The code includes logic (though currently disabled by a preprocessor flag) to handle specific line-breaking rules for East Asian text.

Now, I'll formulate the summary, including connections to web technologies, examples, and potential errors.
这是 `blink/renderer/core/layout/inline/inline_items_builder.cc` 文件的第一部分，其主要功能是构建用于表示内联布局的 `InlineItem` 对象的列表。这个构建过程是布局（layout）阶段的关键部分，它将文档的结构和样式信息转换为可以在屏幕上渲染的内联元素序列。

**核心功能归纳:**

* **构建 `InlineItem` 列表:**  `InlineItemsBuilderTemplate` 类的核心职责是生成一个 `InlineItem` 对象的 `HeapVector`。这些 `InlineItem` 代表了内联内容的基本单元，例如文本片段、空格、换行符、以及其他内联元素。
* **处理文本内容:** 它负责将 `LayoutText` 对象中的文本内容添加到内部缓冲区 (`text_`) 中，并创建相应的 `InlineItem`。这个过程包括处理文本的各种转换（例如，`TransformedString`）。
* **处理空白符:**  代码实现了 CSS 中关于空白符处理的复杂规则，包括合并（collapsing）、保留（preserving）和根据换行符进行分割。
* **支持文本重用优化:** 为了提高性能，代码尝试重用之前布局计算中生成的 `InlineItem` 对象，如果文本内容和样式没有发生显著变化。
* **处理 SVG 文本:**  代码包含处理 SVG 文本块的逻辑，允许对 SVG 文本进行分块处理。
* **维护文本偏移映射:** 通过 `OffsetMappingBuilder`，它维护了原始文本和转换后文本之间的偏移映射，这对于后续处理（如选择和编辑）至关重要。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:** `InlineItemsBuilder` 处理的输入是基于 HTML 结构生成的 `LayoutObject` 树。例如，考虑以下 HTML 片段：

    ```html
    <p>这是一段 <span>内联</span> 文本。</p>
    ```

    `InlineItemsBuilder` 会遍历 `<p>` 元素下的子元素（文本节点和 `<span>` 元素），并为每个部分创建相应的 `InlineItem`。

2. **CSS:** CSS 样式规则极大地影响 `InlineItemsBuilder` 的行为，尤其是以下属性：

    *   **`white-space`:**  决定如何处理元素内的空白符。
        *   `white-space: normal;` (默认):  合并连续的空白符，忽略换行符。`InlineItemsBuilder` 会将多个空格合并成一个，并可能移除换行符。
        *   `white-space: pre;`：保留所有空白符和换行符。`InlineItemsBuilder` 会为每个空格和换行符创建一个 `InlineItem`。
        *   `white-space: nowrap;`：合并空白符，但不允许文本换行。`InlineItemsBuilder` 会合并空格，但会影响后续的换行逻辑。
        *   `white-space: pre-wrap;`：保留换行符，并允许在必要时进行换行。`InlineItemsBuilder` 会保留换行符，并在空格处提供潜在的换行机会。
        *   `white-space: pre-line;`：合并连续的空白符，但保留换行符。`InlineItemsBuilder` 会合并空格，并为换行符创建 `InlineItem`。
    *   **`word-break` 和 `overflow-wrap`:** 影响单词如何在行末断开。`InlineItemsBuilder` 中会根据这些属性插入或不插入潜在的换行机会 (`BreakOpportunity` 类型的 `InlineItem`)。
    *   **`text-combine-upright`:**  影响垂直排版中字符的组合方式。代码中特别处理了 `is_text_combine_` 的情况。
    *   **字体相关属性 (如 `font-family`, `font-size`):**  影响文本的渲染尺寸，虽然这段代码本身不直接处理渲染，但字体信息会影响布局计算，并通过 `ComputedStyle` 传递给 `InlineItemsBuilder`。

3. **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 更改内联元素的内容或影响空白符处理的 CSS 属性时，Blink 引擎会重新进行布局计算，`InlineItemsBuilder` 会根据新的状态重新构建 `InlineItem` 列表。例如，如果 JavaScript 修改了元素的 `textContent`，或者添加/删除了 CSS 类从而改变了 `white-space` 属性，都会触发 `InlineItemsBuilder` 的重新执行。

**逻辑推理与假设输入/输出:**

假设输入一个包含多个空格和换行符的 `LayoutText` 对象，其对应的 CSS `white-space` 属性为 `normal`：

**假设输入:**

*   `LayoutText` 的文本内容为: `"  Hello\n  World!  "`
*   `ComputedStyle` 的 `white-space` 为 `normal`。

**逻辑推理:**

*   `InlineItemsBuilder` 会遍历文本内容。
*   根据 `white-space: normal;` 的规则，连续的空格会被合并成一个空格。
*   换行符 `\n` 会被当作空格处理。
*   首尾的空格也会被移除（虽然这段代码片段中没有直接展示首尾空格移除的逻辑，但在完整的布局流程中会发生）。

**假设输出 (部分 `InlineItem` 列表):**

*   一个 `InlineItem`，类型为 `kText`，内容为 `" Hello "` (原始的
Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_items_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/inline_items_builder.h"

#include <type_traits>

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_span.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping_builder.h"
#include "third_party/blink/renderer/core/layout/inline/transformed_string.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"

namespace blink {
class HTMLAreaElement;

template <typename MappingBuilder>
InlineItemsBuilderTemplate<MappingBuilder>::InlineItemsBuilderTemplate(
    LayoutBlockFlow* block_flow,
    HeapVector<InlineItem>* items,
    const String& previous_text_content,
    const SvgTextChunkOffsets* chunk_offsets)
    : block_flow_(block_flow),
      items_(items),
      text_chunk_offsets_(chunk_offsets),
      is_text_combine_(block_flow_->IsLayoutTextCombine()) {
  const LayoutObject* child = block_flow->FirstChild();
  if (!previous_text_content.IsNull() && child && child->NextSibling()) {
    // 10 avoids reallocations in many cases of Speedometer3.
    constexpr wtf_size_t kAdditionalSize = 10;
    wtf_size_t capacity = previous_text_content.length() + kAdditionalSize;
    if (previous_text_content.Is8Bit()) {
      text_.ReserveCapacity(capacity);
    } else {
      text_.Reserve16BitCapacity(capacity);
    }
  }
}

// Returns true if items builder is used for other than offset mapping.
template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::NeedsBoxInfo() {
  return !std::is_same<OffsetMappingBuilder, MappingBuilder>::value;
}

template <typename MappingBuilder>
InlineItemsBuilderTemplate<MappingBuilder>::~InlineItemsBuilderTemplate() {
  DCHECK_EQ(0u, bidi_context_.size());
  DCHECK_EQ(text_.length(), items_->empty() ? 0 : items_->back().EndOffset());
}

template <typename MappingBuilder>
String InlineItemsBuilderTemplate<MappingBuilder>::ToString() {
  return text_.ToString();
}

namespace {

// TODO(curbug.com/324111880): We can't support forced-breaks in ruby-base boxes
// until ruby-columns become actually line-breakable. So we replace
// forced-breaks in ruby-base boxes with spaces for now. This flag should be
// removed before shipping RubyLineBreakable.
constexpr bool kDisableForcedBreakInRubyColumn = true;

// The spec turned into a discussion that may change. Put this logic on hold
// until CSSWG resolves the issue.
// https://github.com/w3c/csswg-drafts/issues/337
#define SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH 0

#if SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH
// Determine "Ambiguous" East Asian Width is Wide or Narrow.
// Unicode East Asian Width
// http://unicode.org/reports/tr11/
bool IsAmbiguosEastAsianWidthWide(const ComputedStyle* style) {
  UScriptCode script = style->GetFontDescription().GetScript();
  return script == USCRIPT_KATAKANA_OR_HIRAGANA ||
         script == USCRIPT_SIMPLIFIED_HAN || script == USCRIPT_TRADITIONAL_HAN;
}

// Determine if a character has "Wide" East Asian Width.
bool IsEastAsianWidthWide(UChar32 c, const ComputedStyle* style) {
  UEastAsianWidth eaw = static_cast<UEastAsianWidth>(
      u_getIntPropertyValue(c, UCHAR_EAST_ASIAN_WIDTH));
  return eaw == U_EA_WIDE || eaw == U_EA_FULLWIDTH || eaw == U_EA_HALFWIDTH ||
         (eaw == U_EA_AMBIGUOUS && style &&
          IsAmbiguosEastAsianWidthWide(style));
}
#endif

// Determine whether a newline should be removed or not.
// CSS Text, Segment Break Transformation Rules
// https://drafts.csswg.org/css-text-3/#line-break-transform
bool ShouldRemoveNewlineSlow(const StringBuilder& before,
                             unsigned space_index,
                             const ComputedStyle* before_style,
                             const StringView& after,
                             const ComputedStyle* after_style) {
  // Remove if either before/after the newline is zeroWidthSpaceCharacter.
  UChar32 last = 0;
  DCHECK(space_index == before.length() ||
         (space_index < before.length() && before[space_index] == ' '));
  if (space_index) {
    last = before[space_index - 1];
    if (last == kZeroWidthSpaceCharacter)
      return true;
  }
  UChar32 next = 0;
  if (!after.empty()) {
    next = after[0];
    if (next == kZeroWidthSpaceCharacter)
      return true;
  }

#if SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH
  // Logic below this point requires both before and after be 16 bits.
  if (before.Is8Bit() || after.Is8Bit())
    return false;

  // Remove if East Asian Widths of both before/after the newline are Wide, and
  // neither side is Hangul.
  // TODO(layout-dev): Don't remove if any side is Emoji.
  if (U16_IS_TRAIL(last) && space_index >= 2) {
    UChar last_last = before[space_index - 2];
    if (U16_IS_LEAD(last_last))
      last = U16_GET_SUPPLEMENTARY(last_last, last);
  }
  if (!Character::IsHangul(last) && IsEastAsianWidthWide(last, before_style)) {
    if (U16_IS_LEAD(next) && after.length() > 1) {
      UChar next_next = after[1];
      if (U16_IS_TRAIL(next_next))
        next = U16_GET_SUPPLEMENTARY(next, next_next);
    }
    if (!Character::IsHangul(next) && IsEastAsianWidthWide(next, after_style))
      return true;
  }
#endif

  return false;
}

bool ShouldRemoveNewline(const StringBuilder& before,
                         unsigned space_index,
                         const ComputedStyle* before_style,
                         const StringView& after,
                         const ComputedStyle* after_style) {
  // All characters before/after removable newline are 16 bits.
  return (!before.Is8Bit() || !after.Is8Bit()) &&
         ShouldRemoveNewlineSlow(before, space_index, before_style, after,
                                 after_style);
}

inline InlineItem& AppendItem(HeapVector<InlineItem>* items,
                              InlineItem::InlineItemType type,
                              unsigned start,
                              unsigned end,
                              LayoutObject* layout_object) {
  return items->emplace_back(type, start, end, layout_object);
}

inline bool ShouldIgnore(UChar c) {
  // Ignore carriage return and form feed.
  // https://drafts.csswg.org/css-text-3/#white-space-processing
  // https://github.com/w3c/csswg-drafts/issues/855
  //
  // Unicode Default_Ignorable is not included because we need some of them
  // in the line breaker (e.g., SOFT HYPHEN.) HarfBuzz ignores them while
  // shaping.
  return c == kCarriageReturnCharacter || c == kFormFeedCharacter;
}

// Characters needing a separate control item than other text items.
// It makes the line breaker easier to handle.
inline bool IsControlItemCharacter(UChar c) {
  return c == kNewlineCharacter || c == kTabulationCharacter ||
         // Make ZWNJ a control character so that it can prevent kerning.
         c == kZeroWidthNonJoinerCharacter ||
         // Include ignorable character here to avoids shaping/rendering
         // these glyphs, and to help the line breaker to ignore them.
         ShouldIgnore(c);
}

// Find the end of the collapsible spaces.
// Returns whether this space run contains a newline or not, because it changes
// the collapsing behavior.
inline bool MoveToEndOfCollapsibleSpaces(const StringView& string,
                                         unsigned* offset,
                                         UChar* c) {
  DCHECK_EQ(*c, string[*offset]);
  DCHECK(Character::IsCollapsibleSpace(*c));
  bool space_run_has_newline = *c == kNewlineCharacter;
  for ((*offset)++; *offset < string.length(); (*offset)++) {
    *c = string[*offset];
    space_run_has_newline |= *c == kNewlineCharacter;
    if (!Character::IsCollapsibleSpace(*c))
      break;
  }
  return space_run_has_newline;
}

// Find the last item to compute collapsing with. Opaque items such as
// open/close or bidi controls are ignored.
// Returns nullptr if there were no previous items.
InlineItem* LastItemToCollapseWith(HeapVector<InlineItem>* items) {
  for (auto& item : base::Reversed(*items)) {
    if (item.EndCollapseType() != InlineItem::kOpaqueToCollapsing) {
      return &item;
    }
  }
  return nullptr;
}

inline bool IsNonOrc16BitCharacter(UChar ch) {
  return ch >= 0x100 && ch != kObjectReplacementCharacter;
}

}  // anonymous namespace

template <typename MappingBuilder>
InlineItemsBuilderTemplate<MappingBuilder>::BoxInfo::BoxInfo(
    unsigned item_index,
    const InlineItem& item)
    : style(*item.Style()),
      item_index(item_index),
      should_create_box_fragment(item.ShouldCreateBoxFragment()),
      text_metrics(style->GetFontHeight()) {
  DCHECK(style);
}

// True if this inline box should create a box fragment when it has |child|.
template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::BoxInfo::
    ShouldCreateBoxFragmentForChild(const BoxInfo& child) const {
  // When a child inline box has margins, the parent has different width/height
  // from the union of children.
  const ComputedStyle& child_style = *child.style;
  if (child_style.MayHaveMargin())
    return true;

  // Because a culled inline box computes its position from its first child,
  // when the first child is shifted vertically, its position will shift too.
  // Note, this is needed only when it's the first child, but checking it need
  // to take collapsed spaces into account. Uncull even when it's not the first
  // child.
  if (child_style.VerticalAlign() != EVerticalAlign::kBaseline)
    return true;

  // Returns true when parent and child boxes have different font metrics, since
  // they may have different heights and/or locations in block direction.
  if (text_metrics != child.text_metrics)
    return true;

  return false;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::BoxInfo::
    SetShouldCreateBoxFragment(HeapVector<InlineItem>* items) {
  DCHECK(!should_create_box_fragment);
  should_create_box_fragment = true;
  (*items)[item_index].SetShouldCreateBoxFragment();
}

// Append a string as a text item.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendTextItem(
    const TransformedString& transformed,
    LayoutText* layout_object) {
  DCHECK(layout_object);
  AppendTextItem(InlineItem::kText, transformed, layout_object);
}

template <typename MappingBuilder>
InlineItem& InlineItemsBuilderTemplate<MappingBuilder>::AppendTextItem(
    InlineItem::InlineItemType type,
    const TransformedString& transformed,
    LayoutText* layout_object) {
  DCHECK(layout_object);
  unsigned start_offset = text_.length();
  AppendTransformedString(transformed, *layout_object);
  InlineItem& item =
      AppendItem(items_, type, start_offset, text_.length(), layout_object);
  DCHECK(!item.IsEmptyItem());
  is_block_level_ = false;
  return item;
}

// Empty text items are not needed for the layout purposes, but all LayoutObject
// must be captured in InlineItemsData to maintain states of LayoutObject in
// this inline formatting context.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendEmptyTextItem(
    LayoutText* layout_object) {
  DCHECK(layout_object);
  unsigned offset = text_.length();
  InlineItem& item =
      AppendItem(items_, InlineItem::kText, offset, offset, layout_object);
  item.SetEndCollapseType(InlineItem::kOpaqueToCollapsing);
  item.SetIsEmptyItem(true);
  item.SetIsBlockLevel(true);
}

// Same as AppendBreakOpportunity, but mark the item as IsGenerated().
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::
    AppendGeneratedBreakOpportunity(LayoutObject* layout_object) {
  if (block_flow_->IsSVGText()) {
    return;
  }
  DCHECK(layout_object);
  typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
  InlineItem& item = AppendBreakOpportunity(layout_object);
  item.SetIsGeneratedForLineBreak();
  item.SetEndCollapseType(InlineItem::kOpaqueToCollapsing);
}

template <typename MappingBuilder>
inline void InlineItemsBuilderTemplate<MappingBuilder>::DidAppendForcedBreak() {
  // Bisecting available widths can't handle multiple logical paragraphs, so
  // forced break should disable it. See `ParagraphLineBreaker`.
  is_bisect_line_break_disabled_ = true;
}

template <typename MappingBuilder>
inline void InlineItemsBuilderTemplate<MappingBuilder>::DidAppendTextReusing(
    const InlineItem& item) {
  is_block_level_ &= item.IsBlockLevel();
  if (item.IsForcedLineBreak()) {
    DidAppendForcedBreak();
  }
}

template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::AppendTextReusing(
    const InlineNodeData& original_data,
    LayoutText* layout_text) {
  DCHECK(layout_text);
  const auto& items = layout_text->InlineItems();
  const InlineItem& old_item0 = items.front();
  if (!old_item0.Length())
    return false;

  const String& original_string = original_data.text_content;

  // Don't reuse existing items if they might be affected by whitespace
  // collapsing.
  // TODO(layout-dev): This could likely be optimized further.
  // TODO(layout-dev): Handle cases where the old items are not consecutive.
  const ComputedStyle& new_style = layout_text->StyleRef();
  const bool collapse_spaces = new_style.ShouldCollapseWhiteSpaces();
  bool preserve_newlines = new_style.ShouldPreserveBreaks();
  if (preserve_newlines && is_text_combine_) [[unlikely]] {
    preserve_newlines = false;
  }
  if (InlineItem* last_item = LastItemToCollapseWith(items_)) {
    if (collapse_spaces) {
      switch (last_item->EndCollapseType()) {
        case InlineItem::kCollapsible:
          switch (original_string[old_item0.StartOffset()]) {
            case kSpaceCharacter:
              // If the original string starts with a collapsible space, it may
              // be collapsed.
              return false;
            case kNewlineCharacter:
              // Collapsible spaces immediately before a preserved newline
              // should be removed to be consistent with
              // AppendForcedBreakCollapseWhitespace.
              if (preserve_newlines)
                return false;
          }
          // If the last item ended with a collapsible space run with segment
          // breaks, we need to run the full algorithm to apply segment break
          // rules. This may result in removal of the space in the last item.
          if (last_item->IsEndCollapsibleNewline()) {
            const StringView old_item0_view(
                original_string, old_item0.StartOffset(), old_item0.Length());
            if (ShouldRemoveNewline(text_, last_item->EndOffset() - 1,
                                    last_item->Style(), old_item0_view,
                                    &new_style)) {
              return false;
            }
          }
          break;
        case InlineItem::kNotCollapsible: {
          const String& source_text = layout_text->TransformedText();
          if (source_text.length() &&
              Character::IsCollapsibleSpace(source_text[0])) {
            // If the start of the original string was collapsed, it may be
            // restored.
            if (original_string[old_item0.StartOffset()] != kSpaceCharacter)
              return false;
            // If the start of the original string was not collapsed, and the
            // collapsible space run contains newline, the newline may be
            // removed.
            unsigned offset = 0;
            UChar c = source_text[0];
            bool contains_newline =
                MoveToEndOfCollapsibleSpaces(source_text, &offset, &c);
            if (contains_newline &&
                ShouldRemoveNewline(text_, text_.length(), last_item->Style(),
                                    StringView(source_text, offset),
                                    &new_style)) {
              return false;
            }
          }
          break;
        }
        case InlineItem::kCollapsed:
          RestoreTrailingCollapsibleSpace(last_item);
          return false;
        case InlineItem::kOpaqueToCollapsing:
          NOTREACHED();
      }
    } else if (last_item->EndCollapseType() == InlineItem::kCollapsed) {
      RestoreTrailingCollapsibleSpace(last_item);
      return false;
    }

    // On nowrap -> wrap boundary, a break opporunity may be inserted.
    DCHECK(last_item->Style());
    if (!last_item->Style()->ShouldWrapLine() && new_style.ShouldWrapLine()) {
      return false;
    }

  } else if (collapse_spaces) {
    // If the original string starts with a collapsible space, it may be
    // collapsed because it is now a leading collapsible space.
    if (original_string[old_item0.StartOffset()] == kSpaceCharacter)
      return false;
  }

  if (preserve_newlines) {
    // We exit and then re-enter all bidi contexts around a forced break. So, We
    // must go through the full pipeline to ensure that we exit and enter the
    // correct bidi contexts the re-layout.
    if (bidi_context_.size() || layout_text->HasBidiControlInlineItems()) {
      if (layout_text->TransformedText().Contains(kNewlineCharacter)) {
        return false;
      }
    }
  }

  if (old_item0.StartOffset() > 0 &&
      ShouldInsertBreakOpportunityAfterLeadingPreservedSpaces(
          layout_text->TransformedText(), new_style)) [[unlikely]] {
    // e.g. <p>abc xyz</p> => <p> xyz</p> where "abc" and " xyz" are different
    // Text node. |text_| is " \u200Bxyz".
    return false;
  }

  for (const InlineItem& item : items) {
    // Collapsed space item at the start will not be restored, and that not
    // needed to add.
    if (!text_.length() && !item.Length() && collapse_spaces)
      continue;

    // We are reusing items that included 'generated line breaks', inserted to
    // deal with leading preserved space sequences. If we are performing a
    // relayout after removing a <br> (eg. <div>abc<br><span> dfg</span></div>)
    // it may imply that the preserved spaces are not a leading sequence
    // anymore.
    if (item.IsGeneratedForLineBreak()) {
      // We wont restore 'generated line breaks' at the start
      // TODO(jfernandez): How it's possible that we have a generated break at
      // position 0 ?
      if (!text_.length())
        continue;
      int index = text_.length() - 1;
      while (index >= 0 && text_[index] == kSpaceCharacter)
        --index;
      if (index >= 0 && text_[index] != kNewlineCharacter)
        continue;
    }

    unsigned start = text_.length();
    has_non_orc_16bit_ =
        has_non_orc_16bit_ || original_data.HasNonOrc16BitCharacters();
    text_.Append(original_string, item.StartOffset(), item.Length());

    // If the item's position within the container remains unchanged the item
    // itself may be reused.
    if (item.StartOffset() == start) {
      items_->push_back(item);
      DidAppendTextReusing(item);
      continue;
    }

    // If the position has shifted the item and the shape result needs to be
    // adjusted to reflect the new start and end offsets.
    unsigned end = start + item.Length();
    const ShapeResult* adjusted_shape_result = nullptr;
    if (item.TextShapeResult()) {
      DCHECK_EQ(item.Type(), InlineItem::kText);
      adjusted_shape_result = item.TextShapeResult()->CopyAdjustedOffset(start);
      DCHECK(adjusted_shape_result);
    } else {
      // The following should be true, but some unit tests fail.
      // DCHECK_EQ(item->Type(), InlineItem::kControl);
    }

    InlineItem& adjusted_item =
        items_->emplace_back(item, start, end, adjusted_shape_result);
#if DCHECK_IS_ON()
    DCHECK_EQ(start, adjusted_item.StartOffset());
    DCHECK_EQ(end, adjusted_item.EndOffset());
    if (adjusted_item.TextShapeResult()) {
      DCHECK_EQ(start, adjusted_item.TextShapeResult()->StartIndex());
      DCHECK_EQ(end, adjusted_item.TextShapeResult()->EndIndex());
    }
    DCHECK_EQ(item.IsEmptyItem(), adjusted_item.IsEmptyItem());
#endif
    DidAppendTextReusing(adjusted_item);
  }
  return true;
}

template <>
bool InlineItemsBuilderTemplate<OffsetMappingBuilder>::AppendTextReusing(
    const InlineNodeData&,
    LayoutText*) {
  NOTREACHED();
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendText(
    LayoutText* layout_text,
    const InlineNodeData* previous_data) {
  // If the LayoutText element hasn't changed, reuse the existing items.
  if (previous_data && layout_text->HasValidInlineItems()) {
    if (AppendTextReusing(*previous_data, layout_text)) {
      return;
    }
  }

  // If not create a new item as needed.
  if (layout_text->IsWordBreak()) [[unlikely]] {
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_,
                                                   layout_text);
    if (is_text_combine_) [[unlikely]] {
      // We don't break text runs in text-combine-upright:all.
      // Note: Even if we have overflow-wrap:normal and word-break:keep-all,
      // <wbr> causes line break.
      Append(InlineItem::kText, kZeroWidthSpaceCharacter, layout_text);
      return;
    }
    AppendBreakOpportunity(layout_text);
    return;
  }

  if (!layout_text->HasVariableLengthTransform()) {
    AppendText(TransformedString(layout_text->TransformedText()), *layout_text);
    return;
  }
  // Do not use LayoutText::OriginalText() here.  This code is used when
  // OriginalText() was updated but TransformedText() is not updated yet, and we
  // need to use TransformedText() in that case.  It is required to make
  // InlineNode::SetTextWithOffset() workable.
  auto [original_length, offset_map] =
      layout_text->GetVariableLengthTransformResult();
  String transformed = layout_text->TransformedText();
  const Vector<unsigned> length_map = TransformedString::CreateLengthMap(
      original_length, transformed.length(), offset_map);
  CHECK(transformed.length() == length_map.size() || length_map.size() == 0);
  AppendText(
      TransformedString(transformed, {length_map.data(), length_map.size()}),
      *layout_text);
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendText(
    const String& string,
    LayoutText* layout_object) {
  AppendText(TransformedString(string), *layout_object);
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendText(
    const TransformedString& transformed,
    LayoutText& layout_object) {
  StringView string = transformed.View();
  if (string.empty()) {
    AppendEmptyTextItem(&layout_object);
    return;
  }

  const wtf_size_t estimated_length = text_.length() + string.length();
  if (estimated_length > text_.Capacity()) {
    // The reallocations may occur very frequently for large text such as log
    // files. We use a more aggressive expansion strategy, the same as
    // |Vector::ExpandCapacity| does for |Vector|s with inline storage.
    // |ReserveCapacity| reserves only the requested size.
    const wtf_size_t new_capacity =
        std::max(estimated_length, text_.Capacity() * 2);
    if (string.Is8Bit())
      text_.ReserveCapacity(new_capacity);
    else
      text_.Reserve16BitCapacity(new_capacity);
  }

  typename MappingBuilder::SourceNodeScope scope(&mapping_builder_,
                                                 &layout_object);

  const ComputedStyle& style = layout_object.StyleRef();
  bool should_not_preserve_newline;
  if (layout_object.IsSVGInlineText() || is_text_combine_ ||
      ruby_text_nesting_level_ > 0) [[unlikely]] {
    should_not_preserve_newline = true;
  } else {
    should_not_preserve_newline = false;
  }

  RestoreTrailingCollapsibleSpaceIfRemoved();

  if (text_chunk_offsets_ && AppendTextChunks(transformed, layout_object)) {
    return;
  }
  if (style.ShouldPreserveWhiteSpaces()) {
    AppendPreserveWhitespace(transformed, &style, &layout_object);
  } else if (style.ShouldPreserveBreaks() && !should_not_preserve_newline) {
    AppendPreserveNewline(transformed, &style, &layout_object);
  } else {
    AppendCollapseWhitespace(transformed, &style, &layout_object);
  }
}

template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::AppendTextChunks(
    const TransformedString& transformed,
    LayoutText& layout_text) {
  auto iter = text_chunk_offsets_->find(&layout_text);
  if (iter == text_chunk_offsets_->end())
    return false;
  const ComputedStyle& style = layout_text.StyleRef();
  const bool should_collapse_space = style.ShouldCollapseWhiteSpaces();
  unsigned length = transformed.View().length();
  unsigned start = 0;
  for (unsigned offset : iter->value) {
    DCHECK_LE(offset, length);
    if (start < offset) {
      if (!should_collapse_space) {
        AppendPreserveWhitespace(transformed.Substring(start, offset - start),
                                 &style, &layout_text);
      } else {
        AppendCollapseWhitespace(transformed.Substring(start, offset - start),
                                 &style, &layout_text);
      }
    }
    ExitAndEnterSvgTextChunk(layout_text);
    start = offset;
  }
  if (start >= length) {
    return true;
  }
  if (!should_collapse_space) {
    AppendPreserveWhitespace(transformed.Substring(start), &style,
                             &layout_text);
  } else {
    AppendCollapseWhitespace(transformed.Substring(start), &style,
                             &layout_text);
  }
  return true;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendTransformedString(
    const TransformedString& transformed,
    const LayoutText& layout_text) {
  has_non_orc_16bit_ = has_non_orc_16bit_ || !transformed.View().Is8Bit();
  text_.Append(transformed.View());
  if (!transformed.HasLengthMap()) {
    mapping_builder_.AppendIdentityMapping(transformed.View().length());
    return;
  }

  // 1 followed by 0+     => expanded
  // 2 or larger          => shrink
  // 1+ not followed by 0 => identity
  unsigned identity_start = kNotFound;
  unsigned size = transformed.View().length();
  for (unsigned i = 0; i < size; ++i) {
    TransformedString::Length len = transformed.LengthMap()[i];
    if (len > 1u) {
      if (identity_start != kNotFound) {
        mapping_builder_.AppendIdentityMapping(i - identity_start);
        identity_start = kNotFound;
      }
      mapping_builder_.AppendVariableMapping(len, 1u);
    } else if (len == 0u) {
      // LengthMap starts with 0, or 2+ is followed by 0.  They should not
      // happen.
      CHECK_NE(identity_start, kNotFound);
      if (i - identity_start > 1) {
        mapping_builder_.AppendIdentityMapping(i - identity_start - 1);
      }
      identity_start = kNotFound;
      unsigned zero_length = 1;
      for (++i; i < size; ++i) {
        if (transformed.LengthMap()[i] != 0) {
          --i;
          break;
        }
        ++zero_length;
      }
      mapping_builder_.AppendVariableMapping(1u, 1u + zero_length);
    } else {
      DCHECK_EQ(1u, len);
      if (identity_start == kNotFound) {
        identity_start = i;
      }
    }
  }
  if (identity_start != kNotFound) {
    mapping_builder_.AppendIdentityMapping(size - identity_start);
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendCollapseWhitespace(
    const TransformedString& transformed,
    const ComputedStyle* style,
    LayoutText* layout_object) {
  StringView string = transformed.View();
  DCHECK(!string.empty());

  // This algorithm segments the input string at the collapsible space, and
  // process collapsible space run and non-space run alternately.

  // The first run, regardless it is a collapsible space run or not, is special
  // that it can interact with the last item. Depends on the end of the last
  // item, it may either change collapsing behavior to collapse the leading
  // spaces of this item entirely, or remove the trailing spaces of the last
  // item.

  // Due to this difference, this algorithm process the first run first, then
  // loop through the rest of runs.

  unsigned start_offset;
  InlineItem::CollapseType end_collapse = InlineItem::kNotCollapsible;
  unsigned i = 0;
  UChar c = string[i];
  bool space_run_has_newline = false;
  if (Character::IsCollapsibleSpace(c)) {
    // Find the end of the collapsible space run.
    space_run_has_newline = MoveToEndOfCollapsibleSpaces(string, &i, &c);

    // LayoutBR does not set preserve_newline, but should be preserved.
    if (space_run_has_newline && string.length() == 1 && layout_object &&
        layout_object->IsBR()) [[unlikely]] {
      // https://drafts.csswg.org/css-ruby/#anon-gen-unbreak
      if (is_text_combine_ || ruby_text_nesting_level_ > 0) [[unlikely]] {
        AppendTextItem(TransformedString(" "), layout_object);
      } else {
        AppendForcedBreakCollapseWhitespace(layout_object);
      }
      return;
    }

    // Check the last item this space run may be collapsed with.
    bool insert_space;
    if (InlineItem* item = LastItemToCollapseWith(items_)) {
      if (item->EndCollapseType() == InlineItem::kNotCollapsible) {
        // The last item does not end with a collapsible space.
        // Insert a space to represent this space run.
        insert_space = true;
      } else {
        // The last item ends with a collapsible space this run should collapse
        // to. Collapse the entire space run in this item.
        DCHECK(item->EndCollapseType() == InlineItem::kCollapsible);
        insert_space = false;

        // If the space run either in this item or in the last item contains a
        // newline, apply segment break rules. This may result in removal of
        // the space in the last item.
        if ((space_run_has_newline || item->IsEndCollapsibleNewline()) &&
            item->Type() == InlineItem::kText &&
            ShouldRemoveNewline(text_, item->EndOffset() - 1, item->Style(),
                                StringView(string, i), style)) {
          RemoveTrailingCollapsibleSpace(item);
          space_run_has_newline = false;
        } else if (!item->Style()->ShouldWrapLine() &&
                   style->ShouldWrapLine()) {
          // Otherwise, remove the space run entirely, collapsing to the space
          // in the last item.

          // There is a special case to generate a break opportunity though.
          // Spec-wise, collapsed spaces are "zero advance width, invisible,
          // but retains its soft wrap opportunity".
          // https://drafts.csswg.org/css-text-3/#collapse
          // In most cases, this is not needed and that collapsed spaces are
          // removed entirely. However, when the first collapsible space is
          // 'nowrap', and the following collapsed space is 'wrap', the
          // collapsed space needs to create a break opportunity.
          // Note that we don't need to generate a break opportunity right
          // after a forced break.
          if (item->Type() != InlineItem::kControl ||
              text_[item->StartOffset()] != kNewlineCharacter) {
            AppendGeneratedBreakOpportunity(layout_object);
          }
        }
      }
    } else {
      // This space is at the beginning of the paragraph. Remove leading spaces
      // as CSS requires.
      insert_space = false;
    }

    // If this space run contains a newline, apply segment break rules.
    if (space_run_has_newline &&
        ShouldRemoveNewline(text_, text_.length(), style, StringView(string, i),
                            style)) {
      insert_space = space_run_has_newline = false;
    }

    // Done computing the interaction with the last item. Start appending.
    start_offset = text_.length();

    DCHECK(i);
    unsigned collapsed_length = i;
    if (insert_space) {
      text_.Append(kSpaceCharacter);
      mapping_builder_.AppendIdentityMapping(1);
      colla
"""


```