Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the Chromium Blink rendering engine. Specifically, the code is from `inline_items_builder.cc`. I need to identify the core purpose of this code and how it relates to web content (HTML, CSS, JavaScript).

Here's a breakdown of the code's actions:

1. **Text Processing:** The code iterates through strings, identifying spaces and non-space characters. It handles whitespace collapsing according to CSS rules.
2. **Inline Item Creation:**  It creates various `InlineItem` objects, representing different parts of the inline layout (text, controls like line breaks, atomic inlines, etc.).
3. **Bidi Handling:** It manages bidirectional text embedding and isolation using Unicode control characters.
4. **Ruby Annotation Support:** It includes logic for handling ruby annotations (small text above/below base text).
5. **Line Breaking Considerations:** It inserts break opportunities and handles forced breaks.
6. **Layout Object Association:**  It associates the created `InlineItem`s with their corresponding `LayoutObject`s.
7. **State Management:** It maintains state regarding whether the content is block-level, contains floats, bidi controls, etc.

Now, I need to synthesize this into a concise summary, relating the actions to web technologies where applicable, and provide examples if there are clear connections. I also need to look for common errors or assumptions in how developers might use the related features.

**Plan:**

1. **Identify the Core Function:** The code's primary function is to build a sequence of `InlineItem`s from text content, taking into account CSS whitespace rules, bidi, and ruby.
2. **Relate to Web Technologies:**
    *   **HTML:** The input is derived from HTML text content.
    *   **CSS:**  CSS `white-space` property dictates how whitespace is handled. CSS bidi properties (`unicode-bidi`, `direction`) influence bidi processing. CSS ruby properties control ruby annotation layout.
    *   **JavaScript:** While this specific C++ code doesn't directly interact with JavaScript *execution*, the layout it produces affects how JavaScript might interact with the DOM (e.g., getting text ranges, measuring element sizes).
3. **Provide Examples:** Illustrate how CSS `white-space` impacts the collapsing of spaces, or how `unicode-bidi` affects text direction.
4. **Consider User/Programming Errors:**  Think about common misconceptions or mistakes developers might make regarding whitespace handling or bidi.
5. **Formulate the Summary:**  Write a concise summary of the code's functionality, focusing on its role in the rendering process.
这段代码片段主要负责构建用于内联布局的 `InlineItem` 序列。它处理文本内容，并根据 CSS 的 `white-space` 属性来决定如何处理空格和换行符，同时还处理了双向文本 (BiDi) 和 Ruby 注释。

**核心功能归纳:**

*   **处理文本字符串并分解成 `InlineItem`:**  这段代码遍历输入的文本字符串，并根据字符的类型（空格、非空格字符、控制字符等）以及相关的 CSS 样式，将其分解成一个个 `InlineItem` 对象。
*   **空格处理 (Whitespace Handling):**  根据 CSS 的 `white-space` 属性，决定如何处理空格，包括：
    *   **合并空格 (Collapsing Whitespace):** 将多个连续的空格合并成一个，并移除行首和行尾的空格。
    *   **保留空格 (Preserving Whitespace):**  按原样保留空格和换行符。
    *   **保留换行符 (Preserving Newlines):**  将换行符转换成强制换行符。
*   **处理控制字符 (Control Characters):**  识别并处理换行符 (`\n`)、制表符 (`\t`)、零宽度非连接符 (ZWNJ) 等控制字符，将它们添加到 `InlineItem` 序列中。
*   **处理双向文本 (BiDi):**  当遇到需要进行 BiDi 处理的文本时，会插入相应的 Unicode 控制字符（如 LRE, RLE, LRO, RLO, PDF, LRI, RLI, FSI, PDI），以控制文本的显示方向。
*   **处理 Ruby 注释:**  识别并处理 Ruby 注释相关的标签，插入 `kOpenRubyColumn` 和 `kCloseRubyColumn` 等类型的 `InlineItem`。
*   **插入换行机会 (Break Opportunities):**  在某些情况下（例如，在保留空格的场景下），会插入软换行机会 (`kZeroWidthSpaceCharacter`)，以便在必要时进行换行。
*   **处理强制换行 (Forced Breaks):**  将换行符 (`\n`) 转换成强制换行符，并插入相应的 `InlineItem`。
*   **处理行内块级元素 (Block-in-Inline):**  识别并处理行内的块级元素，插入 `kBlockInInline` 类型的 `InlineItem`。
*   **处理浮动元素 (Floating Elements):** 识别并处理浮动元素，插入 `kFloating` 类型的 `InlineItem`。
*   **处理绝对定位元素 (Out-of-Flow Positioned Elements):** 识别并处理绝对定位元素，插入 `kOutOfFlowPositioned` 类型的 `InlineItem`。
*   **维护状态:**  记录当前是否处于块级元素内 (`is_block_level_`)，是否包含浮动元素 (`has_floats_`)，是否包含 BiDi 控制字符 (`has_bidi_controls_`)，是否包含 Ruby 注释 (`has_ruby_`) 等状态信息。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **HTML:**  `inline_items_builder.cc` 处理的文本内容通常来自于 HTML 文本节点或者某些特定的 HTML 元素（例如，`<br>` 元素会导致插入强制换行符）。
    *   **例子:**  对于 HTML 代码 `<div>Hello <span>world</span></div>`，当处理文本节点 "Hello " 和 "world" 时，`inline_items_builder.cc` 会被调用。

*   **CSS:**  CSS 的 `white-space` 属性直接影响 `inline_items_builder.cc` 如何处理空格和换行符。
    *   **例子:**
        *   如果 CSS 设置了 `white-space: normal;` (默认值)，连续的空格会被合并成一个，行首和行尾的空格会被移除。
        *   如果 CSS 设置了 `white-space: pre;`，所有的空格和换行符都会被保留。
        *   如果 CSS 设置了 `white-space: pre-line;`，连续的空格会被合并，但换行符会被保留。
    *   CSS 的 `direction` 和 `unicode-bidi` 属性影响 BiDi 文本的处理。
        *   **例子:**  对于包含阿拉伯语或希伯来语的文本，如果 CSS 设置了 `direction: rtl;`，`inline_items_builder.cc` 可能会插入 RLE (Right-to-Left Embedding) 等控制字符。
    *   CSS 的 Ruby 注释相关的属性（例如，`ruby-position`）也会影响 Ruby 注释的布局，从而影响 `inline_items_builder.cc` 的处理逻辑。

*   **JavaScript:**  JavaScript 可以通过 DOM API 获取和修改 HTML 元素的内容，这些修改最终会影响到 `inline_items_builder.cc` 的输入。
    *   **例子:**  如果 JavaScript 代码使用 `element.textContent = "New  text";` 修改了元素的内容，那么当 Blink 重新布局该元素时，`inline_items_builder.cc` 会处理新的文本内容，并根据相关的 CSS 规则合并空格。

**假设输入与输出 (逻辑推理):**

假设输入的文本字符串是 "Hello  world\n"，并且元素的 CSS `white-space` 属性为 `normal`。

*   **假设输入:**
    *   `string`: "Hello  world\n"
    *   `style.ShouldCollapseWhiteSpaces()`: `true` (因为 `white-space` 是 `normal`)
*   **预期输出 (部分):**
    *   会创建两个 `InlineItem::kText` 类型的对象，分别对应 "Hello " 和 "world"。
    *   连续的空格 "  " 会被合并成一个空格。
    *   换行符 "\n" 会被视为一个软换行机会（取决于上下文，可能会被忽略或转换成强制换行）。
    *   `mapping_builder_` 会记录原始字符串到 `text_` 的映射关系，反映空格的合并。

假设输入的文本字符串是 "Hello  world\n"，并且元素的 CSS `white-space` 属性为 `pre`.

*   **假设输入:**
    *   `string`: "Hello  world\n"
    *   `style.ShouldCollapseWhiteSpaces()`: `false` (因为 `white-space` 是 `pre`)
*   **预期输出 (部分):**
    *   会创建一个 `InlineItem::kText` 类型的对象，对应 "Hello  world\n"。
    *   连续的空格 "  " 会被保留。
    *   换行符 "\n" 会被保留。
    *   `mapping_builder_` 会记录原始字符串到 `text_` 的直接映射。

**用户或者编程常见的使用错误举例说明:**

*   **误解 `white-space: normal;` 的行为:**  开发者可能会期望在 HTML 中输入的多个空格或换行符在页面上按原样显示，但由于 `white-space: normal;` 的默认行为是合并空格和忽略多余的换行符，结果可能与预期不符。
    *   **错误示例:**  HTML 中输入 `<p>Line 1

        Line 2</p>`，期望两行之间有空行，但实际上 `white-space: normal;` 会忽略多余的换行符，导致两行紧挨着显示。
*   **忘记处理 BiDi 文本:**  在处理包含不同书写方向的文本时，如果没有正确设置 CSS 的 `direction` 和 `unicode-bidi` 属性，可能导致文本显示错乱。
    *   **错误示例:**  在一段英文文本中嵌入了一段阿拉伯语，如果没有设置 `direction: rtl; unicode-bidi: bidi-override;`，阿拉伯语文本可能会从左到右显示，而不是从右到左。
*   **不理解 Ruby 注释的结构:**  开发者可能不清楚 Ruby 注释中各个组成部分（例如，ruby base, ruby text）的 HTML 结构和 CSS 属性，导致样式设置或布局出现问题。

**归纳一下它的功能 (针对提供的代码片段):**

这段代码片段专注于处理文本字符串中的空格和换行符。它根据 CSS 的 `white-space` 属性来决定是否应该合并空格，以及如何处理换行符。具体来说：

*   它会检查字符串的开头是否是需要保留的空格，并在适当的时候插入换行机会。
*   它会遍历字符串，区分空格和非空格字符。
*   对于需要合并的空格，它会计算连续空格的长度，并在 `mapping_builder_` 中记录合并的信息。
*   对于不需要合并的空格，它会直接添加到 `text_` 中。
*   它还会处理位于文本末尾的空格，并根据情况决定是否保留。
*   如果检测到换行符，并且 CSS 没有指示保留换行符，它可能会移除该换行符。

总而言之，这段代码是内联布局过程中处理文本内容细节的关键部分，它确保了文本内容能够根据 CSS 规则正确地被分解和格式化，为后续的布局计算奠定基础。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_items_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
psed_length--;
    }
    if (collapsed_length)
      mapping_builder_.AppendCollapsedMapping(collapsed_length);

    // If this space run is at the end of this item, keep whether the
    // collapsible space run has a newline or not in the item.
    if (i == string.length()) {
      end_collapse = InlineItem::kCollapsible;
    }
  } else {
    // If the last item ended with a collapsible space run with segment breaks,
    // apply segment break rules. This may result in removal of the space in the
    // last item.
    if (InlineItem* item = LastItemToCollapseWith(items_)) {
      if (item->EndCollapseType() == InlineItem::kCollapsible &&
          item->IsEndCollapsibleNewline() &&
          ShouldRemoveNewline(text_, item->EndOffset() - 1, item->Style(),
                              string, style)) {
        RemoveTrailingCollapsibleSpace(item);
      }
    }

    start_offset = text_.length();
  }

  // The first run is done. Loop through the rest of runs.
  if (i < string.length()) {
    while (true) {
      // Append the non-space text until we find a collapsible space.
      // |string[i]| is guaranteed not to be a space.
      DCHECK(!Character::IsCollapsibleSpace(string[i]));
      unsigned start_of_non_space = i;
      for (i++; i < string.length(); i++) {
        c = string[i];
        if (Character::IsCollapsibleSpace(c))
          break;
      }
      AppendTransformedString(
          transformed.Substring(start_of_non_space, i - start_of_non_space),
          *layout_object);

      if (i == string.length()) {
        end_collapse = InlineItem::kNotCollapsible;
        break;
      }

      // Process a collapsible space run. First, find the end of the run.
      DCHECK_EQ(c, string[i]);
      DCHECK(Character::IsCollapsibleSpace(c));
      unsigned start_of_spaces = i;
      space_run_has_newline = MoveToEndOfCollapsibleSpaces(string, &i, &c);

      // Because leading spaces are handled before this loop, no need to check
      // cross-item collapsing.
      DCHECK(start_of_spaces);

      // If this space run contains a newline, apply segment break rules.
      bool remove_newline = space_run_has_newline &&
                            ShouldRemoveNewline(text_, text_.length(), style,
                                                StringView(string, i), style);
      if (remove_newline) [[unlikely]] {
        // |kNotCollapsible| because the newline is removed, not collapsed.
        end_collapse = InlineItem::kNotCollapsible;
        space_run_has_newline = false;
      } else {
        // If the segment break rules did not remove the run, append a space.
        text_.Append(kSpaceCharacter);
        mapping_builder_.AppendIdentityMapping(1);
        start_of_spaces++;
        end_collapse = InlineItem::kCollapsible;
      }

      if (i != start_of_spaces)
        mapping_builder_.AppendCollapsedMapping(i - start_of_spaces);

      // If this space run is at the end of this item, keep whether the
      // collapsible space run has a newline or not in the item.
      if (i == string.length()) {
        break;
      }
    }
  }

  DCHECK_GE(text_.length(), start_offset);
  if (text_.length() == start_offset) [[unlikely]] {
    AppendEmptyTextItem(layout_object);
    return;
  }

  InlineItem& item = AppendItem(items_, InlineItem::kText, start_offset,
                                text_.length(), layout_object);
  item.SetEndCollapseType(end_collapse, space_run_has_newline);
  DCHECK(!item.IsEmptyItem());
  is_block_level_ = false;
}

template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::
    ShouldInsertBreakOpportunityAfterLeadingPreservedSpaces(
        StringView string,
        const ComputedStyle& style,
        unsigned index) const {
  DCHECK_LE(index, string.length());
  if (is_text_combine_) [[unlikely]] {
    return false;
  }
  // Check if we are at a preserved space character and auto-wrap is enabled.
  if (style.ShouldCollapseWhiteSpaces() || !style.ShouldWrapLine() ||
      !string.length() || index >= string.length() ||
      string[index] != kSpaceCharacter) {
    return false;
  }

  // Preserved leading spaces must be at the beginning of the first line or just
  // after a forced break.
  if (index)
    return string[index - 1] == kNewlineCharacter;
  return text_.empty() || text_[text_.length() - 1] == kNewlineCharacter;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::
    InsertBreakOpportunityAfterLeadingPreservedSpaces(
        const TransformedString& transformed,
        const ComputedStyle& style,
        LayoutText* layout_object,
        unsigned* start) {
  DCHECK(start);
  StringView string = transformed.View();
  if (ShouldInsertBreakOpportunityAfterLeadingPreservedSpaces(
          string, style, *start)) [[unlikely]] {
    wtf_size_t end = *start;
    do {
      ++end;
    } while (end < string.length() && string[end] == kSpaceCharacter);
    AppendTextItem(transformed.Substring(*start, end - *start), layout_object);
    AppendGeneratedBreakOpportunity(layout_object);
    *start = end;
  }
}

// TODO(yosin): We should remove |style| and |string| parameter because of
// except for testing, we can get them from |LayoutText|.
// Even when without whitespace collapsing, control characters (newlines and
// tabs) are in their own control items to make the line breaker not special.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendPreserveWhitespace(
    const TransformedString& transformed,
    const ComputedStyle* style,
    LayoutText* layout_object) {
  DCHECK(style);

  // A soft wrap opportunity exists at the end of the sequence of preserved
  // spaces. https://drafts.csswg.org/css-text-3/#white-space-phase-1
  // Due to our optimization to give opportunities before spaces, the
  // opportunity after leading preserved spaces needs a special code in the line
  // breaker. Generate an opportunity to make it easy.
  unsigned start = 0;
  InsertBreakOpportunityAfterLeadingPreservedSpaces(transformed, *style,
                                                    layout_object, &start);
  const StringView transformed_view = transformed.View();
  const wtf_size_t length = transformed_view.length();
  if (start >= length) [[unlikely]] {
    return;
  }
  if (layout_object->HasNoControlItems()) {
    AppendTextItem(transformed.Substring(start), layout_object);
    return;
  }
  wtf_size_t control = transformed_view.Find(IsControlItemCharacter, start);
  if (control == kNotFound) {
    layout_object->SetHasNoControlItems();
    AppendTextItem(transformed.Substring(start), layout_object);
    return;
  }

  // Split the transformed string by control items.
  while (start < length) {
    if (control != start) {
      AppendTextItem(transformed.Substring(start, control - start),
                     layout_object);
      if (control >= length) {
        break;
      }
      start = control;
    }

    const UChar c = transformed_view[start];
    switch (c) {
      case kNewlineCharacter:
        if (is_text_combine_ || ruby_text_nesting_level_ > 0) [[unlikely]] {
          start++;
          AppendTextItem(TransformedString(" "), layout_object);
          break;
        }
        AppendForcedBreak(layout_object);
        start++;
        // A forced break is not a collapsible space, but following collapsible
        // spaces are leading spaces and they need a special code in the line
        // breaker. Generate an opportunity to make it easy.
        InsertBreakOpportunityAfterLeadingPreservedSpaces(
            transformed, *style, layout_object, &start);
        break;
      case kTabulationCharacter: {
        wtf_size_t tab_end = transformed_view.Find(
            [](UChar c) { return c != kTabulationCharacter; }, start + 1);
        if (tab_end == kNotFound) {
          tab_end = length;
        }
        InlineItem& item = AppendTextItem(
            InlineItem::kControl, transformed.Substring(start, tab_end - start),
            layout_object);
        item.SetTextType(TextItemType::kFlowControl);
        start = tab_end;
        is_score_line_break_disabled_ = true;
        break;
      }
      case kZeroWidthNonJoinerCharacter:
        // ZWNJ splits item, but it should be text.
        control = transformed_view.Find(IsControlItemCharacter, start + 1);
        if (control == kNotFound) {
          control = length;
        }
        continue;
      default: {
        DCHECK(IsControlItemCharacter(c));
        InlineItem& item = Append(InlineItem::kControl, c, layout_object);
        item.SetTextType(TextItemType::kFlowControl);
        start++;
        break;
      }
    }
    if (start >= length) {
      break;
    }

    control = transformed_view.Find(IsControlItemCharacter, start);
    if (control == kNotFound) {
      control = length;
    }
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendPreserveNewline(
    const TransformedString& transformed,
    const ComputedStyle* style,
    LayoutText* layout_object) {
  String string = transformed.View().ToString();
  for (unsigned start = 0; start < string.length();) {
    if (string[start] == kNewlineCharacter) {
      AppendForcedBreakCollapseWhitespace(layout_object);
      start++;
      continue;
    }

    wtf_size_t end = string.find(kNewlineCharacter, start + 1);
    if (end == kNotFound)
      end = string.length();
    DCHECK_GE(end, start);
    AppendCollapseWhitespace(transformed.Substring(start, end - start), style,
                             layout_object);
    start = end;
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendForcedBreak(
    LayoutObject* layout_object) {
  DCHECK(layout_object);
  // Combined text should ignore force line break[1].
  // [1] https://drafts.csswg.org/css-writing-modes-3/#text-combine-layout
  DCHECK(!is_text_combine_);
  // At the forced break, add bidi controls to pop all contexts.
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-embedding-breaks
  if (!bidi_context_.empty()) {
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    // These bidi controls need to be associated with the |layout_object| so
    // that items from a LayoutObject are consecutive.
    for (const auto& bidi : base::Reversed(bidi_context_)) {
      AppendOpaque(InlineItem::kBidiControl, bidi.exit, layout_object);
    }
  }

  InlineItem& item =
      Append(InlineItem::kControl, kNewlineCharacter, layout_object);
  item.SetTextType(TextItemType::kForcedLineBreak);

  // A forced break is not a collapsible space, but following collapsible spaces
  // are leading spaces and that they should be collapsed.
  // Pretend that this item ends with a collapsible space, so that following
  // collapsible spaces can be collapsed.
  item.SetEndCollapseType(InlineItem::kCollapsible, false);

  // Then re-add bidi controls to restore the bidi context.
  if (!bidi_context_.empty()) {
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    for (const auto& bidi : bidi_context_) {
      AppendOpaque(InlineItem::kBidiControl, bidi.enter, layout_object);
    }
  }

  DidAppendForcedBreak();
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::
    AppendForcedBreakCollapseWhitespace(LayoutObject* layout_object) {
  // Remove collapsible spaces immediately before a preserved newline.
  RemoveTrailingCollapsibleSpaceIfExists();

  AppendForcedBreak(layout_object);
}

template <typename MappingBuilder>
InlineItem& InlineItemsBuilderTemplate<MappingBuilder>::AppendBreakOpportunity(
    LayoutObject* layout_object) {
  DCHECK(layout_object);
  InlineItem& item = AppendOpaque(InlineItem::kControl,
                                  kZeroWidthSpaceCharacter, layout_object);
  item.SetTextType(TextItemType::kFlowControl);
  return item;
}

// The logic is similar to AppendForcedBreak().
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::ExitAndEnterSvgTextChunk(
    LayoutText& layout_text) {
  DCHECK(block_flow_->IsSVGText());
  DCHECK(text_chunk_offsets_);

  if (bidi_context_.empty())
    return;
  typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
  // These bidi controls need to be associated with the |layout_text| so
  // that items from a LayoutObject are consecutive.
  for (const auto& bidi : base::Reversed(bidi_context_))
    AppendOpaque(InlineItem::kBidiControl, bidi.exit, &layout_text);

  // Then re-add bidi controls to restore the bidi context.
  for (const auto& bidi : bidi_context_)
    AppendOpaque(InlineItem::kBidiControl, bidi.enter, &layout_text);
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::EnterSvgTextChunk(
    const ComputedStyle* style) {
  if (!block_flow_->IsSVGText() || !text_chunk_offsets_) [[likely]] {
    return;
  }
  EnterBidiContext(nullptr, style, kLeftToRightIsolateCharacter,
                   kRightToLeftIsolateCharacter,
                   kPopDirectionalIsolateCharacter);
  // This context is automatically popped by Exit(nullptr) in ExitBlock().
}

template <typename MappingBuilder>
InlineItem& InlineItemsBuilderTemplate<MappingBuilder>::Append(
    InlineItem::InlineItemType type,
    UChar character,
    LayoutObject* layout_object) {
  DCHECK_NE(character, kSpaceCharacter);

  has_non_orc_16bit_ = has_non_orc_16bit_ || IsNonOrc16BitCharacter(character);
  text_.Append(character);
  mapping_builder_.AppendIdentityMapping(1);
  unsigned end_offset = text_.length();
  InlineItem& item =
      AppendItem(items_, type, end_offset - 1, end_offset, layout_object);
  is_block_level_ &= item.IsBlockLevel();
  return item;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendAtomicInline(
    LayoutObject* layout_object) {
  DCHECK(layout_object);
  typename MappingBuilder::SourceNodeScope scope(&mapping_builder_,
                                                 layout_object);
  RestoreTrailingCollapsibleSpaceIfRemoved();
  Append(InlineItem::kAtomicInline, kObjectReplacementCharacter, layout_object);

  // When this atomic inline is inside of an inline box, the height of the
  // inline box can be different from the height of the atomic inline. Ensure
  // the inline box creates a box fragment so that its height is available in
  // the fragment tree.
  if (!boxes_.empty()) {
    BoxInfo* current_box = &boxes_.back();
    if (!current_box->should_create_box_fragment)
      current_box->SetShouldCreateBoxFragment(items_);
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendBlockInInline(
    LayoutObject* layout_object) {
  DCHECK(layout_object);
  // Before a block-in-inline is like after a forced break.
  RemoveTrailingCollapsibleSpaceIfExists();
  InlineItem& item = Append(InlineItem::kBlockInInline,
                            kObjectReplacementCharacter, layout_object);
  // After a block-in-inline is like after a forced break. See
  // |AppendForcedBreak|.
  item.SetEndCollapseType(InlineItem::kCollapsible, false);

  if (ShouldUpdateLayoutObject()) {
    // Prevent the inline box from culling to avoid the need of the special
    // logic when traversing.
    DCHECK(!layout_object->Parent() ||
           IsA<LayoutInline>(layout_object->Parent()));
    if (auto* parent = To<LayoutInline>(layout_object->Parent()))
      parent->SetShouldCreateBoxFragment();
  }

  // Block-in-inline produces 3 logical paragraphs. It requires to bisect
  // block-in-inline, before it and after it separately. See
  // `ParagraphLineBreaker`.
  is_bisect_line_break_disabled_ = true;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendFloating(
    LayoutObject* layout_object) {
  AppendOpaque(InlineItem::kFloating, kObjectReplacementCharacter,
               layout_object);
  has_floats_ = true;
  // Floats/exclusions require computing line heights, which is currently
  // skipped during the bisect. See `ParagraphLineBreaker`.
  is_bisect_line_break_disabled_ = true;
  // `ScoreLineBreaker` supports "simple" floats. See`LineWidths`.
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendOutOfFlowPositioned(
    LayoutObject* layout_object) {
  AppendOpaque(InlineItem::kOutOfFlowPositioned, kObjectReplacementCharacter,
               layout_object);
}

template <typename MappingBuilder>
InlineItem& InlineItemsBuilderTemplate<MappingBuilder>::AppendOpaque(
    InlineItem::InlineItemType type,
    UChar character,
    LayoutObject* layout_object) {
  has_non_orc_16bit_ = has_non_orc_16bit_ || IsNonOrc16BitCharacter(character);
  text_.Append(character);
  mapping_builder_.AppendIdentityMapping(1);
  unsigned end_offset = text_.length();
  InlineItem& item =
      AppendItem(items_, type, end_offset - 1, end_offset, layout_object);
  item.SetEndCollapseType(InlineItem::kOpaqueToCollapsing);
  is_block_level_ &= item.IsBlockLevel();
  return item;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::AppendOpaque(
    InlineItem::InlineItemType type,
    LayoutObject* layout_object) {
  unsigned end_offset = text_.length();
  InlineItem& item =
      AppendItem(items_, type, end_offset, end_offset, layout_object);
  item.SetEndCollapseType(InlineItem::kOpaqueToCollapsing);
  is_block_level_ &= item.IsBlockLevel();
}

// Removes the collapsible space at the end of |text_| if exists.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<
    MappingBuilder>::RemoveTrailingCollapsibleSpaceIfExists() {
  if (InlineItem* item = LastItemToCollapseWith(items_)) {
    if (item->EndCollapseType() == InlineItem::kCollapsible) {
      RemoveTrailingCollapsibleSpace(item);
    }
  }
}

// Removes the collapsible space at the end of the specified item.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::RemoveTrailingCollapsibleSpace(
    InlineItem* item) {
  DCHECK(item);
  DCHECK_EQ(item->EndCollapseType(), InlineItem::kCollapsible);
  DCHECK_GT(item->Length(), 0u);

  // A forced break pretends that it's a collapsible space, see
  // |AppendForcedBreak()|. It should not be removed.
  if (item->Type() != InlineItem::kText) {
    DCHECK(item->Type() == InlineItem::kControl ||
           item->Type() == InlineItem::kBlockInInline);
    return;
  }

  DCHECK_GT(item->EndOffset(), item->StartOffset());
  unsigned space_offset = item->EndOffset() - 1;
  DCHECK_EQ(text_[space_offset], kSpaceCharacter);
  text_.erase(space_offset);
  mapping_builder_.CollapseTrailingSpace(space_offset);

  // Keep the item even if the length became zero. This is not needed for
  // the layout purposes, but needed to maintain LayoutObject states. See
  // |AppendEmptyTextItem()|.
  item->SetEndOffset(item->EndOffset() - 1);
  item->SetEndCollapseType(InlineItem::kCollapsed);

  // Trailing spaces can be removed across non-character items.
  // Adjust their offsets if after the removed index.
  for (item++; item != items_->data() + items_->size(); item++) {
    item->SetOffset(item->StartOffset() - 1, item->EndOffset() - 1);
  }
}

// Restore removed collapsible space at the end of items.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<
    MappingBuilder>::RestoreTrailingCollapsibleSpaceIfRemoved() {
  if (InlineItem* last_item = LastItemToCollapseWith(items_)) {
    if (last_item->EndCollapseType() == InlineItem::kCollapsed) {
      RestoreTrailingCollapsibleSpace(last_item);
    }
  }
}

// Restore removed collapsible space at the end of the specified item.
template <typename MappingBuilder>
void InlineItemsBuilderTemplate<
    MappingBuilder>::RestoreTrailingCollapsibleSpace(InlineItem* item) {
  DCHECK(item);
  DCHECK(item->EndCollapseType() == InlineItem::kCollapsed);

  mapping_builder_.RestoreTrailingCollapsibleSpace(
      To<LayoutText>(*item->GetLayoutObject()), item->EndOffset());

  // TODO(kojii): Implement StringBuilder::insert().
  if (text_.length() == item->EndOffset()) {
    text_.Append(' ');
  } else {
    String current = text_.ToString();
    text_.Clear();
    text_.Append(StringView(current, 0, item->EndOffset()));
    text_.Append(' ');
    text_.Append(StringView(current, item->EndOffset()));
  }

  item->SetEndOffset(item->EndOffset() + 1);
  item->SetEndCollapseType(InlineItem::kCollapsible);

  for (item++; item != items_->data() + items_->size(); item++) {
    item->SetOffset(item->StartOffset() + 1, item->EndOffset() + 1);
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::EnterBidiContext(
    LayoutObject* node,
    UChar enter,
    UChar exit) {
  AppendOpaque(InlineItem::kBidiControl, enter);
  bidi_context_.push_back(BidiContext{node, enter, exit});
  has_bidi_controls_ = true;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::EnterBidiContext(
    LayoutObject* node,
    const ComputedStyle* style,
    UChar ltr_enter,
    UChar rtl_enter,
    UChar exit) {
  EnterBidiContext(node, IsLtr(style->Direction()) ? ltr_enter : rtl_enter,
                   exit);
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::EnterBlock(
    const ComputedStyle* style) {
  // Handle bidi-override on the block itself.
  if (style->RtlOrdering() == EOrder::kLogical) {
    EnterSvgTextChunk(style);
    switch (style->GetUnicodeBidi()) {
      case UnicodeBidi::kNormal:
      case UnicodeBidi::kEmbed:
      case UnicodeBidi::kIsolate:
        // Isolate and embed values are enforced by default and redundant on the
        // block elements.
        // Direction is handled as the paragraph level by
        // BidiParagraph::SetParagraph().
        if (style->Direction() == TextDirection::kRtl)
          has_bidi_controls_ = true;
        break;
      case UnicodeBidi::kBidiOverride:
      case UnicodeBidi::kIsolateOverride:
        EnterBidiContext(nullptr, style, kLeftToRightOverrideCharacter,
                         kRightToLeftOverrideCharacter,
                         kPopDirectionalFormattingCharacter);
        break;
      case UnicodeBidi::kPlaintext:
        // Plaintext is handled as the paragraph level by
        // BidiParagraph::SetParagraph().
        has_bidi_controls_ = true;
        // It's not easy to compute which lines will change with `unicode-bidi:
        // plaintext`. Since it is quite uncommon that just disable line cache.
        has_unicode_bidi_plain_text_ = true;
        break;
    }
  } else {
    DCHECK_EQ(style->RtlOrdering(), EOrder::kVisual);
    EnterBidiContext(nullptr, style, kLeftToRightOverrideCharacter,
                     kRightToLeftOverrideCharacter,
                     kPopDirectionalFormattingCharacter);
  }

  if (style->IsDisplayListItem() && style->ListStyleType()) {
    is_block_level_ = false;
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::EnterInline(
    LayoutInline* node) {
  DCHECK(node);

  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  const ComputedStyle* style = node->Style();
  if (style->RtlOrdering() == EOrder::kLogical) {
    switch (style->GetUnicodeBidi()) {
      case UnicodeBidi::kNormal:
        break;
      case UnicodeBidi::kEmbed:
        EnterBidiContext(node, style, kLeftToRightEmbedCharacter,
                         kRightToLeftEmbedCharacter,
                         kPopDirectionalFormattingCharacter);
        break;
      case UnicodeBidi::kBidiOverride:
        EnterBidiContext(node, style, kLeftToRightOverrideCharacter,
                         kRightToLeftOverrideCharacter,
                         kPopDirectionalFormattingCharacter);
        break;
      case UnicodeBidi::kIsolate:
        EnterBidiContext(node, style, kLeftToRightIsolateCharacter,
                         kRightToLeftIsolateCharacter,
                         kPopDirectionalIsolateCharacter);
        break;
      case UnicodeBidi::kPlaintext:
        has_unicode_bidi_plain_text_ = true;
        EnterBidiContext(node, kFirstStrongIsolateCharacter,
                         kPopDirectionalIsolateCharacter);
        break;
      case UnicodeBidi::kIsolateOverride:
        EnterBidiContext(node, kFirstStrongIsolateCharacter,
                         kPopDirectionalIsolateCharacter);
        EnterBidiContext(node, style, kLeftToRightOverrideCharacter,
                         kRightToLeftOverrideCharacter,
                         kPopDirectionalFormattingCharacter);
        break;
    }
  }

  has_ruby_ = has_ruby_ || node->IsInlineRubyText();
  if (node->IsInlineRubyText()) {
    ++ruby_text_nesting_level_;
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    if (!node->Parent()->IsInlineRuby()) {
      // This creates a ruby column with a placeholder-only ruby-base.
      AppendOpaque(InlineItem::kOpenRubyColumn,
                   IsLtr(style->Direction()) ? kLeftToRightIsolateCharacter
                                             : kRightToLeftIsolateCharacter,
                   nullptr);
      AppendOpaque(InlineItem::kRubyLinePlaceholder, nullptr);
    } else {
      AppendOpaque(InlineItem::kRubyLinePlaceholder, node->Parent());
    }
  }
  AppendOpaque(InlineItem::kOpenTag, node);

  if (NeedsBoxInfo()) {
    // Set |ShouldCreateBoxFragment| of the parent box if needed.
    BoxInfo* current_box =
        &boxes_.emplace_back(items_->size() - 1, items_->back());
    if (boxes_.size() > 1) {
      BoxInfo* parent_box = std::prev(current_box);
      if (!parent_box->should_create_box_fragment &&
          parent_box->ShouldCreateBoxFragmentForChild(*current_box)) {
        parent_box->SetShouldCreateBoxFragment(items_);
      }
    }
  }

  typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
  if (node->IsInlineRuby()) {
    AppendOpaque(InlineItem::kOpenRubyColumn,
                 IsLtr(style->Direction()) ? kLeftToRightIsolateCharacter
                                           : kRightToLeftIsolateCharacter,
                 node);
    if (kDisableForcedBreakInRubyColumn) {
      ++ruby_text_nesting_level_;
    }
    AppendOpaque(InlineItem::kRubyLinePlaceholder, node);
  } else if (node->IsInlineRubyText()) {
    AppendOpaque(InlineItem::kRubyLinePlaceholder, node);
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::ExitBlock() {
  Exit(nullptr);

  // Segment Break Transformation Rules[1] defines to keep trailing new lines,
  // but it will be removed in Phase II[2]. We prefer not to add trailing new
  // lines and collapsible spaces in Phase I.
  RemoveTrailingCollapsibleSpaceIfExists();
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::ExitInline(
    LayoutObject* node) {
  DCHECK(node);

  if (node->IsInlineRuby()) {
    if (kDisableForcedBreakInRubyColumn) {
      --ruby_text_nesting_level_;
    }
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    wtf_size_t size = items_->size();
    if (size >= 3 &&
        items_->at(size - 3).Type() == InlineItem::kCloseRubyColumn &&
        items_->at(size - 2).Type() == InlineItem::kOpenRubyColumn &&
        items_->at(size - 1).Type() == InlineItem::kRubyLinePlaceholder) {
      // Remove the last kOpenRubyColumn and kRubyLinePlaceholder.
      text_.Resize(items_->at(size - 2).StartOffset());
      items_->Shrink(size - 2);
      // kOpenRubyColumn called AppendIdentityMapping(1).
      mapping_builder_.RevertIdentityMapping1();
    } else {
      AppendOpaque(InlineItem::kCloseRubyColumn,
                   kPopDirectionalIsolateCharacter, node);
    }
  } else if (node->IsInlineRubyText()) {
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    AppendOpaque(InlineItem::kRubyLinePlaceholder, node);
  }

  if (NeedsBoxInfo()) {
    BoxInfo* current_box = &boxes_.back();
    if (!current_box->should_create_box_fragment) {
      // Set ShouldCreateBoxFragment if this inline box is empty so that we can
      // compute its position/size correctly. Check this by looking for any
      // non-empty items after the last |kOpenTag|.
      const unsigned open_item_index = current_box->item_index;
      DCHECK_GE(items_->size(), open_item_index + 1);
      DCHECK_EQ((*items_)[open_item_index].Type(), InlineItem::kOpenTag);
      for (unsigned i = items_->size() - 1;; --i) {
        InlineItem& item = (*items_)[i];
        if (i == open_item_index) {
          DCHECK_EQ(i, current_box->item_index);
          // TODO(kojii): <area> element fails to hit-test when we don't cull.
          if (!IsA<HTMLAreaElement>(item.GetLayoutObject()->GetNode()))
            item.SetShouldCreateBoxFragment();
          break;
        }
        DCHECK_GT(i, current_box->item_index);
        if (item.IsEmptyItem()) {
          // float, abspos, collapsed space(<div>ab <span> </span>).
          // See editing/caret/empty_inlines.html
          // See also [1] for empty line box.
          // [1] https://drafts.csswg.org/css2/visuren.html#phantom-line-box
          continue;
        }
        if (item.IsCollapsibleSpaceOnly()) {
          // Because we can't collapse trailing spaces until next node, we
          // create box fragment for it: <div>ab<span> </span></div>
          // See editing/selection/mixed-editability-10.html
          continue;
        }
        break;
      }
    }

    boxes_.pop_back();
  }

  AppendOpaque(InlineItem::kCloseTag, node);

  if (node->IsInlineRubyText()) {
    --ruby_text_nesting_level_;
    typename MappingBuilder::SourceNodeScope scope(&mapping_builder_, nullptr);
    if (node->Parent()->IsInlineRuby()) {
      LayoutObject* ruby_container = node->Parent();
      AppendOpaque(InlineItem::kCloseRubyColumn,
                   kPopDirectionalIsolateCharacter, ruby_container);
      // This produces almost-empty ruby-columns if </ruby> follows.
      // The beginning part of this function removes such ruby-columns.
      AppendOpaque(InlineItem::kOpenRubyColumn,
                   IsLtr(node->Parent()->Style()->Direction())
                       ? kLeftToRightIsolateCharacter
                       : kRightToLeftIsolateCharacter,
                   ruby_container);
      AppendOpaque(InlineItem::kRubyLinePlaceholder, node);
    } else {
      AppendOpaque(InlineItem::kCloseRubyColumn,
                   kPopDirectionalIsolateCharacter, nullptr);
    }
  }

  Exit(node);
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::Exit(LayoutObject* node) {
  while (!bidi_context_.empty() && bidi_context_.back().node == node) {
    AppendOpaque(InlineItem::kBidiControl, bidi_context_.back().exit);
    bidi_context_.pop_back();
  }
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::DidFinishCollectInlines(
    InlineNodeData* data) {
  data->text_content = ToString();
  data->has_non_orc_16bit_ = has_non_orc_16bit_;

  // Set |is_bidi_enabled_| for all UTF-16 strings for now, because at this
  // point the string may or may not contain RTL characters.
  // |SegmentText()| will analyze the text and reset |is_bidi_enabled_| if it
  // doesn't contain any RTL characters.
  data->is_bidi_enabled_ =
      HasBidiControls() ||
      (has_non_orc_16bit_ && Character::MaybeBidiRtl(data->text_content));
  data->has_floats_ = has_floats_;
  data->has_initial_letter_box_ = has_initial_letter_box_;
  data->has_ruby_ = has_ruby_;
  data->is_block_level_ = IsBlockLevel();
  data->changes_may_affect_earlier_lines_ = HasUnicodeBidiPlainText();
  data->is_bisect_line_break_disabled_ = is_bisect_line_break_disabled_;
  data->is_score_line_break_disabled_ = is_score_line_break_disabled_;

#if DCHECK_IS_ON()
  data->CheckConsistency();
#endif
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::SetHasInititialLetterBox() {
  DCHECK(!items_->empty());
  DCHECK(!has_initial_letter_box_);
  has_initial_letter_box_ = true;
  // Floats/exclusions require computing line heights, which is currently
  // skipped during the bisect. See `ParagraphLineBreaker`.
  is_bisect_line_break_disabled_ = true;
  is_score_line_break_disabled_ = true;
}

template <typename MappingBuilder>
void InlineItemsBuilderTemplate<MappingBuilder>::SetIsSymbolMarker() {
  DCHECK(!items_->empty());
  items_->back().SetIsSymbolMarker();
}

template <typename MappingBuilder>
bool InlineItemsBuilderTemplate<MappingBuilder>::ShouldUpdateLayoutObject()
    const {
  r
```