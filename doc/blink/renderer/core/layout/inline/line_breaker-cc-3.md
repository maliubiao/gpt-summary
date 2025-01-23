Response:
My thought process to arrive at the summary of the provided code snippet goes like this:

1. **Identify the core function:** The code clearly deals with handling the end of a line in the context of inline layout. Keywords like "trailing," "collapsible space," "whitespace," and "line break" are strong indicators.

2. **Break down the functionality into smaller units:**  I can see several distinct actions being performed:
    * Removing trailing collapsible spaces.
    * Calculating the width of these spaces without removing them.
    * Identifying trailing collapsible spaces.
    * Splitting off trailing spaces that have specific bidirectional (Bidi) properties.
    * Handling forced line breaks (`<br>` tags).
    * Measuring the size of atomic inline elements (like images or replaced content).
    * Handling block-level elements within inline content.
    * Dealing with Ruby annotations (text above/below base text).

3. **Look for connections to web technologies:** The mention of "ruby," "whitespace," and line breaks directly relates to how HTML, CSS, and JavaScript (through DOM manipulation) can influence text layout. I need to provide examples of these connections.

4. **Consider potential edge cases and errors:**  The code includes checks (`DCHECK`, `CHECK`) suggesting a focus on correctness. I need to think about what kinds of errors a web developer or even the browser engine itself might encounter related to line breaking and how this code might prevent or handle them.

5. **Infer logical flow (even without seeing the full file):**  The presence of "part 4 of 6" implies this code is part of a larger process. The functions likely get called in a specific sequence during the line breaking algorithm. While I don't know the exact sequence, I can infer that:
    * Trailing space computation probably happens before final line construction.
    * Handling forced breaks is a specific case triggered by certain inline items.
    * Bidi splitting happens to ensure correct text directionality.
    * Ruby handling is a more complex scenario involving sub-line layout.

6. **Focus on the *what* and *why*, not just the *how*:**  The code uses specific data structures and algorithms within the Blink engine. My summary needs to abstract away these implementation details and focus on the high-level purpose of each function. For instance, instead of explaining how `trailing_collapsible_space_` is used, I'll describe the broader goal of removing or measuring trailing spaces.

7. **Structure the summary logically:** I'll group related functionalities together. Starting with the core concept of trailing spaces makes sense, then moving to other specific line-breaking scenarios like forced breaks and inline blocks.

8. **Review and refine:** After drafting the initial summary, I'll review it to ensure accuracy, clarity, and completeness, given the information available in the snippet. I'll make sure the examples are relevant and the assumptions about input/output are reasonable.

Applying these steps to the provided code snippet leads to a summary that covers the key functionalities, their relevance to web technologies, potential errors, and the overall purpose of this part of the `line_breaker.cc` file. The "assumptions about input/output" section is crucial because I don't have the full context. I need to make reasonable guesses based on the function names and the operations performed. For example, the `ComputeTrailingCollapsibleSpace` function likely takes a `LineInfo` object and modifies its state related to trailing spaces.
这是 `blink/renderer/core/layout/inline/line_breaker.cc` 文件的第 4 部分，主要负责处理**行尾的特殊情况**和**一些复杂的内联元素**，以便确定行的最终构成和断点。

以下是该部分代码的功能归纳：

**核心功能：处理行尾的空白、强制换行、内联级别的块元素以及 Ruby 注释。**

**具体功能点：**

1. **处理行尾可折叠空白 (Trailing Collapsible Space):**
   - **移除尾部可折叠空白 (`ConsumeTrailingCollapsibleSpace`):**  当行尾存在可以被折叠的空白字符时，此函数负责将其从行的末尾移除，并更新行的 `position_` 和 `inline_size`。
   - **计算尾部可折叠空白的宽度 (`TrailingCollapsibleSpaceWidth`):**  在不移除的情况下，计算行尾可折叠空白的宽度。这在一些布局计算中很有用。
   - **查找尾部可折叠空白 (`ComputeTrailingCollapsibleSpace`, `ComputeTrailingCollapsibleSpaceHelper`):**  遍历行的内容，识别并缓存尾部的可折叠空白项。会考虑 Ruby 注释的情况。

2. **处理行尾需要根据 Bidi 规则处理的空白 (Trailing Bidi Preserved Space):**
   - **分割需要特殊 Bidi 处理的尾部空白 (`SplitTrailingBidiPreservedSpace`):** 根据 Unicode 双向算法 (Bidi) 的规则 L1，行尾的某些空白字符需要重置为段落的 Bidi 水平。此函数会将这些空白字符分割成单独的 `InlineItemResult`，并标记 `has_only_bidi_trailing_spaces`，以便后续 Bidi 重排序处理。

3. **处理强制换行符 (`HandleForcedLineBreak`):**
   - 当遇到 `<br>` 元素或类似机制导致的强制换行时，此函数负责处理。
   - 会检查溢出情况，并在必要时添加换行符。
   - 特别处理了带有 `clear` 属性的 `<br>` 元素在分栏布局中的情况。
   - 会将强制换行符标记为行的末尾，并设置相应的标志。
   - 还会包含强制换行符后面的闭合标签（如果有），因为这些标签的 margin/border/padding 会影响布局。

4. **处理控制字符 (`HandleControlItem`):**
   - 处理类似制表符 (`\t`)、零宽空格 (`<wbr>`) 等控制字符。
   - 制表符会根据字体和 `tab-size` 计算宽度。
   - 零宽空格会创建潜在的换行机会。
   - 忽略回车符 (`\r`) 和换页符 (`\f`)。

5. **处理 Bidi 控制字符 (`HandleBidiControlItem`):**
   - 处理影响文本方向的 Unicode 控制字符，如 LRE、RLE、PDF 等。
   - 将 "进入" 型的 Bidi 控制字符视为类似开始标签，"退出" 型的视为类似结束标签。

6. **处理原子内联元素 (Atomic Inline Elements) (`HandleAtomicInline`):**
   - 处理像图像 (`<img>`)、嵌入内容 (`<video>`, `<canvas>`) 或 `initial-letter` 等原子性的内联元素。
   - 计算元素的 margin。
   - 根据 `LineBreakerMode`（内容大小计算还是实际布局），调用相应的布局或尺寸计算方法。
   - 为 `initial-letter-box` 应用内联排版调整 (Inline Kerning)。

7. **处理内联级别的块元素 (Block-in-Inline) (`HandleBlockInInline`):**
   - 处理 `display: inline-block` 或类似的元素。
   - 如果行前有其他元素，会在块级元素前强制换行。
   - 执行块级元素的布局，并将其布局结果存储在 `LineInfo` 中。
   - 处理块级元素内部发生的断行情况，并可能创建用于并行布局的 `InlineBreakToken`。

8. **处理 Ruby 注释 (`HandleRuby`):**
   - 处理在内联文本中添加 Ruby 注释的情况。
   - 解析 Ruby 相关的内联元素 (Base, Text)。
   - 创建子 `LineInfo` 来处理 Ruby Base 和 Annotation 的布局。
   - 计算 Ruby 元素的整体大小，并考虑悬挂 (Overhang) 效果。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML:** 该代码直接处理 HTML 结构中的内联元素，例如 `<br>`, `<img>`, 以及 Ruby 相关的标签。
- **CSS:**  代码会读取和使用元素的 CSS 样式信息，例如 `white-space` 属性（影响空白处理）、`tab-size`、`clear` 属性、字体信息、Bidi 相关属性等。这些样式决定了如何进行断行和布局。
- **JavaScript:** JavaScript 通过 DOM 操作可以创建、修改 HTML 结构和 CSS 样式，从而间接地影响 `LineBreaker` 的行为。例如，通过 JavaScript 动态添加一个 `<br>` 元素会触发 `HandleForcedLineBreak` 的执行。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `ConsumeTrailingCollapsibleSpace`)：**

- `line_info`: 代表当前行的信息，其中包含一个或多个 `InlineItemResult`。
- `trailing_collapsible_space_`:  一个包含行尾可折叠空白信息的结构，例如指向空白字符的 `InlineItemResult`。
- 假设行尾存在一个空格字符。

**输出：**

- `line_info`:  其 `position_` 减少了空格字符的宽度，如果空格有相关的 `ShapeResultView` (例如，由于某些特殊渲染效果)，则会更新 `item_result->shape_result` 和 `item_result->inline_size`。如果空格没有特殊的渲染效果，则会将对应 `InlineItemResult` 的 `text_offset.end` 设置为 `text_offset.start`，使其变为空。
- `trailing_collapsible_space_` 被重置。
- `trailing_whitespace_` 被设置为 `WhitespaceState::kCollapsed`。

**假设输入 (针对 `HandleForcedLineBreak`)：**

- `item`: 指向 `<br>` 元素的 `InlineItem`。
- `line_info`: 代表当前行的信息。

**输出：**

- `line_info`:  添加一个新的 `InlineItemResult` 代表 `<br>` 元素，并设置 `should_create_line_box` 为 true，表示需要创建一个新的行盒。`is_forced_break_` 被设置为 true，并且 `line_info` 被标记为具有强制换行。
- 如果 `<br>` 元素有 `clear` 属性并且存在浮动需要清除，可能会提前结束当前行的处理。

**用户或编程常见的使用错误举例：**

1. **HTML 中过多的连续空格或制表符：** 虽然浏览器会折叠多个连续的空白字符，但理解 `LineBreaker` 如何处理这些空白可以帮助开发者避免不必要的布局困扰。例如，不小心在 HTML 中加入了大量的空格，可能会导致 `ConsumeTrailingCollapsibleSpace` 或 `SplitTrailingBidiPreservedSpace` 被频繁调用。

2. **CSS 中 `white-space` 属性使用不当：**  `white-space: pre` 或 `white-space: nowrap` 等属性会显著影响 `LineBreaker` 的行为。如果开发者对这些属性的理解有偏差，可能会导致文本布局不符合预期。例如，设置了 `white-space: nowrap` 但期望文本自动换行。

3. **在 Bidi 环境中不理解空白字符的影响：**  在从右向左 (RTL) 的文本中，行尾的空白字符可能需要特殊的处理以符合 Bidi 规则。开发者可能没有意识到这些空白字符会被 `SplitTrailingBidiPreservedSpace` 处理，从而导致一些布局上的意外。

4. **错误地嵌套或使用 Ruby 标签：** 如果 HTML 中 Ruby 标签的结构不正确，`HandleRuby` 可能会解析失败，导致布局错误。例如，缺少 `<rt>` 标签或标签闭合不正确。

**总结：**

这部分代码在 Blink 渲染引擎的行布局过程中扮演着至关重要的角色，它负责处理行尾的各种特殊情况，确保文本能够按照 CSS 规则正确地断行和排列。它涉及到对空白字符的处理、强制换行的实现、内联级别块元素的布局以及复杂排版特性如 Ruby 注释的支持。理解这部分代码的功能有助于理解浏览器如何将 HTML、CSS 转化为最终的视觉呈现。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
e have a trailing collapsible space. Remove it.
  InlineItemResult* item_result = &trailing_collapsible_space_->ItemResult();
  bool position_was_saturated = position_ == LayoutUnit::Max();
  position_ -= item_result->inline_size;
  if (const ShapeResultView* collapsed_shape_result =
          trailing_collapsible_space_->collapsed_shape_result) {
    --item_result->text_offset.end;
    item_result->text_offset.AssertNotEmpty();
    item_result->shape_result = collapsed_shape_result;
    item_result->inline_size = item_result->shape_result->SnappedWidth();
    position_ += item_result->inline_size;
  } else {
    // Make it empty, but don't remove. See `HandleEmptyText`.
    item_result->text_offset.end = item_result->text_offset.start;
    item_result->shape_result = nullptr;
    item_result->inline_size = LayoutUnit();
  }
  for (auto [results, index] :
       trailing_collapsible_space_->ancestor_ruby_columns) {
    InlineItemResult& ruby_column = (*results)[index];
    CHECK(ruby_column.IsRubyColumn());
    LineInfo& base_line = ruby_column.ruby_column->base_line;
    LayoutUnit new_width = base_line.ComputeWidth();
    base_line.SetWidth(base_line.AvailableWidth(), new_width);
    // Update LineInfo::end_offset_for_justify_.
    base_line.UpdateTextAlign();
    for (auto& line : ruby_column.ruby_column->annotation_line_list) {
      new_width = std::max(new_width, line.Width());
    }
    ruby_column.inline_size = new_width;
  }
  if (position_was_saturated ||
      !trailing_collapsible_space_->ancestor_ruby_columns.empty()) {
    position_ = line_info->ComputeWidth();
  }
  trailing_collapsible_space_.reset();
  trailing_whitespace_ = WhitespaceState::kCollapsed;
}

// Compute the width of trailing spaces without removing it.
LayoutUnit LineBreaker::TrailingCollapsibleSpaceWidth(LineInfo* line_info) {
  ComputeTrailingCollapsibleSpace(line_info);
  if (!trailing_collapsible_space_.has_value())
    return LayoutUnit();

  // Normally, the width of new_reuslt is smaller, but technically it can be
  // larger. In such case, it means the trailing spaces has negative width.
  InlineItemResult& item_result = trailing_collapsible_space_->ItemResult();
  LayoutUnit width_diff = item_result.inline_size;
  if (const ShapeResultView* collapsed_shape_result =
          trailing_collapsible_space_->collapsed_shape_result) {
    width_diff -= collapsed_shape_result->SnappedWidth();
  }
  if (trailing_collapsible_space_->ancestor_ruby_columns.empty()) {
    return width_diff;
  }
  for (auto [results, index] :
       trailing_collapsible_space_->ancestor_ruby_columns) {
    InlineItemResult& ruby_column = (*results)[index];
    CHECK(ruby_column.IsRubyColumn());
    LayoutUnit new_width =
        ruby_column.ruby_column->base_line.Width() - width_diff;
    for (auto& line : ruby_column.ruby_column->annotation_line_list) {
      new_width = std::max(new_width, line.Width());
    }
    width_diff = ruby_column.inline_size - new_width;
    if (width_diff == LayoutUnit()) {
      break;
    }
  }
  return width_diff;
}

// Find trailing collapsible space in `line_info` and its descendants if exists.
// The result is cached to |trailing_collapsible_space_|.
void LineBreaker::ComputeTrailingCollapsibleSpace(LineInfo* line_info) {
  if (trailing_whitespace_ == WhitespaceState::kLeading ||
      trailing_whitespace_ == WhitespaceState::kNone ||
      trailing_whitespace_ == WhitespaceState::kCollapsed ||
      trailing_whitespace_ == WhitespaceState::kPreserved) {
    trailing_collapsible_space_.reset();
    return;
  }
  DCHECK(trailing_whitespace_ == WhitespaceState::kUnknown ||
         trailing_whitespace_ == WhitespaceState::kCollapsible);

  trailing_whitespace_ = WhitespaceState::kNone;
  if (!ComputeTrailingCollapsibleSpaceHelper(*line_info)) {
    trailing_collapsible_space_.reset();
  }
}

// Returns true if trailing_whitespace_ is determined.
bool LineBreaker::ComputeTrailingCollapsibleSpaceHelper(LineInfo& line_info) {
  const String& text = Text();
  for (auto& item_result : base::Reversed(*line_info.MutableResults())) {
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;
    if (RuntimeEnabledFeatures::NoCollapseSpaceBeforeRubyEnabled() &&
        item_result.IsRubyColumn()) {
      if (ComputeTrailingCollapsibleSpaceHelper(
              item_result.ruby_column->base_line)) {
        if (trailing_collapsible_space_ &&
            trailing_collapsible_space_->item_result_index != WTF::kNotFound) {
          trailing_collapsible_space_->ancestor_ruby_columns.push_back(
              std::make_pair(line_info.MutableResults(),
                             std::distance(line_info.MutableResults()->data(),
                                           &item_result)));
        }
        return true;
      }
      continue;
    } else if (item.EndCollapseType() == InlineItem::kOpaqueToCollapsing) {
      continue;
    }
    if (item.Type() == InlineItem::kText) {
      if (RuntimeEnabledFeatures::NoCollapseSpaceBeforeRubyEnabled() &&
          item_result.Length() == 0) {
        continue;
      }
      DCHECK_GT(item_result.EndOffset(), 0u);
      DCHECK(item.Style());
      if (Character::IsOtherSpaceSeparator(text[item_result.EndOffset() - 1])) {
        trailing_whitespace_ = WhitespaceState::kPreserved;
        trailing_collapsible_space_.reset();
        return true;
      }
      if (!IsBreakableSpace(text[item_result.EndOffset() - 1])) {
        trailing_collapsible_space_.reset();
        return true;
      }
      if (item.Style()->ShouldPreserveWhiteSpaces()) {
        trailing_whitespace_ = WhitespaceState::kPreserved;
        trailing_collapsible_space_.reset();
        return true;
      }
      // |shape_result| is nullptr if this is an overflow because BreakText()
      // uses kNoResultIfOverflow option.
      if (!item_result.shape_result) {
        trailing_collapsible_space_.reset();
        return true;
      }

      InlineItemResults* results = line_info.MutableResults();
      wtf_size_t index = std::distance(results->data(), &item_result);
      if (!trailing_collapsible_space_.has_value() ||
          trailing_collapsible_space_->item_results != results ||
          trailing_collapsible_space_->item_result_index != index) {
        trailing_collapsible_space_.emplace();
        trailing_collapsible_space_->item_results = results;
        trailing_collapsible_space_->item_result_index = index;
        if (item_result.EndOffset() - 1 > item_result.StartOffset()) {
          trailing_collapsible_space_->collapsed_shape_result =
              TruncateLineEndResult(line_info, item_result,
                                    item_result.EndOffset() - 1);
        }
      }
      trailing_whitespace_ = WhitespaceState::kCollapsible;
      return true;
    }
    if (item.Type() == InlineItem::kControl) {
      if (item.TextType() == TextItemType::kForcedLineBreak) {
        DCHECK_EQ(text[item.StartOffset()], kNewlineCharacter);
        continue;
      }
      trailing_whitespace_ = WhitespaceState::kPreserved;
      trailing_collapsible_space_.reset();
      return true;
    }
    trailing_collapsible_space_.reset();
    return true;
  }
  return false;
}

// Per UAX#9 L1, any spaces logically at the end of a line must be reset to the
// paragraph's bidi level. If there are any such trailing spaces in an item
// result together with other non-space characters, this method splits them into
// their own item result.
//
// Furthermore, item results can't override their item's bidi level, so this
// method instead marks all such item results with `has_only_trailing_spaces`,
// which will cause them to be treated as having the base bidi level in
// InlineLayoutAlgorithm::BidiReorder.
void LineBreaker::SplitTrailingBidiPreservedSpace(LineInfo* line_info) {
  DCHECK(trailing_whitespace_ == WhitespaceState::kLeading ||
         trailing_whitespace_ == WhitespaceState::kNone ||
         trailing_whitespace_ == WhitespaceState::kCollapsed ||
         trailing_whitespace_ == WhitespaceState::kPreserved);

  if (trailing_whitespace_ == WhitespaceState::kLeading ||
      trailing_whitespace_ == WhitespaceState::kNone) {
    return;
  }

  if (!node_.IsBidiEnabled()) {
    return;
  }

  // TODO(abotella): This early return fixes a crash (crbug.com/324684931)
  // caused by |HandleTextForFastMinContent| creating item results with null
  // |shape_result|. This might affect hanging other space separators, but their
  // behavior with min-content is known to have bugs even in purely LTR text.
  if (mode_ == LineBreakerMode::kMinContent) {
    return;
  }

  // At this point, all trailing collapsible spaces have been collapsed, and all
  // remaining trailing spaces must be preserved.

  const String& text = Text();
  wtf_size_t result_index = line_info->Results().size();
  for (auto& item_result : base::Reversed(*line_info->MutableResults())) {
    result_index--;
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;

    if (item_result.has_only_bidi_trailing_spaces ||
        item.EndCollapseType() == InlineItem::kOpaqueToCollapsing ||
        item.TextType() == TextItemType::kForcedLineBreak) {
      continue;
    }

    if (item.Type() != InlineItem::kText &&
        item.Type() != InlineItem::kControl) {
      return;
    }

    DCHECK_GT(item_result.EndOffset(), 0u);

    wtf_size_t i = item_result.EndOffset();
    for (; i > item_result.StartOffset() &&
           (IsBreakableSpace(text[i - 1]) || IsBidiTrailingSpace(text[i - 1]));
         i--) {
    }

    if (i == item_result.StartOffset()) {
      item_result.has_only_bidi_trailing_spaces = true;
    } else if (i == item_result.EndOffset()) {
      break;
    } else {
      // Only split the item if its bidi level doesn't match the paragraph's.
      // We check the item's bidi level, rather than its direction, because
      // higher bidi levels with the same direction (i.e. level 2 on an LTR
      // paragraph) must also be reset.
      if (item.BidiLevel() != (UBiDiLevel)base_direction_) {
        const ShapeResultView* source_shape_result =
            item_result.shape_result.Get();
        LayoutUnit prev_inline_size = item_result.inline_size;
        wtf_size_t start = item_result.StartOffset();
        wtf_size_t end = item_result.EndOffset();

        item_result.text_offset.end = i;
        item_result.shape_result =
            ShapeResultView::Create(source_shape_result, start, i);
        item_result.inline_size = item_result.shape_result->SnappedWidth();
        DCHECK_LE(item_result.inline_size, prev_inline_size);

        InlineItemResult spaces_result(&item, item_result.item_index,
                                       TextOffsetRange(i, end),
                                       item_result.break_anywhere_if_overflow,
                                       item_result.should_create_line_box,
                                       item_result.has_unpositioned_floats);
        spaces_result.has_only_bidi_trailing_spaces = true;
        spaces_result.shape_result =
            ShapeResultView::Create(source_shape_result, i, end);
        spaces_result.inline_size = prev_inline_size - item_result.inline_size;

        line_info->MutableResults()->insert(result_index + 1,
                                            std::move(spaces_result));
      }
      break;
    }
  }
}

// |item| is |nullptr| if this is an implicit forced break.
void LineBreaker::HandleForcedLineBreak(const InlineItem* item,
                                        LineInfo* line_info) {
  // Check overflow, because the last item may have overflowed.
  if (HandleOverflowIfNeeded(line_info))
    return;

  if (item) {
    DCHECK_EQ(item->TextType(), TextItemType::kForcedLineBreak);
    DCHECK_EQ(Text()[item->StartOffset()], kNewlineCharacter);

    // Special-code for BR clear elements. If we have floats that extend into
    // subsequent fragmentainers, we cannot get past the floats in the current
    // fragmentainer. If this is the case, and if there's anything on the line
    // before the BR element, add a line break before it, so that we at least
    // attempt to place that part of the line right away. The remaining BR clear
    // element will be placed on a separate line, which we'll push past as many
    // fragmentainers as we need to. Example:
    //
    // <div style="columns:4; column-fill:auto; height:100px;">
    //   <div style="float:left; width:10px; height:350px;"></div>
    //   first column<br clear="all">
    //   fourth column
    // </div>
    //
    // Here we'll create one line box for the first float fragment and the text
    // "first column". We'll later on attempt to create another line box for the
    // BR element, but it will fail in the inline layout algorithm, because it's
    // impossible to clear past the float. We'll retry in the second and third
    // columns, but the float is still in the way. Finally, in the fourth
    // column, we'll add the BR, add clearance, and then create a line for the
    // text "fourth column" past the float.
    //
    // This solution isn't perfect, because of this additional line box for the
    // BR element. We'll push the line box containing the BR to a fragmentainer
    // where it doesn't really belong, and it will take up block space there
    // (this can be observed if the float clearance is less than the height of
    // the line, so that there will be a gap between the bottom of the float and
    // the content that follows). No browser engines currently get BR clearance
    // across fragmentainers right.
    if (constraint_space_.HasBlockFragmentation() && item->GetLayoutObject() &&
        item->GetLayoutObject()->IsBR() &&
        exclusion_space_->NeedsClearancePastFragmentainer(
            item->Style()->Clear(*current_style_))) {
      if (!line_info->Results().empty()) {
        state_ = LineBreakState::kDone;
        return;
      }
    }

    InlineItemResult* item_result = AddItem(*item, line_info);
    item_result->should_create_line_box = true;
    item_result->has_only_pre_wrap_trailing_spaces = true;
    item_result->has_only_bidi_trailing_spaces = true;
    item_result->can_break_after = true;
    MoveToNextOf(*item);

    // Include following close tags. The difference is visible when they have
    // margin/border/padding.
    //
    // This is not a defined behavior, but legacy/WebKit do this for preserved
    // newlines and <br>s. Gecko does this only for preserved newlines (but
    // not for <br>s).
    const HeapVector<InlineItem>& items = Items();
    while (!IsAtEnd()) {
      const InlineItem& next_item = items[current_.item_index];
      if (next_item.Type() == InlineItem::kCloseTag) {
        HandleCloseTag(next_item, line_info);
        continue;
      }
      if (next_item.Type() == InlineItem::kText && !next_item.Length()) {
        HandleEmptyText(next_item, line_info);
        continue;
      }
      break;
    }
  }

  if (HasHyphen()) [[unlikely]] {
    position_ -= RemoveHyphen(line_info->MutableResults());
  }
  is_forced_break_ = true;
  line_info->SetHasForcedBreak();
  line_info->SetIsLastLine(true);
  state_ = LineBreakState::kDone;
}

// Measure control items; new lines and tab, that are similar to text, affect
// layout, but do not need shaping/painting.
void LineBreaker::HandleControlItem(const InlineItem& item,
                                    LineInfo* line_info) {
  DCHECK_GE(item.Length(), 1u);
  if (item.TextType() == TextItemType::kForcedLineBreak) {
    HandleForcedLineBreak(&item, line_info);
    return;
  }

  DCHECK_EQ(item.TextType(), TextItemType::kFlowControl);
  UChar character = Text()[item.StartOffset()];
  switch (character) {
    case kTabulationCharacter: {
      DCHECK(item.Style());
      const ComputedStyle& style = *item.Style();
      if (!style.GetFont().PrimaryFont()) {
        // TODO(crbug.com/561873): PrimaryFont should not be nullptr.
        HandleEmptyText(item, line_info);
        return;
      }
      const ShapeResult* shape_result =
          ShapeResult::CreateForTabulationCharacters(
              &style.GetFont(), item.Direction(), style.GetTabSize(), position_,
              item.StartOffset(), item.Length());
      HandleText(item, *shape_result, line_info);
      return;
    }
    case kZeroWidthSpaceCharacter: {
      // <wbr> tag creates break opportunities regardless of auto_wrap.
      InlineItemResult* item_result = AddItem(item, line_info);
      // A generated break opportunity doesn't generate fragments, but we still
      // need to add this for rewind to find this opportunity. This will be
      // discarded in |InlineLayoutAlgorithm| when it generates fragments.
      if (!item.IsGeneratedForLineBreak())
        item_result->should_create_line_box = true;
      item_result->can_break_after = true;
      break;
    }
    case kCarriageReturnCharacter:
    case kFormFeedCharacter:
      // Ignore carriage return and form feed.
      // https://drafts.csswg.org/css-text-3/#white-space-processing
      // https://github.com/w3c/csswg-drafts/issues/855
      HandleEmptyText(item, line_info);
      return;
    default:
      NOTREACHED();
  }
  MoveToNextOf(item);
}

void LineBreaker::HandleBidiControlItem(const InlineItem& item,
                                        LineInfo* line_info) {
  DCHECK_EQ(item.Length(), 1u);

  // Bidi control characters have enter/exit semantics. Handle "enter"
  // characters simialr to open-tag, while "exit" (pop) characters similar to
  // close-tag.
  UChar character = Text()[item.StartOffset()];
  bool is_pop = character == kPopDirectionalIsolateCharacter ||
                character == kPopDirectionalFormattingCharacter;
  InlineItemResults* item_results = line_info->MutableResults();
  if (is_pop) {
    if (!item_results->empty()) {
      InlineItemResult* item_result = AddItem(item, line_info);
      InlineItemResult* last = &(*item_results)[item_results->size() - 2];
      // Honor the last |can_break_after| if it's true, in case it was
      // artificially set to true for break-after-space.
      if (last->can_break_after) {
        item_result->can_break_after = last->can_break_after;
        last->can_break_after = false;
      } else {
        // Otherwise compute from the text. |LazyLineBreakIterator| knows how to
        // break around bidi control characters.
        ComputeCanBreakAfter(item_result, auto_wrap_, break_iterator_);
      }
    } else {
      AddItem(item, line_info);
    }
  } else {
    if (state_ == LineBreakState::kTrailing &&
        CanBreakAfterLast(*item_results)) {
      DCHECK(!line_info->IsLastLine());
      MoveToNextOf(item);
      state_ = LineBreakState::kDone;
      return;
    }
    InlineItemResult* item_result = AddItem(item, line_info);
    DCHECK(!item_result->can_break_after);
  }
  MoveToNextOf(item);
}

void LineBreaker::HandleAtomicInline(const InlineItem& item,
                                     LineInfo* line_info) {
  DCHECK(item.Type() == InlineItem::kAtomicInline ||
         item.Type() == InlineItem::kInitialLetterBox);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();

  const LayoutUnit remaining_width = RemainingAvailableWidth();
  bool ignore_overflow_if_negative_margin = false;
  if (state_ == LineBreakState::kContinue && remaining_width < 0 &&
      (!parent_breaker_ || auto_wrap_)) {
    const unsigned item_index = current_.item_index;
    DCHECK_EQ(item_index, static_cast<unsigned>(&item - Items().data()));
    HandleOverflow(line_info);
    if (!line_info->HasOverflow() || item_index != current_.item_index) {
      return;
    }
    // Compute margins if this line overflows. Negative margins can put the
    // position back.
    DCHECK_NE(state_, LineBreakState::kContinue);
    ignore_overflow_if_negative_margin = true;
  }

  // Compute margins before computing overflow, because even when the current
  // position is beyond the end, negative margins can bring this item back to on
  // the current line.
  InlineItemResult* item_result = AddItem(item, line_info);
  item_result->margins =
      ComputeLineMarginsForVisualContainer(constraint_space_, style);
  LayoutUnit inline_margins = item_result->margins.InlineSum();
  if (ignore_overflow_if_negative_margin) [[unlikely]] {
    DCHECK_LT(remaining_width, 0);
    // The margin isn't negative, or the negative margin isn't large enough to
    // put the position back. Break this line before this item.
    if (inline_margins >= remaining_width) {
      RemoveLastItem(line_info);
      return;
    }
    // This line once overflowed, but the negative margin puts the position
    // back.
    state_ = LineBreakState::kContinue;
    line_info->SetHasOverflow(false);
  }

  // Last item may have ended with a hyphen, because at that point the line may
  // have ended there. Remove it because there are more items.
  if (HasHyphen()) [[unlikely]] {
    position_ -= RemoveHyphen(line_info->MutableResults());
  }

  const bool is_initial_letter_box =
      item.Type() == InlineItem::kInitialLetterBox;
  // When we're just computing min/max content sizes, we can skip the full
  // layout and just compute those sizes. On the other hand, for regular
  // layout we need to do the full layout and get the layout result.
  // Doing a full layout for min/max content can also have undesirable
  // side effects when that falls back to legacy layout.
  if (mode_ == LineBreakerMode::kContent || [&] {
        if (is_initial_letter_box) [[unlikely]] {
          return true;
        }
        return false;
      }()) {
    // If our baseline-source is non-auto use the easier to reason about
    // "default" algorithm type.
    BaselineAlgorithmType baseline_algorithm_type =
        style.BaselineSource() == EBaselineSource::kAuto
            ? BaselineAlgorithmType::kInlineBlock
            : BaselineAlgorithmType::kDefault;

    // https://drafts.csswg.org/css-pseudo-4/#first-text-line
    // > The first line of a table-cell or inline-block cannot be the first
    // > formatted line of an ancestor element.
    item_result->layout_result =
        BlockNode(To<LayoutBox>(item.GetLayoutObject()))
            .LayoutAtomicInline(constraint_space_, node_.Style(),
                                /* use_first_line_style */ false,
                                baseline_algorithm_type);
    // Ensure `NeedsCollectInlines` isn't set, or it may cause security risks.
    CHECK(!node_.GetLayoutBox()->NeedsCollectInlines());

    const auto& physical_box_fragment = To<PhysicalBoxFragment>(
        item_result->layout_result->GetPhysicalFragment());
    item_result->inline_size =
        LogicalFragment(constraint_space_.GetWritingDirection(),
                        physical_box_fragment)
            .InlineSize();

    if (is_initial_letter_box &&
        ShouldApplyInlineKerning(physical_box_fragment)) [[unlikely]] {
      // Apply "Inline Kerning" to the initial letter box[1].
      // [1] https://drafts.csswg.org/css-inline/#initial-letter-inline-position
      const LineBoxStrut side_bearing =
          ComputeNegativeSideBearings(physical_box_fragment);
      if (IsLtr(base_direction_)) {
        item_result->margins.inline_start += side_bearing.inline_start;
        inline_margins += side_bearing.inline_start;
      } else {
        item_result->margins.inline_end += side_bearing.inline_end;
        inline_margins += side_bearing.inline_end;
      }
    }

    item_result->inline_size += inline_margins;
  } else {
    DCHECK(mode_ == LineBreakerMode::kMaxContent ||
           mode_ == LineBreakerMode::kMinContent);
    ComputeMinMaxContentSizeForBlockChild(item, item_result);
  }

  item_result->should_create_line_box = true;
  item_result->can_break_after = CanBreakAfterAtomicInline(item);

  position_ += item_result->inline_size;

  trailing_whitespace_ = WhitespaceState::kNone;
  MoveToNextOf(item);
}

void LineBreaker::ComputeMinMaxContentSizeForBlockChild(
    const InlineItem& item,
    InlineItemResult* item_result) {
  DCHECK(mode_ == LineBreakerMode::kMaxContent ||
         mode_ == LineBreakerMode::kMinContent);
  if (mode_ == LineBreakerMode::kMaxContent && max_size_cache_) {
    const unsigned item_index =
        base::checked_cast<unsigned>(&item - Items().data());
    item_result->inline_size = (*max_size_cache_)[item_index];
    return;
  }

  DCHECK(mode_ == LineBreakerMode::kMinContent || !max_size_cache_);
  BlockNode child(To<LayoutBox>(item.GetLayoutObject()));

  MinMaxConstraintSpaceBuilder builder(constraint_space_, node_.Style(), child,
                                       /* is_new_fc */ true);
  builder.SetAvailableBlockSize(constraint_space_.AvailableSize().block_size);
  builder.SetPercentageResolutionBlockSize(
      constraint_space_.PercentageResolutionBlockSize());
  builder.SetReplacedPercentageResolutionBlockSize(
      constraint_space_.ReplacedPercentageResolutionBlockSize());
  const auto space = builder.ToConstraintSpace();

  const MinMaxSizesResult result =
      ComputeMinAndMaxContentContribution(node_.Style(), child, space);
  // Ensure `NeedsCollectInlines` isn't set, or it may cause security risks.
  CHECK(!node_.GetLayoutBox()->NeedsCollectInlines());
  const LayoutUnit inline_margins = item_result->margins.InlineSum();
  const LineBreaker* main_breaker = parent_breaker_ ? parent_breaker_ : this;
  if (main_breaker->mode_ == LineBreakerMode::kMinContent) {
    item_result->inline_size = result.sizes.min_size + inline_margins;
    if (depends_on_block_constraints_out_)
      *depends_on_block_constraints_out_ |= result.depends_on_block_constraints;
    if (MaxSizeCache* size_cache = main_breaker->max_size_cache_) {
      if (size_cache->empty()) {
        size_cache->resize(Items().size());
      }
      const unsigned item_index =
          base::checked_cast<unsigned>(&item - Items().data());
      (*size_cache)[item_index] = result.sizes.max_size + inline_margins;
    }
    return;
  }

  DCHECK(mode_ == LineBreakerMode::kMaxContent && !max_size_cache_);
  item_result->inline_size = result.sizes.max_size + inline_margins;
}

void LineBreaker::HandleBlockInInline(const InlineItem& item,
                                      const BlockBreakToken* block_break_token,
                                      LineInfo* line_info) {
  DCHECK_EQ(item.Type(), InlineItem::kBlockInInline);
  DCHECK(!block_break_token || block_break_token->InputNode().GetLayoutBox() ==
                                   item.GetLayoutObject());

  if (!line_info->Results().empty()) {
    // If there were any items, force a line break before this item.
    force_non_empty_if_last_line_ = false;
    HandleForcedLineBreak(nullptr, line_info);
    return;
  }

  InlineItemResult* item_result = AddItem(item, line_info);
  bool move_past_block = true;
  if (mode_ == LineBreakerMode::kContent) {
    // The exclusion spaces *must* match. If they don't we'll have an incorrect
    // layout (as it will potentially won't consider some preceeding floats).
    // Move the derived geometry for performance.
    DCHECK(*exclusion_space_ == constraint_space_.GetExclusionSpace());
    constraint_space_.GetExclusionSpace().MoveAndUpdateDerivedGeometry(
        *exclusion_space_);

    BlockNode block_node(To<LayoutBox>(item.GetLayoutObject()));
    std::optional<ConstraintSpace> modified_space;
    const ConstraintSpace& child_space =
        constraint_space_.CloneForBlockInInlineIfNeeded(modified_space);
    const ColumnSpannerPath* spanner_path_for_child =
        FollowColumnSpannerPath(column_spanner_path_, block_node);
    const LayoutResult* layout_result =
        block_node.Layout(child_space, block_break_token,
                          /* early_break */ nullptr, spanner_path_for_child);
    // Ensure `NeedsCollectInlines` isn't set, or it may cause security risks.
    CHECK(!node_.GetLayoutBox()->NeedsCollectInlines());
    line_info->SetBlockInInlineLayoutResult(layout_result);

    // Early exit if the layout didn't succeed.
    if (layout_result->Status() != LayoutResult::kSuccess) {
      state_ = LineBreakState::kDone;
      return;
    }

    const auto& fragment = layout_result->GetPhysicalFragment();
    item_result->inline_size =
        LogicalFragment(constraint_space_.GetWritingDirection(), fragment)
            .InlineSize();

    item_result->should_create_line_box = !layout_result->IsSelfCollapsing();
    item_result->layout_result = layout_result;

    if (const auto* outgoing_block_break_token = To<BlockBreakToken>(
            layout_result->GetPhysicalFragment().GetBreakToken())) {
      // The block broke inside. If the block itself fits, but some content
      // inside overflowed, we now need to enter a parallel flow, i.e. resume
      // the block-in-inline in the next fragmentainer, but continue layout of
      // any actual inline content after the block-in- inline in the current
      // fragmentainer.
      if (outgoing_block_break_token->IsAtBlockEnd()) {
        const auto* parallel_token =
            InlineBreakToken::CreateForParallelBlockFlow(
                node_, current_, *outgoing_block_break_token);
        line_info->PropagateParallelFlowBreakToken(parallel_token);
      } else {
        // The block-in-inline broke inside, and it's still in the same flow.
        resume_block_in_inline_in_same_flow_ = true;
        move_past_block = false;
      }
    }
  } else {
    DCHECK(mode_ == LineBreakerMode::kMaxContent ||
           mode_ == LineBreakerMode::kMinContent);
    ComputeMinMaxContentSizeForBlockChild(item, item_result);
  }

  position_ += item_result->inline_size;
  line_info->SetIsBlockInInline();
  line_info->SetHasForcedBreak();
  is_forced_break_ = true;
  trailing_whitespace_ = WhitespaceState::kNone;

  // If there's no break inside the block, or if the break inside the block is
  // for a parallel flow, proceed to the next item for the next line.
  if (move_past_block) {
    MoveToNextOf(item);
  }
  state_ = LineBreakState::kDone;
}

bool LineBreaker::HandleRuby(LineInfo* line_info, LayoutUnit retry_size) {
  const RubyBreakTokenData* ruby_token = ruby_break_token_;
  // Clear ruby_break_token_ first because HandleRuby() might set it again due
  // to rewinding.
  ruby_break_token_ = nullptr;
  InlineItemTextIndex base_start = current_;
  wtf_size_t base_end_index;
  Vector<AnnotationBreakTokenData, 1> annotation_data;
  wtf_size_t open_column_item_index;
  if (!ruby_token) {
    open_column_item_index = current_.item_index;
    RubyItemIndexes ruby_indexes =
        ParseRubyInInlineItems(Items(), current_.item_index);
    base_end_index = ruby_indexes.base_end;
    if (Items()[base_end_index].Type() == InlineItem::kCloseRubyColumn) {
      // No ruby-text. We don't need a kOpenRubyColumn result.
      return false;
    }
    UseCounter::Count(GetDocument(), WebFeature::kRenderRuby);
    DCHECK_EQ(Items()[base_end_index].Type(), InlineItem::kOpenTag);
    DCHECK(Items()[base_end_index].GetLayoutObject()->IsInlineRubyText());
    base_start = {current_.item_index + 1,
                  Items()[current_.item_index].EndOffset()};

    wtf_size_t start = ruby_indexes.annotation_start;
    annotation_data.push_back(AnnotationBreakTokenData{
        {start, Items()[start].StartOffset()}, start, ruby_indexes.column_end});
  } else {
    open_column_item_index = ruby_token->open_column_item_index;
    base_end_index = ruby_token->ruby_base_end_item_index;
    annotation_data = ruby_token->annotation_data;
  }
  const InlineItem& item = Items()[open_column_item_index];

  LineInfo base_line_info = CreateSubLineInfo(
      base_start, base_end_index, LineBreakerMode::kMaxContent, kIndefiniteSize,
      trailing_whitespace_, /* disable_trailing_whitespace_collapsing */ true);
  base_line_info.OverrideLineStyle(*current_style_);
  base_line_info.SetIsRubyBase();
  base_line_info.UpdateTextAlign();

  const wtf_size_t number_of_annotations = annotation_data.size();
  HeapVector<LineInfo, 1> annotation_line_list;
  annotation_line_list.reserve(number_of_annotations);
  for (const auto& data : annotation_data) {
    annotation_line_list.push_back(CreateSubLineInfo(
        data.start, data.end_item_index, LineBreakerMode::kMaxContent,
        kIndefiniteSize, WhitespaceState::kLeading));
    annotation_line_list.back().OverrideLineStyle(
        Items()[data.start_item_index].GetLayoutObject()->StyleRef());
  }

  LayoutUnit ruby_size = MaxLineWidth(base_line_info, annotation_line_list);
  LayoutUnit available = RemainingAvailableWidth().ClampNegativeToZero();
  AnnotationOverhang overhang =
      GetOverhang(ruby_size, base_line_info, annotation_line_list);
  if (!CanApp
```