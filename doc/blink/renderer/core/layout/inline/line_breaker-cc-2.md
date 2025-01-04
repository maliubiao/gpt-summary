Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to analyze the code and identify its core purpose. The code seems to be related to breaking lines of text for layout purposes. I should look for keywords and logic related to:

1. **Line breaking**:  Function names like `BreakTextAt`, `BreakTextAtPreviousBreakOpportunity`, `HandleTextForFastMinContent` strongly suggest this.
2. **Text properties**:  References to `InlineItem`, `ShapeResult`, `TextOffset`, `ComputedStyle`, `hyphenation` indicate interaction with text and its styling.
3. **Layout dimensions**:  `inline_size`, `position_` suggest calculations related to the width of text.
4. **Break opportunities**:  The use of `break_iterator_` points to the logic of finding valid points to break a line.
5. **Whitespace handling**:  Variables like `trailing_whitespace_` and functions dealing with spaces are present.
6. **Min-content**: The `HandleTextForFastMinContent` function explicitly mentions this layout mode.

I should also look for connections to web technologies like Javascript, HTML, and CSS, providing examples if any exist. For instance, CSS's `white-space` and `word-wrap` properties directly influence line breaking.

I need to analyze specific functions and their inputs and outputs to understand the logical flow. For example, `BreakTextAt` takes a break point as input and seems to adjust the `item_result` accordingly.

Finally, I need to identify potential user or programming errors related to line breaking, such as incorrect usage of CSS properties or unexpected behavior due to complex text content.

Given this is part 3 of 6, I should focus on the functionalities exposed in this particular snippet and avoid making assumptions about the complete file.
这是 `blink/renderer/core/layout/inline/line_breaker.cc` 文件的第三部分，主要功能是处理文本项的断行逻辑，特别是针对文本内容在不同断行机会上的处理，以及为后续的布局阶段提供断行候选点信息。

**功能归纳：**

这部分代码主要负责以下功能：

1. **在指定的断点处截断文本项 (`BreakTextAt`)：**  根据传入的断点信息 (`break_at_`)，修改当前文本项 (`item_result`) 的结束位置，并根据是否需要连字符来添加连字符。
2. **在之前的断点机会处截断文本项 (`BreakTextAtPreviousBreakOpportunity`)：**  在文本项中回溯到上一个合法的断行机会，并将文本项在那里截断。
3. **为 `min-content` 模式快速处理文本项 (`HandleTextForFastMinContent`)：**  这是一个优化的处理方式，用于计算 `min-content` 布局下的文本宽度。它会遍历文本中的所有断行机会，并找到最宽的“单词” (由断点分隔)。
4. **处理空文本项 (`HandleEmptyText`)：**  对于空的或完全折叠的文本，添加一个空的 `InlineItemResult`。
5. **重新塑形文本 (`ShapeText`)：**  对指定范围的文本进行重新排版，生成 `ShapeResult` 对象，包含了文本的布局信息。
6. **追加断行候选点 (`AppendCandidates`)：**  为文本项生成一系列可能的断行点（`LineBreakCandidate`），这些候选点将被后续的断行算法使用，以找到最佳的断行位置。
7. **判断是否可以在文本项内部断行 (`CanBreakInside`)：**  检查一个文本项是否包含可以断开的位置。
8. **截断行尾结果 (`TruncateLineEndResult`)：**  根据给定的结束偏移量，截断 `InlineItemResult` 中关联的 `ShapeResult`，生成一个新的 `ShapeResultView`。
9. **更新形状结果 (`UpdateShapeResult`)：**  根据 `InlineItemResult` 的起始和结束偏移量，更新其 `ShapeResult`。
10. **处理尾随空格 (`HandleTrailingSpaces`)：**  处理行尾的空格，根据 `white-space` 属性决定是否折叠或保留。
11. **回溯尾部的开放标签 (`RewindTrailingOpenTags`)：**  在断行时，移除尾部的开放标签。
12. **移除尾部的可折叠空格 (`RemoveTrailingCollapsibleSpace`)：** 根据 CSS 规范，移除行尾的可折叠空格。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS 的 `white-space` 属性：**
    * `HandleTrailingSpaces` 函数会根据 `white-space` 的值（如 `normal`, `nowrap`, `pre-wrap` 等）来决定如何处理尾随的空格。例如，如果 `white-space: normal;`，则尾随的空格会被折叠；如果 `white-space: pre;` 或 `white-space: pre-wrap;`，则尾随的空格会被保留。
    * `HandleTextForFastMinContent` 中也会考虑 `item_style.ShouldCollapseWhiteSpaces()` 来决定如何处理空格。
* **CSS 的 `word-wrap` 或 `overflow-wrap` 属性：**
    * `auto_wrap_` 变量可能与 `word-wrap: break-word;` 或 `overflow-wrap: break-word;` 属性相关联。当设置为 `true` 时，即使在单词中间也会寻找断行机会。`AppendCandidates` 函数中的 `if (auto_wrap_)` 分支体现了这一点。
* **CSS 的 `text-indent` 属性：**
    * `HandleTextForFastMinContent` 中会检查 `line_info->TextIndent()`，用于处理首行缩进。负的 `text-indent` 可能会导致行首的断行行为不同。
* **CSS 的 `hyphens` 属性：**
    * `BreakTextAt` 和 `HandleTextForFastMinContent` 中都涉及到连字符的处理 (`break_at_.is_hyphenated`, `AddHyphen`, `hyphenation_`)，这与 CSS 的 `hyphens` 属性相关。`AppendCandidates` 中也会根据 `hyphens` 属性插入连字符断点。
* **HTML 的 `<br>` 标签和换行符：**
    * 隐式地，这些代码处理了由 `<br>` 标签或文本内容中的换行符 (`\n`) 引起的强制断行。虽然代码中没有直接提及 HTML 标签，但断行逻辑是为渲染 HTML 内容服务的。
* **JavaScript 操作 DOM 和样式：**
    * JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会最终影响到 Blink 引擎的布局和断行逻辑。例如，通过 JavaScript 修改元素的 `white-space` 属性，会导致 `LineBreaker` 的行为发生变化。

**逻辑推理、假设输入与输出：**

**假设输入：**

一个包含文本 "This is a long word that might need to be hyphenated." 的 `InlineItem` 对象，其 CSS 样式为 `white-space: normal; hyphens: auto;`，当前行宽有限。

**`BreakTextAt` 函数的假设输入与输出：**

* **假设输入：**
    * `item_index`: 当前文本项的索引。
    * `break_at_`:  一个表示断点信息的结构，其中 `end.item_index` 指向当前文本项， `end.text_offset` 指向 "hyphenated" 中 "hyphen" 后的某个位置， `is_hyphenated` 为 `true`。
    * `item_result`:  当前文本项的 `InlineItemResult` 对象，其 `text_offset.end` 指向 "hyphenated" 的末尾。
    * `line_info`: 当前行的信息。
* **预期输出：**
    * `item_result` 的 `text_offset.end` 会被更新为 `break_at_.end.text_offset` 指向的位置。
    * 如果需要连字符，会在 `line_info->MutableResults()` 中添加一个表示连字符的 `InlineItemResult`。
    * 函数返回 `true`，表示发生了断行。

**`HandleTextForFastMinContent` 函数的假设输入与输出：**

* **假设输入：**
    * `item_result`:  当前文本项的 `InlineItemResult` 对象，其 `text_offset.start` 指向 "This"。
    * `item`:  表示文本 "This is a long word" 的 `InlineItem` 对象。
    * `shape_result`:  已经排版过该文本的 `ShapeResult` 对象。
    * `line_info`: 当前行的信息。
    * `mode_` 为 `LineBreakerMode::kMinContent`。
* **预期输出：**
    * 函数会遍历 "This", "is", "a", "long", "word" 这些单词，并计算它们的宽度。
    * `item_result->inline_size` 将会被设置为最宽的单词 "long" 的宽度。
    * 函数返回 `true`。

**`AppendCandidates` 函数的假设输入与输出：**

* **假设输入：**
    * `item_result`:  表示文本 "is a" 的 `InlineItemResult` 对象。
    * `line_info`: 当前行的信息。
    * `context`:  当前的 `LineBreakCandidateContext` 对象，可能已经包含之前的断点候选信息。
* **预期输出：**
    * `context` 对象会被更新，包含 "is" 和 "a" 之间的空格，以及 "a" 之后的可能的断点位置作为新的 `LineBreakCandidate`。每个候选点会包含其偏移量和位置信息。

**用户或编程常见的使用错误举例：**

1. **CSS `white-space: nowrap;` 导致意外的溢出：**  用户可能设置了 `white-space: nowrap;`，期望文本不换行，但如果容器宽度不足，会导致文本溢出容器，`LineBreaker` 将不会进行断行。
2. **错误地使用 `word-break: break-all;` 或 `overflow-wrap: break-word;`：**  虽然这些属性可以强制断词，但在某些情况下可能会导致不自然的断行效果，例如在不应该断开的地方断开单词。
3. **混合使用不同的 `white-space` 值导致布局混乱：**  在一个包含多个内联元素的容器中，如果这些元素使用了不同的 `white-space` 值，可能会导致意外的空格折叠或保留，影响断行效果。
4. **假设断行总是发生在空格处：**  用户可能认为只有空格才是断行点，但实际上，根据 CSS 属性和语言规则，断行可能发生在其他位置，例如连字符、CJK 字符之间等。`LineBreaker` 的逻辑会考虑这些情况。
5. **忘记处理长单词的溢出：**  如果用户没有使用 `word-wrap: break-word;` 或 `overflow-wrap: break-word;`，并且存在很长的、没有空格的单词，可能会导致该单词溢出容器。

总而言之，这部分代码是 Blink 引擎中负责文本断行核心逻辑的关键部分，它深入处理了各种断行场景，并与 CSS 属性紧密相关，最终决定了文本内容如何在网页上进行排列显示。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
item_index >= break_at_.end.item_index;
  if (should_break) {
    DCHECK_LE(break_at_.end.text_offset, item_result->text_offset.end);
    item_result->text_offset.end = break_at_.end.text_offset;
    item_result->text_offset.AssertValid();
  } else {
    DCHECK_GE(break_at_.end.text_offset, item_result->text_offset.end);
  }
  if (item_result->Length()) {
    const ShapeResultView* shape_result = breaker.ShapeLineAt(
        item_result->StartOffset(), item_result->EndOffset());
    item_result->inline_size =
        shape_result->SnappedWidth().ClampNegativeToZero();
    item_result->shape_result = shape_result;
    if (break_at_.is_hyphenated) {
      AddHyphen(line_info->MutableResults(), item_result);
    }
  } else {
    DCHECK_EQ(item_result->inline_size, LayoutUnit());
    DCHECK(!break_at_.is_hyphenated);
  }
  item_result->can_break_after = true;
  trailing_whitespace_ = WhitespaceState::kNone;
  return should_break;
}

// Breaks the text item at the previous break opportunity from
// |item_result->text_offset.end|. Returns false if there were no previous break
// opportunities.
bool LineBreaker::BreakTextAtPreviousBreakOpportunity(
    InlineItemResults& results,
    wtf_size_t item_result_index) {
  InlineItemResult* item_result = &results[item_result_index];
  DCHECK(item_result->item);
  DCHECK(item_result->may_break_inside);
  const InlineItem& item = *item_result->item;
  DCHECK_EQ(item.Type(), InlineItem::kText);
  DCHECK(item.Style() && item.Style()->ShouldWrapLine());
  DCHECK(!is_text_combine_);

  // TODO(jfernandez): Should we use the non-hangable-run-end instead ?
  unsigned break_opportunity = break_iterator_.PreviousBreakOpportunity(
      item_result->EndOffset() - 1, item_result->StartOffset());
  if (break_opportunity <= item_result->StartOffset())
    return false;
  item_result->text_offset.end = break_opportunity;
  item_result->text_offset.AssertNotEmpty();
  item_result->shape_result = ShapeResultView::Create(
      item.TextShapeResult(), item_result->StartOffset(),
      item_result->EndOffset());
  item_result->inline_size =
      item_result->shape_result->SnappedWidth().ClampNegativeToZero();
  item_result->can_break_after = true;

  if (trailing_collapsible_space_.has_value() &&
      trailing_collapsible_space_->item_results == &results &&
      trailing_collapsible_space_->item_result_index == item_result_index) {
    trailing_collapsible_space_.reset();
  }

  return true;
}

// This function handles text item for min-content. The specialized logic is
// because min-content is very expensive by breaking at every break opportunity
// and producing as many lines as the number of break opportunities.
//
// This function breaks the text in InlineItem at every break opportunity,
// computes the maximum width of all words, and creates one InlineItemResult
// that has the maximum width. For example, for a text item of "1 2 34 5 6",
// only the width of "34" matters for min-content.
//
// The first word and the last word, "1" and "6" in the example above, are
// handled in normal |HandleText()| because they may form a word with the
// previous/next item.
bool LineBreaker::HandleTextForFastMinContent(InlineItemResult* item_result,
                                              const InlineItem& item,
                                              const ShapeResult& shape_result,
                                              LineInfo* line_info) {
  DCHECK_EQ(mode_, LineBreakerMode::kMinContent);
  DCHECK(auto_wrap_);
  DCHECK(item.Type() == InlineItem::kText ||
         (item.Type() == InlineItem::kControl &&
          Text()[item.StartOffset()] == kTabulationCharacter));
  DCHECK(&shape_result);

  // Break the text at every break opportunity and measure each word.
  unsigned start_offset = item_result->StartOffset();
  DCHECK_LT(start_offset, item.EndOffset());
  DCHECK_EQ(shape_result.StartIndex(), item.StartOffset());
  DCHECK_GE(start_offset, shape_result.StartIndex());
  const unsigned item_end_offset = item.EndOffset();
  unsigned end_offset = item_end_offset;

  bool should_break_at_first_opportunity = false;
  const LayoutUnit indent = line_info->TextIndent();
  if (indent) [[unlikely]] {
    if (indent < 0) [[unlikely]] {
      // A negative `text-indent` can make this line not wrap at the first
      // break opportunity if it's in the indent. Use `HandleText()`.
      return false;
    }
    should_break_at_first_opportunity = true;
    end_offset = start_offset + 1;
  } else if (position_ < indent) [[unlikely]] {
    // A negative margin can move the position before the initial position.
    // This line may not wrap at the first break opportunity if it appears
    // before the initial position. Fall back to `HandleText()`.
    return false;
  } else {
    if (position_ != indent) [[unlikely]] {
      // Break at the first opportunity if there were previous items.
      should_break_at_first_opportunity = true;
      end_offset = start_offset + 1;
    }
#if EXPENSIVE_DCHECKS_ARE_ON()
    // Whether the start offset is at middle of a word or not can also be
    // determined by `line_info->Results()`. Check if they match.
    auto results = base::make_span(line_info->Results());
    DCHECK_EQ(item_result, &results.back());
    results = results.first(results.size() - 1);
    bool is_at_mid_word = false;
    for (const InlineItemResult& result : base::Reversed(results)) {
      DCHECK(!result.can_break_after);
      if (result.inline_size) {
        is_at_mid_word = true;
        break;
      }
    }
    DCHECK_EQ(should_break_at_first_opportunity,
              is_at_mid_word ||
                  (has_cloned_box_decorations_ &&
                   cloned_box_decorations_initial_size_ > LayoutUnit()));
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
  }

  shape_result.EnsurePositionData();
  const unsigned saved_start_offset = break_iterator_.StartOffset();
  FastMinTextContext context;
  const String& text = Text();
  const ComputedStyle& item_style = *item.Style();
  const bool should_break_spaces = item_style.ShouldBreakSpaces();
  unsigned next_break = 0;
  unsigned non_hangable_run_end = 0;
  bool can_break_after = false;
  while (start_offset < end_offset) {
    // TODO(crbug.com/332328872): `following()` scans back to the start of the
    // string. Resetting the ICU `BreakIterator` is faster than the scanning.
    break_iterator_.SetStartOffset(start_offset);

    next_break = break_iterator_.NextBreakOpportunity(
        start_offset + 1, std::min(item_end_offset + 1, text.length()));

    if (next_break > item_end_offset) [[unlikely]] {
      // The `item.EndOffset()` is not breakable; e.g., middle of a word.
      DCHECK_EQ(next_break, item_end_offset + 1);
      if (start_offset == item_result->StartOffset()) {
        // If this is the first word of this line, create an `InlineItemResult`
        // of this word with `!can_break_after`, so that it can create a line
        // with following items.
        next_break = item_end_offset;
        can_break_after = false;
      } else {
        const UChar next_ch = text[next_break - 1];
        if (next_ch == kNewlineCharacter) {
          // Optimize to avoid splitting `InlineItemResult`. If the next is a
          // forced break, this line ends without additional widths.
          next_break = item_end_offset;
          can_break_after = false;
        } else {
          // If the end of `item` is middle of a word, spilt before the last
          // word. The last word should create a line with following items.
          next_break = start_offset;
          DCHECK(can_break_after);
          break;
        }
      }
    } else {
      can_break_after = true;
    }
    DCHECK_LE(next_break, item_end_offset);

    // Remove trailing spaces.
    non_hangable_run_end = next_break;
    if (!should_break_spaces) {
      while (non_hangable_run_end > start_offset &&
             IsBreakableSpace(text[non_hangable_run_end - 1])) {
        --non_hangable_run_end;
      }
    }

    // `word_len` may be zero if `start_offset` is at a breakable space.
    DCHECK_GE(non_hangable_run_end, start_offset);
    if (const wtf_size_t word_len = non_hangable_run_end - start_offset) {
      bool has_hyphen = can_break_after &&
                        text[non_hangable_run_end - 1] == kSoftHyphenCharacter;
      if (hyphenation_) [[unlikely]] {
        const StringView word(text, start_offset, word_len);
        if (should_break_at_first_opportunity) [[unlikely]] {
          if (const wtf_size_t location =
                  hyphenation_->FirstHyphenLocation(word, 0)) {
            next_break = non_hangable_run_end = start_offset + location;
            has_hyphen = can_break_after = true;
          }
          context.Add(shape_result, start_offset, non_hangable_run_end,
                      has_hyphen, *item_result);
        } else {
          context.AddHyphenated(shape_result, start_offset,
                                non_hangable_run_end, has_hyphen, *item_result,
                                *hyphenation_, word);
        }
      } else {
        context.Add(shape_result, start_offset, non_hangable_run_end,
                    has_hyphen, *item_result);
      }
    }

    DCHECK_GT(next_break, start_offset);
    start_offset = next_break;
  }

  break_iterator_.SetStartOffset(saved_start_offset);

  // Create an `InlineItemResult` that has the max of widths of all words.
  DCHECK_GE(non_hangable_run_end, item_result->StartOffset());
  DCHECK_LE(non_hangable_run_end, item_end_offset);
  if (item_style.ShouldCollapseWhiteSpaces()) {
    item_result->text_offset.end = non_hangable_run_end;
    trailing_whitespace_ = non_hangable_run_end != next_break
                               ? WhitespaceState::kCollapsed
                               : WhitespaceState::kNone;
  } else {
    item_result->text_offset.end = next_break;
    trailing_whitespace_ = non_hangable_run_end != next_break
                               ? WhitespaceState::kPreserved
                               : WhitespaceState::kNone;
  }
  item_result->text_offset.AssertValid();
  item_result->inline_size = context.MinInlineSize();
  position_ += item_result->inline_size;
  item_result->can_break_after = can_break_after;
  if (can_break_after) {
    state_ = LineBreakState::kTrailing;
  } else {
    state_ = LineBreakState::kOverflow;
  }

  DCHECK_GE(next_break, non_hangable_run_end);
  DCHECK_LE(next_break, item_end_offset);
  if (next_break >= item_end_offset) {
    MoveToNextOf(item);
  } else {
    // It's critical to move forward to avoid an infinite loop.
    DCHECK_EQ(current_.text_offset, item_result->StartOffset());
    CHECK_GT(next_break, current_.text_offset);
    current_.text_offset = next_break;
  }
  return true;
}

void LineBreaker::HandleEmptyText(const InlineItem& item, LineInfo* line_info) {
  // Add an empty `InlineItemResult` for empty or fully collapsed text. They
  // aren't necessary for line breaking/layout purposes, but callsites may need
  // to see all `InlineItem` by iterating `InlineItemResult`. For example,
  // `CreateLine` needs to `ClearNeedsLayout` for all `LayoutObject` including
  // empty or fully collapsed text.
  AddEmptyItem(item, line_info);
  MoveToNextOf(item);
}

// Re-shape the specified range of |InlineItem|.
const ShapeResult* LineBreaker::ShapeText(const InlineItem& item,
                                          unsigned start,
                                          unsigned end,
                                          ShapeOptions options) {
  ShapeResult* shape_result = nullptr;
  if (!items_data_->segments) {
    RunSegmenter::RunSegmenterRange segment_range =
        InlineItemSegment::UnpackSegmentData(start, end, item.SegmentData());
    shape_result = shaper_.Shape(&item.Style()->GetFont(), item.Direction(),
                                 start, end, segment_range, options);
  } else {
    shape_result = items_data_->segments->ShapeText(
        &shaper_, &item.Style()->GetFont(), item.Direction(), start, end,
        base::checked_cast<unsigned>(&item - items_data_->items.data()),
        options);
  }
  if (spacing_.HasSpacing()) [[unlikely]] {
    shape_result->ApplySpacing(spacing_);
  }
  return shape_result;
}

void LineBreaker::AppendCandidates(const InlineItemResult& item_result,
                                   const LineInfo& line_info,
                                   LineBreakCandidateContext& context) {
  DCHECK(item_result.item);
  const InlineItem& item = *item_result.item;
  const wtf_size_t item_index = item_result.item_index;
  DCHECK(context.GetState() == LineBreakCandidateContext::kBreak ||
         !context.Candidates().empty());

  DCHECK_EQ(item.Type(), InlineItem::kText);
  if (!item.Length()) {
    // Fully collapsed spaces don't have break opportunities.
    context.AppendTrailingSpaces(
        item_result.can_break_after ? LineBreakCandidateContext::kBreak
                                    : context.GetState(),
        {item_result.item_index, item.EndOffset()}, context.Position());
    context.SetLast(&item, item.EndOffset());
    return;
  }

  DCHECK(item.TextShapeResult());
  struct ShapeResultWrapper {
    STACK_ALLOCATED();

   public:
    explicit ShapeResultWrapper(const ShapeResult* shape_result)
        : shape_result(shape_result),
          shape_result_start_index(shape_result->StartIndex()),
          is_ltr(shape_result->IsLtr()) {
      shape_result->EnsurePositionData();
    }

    bool IsLtr() const { return is_ltr; }

    // The returned position is in the external coordinate system set by
    // `SetBasePosition`, not the internal one of the `ShapeResult`.
    float PositionForOffset(unsigned offset) const {
      DCHECK_GE(offset, shape_result_start_index);
      const float position = shape_result->CachedPositionForOffset(
          offset - shape_result_start_index);
      return IsLtr() ? base_position + position : base_position - position;
    }

    // Adjusts the internal coordinate system of the `ShapeResult` to the
    // specified one.
    void SetBasePosition(wtf_size_t offset, float adjusted) {
      DCHECK_GE(offset, shape_result_start_index);
      const float position = shape_result->CachedPositionForOffset(
          offset - shape_result_start_index);
      base_position = IsLtr() ? adjusted - position : adjusted + position;
      DCHECK_EQ(adjusted, PositionForOffset(offset));
    }

    unsigned PreviousSafeToBreakOffset(unsigned offset) const {
      // Unlike `PositionForOffset`, `PreviousSafeToBreakOffset` takes the
      // "external" offset that takes care of `StartIndex()`.
      return shape_result->CachedPreviousSafeToBreakOffset(offset);
    }

    const ShapeResult* const shape_result;
    const wtf_size_t shape_result_start_index;
    float base_position = .0f;
    const bool is_ltr;
  } shape_result(item.TextShapeResult());
  const String& text_content = Text();

  // Extend the end offset to the end of the item or the end of this line,
  // whichever earlier. This is not only for performance but also to include
  // trailing spaces that may be removed by the line breaker.
  TextOffsetRange offset = item_result.TextOffset();
  offset.end = std::max(offset.end,
                        std::min(item.EndOffset(), line_info.EndTextOffset()));

  // Extend the start offset to `context.last_end_offset`. Trailing spaces may
  // be skipped, or leading spaces may be already handled.
  if (context.LastItem()) {
    DCHECK_GE(context.LastEndOffset(), item.StartOffset());
    if (context.LastEndOffset() >= offset.end) {
      return;  // Return if all characters were already handled.
    }
    offset.start = context.LastEndOffset();
    offset.AssertNotEmpty();
    shape_result.SetBasePosition(offset.start, context.Position());

    // Handle leading/trailing spaces if they were skipped.
    if (IsBreakableSpace(text_content[offset.start])) {
      DCHECK_GE(offset.start, item.StartOffset());
      do {
        ++offset.start;
      } while (offset.start < offset.end &&
               IsBreakableSpace(text_content[offset.start]));
      const float end_position = shape_result.PositionForOffset(offset.start);
      if (!offset.Length()) {
        context.AppendTrailingSpaces(item_result.can_break_after
                                         ? LineBreakCandidateContext::kBreak
                                         : LineBreakCandidateContext::kMidWord,
                                     {item_index, offset.start}, end_position);
        context.SetLast(&item, offset.end);
        return;
      }
      context.AppendTrailingSpaces(auto_wrap_
                                       ? LineBreakCandidateContext::kBreak
                                       : LineBreakCandidateContext::kMidWord,
                                   {item_index, offset.start}, end_position);
    }
  } else {
    shape_result.SetBasePosition(offset.start, context.Position());
  }
  offset.AssertNotEmpty();
  DCHECK_GE(offset.start, item.StartOffset());
  DCHECK_GE(offset.start, context.LastEndOffset());
  DCHECK_LE(offset.end, item.EndOffset());
  context.SetLast(&item, offset.end);

  // Setup the style and its derived fields for this `item`.
  if (offset.start < break_iterator_.StartOffset()) {
    break_iterator_.SetStartOffset(offset.start);
  }
  DCHECK(item.Style());
  SetCurrentStyle(*item.Style());

  // Find all break opportunities in `item_result`.
  std::optional<LayoutUnit> hyphen_advance_cache;
  for (;;) {
    // Compute the offset of the next break opportunity.
    wtf_size_t next_offset;
    if (auto_wrap_) {
      const wtf_size_t len = std::min(offset.end + 1, text_content.length());
      next_offset = break_iterator_.NextBreakOpportunity(offset.start + 1, len);
    } else {
      next_offset = offset.end + 1;
    }
    if (next_offset > offset.end && item_result.can_break_after) {
      // If `can_break_after`, honor it over `next_offset`. CSS can allow the
      // break at the end. E.g., fast/inline/line-break-atomic-inline.html
      next_offset = offset.end;
    }

    // Compute the position of the break opportunity and the end of the word.
    wtf_size_t end_offset;
    float next_position;
    float end_position;
    LineBreakCandidateContext::State next_state =
        LineBreakCandidateContext::kBreak;
    float penalty = 0;
    bool is_hyphenated = false;
    if (next_offset > offset.end) {
      // If the next break opportunity is beyond this item, stop at the end of
      // this item and set `is_middle_word`.
      end_offset = next_offset = offset.end;
      end_position = next_position =
          shape_result.PositionForOffset(next_offset);
      next_state = LineBreakCandidateContext::kMidWord;
    } else {
      if (next_offset == offset.end && !item_result.can_break_after) {
        // Can't break at `next_offset` by higher level protocols.
        // E.g., `<span>1 </span>2`.
        next_state = LineBreakCandidateContext::kMidWord;
      }
      next_position = shape_result.PositionForOffset(next_offset);

      // Exclude trailing spaces if any.
      end_offset = next_offset;
      DCHECK_GT(end_offset, offset.start);
      UChar last_ch = text_content[end_offset - 1];
      while (IsBreakableSpace(last_ch)) {
        --end_offset;
        if (end_offset == offset.start) {
          last_ch = 0;
          break;
        }
        last_ch = text_content[end_offset - 1];
      }
      DCHECK_LE(end_offset, offset.end);

      if (hyphenation_) [[unlikely]] {
        const LayoutUnit hyphen_advance =
            HyphenAdvance(*current_style_, shape_result.IsLtr(),
                          item_result.hyphen, hyphen_advance_cache);
        DCHECK_GT(end_offset, offset.start);
        const wtf_size_t word_len = end_offset - offset.start;
        const StringView word(text_content, offset.start, word_len);
        Vector<wtf_size_t, 8> locations = hyphenation_->HyphenLocations(word);
        // |locations| is a list of hyphenation points in the descending order.
#if EXPENSIVE_DCHECKS_ARE_ON()
        DCHECK(!locations.Contains(0u));
        DCHECK(!locations.Contains(word_len));
        DCHECK(std::is_sorted(locations.rbegin(), locations.rend()));
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
        const float hyphen_penalty = context.HyphenPenalty();
        InlineItemTextIndex hyphen_offset = {item_index, 0};
        for (const wtf_size_t location : base::Reversed(locations)) {
          hyphen_offset.text_offset = offset.start + location;
          const float position =
              shape_result.PositionForOffset(hyphen_offset.text_offset);
          context.Append(LineBreakCandidateContext::kBreak, hyphen_offset,
                         hyphen_offset, position, position + hyphen_advance,
                         hyphen_penalty,
                         /*is_hyphenated*/ true);
        }
      }

      // Compute the end position of this word, excluding trailing spaces.
      wtf_size_t end_safe_offset;
      switch (next_state) {
        case LineBreakCandidateContext::kBreak:
          end_safe_offset = shape_result.PreviousSafeToBreakOffset(end_offset);
          if (end_safe_offset < offset.start) {
            DCHECK_EQ(context.Candidates().back().offset.text_offset,
                      offset.start);
            end_safe_offset = offset.start;
          }
          break;
        case LineBreakCandidateContext::kMidWord:
          end_safe_offset = end_offset;
          break;
      }
      if (end_safe_offset == end_offset) {
        if (end_offset == next_offset) {
          end_position = next_position;
        } else {
          end_position = shape_result.PositionForOffset(end_offset);
        }
      } else {
        DCHECK_LT(end_safe_offset, end_offset);
        end_position = shape_result.PositionForOffset(end_safe_offset);
        const ShapeResult* end_shape_result =
            ShapeText(item, end_safe_offset, end_offset);
        end_position += end_shape_result->Width();
      }

      DCHECK(!is_hyphenated);
      if (end_offset == item_result.EndOffset()) {
        is_hyphenated = item_result.is_hyphenated;
      } else if (last_ch == kSoftHyphenCharacter &&
                 next_state == LineBreakCandidateContext::kBreak) [[unlikely]] {
        is_hyphenated = true;
      }
      if (is_hyphenated) {
        end_position += HyphenAdvance(*current_style_, shape_result.IsLtr(),
                                      item_result.hyphen, hyphen_advance_cache);
        penalty = context.HyphenPenalty();
      }
    }

    context.Append(next_state, {item_index, next_offset},
                   {item_index, end_offset}, next_position, end_position,
                   penalty, is_hyphenated);
    if (next_offset >= offset.end) {
      break;
    }
    offset.start = next_offset;
  }
}

bool LineBreaker::CanBreakInside(const LineInfo& line_info) {
  const InlineItemResults& item_results = line_info.Results();
  for (const InlineItemResult& item_result :
       base::make_span(item_results.begin(), item_results.size() - 1)) {
    if (item_result.can_break_after) {
      return true;
    }
  }
  for (const InlineItemResult& item_result : item_results) {
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;
    if (item.Type() == InlineItem::kText) {
      if (item_result.may_break_inside && CanBreakInside(item_result)) {
        return true;
      }
    }
  }
  return false;
}

bool LineBreaker::CanBreakInside(const InlineItemResult& item_result) {
  DCHECK(item_result.may_break_inside);
  DCHECK(item_result.item);
  const InlineItem& item = *item_result.item;
  DCHECK_EQ(item.Type(), InlineItem::kText);
  DCHECK(item.Style());
  SetCurrentStyle(*item.Style());
  if (!auto_wrap_) {
    return false;
  }
  const TextOffsetRange& offset = item_result.TextOffset();
  if (offset.start < break_iterator_.StartOffset()) {
    break_iterator_.SetStartOffset(offset.start);
  }
  const wtf_size_t next_offset =
      break_iterator_.NextBreakOpportunity(offset.start + 1);
  return next_offset < offset.end;
}

// Compute a new ShapeResult for the specified end offset.
// The end is re-shaped if it is not safe-to-break.
const ShapeResultView* LineBreaker::TruncateLineEndResult(
    const LineInfo& line_info,
    const InlineItemResult& item_result,
    unsigned end_offset) {
  DCHECK(item_result.item);
  const InlineItem& item = *item_result.item;

  // Check given offsets require to truncate |item_result.shape_result|.
  const unsigned start_offset = item_result.StartOffset();
  const ShapeResultView* source_result = item_result.shape_result.Get();
  DCHECK(source_result);
  DCHECK_GE(start_offset, source_result->StartIndex());
  DCHECK_LE(end_offset, source_result->EndIndex());
  DCHECK(start_offset > source_result->StartIndex() ||
         end_offset < source_result->EndIndex());

  if (!NeedsAccurateEndPosition(line_info, item)) {
    return ShapeResultView::Create(source_result, start_offset, end_offset);
  }

  unsigned last_safe = source_result->PreviousSafeToBreakOffset(end_offset);
  DCHECK_LE(last_safe, end_offset);
  // TODO(abotella): Shouldn't last_safe <= start_offset trigger a reshaping?
  if (last_safe == end_offset || last_safe <= start_offset) {
    return ShapeResultView::Create(source_result, start_offset, end_offset);
  }

  const ShapeResult* end_result =
      ShapeText(item, std::max(last_safe, start_offset), end_offset);
  DCHECK_EQ(end_result->Direction(), source_result->Direction());
  ShapeResultView::Segment segments[2];
  segments[0] = {source_result, start_offset, last_safe};
  segments[1] = {end_result, 0, end_offset};
  return ShapeResultView::Create(segments);
}

// Update |ShapeResult| in |item_result| to match to its |start_offset| and
// |end_offset|. The end is re-shaped if it is not safe-to-break.
void LineBreaker::UpdateShapeResult(const LineInfo& line_info,
                                    InlineItemResult* item_result) {
  DCHECK(item_result);
  item_result->shape_result =
      TruncateLineEndResult(line_info, *item_result, item_result->EndOffset());
  DCHECK(item_result->shape_result);
  item_result->inline_size = item_result->shape_result->SnappedWidth();
}

inline void LineBreaker::HandleTrailingSpaces(const InlineItem& item,
                                              LineInfo* line_info) {
  const ShapeResult* shape_result = item.TextShapeResult();
  // Call |HandleTrailingSpaces| even if |item| does not have |ShapeResult|, so
  // that we skip spaces.
  HandleTrailingSpaces(item, shape_result, line_info);
}

void LineBreaker::HandleTrailingSpaces(const InlineItem& item,
                                       const ShapeResult* shape_result,
                                       LineInfo* line_info) {
  DCHECK(item.Type() == InlineItem::kText ||
         (item.Type() == InlineItem::kControl &&
          Text()[item.StartOffset()] == kTabulationCharacter));
  bool is_control_tab = item.Type() == InlineItem::kControl &&
                        Text()[item.StartOffset()] == kTabulationCharacter;
  DCHECK(item.Type() == InlineItem::kText || is_control_tab);
  DCHECK_GE(current_.text_offset, item.StartOffset());
  DCHECK_LT(current_.text_offset, item.EndOffset());
  const String& text = Text();
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();

  if (!auto_wrap_) {
    state_ = LineBreakState::kDone;
    return;
  }
  DCHECK(!is_text_combine_);

  if (style.ShouldCollapseWhiteSpaces() &&
      !Character::IsOtherSpaceSeparator(text[current_.text_offset])) {
    if (text[current_.text_offset] != kSpaceCharacter) {
      if (current_.text_offset > 0 &&
          IsBreakableSpace(text[current_.text_offset - 1])) {
        trailing_whitespace_ = WhitespaceState::kCollapsible;
      }
      state_ = LineBreakState::kDone;
      return;
    }

    // Skipping one whitespace removes all collapsible spaces because
    // collapsible spaces are collapsed to single space in InlineItemBuilder.
    current_.text_offset++;
    trailing_whitespace_ = WhitespaceState::kCollapsed;

    // Make the last item breakable after, even if it was nowrap.
    InlineItemResults* item_results = line_info->MutableResults();
    DCHECK(!item_results->empty());
    item_results->back().can_break_after = true;
  } else if (!style.ShouldBreakSpaces()) {
    // Find the end of the run of space characters in this item.
    // Other white space characters (e.g., tab) are not included in this item.
    DCHECK(style.ShouldBreakOnlyAfterWhiteSpace() ||
           Character::IsOtherSpaceSeparator(text[current_.text_offset]));
    unsigned end = current_.text_offset;
    while (end < item.EndOffset() &&
           IsBreakableSpaceOrOtherSeparator(text[end]))
      end++;
    if (end == current_.text_offset) {
      if (IsBreakableSpaceOrOtherSeparator(text[end - 1]))
        trailing_whitespace_ = WhitespaceState::kPreserved;
      state_ = LineBreakState::kDone;
      return;
    }

    // TODO (jfernandez): Could we just modify the last ItemResult
    // instead of creating a new one ?
    // Probably we can (koji). We would need to review usage of these
    // item results, and change them to use "non_hangable_run_end"
    // instead.
    DCHECK(shape_result);
    InlineItemResult* item_result = AddItem(item, end, line_info);
    item_result->should_create_line_box = true;
    item_result->has_only_pre_wrap_trailing_spaces = true;
    item_result->has_only_bidi_trailing_spaces = true;
    item_result->shape_result = ShapeResultView::Create(shape_result);
    if (item_result->StartOffset() == item.StartOffset() &&
        item_result->EndOffset() == item.EndOffset()) {
      item_result->inline_size =
          item_result->shape_result && mode_ != LineBreakerMode::kMinContent
              ? item_result->shape_result->SnappedWidth()
              : LayoutUnit();
    } else {
      UpdateShapeResult(*line_info, item_result);
      if (mode_ == LineBreakerMode::kMinContent) {
        item_result->inline_size = LayoutUnit();
      }
    }
    position_ += item_result->inline_size;
    item_result->can_break_after =
        end < text.length() && !IsBreakableSpaceOrOtherSeparator(text[end]);
    current_.text_offset = end;
    trailing_whitespace_ = WhitespaceState::kPreserved;
  }

  // If non-space characters follow, the line is done.
  // Otherwise keep checking next items for the break point.
  DCHECK_LE(current_.text_offset, item.EndOffset());
  if (current_.text_offset < item.EndOffset()) {
    state_ = LineBreakState::kDone;
    return;
  }
  DCHECK_EQ(current_.text_offset, item.EndOffset());
  const InlineItemResults& item_results = line_info->Results();
  if (item_results.empty() || item_results.back().item != &item) {
    // If at the end of `item` but the item hasn't been added to `line_info`,
    // add an empty text item. See `HandleEmptyText`.
    AddEmptyItem(item, line_info);
  }
  current_.item_index++;
  state_ = LineBreakState::kTrailing;
}

void LineBreaker::RewindTrailingOpenTags(LineInfo* line_info) {
  // Remove trailing open tags. Open tags are included as trailable items
  // because they are ambiguous. When the line ends, and if the end of line has
  // open tags, they are not trailable.
  // TODO(crbug.com/1009936): Open tags and trailing space items can interleave,
  // but the current code supports only one trailing space item. Multiple
  // trailing space items and interleaved open/close tags should be supported.
  const InlineItemResults& item_results = line_info->Results();
  for (const InlineItemResult& item_result : base::Reversed(item_results)) {
    DCHECK(item_result.item);
    if (item_result.item->Type() != InlineItem::kOpenTag) {
      unsigned end_index =
          base::checked_cast<unsigned>(&item_result - item_results.data() + 1);
      if (end_index < item_results.size()) {
        const InlineItemResult& end_item_result = item_results[end_index];
        const InlineItemTextIndex end = end_item_result.Start();
        ResetRewindLoopDetector();
        Rewind(end_index, line_info);
        current_ = end;
        items_data_->AssertOffset(current_.item_index, current_.text_offset);
      }
      break;
    }
  }
}

// Remove trailing collapsible spaces in |line_info|.
// https://drafts.csswg.org/css-text-3/#white-space-phase-2
void LineBreaker::RemoveTrailingCollapsibleSpace(LineInfo* line_info) {
  // Rewind trailing open-tags to wrap before them, except when this line ends
  // with a forced break, including the one implied by block-in-inline.
  if (!is_forced_break_) {
    RewindTrailingOpenTags(line_info);
  }

  ComputeTrailingCollapsibleSpace(line_info);
  if (!trailing_collapsible_space_.has_value()) {
    return;
  }

  // W
"""


```