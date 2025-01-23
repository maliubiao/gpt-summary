Response:
The user wants a summary of the functionality of the `LineBreaker` class in the provided C++ code. I need to extract the core responsibilities of this class and explain how it interacts with web technologies like JavaScript, HTML, and CSS. I should also analyze the provided code snippets for any logical deductions, potential user errors, and provide concrete examples where relevant. Finally, I need to synthesize this information into a concise summary, noting that this is the final part of a larger explanation.

Here's a breakdown of the steps:

1. **Identify Core Functionalities:**  Analyze the method names and the logic within them to determine the main tasks of the `LineBreaker`.
2. **Relate to Web Technologies:** Explain how the `LineBreaker`'s actions are driven by and influence JavaScript, HTML, and CSS. Provide specific examples.
3. **Logical Reasoning with Examples:**  Find instances of conditional logic and explain the assumed input and predicted output.
4. **Common Usage Errors:** Identify potential mistakes developers might make that could lead to unexpected behavior related to line breaking.
5. **Synthesize Summary:** Condense the findings from the previous steps into a clear and concise summary of the `LineBreaker`'s purpose.
这是 `blink/renderer/core/layout/inline/line_breaker.cc` 文件中 `LineBreaker` 类的部分代码，主要负责在布局过程中，决定如何在行内元素中进行断行。这是第六部分，也是最后一部分代码，因此我们应该能从中看到一些收尾和总结性的操作。

**功能归纳：**

这段代码主要处理在断行过程中遇到**无法找到合适的断点并需要回溯 (rewind)** 的情况，以及在一些特定场景下**重试断行**的逻辑。它还包含了一些设置和管理 `LineBreaker` 状态的辅助功能。

具体来说，这段代码实现了以下功能：

1. **回溯 (Rewind) 机制：**
   -  当当前位置无法断行时，`Rewind` 函数会将断行位置回退到之前的一个可能断点。
   -  它会根据不同的情况（例如：是否包含连字符、是否是 Ruby 元素）来决定回退的策略。
   -  在回溯过程中会考虑浮动元素 (floats)，避免不必要的回溯，提高效率。
   -  为了防止无限回溯循环，代码中包含了检测机制。
   -  回溯会更新 `LineBreaker` 的内部状态，例如当前位置 (`current_`)、已处理的项 (`item_results`)、当前样式 (`current_style_`) 等。

2. **重试断行 (RetryAfterOverflow)：**
   -  当断行失败并溢出时，`RetryAfterOverflow` 函数会重置 `LineBreaker` 的状态，并尝试使用不同的断行策略进行重试。
   -  例如，如果第一次尝试使用了基于短语的断行 (`LineBreakType::kPhrase`) 但失败了，可以禁用短语断行并使用普通的断行规则重试。
   -  或者，当 `overflow-wrap: anywhere` 属性生效时，如果发生溢出，会强制允许在任何位置断行并重试。

3. **处理尾随空格 (RewindOverflow)：**
   - `RewindOverflow` 函数在回溯时，会检查回退点之后是否存在可以被视为尾随的元素（例如空格、某些控制字符、闭合标签等）。
   - 如果存在尾随元素，这些元素可以被留在当前行，而无需回溯到它们之前。这有助于优化断行结果。

4. **计算和设置当前样式 (ComputeCurrentStyle, SetCurrentStyle, SetCurrentStyleForce)：**
   - `ComputeCurrentStyle` 函数用于在回溯时，根据指定索引的元素计算其适用的样式。
   - `SetCurrentStyle` 和 `SetCurrentStyleForce` 函数用于更新 `LineBreaker` 的当前样式，并根据新的样式更新内部状态，例如是否自动换行 (`auto_wrap_`)、断词迭代器 (`break_iterator_`) 的配置等。

5. **管理 `LineBreaker` 状态：**
   - 代码中维护了 `state_` 变量，用于表示 `LineBreaker` 的当前状态（例如：`kTrailing` 表示可以添加尾随空格，`kOverflow` 表示溢出等）。
   -  通过设置和检查 `state_`，可以控制断行的流程。

6. **创建断行标记 (CreateBreakToken)：**
   - `CreateBreakToken` 函数在断行完成时创建 `InlineBreakToken` 对象，用于记录断行的信息，例如断点位置、样式、是否是强制断行等。这个标记会被用于后续的布局和渲染过程。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML:** `LineBreaker` 处理的文本内容和元素结构直接来源于 HTML。HTML 标签定义了行内元素的边界和类型，这些信息被 `LineBreaker` 用于判断断行的时机和位置。例如，`<span>`、`<a>`、`<img>` 等不同的行内元素会有不同的断行特性。
   - **例子:**  当遇到 `<b>加粗文字</b>` 时，`LineBreaker` 会将 `<b>` 和 `</b>` 视为独立的 inline item，并根据其周围的文本和样式来决定是否需要断行。

- **CSS:** CSS 样式是驱动 `LineBreaker` 行为的关键。以下 CSS 属性会直接影响断行：
    - `word-break`:  决定单词内部是否可以断行。
        - **例子:** 当 `word-break: break-all;` 时，即使单词很长，`LineBreaker` 也会强制在允许的位置断开。
        - **假设输入:**  一个很长的英文单词 "antidisestablishmentarianism" 在一个宽度有限的容器中。
        - **输出:** 如果没有设置 `word-break: break-all;`，可能会溢出。设置后，`LineBreaker` 会在单词内部断开，以适应容器宽度。
    - `overflow-wrap` (或 `word-wrap`):  决定当一个单词过长无法放入一行时是否允许断开。
        - **例子:**  当 `overflow-wrap: anywhere;` 时，即使没有显式的空格或连字符，`LineBreaker` 也会在必要时断开单词。
        - **用户常见错误:**  开发者可能会忘记设置 `overflow-wrap`，导致过长的单词溢出容器。
    - `white-space`:  影响如何处理空格和换行符。
        - **例子:** 当 `white-space: nowrap;` 时，`LineBreaker` 不会进行自动换行。
    - `hyphens`:  控制是否使用连字符连接断开的单词。
        - **例子:** 当 `hyphens: auto;` 时，`LineBreaker` 会尝试在合适的音节处使用连字符断开单词。
    - `line-break`:  定义了断行的严格程度。
        - **例子:** `line-break: anywhere;` 允许在任何字符之间断行。
    - `text-indent`:  首行文本缩进。代码中处理了当只有首行缩进和浮动元素时，回溯缩进的情况。
    - 字体相关的属性 (font-family, font-size 等) 也会影响文本的宽度，从而间接影响断行。

- **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式，从而间接影响 `LineBreaker` 的行为。例如，通过 JavaScript 改变元素的文本内容或样式，会导致重新布局，`LineBreaker` 会根据新的内容和样式重新进行断行。
    - **例子:**  一个 JavaScript 脚本动态地向一个 `<div>` 元素中添加了很长的文本内容，或者修改了该元素的 `word-break` 属性。这将触发 `LineBreaker` 重新计算断行。

**逻辑推理举例：**

在 `RewindOverflow` 函数中，有一段处理尾随空格的逻辑：

```c++
    if (item_result.Type() == InlineItem::kText) {
      // Text items are trailable if they start with trailable spaces.
      if (!item_result.Length()) {
        // Empty text items are trailable, see `HandleEmptyText`.
        continue;
      }
      if (item_result.shape_result ||  // kNoResultIfOverflow if 'break-word'
          (break_anywhere_if_overflow_ && !override_break_anywhere_)) {
        DCHECK(item.Style());
        const ComputedStyle& style = *item.Style();
        if (style.ShouldWrapLine() && !style.ShouldBreakSpaces() &&
            IsBreakableSpace(text[item_result.StartOffset()])) {
          // If all characters are trailable spaces, check the next item.
          if (item_result.shape_result &&
              IsAllBreakableSpaces(text, item_result.StartOffset() + 1,
                                   item_result.EndOffset())) {
            continue;
          }
          // If this item starts with spaces followed by non-space characters,
          // the line should break after the spaces. Rewind to before this item.
          //
          // After the rewind, we want to |HandleTrailingSpaces| in this |item|,
          // but |Rewind| may have failed when we have floats. Set the |state_|
          // to |kTrailing| and let the next |HandleText| to handle this.
          state_ = LineBreakState::kTrailing;
          Rewind(index, line_info);
          return;
        }
      }
    }
```

- **假设输入:**  当前回溯到某个位置，并且该位置之后是一个文本 inline item，其内容为 "   abc"。
- **逻辑推理:** 代码会检查该文本项是否以可断行的空格开始 (`IsBreakableSpace`)。如果满足条件，则会设置 `state_` 为 `kTrailing` 并回溯到该文本项之前。
- **输出:**  `LineBreaker` 将会认为这些前导空格是可尾随的，并可能将它们留在上一行，然后在 "abc" 之前断行。

**用户或编程常见的使用错误举例：**

1. **忘记处理长单词溢出:** 开发者可能没有考虑到内容中会出现非常长的、没有空格或连字符的单词，导致在宽度有限的容器中发生溢出。
   - **错误:**  容器宽度固定，内容为 "Thisisaverylongwordwithoutanyspaces." 且未设置 `overflow-wrap` 或 `word-break`。
   - **结果:**  该单词会超出容器的边界。

2. **过度依赖默认断行行为:** 开发者可能没有意识到不同浏览器或不同语言的断行规则可能存在差异，导致在某些情况下出现不期望的断行结果。
   - **错误:**  假设所有浏览器对中文的断行行为都一致，但实际上某些旧版本浏览器可能存在差异。
   - **结果:**  在某些浏览器上，中文文本可能在不合适的位置断开。

3. **与 `white-space` 属性冲突:**  开发者可能设置了 `white-space: nowrap;` 阻止换行，但又期望文本能够根据容器宽度自动换行。
   - **错误:**  设置了 `white-space: nowrap;` 但容器宽度有限，内容很长。
   - **结果:**  文本不会换行，而是会超出容器边界。

这段代码是 `LineBreaker` 核心逻辑的一部分，专注于处理断行过程中的复杂情况，确保文本能够尽可能合理地分布在不同的行中，同时考虑到各种 CSS 属性的影响。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
te_ = LineBreakState::kTrailing;
          Rewind(new_end, line_info);
          return;
        }

        // Failed to break to fit. Restore to the original state.
        if (HasHyphen()) [[unlikely]] {
          RemoveHyphen(item_results);
        }
        *item_result = std::move(item_result_before);
        SetCurrentStyle(*was_current_style);
      }
    } else if (item_result->IsRubyColumn()) {
      // If space is available, and if this ruby column is breakable, part of
      // the ruby column may fit. Try to break this item.
      if (width_to_rewind < 0 && item_result->may_break_inside) {
        const auto& rewound_ruby_column = *item_result->ruby_column;
        const LineInfo& base_line = rewound_ruby_column.base_line;
        Rewind(i, line_info);
        HandleRuby(line_info, base_line.Width());
        const LineInfo& new_base_line =
            line_info->Results().back().ruby_column->base_line;
        LayoutUnit new_width = new_base_line.Width();
        if (new_width > LayoutUnit() && new_width != base_line.Width()) {
          // We succeeded to shorten the ruby column.
          state_ = LineBreakState::kDone;
          return;
        } else if (i == 0 && new_base_line.GetBreakToken()) {
          // We couldn't shorten the ruby column and can't rewind more.
          // We accept this result.
          state_ = LineBreakState::kDone;
          return;
        }
      }
    }
  }

  if (applied_text_indent_ && width_to_rewind > LayoutUnit() &&
      is_first_formatted_line_ && !leading_floats_.floats.empty() &&
      RuntimeEnabledFeatures::LineBoxBelowLeadingFloatsEnabled()) {
    // If there is no inflow content and there are only leading floats, also
    // rewind text indentation. The idea here is that text-indent alone
    // shouldn't contribute to overflow (and it doesn't even belong on this
    // line, since we've rewound past everything else), so that we won't attempt
    // to place inline content in the layout opportunity below the floats, but
    // rather create a "line" with just the leading floats, and then another
    // line for any real inline content.
    //
    // This matters for block fragmentation. If there's one line box with both
    // leading floats and a real inline content below them, the fragmentation
    // engine has no means of inserting a fragmentation break between the float
    // and the inline content, since lines are monolithic.
    position_ -= applied_text_indent_;
    width_to_rewind -= applied_text_indent_;
    applied_text_indent_ = LayoutUnit();
    if (width_to_rewind <= LayoutUnit()) {
      state_ = LineBreakState::kDone;
      return;
    }
  }

  // Reaching here means that the rewind point was not found.

  if (break_iterator_.BreakType() == LineBreakType::kPhrase &&
      !disable_phrase_ && mode_ == LineBreakerMode::kContent) {
    // If the phrase line break overflowed, retry with the normal line break.
    disable_phrase_ = true;
    RetryAfterOverflow(line_info, item_results);
    return;
  }

  if (!override_break_anywhere_ && has_break_anywhere_if_overflow) {
    // Overflow occurred but `overflow-wrap` is set. Change the break type and
    // retry the line breaking.
    override_break_anywhere_ = true;
    RetryAfterOverflow(line_info, item_results);
    return;
  }

  // Let this line overflow.
  line_info->SetHasOverflow();

  // TODO(kojii): `ScoreLineBreaker::ComputeScores` gets confused if there're
  // overflowing lines. Disable the score line break for now. E.g.:
  //   css2.1/t1601-c547-indent-01-d.html
  //   virtual/text-antialias/international/bdi-neutral-wrapped.html
  disable_score_line_break_ = true;
  // The bisect line breaker doesn't support overflowing content.
  disable_bisect_line_break_ = true;

  // Restore the hyphenation states to before the loop if needed.
  DCHECK(!HasHyphen());
  if (hyphen_index_before) [[unlikely]] {
    position_ += AddHyphen(item_results, *hyphen_index_before);
  }

  // If there was a break opportunity, the overflow should stop there.
  if (break_before) {
    RewindOverflow(break_before, line_info);
    return;
  }

  if (CanBreakAfterLast(*item_results)) {
    state_ = LineBreakState::kTrailing;
    return;
  }

  // No break opportunities. Break at the earliest break opportunity.
  DCHECK(base::ranges::all_of(*item_results,
                              [](const InlineItemResult& item_result) {
                                return !item_result.can_break_after;
                              }));
  state_ = LineBreakState::kOverflow;
}

void LineBreaker::RetryAfterOverflow(LineInfo* line_info,
                                     InlineItemResults* item_results) {
  // `ScoreLineBreaker` doesn't support multi-pass line breaking.
  disable_score_line_break_ = true;
  // The bisect line breaker doesn't support multi-pass line breaking.
  disable_bisect_line_break_ = true;

  state_ = LineBreakState::kContinue;

  // Rewind all items.
  //
  // Also `SetCurrentStyle` forcibly, because the retry uses different
  // conditions such as `override_break_anywhere_`.
  //
  // TODO(kojii): Not all items need to rewind, but such case is rare and
  // rewinding all items simplifes the code.
  if (!item_results->empty()) {
    SetCurrentStyleForce(ComputeCurrentStyle(0, line_info));
    Rewind(0, line_info);
  } else {
    SetCurrentStyleForce(*current_style_);
  }
  ResetRewindLoopDetector();
}

// Rewind to |new_end| on overflow. If trailable items follow at |new_end|, they
// are included (not rewound).
void LineBreaker::RewindOverflow(unsigned new_end, LineInfo* line_info) {
  const InlineItemResults& item_results = line_info->Results();
  DCHECK_LT(new_end, item_results.size());

  unsigned open_tag_count = 0;
  const String& text = Text();
  for (unsigned index = new_end; index < item_results.size(); index++) {
    const InlineItemResult& item_result = item_results[index];
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;
    if (item.Type() == InlineItem::kText) {
      // Text items are trailable if they start with trailable spaces.
      if (!item_result.Length()) {
        // Empty text items are trailable, see `HandleEmptyText`.
        continue;
      }
      if (item_result.shape_result ||  // kNoResultIfOverflow if 'break-word'
          (break_anywhere_if_overflow_ && !override_break_anywhere_)) {
        DCHECK(item.Style());
        const ComputedStyle& style = *item.Style();
        if (style.ShouldWrapLine() && !style.ShouldBreakSpaces() &&
            IsBreakableSpace(text[item_result.StartOffset()])) {
          // If all characters are trailable spaces, check the next item.
          if (item_result.shape_result &&
              IsAllBreakableSpaces(text, item_result.StartOffset() + 1,
                                   item_result.EndOffset())) {
            continue;
          }
          // If this item starts with spaces followed by non-space characters,
          // the line should break after the spaces. Rewind to before this item.
          //
          // After the rewind, we want to |HandleTrailingSpaces| in this |item|,
          // but |Rewind| may have failed when we have floats. Set the |state_|
          // to |kTrailing| and let the next |HandleText| to handle this.
          state_ = LineBreakState::kTrailing;
          Rewind(index, line_info);
          return;
        }
      }
    } else if (item.Type() == InlineItem::kControl) {
      // All control characters except newline are trailable if auto_wrap. We
      // should not have rewound if there was a newline, so safe to assume all
      // controls are trailable.
      DCHECK_NE(text[item_result.StartOffset()], kNewlineCharacter);
      DCHECK(item.Style());
      const ComputedStyle& style = *item.Style();
      if (style.ShouldWrapLine() && !style.ShouldBreakSpaces()) {
        continue;
      }
    } else if (item.Type() == InlineItem::kOpenTag) {
      // Open tags are ambiguous. This open tag is not trailable:
      //   <span>text
      // but these are trailable:
      //   <span> text
      //   <span></span>text
      //   <span> </span>text
      // Count the nest-level and mark where the nest-level was 0.
      if (!open_tag_count)
        new_end = index;
      open_tag_count++;
      continue;
    } else if (item.Type() == InlineItem::kCloseTag) {
      if (open_tag_count > 0)
        open_tag_count--;
      continue;
    } else if (IsTrailableItemType(item.Type())) {
      continue;
    }

    // Found a non-trailable item. Rewind to before the item, or to before the
    // open tag if the nest-level is not zero.
    if (open_tag_count)
      index = new_end;
    state_ = LineBreakState::kDone;
    DCHECK(!line_info->IsLastLine());
    Rewind(index, line_info);
    return;
  }

  // The open tag turned out to be non-trailable if the nest-level is not zero.
  // Rewind to before the open tag.
  if (open_tag_count) {
    state_ = LineBreakState::kDone;
    DCHECK(!line_info->IsLastLine());
    Rewind(new_end, line_info);
    return;
  }

  // All items are trailable. Done without rewinding.
  trailing_whitespace_ = WhitespaceState::kUnknown;
  position_ = line_info->ComputeWidth();
  state_ = LineBreakState::kDone;
  DCHECK(!line_info->IsLastLine());
  if (IsAtEnd()) {
    line_info->SetIsLastLine(true);
  }
}

void LineBreaker::Rewind(unsigned new_end, LineInfo* line_info) {
  InlineItemResults& item_results = *line_info->MutableResults();
  DCHECK_LT(new_end, item_results.size());
  if (last_rewind_) {
    // Detect rewind-loop. If we're trying to rewind to the same index twice,
    // we're in the infinite loop.
    if (current_.item_index == last_rewind_->from_item_index &&
        new_end == last_rewind_->to_index) {
      NOTREACHED();
    }
    last_rewind_.emplace(RewindIndex{current_.item_index, new_end});
  }

  // Check if floats are being rewound.
  if (RuntimeEnabledFeatures::RewindFloatsEnabled()) {
    RewindFloats(new_end, *line_info, item_results);
  } else {
    // The code and comments in this `else` block is obsolete when
    // `RewindFloatsEnabled` is enabled, and will be removed when the flag
    // didn't hit any web-compat issues. See crbug.com/1499290 and its CLs for
    // more details.

    // Avoid rewinding floats if possible. They will be added back anyway while
    // processing trailing items even when zero available width. Also this saves
    // most cases where our support for rewinding positioned floats is not great
    // yet (see below.)
    while (item_results[new_end].item->Type() == InlineItem::kFloating) {
      // We assume floats can break after, or this may cause an infinite loop.
      DCHECK(item_results[new_end].can_break_after);
      ++new_end;
      if (new_end == item_results.size()) {
        if (!hyphen_index_ && has_any_hyphens_) [[unlikely]] {
          RestoreLastHyphen(&item_results);
        }
        position_ = line_info->ComputeWidth();
        return;
      }
    }

    // Because floats are added to |positioned_floats_| or
    // |unpositioned_floats_|, rewinding them needs to remove from these lists
    // too.
    for (unsigned i = item_results.size(); i > new_end;) {
      InlineItemResult& rewind = item_results[--i];
      if (rewind.positioned_float) {
        // We assume floats can break after, or this may cause an infinite loop.
        DCHECK(rewind.can_break_after);
        // TODO(kojii): We do not have mechanism to remove once positioned
        // floats yet, and that rewinding them may lay it out twice. For now,
        // prohibit rewinding positioned floats. This may results in incorrect
        // layout, but still better than rewinding them.
        new_end = i + 1;
        if (new_end == item_results.size()) {
          if (!hyphen_index_ && has_any_hyphens_) [[unlikely]] {
            RestoreLastHyphen(&item_results);
          }
          position_ = line_info->ComputeWidth();
          return;
        }
        break;
      }
    }
  }

  if (new_end) {
    // Use |results[new_end - 1].end_offset| because it may have been truncated
    // and may not be equal to |results[new_end].start_offset|.
    MoveToNextOf(item_results[new_end - 1]);
    trailing_whitespace_ = WhitespaceState::kUnknown;
    // When space item is followed by empty text, we will break line at empty
    // text. See http://crbug.com/1104534
    // Example:
    //   [0] kOpeNTag 0-0 <i>
    //   [1] kText 0-10 "012345679"
    //   [2] kOpenTag 10-10 <b> <= |item_results[new_end - 1]|
    //   [3] kText 10-10 ""     <= |current_.item_index|
    //   [4] kText 10-11 " "
    //   [5] kCloseTag 11-11 <b>
    //   [6] kText 11-13 "ab"
    //   [7] kCloseTag 13-13 <i>
    // Note: We can have multiple empty |LayoutText| by ::first-letter, nested
    // <q>, Text.splitText(), etc.
    const HeapVector<InlineItem>& items = Items();
    while (!IsAtEnd() &&
           items[current_.item_index].Type() == InlineItem::kText &&
           !items[current_.item_index].Length()) {
      HandleEmptyText(items[current_.item_index], line_info);
    }
  } else {
    // Rewinding all items.
    current_ = line_info->Start();
    if (!item_results.empty() && item_results.front().IsRubyColumn()) {
      ruby_break_token_ =
          item_results.front().ruby_column->start_ruby_break_token;
    }
    trailing_whitespace_ = WhitespaceState::kLeading;
    maybe_have_end_overhang_ = false;
  }
  SetCurrentStyle(ComputeCurrentStyle(new_end, line_info));

  item_results.Shrink(new_end);

  trailing_collapsible_space_.reset();
  if (hyphen_index_ && *hyphen_index_ >= new_end) [[unlikely]] {
    hyphen_index_.reset();
  }
  if (!hyphen_index_ && has_any_hyphens_) [[unlikely]] {
    RestoreLastHyphen(&item_results);
  }
  position_ = line_info->ComputeWidth();
  if (has_cloned_box_decorations_) [[unlikely]] {
    RecalcClonedBoxDecorations();
  }
}

// Returns the style to use for |item_result_index|. Normally when handling
// items sequentially, the current style is updated on open/close tag. When
// rewinding, this function computes the style for the specified item.
const ComputedStyle& LineBreaker::ComputeCurrentStyle(
    unsigned item_result_index,
    LineInfo* line_info) const {
  const InlineItemResults& item_results = line_info->Results();

  // Use the current item if it can compute the current style.
  const InlineItem* item = item_results[item_result_index].item;
  DCHECK(item);
  if (item->Type() == InlineItem::kText ||
      item->Type() == InlineItem::kCloseTag) {
    DCHECK(item->Style());
    return *item->Style();
  }

  // Otherwise look back an item that can compute the current style.
  while (item_result_index) {
    item = item_results[--item_result_index].item;
    if (item->Type() == InlineItem::kText ||
        item->Type() == InlineItem::kOpenTag) {
      DCHECK(item->Style());
      return *item->Style();
    }
    if (item->Type() == InlineItem::kCloseTag) {
      return item->GetLayoutObject()->Parent()->StyleRef();
    }
  }

  // Use the style at the beginning of the line if no items are available.
  if (break_token_ && break_token_->Style())
    return *break_token_->Style();
  return line_info->LineStyle();
}

void LineBreaker::SetCurrentStyle(const ComputedStyle& style) {
  if (&style == current_style_) {
#if EXPENSIVE_DCHECKS_ARE_ON()
    // Check that cache fields are already setup correctly.
    DCHECK_EQ(auto_wrap_, ShouldAutoWrap(style));
    if (auto_wrap_) {
      DCHECK_EQ(break_iterator_.IsSoftHyphenEnabled(),
                style.GetHyphens() != Hyphens::kNone &&
                    (disable_phrase_ ||
                     style.WordBreak() != EWordBreak::kAutoPhrase));
      DCHECK_EQ(break_iterator_.Locale(), style.GetFontDescription().Locale());
    }
    ShapeResultSpacing<String> spacing(spacing_.Text(), is_svg_text_);
    spacing.SetSpacing(style.GetFont().GetFontDescription());
    DCHECK_EQ(spacing.LetterSpacing(), spacing_.LetterSpacing());
    DCHECK_EQ(spacing.WordSpacing(), spacing_.WordSpacing());
#endif  //  EXPENSIVE_DCHECKS_ARE_ON()
    return;
  }
  SetCurrentStyleForce(style);
}

void LineBreaker::SetCurrentStyleForce(const ComputedStyle& style) {
  current_style_ = &style;

  const FontDescription& font_description = style.GetFontDescription();
  spacing_.SetSpacing(font_description);

  auto_wrap_ = ShouldAutoWrap(style);
  if (auto_wrap_) {
    DCHECK(!is_text_combine_);
    break_iterator_.SetLocale(font_description.Locale());
    Hyphens hyphens = style.GetHyphens();
    const LineBreak line_break = style.GetLineBreak();
    if (line_break == LineBreak::kAnywhere) [[unlikely]] {
      break_iterator_.SetStrictness(LineBreakStrictness::kDefault);
      break_iterator_.SetBreakType(LineBreakType::kBreakCharacter);
      break_anywhere_if_overflow_ = false;
    } else {
      break_iterator_.SetStrictness(StrictnessFromLineBreak(line_break));
      LineBreakType line_break_type;
      switch (style.WordBreak()) {
        case EWordBreak::kNormal:
          line_break_type = LineBreakType::kNormal;
          break_anywhere_if_overflow_ = false;
          break;
        case EWordBreak::kBreakAll:
          line_break_type = LineBreakType::kBreakAll;
          break_anywhere_if_overflow_ = false;
          break;
        case EWordBreak::kBreakWord:
          line_break_type = LineBreakType::kNormal;
          break_anywhere_if_overflow_ = true;
          break;
        case EWordBreak::kKeepAll:
          line_break_type = LineBreakType::kKeepAll;
          break_anywhere_if_overflow_ = false;
          break;
        case EWordBreak::kAutoPhrase:
          if (disable_phrase_) [[unlikely]] {
            line_break_type = LineBreakType::kNormal;
          } else {
            line_break_type = LineBreakType::kPhrase;
            hyphens = Hyphens::kNone;
            UseCounter::Count(GetDocument(), WebFeature::kLineBreakPhrase);
          }
          break_anywhere_if_overflow_ = false;
          break;
      }
      if (!break_anywhere_if_overflow_) {
        // `overflow-wrap: anywhere` affects both layout and min-content, while
        // `break-word` affects layout but not min-content.
        const EOverflowWrap overflow_wrap = style.OverflowWrap();
        break_anywhere_if_overflow_ =
            overflow_wrap == EOverflowWrap::kAnywhere ||
            (overflow_wrap == EOverflowWrap::kBreakWord &&
             mode_ == LineBreakerMode::kContent);
      }
      if (break_anywhere_if_overflow_) [[unlikely]] {
        if (override_break_anywhere_) [[unlikely]] {
          line_break_type = LineBreakType::kBreakCharacter;
        } else if (mode_ == LineBreakerMode::kMinContent) [[unlikely]] {
          override_break_anywhere_ = true;
          line_break_type = LineBreakType::kBreakCharacter;
        }
      }
      break_iterator_.SetBreakType(line_break_type);
    }

    if (hyphens == Hyphens::kNone) [[unlikely]] {
      break_iterator_.EnableSoftHyphen(false);
      hyphenation_ = nullptr;
    } else {
      break_iterator_.EnableSoftHyphen(true);
      hyphenation_ = style.GetHyphenationWithLimits();
    }

    if (style.ShouldBreakSpaces()) {
      break_iterator_.SetBreakSpace(BreakSpaceType::kAfterEverySpace);
      disable_score_line_break_ = true;
    } else {
      break_iterator_.SetBreakSpace(BreakSpaceType::kAfterSpaceRun);
    }
  }
}

bool LineBreaker::IsPreviousItemOfType(InlineItem::InlineItemType type) {
  return current_.item_index > 0
             ? Items().at(current_.item_index - 1).Type() == type
             : false;
}

void LineBreaker::MoveToNextOf(const InlineItem& item) {
  current_.text_offset = item.EndOffset();
  current_.item_index++;
#if DCHECK_IS_ON()
  const HeapVector<InlineItem>& items = Items();
  if (current_.item_index < items.size()) {
    items[current_.item_index].AssertOffset(current_.text_offset);
  } else {
    DCHECK_EQ(current_.text_offset, Text().length());
  }
#endif
}

void LineBreaker::MoveToNextOf(const InlineItemResult& item_result) {
  current_ = item_result.End();
  DCHECK(item_result.item);
  if (current_.text_offset == item_result.item->EndOffset()) {
    current_.item_index++;
  }
}

void LineBreaker::SetInputRange(InlineItemTextIndex start,
                                wtf_size_t end_item_index,
                                WhitespaceState initial_whitespace_state,
                                const LineBreaker* parent) {
  current_ = start;
  end_item_index_ = end_item_index;
  initial_whitespace_ = initial_whitespace_state;
  parent_breaker_ = parent;
}

const InlineBreakToken* LineBreaker::CreateBreakToken(
    const LineInfo& line_info) {
#if DCHECK_IS_ON()
  DCHECK(!has_considered_creating_break_token_);
  has_considered_creating_break_token_ = true;
#endif

  DCHECK(current_style_);
  const HeapVector<InlineItem>& items = Items();
  DCHECK_LE(current_.item_index, items.size());
  // If we have reached the end, create no break token.
  if (IsAtEnd()) {
    return nullptr;
  }

  const BlockBreakToken* sub_break_token = nullptr;
  if (resume_block_in_inline_in_same_flow_) {
    const auto* block_in_inline = line_info.BlockInInlineLayoutResult();
    DCHECK(block_in_inline);
    if (block_in_inline->Status() != LayoutResult::kSuccess) [[unlikely]] {
      return nullptr;
    }
    // Look for a break token inside the block-in-inline, so that we can add it
    // to the inline break token that we're about to create.
    const auto& block_in_inline_fragment =
        To<PhysicalBoxFragment>(block_in_inline->GetPhysicalFragment());
    sub_break_token = block_in_inline_fragment.GetBreakToken();
  }

  bool is_past_first_formatted_line =
      !is_first_formatted_line_ || !line_info.IsEmptyLine();

  DCHECK_EQ(line_info.HasForcedBreak(), is_forced_break_);
  unsigned flags =
      (is_forced_break_ ? InlineBreakToken::kIsForcedBreak : 0) |
      (line_info.UseFirstLineStyle() ? InlineBreakToken::kUseFirstLineStyle
                                     : 0) |
      (cloned_box_decorations_count_
           ? InlineBreakToken::kHasClonedBoxDecorations
           : 0) |
      (is_past_first_formatted_line
           ? InlineBreakToken::kIsPastFirstFormattedLine
           : 0);

  return InlineBreakToken::Create(node_, current_style_, current_, flags,
                                  sub_break_token, ruby_break_token_);
}

}  // namespace blink
```