Response:
The user wants a summary of the functionality of the `line_breaker.cc` file, which is part of the Chromium Blink rendering engine. I need to identify the main purpose of this code and how it relates to web page rendering. Specifically, I need to explain its connection to Javascript, HTML, and CSS, providing examples. I should also look for logic that involves assumptions about input and output, and highlight potential user or programming errors related to this code.

Here's a breakdown of the process:

1. **Identify the Core Functionality:** Based on the file name and the code snippets, the primary function is clearly **line breaking**. This involves deciding where to wrap lines of text within a given width.

2. **Relate to Web Technologies:**
    * **HTML:**  The text being broken comes from the HTML content. The structure of the HTML (e.g., inline vs. block elements) influences line breaking.
    * **CSS:** CSS properties like `width`, `word-wrap`, `white-space`, `text-align`, and hyphenation directly control how line breaking occurs. Floats also influence line layout.
    * **JavaScript:** While the core line breaking logic is in C++, JavaScript can indirectly affect it by manipulating the HTML content or CSS styles.

3. **Analyze Logic and Assumptions (Input/Output):** The code contains various conditional checks and state management. A key aspect is the `LineInfo` structure which accumulates information about the current line. Assumptions are made about the input being a sequence of `InlineItem`s. The output is the set of `InlineItemResult`s for a line, indicating where items start and end on that line.

4. **Identify Potential Errors:** Common issues relate to how users expect text to wrap, especially with whitespace, long words, and the interaction of different CSS properties. Programming errors could arise from incorrect state management or handling edge cases.

5. **Structure the Summary:**  Organize the information into clear sections covering the core functionality, relationships to web technologies, logic/assumptions, and potential errors. Provide concrete examples for each.

6. **Address the "Part 2 of 6" Request:**  Acknowledge this and focus the summary on the content provided in this specific snippet, while keeping in mind the overall context of line breaking.

**Specific Observations from the Code Snippet:**

* **`LineBreaker` Class:**  This is the central class responsible for the line breaking process.
* **`NextLine` Method:**  This method is responsible for generating the next line of text.
* **`BreakLine` Method:** This is the core logic for determining where to break the current line. It iterates through `InlineItem`s.
* **`LineInfo`:** This structure holds information about the current line being built, including the start and end indices of items, width, and offsets.
* **`InlineItem` and `InlineItemResult`:** These represent the elements being laid out and the results of their placement on a line, respectively.
* **Handling Different `InlineItem` Types:** The code has specific logic for different types of inline elements (text, controls, floats, blocks, ruby, etc.).
* **Whitespace Handling:**  There's logic for collapsing and preserving whitespace.
* **Hyphenation:** The code includes support for hyphenating words.
* **Overflow:**  The code deals with situations where content doesn't fit on a line.
* **`break_at_`:** This seems to be a mechanism for forcing a break at a specific point, likely for testing or specific layout requirements.
* **`LineBreakState`:** This enum manages the current state of the line breaking process.

By considering these observations, I can construct a comprehensive summary of the provided code.
这是`blink/renderer/core/layout/inline/line_breaker.cc`文件的第二部分代码，其核心功能是**实现文本的断行（line breaking）逻辑**。  它负责决定如何在给定的可用宽度内将一系列的内联元素（Inline Items）排列成一行，并在必要时进行换行。

基于这段代码，我们可以归纳出以下具体功能：

**1. 初始化和准备下一行 (`NextLine`)**

*   `PrepareNextLine(line_info)`:  在开始处理新的一行之前进行必要的准备工作。
*   处理块级内联元素 (`break_token_->IsInParallelBlockFlow()`)：如果遇到溢出的块级内联元素（例如，在内联上下文中的 `<div>`），会调用 `HandleBlockInInline` 或 `HandleFloat` 来处理，并将状态设置为完成当前行 (`kDone`)，表示这一行只包含这个块级内联元素。
*   `BreakLine(line_info)`: 调用核心的断行逻辑来填充 `line_info`。
*   处理连字符 (`HasHyphen()`)：如果在断行过程中添加了连字符，调用 `FinalizeHyphen` 进行最终处理。
*   处理尾随空白 (`RemoveTrailingCollapsibleSpace`, `SplitTrailingBidiPreservedSpace`):  根据 CSS 规则移除或分割行尾的空白字符。
*   检查一致性 (`result.CheckConsistency`)：在调试模式下，检查 `InlineItemResult` 的一致性。
*   决定是否创建行框 (`ShouldCreateLineBox`)：根据是否存在需要行框的元素（文本等）、列表标记的位置、以及是否处于最小/最大内容尺寸计算模式来决定是否需要为当前行创建行框。
*   设置行尾信息 (`SetEndItemIndex`, `SetHasTrailingSpaces`)：记录当前行的最后一个元素的索引，并标记是否存在尾随空格。
*   处理覆盖的可用宽度 (`override_available_width_`)：如果可用宽度被临时覆盖，则恢复原始值。
*   计算行位置 (`ComputeLineLocation`)：根据可用宽度和当前位置计算行的最终位置。
*   处理 Ruby 注音 (`ruby_break_token_`)：如果当前行有 Ruby 注音，则记录 Ruby 注音的结束标记。
*   创建断点标记 (`CreateBreakToken`)：在内容模式下，为当前行创建一个断点标记，用于后续的断行操作。
*   调试断点 (`break_at_`)：在调试模式下，如果设置了 `break_at_`，会检查实际的断行位置是否符合预期。

**2. 核心断行逻辑 (`BreakLine`)**

*   处理 Ruby 注音 (`HandleRuby`)：如果存在 Ruby 注音，会调用 `HandleRuby` 进行处理。
*   处理行尾 (`IsAtEnd()`)：如果到达了内容的末尾，则标记当前行为最后一行，并返回。
*   根据 `break_at_` 断行：如果设置了 `break_at_`，并且当前位置超过或等于 `break_at_.offset`，则停止断行。
*   处理溢出 (`state_ == LineBreakState::kOverflow`)：如果前一个元素的处理导致溢出，并且可以在最后一个元素后断行，则将状态设置为 `kTrailing`。
*   循环处理内联元素：根据 `current_.item_index` 遍历 `InlineItem` 列表。
*   针对不同类型的 `InlineItem` 调用相应的处理函数：
    *   `HandleText`: 处理文本内容。
    *   `HandleEmptyText`: 处理空文本节点。
    *   `HandleOpenTag`, `HandleCloseTag`: 处理 HTML 标签的开始和结束。
    *   `HandleControlItem`: 处理控制字符（如换行符）。
    *   `HandleFloat`: 处理浮动元素。
    *   `HandleBidiControlItem`: 处理双向文本控制字符。
    *   `HandleBlockInInline`: 处理块级内联元素。
    *   `AddItem`:  将元素添加到当前行。
    *   `HandleAtomicInline`: 处理原子内联元素（例如 `<img>`）。
    *   `HandleInitialLetter`: 处理首字母下沉。
    *   `HandleOpenRubyColumn`, `HandleCloseRubyColumn`, `HandleRubyLinePlaceholder`: 处理 Ruby 注音相关的元素。
    *   `HandleOutOfFlowPositioned`: 处理脱离文档流定位的元素。
    *   `HandleListMarker`: 处理列表标记，并强制如果这是最后一行则不为空行。
*   处理尾随状态 (`state_ == LineBreakState::kTrailing`)：如果状态为尾随，则在遇到任何不可尾随的元素之前断行。

**3. 计算行位置 (`ComputeLineLocation`)**

*   设置行的宽度 (`SetWidth`)：根据可用宽度和已占据的位置计算行的宽度。
*   设置 BFC 偏移 (`SetBfcOffset`)：设置块格式化上下文（BFC）的偏移量。
*   更新文本对齐 (`UpdateTextAlign`)：在内容模式下，更新行的文本对齐方式。

**4. 判断断行机会 (`CanBreakAfterAtomicInline`, `CanBreakAfter`)**

*   `CanBreakAfterAtomicInline`:  判断原子内联元素后是否可以断行，会考虑 `sticky_images_quirk_` 这个特殊的兼容性处理。对于 `text-combine` 元素有特殊的处理。
*   `CanBreakAfter`: 判断普通内联元素后是否可以断行，依赖于断行迭代器 (`break_iterator_`)。对于控制字符和 Ruby 注音相关的字符有特殊的处理。对于 `text-combine` 元素有特殊的处理。

**5. 辅助函数和判断 (`MayBeAtomicInline`, `TryGetAtomicInlineItemAfter`, `IgnorableBidiControlLength`)**

*   `MayBeAtomicInline`: 判断给定偏移位置是否可能是一个原子内联元素。
*   `TryGetAtomicInlineItemAfter`: 尝试获取给定 `InlineItem` 之后的原子内联元素。
*   `IgnorableBidiControlLength`: 计算可以忽略的双向文本控制字符的长度。

**6. 处理文本 (`HandleText`)**

*   处理尾随空格 (`state_ == LineBreakState::kTrailing`)：如果处于尾随状态，只处理尾随的空格。
*   跳过前导可折叠空格 (`trailing_whitespace_ == WhitespaceState::kLeading`)：如果遇到前导的可折叠空格，则跳过。
*   处理溢出 (`state_ == LineBreakState::kContinue && !CanFitOnLine()`)：如果当前行无法容纳当前元素，则调用 `HandleOverflow` 处理溢出情况。
*   移除连字符 (`HasHyphen()`)：如果在处理文本前存在连字符，则移除。
*   提交悬挂结束 (`maybe_have_end_overhang_`)：处理可能的末端悬挂。
*   添加 `InlineItemResult`: 将当前处理的文本片段添加到当前行的结果中。
*   调用 `BreakText` 尝试在文本内部断行（如果 `auto_wrap_` 为 true）。
*   处理 SVG 文本 (`is_svg_text_`)：调用 `SplitTextIntoSegments` 处理 SVG 文本的分割。
*   处理非自动换行的情况：如果 `auto_wrap_` 为 false，则将整个文本项添加到当前行。

**7. 分割 SVG 文本 (`SplitTextIntoSegments`, `ShouldCreateNewSvgSegment`)**

*   `SplitTextIntoSegments`:  根据 SVG 的 `x`, `y`, `dx`, `dy`, `rotate` 属性将 SVG 文本分割成不同的段落。
*   `ShouldCreateNewSvgSegment`: 判断是否需要创建一个新的 SVG 文本段落。

**8. 文本断行核心逻辑 (`BreakText`, `BreakTextAt`)**

*   `BreakText`:  使用 `ShapingLineBreaker` 类来实际进行文本的排版和断行。它会尝试在给定的可用宽度内放置尽可能多的文本，并考虑连字符的情况。
*   `BreakTextAt`:  当设置了 `break_at_` 时，强制在指定的位置断行。

**与 Javascript, HTML, CSS 的关系：**

*   **HTML:** `LineBreaker` 处理的是从 HTML 文档解析出来的内联元素。例如，`<span>` 标签包裹的文本会被解析成 `InlineItem::kText` 类型的元素，`<img>` 标签会被解析成 `InlineItem::kAtomicInline` 类型的元素。
    *   **例子:**  HTML 代码 `<p>This is a <span>long</span> text.</p>` 中的 "long" 会被识别为一个 `InlineItem::kText`。
*   **CSS:** CSS 样式属性直接影响 `LineBreaker` 的断行行为。
    *   `width`:  决定了 `LineBreaker` 的可用宽度。
        *   **例子:**  CSS `p { width: 200px; }` 会告诉 `LineBreaker` 在 200 像素的宽度内进行断行。
    *   `white-space`:  影响空白字符的处理和是否允许换行。
        *   **例子:**  CSS `pre { white-space: pre-wrap; }` 会使 `LineBreaker` 保留空白并允许在必要时换行。
    *   `word-wrap` 或 `overflow-wrap`:  决定是否在单词内部断行以避免溢出。
        *   **例子:**  CSS `p { overflow-wrap: break-word; }` 会指示 `LineBreaker` 在长单词无法放下时进行断字。
    *   `text-align`:  影响行内内容的对齐方式（在 `ComputeLineLocation` 中体现）。
        *   **例子:**  CSS `div { text-align: center; }` 会影响 `LineInfo::UpdateTextAlign()` 的计算。
    *   `hyphens`:  控制是否以及如何进行连字符连接。
        *   **例子:**  CSS `p { hyphens: auto; }` 会触发 `LineBreaker` 中的连字符处理逻辑。
    *   `float`: 浮动元素的存在会影响可用宽度和断行位置。
        *   **例子:**  CSS `img { float: left; }` 会使文本环绕图片，`LineBreaker` 需要处理这种布局。
*   **Javascript:** Javascript 可以动态修改 HTML 结构和 CSS 样式，从而间接地影响 `LineBreaker` 的行为。
    *   **例子:** Javascript 可以通过 `element.style.width = '300px'` 来改变元素的宽度，导致 `LineBreaker` 重新进行断行计算。

**逻辑推理的假设输入与输出：**

假设输入一系列的 `InlineItem` 对象，例如：

```
InlineItem[0]: type=kText, start=0, end=5, text="Hello"
InlineItem[1]: type=kControl, start=5, end=6, text=" "
InlineItem[2]: type=kText, start=6, end=11, text="World"
```

并且假设可用宽度足够放下 "Hello"，但不足以放下 "Hello World"。

**预期输出（第一行）：**

```
LineInfo:
  start_item_index: 0
  end_item_index: 1  // 断在 "Hello " 之后
  width:  ... (等于 "Hello " 的宽度)
  results:
    InlineItemResult[0]: item=InlineItem[0], start_offset=0, end_offset=5, inline_size=...
    InlineItemResult[1]: item=InlineItem[1], start_offset=5, end_offset=6, inline_size=...
```

**预期输出（第二行）：**

```
LineInfo:
  start_item_index: 2
  end_item_index: 3
  width: ... (等于 "World" 的宽度)
  results:
    InlineItemResult[0]: item=InlineItem[2], start_offset=6, end_offset=11, inline_size=...
```

**用户或编程常见的使用错误：**

1. **CSS 属性冲突导致意外断行:** 用户可能会设置相互冲突的 CSS 属性，导致 `LineBreaker` 按照不期望的方式断行。
    *   **例子:**  同时设置了 `white-space: nowrap;` 和 `overflow-wrap: break-word;`，可能会导致在极长单词的情况下才断行，而不是在容器边缘就断行。
2. **错误理解空白处理:** 用户可能不理解 CSS 的空白处理规则，导致对行尾或行首空白的显示感到困惑。
    *   **例子:**  在 HTML 中输入多个空格，期望在页面上显示多个空格，但由于默认的空白折叠规则，只会显示一个空格。
3. **忘记处理长单词溢出:**  如果没有设置 `overflow-wrap: break-word;`，过长的单词可能会超出容器的边界。
    *   **例子:**  一个很长的 URL 或没有空格的字符串可能会导致水平滚动条出现。
4. **在 Javascript 中错误地操作 DOM 导致断行异常:**  不恰当的 Javascript DOM 操作可能会破坏 `InlineItem` 的结构，导致 `LineBreaker` 出现意想不到的行为。
    *   **例子:**  在 `LineBreaker` 正在计算布局时，Javascript 移除了一个包含文本的节点。
5. **对 Ruby 注音布局的误解:** 用户可能不理解 Ruby 注音的布局规则，导致对注音的显示位置感到困惑。

总而言之，这段代码是 Blink 渲染引擎中负责将内联内容排列成行的关键部分，它深入地与 HTML 的结构和 CSS 的样式属性交互，以确定最终的文本布局。理解其功能有助于开发者更好地理解浏览器的排版行为，并避免常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
_count_) [[unlikely]] {
    RecalcClonedBoxDecorations();
  }

  ResetRewindLoopDetector();
#if DCHECK_IS_ON()
  has_considered_creating_break_token_ = false;
#endif
}

void LineBreaker::NextLine(LineInfo* line_info) {
  PrepareNextLine(line_info);

  if (break_token_ && break_token_->IsInParallelBlockFlow()) {
    const auto* block_break_token = break_token_->GetBlockBreakToken();
    DCHECK(block_break_token);
    const InlineItem& item = Items()[break_token_->StartItemIndex()];
    DCHECK_EQ(item.GetLayoutObject(),
              block_break_token->InputNode().GetLayoutBox());
    if (block_break_token->InputNode().IsFloating()) {
      HandleFloat(item, block_break_token, line_info);
    } else {
      // Overflowed block-in-inline, i.e. in a parallel flow.
      DCHECK_EQ(item.Type(), InlineItem::kBlockInInline);
      HandleBlockInInline(item, block_break_token, line_info);
    }

    state_ = LineBreakState::kDone;
    line_info->SetIsEmptyLine();
    return;
  }

  BreakLine(line_info);

  if (HasHyphen()) [[unlikely]] {
    FinalizeHyphen(line_info->MutableResults());
  }
  if (!disable_trailing_whitespace_collapsing_) {
    RemoveTrailingCollapsibleSpace(line_info);
    SplitTrailingBidiPreservedSpace(line_info);
  }

  const InlineItemResults& item_results = line_info->Results();
#if DCHECK_IS_ON()
  for (const auto& result : item_results)
    result.CheckConsistency(mode_ == LineBreakerMode::kMinContent);
#endif

  // We should create a line-box when:
  //  - We have an item which needs a line box (text, etc).
  //  - A list-marker is present, and it would be the last line or last line
  //    before a forced new-line.
  //  - During min/max content sizing (to correctly determine the line width).
  //
  // TODO(kojii): There are cases where we need to PlaceItems() without creating
  // line boxes. These cases need to be reviewed.
  const bool should_create_line_box =
      ShouldCreateLineBox(item_results) ||
      (force_non_empty_if_last_line_ && line_info->IsLastLine()) ||
      mode_ != LineBreakerMode::kContent;

  if (!should_create_line_box) {
    if (To<LayoutBlockFlow>(node_.GetLayoutBox())->HasLineIfEmpty())
      line_info->SetHasLineEvenIfEmpty();
    else
      line_info->SetIsEmptyLine();
  }

  line_info->SetEndItemIndex(current_.item_index);
  if (!disable_trailing_whitespace_collapsing_) {
    DCHECK_NE(trailing_whitespace_, WhitespaceState::kUnknown);
    if (trailing_whitespace_ == WhitespaceState::kPreserved) {
      line_info->SetHasTrailingSpaces();
    }
  }

  if (override_available_width_) [[unlikely]] {
    // Clear the overridden available width so that `line_info` has the original
    // available width for aligning.
    override_available_width_ = LayoutUnit();
    UpdateAvailableWidth();
  }
  ComputeLineLocation(line_info);
  DCHECK(!ruby_break_token_);
  const InlineItemResults& results = line_info->Results();
  if (!results.empty() && results.back().IsRubyColumn()) {
    ruby_break_token_ = results.back().ruby_column->end_ruby_break_token;
  }
  if (mode_ == LineBreakerMode::kContent) {
    line_info->SetBreakToken(CreateBreakToken(*line_info));
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  if (break_at_) [[unlikely]] {
    // If `break_at_` is set, the line should break `break_at_.offset`, but due
    // to minor differences in trailing spaces, it may not match exactly. It
    // should at least be beyond `break_at_.end`.
    DCHECK_GE(line_info->End(), break_at_.end);
  }
#endif  // EXPENSIVE_DCHECKS_ARE_ON()
}

void LineBreaker::BreakLine(LineInfo* line_info) {
  DCHECK(!line_info->IsLastLine());
  const HeapVector<InlineItem>& items = Items();
  // If `kMinContent`, the line will overflow. Avoid calling `HandleOverflow()`
  // for the performance.
  if (mode_ == LineBreakerMode::kMinContent) [[unlikely]] {
    state_ = LineBreakState::kOverflow;
  } else {
    state_ = LineBreakState::kContinue;
  }
  trailing_whitespace_ = initial_whitespace_;

  while (state_ != LineBreakState::kDone) {
    if (ruby_break_token_) {
      HandleRuby(line_info);
      HandleOverflowIfNeeded(line_info);
      continue;
    }

    // If we reach at the end of the block, this is the last line.
    DCHECK_LE(current_.item_index, items.size());
    if (IsAtEnd()) {
      // Still check overflow because the last item may have overflowed.
      if (HandleOverflowIfNeeded(line_info) && !IsAtEnd()) {
        continue;
      }
      if (HasHyphen()) [[unlikely]] {
        position_ -= RemoveHyphen(line_info->MutableResults());
      }
      line_info->SetIsLastLine(true);
      return;
    }
    if (break_at_ && current_ >= break_at_.offset) [[unlikely]] {
      return;
    }

    // If |state_| is overflow, break at the earliest break opportunity.
    const InlineItemResults& item_results = line_info->Results();
    if (state_ == LineBreakState::kOverflow && CanBreakAfterLast(item_results))
        [[unlikely]] {
      state_ = LineBreakState::kTrailing;
    }

    // Handle trailable items first. These items may not be break before.
    // They (or part of them) may also overhang the available width.
    const InlineItem& item = items[current_.item_index];
    if (item.Type() == InlineItem::kText) {
      if (item.Length())
        HandleText(item, *item.TextShapeResult(), line_info);
      else
        HandleEmptyText(item, line_info);
#if DCHECK_IS_ON()
      if (!item_results.empty())
        item_results.back().CheckConsistency(true);
#endif
      continue;
    }
    if (item.Type() == InlineItem::kOpenTag) {
      HandleOpenTag(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kCloseTag) {
      HandleCloseTag(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kControl) {
      HandleControlItem(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kFloating) {
      HandleFloat(item, /* float_break_token */ nullptr, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kBidiControl) {
      HandleBidiControlItem(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kBlockInInline) {
      const BlockBreakToken* block_break_token =
          break_token_ ? break_token_->GetBlockBreakToken() : nullptr;
      HandleBlockInInline(item, block_break_token, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kCloseRubyColumn ||
        item.Type() == InlineItem::kRubyLinePlaceholder) {
      AddItem(item, line_info);
      MoveToNextOf(item);
      continue;
    }

    // Items after this point are not trailable. If we're trailing, break before
    // any non-trailable items
    DCHECK(!IsTrailableItemType(item.Type()));
    if (state_ == LineBreakState::kTrailing) {
      DCHECK(!line_info->IsLastLine());
      return;
    }

    if (item.Type() == InlineItem::kAtomicInline) {
      HandleAtomicInline(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kInitialLetterBox) [[unlikely]] {
      HandleInitialLetter(item, line_info);
      continue;
    }
    if (item.Type() == InlineItem::kOpenRubyColumn) {
      // Skip to call HandleRuby() for a placeholder-only ruby column.
      const wtf_size_t i = current_.item_index;
      if (items[i + 1].Type() == InlineItem::kRubyLinePlaceholder &&
          (items[i + 2].Type() == InlineItem::kCloseRubyColumn ||
           (items[i + 2].Type() == InlineItem::kRubyLinePlaceholder &&
            items[i + 3].Type() == InlineItem::kCloseRubyColumn))) {
        AddItem(item, line_info);
        MoveToNextOf(item);
        continue;
      }
      if (!HandleRuby(line_info)) {
        AddItem(item, line_info);
        MoveToNextOf(item);
      }
      HandleOverflowIfNeeded(line_info);
      continue;
    }
    if (item.Type() == InlineItem::kOutOfFlowPositioned) {
      HandleOutOfFlowPositioned(item, line_info);
    } else if (item.Length()) {
      NOTREACHED();
    } else if (item.Type() == InlineItem::kListMarker) {
      InlineItemResult* item_result = AddItem(item, line_info);
      force_non_empty_if_last_line_ = true;
      DCHECK(!item_result->can_break_after);
      MoveToNextOf(item);
    } else {
      NOTREACHED();
    }
  }
}

void LineBreaker::ComputeLineLocation(LineInfo* line_info) const {
  // Negative margins can make the position negative, but the inline size is
  // always positive or 0.
  LayoutUnit available_width = AvailableWidth();
  line_info->SetWidth(available_width,
                      position_ + cloned_box_decorations_end_size_);
  line_info->SetBfcOffset(
      {line_opportunity_.line_left_offset, line_opportunity_.bfc_block_offset});
  if (mode_ == LineBreakerMode::kContent) {
    line_info->UpdateTextAlign();
  }
}

// Atomic inlines have break opportunities before and after, even when the
// adjacent character is U+00A0 NO-BREAK SPACE character, except when sticky
// images quirk is applied.
// Note: We treat text combine as text content instead of atomic inline box[1].
// [1] https://drafts.csswg.org/css-writing-modes-3/#text-combine-layout
bool LineBreaker::CanBreakAfterAtomicInline(const InlineItem& item) const {
  DCHECK(item.Type() == InlineItem::kAtomicInline ||
         item.Type() == InlineItem::kInitialLetterBox);
  if (!auto_wrap_) {
    return false;
  }
  if (item.EndOffset() == Text().length()) {
    return true;
  }
  // We can not break before sticky images quirk was applied.
  if (item.IsImage())
    return !sticky_images_quirk_;

  // Handles text combine
  // See "fast/writing-mode/text-combine-line-break.html".
  auto* const text_combine = MayBeTextCombine(&item);
  if (!text_combine) [[likely]] {
    return true;
  }

  // Populate |text_content| with |item| and text content after |item|.
  StringBuilder text_content;
  InlineNode(text_combine).PrepareLayoutIfNeeded();
  text_content.Append(text_combine->GetTextContent());
  const auto text_combine_end_offset = text_content.length();
  auto* const atomic_inline_item = TryGetAtomicInlineItemAfter(item);
  if (auto* next_text_combine = MayBeTextCombine(atomic_inline_item)) {
    // Note: In |LineBreakerMode::k{Min,Max}Content|, we've not laid
    // out atomic line box yet.
    InlineNode(next_text_combine).PrepareLayoutIfNeeded();
    text_content.Append(next_text_combine->GetTextContent());
  } else {
    text_content.Append(StringView(Text(), item.EndOffset(),
                                   Text().length() - item.EndOffset()));
  }

  DCHECK_EQ(Text(), break_iterator_.GetString());
  LazyLineBreakIterator break_iterator(break_iterator_,
                                       text_content.ReleaseString());
  return break_iterator.IsBreakable(text_combine_end_offset);
}

bool LineBreaker::CanBreakAfter(const InlineItem& item) const {
  DCHECK_NE(item.Type(), InlineItem::kAtomicInline);
  DCHECK(auto_wrap_);
  const bool can_break_after = break_iterator_.IsBreakable(item.EndOffset());
  if (item.Type() != InlineItem::kText) {
    DCHECK_EQ(item.Type(), InlineItem::kControl) << "We get the test case!";
    // Example: <div>12345\t\t678</div>
    //  InlineItem[0] kText "12345"
    //  InlineItem[1] kControl "\t\t"
    //  InlineItem[2] kText "678"
    // See LineBreakerTest.OverflowTab
    return can_break_after;
  }
  // Bidi controls produced by kOpenRubyColumn/kCloseRubyColumn are ignorable.
  unsigned ignorable_bidi_length = IgnorableBidiControlLength(item);
  if (ignorable_bidi_length > 0u) {
    return break_iterator_.IsBreakable(item.EndOffset() +
                                       ignorable_bidi_length);
  }
  auto* const atomic_inline_item = TryGetAtomicInlineItemAfter(item);
  if (!atomic_inline_item)
    return can_break_after;

  // We can not break before sticky images quirk was applied.
  if (Text()[atomic_inline_item->StartOffset()] == kNoBreakSpaceCharacter)
      [[unlikely]] {
    // "One " <img> => We can break after "One ".
    // "One" <img> => We can not break after "One".
    // See "tables/mozilla/bugs/bug101674.html"
    DCHECK(atomic_inline_item->IsImage() && sticky_images_quirk_);
    return can_break_after;
  }

  // Handles text combine as its text contents followed by |item|.
  // See "fast/writing-mode/text-combine-line-break.html".
  auto* const text_combine = MayBeTextCombine(atomic_inline_item);
  if (!text_combine) [[likely]] {
    return true;
  }

  // Populate |text_content| with |item| and |text_combine|.
  // Following test reach here:
  //  * fast/writing-mode/text-combine-compress.html
  //  * virtual/text-antialias/international/text-combine-image-test.html
  //  * virtual/text-antialias/international/text-combine-text-transform.html
  StringBuilder text_content;
  text_content.Append(StringView(Text(), item.StartOffset(), item.Length()));
  const auto item_end_offset = text_content.length();
  // Note: In |LineBreakerMode::k{Min,Max}Content|, we've not laid out
  // atomic line box yet.
  InlineNode(text_combine).PrepareLayoutIfNeeded();
  text_content.Append(text_combine->GetTextContent());

  DCHECK_EQ(Text(), break_iterator_.GetString());
  LazyLineBreakIterator break_iterator(break_iterator_,
                                       text_content.ReleaseString());
  return break_iterator.IsBreakable(item_end_offset);
}

bool LineBreaker::MayBeAtomicInline(wtf_size_t offset) const {
  DCHECK_LT(offset, Text().length());
  const auto char_code = Text()[offset];
  if (char_code == kObjectReplacementCharacter)
    return true;
  return sticky_images_quirk_ && char_code == kNoBreakSpaceCharacter;
}

const InlineItem* LineBreaker::TryGetAtomicInlineItemAfter(
    const InlineItem& item) const {
  DCHECK(auto_wrap_);
  const String& text = Text();
  if (item.EndOffset() == text.length())
    return nullptr;
  if (!MayBeAtomicInline(item.EndOffset()))
    return nullptr;

  // This kObjectReplacementCharacter can be any objects, such as a floating or
  // an OOF object. Check if it's really an atomic inline.
  for (const auto& next_item :
       base::span(Items()).subspan(items_data_->ToItemIndex(item) + 1)) {
    DCHECK_EQ(next_item.StartOffset(), item.EndOffset());
    if (next_item.Type() == InlineItem::kAtomicInline) {
      return &next_item;
    }
    if (next_item.EndOffset() > item.EndOffset()) {
      return nullptr;
    }
  }
  return nullptr;
}

unsigned LineBreaker::IgnorableBidiControlLength(const InlineItem& item) const {
  const InlineItem* items = Items().data();
  for (wtf_size_t i =
           base::checked_cast<wtf_size_t>(std::distance(items, &item)) + 1;
       i < end_item_index_; ++i) {
    if (items[i].Length() == 0u) {
      continue;
    }
    if (items[i].Type() != InlineItem::kOpenRubyColumn &&
        items[i].Type() != InlineItem::kCloseRubyColumn) {
      return items[i].StartOffset() - item.EndOffset();
    }
  }
  return (end_item_index_ >= Items().size()
              ? Text().length()
              : items[end_item_index_].StartOffset()) -
         item.EndOffset();
}

void LineBreaker::HandleText(const InlineItem& item,
                             const ShapeResult& shape_result,
                             LineInfo* line_info) {
  DCHECK(item.Type() == InlineItem::kText ||
         (item.Type() == InlineItem::kControl &&
          Text()[item.StartOffset()] == kTabulationCharacter));
  DCHECK(&shape_result);
  DCHECK_EQ(auto_wrap_, ShouldAutoWrap(*item.Style()));

  // If we're trailing, only trailing spaces can be included in this line.
  if (state_ == LineBreakState::kTrailing) [[unlikely]] {
    HandleTrailingSpaces(item, &shape_result, line_info);
    return;
  }

  // Skip leading collapsible spaces.
  // Most cases such spaces are handled as trailing spaces of the previous line,
  // but there are some cases doing so is too complex.
  if (trailing_whitespace_ == WhitespaceState::kLeading) {
    if (item.Style()->ShouldCollapseWhiteSpaces() &&
        Text()[current_.text_offset] == kSpaceCharacter) {
      // Skipping one whitespace removes all collapsible spaces because
      // collapsible spaces are collapsed to single space in
      // InlineItemBuilder.
      ++current_.text_offset;
      if (current_.text_offset == item.EndOffset()) {
        HandleEmptyText(item, line_info);
        return;
      }
    }
    // |trailing_whitespace_| will be updated as we read the text.
  }

  // Go to |HandleOverflow()| if the last item overflowed, and we're adding
  // text.
  if (state_ == LineBreakState::kContinue && !CanFitOnLine()) {
    // |HandleOverflow()| expects all trailable items are added. If this text
    // starts with trailable spaces, add them. TODO(kojii): This can be
    // optimzied further. This is necesasry only if |HandleOverflow()| does not
    // rewind, but in most cases it will rewind.
    const String& text = Text();
    if (auto_wrap_ && IsBreakableSpace(text[current_.text_offset])) {
      HandleTrailingSpaces(item, &shape_result, line_info);
      if (state_ != LineBreakState::kDone) {
        state_ = LineBreakState::kContinue;
        return;
      }
    }
    HandleOverflow(line_info);
    return;
  }

  if (HasHyphen()) [[unlikely]] {
    position_ -= RemoveHyphen(line_info->MutableResults());
  }

  // Try to commit |pending_end_overhang_| of a prior InlineItemResult.
  // |pending_end_overhang_| doesn't work well with bidi reordering. It's
  // difficult to compute overhang after bidi reordering because it affect
  // line breaking.
  if (maybe_have_end_overhang_) {
    position_ -= CommitPendingEndOverhang(item, line_info);
  }

  InlineItemResult* item_result = nullptr;
  if (!is_svg_text_) {
    item_result = AddItem(item, line_info);
    item_result->should_create_line_box = true;
  }

  if (auto_wrap_) {
    // Check `parent_breaker_` because sub-LineInfo instances for <ruby>
    // require non-null InlineItemResult::shape_result.
    if (mode_ == LineBreakerMode::kMinContent && !parent_breaker_ &&
        HandleTextForFastMinContent(item_result, item, shape_result,
                                    line_info)) {
      return;
    }

    // Try to break inside of this text item.
    const LayoutUnit available_width = RemainingAvailableWidth();
    BreakResult break_result =
        BreakText(item_result, item, shape_result, available_width,
                  available_width, line_info);
    DCHECK(item_result->shape_result || !item_result->TextOffset().Length() ||
           (break_result == kOverflow && break_anywhere_if_overflow_ &&
            !override_break_anywhere_));
    position_ += item_result->inline_size;
    MoveToNextOf(*item_result);

    if (break_result == kSuccess) {
      DCHECK(item_result->shape_result || !item_result->TextOffset().Length());

      // If the break is at the middle of a text item, we know no trailable
      // items follow, only trailable spaces if any. This is very common that
      // shortcut to handling trailing spaces.
      if (item_result->EndOffset() < item.EndOffset())
        return HandleTrailingSpaces(item, &shape_result, line_info);

      // The break point found at the end of this text item. Continue looking
      // next items, because the next item maybe trailable, or can prohibit
      // breaking before.
      return;
    }
    if (break_result == kBreakAt) [[unlikely]] {
      // If this break is caused by `break_at_`, only trailing spaces or
      // trailing items can follow.
      if (item_result->EndOffset() < item.EndOffset()) {
        HandleTrailingSpaces(item, &shape_result, line_info);
        return;
      }
      state_ = LineBreakState::kTrailing;
      return;
    }
    DCHECK_EQ(break_result, kOverflow);

    // Handle `overflow-wrap` if it is enabled and if this text item overflows.
    if (!item_result->shape_result) [[unlikely]] {
      DCHECK(break_anywhere_if_overflow_ && !override_break_anywhere_);
      HandleOverflow(line_info);
      return;
    }

    // Hanging trailing spaces may resolve the overflow.
    if (item_result->has_only_pre_wrap_trailing_spaces) {
      state_ = LineBreakState::kTrailing;
      if (item_result->item->Style()->ShouldPreserveWhiteSpaces() &&
          IsBreakableSpace(Text()[item_result->EndOffset() - 1])) {
        unsigned end_index = base::checked_cast<unsigned>(
            item_result - line_info->Results().data());
        if (!parent_breaker_ || end_index > 0u) {
          Rewind(end_index, line_info);
        }
      }
      return;
    }

    // If we're seeking for the first break opportunity, update the state.
    if (state_ == LineBreakState::kOverflow) [[unlikely]] {
      if (item_result->can_break_after)
        state_ = LineBreakState::kTrailing;
      return;
    }

    // If this is all trailable spaces, this item is trailable, and next item
    // maybe too. Don't go to |HandleOverflow()| yet.
    if (IsAllBreakableSpaces(Text(), item_result->StartOffset(),
                             item_result->EndOffset()))
      return;

    HandleOverflow(line_info);
    return;
  }

  if (is_svg_text_) {
    SplitTextIntoSegments(item, line_info);
    return;
  }

  // Add until the end of the item if !auto_wrap. In most cases, it's the whole
  // item.
  DCHECK_EQ(item_result->EndOffset(), item.EndOffset());
  if (item_result->StartOffset() == item.StartOffset()) {
    item_result->inline_size =
        shape_result.SnappedWidth().ClampNegativeToZero();
    item_result->shape_result = ShapeResultView::Create(&shape_result);
  } else {
    // <wbr> can wrap even if !auto_wrap. Spaces after that will be leading
    // spaces and thus be collapsed.
    DCHECK(trailing_whitespace_ == WhitespaceState::kLeading &&
           item_result->StartOffset() >= item.StartOffset());
    item_result->shape_result = ShapeResultView::Create(
        &shape_result, item_result->StartOffset(), item_result->EndOffset());
    item_result->inline_size =
        item_result->shape_result->SnappedWidth().ClampNegativeToZero();
  }

  DCHECK(!item_result->may_break_inside);
  DCHECK(!item_result->can_break_after);
  trailing_whitespace_ = WhitespaceState::kUnknown;
  position_ += item_result->inline_size;
  MoveToNextOf(item);
}

// In SVG <text>, we produce InlineItemResult split into segments partitioned
// by x/y/dx/dy/rotate attributes.
//
// Split in PrepareLayout() or after producing FragmentItem would need
// additional memory overhead. So we split in LineBreaker while it converts
// InlineItems to InlineItemResults.
void LineBreaker::SplitTextIntoSegments(const InlineItem& item,
                                        LineInfo* line_info) {
  DCHECK(is_svg_text_);
  DCHECK_EQ(current_.text_offset, item.StartOffset());

  const ShapeResult& shape = *item.TextShapeResult();
  if (shape.NumGlyphs() == 0 || !needs_svg_segmentation_) {
    InlineItemResult* result = AddItem(item, line_info);
    result->should_create_line_box = true;
    result->shape_result = ShapeResultView::Create(&shape);
    result->inline_size = shape.SnappedWidth();
    current_.text_offset = item.EndOffset();
    position_ += result->inline_size;
    trailing_whitespace_ = WhitespaceState::kUnknown;
    MoveToNextOf(item);
    return;
  }

  Vector<unsigned> index_list;
  index_list.reserve(shape.NumGlyphs());
  shape.ForEachGlyph(0, CollectCharIndex, &index_list);
  if (shape.IsRtl())
    index_list.Reverse();
  wtf_size_t size = index_list.size();
  unsigned glyph_start = current_.text_offset;
  for (wtf_size_t i = 0; i < size; ++i) {
#if DCHECK_IS_ON()
    // The first glyph index can be greater than StartIndex() if the leading
    // part of the string was not mapped to any glyphs.
    if (i == 0)
      DCHECK_LE(glyph_start, index_list[0]);
    else
      DCHECK_EQ(glyph_start, index_list[i]);
#endif
    unsigned glyph_end = i + 1 < size ? index_list[i + 1] : shape.EndIndex();
    StringView text_view(Text());
    bool should_split = i == size - 1;
    for (; glyph_start < glyph_end;
         glyph_start = text_view.NextCodePointOffset(glyph_start)) {
      ++svg_addressable_offset_;
      should_split = should_split || ShouldCreateNewSvgSegment();
    }
    if (!should_split)
      continue;
    InlineItemResult* result = AddItem(item, glyph_end, line_info);
    result->should_create_line_box = true;
    auto* shape_result_view =
        ShapeResultView::Create(&shape, current_.text_offset, glyph_end);
    // For general CSS text, we apply SnappedWidth().ClampNegativeToZero().
    // However we need to remove ClampNegativeToZero() for SVG <text> in order
    // to get similar character positioning.
    //
    // For general CSS text, a negative word-spacing value decreases
    // inline_size of an InlineItemResult consisting of multiple characters,
    // and the inline_size rarely becomes negative.  However, for SVG <text>,
    // it decreases inline_size of an InlineItemResult consisting of only a
    // space character, and the inline_size becomes negative easily.
    //
    // See svg/W3C-SVG-1.1/text-spacing-01-b.svg.
    result->inline_size = shape_result_view->SnappedWidth();
    result->shape_result = std::move(shape_result_view);
    current_.text_offset = glyph_end;
    position_ += result->inline_size;
  }
  trailing_whitespace_ = WhitespaceState::kUnknown;
  MoveToNextOf(item);
}

bool LineBreaker::ShouldCreateNewSvgSegment() const {
  DCHECK(is_svg_text_);
  for (const auto& range : node_.SvgTextPathRangeList()) {
    if (range.start_index <= svg_addressable_offset_ &&
        svg_addressable_offset_ <= range.end_index)
      return true;
  }
  for (const auto& range : node_.SvgTextLengthRangeList()) {
    if (To<SVGTextContentElement>(range.layout_object->GetNode())
            ->lengthAdjust()
            ->CurrentEnumValue() == kSVGLengthAdjustSpacingAndGlyphs)
      continue;
    if (range.start_index <= svg_addressable_offset_ &&
        svg_addressable_offset_ <= range.end_index)
      return true;
  }
  const SvgCharacterData& char_data =
      svg_resolved_iterator_->AdvanceTo(svg_addressable_offset_);
  return char_data.HasRotate() || char_data.HasX() || char_data.HasY() ||
         char_data.HasDx() || char_data.HasDy();
}

LineBreaker::BreakResult LineBreaker::BreakText(
    InlineItemResult* item_result,
    const InlineItem& item,
    const ShapeResult& item_shape_result,
    LayoutUnit available_width,
    LayoutUnit available_width_with_hyphens,
    LineInfo* line_info) {
  DCHECK(item.Type() == InlineItem::kText ||
         (item.Type() == InlineItem::kControl &&
          Text()[item.StartOffset()] == kTabulationCharacter));
  DCHECK(&item_shape_result);
  item.AssertOffset(item_result->StartOffset());

  // The hyphenation state should be cleared before the entry. This function
  // may reset it, but this function cannot determine whether it should update
  // |position_| or not.
  DCHECK(!HasHyphen());

  DCHECK_EQ(item_shape_result.StartIndex(), item.StartOffset());
  DCHECK_EQ(item_shape_result.EndIndex(), item.EndOffset());
  class ShapingLineBreakerImpl : public ShapingLineBreaker {
    STACK_ALLOCATED();

   public:
    ShapingLineBreakerImpl(LineBreaker* line_breaker,
                           const InlineItem* item,
                           const ShapeResult* result)
        : ShapingLineBreaker(result,
                             &line_breaker->break_iterator_,
                             line_breaker->hyphenation_,
                             &item->Style()->GetFont()),
          line_breaker_(line_breaker),
          item_(item) {}

   protected:
    const ShapeResult* Shape(unsigned start,
                             unsigned end,
                             ShapeOptions options) final {
      return line_breaker_->ShapeText(*item_, start, end, options);
    }

   private:
    LineBreaker* line_breaker_;
    const InlineItem* item_;

  } breaker(this, &item, &item_shape_result);

  const ComputedStyle& style = *item.Style();
  breaker.SetTextSpacingTrim(style.GetFontDescription().GetTextSpacingTrim());
  breaker.SetLineStart(line_info->StartOffset());
  breaker.SetIsAfterForcedBreak(previous_line_had_forced_break_);

  // Reshaping between the last character and trailing spaces is needed only
  // when we need accurate end position, because kerning between trailing spaces
  // is not visible.
  if (!NeedsAccurateEndPosition(*line_info, item))
    breaker.SetDontReshapeEndIfAtSpace();

  if (break_at_) [[unlikely]] {
    if (BreakTextAt(item_result, item, breaker, line_info)) {
      return kBreakAt;
    }
    return kSuccess;
  }

  // Use kNoResultIfOverflow if 'break-word' and we're trying to break normally
  // because if this item overflows, we will rewind and break line again. The
  // overflowing ShapeResult is not needed.
  if (break_anywhere_if_overflow_ && !override_break_anywhere_)
    breaker.SetNoResultIfOverflow();

#if DCHECK_IS_ON()
  unsigned try_count = 0;
#endif
  LayoutUnit inline_size;
  ShapingLineBreaker::Result result;
  while (true) {
#if DCHECK_IS_ON()
    ++try_count;
    DCHECK_LE(try_count, 2u);
#endif
    const ShapeResultView* shape_result =
        breaker.ShapeLine(item_result->StartOffset(),
                          available_width.ClampNegativeToZero(), &result);

    // If this item overflows and 'break-word' is set, this line will be
    // rewinded. Making this item long enough to overflow is enough.
    if (!shape_result) {
      DCHECK(breaker.NoResultIfOverflow());
      item_result->inline_size = available_width_with_hyphens + 1;
      item_result->text_offset.end = item.EndOffset();
      item_result->text_offset.AssertNotEmpty();
      return kOverflow;
    }
    DCHECK_EQ(shape_result->NumCharacters(),
              result.break_offset - item_result->StartOffset());
    // It is critical to move the offset forward, or LineBreaker may keep
    // adding InlineItemResult until all the memory is consumed.
    CHECK_GT(result.break_offset, item_result->StartOffset());

    inline_size = shape_result->SnappedWidth().ClampNegativeToZero();
    item_result->inline_size = inline_size;
    if (result.is_hyphenated) [[unlikely]] {
      InlineItemResults* item_results = line_info->MutableResults();
      const LayoutUnit hyphen_inline_size =
          AddHyphen(item_results, item_result);
      // If the hyphen overflows, retry with the reduced available width.
      if (!result.is_overflow && inline_size <= available_width) {
        const LayoutUnit space_for_hyphen =
            available_width_with_hyphens - inline_size;
        if (space_for_hyphen >= 0 && hyphen_inline_size > space_for_hyphen) {
          available_width -= hyphen_inline_size;
          RemoveHyphen(item_results);
          continue;
        }
      }
      inline_size = item_result->inline_size;
    }
    item_result->text_offset.end = result.break_offset;
    item_result->text_offset.AssertNotEmpty();
    item_result->has_only_pre_wrap_trailing_spaces = result.has_trailing_spaces;
    item_result->has_only_bidi_trailing_spaces = result.has_trailing_spaces;
    item_result->shape_result = shape_result;
    break;
  }

  // * If width <= available_width:
  //   * If offset < item.EndOffset(): the break opportunity to fit is found.
  //   * If offset == item.EndOffset(): the break opportunity at the end fits,
  //     or the first break opportunity is beyond the end.
  //     There may be room for more characters.
  // * If width > available_width: The first break opportunity does not fit.
  //   offset is the first break opportunity, either inside, at the end, or
  //   beyond the end.
  if (item_result->EndOffset() < item.EndOffset()) {
    item_result->can_break_after = true;

    if (break_iterator_.BreakType() == LineBreakType::kBreakCharacter)
        [[unlikely]] {
      trailing_whitespace_ = WhitespaceState::kUnknown;
    } else {
      trailing_whitespace_ = WhitespaceState::kNone;
    }
  } else {
    DCHECK_EQ(item_result->EndOffset(), item.EndOffset());
    item_result->can_break_after = CanBreakAfter(item);
    trailing_whitespace_ = WhitespaceState::kUnknown;
  }

  // This result is not breakable any further if overflow. This information is
  // useful to optimize |HandleOverflow()|.
  item_result->may_break_inside = !result.is_overflow;

  // TODO(crbug.com/1003742): We should use |result.is_overflow| here. For now,
  // use |inline_size| because some tests rely on this behavior.
  return inline_size <= available_width_with_hyphens ? kSuccess : kOverflow;
}

bool LineBreaker::BreakTextAt(InlineItemResult* item_result,
                              const InlineItem& item,
                              ShapingLineBreaker& breaker,
                              LineInfo* line_info) {
  DCHECK(break_at_);
  DCHECK_LE(current_.text_offset, break_at_.end.text_offset);
  DCHECK_LE(current_.item_index, break_at_.offset.item_index);
  const bool should_break = current_.
"""


```