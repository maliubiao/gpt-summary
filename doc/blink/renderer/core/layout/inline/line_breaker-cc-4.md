Response:
My thought process to arrive at the summary of `line_breaker.cc` goes through these stages:

1. **Understanding the Context:** The prompt clearly states the file's location within the Chromium Blink engine and its role in inline layout. The path `blink/renderer/core/layout/inline/line_breaker.cc` strongly suggests its core responsibility is handling line breaking within inline content. The "part 5 of 6" indicates this is a substantial piece of a larger process.

2. **Initial Scan and Keyword Spotting:** I'd quickly scan the provided code snippet, looking for recurring keywords and patterns. Terms like `LineBreaker`, `LineInfo`, `InlineItem`, `ruby`, `float`, `break`, `width`, `available`, `overhang`, `whitespace`, and various `Handle...` functions jump out. These provide immediate clues about the file's key concerns.

3. **Decomposition by Functionality (High-Level):** Based on the keywords, I would start mentally grouping related functionalities. I'd notice distinct sections dealing with:
    * **Ruby handling:** The frequent mentions of `ruby`, `annotation`, `base_line`, `IsMonolithicRuby`, and `AddRubyColumnResult` clearly indicate a major function is correctly laying out ruby text.
    * **Float management:** `HandleFloat`, `ShouldPushFloatAfterLine`, `PositionFloat`, and `RewindFloats` signal responsibility for positioning and managing floats within the line.
    * **General inline item processing:** The numerous `Handle...` functions (e.g., `HandleText`, `HandleOpenTag`, `HandleCloseTag`, `HandleAtomicInline`) suggest a core mechanism for iterating through and processing different types of inline elements.
    * **Line breaking logic:**  The core name `LineBreaker` itself, combined with `CreateSubLineInfo`, `GetBreakToken`, and `HandleOverflow`, points to the fundamental task of deciding where lines should break.
    * **Whitespace handling:** `trailing_whitespace_`, `WhitespaceState`, and mentions of collapsing indicate an awareness of how whitespace affects line breaking.
    * **Overhangs:**  `lyStartOverhang`, `GetOverhang`, `pending_end_overhang` suggest handling of content that extends beyond the typical line box.

4. **Analyzing Specific Code Sections (Deeper Dive):** I would then examine specific blocks of code, particularly the `Handle...` functions, to understand the logic involved. For instance, within `HandleRubyColumn`, I see the logic for handling monolithic (unbreakable) rubies and the more complex logic for breaking ruby columns, including calculations of available space for base and annotation lines. Similarly, in `HandleFloat`, the checks for fitting, pushing to the next line, and the interaction with `exclusion_space_` become apparent.

5. **Identifying Relationships to Web Technologies:**  The prompt specifically asks about connections to HTML, CSS, and JavaScript. While the C++ code itself doesn't *directly* execute JavaScript, it's a core part of the rendering engine that *implements* CSS properties. I would connect the functionalities to:
    * **HTML:** The `InlineItem` types (like open/close tags) directly correspond to HTML elements. Ruby support reflects the `<ruby>` tag. Floats relate to the `float` CSS property.
    * **CSS:**  Properties like `white-space`, `text-wrap`, `ruby-position`, margins, padding, borders, and `box-decoration-break` are directly handled or their effects are implemented by this code.
    * **JavaScript:** While indirect, JavaScript can manipulate the DOM and CSS styles, which in turn triggers the line-breaking logic implemented in this file.

6. **Inferring Logic and Assumptions:** Based on the code, I would infer assumptions made by the `LineBreaker`. For example, the handling of ruby suggests the assumption that a ruby consists of a base and annotations. The float handling assumes a concept of available space and exclusion areas. The whitespace handling assumes specific rules for collapsing.

7. **Considering Potential Errors:** The prompt also asks about common errors. I'd think about scenarios where things might go wrong:
    * Incorrectly specified CSS leading to unexpected line breaks.
    * Complex interactions between floats and inline content causing layout shifts.
    * Edge cases with ruby rendering.
    * Issues with whitespace collapsing, particularly around ruby or floats.

8. **Structuring the Summary:** Finally, I would organize my understanding into a coherent summary. I'd start with the core function, then break it down into major areas of responsibility, providing specific examples and relating them back to web technologies. The goal is to provide a concise yet informative overview of the file's purpose and workings, addressing all aspects of the prompt. The "Part 5 of 6" also implies that this file is deeply involved in a particular stage of the rendering pipeline.

By following these steps, I can effectively analyze the provided code snippet and generate a comprehensive summary of the `line_breaker.cc` file's functionality. The iterative process of scanning, decomposing, analyzing, and connecting to broader concepts helps build a complete picture.
这是 `blink/renderer/core/layout/inline/line_breaker.cc` 文件的第 5 部分，它主要负责 **处理复杂内联元素和特殊情况下的断行逻辑**。

结合之前的部分（假设我们已经了解了它处理基本文本和简单内联元素的断行），这部分的功能可以归纳为：

**核心功能：处理复杂内联元素和特殊断行场景**

* **处理 Ruby 标记 ( `<ruby>` )：** 这是这部分代码的核心功能。它负责计算 Ruby 文本（基文本和注音/注释）的布局，并决定在何处断行。
    * **`HandleRubyColumn` 函数：**  是处理 `<ruby>` 元素的主要逻辑入口。它创建并管理 `LineInfo` 对象来分别存储基文本和注释行的信息。
    * **判断 Ruby 是否整体不可断 (`IsMonolithicRuby`)：**  根据一些规则（例如嵌套 Ruby、`text-wrap` 属性、基文本和注释文本的长度等）判断整个 Ruby 结构是否应该作为一个整体不可分割。
    * **创建子 `LineInfo` (`CreateSubLineInfo`)：**  为 Ruby 的基文本和注释文本创建独立的 `LineInfo` 对象，以便单独处理它们的断行。
    * **添加 Ruby 列结果 (`AddRubyColumnResult`)：**  将 Ruby 的布局信息（包括基文本和注释行的 `LineInfo`）添加到当前的 `LineInfo` 中。
    * **处理 Ruby 的溢出和断行：** 如果 Ruby 结构过宽，需要决定如何在基文本和注释文本之间进行断行。

* **处理浮动元素 ( `float` )：** 负责将浮动元素放置到合适的位置，并更新可用宽度。
    * **`HandleFloat` 函数：**  处理 `float` 元素的逻辑，包括判断浮动元素是否应该推到下一行 (`ShouldPushFloatAfterLine`)，以及实际放置浮动元素 (`PositionFloat`)。
    * **更新行机会 (`UpdateLineOpportunity`)：** 在放置浮动元素后，更新当前行的可用空间信息。
    * **回滚浮动 (`RewindFloats`)：** 在需要回滚断行决策时，撤销浮动元素的影响。

* **处理初始字母 (Initial Letter)：**
    * **`HandleInitialLetter` 函数：**  处理 CSS 的 `initial-letter` 属性，其实现方式类似于处理原子内联元素。

* **处理绝对定位元素 (Out-of-Flow Positioned)：**
    * **`HandleOutOfFlowPositioned` 函数：**  处理 `position: absolute` 或 `position: fixed` 的元素。这些元素不参与正常的内联布局，但在断行时仍需要记录它们的存在。

* **处理标签元素 (`<tag>`)：**
    * **`HandleOpenTag` 函数：** 处理 HTML 打开标签，计算边框、内边距和外边距，并更新当前样式。
    * **`HandleCloseTag` 函数：** 处理 HTML 关闭标签，计算内联结束大小，并恢复父元素的样式。

* **处理溢出情况 (`HandleOverflow`)：**  当一行无法容纳所有内容时，寻找合适的断点。这部分逻辑会尝试回滚到前一个可断点，或者在文本内部寻找可以断开的位置。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    * **`<ruby>` 标签：**  `HandleRubyColumn` 函数直接对应于 HTML 的 `<ruby>` 标签的处理。它解析 `<rb>`, `<rt>`, `<rp>` 等子元素，并按照规范进行布局。
        * **假设输入：** HTML 代码片段 `<ruby>基<rt>jī</rt></ruby>`
        * **输出：** `LineBreaker` 会计算出 "基" 和 "jī" 的位置和尺寸，可能需要考虑可用宽度来决定是否需要将注音放在基文本上方或旁边。
    * **`float` 属性：** `HandleFloat` 函数处理 CSS 的 `float: left` 或 `float: right` 属性。
        * **假设输入：** HTML 代码片段 `<img style="float: left" src="...">文本内容`，可用宽度为 200px，图片宽度为 50px。
        * **输出：** `LineBreaker` 会尝试将图片放置在当前行的左侧，并将文本内容环绕在图片周围。如果当前行剩余空间不足以容纳图片，可能会将图片推到下一行。
    * **其他标签：** `HandleOpenTag` 和 `HandleCloseTag` 处理各种 HTML 标签，计算它们带来的边距、内边距等效果，这直接影响了元素的布局。

* **CSS:**
    * **`text-wrap` 属性：** `IsMonolithicRuby` 函数会考虑 `text-wrap: balance` 或 `text-wrap: pretty` 等属性，这些属性会影响 Ruby 文本的断行策略。
    * **`ruby-position` 属性：** `AddRubyColumnResult` 中会根据 `ruby-position` 属性决定注音的位置（上方或旁边）。
    * **边距、内边距、边框属性：** `HandleOpenTag` 和 `HandleCloseTag` 会读取元素的 `margin`, `padding`, `border` 等 CSS 属性，并计算它们在内联布局中的贡献。
    * **`initial-letter` 属性：** `HandleInitialLetter` 负责实现 CSS 的 `initial-letter` 效果。
    * **`position: absolute/fixed` 属性：** `HandleOutOfFlowPositioned` 处理这些脱离文档流的元素。
    * **`white-space` 属性：** 虽然代码片段中没有直接体现，但 `white-space` 属性会影响断行的规则，例如 `white-space: nowrap` 会阻止断行。

* **JavaScript:**
    * JavaScript 可以动态修改元素的样式和结构，从而间接影响 `LineBreaker` 的行为。例如，通过 JavaScript 改变元素的 `float` 属性或添加 `<ruby>` 元素，会导致 `LineBreaker` 重新计算布局。

**逻辑推理的假设输入与输出：**

* **假设输入（Ruby）：**  一个 `<ruby>` 元素，其基文本宽度为 150px，注音宽度为 80px，当前行剩余可用宽度为 100px。`text-wrap` 属性为默认值。
* **输出：** `LineBreaker` 可能会决定将 Ruby 结构断行，例如将基文本放在当前行，并将注音放在下一行，或者如果允许，在基文本内部断行。这取决于更精细的断行规则和参数。

* **假设输入（Float）：**  一个 `float: left` 的图片，宽度为 60px，当前行已占用 50px，剩余可用宽度为 80px。
* **输出：** `LineBreaker` 会将图片放置在当前行的左侧，并更新剩余可用宽度为 20px (80 - 60)。后续的内联内容会从图片的右侧开始排列。

**用户或编程常见的使用错误：**

* **不正确的 Ruby 结构：**  例如，缺少 `<rt>` 标签，或者 `<rb>` 和 `<rt>` 标签的对应关系错误，可能导致 `LineBreaker` 无法正确解析和布局 Ruby 文本。
* **过度依赖浮动进行布局：**  过度使用 `float` 可能会导致复杂的布局问题，例如元素重叠或布局不稳定。`LineBreaker` 需要处理这些复杂情况，但也可能在某些极端情况下产生非预期的布局结果。
* **`white-space` 属性的误用：**  错误地使用 `white-space: nowrap` 可能会导致文本溢出容器，`LineBreaker` 会尽力处理，但在强制不断行的情况下可能无法完美解决。
* **复杂的嵌套元素和样式：**  过于复杂的 HTML 结构和 CSS 样式组合可能会增加 `LineBreaker` 处理的难度，可能导致性能问题或难以预测的断行结果。

**归纳其功能：**

总而言之，`blink/renderer/core/layout/inline/line_breaker.cc` 的这部分主要负责处理内联布局中更复杂和特殊的情况，特别是 **Ruby 文本和浮动元素**的布局和断行。它需要理解和实现 HTML 和 CSS 的相关规范，并做出合理的断行决策，以保证页面的正确渲染。它还需要处理各种边缘情况和潜在的用户错误，以提供健壮的布局能力。 这部分与之前的部分共同构成了内联元素断行的完整逻辑。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
lyStartOverhang(*line_info, line_info->Results().size(),
                             *current_style_, overhang.start)) {
    overhang.start = LayoutUnit();
  }
  bool is_monolithic = IsMonolithicRuby(base_line_info, annotation_line_list);
  if ((retry_size == kIndefiniteSize &&
       ruby_size <= available + overhang.start) ||
      is_monolithic) {
    if (mode_ == LineBreakerMode::kContent) {
      // Recreate lines because lines created with LineBreakerMode::kMaxContent
      // are not usable in InlineLayoutAlgorithm.
      base_line_info = CreateSubLineInfo(
          base_start, base_end_index, LineBreakerMode::kContent,
          kIndefiniteSize, trailing_whitespace_,
          /* disable_trailing_whitespace_collapsing */ true);
      for (wtf_size_t i = 0; i < annotation_data.size(); ++i) {
        annotation_line_list[i] = CreateSubLineInfo(
            annotation_data[i].start, annotation_data[i].end_item_index,
            LineBreakerMode::kContent, kIndefiniteSize,
            WhitespaceState::kLeading);
      }
    }

    InlineItemResult* result =
        AddRubyColumnResult(item, base_line_info, annotation_line_list,
                            annotation_data, ruby_size, ruby_token, *line_info);
    result->ruby_column->start_ruby_break_token = ruby_token;
    result->may_break_inside = !is_monolithic;
    position_ += ruby_size;
    // Move to a kCloseRubyColumn item.
    current_ = annotation_line_list[0].End();
    return true;
  }

  // Try to break the ruby column.

  LayoutUnit base_intrinsic_size = base_line_info.Width();
  LayoutUnit base_target = retry_size == kIndefiniteSize
                               ? (available * base_intrinsic_size / ruby_size)
                               : retry_size - 1;
  base_line_info = CreateSubLineInfo(base_start, base_end_index, mode_,
                                     base_target, trailing_whitespace_);
  // We assume a base LineInfo contains at least one InlineItemResult.
  // If it's zero, we can't adjust LogicalRubyColumns on bidi reorder.
  CHECK_GT(base_line_info.Results().size(), 0u);

  bool annotation_is_broken = false;
  for (wtf_size_t i = 0; i < number_of_annotations; ++i) {
    LineInfo& line = annotation_line_list[i];
    // If all items in the base line is consumed, we should consume all items
    // in annotation lines too.  The point just after the base line might be
    // non-breakable and we need to continue handling the following InlineItems
    // in such case. However it's very difficult if annotation items remain.
    LayoutUnit limit = kIndefiniteSize;
    LineBreakerMode mode = mode_;
    if (base_line_info.GetBreakToken()) {
      if (retry_size != kIndefiniteSize) {
        limit = line.Width() * base_line_info.Width() / base_intrinsic_size;
      } else {
        limit = available * line.Width() / ruby_size;
      }
    } else {
      // If the base is consumed entirely, the corresponding annotations should
      // be consumed entirely too.
      if (mode == LineBreakerMode::kMinContent) {
        mode = LineBreakerMode::kMaxContent;
      }
    }
    line = CreateSubLineInfo(annotation_data[i].start,
                             annotation_data[i].end_item_index, mode, limit,
                             WhitespaceState::kLeading);
    annotation_is_broken = annotation_is_broken || line.GetBreakToken();
  }

  ruby_size = MaxLineWidth(base_line_info, annotation_line_list);
  InlineItemResult* result =
      AddRubyColumnResult(item, base_line_info, annotation_line_list,
                          annotation_data, ruby_size, ruby_token, *line_info);
  result->ruby_column->start_ruby_break_token = ruby_token;
  result->may_break_inside = true;
  position_ += ruby_size;

  // If the base line and annotation lines have no BreakToken, we should add
  // them even though they are wider than the available width.  The
  // InlineItemResult for the ruby column may be rewound.
  if (!base_line_info.GetBreakToken() && !annotation_is_broken) {
    current_ = annotation_line_list[0].End();
    return true;
  }
  DCHECK(base_line_info.GetBreakToken());
  current_ = base_line_info.End();

  // We have a broken line, and need to provide a RubyBreakTokenData.
  Vector<AnnotationBreakTokenData, 1> breaks;
  breaks.reserve(number_of_annotations);
  for (wtf_size_t i = 0; i < number_of_annotations; ++i) {
    breaks.push_back(AnnotationBreakTokenData{
        annotation_line_list[i].End(), annotation_data[i].start_item_index,
        annotation_data[i].end_item_index});
  }
  result->ruby_column->end_ruby_break_token =
      MakeGarbageCollected<RubyBreakTokenData>(open_column_item_index,
                                               base_end_index, breaks);

  if (retry_size == kIndefiniteSize) {
    // We can't continue to handle following InlineItems if we break inside a
    // ruby column. So we try to rewind if necessary, then finish this line.
    HandleOverflowIfNeeded(line_info);
    if (!line_info->Results().empty()) {
      state_ = LineBreakState::kDone;
    }
  }
  return true;
}

bool LineBreaker::IsMonolithicRuby(
    const LineInfo& base_line,
    const HeapVector<LineInfo, 1>& annotation_line_list) const {
  // Not breakable if it's an inner ruby column of nested rubies.
  if (end_item_index_ != Items().size()) {
    return true;
  }

  if (!auto_wrap_) {
    return true;
  }

  // The base line is not breakable.
  if (base_line.Width() <= LayoutUnit()) {
    return true;
  }

  // We don't break rubies in text-wrap:balance and text-wrap:pretty
  // because the sum of broken ruby inline-size can be different from the
  // inline-size of a non-broken ruby.
  if (!node_.Style().ShouldWrapLineGreedy()) {
    return true;
  }

  if (!RuntimeEnabledFeatures::RubyShortHeuristicsEnabled()) {
    return false;
  }
  // Not breakable if the number of the base letters is <= 4 and the number of
  // the annotation letters is <= 8.
  //
  // TODO(layout-dev): Should we take into account of East Asian Width?
  constexpr wtf_size_t kBaseLetterLimit = 4;
  constexpr wtf_size_t kAnnotationLetterLimit = 8;
  if (!base_line.GlyphCountIsGreaterThan(kBaseLetterLimit)) {
    auto iter = std::find_if(
        annotation_line_list.begin(), annotation_line_list.end(),
        [](const LineInfo& line) {
          return line.GlyphCountIsGreaterThan(kAnnotationLetterLimit);
        });
    if (iter == annotation_line_list.end()) {
      return true;
    }
  }

  return false;
}

LineInfo LineBreaker::CreateSubLineInfo(
    InlineItemTextIndex start,
    wtf_size_t end_item_index,
    LineBreakerMode mode,
    LayoutUnit limit,
    WhitespaceState initial_whitespace_state,
    bool disable_trailing_whitespace_collapsing) {
  bool disallow_auto_wrap = false;
  if (limit == kIndefiniteSize) {
    limit = LayoutUnit::Max();
    disallow_auto_wrap = true;
  }
  ExclusionSpace empty_exclusion_space;
  LeadingFloats empty_leading_floats;
  LineInfo sub_line_info;
  LineBreaker sub_line_breaker(
      node_, mode, constraint_space_, LineLayoutOpportunity(limit),
      empty_leading_floats,
      /* break_token */ nullptr,
      /* column_spanner_path */ nullptr, &empty_exclusion_space);
  sub_line_breaker.disallow_auto_wrap_ = disallow_auto_wrap;
  sub_line_breaker.SetInputRange(start, end_item_index,
                                 initial_whitespace_state, this);
  if (RuntimeEnabledFeatures::NoCollapseSpaceBeforeRubyEnabled()) {
    sub_line_breaker.disable_trailing_whitespace_collapsing_ =
        disable_trailing_whitespace_collapsing;
  }
  // OverrideAvailableWidth() prevents HandleFloat() from updating
  // available_width_.
  sub_line_breaker.OverrideAvailableWidth(limit);
  sub_line_breaker.NextLine(&sub_line_info);
  if (disallow_auto_wrap) {
    CHECK(sub_line_breaker.IsAtEnd());
  }
  return sub_line_info;
}

InlineItemResult* LineBreaker::AddRubyColumnResult(
    const InlineItem& item,
    const LineInfo& base_line_info,
    const HeapVector<LineInfo, 1>& annotation_line_list,
    const Vector<AnnotationBreakTokenData, 1>& annotation_data_list,
    LayoutUnit ruby_size,
    bool is_continuation,
    LineInfo& line_info) {
  CHECK_EQ(item.Type(), InlineItem::kOpenRubyColumn);
  InlineItemResult* column_result = AddEmptyItem(item, &line_info);
  column_result->inline_size = ruby_size;
  auto* data = MakeGarbageCollected<InlineItemResultRubyColumn>();
  column_result->ruby_column = data;
  data->base_line = base_line_info;
  data->base_line.OverrideLineStyle(*current_style_);
  data->base_line.SetIsRubyBase();
  data->base_line.UpdateTextAlign();
  if (data->base_line.MayHaveRubyOverhang()) {
    line_info.SetMayHaveRubyOverhang();
  }
  line_info.SetHaveTextCombineOrRubyItem();
  data->is_continuation = is_continuation;

  data->annotation_line_list = annotation_line_list;
  for (wtf_size_t i = 0; i < annotation_line_list.size(); ++i) {
    LayoutObject& annotation_object =
        *Items()[annotation_data_list[i].start_item_index].GetLayoutObject();
    data->annotation_line_list[i].OverrideLineStyle(*annotation_object.Style());
    data->annotation_line_list[i].SetIsRubyText();
    data->annotation_line_list[i].UpdateTextAlign();
    const LayoutObject* parent = annotation_object.Parent();
    data->position_list.push_back(
        parent->IsInlineRuby()
            ? parent->Style(use_first_line_style_)->GetRubyPosition()
            : RubyPosition::kOver);
  }
  DCHECK_EQ(data->annotation_line_list.size(), data->position_list.size());

  column_result->text_offset.end = annotation_line_list[0].EndTextOffset();
  column_result->should_create_line_box = true;
  column_result->can_break_after = CanBreakAfterRubyColumn(
      *column_result, annotation_data_list[0].end_item_index);

  if (base_line_info.Width() < ruby_size) {
    line_info.SetMayHaveRubyOverhang();

    AnnotationOverhang overhang = GetOverhang(*column_result);
    if (overhang.end > LayoutUnit()) {
      column_result->pending_end_overhang = overhang.end;
      maybe_have_end_overhang_ = true;
    }

    if (CanApplyStartOverhang(line_info, line_info.Results().size() - 1,
                              column_result->item->GetLayoutObject()
                                  ? *column_result->item->Style()
                                  : *current_style_,
                              overhang.start)) {
      DCHECK_EQ(column_result->margins.inline_start, LayoutUnit());
      DCHECK_EQ((*column_result->ruby_column->base_line.MutableResults())[0]
                    .item->Type(),
                InlineItem::kRubyLinePlaceholder);
      (*column_result->ruby_column->base_line.MutableResults())[0]
          .margins.inline_start = -overhang.start;
      position_ -= overhang.start;
    }
  }
  trailing_whitespace_ =
      RuntimeEnabledFeatures::NoCollapseSpaceBeforeRubyEnabled()
          ? WhitespaceState::kUnknown
          : WhitespaceState::kNone;
  return column_result;
}

bool LineBreaker::CanBreakAfterRubyColumn(
    const InlineItemResult& column_result,
    wtf_size_t column_end_item_index) const {
  DCHECK_EQ(column_result.item->Type(), InlineItem::kOpenRubyColumn);
  DCHECK(column_result.ruby_column);
  if (!auto_wrap_) {
    return false;
  }
  const LineInfo& base_line = column_result.ruby_column->base_line;
  if (base_line.GetBreakToken()) {
    return true;
  }
  // Populate `text_content` with column_result's base text and text content
  // after `column_result`.
  StringBuilder text_content;
  unsigned base_text_length =
      base_line.EndTextOffset() - base_line.StartOffset();
  text_content.Append(
      StringView(Text(), base_line.StartOffset(), base_text_length));
  const InlineItem& next_item = Items()[column_end_item_index];
  DCHECK_EQ(next_item.Type(), InlineItem::kCloseRubyColumn);
  unsigned ignorable_bidi_length = 1 + IgnorableBidiControlLength(next_item);
  text_content.Append(
      StringView(Text(), next_item.StartOffset() + ignorable_bidi_length));
  LazyLineBreakIterator break_iterator(break_iterator_,
                                       text_content.ReleaseString());
  return break_iterator.IsBreakable(base_text_length);
}

// Figure out if the float should be pushed after the current line. This
// should only be considered if we're not resuming the float, after having
// broken inside or before it in the previous fragmentainer. Otherwise we must
// attempt to place it.
bool LineBreaker::ShouldPushFloatAfterLine(
    UnpositionedFloat* unpositioned_float,
    LineInfo* line_info) {
  if (unpositioned_float->token) {
    return false;
  }

  LayoutUnit inline_margin_size =
      ComputeMarginBoxInlineSizeForUnpositionedFloat(unpositioned_float);

  LayoutUnit used_size = position_ + inline_margin_size +
                         ComputeFloatAncestorInlineEndSize(
                             constraint_space_, Items(), current_.item_index);
  bool can_fit_float =
      used_size <= line_opportunity_.AvailableFloatInlineSize().AddEpsilon();
  if (!can_fit_float) {
    // Floats need to know the current line width to determine whether to put it
    // into the current line or to the next line. Trailing spaces will be
    // removed if this line breaks here because they should be collapsed across
    // floats, but they are still included in the current line position at this
    // point. Exclude it when computing whether this float can fit or not.
    can_fit_float = used_size - TrailingCollapsibleSpaceWidth(line_info) <=
                    line_opportunity_.AvailableFloatInlineSize().AddEpsilon();
  }

  LayoutUnit bfc_block_offset =
      unpositioned_float->origin_bfc_offset.block_offset;

  // The float should be positioned after the current line if:
  //  - It can't fit within the non-shape area. (Assuming the current position
  //    also is strictly within the non-shape area).
  //  - It will be moved down due to block-start edge alignment.
  //  - It will be moved down due to clearance.
  //  - An earlier float has been pushed to the next fragmentainer.
  return !can_fit_float ||
         exclusion_space_->LastFloatBlockStart() > bfc_block_offset ||
         exclusion_space_->ClearanceOffset(unpositioned_float->ClearType(
             constraint_space_.Direction())) > bfc_block_offset;
}

// Performs layout and positions a float.
//
// If there is a known available_width (e.g. something has resolved the
// container BFC block offset) it will attempt to position the float on the
// current line.
// Additionally updates the available_width for the line as the float has
// (probably) consumed space.
//
// If the float is too wide *or* we already have UnpositionedFloats we add it
// as an UnpositionedFloat. This should be positioned *immediately* after we
// are done with the current line.
// We have this check if there are already UnpositionedFloats as we aren't
// allowed to position a float "above" another float which has come before us
// in the document.
void LineBreaker::HandleFloat(const InlineItem& item,
                              const BlockBreakToken* float_break_token,
                              LineInfo* line_info) {
  // When rewind occurs, an item may be handled multiple times.
  // Since floats are put into a separate list, avoid handling same floats
  // twice.
  // Ideally rewind can take floats out of floats list, but the difference is
  // sutble compared to the complexity.
  //
  // Additionally, we need to skip floats if we're retrying a line after a
  // fragmentainer break. In that case the floats associated with this line will
  // already have been processed.
  InlineItemResult* item_result = AddItem(item, line_info);
  auto index_before_float = current_;
  item_result->can_break_after = auto_wrap_;
  MoveToNextOf(item);

  // If we are currently computing our min/max-content size, simply append the
  // unpositioned floats to |LineInfo| and abort.
  if (mode_ != LineBreakerMode::kContent) {
    return;
  }

  // Make sure we populate the positioned_float inside the |item_result|.
  if (current_.item_index <= leading_floats_.handled_index &&
      !leading_floats_.floats.empty()) {
    DCHECK_LT(leading_floats_index_, leading_floats_.floats.size());
    item_result->positioned_float =
        leading_floats_.floats[leading_floats_index_++];

    // Save a backup copy of `exclusion_space_` even if leading floats don't
    // modify it. See `RewindFloat`.
    DCHECK(exclusion_space_);
    item_result->exclusion_space_before_position_float.CopyFrom(
        *exclusion_space_);

    if (RuntimeEnabledFeatures::LineBoxBelowLeadingFloatsEnabled()) {
      return;
    }

    // Don't break after leading floats if indented.
    if (position_ != 0)
      item_result->can_break_after = false;
    return;
  }

  const LayoutUnit bfc_block_offset = line_opportunity_.bfc_block_offset;
  // The BFC offset passed to `ShouldHideForPaint` should be the bottom offset
  // of the line, which we don't know at this point. However, since block layout
  // will relayout to fix the clamp BFC offset to the bottom of the last line
  // before clamp, we now that if the line's BFC offset is equal or greater than
  // the clamp BFC offset in the final relayout, the line will be hidden.
  bool is_hidden_for_paint =
      constraint_space_.GetLineClampData().ShouldHideForPaint();
  UnpositionedFloat unpositioned_float(
      BlockNode(To<LayoutBox>(item.GetLayoutObject())), float_break_token,
      constraint_space_.AvailableSize(),
      constraint_space_.PercentageResolutionSize(),
      constraint_space_.ReplacedPercentageResolutionSize(),
      {constraint_space_.GetBfcOffset().line_offset, bfc_block_offset},
      constraint_space_, node_.Style(),
      constraint_space_.FragmentainerBlockSize(),
      constraint_space_.FragmentainerOffset(), is_hidden_for_paint);

  bool float_after_line =
      ShouldPushFloatAfterLine(&unpositioned_float, line_info);

  // Check if we already have a pending float. That's because a float cannot be
  // higher than any block or floated box generated before.
  if (HasUnpositionedFloats(line_info->Results()) || float_after_line) {
    item_result->has_unpositioned_floats = true;
    return;
  }

  // Save a backup copy of `exclusion_space_` for when rewinding. See
  // `RewindFloats`.
  DCHECK(exclusion_space_);
  item_result->exclusion_space_before_position_float.CopyFrom(
      *exclusion_space_);

  item_result->positioned_float =
      PositionFloat(&unpositioned_float, exclusion_space_);
  // Ensure `NeedsCollectInlines` isn't set, or it may cause security risks.
  CHECK(!node_.GetLayoutBox()->NeedsCollectInlines());

  if (constraint_space_.HasBlockFragmentation()) {
    if (const auto* break_token = item_result->positioned_float->BreakToken()) {
      const auto* parallel_token = InlineBreakToken::CreateForParallelBlockFlow(
          node_, index_before_float, *break_token);
      line_info->PropagateParallelFlowBreakToken(parallel_token);
      if (item_result->positioned_float->minimum_space_shortage) {
        line_info->PropagateMinimumSpaceShortage(
            item_result->positioned_float->minimum_space_shortage);
      }
      if (break_token->IsBreakBefore()) {
        return;
      }
    }
  }

  UpdateLineOpportunity();
}

void LineBreaker::UpdateLineOpportunity() {
  const LayoutUnit bfc_block_offset = line_opportunity_.bfc_block_offset;
  LayoutOpportunity opportunity = exclusion_space_->FindLayoutOpportunity(
      {constraint_space_.GetBfcOffset().line_offset, bfc_block_offset},
      constraint_space_.AvailableSize().inline_size);

  DCHECK_EQ(bfc_block_offset, opportunity.rect.BlockStartOffset());

  line_opportunity_ = opportunity.ComputeLineLayoutOpportunity(
      constraint_space_, line_opportunity_.line_block_size, LayoutUnit());
  UpdateAvailableWidth();

  DCHECK_GE(AvailableWidth(), LayoutUnit());
}

// Restore the states changed by `HandleFloat` to before
// `item_results[new_end]`.
void LineBreaker::RewindFloats(unsigned new_end,
                               LineInfo& line_info,
                               InlineItemResults& item_results) {
  for (const InlineItemResult& item_result :
       base::make_span(item_results).subspan(new_end)) {
    if (item_result.positioned_float) {
      const unsigned item_index = item_result.item_index;
      line_info.RemoveParallelFlowBreakToken(item_index);

      // Adjust `leading_floats_index_` if this is a leading float. See
      // `HandleFloat` and `PositionLeadingFloats`.
      if (item_index < leading_floats_.handled_index) {
        for (unsigned i = 0; i < leading_floats_.floats.size(); ++i) {
          if (leading_floats_.floats[i].layout_result ==
              item_result.positioned_float->layout_result) {
            leading_floats_index_ = i;
            // Need to restore `exclusion_space_` even if leading floats don't
            // modify `exclusion_space_`, because there may be following
            // non-leading floats that modified it.
            break;
          }
        }
      }

      *exclusion_space_ = item_result.exclusion_space_before_position_float;
      UpdateLineOpportunity();
      break;
    }
  }
}

void LineBreaker::HandleInitialLetter(const InlineItem& item,
                                      LineInfo* line_info) {
  // TODO(crbug.com/1276900): We should check behavior when line breaking
  // after initial letter box.
  HandleAtomicInline(item, line_info);
}

void LineBreaker::HandleOutOfFlowPositioned(const InlineItem& item,
                                            LineInfo* line_info) {
  DCHECK_EQ(item.Type(), InlineItem::kOutOfFlowPositioned);
  InlineItemResult* item_result = AddItem(item, line_info);

  // Break opportunity after OOF is not well-defined nor interoperable. Using
  // |kObjectReplacementCharacter|, except when this is a leading OOF, seems to
  // produce reasonable and interoperable results in common cases.
  DCHECK(!item_result->can_break_after);
  if (item_result->should_create_line_box)
    ComputeCanBreakAfter(item_result, auto_wrap_, break_iterator_);

  MoveToNextOf(item);
}

bool LineBreaker::ComputeOpenTagResult(const InlineItem& item,
                                       const ConstraintSpace& constraint_space,
                                       bool is_in_svg_text,
                                       InlineItemResult* item_result) {
  DCHECK_EQ(item.Type(), InlineItem::kOpenTag);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();
  if (!is_in_svg_text && item.ShouldCreateBoxFragment() &&
      (style.HasBorder() || style.MayHavePadding() || style.MayHaveMargin())) {
    item_result->borders = ComputeLineBorders(style);
    item_result->padding = ComputeLinePadding(constraint_space, style);
    item_result->margins = ComputeLineMarginsForSelf(constraint_space, style);
    item_result->inline_size = item_result->margins.inline_start +
                               item_result->borders.inline_start +
                               item_result->padding.inline_start;
    return true;
  }
  return false;
}

void LineBreaker::HandleOpenTag(const InlineItem& item, LineInfo* line_info) {
  DCHECK_EQ(item.Type(), InlineItem::kOpenTag);

  InlineItemResult* item_result = AddItem(item, line_info);
  DCHECK(item.Style());
  const ComputedStyle& style = *item.Style();
  if (ComputeOpenTagResult(item, constraint_space_, is_svg_text_,
                           item_result)) {
    // Negative margins on open tags may bring the position back. Update
    // |state_| if that happens.
    if (item_result->inline_size < 0 && state_ == LineBreakState::kTrailing)
        [[unlikely]] {
      LayoutUnit available_width = AvailableWidthToFit();
      if (position_ > available_width &&
          position_ + item_result->inline_size <= available_width) {
        state_ = LineBreakState::kContinue;
      }
    }

    position_ += item_result->inline_size;

    // While the spec defines "non-zero margins, padding, or borders" prevents
    // line boxes to be zero-height, tests indicate that only inline direction
    // of them do so. See should_create_line_box_.
    // Force to create a box, because such inline boxes affect line heights.
    if (!item_result->should_create_line_box && !item.IsEmptyItem())
      item_result->should_create_line_box = true;
  }

  if (style.BoxDecorationBreak() == EBoxDecorationBreak::kClone) [[unlikely]] {
    // Compute even when no margins/borders/padding to ensure correct counting.
    has_cloned_box_decorations_ = true;
    disable_score_line_break_ = true;
    ++cloned_box_decorations_count_;
    cloned_box_decorations_end_size_ += item_result->margins.inline_end +
                                        item_result->borders.inline_end +
                                        item_result->padding.inline_end;
  }

  bool was_auto_wrap = auto_wrap_;
  SetCurrentStyle(style);
  MoveToNextOf(item);

  DCHECK(!item_result->can_break_after);
  const InlineItemResults& item_results = line_info->Results();
  if (!was_auto_wrap && auto_wrap_ && item_results.size() >= 2) [[unlikely]] {
    if (IsPreviousItemOfType(InlineItem::kText)) {
      ComputeCanBreakAfter(std::prev(item_result), auto_wrap_, break_iterator_);
    }
  }
}

void LineBreaker::HandleCloseTag(const InlineItem& item, LineInfo* line_info) {
  InlineItemResult* item_result = AddItem(item, line_info);

  if (!is_svg_text_) {
    DCHECK(item.Style());
    const ComputedStyle& style = *item.Style();
    item_result->inline_size = ComputeInlineEndSize(constraint_space_, &style);
    position_ += item_result->inline_size;

    if (!item_result->should_create_line_box && !item.IsEmptyItem())
      item_result->should_create_line_box = true;

    if (style.BoxDecorationBreak() == EBoxDecorationBreak::kClone)
        [[unlikely]] {
      DCHECK_GT(cloned_box_decorations_count_, 0u);
      --cloned_box_decorations_count_;
      DCHECK_GE(cloned_box_decorations_end_size_, item_result->inline_size);
      cloned_box_decorations_end_size_ -= item_result->inline_size;
    }
  }
  DCHECK(item.GetLayoutObject() && item.GetLayoutObject()->Parent());
  bool was_auto_wrap = auto_wrap_;
  SetCurrentStyle(item.GetLayoutObject()->Parent()->StyleRef());
  MoveToNextOf(item);

  // If the line can break after the previous item, prohibit it and allow break
  // after this close tag instead. Even when the close tag has "nowrap", break
  // after it is allowed if the line is breakable after the previous item.
  const InlineItemResults& item_results = line_info->Results();
  if (item_results.size() >= 2) {
    InlineItemResult* last = std::prev(item_result);
    if (IsA<LayoutTextCombine>(last->item->GetLayoutObject())) [[unlikely]] {
      // |can_break_after| for close tag should be as same as text-combine box.
      // See "text-combine-upright-break-inside-001a.html"
      // e.g. A<tcy style="white-space: pre">x y</tcy>B
      item_result->can_break_after = last->can_break_after;
      return;
    }
    if (last->can_break_after) {
      // A break opportunity before a close tag always propagates to after the
      // close tag.
      item_result->can_break_after = true;
      last->can_break_after = false;
      return;
    }
    if (was_auto_wrap) {
      // We can break before a breakable space if we either:
      //   a) allow breaking before a white space, or
      //   b) the break point is preceded by another breakable space.
      // TODO(abotella): What if the following breakable space is after an
      // open tag which has a different white-space value?
      bool preceded_by_breakable_space =
          item_result->EndOffset() > 0 &&
          IsBreakableSpace(Text()[item_result->EndOffset() - 1]);
      item_result->can_break_after =
          IsBreakableSpace(Text()[item_result->EndOffset()]) &&
          (!current_style_->ShouldBreakOnlyAfterWhiteSpace() ||
           preceded_by_breakable_space);
      return;
    }
    if (auto_wrap_ && !IsBreakableSpace(Text()[item_result->EndOffset() - 1]))
      ComputeCanBreakAfter(item_result, auto_wrap_, break_iterator_);
  }
}

// Handles when the last item overflows.
// At this point, item_results does not fit into the current line, and there
// are no break opportunities in item_results.back().
void LineBreaker::HandleOverflow(LineInfo* line_info) {
  const LayoutUnit available_width = AvailableWidthToFit();
  DCHECK_GT(position_, available_width);

  // Save the hyphenation states before we may make changes.
  InlineItemResults* item_results = line_info->MutableResults();
  std::optional<wtf_size_t> hyphen_index_before = hyphen_index_;
  if (HasHyphen()) [[unlikely]] {
    position_ -= RemoveHyphen(item_results);
  }

  // Compute the width needing to rewind. When |width_to_rewind| goes negative,
  // items can fit within the line.
  LayoutUnit width_to_rewind = position_ - available_width;

  // Keep track of the shortest break opportunity.
  unsigned break_before = 0;

  // True if there is at least one item that has `break-word`.
  bool has_break_anywhere_if_overflow = break_anywhere_if_overflow_;

  // Search for a break opportunity that can fit.
  for (unsigned i = item_results->size(); i;) {
    InlineItemResult* item_result = &(*item_results)[--i];
    has_break_anywhere_if_overflow |= item_result->break_anywhere_if_overflow;

    // Try to break after this item.
    if (i < item_results->size() - 1 && item_result->can_break_after) {
      if (width_to_rewind <= 0) {
        position_ = available_width + width_to_rewind;
        RewindOverflow(i + 1, line_info);
        return;
      }
      break_before = i + 1;
    }

    // Compute the position after this item was removed entirely.
    width_to_rewind -= item_result->inline_size;

    // Try next if still does not fit.
    if (width_to_rewind > 0)
      continue;

    DCHECK(item_result->item);
    const InlineItem& item = *item_result->item;
    if (item.Type() == InlineItem::kText) {
      if (!item_result->Length()) {
        // Empty text items are trailable, see `HandleEmptyText`.
        continue;
      }
      DCHECK(item_result->shape_result ||
             (item_result->break_anywhere_if_overflow &&
              !override_break_anywhere_) ||
             // |HandleTextForFastMinContent| can produce an item without
             // |ShapeResult|. In this case, it is not breakable.
             (mode_ == LineBreakerMode::kMinContent &&
              !item_result->may_break_inside));
      // If space is available, and if this text is breakable, part of the text
      // may fit. Try to break this item.
      if (width_to_rewind < 0 && item_result->may_break_inside) {
        const LayoutUnit item_available_width = -width_to_rewind;
        // Make sure the available width is smaller than the current width. The
        // break point must not be at the end when e.g., the text fits but its
        // right margin does not or following items do not.
        const LayoutUnit min_available_width = item_result->inline_size - 1;
        // If |inline_size| is zero (e.g., `font-size: 0`), |BreakText| cannot
        // make it shorter. Take the previous break opportunity.
        if (min_available_width <= 0) [[unlikely]] {
          if (BreakTextAtPreviousBreakOpportunity(*item_results, i)) {
            RewindOverflow(i + 1, line_info);
            return;
          }
          continue;
        }
        const ComputedStyle* was_current_style = current_style_;
        SetCurrentStyle(*item.Style());
        const InlineItemResult item_result_before = *item_result;
        BreakText(item_result, item, *item.TextShapeResult(),
                  std::min(item_available_width, min_available_width),
                  item_available_width, line_info);
        DCHECK_LE(item_result->EndOffset(), item_result_before.EndOffset());
#if DCHECK_IS_ON()
        item_result->CheckConsistency(true);
#endif

        // If BreakText() changed this item small enough to fit, break here.
        if (item_result->can_break_after &&
            item_result->inline_size <= item_available_width &&
            item_result->EndOffset() < item_result_before.EndOffset()) {
          DCHECK_LT(item_result->EndOffset(), item.EndOffset());

          // If this is the last item, adjust it to accommodate the change.
          const unsigned new_end = i + 1;
          CHECK_LE(new_end, item_results->size());
          if (new_end == item_results->size()) {
            position_ =
                available_width + width_to_rewind + item_result->inline_size;
            DCHECK_EQ(position_, line_info->ComputeWidth());
            current_ = item_result->End();
            items_data_->AssertOffset(current_);
            HandleTrailingSpaces(item, line_info);
            return;
          }

          sta
"""


```