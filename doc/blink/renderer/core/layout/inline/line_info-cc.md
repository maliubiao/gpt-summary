Response:
Let's break down the thought process for analyzing the `line_info.cc` file.

1. **Understand the Core Purpose:** The filename `line_info.cc` and the namespace `blink::layout::inline` immediately suggest this file deals with information related to individual lines within inline layout in the Blink rendering engine. The presence of `#include` directives for other inline layout related headers reinforces this idea.

2. **Identify Key Data Structures:** The `LineInfo` class itself is the central data structure. Look at its member variables. These tell us what information a `LineInfo` object holds:
    * `results_`: A collection of `InlineItemResult` objects. This is crucial; it represents the individual elements on the line.
    * `items_data_`:  Pointer to `InlineItemsData`, likely containing the overall set of inline items.
    * `line_style_`: Pointer to `ComputedStyle`, holding the CSS styles for the line.
    * `break_token_`, `parallel_flow_break_tokens_`: Information about where the line breaks.
    * `bfc_offset_`: Block formatting context offset.
    * Various `LayoutUnit` members (`available_width_`, `width_`, `hang_width_`, etc.): Dimensions related to the line.
    * Boolean flags (`is_last_line_`, `has_forced_break_`, etc.):  Properties of the line.
    * Enumerations (`text_align_`, `base_direction_`): Text formatting properties.

3. **Analyze Key Methods:**  Examine the methods of the `LineInfo` class. Group them by functionality:
    * **Initialization/Reset:** `Reset()`, `SetLineStyle()`:  How is a `LineInfo` object prepared?
    * **Accessors:**  Methods that return information about the line (e.g., `GetTextAlign()`, `InflowStartOffset()`, `End()`, `ComputeWidth()`).
    * **Calculations:** Methods that compute derived values based on the line's content and style (e.g., `ComputeNeedsAccurateEndPosition()`, `ComputeTrailingSpaceWidth()`, `ComputeAnnotationBlockOffsetAdjustment()`).
    * **Mutators (Less Common Here):**  Methods that modify the state of the `LineInfo` object (e.g., `RemoveParallelFlowBreakToken()`, though most modifications seem to happen during the line construction process elsewhere).
    * **Debugging/Tracing:** `Trace()`, `operator<<`:  For introspection and debugging.

4. **Connect to Web Technologies (HTML, CSS, JavaScript):**  Think about how the data and methods in `LineInfo` relate to the features of these technologies:
    * **HTML:**  The content of the line comes from HTML elements (text, inline elements like `<span>`, `<a>`, `<img>`). The `InlineItemResult` likely corresponds to these elements.
    * **CSS:** The styling of the line is heavily influenced by CSS properties. `line_style_` holds the `ComputedStyle`, which is the result of applying CSS rules. Specific CSS properties are referenced in methods like `GetTextAlign()`, `TextAlignLast()`, `white-space`, `text-indent`, and ruby-related properties.
    * **JavaScript:** While `line_info.cc` is C++, JavaScript interacts with the rendering engine through the DOM API. Changes to the DOM or CSS via JavaScript will eventually trigger layout calculations that utilize `LineInfo`. There isn't direct interaction *within* this file, but it's part of the process triggered by JavaScript actions.

5. **Look for Logic and Reasoning:** Identify conditional logic (if/else statements, switches) and how decisions are made. For example, the `ComputeNeedsAccurateEndPosition()` method uses a `switch` statement based on `text-align` and `text-align-last` to determine if extra calculations are needed. The `ComputeTrailingSpaceWidth()` function has complex logic to handle different whitespace collapsing scenarios and the `white-space` CSS property.

6. **Consider Potential Errors:** Think about situations where incorrect usage or unexpected input could lead to issues. For example, if the `InlineItemsData` is corrupted or doesn't match the actual content, calculations based on indices and offsets could be wrong. CSS properties with unexpected values could also lead to unusual or incorrect layout.

7. **Structure the Explanation:** Organize the findings into logical sections like "Functionality," "Relation to Web Technologies," "Logic and Reasoning," and "Potential Errors."  Use clear and concise language. Provide specific examples where possible.

8. **Review and Refine:**  Read through the explanation to ensure accuracy and completeness. Check for any ambiguities or areas that could be explained more clearly.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `LineInfo` directly manipulates the DOM. **Correction:** Realized it's a data structure primarily for *layout* calculations, not DOM manipulation. The DOM is the input, not directly modified here.
* **Initial thought:** Focus heavily on individual member variables. **Correction:** Shifted focus to the *interaction* of member variables within the methods to understand the overall functionality.
* **Struggling with "logic and reasoning":**  Initially just listed the methods. **Correction:**  Deeper dive into *why* certain calculations are done, focusing on the conditional logic and CSS property dependencies. The examples in the comments of the code (like the ruby examples) are valuable clues.
* **Overlooking potential errors:** Initially focused only on code-level errors. **Correction:** Expanded to consider user/developer errors related to CSS properties that could affect the layout process.

By following these steps, including the self-correction, a comprehensive and accurate analysis of the `line_info.cc` file can be produced.
这个文件 `blink/renderer/core/layout/inline/line_info.cc` 的主要功能是**存储和管理关于文本行布局的信息**。它定义了一个名为 `LineInfo` 的类，该类包含了在执行内联布局时构建和管理单行所需的所有关键数据。

以下是 `LineInfo` 类的具体功能分解，并解释了它与 JavaScript、HTML 和 CSS 的关系：

**`LineInfo` 类的主要功能：**

1. **存储行内元素的结果 (Results):**
   - `results_`:  这是一个存储 `InlineItemResult` 对象的容器。`InlineItemResult` 描述了行中每个内联元素（例如文本、图片、内联块等）的布局信息，包括其尺寸、位置、偏移量等。
   - **与 HTML 关系:** 行中的每个 `InlineItemResult` 通常对应于 HTML 结构中的一个内联元素或一段文本。例如，`<span>text</span>` 中的 "text" 会作为一个 `InlineItemResult` 存储。
   - **与 CSS 关系:** CSS 样式会影响 `InlineItemResult` 中存储的布局信息。例如，`font-size` 会影响文本的尺寸，`margin` 会影响元素之间的间距。

2. **关联内联元素数据 (Items Data):**
   - `items_data_`: 指向 `InlineItemsData` 对象的指针。 `InlineItemsData` 包含了所有内联元素的原始信息，例如文本内容、标签信息等。
   - **与 HTML 关系:** `InlineItemsData` 基于解析后的 HTML 结构创建。
   - **与 JavaScript 关系:** JavaScript 可以通过 DOM API 修改 HTML 结构和 CSS 样式，从而间接影响 `InlineItemsData` 的内容。

3. **存储行样式 (Line Style):**
   - `line_style_`: 指向 `ComputedStyle` 对象的指针。 `ComputedStyle` 包含了应用于该行的所有 CSS 属性的计算值。
   - **与 CSS 关系:** `line_style_` 直接反映了应用于该行的 CSS 样式，包括字体、颜色、行高、文本对齐方式等。
   - **与 JavaScript 关系:** JavaScript 可以通过修改元素的 `style` 属性或操作 CSS 类来改变应用于该行的样式。

4. **存储断行信息 (Break Token):**
   - `break_token_`: 指向 `InlineBreakToken` 对象的指针。`InlineBreakToken` 描述了该行的断点，例如由于换行符、自动换行等原因导致的断行。
   - `parallel_flow_break_tokens_`: 存储并行流（例如多列布局）中的断行信息。
   - **与 CSS 关系:** `white-space` 属性、`word-break` 属性等会影响断行的行为。
   - **与 HTML 关系:** `<br>` 标签会强制断行。

5. **存储块级内联元素的结果 (Block in Inline Layout Result):**
   - `block_in_inline_layout_result_`: 存储块级内联元素的布局信息。
   - **与 CSS 关系:** `display: inline-block` 的元素会涉及到这种布局。

6. **存储行的尺寸和位置信息:**
   - `available_width_`: 可用于该行的宽度。
   - `width_`: 该行的实际宽度。
   - `hang_width_`: 悬挂空格的宽度。
   - `text_indent_`: 文本缩进。
   - `start_`: 该行的起始位置。
   - `end_item_index_`: 该行结束的 `InlineItem` 的索引。
   - `end_offset_for_justify_`: 用于两端对齐的结束偏移量。

7. **存储文本对齐和方向信息:**
   - `text_align_`: 文本对齐方式（左对齐、右对齐、居中、两端对齐等）。
   - `base_direction_`: 文本的基本方向（从左到右或从右到左）。
   - **与 CSS 关系:** `text-align` 和 `direction` 属性控制这些值。

8. **存储其他布尔标记:**
   - `use_first_line_style_`: 是否使用第一行样式（用于 `::first-line` 伪元素）。
   - `is_last_line_`: 是否是最后一个行。
   - `has_forced_break_`: 是否有强制断行。
   - `is_empty_line_`: 是否是空行。
   - `has_line_even_if_empty_`: 即使为空也需要生成行（例如，包含浮动元素）。
   - `is_block_in_inline_`: 是否包含块级内联元素。
   - `has_overflow_`: 是否溢出。
   - `has_trailing_spaces_`: 是否有尾随空格。
   - `needs_accurate_end_position_`: 是否需要精确的结束位置（例如，用于某些对齐方式）。
   - `is_ruby_base_`, `is_ruby_text_`: 是否是 ruby 注音的基准文本或注音文本。
   - `may_have_text_combine_or_ruby_item_`: 是否可能包含文本组合或 ruby 注音元素。
   - `may_have_ruby_overhang_`: 是否可能有 ruby 注音溢出。
   - `allow_hang_for_alignment_`: 是否允许为了对齐而悬挂。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 当浏览器解析到一段包含文本的 `<div>` 元素时，内联布局过程会为每一行文本创建一个 `LineInfo` 对象。
* **CSS:** 如果 `<div>` 元素的 CSS 样式中设置了 `text-align: center;`，那么该 `LineInfo` 对象的 `text_align_` 成员变量会被设置为 `ETextAlign::kCenter`。
* **JavaScript:** 如果 JavaScript 代码动态地修改了 `<div>` 元素的文本内容，或者通过修改 CSS 样式（例如使用 `element.style.textAlign = 'right';`），那么在重新布局时，相关的 `LineInfo` 对象会被更新，以反映这些变化。

**逻辑推理的假设输入与输出:**

假设输入一个包含 "Hello World" 文本的 `<span>` 元素，其 CSS 样式为 `font-size: 16px;`：

* **假设输入:**
    * HTML: `<span>Hello World</span>`
    * CSS: `span { font-size: 16px; }`
* **逻辑推理 (在 `LineInfo` 内部或相关的布局逻辑中):**
    * 测量 "Hello World" 在 16px 字体下的宽度。
    * 创建一个 `LineInfo` 对象。
    * 将 "Hello World" 对应的 `InlineItemResult` 对象添加到 `results_` 中，其中包含了计算出的宽度和偏移量。
    * 将 `line_style_` 指向包含 `font-size: 16px` 信息的 `ComputedStyle` 对象。
* **可能的输出 (部分 `LineInfo` 成员变量的值):**
    * `results_` 包含一个 `InlineItemResult` 对象，其 `inline_size` 对应于 "Hello World" 在 16px 下的宽度。
    * `line_style_->font_size()` 返回 16px。
    * `width_` 的值等于 "Hello World" 的宽度。

**涉及用户或编程常见的使用错误，请举例说明:**

1. **CSS 属性冲突导致意外布局:**
   - **错误:** 用户可能同时设置了 `text-align: justify;` 和 `white-space: nowrap;`。
   - **后果:**  两端对齐可能无法生效，因为 `nowrap` 阻止了文本的换行，导致只有一行，无法进行两端对齐的空格调整。`LineInfo` 中的 `text_align_` 会是 `kJustify`，但实际布局效果可能不是用户期望的。

2. **JavaScript 动态修改内容导致布局抖动:**
   - **错误:** JavaScript 代码频繁地修改元素的文本内容或 CSS 样式，导致浏览器需要不断地重新计算布局。
   - **后果:**  每次重新布局都会涉及到 `LineInfo` 对象的创建和更新，如果操作过于频繁，会导致页面性能下降和视觉上的抖动。

3. **未考虑不同语言和书写方向的影响:**
   - **错误:**  开发者可能没有考虑到多语言支持，例如在只考虑从左到右书写的情况下编写布局代码。
   - **后果:** 对于从右到左书写的语言（例如阿拉伯语、希伯来语），`LineInfo` 中的 `base_direction_` 会是 `TextDirection::kRtl`，如果布局代码没有正确处理这种情况，可能会导致文本显示错误或截断。

4. **错误的 HTML 结构导致布局混乱:**
   - **错误:**  嵌套了不恰当的内联元素或块级元素。
   - **后果:** 可能导致 `LineInfo` 对象生成不符合预期的行，例如，本应该在一行的文本被分割到多行，或者内联元素的垂直对齐出现问题。

总之，`line_info.cc` 中定义的 `LineInfo` 类是 Blink 渲染引擎中处理文本行布局的核心数据结构，它承载了布局计算的关键信息，并与 HTML 结构、CSS 样式以及 JavaScript 的动态修改密切相关。理解 `LineInfo` 的功能有助于开发者更好地理解浏览器的布局过程，并避免一些常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/line_info.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

namespace blink {

namespace {
inline bool IsHangingSpace(UChar c) {
  return c == kSpaceCharacter || Character::IsOtherSpaceSeparator(c);
}

wtf_size_t GlyphCount(const InlineItemResult& item_result) {
  if (item_result.shape_result) {
    return item_result.shape_result->NumGlyphs();
  } else if (item_result.layout_result) {
    return 1;
  } else if (item_result.IsRubyColumn()) {
    wtf_size_t count = 0;
    for (const auto& nested_result :
         item_result.ruby_column->base_line.Results()) {
      count += GlyphCount(nested_result);
    }
    return count;
  }
  return 0;
}

}  // namespace

void LineInfo::Trace(Visitor* visitor) const {
  visitor->Trace(results_);
  visitor->Trace(items_data_);
  visitor->Trace(line_style_);
  visitor->Trace(break_token_);
  visitor->Trace(parallel_flow_break_tokens_);
  visitor->Trace(block_in_inline_layout_result_);
}

void LineInfo::Reset() {
  items_data_ = nullptr;
  line_style_ = nullptr;
  results_.Shrink(0);

  bfc_offset_ = BfcOffset();

  break_token_ = nullptr;
  parallel_flow_break_tokens_.Shrink(0);

  block_in_inline_layout_result_ = nullptr;

  available_width_ = LayoutUnit();
  width_ = LayoutUnit();
  hang_width_ = LayoutUnit();
  text_indent_ = LayoutUnit();

  annotation_block_start_adjustment_ = LayoutUnit();
  initial_letter_box_block_start_adjustment_ = LayoutUnit();
  initial_letter_box_block_size_ = LayoutUnit();

  start_ = {0, 0};
  end_item_index_ = 0;
  end_offset_for_justify_ = 0;

  text_align_ = ETextAlign::kLeft;
  base_direction_ = TextDirection::kLtr;

  use_first_line_style_ = false;
  is_last_line_ = false;
  has_forced_break_ = false;
  is_empty_line_ = false;
  has_line_even_if_empty_ = false;
  is_block_in_inline_ = false;
  has_overflow_ = false;
  has_trailing_spaces_ = false;
  needs_accurate_end_position_ = false;
  is_ruby_base_ = false;
  is_ruby_text_ = false;
  may_have_text_combine_or_ruby_item_ = false;
  may_have_ruby_overhang_ = false;
  allow_hang_for_alignment_ = false;
}

void LineInfo::SetLineStyle(const InlineNode& node,
                            const InlineItemsData& items_data,
                            bool use_first_line_style) {
  use_first_line_style_ = use_first_line_style;
  items_data_ = &items_data;
  const LayoutBox* box = node.GetLayoutBox();
  line_style_ = box->Style(use_first_line_style_);
  needs_accurate_end_position_ = ComputeNeedsAccurateEndPosition();

  // Reset block start offset related members.
  annotation_block_start_adjustment_ = LayoutUnit();
  initial_letter_box_block_start_adjustment_ = LayoutUnit();
  initial_letter_box_block_size_ = LayoutUnit();
}

ETextAlign LineInfo::GetTextAlign(bool is_last_line) const {
  if (is_ruby_base_)
    return ETextAlign::kJustify;

  if (is_ruby_text_) {
    ETextAlign text_align = LineStyle().GetTextAlign();
    ERubyAlign ruby_align = LineStyle().RubyAlign();
    if ((ruby_align == ERubyAlign::kSpaceAround &&
         (text_align == ComputedStyleInitialValues::InitialTextAlign() ||
          text_align == ETextAlign::kJustify)) ||
        ruby_align == ERubyAlign::kSpaceBetween) {
      return ETextAlign::kJustify;
    }
  }

  return LineStyle().GetTextAlign(is_last_line);
}

bool LineInfo::ComputeNeedsAccurateEndPosition() const {
  // Some 'text-align' values need accurate end position. At this point, we
  // don't know if this is the last line or not, and thus we don't know whether
  // 'text-align' is used or 'text-align-last' is used.
  switch (GetTextAlign()) {
    case ETextAlign::kStart:
      break;
    case ETextAlign::kEnd:
    case ETextAlign::kCenter:
    case ETextAlign::kWebkitCenter:
    case ETextAlign::kJustify:
      return true;
    case ETextAlign::kLeft:
    case ETextAlign::kWebkitLeft:
      if (IsRtl(BaseDirection()))
        return true;
      break;
    case ETextAlign::kRight:
    case ETextAlign::kWebkitRight:
      if (IsLtr(BaseDirection()))
        return true;
      break;
  }
  ETextAlignLast align_last = LineStyle().TextAlignLast();
  if (is_ruby_base_) {
    // See LayoutRubyBase::TextAlignmentForLine().
    align_last = ETextAlignLast::kJustify;
  } else if (is_ruby_text_ &&
             align_last == ComputedStyleInitialValues::InitialTextAlignLast()) {
    // See LayoutRubyText::TextAlignmentForLine().
    align_last = ETextAlignLast::kJustify;
  }
  switch (align_last) {
    case ETextAlignLast::kStart:
    case ETextAlignLast::kAuto:
      return false;
    case ETextAlignLast::kEnd:
    case ETextAlignLast::kCenter:
    case ETextAlignLast::kJustify:
      return true;
    case ETextAlignLast::kLeft:
      if (IsRtl(BaseDirection()))
        return true;
      break;
    case ETextAlignLast::kRight:
      if (IsLtr(BaseDirection()))
        return true;
      break;
  }
  return false;
}

unsigned LineInfo::InflowStartOffset() const {
  for (const auto& item_result : Results()) {
    const InlineItem& item = *item_result.item;
    if ((item.Type() == InlineItem::kText ||
         item.Type() == InlineItem::kControl ||
         item.Type() == InlineItem::kAtomicInline) &&
        item.Length() > 0) {
      return item_result.StartOffset();
    } else if (item_result.IsRubyColumn()) {
      const LineInfo& base_line = item_result.ruby_column->base_line;
      unsigned start_offset = base_line.InflowStartOffset();
      if (start_offset != base_line.EndTextOffset()) {
        return start_offset;
      }
    }
  }
  return EndTextOffset();
}

InlineItemTextIndex LineInfo::End() const {
  if (GetBreakToken()) {
    return GetBreakToken()->Start();
  }
  if (end_item_index_ && end_item_index_ < ItemsData().items.size()) {
    return {end_item_index_, ItemsData().items[end_item_index_].StartOffset()};
  }
  return ItemsData().End();
}

unsigned LineInfo::EndTextOffset() const {
  if (GetBreakToken()) {
    return GetBreakToken()->StartTextOffset();
  }
  if (end_item_index_ && end_item_index_ < ItemsData().items.size()) {
    return ItemsData().items[end_item_index_].StartOffset();
  }
  return ItemsData().text_content.length();
}

unsigned LineInfo::InflowEndOffsetInternal(bool skip_forced_break) const {
  for (const auto& item_result : base::Reversed(Results())) {
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;
    if (skip_forced_break) {
      if (item.Type() == InlineItem::kControl &&
          ItemsData().text_content[item.StartOffset()] == kNewlineCharacter) {
        continue;
      } else if (item.Type() == InlineItem::kText && item.Length() == 0) {
        continue;
      }
    }
    if (item.Type() == InlineItem::kText ||
        item.Type() == InlineItem::kControl ||
        item.Type() == InlineItem::kAtomicInline) {
      return item_result.EndOffset();
    } else if (item_result.IsRubyColumn()) {
      const LineInfo& base_line = item_result.ruby_column->base_line;
      unsigned end_offset =
          base_line.InflowEndOffsetInternal(skip_forced_break);
      if (end_offset != base_line.StartOffset()) {
        return end_offset;
      }
    }
  }
  return StartOffset();
}

bool LineInfo::GlyphCountIsGreaterThan(wtf_size_t limit) const {
  wtf_size_t count = 0;
  for (const auto& item_result : Results()) {
    count += GlyphCount(item_result);
    if (count > limit) {
      return true;
    }
  }
  return false;
}

bool LineInfo::ShouldHangTrailingSpaces() const {
  if (RuntimeEnabledFeatures::
          HangingWhitespaceDoesNotDependOnAlignmentEnabled()) {
    return true;
  }
  if (!HasTrailingSpaces()) {
    return false;
  }
  if (!line_style_->ShouldWrapLine()) {
    return false;
  }
  switch (text_align_) {
    case ETextAlign::kStart:
    case ETextAlign::kJustify:
      return true;
    case ETextAlign::kEnd:
    case ETextAlign::kCenter:
    case ETextAlign::kWebkitCenter:
      return false;
    case ETextAlign::kLeft:
    case ETextAlign::kWebkitLeft:
      return IsLtr(BaseDirection());
    case ETextAlign::kRight:
    case ETextAlign::kWebkitRight:
      return IsRtl(BaseDirection());
  }
  NOTREACHED();
}

bool LineInfo::IsHyphenated() const {
  for (const InlineItemResult& item_result : base::Reversed(Results())) {
    if (item_result.Length()) {
      return item_result.is_hyphenated;
    }
  }
  return false;
}

void LineInfo::UpdateTextAlign() {
  text_align_ = GetTextAlign(IsLastLine());

  if (RuntimeEnabledFeatures::
          HangingWhitespaceDoesNotDependOnAlignmentEnabled()) {
    allow_hang_for_alignment_ = true;

    if (HasTrailingSpaces()) {
      hang_width_ = ComputeTrailingSpaceWidth(&end_offset_for_justify_);
      return;
    }

    hang_width_ = LayoutUnit();
  } else {
    allow_hang_for_alignment_ = false;

    if (HasTrailingSpaces() && line_style_->ShouldWrapLine()) {
      if (ShouldHangTrailingSpaces()) {
        hang_width_ = ComputeTrailingSpaceWidth(&end_offset_for_justify_);
        allow_hang_for_alignment_ = true;
        return;
      }
      hang_width_ = ComputeTrailingSpaceWidth();
    }
  }

  if (text_align_ == ETextAlign::kJustify)
    end_offset_for_justify_ = InflowEndOffset();
}

LayoutUnit LineInfo::ComputeTrailingSpaceWidth(unsigned* end_offset_out) const {
  if (!has_trailing_spaces_) {
    if (end_offset_out)
      *end_offset_out = InflowEndOffset();
    return LayoutUnit();
  }

  LayoutUnit trailing_spaces_width;
  for (const auto& item_result : base::Reversed(Results())) {
    DCHECK(item_result.item);
    const InlineItem& item = *item_result.item;

    // If this item is opaque to whitespace collapsing, whitespace before this
    // item maybe collapsed. Keep looking for previous items.
    if (item.EndCollapseType() == InlineItem::kOpaqueToCollapsing) {
      continue;
    }
    // These items should be opaque-to-collapsing.
    DCHECK(item.Type() != InlineItem::kFloating &&
           item.Type() != InlineItem::kOutOfFlowPositioned &&
           item.Type() != InlineItem::kBidiControl);

    LayoutUnit trailing_item_width;
    bool will_continue = false;

    unsigned end_offset = item_result.EndOffset();
    DCHECK(end_offset);

    if (item.Type() == InlineItem::kControl ||
        item_result.has_only_pre_wrap_trailing_spaces) {
      trailing_item_width = item_result.inline_size;
      will_continue = true;
    } else if (item.Type() == InlineItem::kText) {
      // The last text item may contain trailing spaces if this is a last line,
      // has a forced break, or is 'white-space: pre'.

      if (!item_result.Length()) {
        DCHECK(!item_result.inline_size);
        continue;  // Skip empty items. See `LineBreaker::HandleEmptyText`.
      }
      const String& text = items_data_->text_content;
      if (end_offset && IsHangingSpace(text[end_offset - 1])) {
        do {
          --end_offset;
        } while (end_offset > item_result.StartOffset() &&
                 IsHangingSpace(text[end_offset - 1]));

        // If all characters in this item_result are spaces, check next item.
        if (end_offset == item_result.StartOffset()) {
          trailing_item_width = item_result.inline_size;
          will_continue = true;
        } else {
          // To compute the accurate width, we need to reshape if |end_offset|
          // is not safe-to-break. We avoid reshaping in this case because the
          // cost is high and the difference is subtle for the purpose of this
          // function.
          // TODO(kojii): Compute this without |CreateShapeResult|.
          DCHECK_EQ(item.Direction(), BaseDirection());
          ShapeResult* shape_result =
              item_result.shape_result->CreateShapeResult();
          float end_position = shape_result->PositionForOffset(
              end_offset - shape_result->StartIndex());
          if (IsRtl(BaseDirection())) {
            trailing_item_width = LayoutUnit(end_position);
          } else {
            trailing_item_width =
                LayoutUnit(shape_result->Width() - end_position);
          }
        }
      }
    }

    if (trailing_item_width &&
        RuntimeEnabledFeatures::
            HangingWhitespaceDoesNotDependOnAlignmentEnabled()) {
      switch (item.Style()->GetWhiteSpaceCollapse()) {
        case WhiteSpaceCollapse::kCollapse:
        case WhiteSpaceCollapse::kPreserveBreaks:
          trailing_spaces_width += trailing_item_width;
          break;
        case WhiteSpaceCollapse::kPreserve:
          if (item.Style()->ShouldWrapLine()) {
            if (!trailing_spaces_width && (HasForcedBreak() || IsLastLine())) {
              // Conditional hang: only the part of the trailing spaces that
              // overflow the line actually hang.
              // https://drafts.csswg.org/css-text-4/#conditionally-hang
              LayoutUnit item_end = width_ - trailing_spaces_width;
              LayoutUnit actual_hang_width =
                  std::min(trailing_item_width, item_end - available_width_)
                      .ClampNegativeToZero();
              if (actual_hang_width != trailing_item_width) {
                will_continue = false;
              }
              trailing_spaces_width += actual_hang_width;
            } else {
              trailing_spaces_width += trailing_item_width;
            }
            break;
          }
          // Cases with text-wrap other than nowrap fall are handled just like
          // break-spaces.
          [[fallthrough]];
        case WhiteSpaceCollapse::kBreakSpaces:
          // We don't hang.
          if (will_continue) {
            // TODO(abotella): Does this check out for RTL?
            end_offset = item.EndOffset();
            will_continue = false;
          }
      }
    } else {
      trailing_spaces_width += trailing_item_width;
    }

    if (!will_continue) {
      if (end_offset_out) {
        *end_offset_out = end_offset;
      }
      return trailing_spaces_width;
    }
  }

  // An empty line, or only trailing spaces.
  if (end_offset_out)
    *end_offset_out = StartOffset();
  return trailing_spaces_width;
}

LayoutUnit LineInfo::ComputeWidth() const {
  LayoutUnit inline_size = TextIndent();
  for (const InlineItemResult& item_result : Results()) {
    inline_size += item_result.inline_size;
  }

  return inline_size;
}

#if DCHECK_IS_ON()
float LineInfo::ComputeWidthInFloat() const {
  float inline_size = TextIndent();
  for (const InlineItemResult& item_result : Results()) {
    inline_size += item_result.inline_size.ToFloat();
  }

  return inline_size;
}
#endif

// Block start adjustment and annotation ovreflow
//
//  Ruby without initial letter[1][2]:
//                  RUBY = annotation overflow and block start adjustment
//          This is line has ruby.
//
//  Raise/Sunken[3]: initial_letter_block_start > 0
//   block start adjustment
//        ***** ^
//          *   | block start adjustment
//          *   V
//          *       RUBY = not annotation overflow
//          *   his line has ruby.
//
//   Drop + Ruby(over)[4]: initial_letter_block_start == 0
//                  RUBY = annotation overflow and block start adjustment
//        ***** his line has ruby.
//          *
//          *
//          *
//          *
//
//  Ruby(over) is taller than initial letter[5]:
//                  RUBY = annotation overflow
//        *****     RUBY ^
//          *       RUBY | block start adjustment
//          *       RUBY |
//          *       RUBY V
//          *    his line has ruby.
//
//  Ruby(under) and raise/Sunken[6]:
//        ***** ^
//          *   | block start adjustment
//          *   V
//          *   his line has under ruby.
//          *       RUBY
//
//  Ruby(under) and drop[7]:
//               his line has under ruby
//        ******     RUBY
//          *
//          *
//
// [1] fast/ruby/ruby-position-modern-japanese-fonts.html
// [2] https://wpt.live/css/css-ruby/line-spacing.html
// [3]
// https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-raise-over-ruby.html
// [4]
// https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-drop-over-ruby.html
// [5]
// https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-raise-over-ruby.html
// [6]
// https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-raise-under-ruby.html
// [7]
// https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-drop-under-ruby.html

LayoutUnit LineInfo::ComputeAnnotationBlockOffsetAdjustment() const {
  if (annotation_block_start_adjustment_ < 0) {
    // Test[1] or `ruby-position:under` reach here.
    // [1] https://wpt.live/css/css-ruby/line-spacing.html
    return annotation_block_start_adjustment_ +
           initial_letter_box_block_start_adjustment_;
  }
  // The raise/sunken initial letter may cover annotations[2].
  // [2]
  // https://wpt.live/css/css-inline/initial-letter/initial-letter-block-position-raise-over-ruby.html
  return std::max(annotation_block_start_adjustment_ -
                      initial_letter_box_block_start_adjustment_,
                  LayoutUnit());
}

LayoutUnit LineInfo::ComputeBlockStartAdjustment() const {
  if (annotation_block_start_adjustment_ < 0) {
    // Test[1] or `ruby-position:under` reaches here.
    // [1] https://wpt.live/css/css-ruby/line-spacing.html
    return annotation_block_start_adjustment_ +
           initial_letter_box_block_start_adjustment_;
  }
  // The raise/sunken initial letter may cover annotations[2].
  // [2]
  // https://wpt.live/css/css-initial-letter/initial-letter-block-position-raise-over-ruby.html
  return std::max(annotation_block_start_adjustment_,
                  initial_letter_box_block_start_adjustment_);
}

LayoutUnit LineInfo::ComputeInitialLetterBoxBlockStartAdjustment() const {
  if (!annotation_block_start_adjustment_)
    return LayoutUnit();
  if (annotation_block_start_adjustment_ < 0) {
    return std::min(initial_letter_box_block_start_adjustment_ +
                        annotation_block_start_adjustment_,
                    LayoutUnit());
  }
  return std::max(annotation_block_start_adjustment_ -
                      initial_letter_box_block_start_adjustment_,
                  LayoutUnit());
}

LayoutUnit LineInfo::ComputeTotalBlockSize(
    LayoutUnit line_height,
    LayoutUnit annotation_overflow_block_end) const {
  DCHECK_GE(annotation_overflow_block_end, LayoutUnit());
  const LayoutUnit line_height_with_annotation =
      line_height + annotation_block_start_adjustment_ +
      annotation_overflow_block_end;
  return std::max(initial_letter_box_block_size_, line_height_with_annotation);
}

void LineInfo::RemoveParallelFlowBreakToken(unsigned item_index) {
#if EXPENSIVE_DCHECKS_ARE_ON()
  DCHECK(std::is_sorted(parallel_flow_break_tokens_.begin(),
                        parallel_flow_break_tokens_.end(),
                        [](const auto& a, const auto& b) {
                          return a->StartItemIndex() < b->StartItemIndex();
                        }));
#endif  //  EXPENSIVE_DCHECKS_ARE_ON()
  for (auto iter = parallel_flow_break_tokens_.begin();
       iter != parallel_flow_break_tokens_.end(); ++iter) {
    const InlineBreakToken* break_token = *iter;
    DCHECK(break_token->IsInParallelBlockFlow());
    if (break_token->StartItemIndex() >= item_index) {
      const wtf_size_t index =
          static_cast<wtf_size_t>(iter - parallel_flow_break_tokens_.begin());
      parallel_flow_break_tokens_.Shrink(index);
      break;
    }
  }
}

std::ostream& operator<<(std::ostream& ostream, const LineInfo& line_info) {
  // Feel free to add more LineInfo members.
  ostream << "LineInfo available_width_=" << line_info.AvailableWidth()
          << " width_=" << line_info.Width() << " Results=[\n";
  const String& text_content = line_info.ItemsData().text_content;
  for (const auto& result : line_info.Results()) {
    ostream << result.ToString(text_content, "\t").Utf8() << "\n";
  }
  return ostream << "]";
}

}  // namespace blink

"""

```