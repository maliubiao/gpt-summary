Response:
Let's break down the thought process for analyzing this C++ source file.

1. **Understand the Goal:** The request asks for the functionality of the file `justification_utils.cc`, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common usage errors.

2. **Identify the Core Purpose:** The filename and the presence of terms like "justification," "inline," and "layout" strongly suggest this file deals with the alignment of text within a line, likely related to CSS's `text-align: justify` property.

3. **Scan for Key Data Structures and Functions:**  Look for the main functions and the data they operate on. The most prominent function is `ApplyJustification`. Other important functions are `BuildJustificationText` and `JustifyResults`. The code also uses `LineInfo`, `InlineItemResults`, `ShapeResultSpacing`, and `LogicalLineItem`. These suggest the file interacts with the internal representation of text and layout within Blink.

4. **Analyze `ApplyJustification`:** This seems to be the entry point. It takes `space` (likely extra space to distribute), `target` (for different justification contexts like SVG or Ruby), and `LineInfo`. The call to `ApplyJustificationInternal` suggests a separation of concerns. The initial checks for empty lines and overflow hint at handling edge cases.

5. **Analyze `ApplyJustificationInternal`:**
    * **`BuildJustificationText`:** This function is crucial. It constructs a string representation of the line's content specifically for justification. The comments about `kTextCombineItemMarker` (for combined text) and handling of ruby annotations are key. This shows how complex text layouts are accounted for.
    * **`ShapeResultSpacing`:** This class clearly manages the distribution of extra space. The `SetExpansion` method confirms this.
    * **`JustifyResults`:** This function iterates through the `InlineItemResults` and applies the calculated spacing using `ShapeResult::ApplySpacing`. It handles different types of inline items (text, atomic inlines, ruby).

6. **Analyze `BuildJustificationText` in Detail:**  The logic for `may_have_text_combine_or_ruby` is significant. The use of `kTextCombineItemMarker` as a placeholder for combined text and the conditional handling of ruby bases based on width are important details. This demonstrates the need to represent these complex elements correctly for justification calculations.

7. **Analyze `JustifyResults` in Detail:** The logic for applying spacing to different inline item types is important. The handling of `ShapeResult` for text, the specific spacing for `kAtomicInline` (including text combine), and the recursive call for ruby base lines are key. The adjustment of `line_text_start_offset` for ruby annotations shows how the function adapts to non-contiguous text.

8. **Analyze `ApplyLeftAndRightExpansion`:** This seems to deal with justification when there's a specific need to expand the leftmost and rightmost expandable items. The `ExpandableItemsFinder` helps locate these items.

9. **Connect to Web Technologies (CSS, HTML, JavaScript):**
    * **CSS:**  The most direct link is to `text-align: justify`. The file implements the core logic for this CSS property. Consider other related CSS like `text-combine`, and `ruby-*` properties.
    * **HTML:** The code operates on the rendered representation of HTML content. Examples involving `<p>`, `<span>`, `<ruby>`, and text combine characters would be relevant.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, JavaScript can manipulate the DOM and CSS styles that eventually lead to this justification logic being executed.

10. **Logical Reasoning and Examples:**  Think about specific scenarios and how the code would behave. For instance:
    * **Input:** A string of text with spaces and `text-align: justify`. **Output:** The same text with adjusted spacing between words.
    * **Input:** A line containing a `<ruby>` element and `text-align: justify`. **Output:** The ruby base and text will have spacing adjusted according to the algorithm.
    * **Input:** A line with a text-combine element. **Output:** The spacing around the combined text will be handled specially.

11. **Common Usage Errors (from a *developer* perspective):**  Since this is internal Blink code, "user errors" aren't directly applicable. Instead, consider potential errors in the *implementation* or how the code might interact with other parts of the engine:
    * Incorrect handling of edge cases (e.g., empty lines, lines with only whitespace).
    * Off-by-one errors in offset calculations.
    * Incorrect assumptions about the structure of `InlineItemResults`.
    * Performance issues if the justification algorithm is inefficient.

12. **Structure the Answer:**  Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning with Examples, and Potential Errors. Use clear and concise language. Provide code snippets or simplified examples where helpful.

13. **Review and Refine:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check if all parts of the request have been addressed. For instance, initially, I might not have focused enough on the `ExpandableItemsFinder` and its purpose. Reviewing the code again helps identify such omissions. Also, ensure the examples are concrete and easy to understand.

By following these steps, we can systematically analyze the C++ source file and generate a comprehensive and informative response to the request.
这个文件 `justification_utils.cc` 属于 Chromium Blink 引擎，负责处理文本的对齐方式，特别是 `text-align: justify` 属性的实现。它提供了一些工具函数来计算和应用行内元素的对齐所需的额外空间。

以下是该文件的主要功能点：

**1. 构建用于计算对齐的文本 (`BuildJustificationText`)**

* **功能:**  该函数根据行内的 `InlineItemResults` 构建一个用于计算单词间距的文本字符串。这个构建过程需要特殊处理一些复杂的内联元素，例如：
    * **`text-combine`:**  当遇到 `text-combine` 元素时，会插入一个特定的字符 (`kTextCombineItemMarker`, Hiragana Letter A) 作为占位符。这是为了确保在组合文本前后也能应用对齐间距，与旧版布局兼容。规范中建议将组合文本视为 U+FFFC，但这里为了兼容性使用了另一种方式。
    * **Ruby 注释 (`ruby`)**: 处理 `ruby` 元素比较复杂。它会根据 ruby 基础文本的宽度与 ruby 注释文本的宽度进行不同的处理。
        * 如果基础文本比注释文本宽，则会递归调用自身来处理基础文本的对齐。
        * 如果基础文本不比注释文本宽，则会插入一个对象替换字符 (`kObjectReplacementCharacter`)，将其视为单个拉丁字符。
    * **连字符 (`hyphen`)**: 如果行的最后一个单词被连字符连接，会将连字符添加到构建的文本中。
    * **换行符 (`\n`)**:  会移除行尾的换行符。

* **与 Web 技术的关系:**
    * **CSS:**  与 CSS 的 `text-combine` 和 `ruby-*` 属性密切相关。它负责处理这些特殊排版效果在 `text-align: justify` 下的对齐方式。
    * **HTML:**  操作的是 HTML 渲染后的内联元素信息。`<rtc>`, `<rb>`, `<rt>` 等标签会触发这里的逻辑。

* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        * `text_content`: "你好 world"
        * `results`: 包含 "你好" 和 "world" 两个 `InlineItemResult`
        * `line_text_start_offset`: 0
        * `end_offset`: 10 (假设 "你好 world" 占用 10 个字符位)
        * `may_have_text_combine_or_ruby`: false
    * **输出:** "你好 world"

    * **假设输入:**
        * `text_content`: "<combine>一二</combine> three" (假设 `<combine>` 表示 text-combine 元素)
        * `results`: 包含一个 text-combine 元素和一个文本 "three" 的 `InlineItemResult`
        * `line_text_start_offset`: 0
        * `end_offset`: 15
        * `may_have_text_combine_or_ruby`: true
    * **输出:** "あ three"  (其中 "あ" 代表 `kTextCombineItemMarker`)

**2. 对行内元素应用对齐 (`JustifyResults`)**

* **功能:**  该函数遍历 `InlineItemResults`，根据 `ShapeResultSpacing` 计算出的间距来调整每个行内元素的位置和大小，实现两端对齐。
    * **文本 (`shape_result`):**  对于文本内容，它会调用 `ShapeResult::ApplySpacing` 来应用计算出的单词间距。
    * **原子内联元素 (`kAtomicInline`):** 对于像 `<input>`、`<img>` 这样的原子内联元素，会直接添加计算出的间距。
    * **Ruby 注释 (`IsRubyColumn`):**  对于 ruby 注释，它会递归调用自身来处理 ruby 基础文本的对齐，并根据情况调整 ruby 注释的宽度。
    * **处理前置空格:** 跳过仅包含前置空格的 `InlineItemResult`。

* **与 Web 技术的关系:**
    * **CSS:**  直接影响 `text-align: justify` 的渲染效果。
    * **HTML:**  调整 HTML 元素在渲染树中的位置和大小。

* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        * `text_content`: "hello world"
        * `line_text`: "hello world"
        * `line_text_start_offset`: 0
        * `spacing`: 一个 `ShapeResultSpacing` 对象，计算出需要在 "hello" 和 "world" 之间添加 10px 的间距。
        * `results`: 包含 "hello" 和 "world" 两个 `InlineItemResult`，它们的 `inline_size` 初始值分别为 50px 和 40px。
    * **输出:**
        * `results` 中 "hello" 的 `inline_size` 保持 50px，但其后的间距会增加。
        * `results` 中 "world" 的 `inline_size` 保持 40px，但其 `spacing_before` 可能会增加 10px。
        * 返回值 `last_glyph_spacing` 为 0 (假设 "world" 之后没有更多文本)。

**3. 查找可扩展的元素 (`ExpandableItemsFinder`)**

* **功能:**  用于查找行内可以扩展的第一个和最后一个元素。可扩展的元素通常是具有实际内容的文本块或原子内联元素，或者是 ruby 注释的占位符。

**4. 应用左右扩展 (`ApplyLeftAndRightExpansion`)**

* **功能:**  在行首和行尾的可扩展元素上应用指定的左右扩展空间。这通常用于处理 `text-align: justify` 在首尾行的特殊情况，或者在某些布局场景下需要精确控制首尾元素的间距。

* **与 Web 技术的关系:**
    * **CSS:**  可能与一些更细粒度的文本对齐控制有关，例如处理首尾行的对齐。

**5. 主要的对齐应用函数 (`ApplyJustification` 和 `ApplyJustificationInternal`)**

* **功能:**  `ApplyJustification` 是外部调用的入口，它调用 `ApplyJustificationInternal` 来执行实际的对齐逻辑。`ApplyJustificationInternal` 负责：
    * 处理空行，空行默认左对齐。
    * 处理溢出情况，溢出的行也回退到左对齐。
    * 调用 `BuildJustificationText` 构建用于计算间距的文本。
    * 创建 `ShapeResultSpacing` 对象并设置需要扩展的空间。
    * 根据是否是 Ruby 文本进行特殊处理，例如在 Ruby 基础文本或注释文本两侧添加内边距。
    * 调用 `JustifyResults` 来应用计算出的间距。
    * 返回 Ruby 基础文本的内边距值 (如果适用)。

* **与 Web 技术的关系:**
    * **CSS:**  这是 `text-align: justify` 核心实现的一部分。

**6. 计算 Ruby 基础文本的内边距 (`ComputeRubyBaseInset`)**

* **功能:**  专门用于计算 Ruby 基础文本在两端对齐时需要的内边距。

**用户或编程常见的错误 (与该文件相关的潜在错误):**

由于这是一个底层的布局引擎代码，直接的用户错误较少。更多的是 Blink 引擎的开发者在实现或维护时可能遇到的问题：

* **字符偏移错误:** 在处理复杂的文本结构 (如 text-combine 或 ruby) 时，计算字符偏移量容易出错，导致间距应用到错误的位置。
* **对特殊字符处理不当:**  例如，没有正确处理 U+FFFC 或者 text-combine 的占位符，导致对齐效果不符合预期。
* **Ruby 对齐逻辑错误:** Ruby 的对齐规则比较复杂，可能在计算基础文本和注释文本的宽度和间距时出现错误。
* **性能问题:**  如果 `BuildJustificationText` 或 `JustifyResults` 处理大量文本时效率低下，可能会导致页面渲染性能问题。
* **与字体渲染的交互问题:**  对齐效果依赖于字体渲染的结果 (如字形宽度)，如果与字体渲染模块的交互出现问题，可能导致对齐不准确。

**举例说明编程常见的使用错误 (开发者角度):**

假设开发者在修改或扩展 `justification_utils.cc` 时：

* **错误假设 `InlineItemResults` 的顺序或内容:**  如果错误地认为 `InlineItemResults` 总是按照文本顺序排列，或者忽略了某些类型的 `InlineItemResult`，可能会导致对齐逻辑错误。
* **没有正确更新 `line_text_start_offset`:** 在处理 Ruby 注释等复杂结构时，需要正确维护 `line_text_start_offset`，否则会导致后续的间距计算基于错误的文本范围。
* **忘记处理新的内联元素类型:**  如果 Blink 引擎引入了新的内联元素类型，而 `BuildJustificationText` 或 `JustifyResults` 没有对其进行处理，可能会导致这些元素在 `text-align: justify` 下的渲染出现问题。
* **DCHECK 断言失败:** 文件中使用了大量的 `DCHECK` 进行断言检查。如果开发者引入的修改违反了这些断言，可能会在开发或测试阶段发现问题。例如，`DCHECK_EQ(shape_result->NumCharacters(), item_result.Length());` 确保了 `ShapeResult` 中的字符数与 `InlineItemResult` 的长度一致，如果这个断言失败，说明可能存在字符处理上的错误。

总而言之，`justification_utils.cc` 是 Blink 引擎中实现 `text-align: justify` 这一重要 CSS 属性的关键组成部分，它需要处理各种复杂的文本和内联元素结构，确保文本能够按照预期的两端对齐方式进行渲染。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/justification_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/justification_utils.h"

#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

constexpr UChar kTextCombineItemMarker = 0x3042;  // U+3042 Hiragana Letter A

// Build the source text for ShapeResultSpacing. This needs special handling
// for text-combine items, ruby annotations, and hyphenations.
String BuildJustificationText(const String& text_content,
                              const InlineItemResults& results,
                              unsigned line_text_start_offset,
                              unsigned end_offset,
                              bool may_have_text_combine_or_ruby) {
  if (results.empty()) {
    return String();
  }

  StringBuilder line_text_builder;
  if (may_have_text_combine_or_ruby) [[unlikely]] {
    for (const InlineItemResult& item_result : results) {
      if (item_result.StartOffset() >= end_offset) {
        break;
      }
      if (item_result.item->IsTextCombine()) {
        // To apply justification before and after the combined text, we put
        // ideographic character to increment |ShapeResultSpacing::
        // expansion_opportunity_count_| for legacy layout compatibility.
        // See "fast/writing-mode/text-combine-justify.html".
        // Note: The spec[1] says we should treat combined text as U+FFFC.
        // [1] https://drafts.csswg.org/css-writing-modes-3/#text-combine-layout
        line_text_builder.Append(kTextCombineItemMarker);
        continue;
      }
      if (item_result.IsRubyColumn()) {
        // No need to add k*IsolateCharacter for kOpenRubyColumn if
        // is_continuation is true. It is not followed by `base_line` results.
        if (!item_result.ruby_column->is_continuation) {
          line_text_builder.Append(StringView(text_content,
                                              item_result.item->StartOffset(),
                                              item_result.item->Length()));
        }
        // Add the ruby-base results only if the ruby-base is wider than its
        // ruby-text. Shorter ruby-bases produces OBJECT REPLACEMENT CHARACTER,
        // and it is treated as a single Latin character.
        if (item_result.inline_size ==
            item_result.ruby_column->base_line.Width()) {
          const LineInfo& base_line = item_result.ruby_column->base_line;
          const InlineItemResults& base_results = base_line.Results();
          if (!base_results.empty()) {
            line_text_builder.Append(BuildJustificationText(
                text_content, base_results, base_results.front().StartOffset(),
                base_line.EndOffsetForJustify(),
                base_line.MayHaveTextCombineOrRubyItem()));
          }
        } else {
          line_text_builder.Append(kObjectReplacementCharacter);
        }
        continue;
      }
      line_text_builder.Append(StringView(text_content,
                                          item_result.StartOffset(),
                                          item_result.Length()));
    }
  } else {
    line_text_builder.Append(StringView(text_content,
                                        line_text_start_offset,
                                        end_offset - line_text_start_offset));
  }

  // Append a hyphen if the last word is hyphenated. The hyphen is in
  // |ShapeResult|, but not in text. |ShapeResultSpacing| needs the text that
  // matches to the |ShapeResult|.
  DCHECK(!results.empty());
  const InlineItemResult& last_item_result = results.back();
  if (last_item_result.hyphen) {
    line_text_builder.Append(last_item_result.hyphen.Text());
  } else {
    // Remove the trailing \n.  See crbug.com/331729346.
    wtf_size_t text_length = line_text_builder.length();
    if (text_length > 0u &&
        line_text_builder[text_length - 1] == kNewlineCharacter) {
      if (text_length == 1u) {
        return String();
      }
      line_text_builder.Resize(text_length - 1);
    }
  }

  return line_text_builder.ReleaseString();
}

// This function returns spacing amount on the right of the last glyph.
// It's zero if the last item is an atomic-inline.
float JustifyResults(const String& text_content,
                     const String& line_text,
                     unsigned line_text_start_offset,
                     ShapeResultSpacing<String>& spacing,
                     InlineItemResults& results) {
  float last_glyph_spacing = 0;
  for (wtf_size_t i = 0; i < results.size(); ++i) {
    InlineItemResult& item_result = results[i];
    if (item_result.has_only_pre_wrap_trailing_spaces) {
      break;
    }
    if (item_result.shape_result) {
#if DCHECK_IS_ON()
      // This `if` is necessary for external/wpt/css/css-text/text-justify/
      // text-justify-and-trailing-spaces-*.html.
      if (item_result.StartOffset() - line_text_start_offset +
              item_result.Length() <=
          line_text.length()) {
        DCHECK_EQ(StringView(text_content, item_result.StartOffset(),
                             item_result.Length()),
                  StringView(line_text,
                             item_result.StartOffset() - line_text_start_offset,
                             item_result.Length()));
      }
#endif
      ShapeResult* shape_result = item_result.shape_result->CreateShapeResult();
      DCHECK_GE(item_result.StartOffset(), line_text_start_offset);
      DCHECK_EQ(shape_result->NumCharacters(), item_result.Length());
      last_glyph_spacing = shape_result->ApplySpacing(
          spacing, item_result.StartOffset() - line_text_start_offset -
                       shape_result->StartIndex());
      item_result.inline_size = shape_result->SnappedWidth();
      if (item_result.is_hyphenated) [[unlikely]] {
        item_result.inline_size += item_result.hyphen.InlineSize();
      }
      item_result.shape_result = ShapeResultView::Create(shape_result);
    } else if (item_result.item->Type() == InlineItem::kAtomicInline) {
      last_glyph_spacing = 0;
      float spacing_before = 0.0f;
      DCHECK_LE(line_text_start_offset, item_result.StartOffset());
      const unsigned line_text_offset =
          item_result.StartOffset() - line_text_start_offset;
      const float spacing_after =
          spacing.ComputeSpacing(line_text_offset, spacing_before);
      if (item_result.item->IsTextCombine()) [[unlikely]] {
        // |spacing_before| is non-zero if this |item_result| is after
        // non-CJK character. See "text-combine-justify.html".
        DCHECK_EQ(kTextCombineItemMarker, line_text[line_text_offset]);
        item_result.inline_size += spacing_after;
        item_result.spacing_before = LayoutUnit(spacing_before);
      } else {
        DCHECK_EQ(kObjectReplacementCharacter, line_text[line_text_offset]);
        item_result.inline_size += spacing_after;
        // |spacing_before| is non-zero only before CJK characters.
        DCHECK_EQ(spacing_before, 0.0f);
      }
    } else if (item_result.IsRubyColumn()) {
      LineInfo& base_line = item_result.ruby_column->base_line;
      if (item_result.inline_size == base_line.Width()) {
        last_glyph_spacing =
            JustifyResults(text_content, line_text, line_text_start_offset,
                           spacing, *base_line.MutableResults());
        base_line.SetWidth(base_line.AvailableWidth(),
                           base_line.ComputeWidth());
        item_result.inline_size =
            std::max(item_result.inline_size, base_line.Width());
        item_result.ruby_column->last_base_glyph_spacing =
            LayoutUnit(last_glyph_spacing);
      } else {
        last_glyph_spacing = 0;
        [[maybe_unused]] float spacing_before = 0;
        unsigned offset = item_result.StartOffset() - line_text_start_offset;
        if (!item_result.ruby_column->is_continuation) {
          // Skip k*IsolateCharacter.
          offset += item_result.item->Length();
        }
        [[maybe_unused]] const float spacing_after =
            spacing.ComputeSpacing(offset, spacing_before);
        // ShapeResultSpacing doesn't ask for adding space to OBJECT
        // REPLACEMENT CHARACTER, and asks for adding space to the next item
        // instead.
        DCHECK_EQ(spacing_before, 0.0f);
        DCHECK_EQ(spacing_after, 0.0f);
      }
      if (i + 1 < results.size()) {
        // Adjust line_text_start_offset because line_text is intermittent due
        // to ruby annotations.
        wtf_size_t next_start_offset = results[i + 1].StartOffset();
        if (item_result.inline_size == base_line.Width()) {
          // BuildJustificationText() didn't produce text for the annotation.
          line_text_start_offset +=
              next_start_offset - base_line.EndTextOffset();
        } else {
          // BuildJustificationText() produced only OBJECT REPLACEMENT
          // CHARACTER.
          line_text_start_offset +=
              next_start_offset - base_line.StartOffset() - 1;
        }
      }
    }
  }
  return last_glyph_spacing;
}

class ExpandableItemsFinder {
  STACK_ALLOCATED();

 public:
  void Find(base::span<LogicalLineItem> items) {
    for (auto& item : items) {
      if ((item.shape_result && item.shape_result->NumGlyphs() > 0) ||
          item.layout_result) {
        last_item_ = &item;
        if (!first_item_) {
          first_item_ = &item;
        }
      } else if (item.IsRubyLinePlaceholder()) {
        last_placeholder_item_ = &item;
        if (!first_placeholder_item_) {
          first_placeholder_item_ = &item;
        }
      }
    }
  }

  LogicalLineItem* FirstExpandable() const {
    return first_item_ ? first_item_ : first_placeholder_item_;
  }
  LogicalLineItem* LastExpandable() const {
    return last_item_ ? last_item_ : last_placeholder_item_;
  }

 private:
  // The first or the last LogicalLineItem which has a ShapeResult or is an
  // atomic-inline.
  LogicalLineItem* first_item_ = nullptr;
  LogicalLineItem* last_item_ = nullptr;
  // The first or the last kRubyLinePlaceholder.
  LogicalLineItem* first_placeholder_item_ = nullptr;
  LogicalLineItem* last_placeholder_item_ = nullptr;
};

void ApplyLeftAndRightExpansion(LayoutUnit left_expansion,
                                LayoutUnit right_expansion,
                                LogicalLineItem& item) {
  if (item.shape_result) {
    ShapeResult* shape_result = item.shape_result->CreateShapeResult();
    shape_result->ApplyLeadingExpansion(left_expansion);
    shape_result->ApplyTrailingExpansion(right_expansion);
    item.inline_size += left_expansion + right_expansion;
    item.shape_result = ShapeResultView::Create(shape_result);
  } else if (item.layout_result) {
    item.inline_size += left_expansion + right_expansion;
    item.rect.offset.inline_offset += left_expansion;
  } else {
    DCHECK(item.IsRubyLinePlaceholder());
    item.inline_size += left_expansion + right_expansion;
    item.margin_line_left += left_expansion;
  }
}

std::optional<LayoutUnit> ApplyJustificationInternal(
    LayoutUnit space,
    JustificationTarget target,
    const LineInfo& line_info,
    InlineItemResults* results) {
  // Empty lines should align to start.
  if (line_info.IsEmptyLine()) {
    return std::nullopt;
  }

  // Justify the end of visible text, ignoring preserved trailing spaces.
  unsigned end_offset = line_info.EndOffsetForJustify();

  // If this line overflows, fallback to 'text-align: start'.
  if (space <= 0) {
    return std::nullopt;
  }

  // Can't justify an empty string.
  if (end_offset == line_info.StartOffset()) {
    return std::nullopt;
  }

  // Note: |line_info->StartOffset()| can be different from
  // |ItemsResults[0].StartOffset()|, e.g. <b><input> <input></b> when
  // line break before space (leading space). See http://crbug.com/1240791
  const unsigned line_text_start_offset =
      line_info.Results().front().StartOffset();

  // Construct the line text to compute spacing for.
  String text_content = line_info.ItemsData().text_content;
  String line_text = BuildJustificationText(
      text_content, line_info.Results(), line_text_start_offset, end_offset,
      line_info.MayHaveTextCombineOrRubyItem());
  if (line_text.empty()) {
    return std::nullopt;
  }

  // Compute the spacing to justify.
  ShapeResultSpacing<String> spacing(line_text,
                                     target == JustificationTarget::kSvgText);
  spacing.SetExpansion(space, line_info.BaseDirection());
  const bool is_ruby = target == JustificationTarget::kRubyText ||
                       target == JustificationTarget::kRubyBase;
  if (!spacing.HasExpansion()) {
    if (is_ruby) {
      return space / 2;
    }
    return std::nullopt;
  }

  LayoutUnit inset;
  if (is_ruby) {
    unsigned count = std::min(spacing.ExpansionOppotunityCount(),
                              static_cast<unsigned>(LayoutUnit::Max().Floor()));
    // Inset the ruby base/text by half the inter-ideograph expansion amount.
    inset = space / (count + 1);
    // For ruby text,  inset it by no more than a full-width ruby character on
    // each side.
    if (target == JustificationTarget::kRubyText) {
      inset = std::min(LayoutUnit(2 * line_info.LineStyle().FontSize()), inset);
    }
    spacing.SetExpansion(space - inset, line_info.BaseDirection());
  }

  if (results) {
    DCHECK_EQ(&line_info.Results(), results);
    JustifyResults(text_content, line_text, line_text_start_offset, spacing,
                   *results);
  }
  return inset / 2;
}

}  // namespace

std::optional<LayoutUnit> ApplyJustification(LayoutUnit space,
                                             JustificationTarget target,
                                             LineInfo* line_info) {
  return ApplyJustificationInternal(space, target, *line_info,
                                    line_info->MutableResults());
}

std::optional<LayoutUnit> ComputeRubyBaseInset(LayoutUnit space,
                                               const LineInfo& line_info) {
  DCHECK(line_info.IsRubyBase());
  return ApplyJustificationInternal(space, JustificationTarget::kRubyBase,
                                    line_info, nullptr);
}

bool ApplyLeftAndRightExpansion(LayoutUnit left_expansion,
                                LayoutUnit right_expansion,
                                base::span<LogicalLineItem> items) {
  if (!left_expansion && !right_expansion) {
    return true;
  }
  ExpandableItemsFinder finder;
  finder.Find(items);
  LogicalLineItem* first_expandable = finder.FirstExpandable();
  LogicalLineItem* last_expandable = finder.LastExpandable();
  if (first_expandable && last_expandable) {
    ApplyLeftAndRightExpansion(left_expansion, LayoutUnit(), *first_expandable);
    ApplyLeftAndRightExpansion(LayoutUnit(), right_expansion, *last_expandable);
    return true;
  }
  return false;
}

}  // namespace blink
```