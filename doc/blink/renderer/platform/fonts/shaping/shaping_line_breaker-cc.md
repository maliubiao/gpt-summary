Response:
Let's break down the thought process for analyzing the `shaping_line_breaker.cc` file. The goal is to understand its functionality and its relation to web technologies.

1. **Initial Skim and Keywords:**  First, I'd quickly skim the code, looking for recognizable keywords and patterns. Things like `Copyright`, `#include`, `namespace`, class names (`ShapingLineBreaker`), function names (`ShapeLine`, `PreviousBreakOpportunity`), and comments mentioning specific browser features or standards (like UAX#14) would immediately jump out.

2. **Identify the Core Class:** The `ShapingLineBreaker` class is clearly central. The constructor gives clues about its dependencies: `ShapeResult`, `LazyLineBreakIterator`, `Hyphenation`, and `Font`. This suggests the class is responsible for breaking lines of text that have already been shaped (rendered into glyphs).

3. **Analyze the Dependencies:** Understanding the dependencies is crucial:
    * `ShapeResult`: This likely holds the results of the shaping process – glyph information, positions, etc. The comment `// Line breaking performance relies on high-performance x-position to character offset lookup.` confirms this.
    * `LazyLineBreakIterator`: This is the standard way to find potential line break points in text. It's responsible for implementing Unicode line breaking rules.
    * `Hyphenation`:  Deals with inserting hyphens to break words across lines.
    * `Font`:  Information about the font being used, needed for things like measuring space widths.

4. **Examine Key Functions:**  Focus on the most important-looking functions:
    * `ShapeLine`: This function name strongly suggests the core functionality: taking a start position and available space, and returning the shaped result for that line. The detailed comments within this function are a goldmine of information about break opportunities, safe-to-break points, and reshaping.
    * `PreviousBreakOpportunity` and `NextBreakOpportunity`:  These directly interact with the `LazyLineBreakIterator` to find valid break points. The handling of hyphenation within these functions is also noteworthy.
    * `Hyphenate`: The logic for determining where to insert hyphens.
    * `ConcatShapeResults` and `ShapeToEnd`:  Helper functions for constructing the final `ShapeResultView`.

5. **Connect to Web Technologies:** Now, consider how these functionalities relate to HTML, CSS, and JavaScript:
    * **HTML:** The input to the line breaking process is ultimately text content within HTML elements. The structure of the HTML document and its styling will influence how line breaking is performed.
    * **CSS:**  CSS properties like `width`, `white-space`, `word-break`, `hyphens`, and `text-align` directly impact the line breaking algorithm. The examples provided in the prompt are crucial for making these connections.
    * **JavaScript:** While this specific C++ code isn't directly JavaScript, JavaScript can manipulate the DOM, change CSS styles, and potentially trigger re-layout, which will then invoke this line breaking logic.

6. **Look for Logic and Assumptions:** Pay attention to the assumptions and edge cases handled:
    * **Safe-to-break points:** The concept of safe-to-break points is important for performance – avoiding unnecessary reshaping.
    * **Reshaping:**  The code explicitly handles cases where breaking at a non-safe point requires re-running the shaping process for portions of the line.
    * **Hyphenation logic:** The `ShouldHyphenate` function considers whether it's the first or last word on the line, and paragraph boundaries.
    * **Handling of spaces:** The special treatment of spaces (trailing spaces, breakable spaces) and the interaction with `BreakSpaceType` is important.
    * **Overflow:** The `is_overflow` flag indicates when a line cannot fit within the available space.
    * **Han Kerning:** The comments about `HanKerning` suggest special handling for East Asian typography.

7. **Consider Common Errors:**  Think about how developers might misuse or encounter issues related to line breaking:
    * **Incorrect `width` settings:** Leading to unexpected overflows.
    * **Conflicting CSS properties:**  `white-space` and `word-break` can have complex interactions.
    * **Forgetting about hyphenation:**  Words might unexpectedly overflow if hyphenation is not enabled or configured correctly.
    * **Dealing with non-breaking spaces:** The `&nbsp;` entity can prevent desired line breaks.

8. **Hypothesize Inputs and Outputs:** For the `ShapeLine` function, consider:
    * **Input:** Starting offset, available width, and the underlying `ShapeResult`.
    * **Output:** A `ShapeResultView` representing the shaped line, and a `Result` struct indicating the break offset, whether it's hyphenated, and if there's overflow. Consider different scenarios like breaking at a space, in the middle of a word (with hyphenation), or when the line overflows.

9. **Refine and Organize:**  Finally, organize the findings into a clear and structured explanation, addressing each part of the prompt (functionality, relationship to web technologies, logic, common errors). Use examples to illustrate the concepts.

This iterative process of skimming, analyzing dependencies, examining key functions, connecting to web technologies, and considering edge cases allows for a comprehensive understanding of the code's purpose and its role in the browser engine.
这个文件 `shaping_line_breaker.cc` 是 Chromium Blink 引擎中负责**文本断行（line breaking）**的关键组件。它的主要功能是根据给定的可用空间，在已完成 shaping (字形生成) 的文本中找到合适的断行点，以便将文本渲染到多行上。

以下是该文件的详细功能分解：

**核心功能：**

1. **查找断行机会 (Break Opportunities)：**
   - 它利用 `LazyLineBreakIterator` 来识别文本中的潜在断行点，例如空格、标点符号、连字符等。
   - 区分不同类型的断行机会，例如：
     - 可以直接断开的空格。
     - 需要插入软连字符 (`kSoftHyphenCharacter`) 才能断开的长单词。
     - 不允许断开的位置。

2. **考虑可用空间 (Available Space)：**
   - `ShapeLine` 函数是其核心，它接收可用于渲染一行的 `available_space` 参数。
   - 它尝试在不超过可用空间的前提下，找到最合适的断行点。

3. **处理文本塑形结果 (ShapeResult)：**
   - 它与 `ShapeResult` 对象紧密合作，该对象包含了文本的字形信息、位置信息等。
   - 利用 `ShapeResult` 提供的高效查找功能（例如，通过像素位置查找字符偏移量），来确定在给定宽度下对应的字符位置。

4. **处理连字符 (Hyphenation)：**
   - 如果提供了 `Hyphenation` 对象，它可以决定是否需要在单词中插入连字符来实现断行。
   - `Hyphenate` 函数负责查找合适的连字符插入位置。
   - 考虑最小词长、前缀长度和后缀长度等连字符规则。

5. **处理行首和行尾的特殊情况：**
   - **`ShouldTrimStartOfWrappedLine` 和 `ShouldTrimEnd`:**  处理行首和行尾的空格裁剪。
   - **`HanKerning`:**  处理 CJK 字符的避头尾（hanging punctuation）特性，可能需要在行首或行尾进行额外的塑形。

6. **处理自动空格 (Auto Spacing)：**
   - 考虑 `TextAutoSpace`，处理例如中英文混排时自动添加的空格，并在断行时进行相应的调整。

7. **优化性能：**
   - 缓存位置数据 (`result_->EnsurePositionData()`) 以提高查找效率。
   - 避免不必要的重新塑形 (reshaping)，只在必要时重新塑形行首或行尾的部分。
   - 利用 `CachedNextSafeToBreakOffset` 和 `CachedPreviousSafeToBreakOffset` 来快速找到不需要重新塑形的断点。

**与 JavaScript, HTML, CSS 的关系：**

该文件是浏览器渲染引擎的核心组成部分，直接影响着网页上文本的排版和显示。

* **HTML：**  `ShapingLineBreaker` 处理的是 HTML 元素中包含的文本内容。HTML 结构决定了文本的上下文和需要断行的范围。
    * **示例：** 当一个 `<div>` 元素包含一段很长的文本时，`ShapingLineBreaker` 会根据 `<div>` 的宽度来决定如何在文本中进行断行，使其能够适应容器的尺寸。

* **CSS：** CSS 样式规则直接影响 `ShapingLineBreaker` 的行为：
    * **`width`：**  元素的 `width` 属性决定了 `available_space` 的大小，这是断行算法的关键输入。
        * **示例：**  `div { width: 200px; }`  这段 CSS 会告诉 `ShapingLineBreaker` 每行的可用空间是 200 像素。
    * **`white-space`：**  控制如何处理空格和换行符。例如，`white-space: nowrap;` 会阻止断行。
        * **示例：** `p { white-space: normal; }` 允许在空格和换行符处断行。`p { white-space: pre-wrap; }` 会保留空格和换行符，并在必要时断行。
    * **`word-break`：**  指定是否允许在单词内断行以防止溢出。
        * **示例：** `span { word-break: break-all; }` 允许在任何字符之间断行，即使是在单词中间。
    * **`hyphens`：**  控制是否启用连字符。
        * **示例：** `p { hyphens: auto; }` 允许浏览器自动插入连字符。
    * **`text-align`：**  虽然不直接影响断行本身，但会影响行的对齐方式，与断行结果共同决定最终的文本布局。
    * **`text-spacing-trim`:** 控制行首和行尾的空格裁剪行为，`ShapingLineBreaker` 中有对应的处理逻辑。

* **JavaScript：** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响 `ShapingLineBreaker` 的工作。
    * **示例：** JavaScript 可以改变一个元素的 `width`，这将触发重新布局，并导致 `ShapingLineBreaker` 重新计算断行位置。
    * **示例：** JavaScript 可以添加或删除 HTML 内容，改变需要进行断行的文本。

**逻辑推理的假设输入与输出：**

假设有以下输入：

* **文本内容：** "This is a long word that might need hyphenation."
* **可用空间：** 100 像素
* **字体：**  一个等宽字体，每个字符宽度 10 像素
* **连字符设置：**  启用自动连字符，最小词长为 5

**可能的输出（取决于具体的连字符算法和实现细节）：**

```
This is a
long
word that
might need
hy-
phenation.
```

或者，如果连字符算法认为 "hyphenation" 在 "hy-" 后断开更合适：

```
This is a
long
word that
might need
hyphena-
tion.
```

**用户或编程常见的使用错误：**

1. **错误的 `width` 设置导致文本溢出：**
   - **错误示例：** CSS 中设置了过小的 `width`，导致即使断行也无法容纳所有文本。
   - **结果：** 文本超出容器边界显示。

2. **`white-space: nowrap;` 阻止断行：**
   - **错误示例：**  意外地设置了 `white-space: nowrap;`，导致文本在一行内显示，即使超出容器宽度也不换行。
   - **结果：**  文本可能水平滚动或溢出屏幕。

3. **混淆 `word-break: break-all;` 和 `overflow-wrap: break-word;`：**
   - **错误示例：**  错误地使用了 `word-break: break-all;`，导致在不必要的情况下将单词强行断开，影响可读性。
   - **结果：**  单词在任意字符处断开。

4. **忘记考虑连字符的影响：**
   - **错误示例：**  在预期需要连字符断行的情况下，没有启用连字符功能。
   - **结果：**  长单词可能导致行溢出，而不是优雅地断开。

5. **动态内容加载导致布局变化：**
   - **错误示例：**  JavaScript 动态加载内容后，没有考虑到可能需要重新计算断行，导致布局错乱。
   - **结果：**  文本的断行位置可能不正确，与其他元素重叠。

6. **不理解避头尾 (hanging punctuation) 的影响：**
   - **错误示例：**  在处理 CJK 文本时，没有理解避头尾的规则，导致标点符号出现在行首或行尾不符合排版规范。
   - **结果：**  排版不美观，可能影响阅读体验。

总而言之，`shaping_line_breaker.cc` 是 Blink 引擎中一个复杂且重要的模块，它负责将文本内容根据可用空间和各种规则进行分割，以便在网页上正确地显示多行文本。理解其功能有助于开发者更好地掌握网页排版的原理，并避免常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/shaping_line_breaker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/fonts/shaping/shaping_line_breaker.h"

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/shaping/text_auto_space.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

namespace blink {

ShapingLineBreaker::ShapingLineBreaker(
    const ShapeResult* result,
    const LazyLineBreakIterator* break_iterator,
    const Hyphenation* hyphenation,
    const Font* font)
    : result_(result),
      break_iterator_(break_iterator),
      hyphenation_(hyphenation),
      font_(font) {
  // Line breaking performance relies on high-performance x-position to
  // character offset lookup. Ensure that the desired cache has been computed.
  DCHECK(result_);
  result_->EnsurePositionData();
}

namespace {

// ShapingLineBreaker computes using visual positions. This function flips
// logical advance to visual, or vice versa.
inline LayoutUnit FlipRtl(LayoutUnit value, TextDirection direction) {
  return IsLtr(direction) ? value : -value;
}

inline bool IsBreakableSpace(UChar ch) {
  return LazyLineBreakIterator::IsBreakableSpace(ch) ||
         Character::IsOtherSpaceSeparator(ch);
}

bool IsAllSpaces(const String& text, unsigned start, unsigned end) {
  return StringView(text, start, end - start)
      .IsAllSpecialCharacters<IsBreakableSpace>();
}

bool ShouldHyphenate(const String& text,
                     unsigned word_start,
                     unsigned word_end,
                     unsigned line_start) {
  // If this is the first word in this line, allow to hyphenate. Otherwise the
  // word will overflow.
  if (word_start <= line_start)
    return true;
  // Do not hyphenate the last word in a paragraph, except when it's a single
  // word paragraph.
  if (IsAllSpaces(text, word_end, text.length()))
    return IsAllSpaces(text, 0, word_start);
  return true;
}

inline void CheckBreakOffset(unsigned offset, unsigned start, unsigned end) {
  // It is critical to move the offset forward, or LineBreaker may keep adding
  // InlineItemResult until all the memory is consumed.
  CHECK_GT(offset, start);
  // The offset must be within the given range, or LineBreaker will fail to
  // sync item with offset.
  CHECK_LE(offset, end);
}

unsigned FindNonHangableEnd(const String& text, unsigned candidate) {
  DCHECK_LT(candidate, text.length());
  DCHECK(IsBreakableSpace(text[candidate]));

  // Looking for the non-hangable run end
  unsigned non_hangable_end = candidate;
  while (non_hangable_end > 0) {
    if (!IsBreakableSpace(text[--non_hangable_end]))
      return non_hangable_end + 1;
  }
  return non_hangable_end;
}

}  // namespace

inline const String& ShapingLineBreaker::GetText() const {
  return break_iterator_->GetString();
}

inline ShapingLineBreaker::EdgeOffset ShapingLineBreaker::FirstSafeOffset(
    unsigned start) const {
  if (!IsStartOfWrappedLine(start)) {
    // When it's not at the start of a wrapped line, disable reshaping.
    return {start};
  }
  if (ShouldTrimStartOfWrappedLine(text_spacing_trim_) &&
      Character::MaybeHanKerningOpen(GetText()[start])) [[unlikely]] {
    // `HanKerning` wants to apply kerning to `kOpen` characters at the start of
    // the line. Reshape it to resolve the `SimpleFontData` and apply
    // `HanKerning` if applicable. Note, it may not actually apply, if the font
    // doesn't have features or the glyph isn't fullwidth.
    if (++start < result_->EndIndex()) {
      return {result_->CachedNextSafeToBreakOffset(start), true};
    }
    return {start, true};
  }
  return {result_->CachedNextSafeToBreakOffset(start)};
}

unsigned ShapingLineBreaker::Hyphenate(unsigned offset,
                                       unsigned word_start,
                                       unsigned word_end,
                                       bool backwards) const {
  DCHECK(hyphenation_);
  DCHECK_GT(word_end, word_start);
  DCHECK_GE(offset, word_start);
  DCHECK_LE(offset, word_end);
  unsigned word_len = word_end - word_start;
  if (word_len < hyphenation_->MinWordLength())
    return 0;

  const String& text = GetText();
  const StringView word(text, word_start, word_len);
  const unsigned word_offset = offset - word_start;
  if (backwards) {
    if (word_offset < hyphenation_->MinPrefixLength())
      return 0;
    unsigned prefix_length =
        hyphenation_->LastHyphenLocation(word, word_offset + 1);
    DCHECK(!prefix_length || prefix_length <= word_offset);
    return prefix_length;
  } else {
    if (word_len - word_offset < hyphenation_->MinSuffixLength())
      return 0;
    unsigned prefix_length = hyphenation_->FirstHyphenLocation(
        word, word_offset ? word_offset - 1 : 0);
    DCHECK(!prefix_length || prefix_length >= word_offset);
    return prefix_length;
  }
}

ShapingLineBreaker::BreakOpportunity ShapingLineBreaker::Hyphenate(
    unsigned offset,
    unsigned start,
    bool backwards) const {
  const String& text = GetText();
  unsigned word_end = break_iterator_->NextBreakOpportunity(offset);
  if (word_end != offset && IsBreakableSpace(text[word_end - 1]))
    word_end = std::max(offset, FindNonHangableEnd(text, word_end - 1));
  if (word_end == offset) {
    DCHECK(IsBreakableSpace(text[offset]) ||
           offset == break_iterator_->PreviousBreakOpportunity(offset, start));
    return {word_end, false};
  }
  unsigned previous_break_opportunity =
      break_iterator_->PreviousBreakOpportunity(offset, start);
  unsigned word_start = previous_break_opportunity;
  // Skip the leading spaces of this word because the break iterator breaks
  // before spaces.
  // TODO (jfernandez): This is no longer true, so we should remove this code.
  while (word_start < text.length() &&
         LazyLineBreakIterator::IsBreakableSpace(text[word_start]))
    word_start++;
  if (offset >= word_start &&
      ShouldHyphenate(text, previous_break_opportunity, word_end, start)) {
    unsigned prefix_length = Hyphenate(offset, word_start, word_end, backwards);
    if (prefix_length)
      return {word_start + prefix_length, true};
  }
  return {backwards ? previous_break_opportunity : word_end, false};
}

ShapingLineBreaker::BreakOpportunity
ShapingLineBreaker::PreviousBreakOpportunity(unsigned offset,
                                             unsigned start) const {
  if (hyphenation_) [[unlikely]] {
    return Hyphenate(offset, start, true);
  }

  // If the break opportunity is preceded by trailing spaces, find the
  // end of non-hangable character (i.e., start of the space run).
  const String& text = GetText();
  unsigned break_offset =
      break_iterator_->PreviousBreakOpportunity(offset, start);
  if (IsBreakableSpace(text[break_offset - 1]))
    return {break_offset, FindNonHangableEnd(text, break_offset - 1), false};

  return {break_offset, false};
}

ShapingLineBreaker::BreakOpportunity ShapingLineBreaker::NextBreakOpportunity(
    unsigned offset,
    unsigned start,
    unsigned len) const {
  if (hyphenation_) [[unlikely]] {
    return Hyphenate(offset, start, false);
  }

  // We should also find the beginning of the space run to find the
  // end of non-hangable character (i.e., start of the space run),
  // which may be useful to avoid reshaping.
  const String& text = GetText();
  unsigned break_offset = break_iterator_->NextBreakOpportunity(offset, len);
  if (IsBreakableSpace(text[break_offset - 1]))
    return {break_offset, FindNonHangableEnd(text, break_offset - 1), false};

  return {break_offset, false};
}

inline void ShapingLineBreaker::SetBreakOffset(unsigned break_offset,
                                               const String& text,
                                               Result* result) {
  result->break_offset = break_offset;
  result->is_hyphenated =
      text[result->break_offset - 1] == kSoftHyphenCharacter;
}

inline void ShapingLineBreaker::SetBreakOffset(
    const BreakOpportunity& break_opportunity,
    const String& text,
    Result* result) {
  result->break_offset = break_opportunity.offset;
  result->is_hyphenated =
      break_opportunity.is_hyphenated ||
      text[result->break_offset - 1] == kSoftHyphenCharacter;
  result->non_hangable_run_end = break_opportunity.non_hangable_run_end;
}

// Shapes a line of text by finding a valid and appropriate break opportunity
// based on the shaping results for the entire paragraph. Re-shapes the start
// and end of the line as needed.
//
// Definitions:
//   Candidate break opportunity: Ideal point to break, disregarding line
//                                breaking rules. May be in the middle of a word
//                                or inside a ligature.
//    Valid break opportunity:    A point where a break is allowed according to
//                                the relevant breaking rules.
//    Safe-to-break:              A point where a break may occur without
//                                affecting the rendering or metrics of the
//                                text. Breaking at safe-to-break point does not
//                                require reshaping.
//
// For example:
//   Given the string "Line breaking example", an available space of 100px and a
//   mono-space font where each glyph is 10px wide.
//
//   Line breaking example
//   |        |
//   0       100px
//
//   The candidate (or ideal) break opportunity would be at an offset of 10 as
//   the break would happen at exactly 100px in that case.
//   The previous valid break opportunity though is at an offset of 5.
//   If we further assume that the font kerns with space then even though it's a
//   valid break opportunity reshaping is required as the combined width of the
//   two segments "Line " and "breaking" may be different from "Line breaking".
const ShapeResultView* ShapingLineBreaker::ShapeLine(
    unsigned start,
    LayoutUnit available_space,
    ShapingLineBreaker::Result* result_out) {
  DCHECK_GE(available_space, LayoutUnit(0));
  const unsigned range_start = result_->StartIndex();
  const unsigned range_end = result_->EndIndex();
  DCHECK_GE(start, range_start);
  DCHECK_LT(start, range_end);
  result_out->is_overflow = false;
  result_out->is_hyphenated = false;
  result_out->has_trailing_spaces = false;
  const String& text = GetText();
  const bool is_break_after_any_space =
      break_iterator_->BreakSpace() == BreakSpaceType::kAfterEverySpace;

  // The start position in the original shape results.
  const LayoutUnit start_position =
      result_->CachedPositionForOffset(start - range_start);

  // If the start offset is not at a safe-to-break boundary, the content between
  // the start and the next safe-to-break boundary needs to be reshaped.
  const ShapeResult* line_start_result = nullptr;
  const TextDirection direction = result_->Direction();
  const EdgeOffset first_safe = FirstSafeOffset(start);
  DCHECK_GE(first_safe.offset, start);
  if (first_safe.offset != start) [[unlikely]] {
    const LayoutUnit first_safe_position =
        result_->CachedPositionForOffset(first_safe.offset - range_start);
    line_start_result = Shape(
        start, first_safe.offset,
        {.is_line_start = true, .han_kerning_start = first_safe.han_kerning});
    // Adjust the available space to take the reshaping into account.
    const LayoutUnit old_width =
        FlipRtl(first_safe_position - start_position, direction);
    if (const LayoutUnit diff = old_width - line_start_result->SnappedWidth()) {
      available_space = std::max(available_space + diff, LayoutUnit());
    }
  }

  // Find a candidate break opportunity by identifying the last offset before
  // exceeding the available space and the determine the closest valid break
  // preceding the candidate.
  const LayoutUnit end_position =
      start_position + FlipRtl(available_space, direction);
  DCHECK_GE(FlipRtl(end_position - start_position, direction), LayoutUnit(0));
  unsigned candidate_break =
      result_->CachedOffsetForPosition(end_position) + range_start;
  if (candidate_break < range_end &&
      result_->HasAutoSpacingAfter(candidate_break)) [[unlikely]] {
    // If there's an auto-space after the `candidate_break`, check if it can fit
    // without the auto-space.
    candidate_break = result_->AdjustOffsetForAutoSpacing(
        TextAutoSpace::GetSpacingWidth(font_), candidate_break, end_position);
  }

  // Extend the `candidate_break` if the next character can fit by applying the
  // `HanKerning` at the line end.
  unsigned last_safe;
  const ShapeResult* line_end_result = nullptr;
  if (candidate_break < range_end && ShouldTrimEnd(text_spacing_trim_) &&
      Character::MaybeHanKerningClose(text[candidate_break])) [[unlikely]] {
    const unsigned adjusted_candidate_break = candidate_break + 1;
    if (break_iterator_->IsBreakable(adjusted_candidate_break)) {
      last_safe = result_->CachedPreviousSafeToBreakOffset(candidate_break);
      line_end_result =
          Shape(last_safe, adjusted_candidate_break, {.han_kerning_end = true});
      const LayoutUnit last_safe_position =
          result_->CachedPositionForOffset(last_safe - range_start);
      const LayoutUnit width_to_last_safe =
          FlipRtl(last_safe_position - start_position, direction);
      if (width_to_last_safe + line_end_result->Width() <= available_space) {
        candidate_break = adjusted_candidate_break;
      } else {
        line_end_result = nullptr;
      }
    }
  }

  if (candidate_break >= range_end) {
    // The |result_| does not have glyphs to fill the available space,
    // and thus unable to compute. Return the result up to range_end.
    DCHECK_EQ(candidate_break, range_end);
    SetBreakOffset(range_end, text, result_out);
    return ShapeToEnd(start, line_start_result, first_safe.offset, range_start,
                      range_end);
  }

  // candidate_break should be >= start, but rounding errors can chime in when
  // comparing floats. See ShapeLineZeroAvailableWidth on Linux/Mac.
  candidate_break = std::max(candidate_break, start);

  // If we are in the middle of a trailing space sequence, which are
  // defined by the UAX#14 spec as Break After (A) class, we should
  // look for breaking opportunityes after the end of the sequence.
  // https://www.unicode.org/reports/tr14/#BA
  // TODO(jfernandez): if break-spaces, do special handling.
  BreakOpportunity break_opportunity;
  const bool use_previous_break_opportunity =
      !IsBreakableSpace(text[candidate_break]) || is_break_after_any_space;
  if (use_previous_break_opportunity) {
    break_opportunity = PreviousBreakOpportunity(candidate_break, start);

    // Overflow if there are no break opportunity before candidate_break.
    // Find the next break opportunity after the candidate_break.
    // TODO: (jfernandez): Maybe also non_hangable_run_end <= start ?
    result_out->is_overflow = break_opportunity.offset <= start;
    if (result_out->is_overflow) {
      DCHECK(use_previous_break_opportunity);
      if (no_result_if_overflow_) {
        return nullptr;
      }
      // No need to scan past range_end for a break opportunity.
      break_opportunity = NextBreakOpportunity(
          std::max(candidate_break, start + 1), start, range_end);
    }
  } else {
    break_opportunity = NextBreakOpportunity(
        std::max(candidate_break, start + 1), start, range_end);
    DCHECK_GT(break_opportunity.offset, start);
    DCHECK(!result_out->is_overflow);

    // If we were looking for a next break opportunity and found one that is
    // after candidate_break but doesn't have a corresponding non-hangable run
    // that spans to at least candidate_break, that would be an overflow.
    // However, there might still be break opportunities before candidate_break
    // that we haven't checked, so we look for them first.
    if (break_opportunity.offset > candidate_break &&
        (!break_opportunity.non_hangable_run_end ||
         *break_opportunity.non_hangable_run_end > candidate_break)) {
      BreakOpportunity previous_opportunity =
          PreviousBreakOpportunity(candidate_break, start);
      if (previous_opportunity.offset > start) {
        break_opportunity = previous_opportunity;
      } else {
        result_out->is_overflow = true;
        if (no_result_if_overflow_) {
          return nullptr;
        }
      }
    }

    // We don't care whether this result contains only spaces if we
    // are breaking after any space. We shouldn't early return either
    // in that case.
    DCHECK(!is_break_after_any_space);
    DCHECK(IsBreakableSpace(text[candidate_break]));
    if (break_opportunity.non_hangable_run_end &&
        break_opportunity.non_hangable_run_end <= start) {
      // TODO (jfenandez): There may be cases where candidate_break is
      // not a breakable space but we also want to early return for
      // triggering the trailing spaces handling
      result_out->has_trailing_spaces = true;
      result_out->break_offset = std::min(range_end, break_opportunity.offset);
      result_out->non_hangable_run_end = break_opportunity.non_hangable_run_end;
#if DCHECK_IS_ON()
      DCHECK(IsAllSpaces(text, start, result_out->break_offset));
#endif
      result_out->is_hyphenated = false;
      return ShapeResultView::Create(result_, start, result_out->break_offset);
    }
  }

  bool reshape_line_end = !line_end_result;
  // |range_end| may not be a break opportunity, but this function cannot
  // measure beyond it.
  if (break_opportunity.offset >= range_end) {
    SetBreakOffset(range_end, text, result_out);
    if (result_out->is_overflow) {
      return ShapeToEnd(start, line_start_result, first_safe.offset,
                        range_start, range_end);
    }
    break_opportunity.offset = range_end;
    // Avoid re-shape if at the end of the range.
    // eg. <span>abc</span>def ghi
    // then `range_end` is at the end of the `<span>`, while break opportunity
    // is at the space.
    reshape_line_end = false;
    if (break_opportunity.non_hangable_run_end &&
        range_end < break_opportunity.non_hangable_run_end) {
      break_opportunity.non_hangable_run_end = std::nullopt;
    }
    if (IsBreakableSpace(text[range_end - 1])) {
      break_opportunity.non_hangable_run_end =
          FindNonHangableEnd(text, range_end - 1);
    }
  }

  // We may have options that imply avoiding re-shape.
  // Note: we must evaluate the need of re-shaping the end of the line, before
  // we consider the non-hangable-run-end.
  if (dont_reshape_end_if_at_space_ && reshape_line_end) {
    // If the actual offset is in a breakable-space sequence, we may need to run
    // the re-shape logic and consider the non-hangable-run-end.
    reshape_line_end = !IsBreakableSpace(text[break_opportunity.offset - 1]);
  }

  // Use the non-hanable-run end as breaking offset (unless we break after eny
  // space)
  if (!is_break_after_any_space && break_opportunity.non_hangable_run_end) {
    break_opportunity.offset =
        std::max(start + 1, *break_opportunity.non_hangable_run_end);
  }
  CheckBreakOffset(break_opportunity.offset, start, range_end);

  // If there are no safe-to-break between the start and the break opportunity,
  // reshape the whole range.
  if (first_safe.offset >= break_opportunity.offset) [[unlikely]] {
    DCHECK_NE(first_safe.offset, start);
    SetBreakOffset(break_opportunity, text, result_out);
    CheckBreakOffset(result_out->break_offset, start, range_end);
    return ShapeResultView::Create(Shape(
        start, break_opportunity.offset,
        {.is_line_start = true, .han_kerning_start = first_safe.han_kerning}));
  }
  DCHECK_GE(first_safe.offset, start);
  DCHECK_LE(first_safe.offset, break_opportunity.offset);

  if (reshape_line_end) {
    // If the previous valid break opportunity is not at a safe-to-break
    // boundary reshape between the safe-to-break offset and the valid break
    // offset. If the resulting width exceeds the available space the
    // preceding boundary is tried until the available space is sufficient.
    while (true) {
      DCHECK_LE(start, break_opportunity.offset);
      if (!is_break_after_any_space && break_opportunity.non_hangable_run_end) {
        break_opportunity.offset =
            std::max(start + 1, *break_opportunity.non_hangable_run_end);
      }
      last_safe =
          result_->CachedPreviousSafeToBreakOffset(break_opportunity.offset);
      // No need to reshape the line end because this opportunity is safe.
      if (last_safe == break_opportunity.offset)
        break;
      if (last_safe > break_opportunity.offset) [[unlikely]] {
        // TODO(crbug.com/1787026): This should not happen, but we see crashes.
        NOTREACHED();
      }

      // Moved the opportunity back enough to require reshaping the whole line.
      if (last_safe < first_safe.offset) [[unlikely]] {
        DCHECK(last_safe == 0 || last_safe < start);
        last_safe = start;
        line_start_result = nullptr;
      }

      // If previously determined to let it overflow, reshape the line end.
      DCHECK_LE(break_opportunity.offset, range_end);
      if (result_out->is_overflow) [[unlikely]] {
        line_end_result = Shape(last_safe, break_opportunity.offset);
        break;
      }

      // Check if this opportunity can fit after reshaping the line end.
      const LayoutUnit safe_position =
          result_->CachedPositionForOffset(last_safe - range_start);
      line_end_result = Shape(last_safe, break_opportunity.offset);
      if (line_end_result->Width() <=
          FlipRtl(end_position - safe_position, direction))
        break;

      // Doesn't fit after the reshape. Try the previous break opportunity.
      line_end_result = nullptr;
      break_opportunity =
          PreviousBreakOpportunity(break_opportunity.offset - 1, start);
      if (break_opportunity.offset > start)
        continue;

      // No suitable break opportunity, not exceeding the available space,
      // found. Any break opportunities beyond candidate_break won't fit
      // either because the ShapeResult has the full context.
      // This line will overflow, but there are multiple choices to break,
      // because none can fit. The one after candidate_break is better for
      // ligatures, but the one before is better for kernings.
      result_out->is_overflow = true;
      // TODO (jfernandez): Would be possible to refactor this logic
      // with the one performed prior tp the reshape
      // (FindBreakingOpportuntty() + overflow handling)?
      break_opportunity = PreviousBreakOpportunity(candidate_break, start);
      if (break_opportunity.offset <= start) {
        break_opportunity = NextBreakOpportunity(
            std::max(candidate_break, start + 1), start, range_end);
        if (break_opportunity.offset >= range_end) {
          SetBreakOffset(range_end, text, result_out);
          return ShapeToEnd(start, line_start_result, first_safe.offset,
                            range_start, range_end);
        }
      }
      // Loop once more to compute last_safe for the new break opportunity.
    }
  }

  if (!line_end_result) {
    last_safe = break_opportunity.offset;
    DCHECK_GT(last_safe, start);
    if (result_->HasAutoSpacingBefore(last_safe)) [[unlikely]] {
      last_safe = result_->CachedPreviousSafeToBreakOffset(last_safe - 1);
      DCHECK_LT(last_safe, break_opportunity.offset);
      line_end_result =
          result_->UnapplyAutoSpacing(TextAutoSpace::GetSpacingWidth(font_),
                                      last_safe, break_opportunity.offset);
    }
  }

  // It is critical to move forward, or callers may end up in an infinite loop.
  CheckBreakOffset(break_opportunity.offset, start, range_end);
  DCHECK_GE(break_opportunity.offset, last_safe);
  DCHECK_EQ(
      break_opportunity.offset - start,
      (line_start_result ? line_start_result->NumCharacters() : 0) +
          (last_safe > first_safe.offset ? last_safe - first_safe.offset : 0) +
          (line_end_result ? line_end_result->NumCharacters() : 0));
  SetBreakOffset(break_opportunity, text, result_out);

  // Create shape results for the line by copying from the re-shaped result (if
  // reshaping was needed) and the original shape results.
  return ConcatShapeResults(start, break_opportunity.offset, first_safe.offset,
                            last_safe, line_start_result, line_end_result);
}
const ShapeResultView* ShapingLineBreaker::ConcatShapeResults(
    unsigned start,
    unsigned end,
    unsigned first_safe,
    unsigned last_safe,
    const ShapeResult* line_start_result,
    const ShapeResult* line_end_result) {
  ShapeResultView::Segment segments[3];
  constexpr unsigned max_length = std::numeric_limits<unsigned>::max();
  unsigned count = 0;
  if (line_start_result) {
    segments[count++] = {line_start_result, 0, max_length};
  }
  if (last_safe > first_safe) {
    segments[count++] = {result_, first_safe, last_safe};
  }
  if (line_end_result) {
    segments[count++] = {line_end_result, last_safe, max_length};
  }
  auto* line_result = ShapeResultView::Create({&segments[0], count});
  DCHECK_EQ(end - start, line_result->NumCharacters());
  return line_result;
}

// Shape from the specified offset to the end of the ShapeResult.
// If |start| is safe-to-break, this copies the subset of the result.
const ShapeResultView* ShapingLineBreaker::ShapeToEnd(
    unsigned start,
    const ShapeResult* line_start_result,
    unsigned first_safe,
    unsigned range_start,
    unsigned range_end) {
  DCHECK(result_);
  DCHECK_EQ(range_start, result_->StartIndex());
  DCHECK_EQ(range_end, result_->EndIndex());
  DCHECK_GE(start, range_start);
  DCHECK_LT(start, range_end);
  DCHECK_GE(first_safe, start);

  // If |start| is safe-to-break, no reshape is needed.
  if (!line_start_result) {
    DCHECK_EQ(first_safe, start);
    // If |start| is at the start of the range the entire result object may be
    // reused, which avoids the sub-range logic and bounds computation.
    if (start == range_start) {
      return ShapeResultView::Create(result_);
    }
    return ShapeResultView::Create(result_, start, range_end);
  }
  DCHECK_NE(first_safe, start);

  // If no safe-to-break offset is found in range, reshape the entire range.
  if (first_safe >= range_end) [[unlikely]] {
    return ShapeResultView::Create(line_start_result, start, range_end);
  }

  // Otherwise reshape to |first_safe|, then copy the rest.
  ShapeResultView::Segment segments[2] = {
      {line_start_result, 0, std::numeric_limits<unsigned>::max()},
      {result_, first_safe, range_end}};
  return ShapeResultView::Create(segments);
}

const ShapeResultView* ShapingLineBreaker::ShapeLineAt(unsigned start,
                                                       unsigned end) {
  DCHECK_GT(end, start);

  const EdgeOffset first_safe = FirstSafeOffset(start);
  DCHECK_GE(first_safe.offset, start);
  const ShapeResult* line_start_result = nullptr;
  if (first_safe.offset != start) {
    const ShapeOptions options{.is_line_start = true,
                               .han_kerning_start = first_safe.han_kerning};
    if (first_safe.offset >= end) {
      // There is no safe-to-break, reshape the whole range.
      return ShapeResultView::Create(Shape(start, end, options));
    }
    line_start_result = Shape(start, first_safe.offset, options);
  }

  unsigned last_safe;
  const ShapeResult* line_end_result = nullptr;
  if (dont_reshape_end_if_at_space_ && IsBreakableSpace(GetText()[end - 1])) {
    last_safe = end;
  } else {
    last_safe = result_->CachedPreviousSafeToBreakOffset(end);
    DCHECK_GE(last_safe, first_safe.offset);
    if (last_safe != end) {
      line_end_result = Shape(last_safe, end);
    }
  }

  return ConcatShapeResults(start, end, first_safe.offset, last_safe,
                            line_start_result, line_end_result);
}

}  // namespace blink

"""

```