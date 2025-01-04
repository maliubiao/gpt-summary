Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:**  The filename itself is a huge clue: `shaping_line_breaker_test.cc`. This immediately tells us the file is testing something related to "shaping" and "line breaking."  The `_test.cc` suffix confirms it's a unit test file.

2. **Examine the Includes:** The `#include` directives provide crucial context. We see:
    * Core Blink/Chromium headers: `Font.h`, `FontCache.h`, `TextRun.h`, `TextBreakIterator.h`, etc. This solidifies the focus on text rendering and layout.
    * Testing frameworks: `gmock/gmock.h`, `gtest/gtest.h`. This is standard for C++ testing in Chromium.
    * Specific shaping headers: `ShapingLineBreaker.h`, `ShapeResultTestInfo.h`, `ShapeResultView.h`. This confirms the file directly tests the `ShapingLineBreaker` class.
    * `unicode/uscript.h`: Indicates involvement with Unicode text processing.

3. **Analyze the Test Fixture:** The `ShapingLineBreakerTest` class inherits from `FontTestBase`. This strongly suggests the tests will involve creating and manipulating fonts. The `SetUp` method confirms this by initializing a `FontDescription`. The `SelectLucidaFont` function shows a specific font can be targeted for testing.

4. **Look for Test Cases (TEST_F):**  The `TEST_F` macros define individual test cases. Let's examine some of them:
    * `ShapeLineLatin`: The name suggests testing line breaking with Latin text. The test sets up a string, a `LazyLineBreakIterator`, a `HarfBuzzShaper`, and then creates a `HarfBuzzShapingLineBreaker`. It then calls `ShapeLine` with different available widths and checks the `break_offset`. This is clearly testing the core line breaking logic.
    * `ShapeLineLatinMultiLine`: Similar to the above, but likely focusing on cases where the text spans multiple lines.
    * `ShapeLineLatinBreakAll`:  This probably tests the `LineBreakType::kBreakAll` mode, where breaks can occur even within words.
    * `ShapeLineZeroAvailableWidth`:  Tests how the line breaker behaves when there's no space available.
    * `ShapeLineRangeEndMidWord`: Focuses on line breaking at the end of a specified range, possibly in the middle of a word.
    * `ShapeLineWithLucidaFont`: Tests line breaking with a specific font (`Lucida Grande`), likely checking for font-specific behaviors or ligatures.
    * `HanKerningCloseUnsafe`: This test name points to a very specific scenario involving Han characters, kerning, and "unsafe" break points. This suggests handling of complex script requirements.
    * `BreakOpportunityTest`:  This is a parameterized test using `INSTANTIATE_TEST_SUITE_P`, indicating it will run the same test logic with multiple sets of input data. The `Next` and `Previous` sub-tests likely check how the line breaker finds the next and previous valid break points.

5. **Identify Key Classes Under Test:** The primary class under test is clearly `ShapingLineBreaker`. The code also uses `HarfBuzzShaper` (a shaper library) and `LazyLineBreakIterator` (for identifying potential break points).

6. **Infer Functionality:** Based on the test cases and the classes involved, we can infer the following functionality of `ShapingLineBreaker`:
    * Determines where to break lines of text given a certain available width.
    * Uses a `LazyLineBreakIterator` to find potential break points (spaces, hyphens, etc.).
    * Uses a shaper (`HarfBuzzShaper`) to measure the width of text segments.
    * Handles different line breaking rules (e.g., `kNormal`, `kBreakAll`).
    * Considers font properties and potentially language-specific rules.
    * Can find the next and previous valid break opportunities.
    * Handles cases with zero available width.
    * Considers "unsafe" break points where breaking might be undesirable.

7. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  The core purpose of line breaking is to render text content correctly within the bounds of HTML elements. The tests simulate scenarios that would occur when laying out text in a web page.
    * **CSS:** The "available space" parameter in `ShapeLine` directly relates to CSS properties like `width`, `max-width`, and the width of the containing block. CSS `word-break` and `overflow-wrap` properties influence how line breaking occurs, and the `LineBreakType` enum hints at this.
    * **JavaScript:** While this test file is C++, JavaScript can indirectly influence line breaking. For instance, JavaScript can dynamically change the content of an element or its CSS styles, which in turn triggers the line breaking logic tested here.

8. **Identify Potential User/Programming Errors:** The tests themselves hint at potential errors:
    * Providing incorrect available width.
    * Not understanding the different line breaking modes (`kNormal` vs. `kBreakAll`).
    * Issues with complex scripts or specific fonts where the line breaking might not behave as expected.

9. **Analyze the Logic and Examples:** For specific tests like `HanKerningCloseUnsafe`, try to understand the specific conditions being tested (Han character, kerning, unsafe break). The parameterized tests in `BreakOpportunityTest` provide concrete examples of input strings and expected break positions. This helps understand the logic of finding break points.

10. **Structure the Answer:** Organize the findings logically, starting with a summary of the file's purpose, then detailing the functionality, relationships to web technologies, error scenarios, and specific examples. Use clear headings and bullet points to improve readability.

By following these steps, we can systematically analyze the C++ test file and extract the required information, even without being a daily Chromium/Blink developer. The key is to leverage the available clues: filename, includes, test names, and the structure of the test cases.
这个文件 `shaping_line_breaker_test.cc` 是 Chromium Blink 引擎中负责测试 `ShapingLineBreaker` 类的单元测试文件。`ShapingLineBreaker` 的主要功能是 **确定文本在给定可用空间内的换行位置**。它考虑了各种因素，例如：

* **单词边界:**  尽量在单词之间换行。
* **标点符号:**  通常允许在标点符号后换行。
* **连字符:**  允许在软连字符处换行。
* **CJK 字符:**  对于中文、日文、韩文等，通常可以在每个字符后换行。
* **`word-break` 和 `overflow-wrap` CSS 属性:**  这些 CSS 属性会影响换行的行为，例如 `break-all` 允许在任何字符之间换行。

**具体功能列举：**

1. **测试基本的拉丁文本换行:**  验证在拉丁字母组成的文本中，`ShapingLineBreaker` 能否正确识别单词边界并进行换行。
2. **测试多行换行:** 验证当文本需要分成多行显示时，`ShapingLineBreaker` 能否正确计算每一行的结束位置。
3. **测试 `break-all` 换行模式:**  模拟 CSS 中 `word-break: break-all;` 的行为，允许在任意字符间换行。
4. **测试可用空间为零的情况:**  验证当没有可用空间时，`ShapingLineBreaker` 如何处理，通常会强制在尽可能早的位置换行。
5. **测试在单词中间指定范围结束的情况:** 验证当给定的文本范围在单词中间结束时，`ShapingLineBreaker` 的行为。
6. **测试使用特定字体的换行:** 使用 `Lucida Grande` 字体进行测试，可能用于验证特定字体下字形的宽度和换行行为。
7. **测试韩文 Kerning 和不安全换行点:** 针对韩文等复杂文字，测试在有字距调整（kerning）且存在不安全换行点的情况下，`ShapingLineBreaker` 的处理逻辑。不安全换行点指的是某些位置虽然语法上可以换行，但视觉上可能会不太美观。
8. **测试查找下一个和上一个换行机会:** 验证 `NextBreakOpportunity` 和 `PreviousBreakOpportunity` 方法，用于查找给定位置之后或之前的有效换行点。
9. **测试禁用软连字符时的换行行为:** 验证在禁用软连字符时，`ShapingLineBreaker` 是否会忽略软连字符作为换行点。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`ShapingLineBreaker` 位于 Blink 渲染引擎的核心部分，它直接参与了浏览器如何将 HTML 结构和 CSS 样式转换为屏幕上的像素。

* **HTML:**  `ShapingLineBreaker` 处理的是 HTML 文档中的文本内容。当浏览器需要渲染一段文本时，`ShapingLineBreaker` 会被用来确定文本应该如何断行以适应容器的宽度。
    * **例子:** 考虑一个 `<div>` 元素，其 CSS `width` 属性被设置为 `200px`。当该 `<div>` 中包含一段很长的文本时，`ShapingLineBreaker` 会计算出哪些位置可以换行，以保证文本在 `200px` 的宽度内完整显示。

* **CSS:**  CSS 的文本相关属性直接影响 `ShapingLineBreaker` 的行为。
    * **例子 (word-break):**  如果 CSS 设置了 `word-break: break-all;`，那么 `ShapingLineBreaker` 在计算换行位置时，就会采用 “break-all” 的策略，即使在单词中间也会断开。该测试文件中的 `ShapeLineLatinBreakAll` 测试就模拟了这种情况。
    * **例子 (overflow-wrap):**  CSS 的 `overflow-wrap: break-word;` (或 `word-wrap: break-word;`)  会影响 `ShapingLineBreaker` 在单词过长无法在正常单词边界换行时的行为，它会强制在单词内部进行换行。
    * **例子 (white-space):** `white-space` 属性，如 `nowrap`，会阻止 `ShapingLineBreaker` 进行换行。
    * **例子 (font-family, font-size):**  `ShapingLineBreaker` 需要知道文本所使用的字体和字号，才能准确计算文本的宽度并进行换行。该测试文件中创建 `Font` 对象就体现了这一点。

* **JavaScript:**  JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响 `ShapingLineBreaker` 的工作。
    * **例子:**  一个 JavaScript 脚本可能会动态地改变一个 `<div>` 元素的 `width` 属性。当宽度改变时，浏览器会重新触发布局，`ShapingLineBreaker` 会根据新的宽度重新计算换行位置。
    * **例子:**  JavaScript 也可能动态地修改元素的文本内容，这同样会导致 `ShapingLineBreaker` 重新计算换行。

**逻辑推理的假设输入与输出：**

以 `TEST_F(ShapingLineBreakerTest, ShapeLineLatin)` 为例：

**假设输入：**

* **文本内容:** "Test run with multiple words and breaking opportunities."
* **可用空间 (LayoutUnit):**  例如，`first4->SnappedWidth()`，这个宽度足够容纳 "Test run with multiple" 这部分文本。
* **起始偏移量 (unsigned):** 0，表示从文本的开头开始。
* **字体 (Font):**  使用默认字体或在 `SetUp` 中设置的字体。
* **换行迭代器 (LazyLineBreakIterator):**  根据文本和语言创建，用于识别潜在的换行点。

**预期输出：**

* **换行偏移量 (break_offset):** 22，对应 "multiple" 单词后的空格位置。
* **ShapeResultView 的宽度 (line->SnappedWidth()):**  与 `first4->SnappedWidth()` 相等，因为提供的可用空间足够容纳到该换行点。

**用户或编程常见的使用错误举例：**

1. **错误地假设所有空格都是换行点:**  `ShapingLineBreaker` 会考虑语言规则和 CSS 属性，并非所有空格都一定是换行点。例如，不间断空格 (`&nbsp;`) 就不会被作为换行点。
    * **例子:** 用户可能在 HTML 中使用了大量的 `&nbsp;` 来控制文本布局，结果可能导致文本超出容器边界，因为 `ShapingLineBreaker` 不会在这些位置换行。

2. **没有考虑 CSS 的 `word-break` 和 `overflow-wrap` 属性:** 开发者可能认为默认的换行行为就足够了，但没有考虑到在某些情况下需要强制断词或允许长单词溢出。
    * **例子:**  一个很长的 URL 或技术术语如果没有空格或连字符，在默认情况下可能不会换行，导致布局问题。开发者需要在 CSS 中使用 `word-break: break-all;` 或 `overflow-wrap: break-word;` 来解决这个问题。

3. **字体加载失败或使用了错误的字体:** `ShapingLineBreaker` 的计算依赖于字体的字形信息。如果字体加载失败或者使用了与预期不同的字体，可能会导致错误的换行结果。
    * **例子:**  开发者在 CSS 中指定了一个用户设备上不存在的字体，浏览器可能会回退到默认字体，这可能导致文本的宽度和换行位置与开发者预期不符。

4. **在 JavaScript 中手动计算换行位置并与浏览器的行为不一致:**  开发者可能尝试在 JavaScript 中自行实现文本换行逻辑，但由于浏览器内部的 `ShapingLineBreaker` 考虑了复杂的规则和优化，手动实现的逻辑很可能与浏览器的行为不一致，导致跨浏览器或不同版本浏览器上的显示差异。

总而言之，`shaping_line_breaker_test.cc` 文件通过各种测试用例，确保 Blink 引擎中的文本换行逻辑能够正确、高效地工作，并且能够处理各种复杂的文本和布局场景，最终保证网页文本在不同设备和浏览器上的正确渲染。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/shaping_line_breaker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/shaping_line_breaker.h"

#include <unicode/uscript.h>
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_test_utilities.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

class HarfBuzzShapingLineBreaker : public ShapingLineBreaker {
  STACK_ALLOCATED();

 public:
  HarfBuzzShapingLineBreaker(const HarfBuzzShaper* shaper,
                             const Font* font,
                             const ShapeResult* result,
                             const LazyLineBreakIterator* break_iterator,
                             const Hyphenation* hyphenation)
      : ShapingLineBreaker(result, break_iterator, hyphenation, font),
        shaper_(shaper),
        font_(font) {}

 protected:
  ShapeResult* Shape(unsigned start, unsigned end, ShapeOptions options) final {
    return shaper_->Shape(font_, GetShapeResult().Direction(), start, end);
  }

  const HarfBuzzShaper* shaper_;
  const Font* font_;
};

const ShapeResultView* ShapeLine(ShapingLineBreaker* breaker,
                                 unsigned start_offset,
                                 LayoutUnit available_space,
                                 unsigned* break_offset) {
  ShapingLineBreaker::Result result;
  const ShapeResultView* shape_result =
      breaker->ShapeLine(start_offset, available_space, &result);
  *break_offset = result.break_offset;
  return shape_result;
}

}  // namespace

class ShapingLineBreakerTest : public FontTestBase {
 protected:
  void SetUp() override {
    font_description.SetComputedSize(12.0);
  }

  void SelectLucidaFont() {
    font_description.SetFamily(
        FontFamily(AtomicString("Lucida Grande"), FontFamily::Type::kFamilyName,
                   SharedFontFamily::Create(AtomicString("Lucida Medium"),
                                            FontFamily::Type::kFamilyName)));
  }

  void TearDown() override {}

  // Compute all break positions by |NextBreakOpportunity|.
  Vector<unsigned> BreakPositionsByNext(const ShapingLineBreaker& breaker,
                                        const String& string) {
    Vector<unsigned> break_positions;
    for (unsigned i = 0; i <= string.length(); i++) {
      unsigned next =
          breaker.NextBreakOpportunity(i, 0, string.length()).offset;
      if (break_positions.empty() || break_positions.back() != next)
        break_positions.push_back(next);
    }
    return break_positions;
  }

  // Compute all break positions by |PreviousBreakOpportunity|.
  Vector<unsigned> BreakPositionsByPrevious(const ShapingLineBreaker& breaker,
                                            const String& string) {
    Vector<unsigned> break_positions;
    for (unsigned i = string.length(); i; i--) {
      unsigned previous = breaker.PreviousBreakOpportunity(i, 0).offset;
      if (previous &&
          (break_positions.empty() || break_positions.back() != previous))
        break_positions.push_back(previous);
    }
    break_positions.Reverse();
    return break_positions;
  }

  FontCachePurgePreventer font_cache_purge_preventer;
  FontDescription font_description;
};

TEST_F(ShapingLineBreakerTest, ShapeLineLatin) {
  Font font(font_description);

  String string = To16Bit(
      "Test run with multiple words and breaking "
      "opportunities.");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kNormal);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // "Test run with multiple"
  const ShapeResult* first4 = shaper.Shape(&font, direction, 0, 22);
  ASSERT_LT(first4->SnappedWidth(), result->SnappedWidth());

  // "Test run with"
  const ShapeResult* first3 = shaper.Shape(&font, direction, 0, 13);
  ASSERT_LT(first3->SnappedWidth(), first4->SnappedWidth());

  // "Test run"
  const ShapeResult* first2 = shaper.Shape(&font, direction, 0, 8);
  ASSERT_LT(first2->SnappedWidth(), first3->SnappedWidth());

  // "Test"
  const ShapeResult* first1 = shaper.Shape(&font, direction, 0, 4);
  ASSERT_LT(first1->SnappedWidth(), first2->SnappedWidth());

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  const ShapeResultView* line = nullptr;
  unsigned break_offset = 0;

  // Test the case where the entire string fits.
  line = ShapeLine(&breaker, 0, result->SnappedWidth(), &break_offset);
  EXPECT_EQ(56u, break_offset);  // After the end of the string.
  EXPECT_EQ(result->SnappedWidth(), line->SnappedWidth());

  // Test cases where we break between words.
  line = ShapeLine(&breaker, 0, first4->SnappedWidth(), &break_offset);
  EXPECT_EQ(22u, break_offset);  // Between "multiple" and " words"
  EXPECT_EQ(first4->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first4->SnappedWidth() + 10, &break_offset);
  EXPECT_EQ(22u, break_offset);  // Between "multiple" and " words"
  EXPECT_EQ(first4->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first4->SnappedWidth() - 1, &break_offset);
  EXPECT_EQ(13u, break_offset);  // Between "width" and "multiple"
  EXPECT_EQ(first3->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first3->SnappedWidth(), &break_offset);
  EXPECT_EQ(13u, break_offset);  // Between "width" and "multiple"
  EXPECT_EQ(first3->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first3->SnappedWidth() - 1, &break_offset);
  EXPECT_EQ(8u, break_offset);  // Between "run" and "width"
  EXPECT_EQ(first2->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first2->SnappedWidth(), &break_offset);
  EXPECT_EQ(8u, break_offset);  // Between "run" and "width"
  EXPECT_EQ(first2->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first2->SnappedWidth() - 1, &break_offset);
  EXPECT_EQ(4u, break_offset);  // Between "Test" and "run"
  EXPECT_EQ(first1->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 0, first1->SnappedWidth(), &break_offset);
  EXPECT_EQ(4u, break_offset);  // Between "Test" and "run"
  EXPECT_EQ(first1->SnappedWidth(), line->SnappedWidth());

  // Test the case where we cannot break earlier.
  line = ShapeLine(&breaker, 0, first1->SnappedWidth() - 1, &break_offset);
  EXPECT_EQ(4u, break_offset);  // Between "Test" and "run"
  EXPECT_EQ(first1->SnappedWidth(), line->SnappedWidth());
}

TEST_F(ShapingLineBreakerTest, ShapeLineLatinMultiLine) {
  Font font(font_description);

  String string = To16Bit("Line breaking test case.");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kNormal);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  const ShapeResult* first = shaper.Shape(&font, direction, 0, 4);
  const ShapeResult* mid_third = shaper.Shape(&font, direction, 0, 16);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  unsigned break_offset = 0;

  ShapeLine(&breaker, 0, result->SnappedWidth() - 1, &break_offset);
  EXPECT_EQ(18u, break_offset);

  ShapeLine(&breaker, 0, first->SnappedWidth(), &break_offset);
  EXPECT_EQ(4u, break_offset);

  ShapeLine(&breaker, 0, mid_third->SnappedWidth(), &break_offset);
  EXPECT_EQ(13u, break_offset);

  ShapeLine(&breaker, 13u, mid_third->SnappedWidth(), &break_offset);
  EXPECT_EQ(24u, break_offset);
}

TEST_F(ShapingLineBreakerTest, ShapeLineLatinBreakAll) {
  Font font(font_description);

  String string = To16Bit("Testing break type-break all.");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kBreakAll);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  const ShapeResult* midpoint = shaper.Shape(&font, direction, 0, 16);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  const ShapeResultView* line;
  unsigned break_offset = 0;

  line = ShapeLine(&breaker, 0, midpoint->SnappedWidth(), &break_offset);
  EXPECT_EQ(16u, break_offset);
  EXPECT_EQ(midpoint->SnappedWidth(), line->SnappedWidth());

  line = ShapeLine(&breaker, 16u, result->SnappedWidth(), &break_offset);
  EXPECT_EQ(29u, break_offset);
  EXPECT_GE(midpoint->SnappedWidth(), line->SnappedWidth());
}

TEST_F(ShapingLineBreakerTest, ShapeLineZeroAvailableWidth) {
  Font font(font_description);

  String string(u"Testing overflow line break.");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kNormal);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  unsigned break_offset = 0;
  LayoutUnit zero(0);

  ShapeLine(&breaker, 0, zero, &break_offset);
  EXPECT_EQ(7u, break_offset);

  ShapeLine(&breaker, 8, zero, &break_offset);
  EXPECT_EQ(16u, break_offset);

  ShapeLine(&breaker, 17, zero, &break_offset);
  EXPECT_EQ(21u, break_offset);

  ShapeLine(&breaker, 22, zero, &break_offset);
  EXPECT_EQ(28u, break_offset);
}

TEST_F(ShapingLineBreakerTest, ShapeLineRangeEndMidWord) {
  Font font(font_description);

  String string(u"Mid word");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kNormal);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction, 0, 2);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  const ShapeResultView* line;
  unsigned break_offset = 0;

  line = ShapeLine(&breaker, 0, LayoutUnit::Max(), &break_offset);
  EXPECT_EQ(2u, break_offset);
  EXPECT_EQ(result->Width(), line->Width());
}

TEST_F(ShapingLineBreakerTest, ShapeLineWithLucidaFont) {
  SelectLucidaFont();
  Font font(font_description);

  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;

  //              012345678901234567890123456789012345
  String string(u"Lorem ipsum, consexx porttitxx. xxx");
  LazyLineBreakIterator break_iterator(string, AtomicString("en-US"),
                                       LineBreakType::kNormal);
  // In LayoutNG we use kAfterSpaceRun as TextBreakIterator`s default behavior.
  break_iterator.SetBreakSpace(BreakSpaceType::kAfterSpaceRun);
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction, 0, 35);
  const ShapeResult* segment1 = shaper.Shape(&font, direction, 13, 31);
  const ShapeResult* segment2 = shaper.Shape(&font, direction, 13, 32);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  const ShapeResultView* line;
  unsigned break_offset = 0;

  line = ShapeLine(&breaker, 13, segment1->SnappedWidth(), &break_offset);
  EXPECT_EQ(31u, break_offset);
  EXPECT_EQ(segment1->Width(), line->Width());

  line = ShapeLine(&breaker, 13, segment2->SnappedWidth(), &break_offset);
  EXPECT_EQ(31u, break_offset);
  EXPECT_EQ(segment1->Width(), line->Width());
}

TEST_F(ShapingLineBreakerTest, HanKerningCloseUnsafe) {
  // Create a condition where all of the following are true:
  // 1. `ShouldTrimEnd(text_spacing_trim_)` (default).
  // 2. The candidate break is `Character::MaybeHanKerningClose`; e.g., U+FF09.
  // 3. After the candidate break is breakable.
  Font font(font_description);
  String string{u"x\uFF09\u3042"};
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  // 4. `ShapeResult::StartIndex` isn't 0.
  const unsigned start_offset = 1;
  ShapeResult* sub_result = result->SubRange(start_offset, result->EndIndex());
  // 5. The candidate break isn't safe to break.
  const unsigned unsafe_offsets[]{1};
  sub_result->AddUnsafeToBreak(unsafe_offsets);
  const LayoutUnit available_width =
      LayoutUnit::FromFloatFloor(sub_result->PositionForOffset(1)) - 1;

  LazyLineBreakIterator break_iterator(string);
  HarfBuzzShapingLineBreaker breaker(&shaper, &font, sub_result,
                                     &break_iterator, nullptr);
  unsigned break_offset = 0;
  ShapeLine(&breaker, start_offset, available_width, &break_offset);
  EXPECT_EQ(break_offset, 2u);
}

struct BreakOpportunityTestData {
  const char16_t* string;
  Vector<unsigned> break_positions;
  Vector<unsigned> break_positions_with_soft_hyphen_disabled;
};

class BreakOpportunityTest
    : public ShapingLineBreakerTest,
      public testing::WithParamInterface<BreakOpportunityTestData> {};

INSTANTIATE_TEST_SUITE_P(
    ShapingLineBreakerTest,
    BreakOpportunityTest,
    testing::Values(BreakOpportunityTestData{u"x y z", {2, 4, 5}},
                    BreakOpportunityTestData{u"y\xADz", {2, 3}, {3}},
                    BreakOpportunityTestData{u"\xADz", {1, 2}, {2}},
                    BreakOpportunityTestData{u"y\xAD", {2}, {2}},
                    BreakOpportunityTestData{u"\xAD\xADz", {2, 3}, {3}}));

TEST_P(BreakOpportunityTest, Next) {
  Font font(font_description);

  const BreakOpportunityTestData& data = GetParam();
  String string(data.string);
  LazyLineBreakIterator break_iterator(string);

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  EXPECT_THAT(BreakPositionsByNext(breaker, string),
              testing::ElementsAreArray(data.break_positions));

  if (!data.break_positions_with_soft_hyphen_disabled.empty()) {
    break_iterator.EnableSoftHyphen(false);
    EXPECT_THAT(BreakPositionsByNext(breaker, string),
                testing::ElementsAreArray(
                    data.break_positions_with_soft_hyphen_disabled));
  }
}

TEST_P(BreakOpportunityTest, Previous) {
  Font font(font_description);

  const BreakOpportunityTestData& data = GetParam();
  String string(data.string);
  LazyLineBreakIterator break_iterator(string);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  HarfBuzzShapingLineBreaker breaker(&shaper, &font, result, &break_iterator,
                                     nullptr);
  EXPECT_THAT(BreakPositionsByPrevious(breaker, string),
              testing::ElementsAreArray(data.break_positions));

  if (!data.break_positions_with_soft_hyphen_disabled.empty()) {
    break_iterator.EnableSoftHyphen(false);
    EXPECT_THAT(BreakPositionsByPrevious(breaker, string),
                testing::ElementsAreArray(
                    data.break_positions_with_soft_hyphen_disabled));
  }
}

}  // namespace blink

"""

```