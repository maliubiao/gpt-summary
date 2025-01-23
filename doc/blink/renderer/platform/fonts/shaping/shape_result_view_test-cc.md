Response:
My thinking process to analyze the `shape_result_view_test.cc` file and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the provided C++ test file. They are specifically interested in its relationship with web technologies (JavaScript, HTML, CSS), logical reasoning within the tests, and potential user/programmer errors the tests might address.

2. **Identify the Core Component:** The filename `shape_result_view_test.cc` strongly suggests that the file tests the `ShapeResultView` class. This is confirmed by the inclusion of `#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"`.

3. **Analyze Imports:** The `#include` directives provide crucial context:
    * `testing/gtest/include/gtest/gtest.h`: Indicates this is a unit test file using the Google Test framework.
    * `third_party/blink/renderer/platform/fonts/...`:  These imports point to the font shaping and rendering part of the Blink engine. Key classes like `Font`, `FontCache`, `HarfBuzzShaper`, `ShapeResult`, and `ShapingLineBreaker` are being used.
    * `third_party/blink/renderer/platform/testing/...`:  Indicates the use of Blink's testing infrastructure, including utilities for font testing.

4. **Examine the Test Structure:**  The file uses the `TEST_F` macro, which means it's a test fixture. The `ShapeResultViewTest` class inherits from `FontTestBase`, setting up the environment for font-related tests. The `SetUp` method initializes a `FontDescription`.

5. **Break Down Individual Tests:**  I will go through each `TEST_F` function and determine its purpose:
    * `ExpandRange`: Tests how a given character range within a shaped text is expanded to include entire glyphs, especially important for ligatures (like "ffi"). This directly relates to text rendering and cursor positioning.
    * `ExpandRangeToIncludePartialGlyphsWithCombiningCharacter`: Focuses on the correct handling of combining characters (like diacritics) to ensure the entire character sequence is selected.
    * `LatinSingleView` and `ArabicSingleView`: Test the creation and behavior of `ShapeResultView` for single segments of text in both left-to-right (Latin) and right-to-left (Arabic) scripts. This verifies basic view creation and iteration.
    * `PreviousSafeToBreak`: Tests a crucial function for text editing and line breaking, ensuring the returned offset is correct for breaking lines.
    * `LatinMultiRun`:  Tests creating a `ShapeResultView` from multiple underlying `ShapeResult` objects. This is important for handling text that has been shaped in separate chunks.
    * `LatinCompositeView`: Similar to `LatinMultiRun`, but focuses on creating a view that combines non-contiguous parts of a single `ShapeResult`.
    * `MixedScriptsCompositeView`: Tests combining `ShapeResult` objects from different scripts (Latin and Chinese). This is important for internationalized text.
    * `TrimEndOfView`: Tests the ability to create a sub-view of an existing `ShapeResultView`.
    * `MarkerAndTrailingSpace`: Likely tests the handling of special characters and whitespace.
    * `SpacesInLTR` and `SpacesInRTL`: Specifically test how `ShapeResultView` handles spaces in left-to-right and right-to-left contexts.
    * `TabulationCharactersInLTR` and `TabulationCharactersInRTL`: Similar to spaces, but for tab characters.
    * `PreviousSafeOffsetInsideView`: Addresses a specific bug where `PreviousSafeToBreakOffset` could return an invalid value.

6. **Relate to Web Technologies:**  For each test, I'll consider how it relates to JavaScript, HTML, and CSS:
    * **JavaScript:**  Text manipulation in JavaScript (e.g., using `substring`, `slice`, or working with text nodes) relies on correct character and glyph boundaries, which these tests verify.
    * **HTML:**  The rendering of text content in HTML elements is directly affected by the font shaping and line breaking logic being tested.
    * **CSS:** CSS properties like `direction`, `unicode-bidi`, `word-break`, and font selection influence the shaping process. While the tests don't directly test CSS parsing, they test the underlying shaping algorithms that CSS relies on.

7. **Identify Logical Reasoning and Examples:**  For tests involving logical manipulation of ranges or offsets (like `ExpandRange` and `PreviousSafeToBreak`), I'll try to articulate the underlying logic and provide simple input/output examples.

8. **Pinpoint Potential Errors:**  By understanding the purpose of each test, I can infer the kinds of errors they aim to prevent. For example, the ligature test prevents issues with selecting partial ligatures, and the combining character test prevents selection issues with accented characters. I'll phrase these as common user or programming errors.

9. **Structure the Output:** I will organize the information into clear sections as requested by the user: functionality, relationships with web technologies, logical reasoning with examples, and common errors.

10. **Refine and Review:**  Finally, I will review my analysis to ensure accuracy, clarity, and completeness, making sure I have addressed all parts of the user's request.
这个文件 `shape_result_view_test.cc` 是 Chromium Blink 引擎中用于测试 `ShapeResultView` 类的单元测试文件。 `ShapeResultView` 是一个用于查看和操作文本 shaping 结果的类，它提供了一种高效的方式来处理文本布局和渲染所需的字形信息。

**主要功能:**

该文件的主要功能是验证 `ShapeResultView` 类的各种功能是否按预期工作。 这包括：

* **创建和管理 `ShapeResultView` 对象:** 测试从 `ShapeResult` 对象创建 `ShapeResultView` 的不同方式，包括创建整个结果的视图和创建部分结果的视图（子视图）。
* **访问和操作字形信息:** 测试通过 `ShapeResultView` 访问字形、字符以及它们之间映射关系的功能，例如获取字形数量、字符数量，以及根据字符范围获取对应的字形信息。
* **处理复杂文本布局特性:** 测试 `ShapeResultView` 如何处理诸如连字 (ligatures)、组合字符 (combining characters) 和不同书写方向 (LTR/RTL) 的文本。
* **支持文本编辑和选择操作:** 测试与文本编辑和选择相关的操作，例如 `ExpandRangeToIncludePartialGlyphs` 用于确保选中完整的字形，即使只选择了部分字符。 `PreviousSafeToBreakOffset` 用于查找安全断行位置。
* **支持多段文本组合:** 测试将多个 `ShapeResult` 对象组合成一个 `ShapeResultView` 的功能，这对于处理包含不同属性或分段的文本非常重要。
* **性能优化:** 虽然测试文件本身不直接测试性能，但 `ShapeResultView` 的设计目标之一是提高处理 shaping 结果的效率，因此这些测试也在间接确保了其基本功能的正确性，为性能优化奠定基础。

**与 JavaScript, HTML, CSS 的关系:**

`ShapeResultView` 处于 Blink 渲染引擎的底层，直接参与文本的布局和渲染过程。 它与 JavaScript, HTML, CSS 的功能有密切关系，体现在以下方面：

* **HTML 内容渲染:**  当浏览器解析 HTML 内容时，文本内容需要被 shaping (字形生成)。 `ShapeResultView` 用于管理这些 shaping 结果，最终用于将文本渲染到屏幕上。
    * **举例:** 当 HTML 中包含 `<p>efficient</p>` 时，Blink 引擎会使用字体 shaping 算法将 "efficient" 转换为一系列字形。 `ShapeResultView` 可以用来查看这些字形信息，例如 'ffi' 可能被渲染成一个单独的连字字形。
* **CSS 样式影响:** CSS 的字体属性 (`font-family`, `font-size`, `font-style`, `font-weight`) 和文本属性 (`direction`, `unicode-bidi`, `letter-spacing`, `word-spacing`) 会直接影响 shaping 的结果。 `ShapeResultView` 处理的是这些 shaping 后的信息。
    * **举例:**  如果 CSS 设置 `direction: rtl;`，则 `ShapeResultView` 需要正确处理从右到左的文本布局，例如阿拉伯语文本的渲染。
* **JavaScript 文本操作:** JavaScript 可以动态修改 HTML 内容，例如通过 `textContent` 或 `innerHTML` 修改文本。 当文本内容改变时，Blink 引擎会重新进行 shaping，并可能创建新的 `ShapeResultView` 对象来管理新的 shaping 结果。
    * **举例:**  JavaScript 代码 `element.textContent = "efficient";`  会导致 Blink 引擎为 "efficient" 字符串生成 shaping 结果，并可以使用 `ShapeResultView` 来检查其字形信息。
* **文本选择和光标定位:** 当用户在网页上选择文本时，浏览器需要确定选择范围内的字符和对应的字形。 `ShapeResultView` 提供的 `ExpandRangeToIncludePartialGlyphs` 功能确保了即使只选择了连字的一部分字符，也能选中整个连字字形。
    * **举例:** 用户在 "efficient" 中选择 "ffici"，`ExpandRangeToIncludePartialGlyphs` 可以将选择范围扩展到包含整个 'ffi' 连字。

**逻辑推理和假设输入与输出:**

以下列举几个测试用例中的逻辑推理和假设输入与输出：

* **`ExpandRange` 测试:**
    * **假设输入:**  字符串 "efficient"，方向 LTR，选择范围从字符索引 0 到 1（即 'e'）。
    * **逻辑推理:** 由于 "ffi" 是一个连字，即使只选择了 'e'，也应该将范围扩展到包含整个连字。
    * **预期输出:** 扩展后的范围是字符索引 0 到 4（即 'effi'）。
    * **假设输入:** 字符串 "efficient"，方向 LTR，选择范围从字符索引 3 到 4（即 'c'）。
    * **逻辑推理:** 由于 'c' 是连字 "ffi" 的一部分，需要将范围扩展到包含整个连字。
    * **预期输出:** 扩展后的范围是字符索引 1 到 4（即 'ffic'）。
* **`PreviousSafeToBreak` 测试:**
    * **假设输入:**  一段希伯来语文本的 `ShapeResultView`，以及一个偏移量。
    * **逻辑推理:**  需要找到在该偏移量之前的一个安全断行位置，这个位置通常是词与词之间的空格或者标点符号之后。
    * **预期输出:** 返回一个字符索引，表示在该索引处可以安全断行。 这个测试会比较 `ShapeResultView` 计算的安全断行位置和 `ShapeResult` 对象缓存的安全断行位置是否一致。

**用户或编程常见的使用错误:**

该文件中的测试用例可以帮助预防以下用户或编程中常见的错误：

* **选择或删除部分连字:**  如果代码没有正确处理连字，用户在选择或删除文本时可能会遇到问题，例如只删除了连字的一部分字符，导致显示异常。 `ExpandRangeToIncludePartialGlyphs` 相关的测试确保了选择和删除操作的原子性，即要么整个连字被选中/删除，要么都不被选中/删除。
* **光标定位在连字中间:**  不正确的实现可能导致光标定位在连字字符的中间，而不是在字符的边界。 `ExpandRangeToIncludePartialGlyphs` 的正确性有助于确保光标定位的准确性。
* **错误处理组合字符:**  组合字符（例如带有重音符号的字母）由多个 Unicode 码点组成。 如果代码没有正确处理，可能会导致选择、删除或渲染组合字符时出现问题。 `ExpandRangeToIncludePartialGlyphsWithCombiningCharacter` 测试确保了组合字符作为一个整体被处理。
* **在 RTL 文本中处理空格或制表符错误:**  在从右到左的文本中，空格和制表符的渲染和行为可能与从左到右的文本不同。 `SpacesInRTL` 和 `TabulationCharactersInRTL` 测试确保了这些字符在 RTL 文本中的正确处理。
* **在多段文本组合时出现错误:** 当需要将来自不同 shaping 结果的文本片段组合在一起时，如果 `ShapeResultView` 的实现有误，可能会导致字形顺序错乱或渲染错误。 `LatinMultiRun` 和 `LatinCompositeView` 等测试用于验证多段文本组合功能的正确性。
* **计算安全断行位置错误:**  错误的断行位置计算可能导致文本在换行时出现不期望的结果，例如在单词中间断行。 `PreviousSafeToBreak` 测试确保了断行位置计算的准确性。
* **处理特殊字符（如 marker）错误:** 一些特殊字符，如零宽度字符或控制字符，可能需要特殊处理。 `MarkerAndTrailingSpace` 测试可能涉及到对这类字符的处理逻辑的验证。

总而言之，`shape_result_view_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎在处理文本布局和渲染时的正确性和健壮性，直接影响用户在网页上看到的文本呈现效果和交互体验。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

#include <unicode/uscript.h>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_test_utilities.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shaping_line_breaker.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class ShapeResultViewTest : public FontTestBase {
 protected:
  void SetUp() override {
    font_description.SetComputedSize(12.0);
  }

  void TearDown() override {}

  FontCachePurgePreventer font_cache_purge_preventer;
  FontDescription font_description;
};

TEST_F(ShapeResultViewTest, ExpandRange) {
  auto GetExpandedRange = [](const String& text, bool ltr, unsigned from,
                             unsigned to) -> Vector<unsigned> {
    FontDescription::VariantLigatures ligatures(
        FontDescription::kEnabledLigaturesState);
    Font font = test::CreateTestFont(
        AtomicString("roboto"),
        test::PlatformTestDataPath("third_party/Roboto/roboto-regular.woff2"),
        100, &ligatures);

    HarfBuzzShaper shaper(text);
    const ShapeResultView* shape_result = ShapeResultView::Create(
        shaper.Shape(&font, ltr ? TextDirection::kLtr : TextDirection::kRtl));
    shape_result->ExpandRangeToIncludePartialGlyphs(&from, &to);
    return Vector<unsigned>({from, to});
  };

  // "ffi" is a ligature, therefore a single glyph. Any range that includes one
  // of the letters must be expanded to all of them.
  EXPECT_EQ(GetExpandedRange("efficient", true, 0, 1), Vector({0u, 1u}));
  EXPECT_EQ(GetExpandedRange("efficient", true, 0, 2), Vector({0u, 4u}));
  EXPECT_EQ(GetExpandedRange("efficient", true, 3, 4), Vector({1u, 4u}));
  EXPECT_EQ(GetExpandedRange("efficient", true, 4, 6), Vector({4u, 6u}));
  EXPECT_EQ(GetExpandedRange("efficient", true, 6, 7), Vector({6u, 7u}));
  EXPECT_EQ(GetExpandedRange("efficient", true, 0, 9), Vector({0u, 9u}));

  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 0, 1), Vector({0u, 1u}));
  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 0, 2), Vector({0u, 2u}));
  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 3, 4), Vector({3u, 4u}));
  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 4, 6), Vector({4u, 8u}));
  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 6, 7), Vector({5u, 8u}));
  EXPECT_EQ(GetExpandedRange("tneiciffe", false, 0, 9), Vector({0u, 9u}));
}

// http://crbug.com/1221008
TEST_F(ShapeResultViewTest,
       ExpandRangeToIncludePartialGlyphsWithCombiningCharacter) {
  Font font(font_description);

  String string(u"abc\u0E35\u0E35\u0E35\u0E35");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  const ShapeResultView* view =
      ShapeResultView::Create(result, result->StartIndex(), result->EndIndex());
  unsigned from = 0;
  unsigned end = string.length();
  view->ExpandRangeToIncludePartialGlyphs(&from, &end);
  EXPECT_EQ(0u, from);
  EXPECT_EQ(string.length(), end);
}

TEST_F(ShapeResultViewTest, LatinSingleView) {
  Font font(font_description);

  String string =
      To16Bit("Test run with multiple words and breaking opportunities.");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> glyphs;
  result->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&glyphs));

  // Test view at the start of the result: "Test run with multiple"
  ShapeResultView::Segment segments[] = {{result, 0, 22}};
  auto* first4 = ShapeResultView::Create(segments);

  EXPECT_EQ(first4->StartIndex(), 0u);
  EXPECT_EQ(first4->NumCharacters(), 22u);
  EXPECT_EQ(first4->NumGlyphs(), 22u);

  Vector<ShapeResultTestGlyphInfo> first4_glyphs;
  first4->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&first4_glyphs));
  EXPECT_EQ(first4_glyphs.size(), 22u);
  EXPECT_TRUE(CompareResultGlyphs(first4_glyphs, glyphs, 0u, 22u));

  // Test view in the middle of the result: "multiple words and breaking"
  segments[0] = {result, 14, 41};
  auto* middle4 = ShapeResultView::Create(segments);

  EXPECT_EQ(middle4->StartIndex(), 14u);
  EXPECT_EQ(middle4->NumCharacters(), 27u);
  EXPECT_EQ(middle4->NumGlyphs(), 27u);

  Vector<ShapeResultTestGlyphInfo> middle4_glyphs;
  middle4->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&middle4_glyphs));
  EXPECT_EQ(middle4_glyphs.size(), 27u);
  EXPECT_TRUE(CompareResultGlyphs(middle4_glyphs, glyphs, 14u, 27u));

  // Test view at the end of the result: "breaking opportunities."
  segments[0] = {result, 33, 56};
  auto* last2 = ShapeResultView::Create(segments);

  EXPECT_EQ(last2->StartIndex(), 33u);
  EXPECT_EQ(last2->NumCharacters(), 23u);
  EXPECT_EQ(last2->NumGlyphs(), 23u);

  Vector<ShapeResultTestGlyphInfo> last2_glyphs;
  last2->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&last2_glyphs));
  EXPECT_EQ(last2_glyphs.size(), 23u);
  EXPECT_TRUE(CompareResultGlyphs(last2_glyphs, glyphs, 33u, 23u));
}

TEST_F(ShapeResultViewTest, ArabicSingleView) {
  Font font(font_description);

  String string = To16Bit("عربى نص");
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> glyphs;
  result->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&glyphs));

  // Test view at the start of the result: "عربى"
  ShapeResultView::Segment segments[] = {{result, 0, 4}};
  auto* first_word = ShapeResultView::Create(segments);
  Vector<ShapeResultTestGlyphInfo> first_glyphs;
  first_word->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&first_glyphs));

  EXPECT_EQ(first_word->StartIndex(), 0u);
  EXPECT_EQ(first_word->NumCharacters(), 4u);
  EXPECT_EQ(first_word->NumGlyphs(), 4u);
  EXPECT_EQ(first_glyphs.size(), 4u);

  String first_reference_string = To16Bit("عربى");
  HarfBuzzShaper first_reference_shaper(first_reference_string);
  const ShapeResult* first_wortd_reference =
      first_reference_shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> first_reference_glyphs;
  first_wortd_reference->ForEachGlyph(
      0, AddGlyphInfo, static_cast<void*>(&first_reference_glyphs));
  EXPECT_EQ(first_reference_glyphs.size(), 4u);

  EXPECT_TRUE(
      CompareResultGlyphs(first_glyphs, first_reference_glyphs, 0u, 4u));
  EXPECT_TRUE(CompareResultGlyphs(first_glyphs, glyphs, 3u, 7u));

  // Test view at the end of the result: "نص"
  segments[0] = {result, 4, 7};
  auto* last_word = ShapeResultView::Create(segments);
  Vector<ShapeResultTestGlyphInfo> last_glyphs;
  last_word->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&last_glyphs));

  EXPECT_EQ(last_word->StartIndex(), 4u);
  EXPECT_EQ(last_word->NumCharacters(), 3u);
  EXPECT_EQ(last_word->NumGlyphs(), 3u);
  EXPECT_EQ(last_glyphs.size(), 3u);
}

TEST_F(ShapeResultViewTest, PreviousSafeToBreak) {
  Font font(font_description);

  String string =
      u"\u0028\u05D1\u0029\u0020\u05D4\u05D1\u05DC\u0020\u05D0\u05DE\u05E8"
      u"\u0020\u05E2\u05DC\u0020"
      u"\u05D3\u05D1\u05E8\u05D9\u0020\u05D4\u05D1\u05DC\u05D9\u0020\u05D4"
      u"\u05E2\u05D5\u05DC\u05DD\u002C"
      u"\u0020\u05D5\u05E1\u05DE\u05DA\u0020\u05D4\u05B2\u05D1\u05B5\u05DC"
      u"\u0020\u05D0\u05DC\u0020\u05D4"
      u"\u05D1\u05DC\u05D9\u05DD\u0020\u05D5\u05D0\u05DD\u0020\u05DC\u05D0"
      u"\u0020\u05D9\u05DE\u05E6\u05D0"
      u"\u0020\u05DE\u05D4\u05E9\u05DE\u05D5\u05EA\u0020\u05E9\u05D4\u05DD"
      u"\u0020\u05E2\u05DC\u0020\u05DE"
      u"\u05E9\u05E7\u05DC\u0020\u05D0\u05E8\u05E5\u0020\u05E9\u05D9\u05E9"
      u"\u05EA\u05E0\u05D4\u0020\u05D7"
      u"\u05D5\u05E5\u0020\u05DE\u05B5\u05D7\u05B2\u05D3\u05B7\u05E8\u0020"
      u"\u05DE\u05B4\u05E9\u05B0\u05C1"
      u"\u05DB\u05B8\u05D1\u05B0\u05DA\u05B8\u0020\u0028\u05E9\u05DE\u05D5"
      u"\u05EA\u0020\u05D6\u05F3\u003A"
      u"\u05DB\u05F4\u05D7\u0029";
  TextDirection direction = TextDirection::kRtl;
  HarfBuzzShaper shaper(string);
  const RunSegmenter::RunSegmenterRange range = {
      51, 131, USCRIPT_HEBREW, blink::OrientationIterator::kOrientationKeep,
      blink::FontFallbackPriority::kText};
  const ShapeResult* shape_result =
      shaper.Shape(&font, direction, 51, 131, range);

  unsigned start_offset = 59;
  unsigned end_offset = 118;
  const ShapeResultView* result_view =
      ShapeResultView::Create(shape_result, start_offset, end_offset);
  const ShapeResult* result = result_view->CreateShapeResult();

  unsigned offset = end_offset;
  do {
    unsigned safe = result_view->PreviousSafeToBreakOffset(offset);
    unsigned cached_safe = result->CachedPreviousSafeToBreakOffset(offset);
    EXPECT_EQ(safe, cached_safe);
  } while (--offset > start_offset);
}

TEST_F(ShapeResultViewTest, LatinMultiRun) {
  Font font(font_description);

  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper_a(To16Bit("hello"));
  HarfBuzzShaper shaper_b(To16Bit(" w"));
  HarfBuzzShaper shaper_c(To16Bit("orld"));
  HarfBuzzShaper shaper_d(To16Bit("!"));

  // Combine four separate results into a single one to ensure we have a result
  // with multiple runs: "hello world!"
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  shaper_a.Shape(&font, direction)->CopyRange(0u, 5u, result);
  shaper_b.Shape(&font, direction)->CopyRange(0u, 2u, result);
  shaper_c.Shape(&font, direction)->CopyRange(0u, 4u, result);
  shaper_d.Shape(&font, direction)->CopyRange(0u, 1u, result);

  Vector<ShapeResultTestGlyphInfo> result_glyphs;
  result->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&result_glyphs));

  // Create composite view out of multiple segments where at least some of the
  // segments have multiple runs: "hello wood wold!"
  ShapeResultView::Segment segments[5] = {
      {result, 0, 8},    // "hello wo"
      {result, 7, 8},    // "o"
      {result, 10, 11},  // "d"
      {result, 5, 8},    // " wo"
      {result, 9, 12},   // "ld!"
  };
  auto* composite_view = ShapeResultView::Create(segments);
  Vector<ShapeResultTestGlyphInfo> view_glyphs;
  composite_view->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&view_glyphs));

  EXPECT_EQ(composite_view->StartIndex(), 0u);
  EXPECT_EQ(composite_view->NumCharacters(), 16u);
  EXPECT_EQ(composite_view->NumGlyphs(), 16u);
  EXPECT_EQ(view_glyphs.size(), 16u);

  HarfBuzzShaper shaper2(To16Bit("hello world!"));
  const ShapeResult* result2 = shaper2.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> glyphs2;
  result2->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&glyphs2));
  EXPECT_TRUE(CompareResultGlyphs(result_glyphs, glyphs2, 0u, 12u));

  HarfBuzzShaper reference_shaper(To16Bit("hello wood wold!"));
  const ShapeResult* reference_result =
      reference_shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> reference_glyphs;
  reference_result->ForEachGlyph(0, AddGlyphInfo,
                                 static_cast<void*>(&reference_glyphs));

  ShapeResult* composite_copy =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(0, 8, composite_copy);
  result->CopyRange(7, 8, composite_copy);
  result->CopyRange(10, 11, composite_copy);
  result->CopyRange(5, 8, composite_copy);
  result->CopyRange(9, 12, composite_copy);

  Vector<ShapeResultTestGlyphInfo> composite_copy_glyphs;
  composite_copy->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&composite_copy_glyphs));

  EXPECT_TRUE(CompareResultGlyphs(view_glyphs, reference_glyphs, 0u, 16u));
  EXPECT_TRUE(
      CompareResultGlyphs(composite_copy_glyphs, reference_glyphs, 0u, 16u));
  EXPECT_EQ(composite_view->Width(), composite_copy->Width());
}

TEST_F(ShapeResultViewTest, LatinCompositeView) {
  Font font(font_description);

  String string =
      To16Bit("Test run with multiple words and breaking opportunities.");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> glyphs;
  result->ForEachGlyph(0, AddGlyphInfo, static_cast<void*>(&glyphs));

  String reference_string = To16Bit("multiple breaking opportunities Test");
  HarfBuzzShaper reference_shaper(reference_string);
  const ShapeResult* reference_result =
      reference_shaper.Shape(&font, direction);
  Vector<ShapeResultTestGlyphInfo> reference_glyphs;

  // Match the character index logic of ShapeResult::CopyRange where the the
  // character index of the first result is preserved and all subsequent ones
  // are adjusted to be sequential.
  // TODO(layout-dev): Arguably both should be updated to renumber the first
  // result as well but some callers depend on the existing behavior.
  ShapeResult* composite_copy =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(14, 23, composite_copy);
  result->CopyRange(33, 55, composite_copy);
  result->CopyRange(4, 5, composite_copy);
  result->CopyRange(0, 4, composite_copy);
  EXPECT_EQ(composite_copy->NumCharacters(), reference_result->NumCharacters());
  EXPECT_EQ(composite_copy->NumGlyphs(), reference_result->NumGlyphs());
  composite_copy->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&reference_glyphs));

  // Create composite view out of multiple segments:
  ShapeResultView::Segment segments[4] = {
      {result, 14, 23},  // "multiple "
      {result, 33, 55},  // "breaking opportunities"
      {result, 4, 5},    // " "
      {result, 0, 4}     // "Test"
  };
  auto* composite_view = ShapeResultView::Create(segments);

  EXPECT_EQ(composite_view->StartIndex(), composite_copy->StartIndex());
  EXPECT_EQ(composite_view->NumCharacters(), reference_result->NumCharacters());
  EXPECT_EQ(composite_view->NumGlyphs(), reference_result->NumGlyphs());

  Vector<ShapeResultTestGlyphInfo> composite_glyphs;
  composite_view->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&composite_glyphs));
  EXPECT_EQ(composite_glyphs.size(), 36u);
  EXPECT_TRUE(CompareResultGlyphs(composite_glyphs, reference_glyphs, 0u, 22u));
  EXPECT_EQ(composite_view->Width(), composite_copy->Width());
}

TEST_F(ShapeResultViewTest, MixedScriptsCompositeView) {
  Font font(font_description);

  String string_a = To16Bit("Test with multiple 字体 ");
  String string_b = To16Bit("and 本書.");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper_a(string_a);
  const ShapeResult* result_a = shaper_a.Shape(&font, direction);
  HarfBuzzShaper shaper_b(string_b);
  const ShapeResult* result_b = shaper_b.Shape(&font, direction);

  String reference_string = To16Bit("Test with multiple 字体 and 本書.");
  HarfBuzzShaper reference_shaper(reference_string);
  const ShapeResult* reference_result =
      reference_shaper.Shape(&font, direction);

  // Create a copy using CopyRange and compare with that to ensure that the same
  // fonts are used for both the composite and the reference. The combined
  // reference_result data might use different fonts, resulting in different
  // glyph ids and metrics.
  ShapeResult* composite_copy =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result_a->CopyRange(0, 22, composite_copy);
  result_b->CopyRange(0, 7, composite_copy);
  EXPECT_EQ(composite_copy->NumCharacters(), reference_result->NumCharacters());
  EXPECT_EQ(composite_copy->NumGlyphs(), reference_result->NumGlyphs());
  Vector<ShapeResultTestGlyphInfo> reference_glyphs;
  composite_copy->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&reference_glyphs));

  ShapeResultView::Segment segments[] = {{result_a, 0, 22}, {result_b, 0, 7}};
  auto* composite_view = ShapeResultView::Create(segments);

  EXPECT_EQ(composite_view->StartIndex(), 0u);
  EXPECT_EQ(composite_view->NumCharacters(), reference_result->NumCharacters());
  EXPECT_EQ(composite_view->NumGlyphs(), reference_result->NumGlyphs());

  Vector<ShapeResultTestGlyphInfo> composite_glyphs;
  composite_view->ForEachGlyph(0, AddGlyphInfo,
                               static_cast<void*>(&composite_glyphs));
  EXPECT_TRUE(CompareResultGlyphs(composite_glyphs, reference_glyphs, 0u,
                                  reference_glyphs.size()));
  EXPECT_EQ(composite_view->Width(), composite_copy->Width());
}

TEST_F(ShapeResultViewTest, TrimEndOfView) {
  Font font(font_description);

  String string = To16Bit("12345678901234567890");
  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Create a view from 5 to 20.
  const ShapeResultView* view1 = ShapeResultView::Create(result, 5, 20);
  EXPECT_EQ(view1->NumCharacters(), 15u);
  EXPECT_EQ(view1->NumGlyphs(), 15u);

  // Trim the last character from the view.
  const ShapeResultView* view2 = ShapeResultView::Create(view1, 5, 19);
  EXPECT_EQ(view2->NumCharacters(), 14u);
  EXPECT_EQ(view2->NumGlyphs(), 14u);
}

TEST_F(ShapeResultViewTest, MarkerAndTrailingSpace) {
  Font font(font_description);

  String string = u"\u2067\u2022\u0020";
  TextDirection direction = TextDirection::kRtl;
  LayoutUnit symbol_width = LayoutUnit(7);
  const ShapeResult* result =
      ShapeResult::CreateForSpaces(&font, direction, 1, 2, symbol_width);

  ShapeResultView::Segment segments[] = {{result, 1, 2}};
  auto* shape_result_view = ShapeResultView::Create(segments);
  const ShapeResult* shape_result = shape_result_view->CreateShapeResult();

  Vector<CharacterRange> ranges;
  shape_result->IndividualCharacterRanges(&ranges);
}

TEST_F(ShapeResultViewTest, SpacesInLTR) {
  Font font(font_description);

  constexpr unsigned kStartIndex = 0;
  constexpr unsigned kLength = 2;
  constexpr float kWidth = 8;
  const auto* result = ShapeResult::CreateForSpaces(
      &font, TextDirection::kLtr, kStartIndex, kLength, kWidth);

  const auto* view0 = ShapeResultView::Create(result, 0, 2);
  EXPECT_EQ(view0->NumCharacters(), 2u);
  EXPECT_EQ(view0->NumGlyphs(), 2u);

  const auto* view1 = ShapeResultView::Create(result, 0, 1);
  EXPECT_EQ(view1->NumCharacters(), 1u);
  EXPECT_EQ(view1->NumGlyphs(), 1u);

  const auto* view2 = ShapeResultView::Create(result, 1, 2);
  EXPECT_EQ(view2->NumCharacters(), 1u);
  EXPECT_EQ(view2->NumGlyphs(), 1u);
}

// http://crbug.com/1160582
TEST_F(ShapeResultViewTest, SpacesInRTL) {
  Font font(font_description);

  constexpr unsigned kStartIndex = 0;
  constexpr unsigned kLength = 2;
  constexpr float kWidth = 8;
  const auto* result = ShapeResult::CreateForSpaces(
      &font, TextDirection::kRtl, kStartIndex, kLength, kWidth);

  const auto* view0 = ShapeResultView::Create(result, 0, 2);
  EXPECT_EQ(view0->NumCharacters(), 2u);
  EXPECT_EQ(view0->NumGlyphs(), 2u);

  const auto* view1 = ShapeResultView::Create(result, 0, 1);
  EXPECT_EQ(view1->NumCharacters(), 1u);
  EXPECT_EQ(view1->NumGlyphs(), 1u);

  const auto* view2 = ShapeResultView::Create(result, 1, 2);
  EXPECT_EQ(view2->NumCharacters(), 1u);
  EXPECT_EQ(view2->NumGlyphs(), 1u);
}

TEST_F(ShapeResultViewTest, TabulationCharactersInLTR) {
  Font font(font_description);

  constexpr float kPosition = 0;
  constexpr unsigned kStartIndex = 0;
  constexpr unsigned kLength = 2;
  const auto* result = ShapeResult::CreateForTabulationCharacters(
      &font, TextDirection::kLtr, TabSize(8), kPosition, kStartIndex, kLength);

  const auto* view0 = ShapeResultView::Create(result, 0, 2);
  EXPECT_EQ(view0->NumCharacters(), 2u);
  EXPECT_EQ(view0->NumGlyphs(), 2u);

  const auto* view1 = ShapeResultView::Create(result, 0, 1);
  EXPECT_EQ(view1->NumCharacters(), 1u);
  EXPECT_EQ(view1->NumGlyphs(), 1u);

  const auto* view2 = ShapeResultView::Create(result, 1, 2);
  EXPECT_EQ(view2->NumCharacters(), 1u);
  EXPECT_EQ(view2->NumGlyphs(), 1u);
}

// http://crbug.com/1255310
TEST_F(ShapeResultViewTest, TabulationCharactersInRTL) {
  Font font(font_description);

  constexpr float kPosition = 0;
  constexpr unsigned kStartIndex = 0;
  constexpr unsigned kLength = 2;
  const auto* result = ShapeResult::CreateForTabulationCharacters(
      &font, TextDirection::kRtl, TabSize(8), kPosition, kStartIndex, kLength);

  const auto* view0 = ShapeResultView::Create(result, 0, 2);
  EXPECT_EQ(view0->NumCharacters(), 2u);
  EXPECT_EQ(view0->NumGlyphs(), 2u);

  const auto* view1 = ShapeResultView::Create(result, 0, 1);
  EXPECT_EQ(view1->NumCharacters(), 1u);
  EXPECT_EQ(view1->NumGlyphs(), 1u);

  const auto* view2 = ShapeResultView::Create(result, 1, 2);
  EXPECT_EQ(view2->NumCharacters(), 1u);
  EXPECT_EQ(view2->NumGlyphs(), 1u);
}

// https://crbug.com/1304876
// In a text containing only Latin characters and without ligatures (or where
// ligatures are not close to the end of the view), PreviousSafeToBreakOffset in
// some cases used to return the length of the view, rather than a position into
// the view.
TEST_F(ShapeResultViewTest, PreviousSafeOffsetInsideView) {
  Font font(font_description);

  HarfBuzzShaper shaper("Blah bla test something. ");
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  // Used to be 14 - 9 = 5, which is before the start of the view.
  auto* view1 = ShapeResultView::Create(result, 9, 14);
  EXPECT_EQ(view1->PreviousSafeToBreakOffset(14), 14u);

  // Used to be 25 - 9 = 16, which is inside the view's range, but not the last
  // safe offset.
  auto* view2 = ShapeResultView::Create(result, 9, 25);
  EXPECT_EQ(view2->PreviousSafeToBreakOffset(24), 24u);
}

}  // namespace blink
```