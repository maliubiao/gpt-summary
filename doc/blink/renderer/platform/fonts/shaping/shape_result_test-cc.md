Response:
The user wants a summary of the functionality of the C++ source code file `shape_result_test.cc`.
This file appears to be a unit test file for the `ShapeResult` class in the Blink rendering engine.

Here's a breakdown of how to summarize its functionality:

1. **Identify the core purpose:** The file tests the `ShapeResult` class.
2. **Analyze the tests:**  Look for common patterns and categories in the `TEST_F` macros.
3. **Connect to broader concepts:**  Relate the tested functionalities to web rendering concepts (fonts, shaping, text layout).
4. **Address specific instructions:**  Explicitly mention if it relates to JavaScript, HTML, or CSS, provide examples, discuss logical reasoning with inputs/outputs, and highlight potential usage errors.
```
ShapeResultTest 的功能归纳 (第1部分):

这个C++源代码文件 `shape_result_test.cc` 是 Chromium Blink 引擎中用于测试 `ShapeResult` 类功能的单元测试文件。`ShapeResult` 类在 Blink 引擎中负责存储文本塑形（shaping）的结果，例如字形（glyphs）、字形的位置信息、以及其他与文本渲染相关的数据。

**具体功能点:**

1. **`ShapeResult` 类的核心功能测试:**  该文件通过各种测试用例验证 `ShapeResult` 类的不同功能，确保其在处理不同文本、字体和书写方向时能正确工作。

2. **测试 `CopyRanges` 方法:**  重点测试了 `ShapeResult` 类的 `CopyRanges` 方法，该方法用于将一个 `ShapeResult` 对象的部分或全部内容复制到另一个 `ShapeResult` 对象中。测试用例涵盖了拉丁文字符和阿拉伯文字符，以及源 `ShapeResult` 对象包含多个文本段落（runs）的情况。
   - **目的:** 验证在不同场景下，`CopyRanges` 方法能否正确复制字形信息和相关的属性。

3. **测试 `SubRange` 方法 (通过比较 `CopyRanges` 的结果间接测试):**  虽然没有直接测试 `SubRange` 方法，但通过将 `CopyRanges` 的结果与 `SubRange` 的结果进行比较，间接地验证了 `SubRange` 方法的正确性。`SubRange` 方法用于创建一个新的 `ShapeResult` 对象，该对象表示原始 `ShapeResult` 对象的一个子范围。

4. **测试文本安全断行 (`IsStartSafeToBreak`):**  测试了 `ShapeResult` 类的 `IsStartSafeToBreak` 方法，该方法用于判断在给定的偏移量处是否可以安全地进行断行。
   - **目的:** 确保文本在渲染时可以在合适的位置断行，避免在不应该断开的地方断开，例如在连字或复合字符中间。

5. **测试添加不安全断行点 (`AddUnsafeToBreak`):**  测试了 `ShapeResult` 类的 `AddUnsafeToBreak` 方法，该方法用于标记某些偏移量为不安全的断行点。
   - **目的:**  允许开发者或渲染引擎指定某些位置不应该断行。

6. **测试计算墨水边界 (`ComputeInkBounds`):**  测试了 `ShapeResult` 类的 `ComputeInkBounds` 方法，该方法用于计算文本的墨水边界，即包含所有字形的最小矩形。
   - **目的:**  用于布局和渲染，确定文本占据的实际空间。

7. **测试应用自动空格 (`ApplyTextAutoSpacing`):**  测试了 `ShapeResult` 类的 `ApplyTextAutoSpacing` 方法，该方法用于在某些字符之间添加额外的空格，例如在西方字符和亚洲字符之间。
   - **目的:**  改善文本的可读性，特别是在混合语言环境中。

8. **测试获取指定偏移量的光标位置 (`CaretPositionForOffset`):**  测试了 `ShapeResult` 类的 `CaretPositionForOffset` 方法，该方法用于获取文本中给定字符偏移量处的光标（caret）位置。
   - **目的:**  用于文本编辑和光标定位。

9. **测试获取指定位置的偏移量 (`OffsetForPosition`):** 测试了 `ShapeResult` 类的 `OffsetForPosition` 方法，该方法用于根据给定的屏幕位置查找对应的文本字符偏移量。
   - **目的:**  用于处理鼠标点击等事件，确定用户在文本中的选择位置。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

虽然此文件本身是 C++ 代码，但它测试的功能直接影响到网页中文本的渲染和交互，这与 JavaScript, HTML, 和 CSS 密切相关。

* **HTML:** HTML 定义了网页的结构和内容，包含需要渲染的文本。`ShapeResult` 处理的就是这些 HTML 中包含的文本。
   * **例子:**  一个 `<div>` 元素包含一段文字 "Hello World"。Blink 引擎会创建 `ShapeResult` 对象来处理这段文本的塑形。

* **CSS:** CSS 负责控制文本的样式，例如字体、大小、颜色、行高、书写方向等。`ShapeResult` 的测试用例中使用了不同的字体和书写方向，模拟了 CSS 样式对文本渲染的影响。
   * **例子:** CSS 规则 `font-family: Roboto; direction: rtl;` 会影响 `ShapeResult` 如何对文本进行塑形。该测试文件中的 `kLatinFont` 和 `kArabicFont` 以及 `TextDirection::kLtr` 和 `TextDirection::kRtl` 就模拟了这种影响。

* **JavaScript:** JavaScript 可以动态地修改 HTML 内容和 CSS 样式，从而间接地影响 `ShapeResult` 的行为。此外，JavaScript 可以通过浏览器 API (例如 `getBoundingClientRect`) 获取渲染后的文本尺寸和位置，这些信息是由 `ShapeResult` 计算出来的。
   * **例子:**  JavaScript 代码动态地改变一个元素的 `textContent`，浏览器会重新进行文本塑形，创建一个新的 `ShapeResult` 对象。或者，JavaScript 可以监听鼠标事件，并使用 `window.getSelection()` 获取用户选中的文本范围，这需要依赖 `ShapeResult` 提供的偏移量信息。

**逻辑推理 (假设输入与输出):**

**假设输入 (以 `CopyRangeLatin` 测试为例):**

* **源 `ShapeResult` 对象:**  包含字符串 "Testing ShapeResultIterator::CopyRange" 的塑形结果，使用 Latin 字体和 LTR 方向。
* **目标 `ShapeResult::ShapeRange` 数组:**  定义了四个目标范围，每个范围都有起始和结束偏移量，以及一个新创建的空的 `ShapeResult` 对象。例如：`{{0, 10, <empty ShapeResult>}, {10, 20, <empty ShapeResult>}, ...}`

**输出:**

* **目标 `ShapeResult` 对象:**  每个目标 `ShapeResult` 对象都会包含源 `ShapeResult` 对象中对应范围的字形信息。例如，第一个目标 `ShapeResult` 将包含 "Testing Sha" 的塑形结果。
* **断言结果:**  测试会断言复制后的目标 `ShapeResult` 中的字形数量和内容与直接从源字符串生成的结果一致。

**用户或编程常见的使用错误 (举例说明):**

* **错误地假设 `IsStartSafeToBreak` 的返回值:** 开发者可能会错误地认为 `IsStartSafeToBreak` 返回 `true` 就一定可以在该位置断行，而忽略了其他可能导致无法断行的因素，例如 CSS 的 `word-break` 或 `overflow-wrap` 属性。
* **在多线程环境下不安全地访问 `ShapeResult`:**  `ShapeResult` 对象可能不是线程安全的，如果在多个线程中同时访问或修改，可能会导致数据竞争和崩溃。
* **没有考虑书写方向 (`TextDirection`):**  在处理双向文本（例如包含阿拉伯语和英语的文本）时，如果没有正确设置 `TextDirection`，可能会导致文本渲染顺序错误。该测试文件就包含了针对不同书写方向的测试用例，提醒开发者注意这一点。
* **在应用 `ApplyTextAutoSpacing` 时传入错误的偏移量:**  如果提供的偏移量不对应于需要添加空格的位置，可能会导致空格添加错误或程序崩溃。

总而言之，`shape_result_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中负责文本塑形的核心组件 `ShapeResult` 的正确性和稳定性，从而保证了网页上文本渲染的质量和用户体验。
```
### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"

#include "base/containers/span.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_test_utilities.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {
class FontsHolder : public GarbageCollected<FontsHolder> {
 public:
  void Trace(Visitor* visitor) const {
    for (const Font& font : fonts) {
      font.Trace(visitor);
    }
  }

  Font fonts[3];
};
}  // namespace

class ShapeResultTest : public FontTestBase {
 public:
  enum FontType {
    kLatinFont = 0,
    kArabicFont = 1,
    kCJKFont = 2,
  };

 protected:
  void SetUp() override {
    FontDescription::VariantLigatures ligatures;
    fonts_holder = MakeGarbageCollected<FontsHolder>();
    fonts_holder->fonts[0] = blink::test::CreateTestFont(
        AtomicString("Roboto"),
        blink::test::PlatformTestDataPath(
            "third_party/Roboto/roboto-regular.woff2"),
        12.0, &ligatures);

    fonts_holder->fonts[1] = blink::test::CreateTestFont(
        AtomicString("Noto"),
        blink::test::PlatformTestDataPath(
            "third_party/Noto/NotoNaskhArabic-regular.woff2"),
        12.0, &ligatures);

    fonts_holder->fonts[2] = blink::test::CreateTestFont(
        AtomicString("M PLUS 1p"),
        blink::test::BlinkWebTestsFontsTestDataPath("mplus-1p-regular.woff"),
        12.0, &ligatures);
  }

  void TearDown() override {}

  void TestCopyRangesLatin(const ShapeResult*) const;
  void TestCopyRangesArabic(const ShapeResult*) const;

  static bool HasNonZeroGlyphOffsets(const ShapeResult& result) {
    for (const auto& run : result.RunsOrParts()) {
      if (run->glyph_data_.HasNonZeroOffsets())
        return true;
    }
    return false;
  }

  ShapeResult* CreateShapeResult(TextDirection direction) const {
    return MakeGarbageCollected<ShapeResult>(direction == TextDirection::kLtr
                                                 ? GetFont(kLatinFont)
                                                 : GetFont(kArabicFont),
                                             0, 0, direction);
  }

  const Font* GetFont(FontType type) const {
    return fonts_holder->fonts + static_cast<size_t>(type);
  }

  FontCachePurgePreventer font_cache_purge_preventer;
  FontDescription font_description;
  Persistent<FontsHolder> fonts_holder;
};

void ShapeResultTest::TestCopyRangesLatin(const ShapeResult* result) const {
  const unsigned num_ranges = 4;
  ShapeResult::ShapeRange ranges[num_ranges] = {
      {0, 10, CreateShapeResult(TextDirection::kLtr)},
      {10, 20, CreateShapeResult(TextDirection::kLtr)},
      {20, 30, CreateShapeResult(TextDirection::kLtr)},
      {30, 38, CreateShapeResult(TextDirection::kLtr)}};
  result->CopyRanges(&ranges[0], num_ranges);

  Vector<ShapeResultTestGlyphInfo> glyphs[num_ranges];
  for (unsigned i = 0; i < num_ranges; i++)
    ComputeGlyphResults(*ranges[i].target, &glyphs[i]);
  EXPECT_EQ(glyphs[0].size(), 10u);
  EXPECT_EQ(glyphs[1].size(), 10u);
  EXPECT_EQ(glyphs[2].size(), 10u);
  EXPECT_EQ(glyphs[3].size(), 8u);

  ShapeResult* reference[num_ranges];
  reference[0] = result->SubRange(0, 10);
  reference[1] = result->SubRange(10, 20);
  reference[2] = result->SubRange(20, 30);
  reference[3] = result->SubRange(30, 38);
  Vector<ShapeResultTestGlyphInfo> reference_glyphs[num_ranges];
  for (unsigned i = 0; i < num_ranges; i++)
    ComputeGlyphResults(*reference[i], &reference_glyphs[i]);
  EXPECT_EQ(reference_glyphs[0].size(), 10u);
  EXPECT_EQ(reference_glyphs[1].size(), 10u);
  EXPECT_EQ(reference_glyphs[2].size(), 10u);
  EXPECT_EQ(reference_glyphs[3].size(), 8u);

  EXPECT_TRUE(CompareResultGlyphs(glyphs[0], reference_glyphs[0], 0u, 10u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[1], reference_glyphs[1], 0u, 10u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[2], reference_glyphs[2], 0u, 10u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[3], reference_glyphs[3], 0u, 8u));
}

void ShapeResultTest::TestCopyRangesArabic(const ShapeResult* result) const {
  const unsigned num_ranges = 4;
  ShapeResult::ShapeRange ranges[num_ranges] = {
      {0, 4, CreateShapeResult(TextDirection::kRtl)},
      {4, 7, CreateShapeResult(TextDirection::kRtl)},
      {7, 10, CreateShapeResult(TextDirection::kRtl)},
      {10, 15, CreateShapeResult(TextDirection::kRtl)}};
  result->CopyRanges(&ranges[0], num_ranges);

  Vector<ShapeResultTestGlyphInfo> glyphs[num_ranges];
  for (unsigned i = 0; i < num_ranges; i++)
    ComputeGlyphResults(*ranges[i].target, &glyphs[i]);
  EXPECT_EQ(glyphs[0].size(), 4u);
  EXPECT_EQ(glyphs[1].size(), 3u);
  EXPECT_EQ(glyphs[2].size(), 3u);
  EXPECT_EQ(glyphs[3].size(), 5u);

  ShapeResult* reference[num_ranges];
  reference[0] = result->SubRange(0, 4);
  reference[1] = result->SubRange(4, 7);
  reference[2] = result->SubRange(7, 10);
  reference[3] = result->SubRange(10, 17);
  Vector<ShapeResultTestGlyphInfo> reference_glyphs[num_ranges];
  for (unsigned i = 0; i < num_ranges; i++)
    ComputeGlyphResults(*reference[i], &reference_glyphs[i]);
  EXPECT_EQ(reference_glyphs[0].size(), 4u);
  EXPECT_EQ(reference_glyphs[1].size(), 3u);
  EXPECT_EQ(reference_glyphs[2].size(), 3u);
  EXPECT_EQ(reference_glyphs[3].size(), 5u);

  EXPECT_TRUE(CompareResultGlyphs(glyphs[0], reference_glyphs[0], 0u, 4u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[1], reference_glyphs[1], 0u, 3u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[2], reference_glyphs[2], 0u, 3u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[3], reference_glyphs[3], 0u, 5u));
}

TEST_F(ShapeResultTest, CopyRangeLatin) {
  String string = "Testing ShapeResultIterator::CopyRange";
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(GetFont(kLatinFont), direction);
  TestCopyRangesLatin(result);
}

// Identical to CopyRangeLatin except the source range shape result is split
// into multiple runs to test the handling of ranges spanning runs and runs
// spanning ranges.
TEST_F(ShapeResultTest, CopyRangeLatinMultiRun) {
  TextDirection direction = TextDirection::kLtr;
  String string = "Testing ShapeResultIterator::CopyRange";
  HarfBuzzShaper shaper_a(string.Substring(0, 5));
  HarfBuzzShaper shaper_b(string.Substring(5, 7));
  HarfBuzzShaper shaper_c(string.Substring(7, 32));
  HarfBuzzShaper shaper_d(string.Substring(32, 38));

  // Combine four separate results into a single one to ensure we have a result
  // with multiple runs.
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(GetFont(kLatinFont), 0, 0, direction);
  shaper_a.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 5u, result);
  shaper_b.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 2u, result);
  shaper_c.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 25u, result);
  shaper_d.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 6u, result);
  TestCopyRangesLatin(result);
}

TEST_F(ShapeResultTest, CopyRangeLatinMultiRunWithHoles) {
  TextDirection direction = TextDirection::kLtr;
  String string = "Testing copying a range with holes";
  HarfBuzzShaper shaper_a(string.Substring(0, 5));
  HarfBuzzShaper shaper_b(string.Substring(5, 7));
  HarfBuzzShaper shaper_c(string.Substring(7, 32));
  HarfBuzzShaper shaper_d(string.Substring(32, 34));

  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(GetFont(kLatinFont), 0, 0, direction);
  shaper_a.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 5u, result);
  shaper_b.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 2u, result);
  shaper_c.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 25u, result);
  shaper_d.Shape(GetFont(kLatinFont), direction)->CopyRange(0u, 2u, result);

  ShapeResult::ShapeRange ranges[] = {
      {4, 17, CreateShapeResult(TextDirection::kLtr)},
      {20, 23, CreateShapeResult(TextDirection::kLtr)},
      {25, 31, CreateShapeResult(TextDirection::kLtr)}};
  result->CopyRanges(&ranges[0], 3);
  Vector<ShapeResultTestGlyphInfo> glyphs[3];
  ComputeGlyphResults(*ranges[0].target, &glyphs[0]);
  ComputeGlyphResults(*ranges[1].target, &glyphs[1]);
  ComputeGlyphResults(*ranges[2].target, &glyphs[2]);
  EXPECT_EQ(glyphs[0].size(), 13u);
  EXPECT_EQ(glyphs[1].size(), 3u);
  EXPECT_EQ(glyphs[2].size(), 6u);

  ShapeResult* reference[3];
  reference[0] = result->SubRange(4, 17);
  reference[1] = result->SubRange(20, 23);
  reference[2] = result->SubRange(25, 31);
  Vector<ShapeResultTestGlyphInfo> reference_glyphs[3];
  ComputeGlyphResults(*reference[0], &reference_glyphs[0]);
  ComputeGlyphResults(*reference[1], &reference_glyphs[1]);
  ComputeGlyphResults(*reference[2], &reference_glyphs[2]);
  EXPECT_EQ(reference_glyphs[0].size(), 13u);
  EXPECT_EQ(reference_glyphs[1].size(), 3u);
  EXPECT_EQ(reference_glyphs[2].size(), 6u);

  EXPECT_TRUE(CompareResultGlyphs(glyphs[0], reference_glyphs[0], 0u, 13u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[1], reference_glyphs[1], 0u, 3u));
  EXPECT_TRUE(CompareResultGlyphs(glyphs[2], reference_glyphs[2], 0u, 6u));
}

TEST_F(ShapeResultTest, CopyRangeArabic) {
  // نص اختبار العربية
  String string(
      u"\u0646\u0635\u0627\u062E\u062A\u0628\u0627\u0631\u0627\u0644\u0639"
      u"\u0631\u0628\u064A\u0629");
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(GetFont(kArabicFont), direction);
  TestCopyRangesArabic(result);
}

// Identical to CopyRangeArabic except the source range shape result is split
// into multiple runs to test the handling of ranges spanning runs and runs
// spanning ranges.
TEST_F(ShapeResultTest, CopyRangeArabicMultiRun) {
  // نص اختبار العربية
  String string(
      u"\u0646\u0635\u0627\u062E\u062A\u0628\u0627\u0631\u0627\u0644\u0639"
      u"\u0631\u0628\u064A\u0629");
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper_a(string.Substring(0, 2));
  HarfBuzzShaper shaper_b(string.Substring(2, 9));
  HarfBuzzShaper shaper_c(string.Substring(9, 15));

  // Combine three separate results into a single one to ensure we have a result
  // with multiple runs.
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(GetFont(kArabicFont), 0, 0, direction);
  shaper_a.Shape(GetFont(kArabicFont), direction)->CopyRange(0u, 2u, result);
  shaper_b.Shape(GetFont(kArabicFont), direction)->CopyRange(0u, 7u, result);
  shaper_c.Shape(GetFont(kArabicFont), direction)->CopyRange(0u, 8u, result);

  TestCopyRangesArabic(result);
}

static struct IsStartSafeToBreakData {
  bool expected;
  const char16_t* text;
  TextDirection direction = TextDirection::kLtr;
  unsigned start_offset = 0;
  unsigned end_offset = 0;
} is_start_safe_to_break_data[] = {
    {true, u"XX", TextDirection::kLtr},
    {true, u"XX", TextDirection::kRtl},
    // SubRange, assuming there is no kerning between "XX".
    {true, u"XX", TextDirection::kLtr, 1, 2},
    {true, u"XX", TextDirection::kRtl, 1, 2},
    // Between "A" and "V" usually have a kerning.
    {false, u"AV", TextDirection::kLtr, 1, 2},
    {false, u"AV", TextDirection::kRtl, 1, 2},
    // SubRange at the middle of a cluster.
    // U+06D7 ARABIC SMALL HIGH LIGATURE QAF WITH LAM WITH ALEF MAKSURA
    {false, u" \u06D7", TextDirection::kLtr, 1, 2},
    {false, u" \u06D7", TextDirection::kRtl, 1, 2},
    {false, u" \u06D7.", TextDirection::kLtr, 1, 3},
    {false, u" \u06D7.", TextDirection::kRtl, 1, 3},
};

class IsStartSafeToBreakDataTest
    : public ShapeResultTest,
      public testing::WithParamInterface<IsStartSafeToBreakData> {};

INSTANTIATE_TEST_SUITE_P(ShapeResultTest,
                         IsStartSafeToBreakDataTest,
                         testing::ValuesIn(is_start_safe_to_break_data));

TEST_P(IsStartSafeToBreakDataTest, IsStartSafeToBreakData) {
  const IsStartSafeToBreakData data = GetParam();
  String string(data.text);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(GetFont(kLatinFont), data.direction);
  if (data.end_offset)
    result = result->SubRange(data.start_offset, data.end_offset);
  EXPECT_EQ(result->IsStartSafeToBreak(), data.expected);
}

TEST_F(ShapeResultTest, AddUnsafeToBreakLtr) {
  HarfBuzzShaper shaper(u"ABC\u3042DEFG");
  ShapeResult* result = shaper.Shape(GetFont(kLatinFont), TextDirection::kLtr);
  Vector<unsigned> offsets{2, 5};
  for (const unsigned offset : offsets) {
    EXPECT_EQ(result->NextSafeToBreakOffset(offset), offset);
  }
  result->AddUnsafeToBreak(offsets);
  result->EnsurePositionData();
  for (const unsigned offset : offsets) {
    EXPECT_NE(result->NextSafeToBreakOffset(offset), offset);
    EXPECT_NE(result->CachedNextSafeToBreakOffset(offset), offset);
  }
}

TEST_F(ShapeResultTest, AddUnsafeToBreakRtl) {
  HarfBuzzShaper shaper(u"\u05d0\u05d1\u05d2\u05d3\u05d4\u05d5");
  ShapeResult* result = shaper.Shape(GetFont(kArabicFont), TextDirection::kRtl);
  Vector<unsigned> offsets{2, 5};
  for (const unsigned offset : offsets) {
    EXPECT_EQ(result->NextSafeToBreakOffset(offset), offset);
  }
  result->AddUnsafeToBreak(offsets);
  result->EnsurePositionData();
  for (const unsigned offset : offsets) {
    EXPECT_NE(result->NextSafeToBreakOffset(offset), offset);
    EXPECT_NE(result->CachedNextSafeToBreakOffset(offset), offset);
  }
}

TEST_F(ShapeResultTest, AddUnsafeToBreakRange) {
  const String string{u"0ABC\u3042DEFG"};
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(GetFont(kLatinFont), TextDirection::kLtr,
                                     1, string.length());
  Vector<unsigned> offsets{2, 5, 7};
  for (const unsigned offset : offsets) {
    EXPECT_EQ(result->NextSafeToBreakOffset(offset), offset);
  }
  result->AddUnsafeToBreak(offsets);
  result->EnsurePositionData();
  for (const unsigned offset : offsets) {
    EXPECT_NE(result->NextSafeToBreakOffset(offset), offset);
    EXPECT_NE(result->CachedNextSafeToBreakOffset(offset), offset);
  }
}

TEST_F(ShapeResultTest, ComputeInkBoundsWithZeroOffset) {
  String string(u"abc");
  HarfBuzzShaper shaper(string);
  const auto* result = shaper.Shape(GetFont(kLatinFont), TextDirection::kLtr);
  EXPECT_FALSE(HasNonZeroGlyphOffsets(*result));
  EXPECT_FALSE(result->ComputeInkBounds().IsEmpty());
}

struct TextAutoSpaceTextData {
  // The string that should be processed.
  const UChar* string;
  // Precalculated insertion points' offsets.
  std::vector<wtf_size_t> offsets;

} text_auto_space_test_data[] = {
    {u"Abcあああ", {3}},
    {u"ああ123あああ", {2, 5}},
    {u"ああ123ああ", {2, 5}},
    {u"ああ123ああ", {1, 2, 3, 4, 5, 6, 7}},
};
class TextAutoSpaceResultText
    : public ShapeResultTest,
      public testing::WithParamInterface<TextAutoSpaceTextData> {};
INSTANTIATE_TEST_SUITE_P(ShapeResultTest,
                         TextAutoSpaceResultText,
                         testing::ValuesIn(text_auto_space_test_data));

Vector<float> RecordPositionBeforeApplyingSpacing(ShapeResult* result,
                                                  wtf_size_t size) {
  Vector<float> before_adding_spacing(size);
  std::generate(before_adding_spacing.begin(), before_adding_spacing.end(),
                [&, i = 0]() mutable {
                  float position = result->PositionForOffset(i);
                  i++;
                  return position;
                });
  return before_adding_spacing;
}

Vector<OffsetWithSpacing, 16> RecordExpectedSpacing(
    const std::vector<wtf_size_t>& offsets_data) {
  Vector<OffsetWithSpacing, 16> offsets(offsets_data.size());
  std::generate_n(offsets.begin(), offsets_data.size(), [&, i = -1]() mutable {
    ++i;
    return OffsetWithSpacing{.offset = offsets_data[i],
                             .spacing = static_cast<float>(0.1 * (i + 1))};
  });
  return offsets;
}

// Tests the spacing should be appended at the correct positions.
TEST_P(TextAutoSpaceResultText, AddAutoSpacingToIdeograph) {
  const auto& test_data = GetParam();
  String string(test_data.string);
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(GetFont(kLatinFont), TextDirection::kLtr);

  // Record the position before applying text-autospace, and fill the spacing
  // widths with different values.
  Vector<float> before_adding_spacing =
      RecordPositionBeforeApplyingSpacing(result, string.length());
  Vector<OffsetWithSpacing, 16> offsets =
      RecordExpectedSpacing(test_data.offsets);
  result->ApplyTextAutoSpacing(offsets);
  float accumulated_spacing = 0.0;
  for (wtf_size_t i = 0, j = 0; i < string.length(); i++) {
    if (j < test_data.offsets.size() && offsets[j].offset == i) {
      accumulated_spacing += offsets[j].spacing;
      j++;
    }
    EXPECT_NEAR(accumulated_spacing,
                result->PositionForOffset(i) - before_adding_spacing[i],
                /* abs_error= */ 1e-5);
  }
}

// TDOO(yosin): We should use a font including U+0A81 or other code point
// having non-zero glyph offset.
TEST_F(ShapeResultTest, DISABLED_ComputeInkBoundsWithNonZeroOffset) {
  // U+0A81 has non-zero glyph offset
  String string(u"xy\u0A81z");
  HarfBuzzShaper shaper(string);
  const auto* result = shaper.Shape(GetFont(kLatinFont), TextDirection::kLtr);
  ASSERT_TRUE(HasNonZeroGlyphOffsets(*result));
  EXPECT_FALSE(result->ComputeInkBounds().IsEmpty());
}

// Tests for CaretPositionForOffset
struct CaretPositionForOffsetTestData {
  // The string that should be processed.
  const UChar* string;
  // Text direction to test
  TextDirection direction;
  // The offsets to test.
  std::vector<wtf_size_t> offsets;
  // Expected positions.
  std::vector<float> positions;
  // The font to use
  ShapeResultTest::FontType font;
  // Adjust mid cluster value
  AdjustMidCluster adjust_mid_cluster;
} caret_position_for_offset_test_data[] = {
    // 0
    {u"012345678901234567890123456789",
     TextDirection::kLtr,
     {0, 1, 4, 5, 12, 18, 30, 32},
#if BUILDFLAG(IS_APPLE)
     {0, 6.738, 26.953, 33.691, 80.859, 121.289, 202.148, 0},
#else
     {0, 7, 28, 35, 84, 126, 210, 0},
#endif
     ShapeResultTest::kLatinFont,
     AdjustMidCluster::kToStart},

    // 1
    {u"012345678901234567890123456789",
     TextDirection::kRtl,
     {0, 1, 4, 5, 12, 18, 30, 32},
#if BUILDFLAG(IS_APPLE)
     {202.148, 195.410, 175.195, 168.457, 121.289, 80.859, 0, 0},
#else
     {210, 203, 182, 175, 126, 84, 0, 0},
#endif
     ShapeResultTest::kLatinFont,
     AdjustMidCluster::kToStart},

    // 2
    {u"0ff1ff23fff456ffff7890fffff12345ffffff6789",
     TextDirection::kLtr,
     {0, 1, 4, 5, 12, 18, 42, 43},
#if BUILDFLAG(IS_APPLE)
     {0, 6.738, 21.809, 25.975, 62.85, 92.994, 226.418, 0},
#else
     {0, 7, 22, 26, 63, 93, 228, 0},
#endif
     ShapeResultTest::kLatinFont,
     AdjustMidCluster::kToStart},

    // 3
    {u"0ff1ff23fff456ffff7890fffff12345ffffff6789",
     TextDirection::kRtl,
     {0, 1, 4, 5, 12, 18, 42, 43},
#if BUILDFLAG(IS_APPLE)
     {226.418, 219.680, 204.609, 200.443, 163.564, 133.424, 0, 0},
#else
     {228, 221, 206, 202, 165, 135, 0, 0},
#endif
     ShapeResultTest::kLatinFont,
     AdjustMidCluster::kToStart},

    // 4
    {u"مَ1مَمَ2مَمَمَ3مَمَمَمَ4مَمَمَمَمَ5مَمَمَمَمَمَ",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 30, 47},
#if BUILDFLAG(IS_APPLE)
     {0, 0, 5.865, 12.727, 12.727, 19.061, 37.723, 55.008, 66.299, 99.832,
      148.746},
#elif BUILDFLAG(IS_WIN)
     {0, 0, 6, 13, 13, 19, 37, 54, 65, 98, 146},
#else
     {0, 0, 6, 13, 13, 20, 40, 58, 70, 105, 156},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToStart},

    // 5
    {u"مَ1مَمَ2مَمَمَ3مَمَمَمَ4مَمَمَمَمَ5مَمَمَمَمَمَ",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 30, 47},
#if BUILDFLAG(IS_APPLE)
     {0, 5.865, 5.865, 12.727, 19.061, 19.061, 37.723, 55.008, 71.256, 99.832,
      148.746},
#elif BUILDFLAG(IS_WIN)
     {0, 6, 6, 13, 19, 19, 37, 54, 70, 98, 146},
#else
     {0, 6, 6, 13, 20, 20, 40, 58, 75, 105, 156},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToEnd},

    // 6
    {u"مَ1مَمَ2مَمَمَ3مَمَمَمَ4مَمَمَمَمَ5مَمَمَمَمَمَ",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 30, 47},
#if BUILDFLAG(IS_APPLE)
     {148.746, 148.746, 142.881, 136.02, 136.02, 130.553, 111.891, 93.738,
      83.315, 49.781, 0},
#elif BUILDFLAG(IS_WIN)
     {146, 146, 140, 133, 133, 128, 110, 92, 82, 49, 0},
#else
     {156, 156, 150, 143, 143, 137, 117, 98, 87, 52, 0},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToStart},

    // 7
    {u"مَ1مَمَ2مَمَمَ3مَمَمَمَ4مَمَمَمَمَ5مَمَمَمَمَمَ",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 30, 47},
#if BUILDFLAG(IS_APPLE)
     {148.746, 142.881, 142.881, 136.02, 130.553, 130.553, 111.891, 93.738,
      78.357, 49.781, 0},
#elif BUILDFLAG(IS_WIN)
     {146, 140, 140, 133, 128, 128, 110, 92, 77, 49, 0},
#else
     {156, 150, 150, 143, 137, 137, 117, 98, 82, 52, 0},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToEnd},

    // 8
    {u"あ1あمَ2あمَあ3あمَあمَ4あمَあمَあ5",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 25, 26},
#if BUILDFLAG(IS_APPLE)
     {0, 12, 18.86, 30.86, 30.86, 36.73, 73.45, 110.18, 134.91, 170.64, 177.5},
#else
     {0, 12, 19, 31, 31, 37, 74, 111, 136, 172, 179},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToStart},

    // 9
    {u"あ1あمَ2あمَあ3あمَあمَ4あمَあمَあ5",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 26},
#if BUILDFLAG(IS_APPLE)
     {0, 12, 18.86, 30.86, 36.73, 36.73, 73.45, 110.18, 140.77, 177.5},
#else
     {0, 12, 19, 31, 37, 37, 74, 111, 142, 179},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToEnd},

    // 10
    {u"あ1あمَ2あمَあ3あمَあمَ4あمَあمَあ5",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 26},
#if BUILDFLAG(IS_APPLE)
     {177.5, 165.5, 158.64, 146.64, 146.64, 140.77, 104.04, 67.32, 42.59, 0},
#else
     {179, 167, 160, 148, 148, 142, 105, 68, 43, 0},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToStart},

    // 11
    {u"あ1あمَ2あمَあ3あمَあمَ4あمَあمَあ5",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 26},
#if BUILDFLAG(IS_APPLE)
     {177.5, 165.5, 158.64, 146.64, 140.77, 140.77, 104.04, 67.32, 36.73, 0},
#else
     {179, 167, 160, 148, 142, 142, 105, 68, 37, 0},
#endif
     ShapeResultTest::kArabicFont,
     AdjustMidCluster::kToEnd},

    // 12
    {u"楽しいドライブ、012345楽しいドライブ、",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 22},
#if BUILDFLAG(IS_APPLE)
     {0, 12, 24, 36, 48, 60, 110.88, 152.64, 212.63, 236.64},
#else
     {0, 12, 24, 36, 48, 60, 110, 150, 210, 234},
#endif
     ShapeResultTest::kCJKFont,
     AdjustMidCluster::kToStart},

    // 13
    {u"楽しいドライブ、012345楽しいドライブ、",
     TextDirection::kLtr,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 22},
#if BUILDFLAG(IS_APPLE)
     {0, 12, 24, 36, 48, 60, 110.88, 152.64, 212.63, 236.64},
#else
     {0, 12, 24, 36, 48, 60, 110, 150, 210, 234},
#endif
     ShapeResultTest::kCJKFont,
     AdjustMidCluster::kToEnd},

    // 14
    {u"楽しいドライブ、012345楽しいドライブ、",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 22},
#if BUILDFLAG(IS_APPLE)
     {236.64, 224.64, 212.64, 200.64, 188.64, 176.64, 125.76, 84, 24, 0},
#else
     {234, 222, 210, 198, 186, 174, 124, 84, 24, 0},
#endif
     ShapeResultTest::kCJKFont,
     AdjustMidCluster::kToStart},

    // 15
    {u"楽しいドライブ、012345楽しいドライブ、",
     TextDirection::kRtl,
     {0, 1, 2, 3, 4, 5, 10, 15, 20, 22},
#if BUILDFLAG(IS_APPLE)
     {236.64, 224.64, 212.64, 200.64, 188.64, 176.64, 125.76, 84, 24, 0},
#else
     {234, 222, 210, 198, 186, 174, 124, 84, 24, 0},
#endif
     ShapeResultTest::kCJKFont,
     AdjustMidCluster::kToEnd},
};
class CaretPositionForOffsetTest
    : public ShapeResultTest,
      public testing::WithParamInterface<CaretPositionForOffsetTestData> {};
INSTANTIATE_TEST_SUITE_P(
    ShapeResult,
    CaretPositionForOffsetTest,
    testing::ValuesIn(caret_position_for_offset_test_data));

TEST_P(CaretPositionForOffsetTest, CaretPositionForOffsets) {
  const auto& test_data = GetParam();
  String text_string(test_data.string);
  HarfBuzzShaper shaper(text_string);
  const ShapeResult* result =
      shaper.Shape(GetFont(test_data.font), test_data.direction);
  StringView text_view(text_string);

  for (wtf_size_t i = 0; i < test_data.offsets.size(); ++i) {
    EXPECT_NEAR(test_data.positions[i],
                result->CaretPositionForOffset(test_data.offsets[i], text_view,
                                               test_data.adjust_mid_cluster),
                0.01f);
  }
}

// Tests for OffsetForPosition
struct CaretOffsetForPositionTestData {
  // The string that should be processed.
  const UChar* string;
  // Text direction to test
  TextDirection direction;
  // The positions to test.
  std::vector<wtf_size_t> positions;
  // The expected offsets.
  std::vector<wtf_size_t> offsets;
  // The font to use
  ShapeResultTest::FontType font;
  // IncludePartialGlyphsOption value
  IncludePartialGlyphsOption partial_glyphs_option;
  // BreakGlyphsOption value
  BreakGlyphsOption break_glyphs_option;
} caret_offset_for_position_test_data[] = {
    // 0
    {u"0123456789",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1,  6,  7,  13, 14, 20, 21, 26, 27, 33,
      34, 40, 41, 47, 48, 53, 54, 60, 61, 67},
     {0,  0,  1,  1,  2,  2,  3,  3,  4,  4,
      5,  5,  6,  6,  7,  7,  8,  8,  9,  9},
#else
     {1,  6,  7,  13, 14, 20, 21, 27, 28, 34,
      35, 41, 42, 48, 49, 55, 56, 62, 63, 69},
     {0,  0,  1,  1,  2,  2,  3,  3,  4,  4,
      5,  5,  6,  6,  7,  7,  8,  8,  9,  9},
#endif
     ShapeResultTest::kLatinFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 1
    {u"0123456789",
     TextDirection::kRtl,
#if BUILDFLAG(IS_APPLE)
     {1,  6,  7,  13, 14, 20, 21, 26, 27, 33,
      34, 40, 41, 47, 48, 53, 54, 60, 61, 67},
     {9,  9,  8,  8,  7,  7,  6,  6,  5,  5,
      4,  4,  3,  3,  2,  2,  1,  1,  0,  0},
#else
     {1,  7,  8,  14, 15, 21, 22, 28, 29, 35,
      36, 42, 43, 49, 50, 56, 57, 63, 64, 69},
     {9,  9,  8,  8,  7,  7,  6,  6,  5,  5,
      4,  4,  3,  3,  2,  2,  1,  1,  0,  0},
#endif
     ShapeResultTest::kLatinFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 2
    {u"0ff1fff23ff",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1,  6,  7,  10, 11, 15, 16, 21, 22, 25, 26,
      30, 31, 34, 35, 41, 42, 47, 48, 51, 52, 56},
     {0,  0,  1,  1,  2,  2,  3,  3,  4,  4,  5,
      5,  6,  6,  7,  7,  8,  8,  9,  9,  10, 10},
#else
     {1,  6,  7,  10, 11, 14, 15, 21, 22, 25, 26,
      29, 30, 33, 34, 40, 41, 47, 48, 51, 52, 55},
     {0,  0,  1,  1,  2,  2,  3,  3,  4,  4,  5,
      5,  6,  6,  7,  7,  8,  8,  9,  9, 10, 10},
#endif
     ShapeResultTest::kLatinFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 3
    {u"0ff1fff23ff",
     TextDirection::kRtl,
#if BUILDFLAG(IS_APPLE)
     {1,  4,  5,  8,  9,  15, 16, 21, 22, 25, 26,
      30, 31, 34, 35, 41, 42, 45, 46, 49, 50, 56},
     {10, 10, 9,  9,  8,  8,  7,  7,  6,  6,  5,
      5,  4,  4,  3,  3,  2,  2,  1,  1,  0,  0},
#else
     {1,  4,  5,  8,  9,  15, 16, 22, 23, 26, 27,
      30, 31, 34, 35, 41, 42, 45, 46, 49, 50, 55},
     {10, 10, 9,  9,  8,  8,  7,  7,  6,  6,  5,
      5,  4,  4,  3,  3,  2,  2,  1,  1,  0,  0},
#endif
     ShapeResultTest::kLatinFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 4
    {u"مَ1مَمَ2مَمَمَ3",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1, 5, 6, 12, 13, 19, 20, 24, 25, 31, 32, 37, 38, 42, 43, 48, 49, 55},
     {0, 0, 2, 2,  3,  3,  5,  5,  7,  7,  8,  8,  10, 10, 12, 12, 14, 14},
#elif BUILDFLAG(IS_WIN)
     {1, 5, 6, 12, 13, 18, 19, 23, 24, 30, 31, 36, 37, 41, 42, 46, 47, 53},
     {0, 0, 2, 2,  3,  3,  5,  5,  7,  7,  8,  8,  10, 10, 12, 12, 14, 14},
#else
     {1, 5, 6, 12, 13, 19, 20, 25, 26, 32, 33, 39, 40, 44, 45, 50, 51, 57},
     {0, 0, 2, 2,  3,  3,  5,  5,  7,  7,  8,  8,  10, 10, 12, 12, 14, 14},
#endif
     ShapeResultTest::kArabicFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 5
    {u"مَ1مَمَ2مَمَمَ3",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1,  2,  3,  9,  10, 15, 16, 21, 22, 27,
      28, 34, 35, 40, 41, 45, 46, 51, 52, 55},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#elif BUILDFLAG(IS_WIN)
     {1,  3,  4,  9,  10, 16, 17, 21, 22, 27,
      28, 34, 35, 39, 40, 44, 45, 50, 51, 53},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#else
     {1,  3,  4,  9,  10, 16, 17, 23, 24, 29,
      30, 36, 37, 42, 43, 48, 49, 54, 55, 57},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#endif
     ShapeResultTest::kArabicFont,
     kIncludePartialGlyphs,
     BreakGlyphsOption(false)},

    // 6
    {u"مَ1مَمَ2مَمَمَ3",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1,  2,  3,  9,  10, 15, 16, 21, 22, 27,
      28, 34, 35, 40, 41, 45, 46, 51, 52, 55},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#elif BUILDFLAG(IS_WIN)
     {1,  3,  4,  9,  10, 16, 17, 21, 22, 27,
      28, 34, 35, 39, 40, 44, 45, 50, 51, 54},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#else
     {1,  3,  4,  9,  10, 16, 17, 23, 24, 29,
      30, 36, 37, 42, 43, 48, 49, 54, 55, 57},
     {0,  0,  2,  2,  3,  3,  5,  5,  7,  7,
      8,  8,  10, 10, 12, 12, 14, 14, 15, 15},
#endif
     ShapeResultTest::kArabicFont,
     kIncludePartialGlyphs,
     BreakGlyphsOption(true)},

    // 7
    {u"مَ1مَمَ2مَمَمَ3",
     TextDirection::kRtl,
#if BUILDFLAG(IS_APPLE)
     {1,  6,  7,  13, 14, 18, 19, 23, 24, 30, 31, 36, 37, 42, 43, 49, 50, 55},
     {14, 14, 12, 12, 10, 10, 8,  8,  7,  7,  5,  5,  3,  3,  2,  2,  0,  0},
#elif BUILDFLAG(IS_WIN)
     {1,  7,  8,  13, 14, 18, 19, 23, 24, 30, 31, 36, 37, 41, 42, 48, 49, 53},
     {14, 14, 12, 12, 10, 10, 8,  8,  7,  7,  5,  5,  3,  3,  2,  2,  0,  0},
#else
     {1,  7,  8,  14, 15, 19, 20, 25, 26, 32, 33, 39, 40, 45, 46, 52, 53, 57},
     {14, 14, 12, 12, 10, 10, 8,  8,  7,  7,  5,  5,  3,  3,  2,  2,  0,  0},
#endif
     ShapeResultTest::kArabicFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 8
    {u"مَ1مَمَ2مَمَمَ3",
     TextDirection::kRtl,
#if BUILDFLAG(IS_APPLE)
     {1,  3,  4,  10, 11, 15, 16, 20, 21, 27,
      28, 33, 34, 39, 40, 45, 46, 52, 53, 55},
     {15, 15, 14, 14, 12, 12, 10, 10, 8,  8,
      7,  7,  5,  5,  3,  3,  2,  2,  0,  0},
#elif BUILDFLAG(IS_WIN)
     {1,  3,  4,  10, 11, 15, 16, 20, 21, 26,
      27, 33, 34, 38, 39, 44, 45, 51, 52, 53},
     {15, 15, 14, 14, 12, 12, 10, 10, 8,  8,
      7,  7,  5,  5,  3,  3,  2,  2,  0,  0},
#else
     {1,  3,  4,  10, 11, 16, 17, 22, 23, 28,
      29, 35, 36, 42, 43, 48, 49, 55, 56, 57},
     {15, 15, 14, 14, 12, 12, 10, 10, 8,  8,
      7,  7,  5,  5,  3,  3,  2,  2,  0, 0},
#endif
     ShapeResultTest::kArabicFont,
     kIncludePartialGlyphs,
     BreakGlyphsOption(true)},

    // 9
    {u"あ1あمَ2あمَあ",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {0, 11, 12, 18, 19, 30, 31, 36, 37, 43, 44, 55, 56, 61, 62, 73},
     {0, 0,  1,  1,  2,  2,  3,  3,  5,  5,  6,  6,  7,  7,  9,  9},
#else
     {1, 11, 12, 18, 19, 30, 31, 36, 37, 43, 44, 55, 56, 61, 62, 73},
     {0, 0,  1,  1,  2,  2,  3,  3,  5,  5,  6,  6,  7,  7,  9,  9},
#endif
     ShapeResultTest::kArabicFont,
     kOnlyFullGlyphs,
     BreakGlyphsOption(false)},

    // 10
    {u"あ1あمَ2あمَあ",
     TextDirection::kLtr,
#if BUILDFLAG(IS_APPLE)
     {1, 6, 7, 15, 16, 24, 25, 33, 34, 40, 41, 49, 50, 58, 59, 67, 68, 73},
     {0, 0, 1, 1,  2,  2,  3,  3,  5,  5,  6,  6,  7,  7,  9,  9,  10, 10},
#else
     {1, 6, 7, 15, 16, 25, 26, 34, 35, 40, 41, 50, 51, 59, 60, 68, 69, 73},
```