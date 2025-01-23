Response:
The user wants me to analyze a C++ source code file, specifically the second part of `harfbuzz_shaper_test.cc`.

Here's a plan:
1. **Summarize the functionality of this code snippet.** This involves looking at the test cases and the operations they perform.
2. **Identify connections to web technologies (JavaScript, HTML, CSS).** This will involve understanding what aspects of text rendering this code tests.
3. **Analyze logical reasoning with input/output examples.**  Examine test cases that involve conditional logic and demonstrate the expected behavior.
4. **Point out potential user or programming errors.**  Consider common mistakes related to the functionalities being tested.这个代码片段主要的功能是**测试 HarfBuzzShaper 类在处理各种文本和字体场景下的字符整形能力，特别是针对 emoji 和特殊字符的处理，以及在文本布局中处理间距和位置计算的能力。**

具体来说，它涵盖了以下几个方面的测试：

**1. Emoji 和变体选择器 (Variation Selector, VS) 的处理:**

*   **`SystemEmojiVSAbsent` 和 `SystemEmojiVS16`:**  测试当系统中缺少特定 emoji 字体或者使用 VS 时，`HarfBuzzShaper` 如何选择合适的字体。
    *   **假设输入:**  包含带有或不带有 VS 的 emoji 字符的字符串，以及不同的字体对象（例如，仅支持单色 emoji 的字体和支持彩色 emoji 的字体）。
    *   **预期输出:** `GetShapedFontFamilyNameForEmojiVS` 函数返回预期的字体名称（例如，系统彩色 emoji 字体，系统单色 emoji 字体，或者特定的 Noto emoji 字体）。
*   **`FontVariantEmojiTest`:** 测试在启用 `FontVariantEmoji` 功能的情况下，如何根据请求的 emoji 变体（例如，文本表示或 emoji 图形表示）选择合适的字体。
    *   **假设输入:**  不带 VS 的 emoji 字符的字符串，以及不同的字体对象，但创建字体时指定了不同的 `FontVariantEmoji` 参数 (`kEmojiVariantEmoji`, `kTextVariantEmoji`, `kUnicodeVariantEmoji`)。
    *   **预期输出:**  `GetShapedFontFamilyNameForEmojiVS` 函数根据请求的变体返回预期的字体名称。
*   **`VSOverrideFontVariantEmoji`:** 测试当文本中同时包含带有 VS 和不带 VS 的 emoji 时，`HarfBuzzShaper` 如何处理，以及 VS 是否会覆盖 `FontVariantEmoji` 的设置。
    *   **假设输入:**  包含带有和不带有 VS 的 emoji 字符的字符串，使用指定了 `kEmojiVariantEmoji` 的字体。
    *   **预期输出:**  `Shape` 方法将文本分割成多个 run，每个 run 使用合适的字体进行渲染。带有 VS 的 emoji 会使用系统字体，而不带 VS 的 emoji 会根据字体的设置来处理。
*   **`FontVariantEmojiTextSystemFallback`:** 测试当请求文本样式的 emoji 但当前字体不支持时，系统如何回退到合适的单色字体。
    *   **假设输入:**  一个 Unicode 字符，请求使用 `kTextVariantEmoji` 风格的彩色字体进行渲染。
    *   **预期输出:**  `GetShapedFontFamilyNameForEmojiVS` 函数返回系统单色 emoji 字体的名称。

**2. 字符间距 (Letter Spacing) 的处理:**

*   **`NegativeLetterSpacing`:** 测试负的字符间距是否能正确应用。
    *   **假设输入:**  字符串 "Hello"，以及一个设置了负字符间距的 `FontDescription`。
    *   **预期输出:**  应用间距后，`ShapeResult` 的宽度会减少相应的量。
*   **`NegativeLetterSpacingTo0` 和 `NegativeLetterSpacingToNegative`:** 测试当负的字符间距导致字符宽度变为 0 或负数时，`HarfBuzzShaper` 的行为 (注释表明 CSS 不允许负宽度，应该被限制为 0)。

**3. 字形数据范围 (Glyph Data Range) 的查询:**

*   **`GlyphDataRangeTest`:** 测试 `FindGlyphDataRange` 函数能否正确返回指定字符范围内的字形数据。这对于处理组合字符或者连字非常重要。
    *   **假设输入:**  包含组合字符（如希伯来语字符和音标符号，或者带有零宽度连接符 ZWJ 的阿拉伯语字符）的字符串，以及需要查询的字符范围。
    *   **预期输出:**  `FindGlyphDataRange` 函数返回的字形范围与预期的字形索引范围一致。

**4. 根据位置查找字符偏移量 (Offset For Position) 和根据偏移量查找位置 (Position For Offset):**

*   **`OffsetForPositionTest`:** 测试 `OffsetForPosition` 和 `CaretOffsetForHitTest` 函数在给定屏幕位置的情况下，能否正确返回对应的字符偏移量，以及 `OffsetToFit` 函数能否根据给定位置和文本方向找到合适的偏移量。 使用固定宽度的字体进行测试。
    *   **假设输入:**  一个固定宽度的字符串，以及不同的屏幕位置值。
    *   **预期输出:**  函数返回的偏移量与预期的偏移量一致。
*   **`PositionForOffsetLatin`, `PositionForOffsetArabic`, `EmojiZWJSequence`:** 测试 `PositionForOffset` 函数能否正确返回给定字符偏移量对应的屏幕位置，包括拉丁字符、阿拉伯字符和 Emoji ZWJ 序列。
    *   **假设输入:**  不同类型的字符串，以及字符偏移量。
    *   **预期输出:**  函数返回的屏幕位置与预期的位置接近。
*   **`IncludePartialGlyphsTest`:**  测试 `OffsetForPosition` 函数在 `IncludePartialGlyphsOption` 参数不同时的行为，并验证其与 `PositionForOffset` 函数的对应关系。
    *   **假设输入:**  不同类型的字符串和屏幕位置。
    *   **预期输出:**  在不同的 `IncludePartialGlyphsOption` 设置下，`OffsetForPosition` 返回的偏移量与 `PositionForOffset` 计算出的位置相对应。
*   **`CachedOffsetPositionMappingForOffsetLatin`, `CachedOffsetPositionMappingArabic`, `CachedOffsetPositionMappingMixed`:** 测试缓存的偏移量-位置映射是否正确。
    *   **假设输入:**  不同类型的字符串。
    *   **预期输出:**  `CachedOffsetForPosition` 和 `CachedPositionForOffset` 能够互相映射，返回正确的偏移量和位置。
*   **`PositionForOffsetMultiGlyphClusterLtr` 和 `PositionForOffsetMultiGlyphClusterRtl`:** 测试对于由多个字形组成的字符簇，`PositionForOffset` 函数是否返回相同的位置。
    *   **假设输入:**  包含组合字符的字符串。
    *   **预期输出:**  组成一个字符簇的多个字符的 `CachedPositionForOffset` 返回相同的值。
*   **`PositionForOffsetMissingGlyph`:**  测试当 `ShapeResult` 中缺少某些字形数据时，`PositionForOffset` 是否会崩溃。

**5. `ShapeResult` 的拷贝和合并:**

*   **`ShapeResultCopyRangeTest` 和 `ShapeResultCopyRangeIntoLatin`, `ShapeResultCopyRangeIntoArabicThaiHanLatin`:** 测试 `CopyRange` 函数能否正确地将 `ShapeResult` 的一部分拷贝到另一个 `ShapeResult` 中，并测试将分割的 `ShapeResult` 重新组合后是否与原始的 `ShapeResult` 一致。
    *   **假设输入:**  不同类型的字符串和分割点。
    *   **预期输出:**  拷贝和合并后的 `ShapeResult` 的字符数、宽度、位置信息等与原始的 `ShapeResult` 一致。
*   **`ShapeResultCopyRangeAcrossRuns` 和 `ShapeResultCopyRangeContextMultiRuns`:** 测试 `CopyRange` 和 `SubRange` 函数在处理跨越多个渲染 run 的文本时的行为。
    *   **假设输入:**  包含多种语言和字符的字符串，导致生成多个渲染 run。
    *   **预期输出:**  拷贝或创建子范围后的 `ShapeResult` 包含预期的字符数。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关系到 Chromium Blink 引擎中处理文本渲染的核心部分，因此与 JavaScript, HTML, CSS 的功能密切相关：

*   **JavaScript:** JavaScript 可以动态地生成和修改网页内容，包括文本。`HarfBuzzShaper` 的正确性直接影响到 JavaScript 操作文本后在页面上的显示是否正确，例如，对于包含 emoji 或复杂脚本的文本。
*   **HTML:** HTML 定义了网页的结构和内容，其中包含大量的文本信息。`HarfBuzzShaper` 负责将 HTML 中的文本内容转换为浏览器可以绘制的字形，包括处理各种字符编码、语言和字体。
*   **CSS:** CSS 用于控制网页的样式，包括字体、字号、字符间距、排版方向等。`HarfBuzzShaper` 需要能够根据 CSS 的样式规则来正确地进行字符整形和布局。

**举例说明:**

*   **HTML 中的 Emoji 显示:**  当 HTML 中包含 emoji 字符（例如 `&#x1F600;` 或直接使用 emoji 字符）时，`HarfBuzzShaper` 需要判断系统是否支持彩色 emoji 字体，如果支持则使用彩色字体渲染，否则可能回退到单色字体。  `SystemEmojiVSAbsent` 和 `SystemEmojiVS16` 等测试覆盖了这种情况。
*   **CSS 中的 `letter-spacing` 属性:**  当 CSS 中设置了 `letter-spacing` 属性时，`HarfBuzzShaper` 在进行字符整形后需要应用这个间距。`NegativeLetterSpacing` 等测试确保了负的字符间距也能被正确处理。
*   **JavaScript 获取文本宽度:**  JavaScript 可以使用 `offsetWidth` 或 `getBoundingClientRect()` 等方法获取元素的尺寸，这依赖于浏览器对文本的渲染。`HarfBuzzShaper` 的位置计算功能（例如 `PositionForOffset`）的正确性直接影响到这些 JavaScript API 返回值的准确性。
*   **文本光标的定位:**  当用户在网页的文本输入框中移动光标时，浏览器需要根据光标的位置找到对应的字符偏移量，这需要用到 `OffsetForPosition` 这样的功能。

**用户或编程常见的使用错误举例:**

*   **用户没有安装支持彩色 emoji 的字体:**  在这种情况下，即使网页使用了 emoji 字符，浏览器也可能只能显示单色版本或者方框。`SystemEmojiVSAbsent` 的测试模拟了这种情况。
*   **开发者错误地使用了负的 `letter-spacing` 导致文本重叠:** 虽然 CSS 规范可能会限制负的 `letter-spacing` 的行为，但是开发者仍然可能尝试使用，`NegativeLetterSpacingTo0` 和 `NegativeLetterSpacingToNegative` 的测试就关注了这种边缘情况。
*   **在处理复杂文本（例如阿拉伯语或印地语）时，没有考虑到字符的组合和变形:**  `GlyphDataRangeTest` 和 `PositionForOffsetMultiGlyphClusterLtr/Rtl` 等测试覆盖了这些场景，如果字符整形不正确，可能会导致文本显示错乱。
*   **在 JavaScript 中进行文本操作时，没有考虑到 Unicode 的复杂性:**  例如，错误地将一个 emoji 表情符号（可能由多个 Unicode 码点组成）当作一个字符处理，这可能会导致与 `HarfBuzzShaper` 的行为不一致。

**归纳一下它的功能:**

总而言之，这个代码片段是 `harfbuzz_shaper_test.cc` 文件的一部分，专注于**测试 HarfBuzzShaper 类在处理各种字符、特别是 emoji 和复杂脚本时的字符整形和布局能力，以及对字符间距和位置计算的正确性验证。** 它通过大量的单元测试，覆盖了各种边界情况和特殊场景，确保 Blink 引擎能够准确地渲染网页上的文本内容。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_shaper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
;
  Font color_font = CreateNotoColorEmoji();

  String text_default(
      u"\u2603"
      u"\ufe0e");
  String emoji_default(
      u"\u2614"
      u"\ufe0e");
  for (String text : {text_default, emoji_default}) {
    EXPECT_EQ(MaybeStripFontationsSuffix(
                  GetShapedFontFamilyNameForEmojiVS(mono_font, text)),
              String(kNotoEmojiFontName));
    const char* system_mono_font_name = kSystemMonoEmojiFont;
#if BUILDFLAG(IS_MAC)
    if (text == text_default) {
      system_mono_font_name = kSystemMonoTextDefaultEmojiFont;
    }
#endif
    EXPECT_EQ(MaybeStripFontationsSuffix(
                  GetShapedFontFamilyNameForEmojiVS(color_font, text)),
              String(system_mono_font_name));
  }
}

TEST_F(HarfBuzzShaperTest, SystemEmojiVS16) {
  ScopedFontVariationSequencesForTest scoped_feature_vs(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_feature_system_emoji_vs(
      true);

  Font mono_font = CreateNotoEmoji();
  Font color_font = CreateNotoColorEmoji();

  String text_default(
      u"\u2603"
      u"\ufe0f");
  String emoji_default(
      u"\u2614"
      u"\ufe0f");
  for (String text : {text_default, emoji_default}) {
    EXPECT_EQ(GetShapedFontFamilyNameForEmojiVS(mono_font, text),
              kSystemColorEmojiFont);
    EXPECT_EQ(MaybeStripFontationsSuffix(
                  GetShapedFontFamilyNameForEmojiVS(color_font, text)),
              kNotoColorEmojiFontName);
  }
}

const FontVariantEmoji variant_emoji_values[] = {
    kEmojiVariantEmoji, kTextVariantEmoji, kUnicodeVariantEmoji};

class FontVariantEmojiTest
    : public HarfBuzzShaperTest,
      public testing::WithParamInterface<FontVariantEmoji> {};

INSTANTIATE_TEST_SUITE_P(HarfBuzzShaperTest,
                         FontVariantEmojiTest,
                         testing::ValuesIn(variant_emoji_values));

TEST_P(FontVariantEmojiTest, FontVariantEmojiSystemFallback) {
  ScopedFontVariationSequencesForTest scoped_feature_vs(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_feature_system_emoji_vs(
      true);
  ScopedFontVariantEmojiForTest scoped_feature_variant_emoji(true);

  const FontVariantEmoji variant_emoji = GetParam();

  String text_default(u"\u2603");
  String emoji_default(u"\u2614");

  Font mono_font = CreateNotoEmoji(variant_emoji);
  Font color_font = CreateNotoColorEmoji(variant_emoji);

  for (String text : {text_default, emoji_default}) {
    bool is_text_presentation =
        (variant_emoji == kTextVariantEmoji) ||
        (variant_emoji == kUnicodeVariantEmoji && text == text_default);
    bool is_emoji_presentation =
        (variant_emoji == kEmojiVariantEmoji) ||
        (variant_emoji == kUnicodeVariantEmoji && text == emoji_default);

    const char* expected_name_for_mono_requested_font =
        is_text_presentation ? kNotoEmojiFontName : kSystemColorEmojiFont;
    const char* expected_name_for_color_requested_font =
        is_emoji_presentation ? kNotoColorEmojiFontName : kSystemMonoEmojiFont;

#if BUILDFLAG(IS_MAC)
    if (text == text_default && !is_emoji_presentation) {
      expected_name_for_color_requested_font = kSystemMonoTextDefaultEmojiFont;
    }
#endif

    EXPECT_EQ(MaybeStripFontationsSuffix(
                  GetShapedFontFamilyNameForEmojiVS(mono_font, text)),
              String(expected_name_for_mono_requested_font));
    EXPECT_EQ(MaybeStripFontationsSuffix(
                  GetShapedFontFamilyNameForEmojiVS(color_font, text)),
              String(expected_name_for_color_requested_font));
  }
}

TEST_F(HarfBuzzShaperTest, VSOverrideFontVariantEmoji) {
  ScopedFontVariationSequencesForTest scoped_feature_vs(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_feature_system_emoji_vs(
      true);
  ScopedFontVariantEmojiForTest scoped_feature_variant_emoji(true);

  String text(u"\u2603\u2614\ufe0e\u2603\ufe0f");
  Font font = blink::test::CreateTestFont(
      AtomicString("Ahem"), blink::test::PlatformTestDataPath("Ahem.woff"), 12,
      nullptr, kEmojiVariantEmoji);

  HeapVector<ShapeResult::RunFontData> run_font_data;
  HarfBuzzShaper shaper(text);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  result->GetRunFontData(&run_font_data);
  EXPECT_EQ(run_font_data.size(), 3u);
  EXPECT_EQ(run_font_data[0].font_data_->PlatformData().FontFamilyName(),
            kSystemColorEmojiFont);
  EXPECT_EQ(run_font_data[1].font_data_->PlatformData().FontFamilyName(),
            kSystemMonoEmojiFont);
  EXPECT_EQ(run_font_data[2].font_data_->PlatformData().FontFamilyName(),
            kSystemColorEmojiFont);
}

TEST_F(HarfBuzzShaperTest, FontVariantEmojiTextSystemFallback) {
  ScopedFontVariationSequencesForTest scoped_feature_vs(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_feature_system_emoji_vs(
      true);
  ScopedFontVariantEmojiForTest scoped_feature_variant_emoji(true);
#if BUILDFLAG(IS_MAC)
  if (base::mac::MacOSVersion() < 13'00'00) {
    GTEST_SKIP();
  }
  const char* mono_font_name = "STIX Two Math";
#elif BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
  const char* mono_font_name = kSystemMonoEmojiFont;
#endif
  String text(u"\u26CE");
  Font color_font = CreateNotoColorEmoji(FontVariantEmoji::kTextVariantEmoji);
  EXPECT_EQ(GetShapedFontFamilyNameForEmojiVS(color_font, text),
            mono_font_name);
}

#endif

TEST_F(HarfBuzzShaperTest, NegativeLetterSpacing) {
  Font font(font_description);

  String string(u"Hello");
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  float width = result->Width();

  ShapeResultSpacing<String> spacing(string);
  FontDescription font_description;
  font_description.SetLetterSpacing(-5);
  spacing.SetSpacing(font_description);
  result->ApplySpacing(spacing);

  EXPECT_EQ(5 * 5, width - result->Width());
}

TEST_F(HarfBuzzShaperTest, NegativeLetterSpacingTo0) {
  Font font(font_description);

  String string(u"00000");
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  float char_width = result->Width() / string.length();

  ShapeResultSpacing<String> spacing(string);
  FontDescription font_description;
  font_description.SetLetterSpacing(-char_width);
  spacing.SetSpacing(font_description);
  result->ApplySpacing(spacing);

  // EXPECT_EQ(0.0f, result->Width());
}

TEST_F(HarfBuzzShaperTest, NegativeLetterSpacingToNegative) {
  Font font(font_description);

  String string(u"00000");
  HarfBuzzShaper shaper(string);
  ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  float char_width = result->Width() / string.length();

  ShapeResultSpacing<String> spacing(string);
  FontDescription font_description;
  font_description.SetLetterSpacing(-2 * char_width);
  spacing.SetSpacing(font_description);
  result->ApplySpacing(spacing);

  // CSS does not allow negative width, it should be clampled to 0.
  // EXPECT_EQ(0.0f, result->Width());
}

static struct GlyphDataRangeTestData {
  const char16_t* text;
  TextDirection direction;
  unsigned run_index;
  unsigned start_offset;
  unsigned end_offset;
  unsigned start_glyph;
  unsigned end_glyph;
} glyph_data_range_test_data[] = {
    // Hebrew, taken from fast/text/selection/hebrew-selection.html
    // The two code points form a grapheme cluster, which produces two glyphs.
    // Character index array should be [0, 0].
    {u"\u05E9\u05B0", TextDirection::kRtl, 0, 0, 1, 0, 2},
    // ZWJ tests taken from fast/text/international/zerowidthjoiner.html
    // Character index array should be [6, 3, 3, 3, 0, 0, 0].
    {u"\u0639\u200D\u200D\u0639\u200D\u200D\u0639", TextDirection::kRtl, 0, 0,
     1, 4, 7},
    {u"\u0639\u200D\u200D\u0639\u200D\u200D\u0639", TextDirection::kRtl, 0, 2,
     5, 1, 4},
    {u"\u0639\u200D\u200D\u0639\u200D\u200D\u0639", TextDirection::kRtl, 0, 4,
     7, 0, 1},
};

std::ostream& operator<<(std::ostream& ostream,
                         const GlyphDataRangeTestData& data) {
  return ostream << data.text;
}

class GlyphDataRangeTest
    : public HarfBuzzShaperTest,
      public testing::WithParamInterface<GlyphDataRangeTestData> {};

INSTANTIATE_TEST_SUITE_P(HarfBuzzShaperTest,
                         GlyphDataRangeTest,
                         testing::ValuesIn(glyph_data_range_test_data));

TEST_P(GlyphDataRangeTest, Data) {
  Font font(font_description);

  auto data = GetParam();
  String string(data.text);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, data.direction);

  const auto& run = TestInfo(result)->RunInfoForTesting(data.run_index);
  auto glyphs = run.FindGlyphDataRange(data.start_offset, data.end_offset);
  unsigned start_glyph = std::distance(run.glyph_data_.begin(), glyphs.begin);
  EXPECT_EQ(data.start_glyph, start_glyph);
  unsigned end_glyph = std::distance(run.glyph_data_.begin(), glyphs.end);
  EXPECT_EQ(data.end_glyph, end_glyph);
}

static struct OffsetForPositionTestData {
  float position;
  unsigned offset_ltr;
  unsigned offset_rtl;
  unsigned hit_test_ltr;
  unsigned hit_test_rtl;
  unsigned fit_ltr_ltr;
  unsigned fit_ltr_rtl;
  unsigned fit_rtl_ltr;
  unsigned fit_rtl_rtl;
} offset_for_position_fixed_pitch_test_data[] = {
    // The left edge.
    {-1, 0, 5, 0, 5, 0, 0, 5, 5},
    {0, 0, 5, 0, 5, 0, 0, 5, 5},
    // Hit test should round to the nearest glyph at the middle of a glyph.
    {4, 0, 4, 0, 5, 0, 1, 5, 4},
    {6, 0, 4, 1, 4, 0, 1, 5, 4},
    // Glyph boundary between the 1st and the 2nd glyph.
    // Avoid testing "10.0" to avoid rounding differences on Windows.
    {9.9, 0, 4, 1, 4, 0, 1, 5, 4},
    {10.1, 1, 3, 1, 4, 1, 2, 4, 3},
    // Run boundary is at position 20. The 1st run has 2 characters.
    {14, 1, 3, 1, 4, 1, 2, 4, 3},
    {16, 1, 3, 2, 3, 1, 2, 4, 3},
    {20.1, 2, 2, 2, 3, 2, 3, 3, 2},
    {24, 2, 2, 2, 3, 2, 3, 3, 2},
    {26, 2, 2, 3, 2, 2, 3, 3, 2},
    // The end of the ShapeResult. The result has 5 characters.
    {44, 4, 0, 4, 1, 4, 5, 1, 0},
    {46, 4, 0, 5, 0, 4, 5, 1, 0},
    {50, 5, 0, 5, 0, 5, 5, 0, 0},
    // Beyond the right edge of the ShapeResult.
    {51, 5, 0, 5, 0, 5, 5, 0, 0},
};

std::ostream& operator<<(std::ostream& ostream,
                         const OffsetForPositionTestData& data) {
  return ostream << data.position;
}

class OffsetForPositionTest
    : public HarfBuzzShaperTest,
      public testing::WithParamInterface<OffsetForPositionTestData> {};

INSTANTIATE_TEST_SUITE_P(
    HarfBuzzShaperTest,
    OffsetForPositionTest,
    testing::ValuesIn(offset_for_position_fixed_pitch_test_data));

TEST_P(OffsetForPositionTest, Data) {
  auto data = GetParam();
  String string(u"01234");
  HarfBuzzShaper shaper(string);
  Font ahem = CreateAhem(10);
  const ShapeResult* result =
      SplitRun(shaper.Shape(&ahem, TextDirection::kLtr), 2);
  EXPECT_EQ(data.offset_ltr,
            result->OffsetForPosition(data.position, BreakGlyphsOption(false)));
  EXPECT_EQ(data.hit_test_ltr,
            result->CaretOffsetForHitTest(data.position, string,
                                          BreakGlyphsOption(false)));
  EXPECT_EQ(data.fit_ltr_ltr,
            result->OffsetToFit(data.position, TextDirection::kLtr));
  EXPECT_EQ(data.fit_ltr_rtl,
            result->OffsetToFit(data.position, TextDirection::kRtl));

  result = SplitRun(shaper.Shape(&ahem, TextDirection::kRtl), 3);
  EXPECT_EQ(data.offset_rtl,
            result->OffsetForPosition(data.position, BreakGlyphsOption(false)));
  EXPECT_EQ(data.hit_test_rtl,
            result->CaretOffsetForHitTest(data.position, string,
                                          BreakGlyphsOption(false)));
  EXPECT_EQ(data.fit_rtl_ltr,
            result->OffsetToFit(data.position, TextDirection::kLtr));
  EXPECT_EQ(data.fit_rtl_rtl,
            result->OffsetToFit(data.position, TextDirection::kRtl));
}

TEST_F(HarfBuzzShaperTest, PositionForOffsetLatin) {
  Font font(font_description);

  String string = To16Bit("Hello World!");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);
  const ShapeResult* first = shaper.Shape(&font, direction, 0, 5);    // Hello
  const ShapeResult* second = shaper.Shape(&font, direction, 6, 11);  // World

  EXPECT_EQ(0.0f, result->PositionForOffset(0));
  ASSERT_NEAR(first->Width(), result->PositionForOffset(5), 1);
  ASSERT_NEAR(second->Width(),
              result->PositionForOffset(11) - result->PositionForOffset(6), 1);
  ASSERT_NEAR(result->Width(), result->PositionForOffset(12), 0.1);
}

TEST_F(HarfBuzzShaperTest, PositionForOffsetArabic) {
  Font font(font_description);

  UChar arabic_string[] = {0x628, 0x64A, 0x629};
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper{String(base::span(arabic_string))};
  const ShapeResult* result = shaper.Shape(&font, direction);

  EXPECT_EQ(0.0f, result->PositionForOffset(3));
  ASSERT_NEAR(result->Width(), result->PositionForOffset(0), 0.1);
}

TEST_F(HarfBuzzShaperTest, EmojiZWJSequence) {
  Font font(font_description);

  UChar emoji_zwj_sequence[] = {0x270C, 0x200D, 0xD83C, 0xDFFF,
                                0x270C, 0x200D, 0xD83C, 0xDFFC};
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper{String(base::span(emoji_zwj_sequence))};
  shaper.Shape(&font, direction);
}

// A Value-Parameterized Test class to test OffsetForPosition() with
// |include_partial_glyphs| parameter.
class IncludePartialGlyphsTest
    : public HarfBuzzShaperTest,
      public ::testing::WithParamInterface<IncludePartialGlyphsOption> {};

INSTANTIATE_TEST_SUITE_P(
    HarfBuzzShaperTest,
    IncludePartialGlyphsTest,
    ::testing::Values(IncludePartialGlyphsOption::kOnlyFullGlyphs,
                      IncludePartialGlyphsOption::kIncludePartialGlyphs));

TEST_P(IncludePartialGlyphsTest,
       OffsetForPositionMatchesPositionForOffsetLatin) {
  Font font(font_description);

  String string = To16Bit("Hello World!");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  IncludePartialGlyphsOption partial = GetParam();
  EXPECT_EQ(0u, result->OffsetForPosition(result->PositionForOffset(0), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(1u, result->OffsetForPosition(result->PositionForOffset(1), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(2u, result->OffsetForPosition(result->PositionForOffset(2), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(3u, result->OffsetForPosition(result->PositionForOffset(3), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(4u, result->OffsetForPosition(result->PositionForOffset(4), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(5u, result->OffsetForPosition(result->PositionForOffset(5), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(6u, result->OffsetForPosition(result->PositionForOffset(6), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(7u, result->OffsetForPosition(result->PositionForOffset(7), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(8u, result->OffsetForPosition(result->PositionForOffset(8), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(9u, result->OffsetForPosition(result->PositionForOffset(9), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(10u,
            result->OffsetForPosition(result->PositionForOffset(10), string,
                                      partial, BreakGlyphsOption(false)));
  EXPECT_EQ(11u,
            result->OffsetForPosition(result->PositionForOffset(11), string,
                                      partial, BreakGlyphsOption(false)));
  EXPECT_EQ(12u,
            result->OffsetForPosition(result->PositionForOffset(12), string,
                                      partial, BreakGlyphsOption(false)));
}

TEST_P(IncludePartialGlyphsTest,
       OffsetForPositionMatchesPositionForOffsetArabic) {
  Font font(font_description);

  UChar arabic_string[] = {0x628, 0x64A, 0x629};
  String string{base::span(arabic_string)};
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  IncludePartialGlyphsOption partial = GetParam();
  EXPECT_EQ(0u, result->OffsetForPosition(result->PositionForOffset(0), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(1u, result->OffsetForPosition(result->PositionForOffset(1), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(2u, result->OffsetForPosition(result->PositionForOffset(2), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(3u, result->OffsetForPosition(result->PositionForOffset(3), string,
                                          partial, BreakGlyphsOption(false)));
}

TEST_P(IncludePartialGlyphsTest,
       OffsetForPositionMatchesPositionForOffsetMixed) {
  Font font(font_description);

  UChar mixed_string[] = {0x628, 0x64A, 0x629, 0xE20, 0x65E5, 0x62};
  String string{base::span(mixed_string)};
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  IncludePartialGlyphsOption partial = GetParam();
  EXPECT_EQ(0u, result->OffsetForPosition(result->PositionForOffset(0), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(1u, result->OffsetForPosition(result->PositionForOffset(1), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(2u, result->OffsetForPosition(result->PositionForOffset(2), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(3u, result->OffsetForPosition(result->PositionForOffset(3), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(4u, result->OffsetForPosition(result->PositionForOffset(4), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(5u, result->OffsetForPosition(result->PositionForOffset(5), string,
                                          partial, BreakGlyphsOption(false)));
  EXPECT_EQ(6u, result->OffsetForPosition(result->PositionForOffset(6), string,
                                          partial, BreakGlyphsOption(false)));
}

TEST_F(HarfBuzzShaperTest, CachedOffsetPositionMappingForOffsetLatin) {
  Font font(font_description);

  String string = To16Bit("Hello World!");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* sr = shaper.Shape(&font, direction);
  sr->EnsurePositionData();

  EXPECT_EQ(0u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(0)));
  EXPECT_EQ(1u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(1)));
  EXPECT_EQ(2u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(2)));
  EXPECT_EQ(3u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(3)));
  EXPECT_EQ(4u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(4)));
  EXPECT_EQ(5u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(5)));
  EXPECT_EQ(6u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(6)));
  EXPECT_EQ(7u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(7)));
  EXPECT_EQ(8u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(8)));
  EXPECT_EQ(9u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(9)));
  EXPECT_EQ(10u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(10)));
  EXPECT_EQ(11u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(11)));
  EXPECT_EQ(12u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(12)));
}

TEST_F(HarfBuzzShaperTest, CachedOffsetPositionMappingArabic) {
  Font font(font_description);

  UChar arabic_string[] = {0x628, 0x64A, 0x629};
  TextDirection direction = TextDirection::kRtl;

  HarfBuzzShaper shaper{String(base::span(arabic_string))};
  const ShapeResult* sr = shaper.Shape(&font, direction);
  sr->EnsurePositionData();

  EXPECT_EQ(0u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(0)));
  EXPECT_EQ(1u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(1)));
  EXPECT_EQ(2u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(2)));
  EXPECT_EQ(3u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(3)));
}

TEST_F(HarfBuzzShaperTest, CachedOffsetPositionMappingMixed) {
  Font font(font_description);

  UChar mixed_string[] = {0x628, 0x64A, 0x629, 0xE20, 0x65E5, 0x62};
  HarfBuzzShaper shaper{String(base::span(mixed_string))};
  const ShapeResult* sr = shaper.Shape(&font, TextDirection::kLtr);
  sr->EnsurePositionData();

  EXPECT_EQ(0u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(0)));
  EXPECT_EQ(1u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(1)));
  EXPECT_EQ(2u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(2)));
  EXPECT_EQ(3u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(3)));
  EXPECT_EQ(4u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(4)));
  EXPECT_EQ(5u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(5)));
  EXPECT_EQ(6u, sr->CachedOffsetForPosition(sr->CachedPositionForOffset(6)));
}

TEST_F(HarfBuzzShaperTest, PositionForOffsetMultiGlyphClusterLtr) {
  Font font(font_description);

  // In this Hindi text, each code unit produces a glyph, and the first 3 glyphs
  // form a grapheme cluster, and the last 2 glyphs form another.
  String string(u"\u0930\u093F\u0902\u0926\u0940");
  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper(string);
  const ShapeResult* sr = shaper.Shape(&font, direction);
  sr->EnsurePositionData();

  // The first 3 code units should be at position 0.
  EXPECT_EQ(0, sr->CachedPositionForOffset(0));
  EXPECT_EQ(0, sr->CachedPositionForOffset(1));
  EXPECT_EQ(0, sr->CachedPositionForOffset(2));
  // The last 2 code units should be > 0, and the same position.
  EXPECT_GT(sr->CachedPositionForOffset(3), 0);
  EXPECT_EQ(sr->CachedPositionForOffset(3), sr->CachedPositionForOffset(4));
}

TEST_F(HarfBuzzShaperTest, PositionForOffsetMultiGlyphClusterRtl) {
  Font font(font_description);

  // In this Hindi text, each code unit produces a glyph, and the first 3 glyphs
  // form a grapheme cluster, and the last 2 glyphs form another.
  String string(u"\u0930\u093F\u0902\u0926\u0940");
  TextDirection direction = TextDirection::kRtl;
  HarfBuzzShaper shaper(string);
  const ShapeResult* sr = shaper.Shape(&font, direction);
  sr->EnsurePositionData();

  // The first 3 code units should be at position 0, but since this is RTL, the
  // position is the right edgef of the character, and thus > 0.
  LayoutUnit pos0 = sr->CachedPositionForOffset(0);
  EXPECT_GT(pos0, 0);
  EXPECT_EQ(pos0, sr->CachedPositionForOffset(1));
  EXPECT_EQ(pos0, sr->CachedPositionForOffset(2));
  // The last 2 code units should be > 0, and the same position.
  LayoutUnit pos3 = sr->CachedPositionForOffset(3);
  EXPECT_GT(pos3, 0);
  EXPECT_LT(pos3, pos0);
  EXPECT_EQ(pos3, sr->CachedPositionForOffset(4));
}

TEST_F(HarfBuzzShaperTest, PositionForOffsetMissingGlyph) {
  Font font(font_description);

  String string(u"\u0633\u0644\u0627\u0645");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kRtl);
  // Because the offset 1 and 2 should form a ligature, SubRange(2, 4) creates a
  // ShapeResult that does not have its first glyph.
  result = result->SubRange(2, 4);
  result->PositionForOffset(0);
  // Pass if |PositionForOffset| does not crash.
}

static struct ShapeResultCopyRangeTestData {
  const char16_t* string;
  TextDirection direction;
  unsigned break_point;
} shape_result_copy_range_test_data[] = {
    {u"ABC", TextDirection::kLtr, 1},
    {u"\u0648\u0644\u064A", TextDirection::kRtl, 1},
    // These strings creates 3 runs. Split it in the middle of 2nd run.
    {u"\u65E5Hello\u65E5\u65E5", TextDirection::kLtr, 3},
    {u"\u0648\u0644\u064A AB \u0628\u062A", TextDirection::kRtl, 5}};

std::ostream& operator<<(std::ostream& ostream,
                         const ShapeResultCopyRangeTestData& data) {
  return ostream << String(data.string) << " @ " << data.break_point << ", "
                 << data.direction;
}

class ShapeResultCopyRangeTest
    : public HarfBuzzShaperTest,
      public testing::WithParamInterface<ShapeResultCopyRangeTestData> {};

INSTANTIATE_TEST_SUITE_P(HarfBuzzShaperTest,
                         ShapeResultCopyRangeTest,
                         testing::ValuesIn(shape_result_copy_range_test_data));

// Split a ShapeResult and combine them should match to the original result.
TEST_P(ShapeResultCopyRangeTest, Split) {
  Font font(font_description);

  const auto& test_data = GetParam();
  String string(test_data.string);
  TextDirection direction = test_data.direction;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Split the result.
  ShapeResult* result1 =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(0, test_data.break_point, result1);
  EXPECT_EQ(test_data.break_point, result1->NumCharacters());
  EXPECT_EQ(0u, result1->StartIndex());
  EXPECT_EQ(test_data.break_point, result1->EndIndex());

  ShapeResult* result2 =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(test_data.break_point, string.length(), result2);
  EXPECT_EQ(string.length() - test_data.break_point, result2->NumCharacters());
  EXPECT_EQ(test_data.break_point, result2->StartIndex());
  EXPECT_EQ(string.length(), result2->EndIndex());

  // Combine them.
  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, test_data.break_point, composite_result);
  result2->CopyRange(0, string.length(), composite_result);
  EXPECT_EQ(string.length(), composite_result->NumCharacters());

  // Test character indexes match.
  Vector<unsigned> expected_character_indexes =
      TestInfo(result)->CharacterIndexesForTesting();
  Vector<unsigned> composite_character_indexes =
      TestInfo(result)->CharacterIndexesForTesting();
  EXPECT_EQ(expected_character_indexes, composite_character_indexes);
}

// Shape ranges and combine them shold match to the result of shaping the whole
// string.
TEST_P(ShapeResultCopyRangeTest, ShapeRange) {
  Font font(font_description);

  const auto& test_data = GetParam();
  String string(test_data.string);
  TextDirection direction = test_data.direction;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Shape each range.
  const ShapeResult* result1 =
      shaper.Shape(&font, direction, 0, test_data.break_point);
  EXPECT_EQ(test_data.break_point, result1->NumCharacters());
  const ShapeResult* result2 =
      shaper.Shape(&font, direction, test_data.break_point, string.length());
  EXPECT_EQ(string.length() - test_data.break_point, result2->NumCharacters());

  // Combine them.
  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, test_data.break_point, composite_result);
  result2->CopyRange(0, string.length(), composite_result);
  EXPECT_EQ(string.length(), composite_result->NumCharacters());

  // Test character indexes match.
  Vector<unsigned> expected_character_indexes =
      TestInfo(result)->CharacterIndexesForTesting();
  Vector<unsigned> composite_character_indexes =
      TestInfo(result)->CharacterIndexesForTesting();
  EXPECT_EQ(expected_character_indexes, composite_character_indexes);
}

TEST_F(HarfBuzzShaperTest, ShapeResultCopyRangeIntoLatin) {
  Font font(font_description);

  String string = To16Bit("Testing ShapeResult::createSubRun");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(0, 10, composite_result);
  result->CopyRange(10, 20, composite_result);
  result->CopyRange(20, 30, composite_result);
  result->CopyRange(30, 33, composite_result);

  EXPECT_EQ(result->NumCharacters(), composite_result->NumCharacters());
  EXPECT_EQ(result->SnappedWidth(), composite_result->SnappedWidth());

  // Rounding of width may be off by ~0.1 on Mac.
  float tolerance = 0.1f;
  EXPECT_NEAR(result->Width(), composite_result->Width(), tolerance);

  EXPECT_EQ(result->SnappedStartPositionForOffset(0),
            composite_result->SnappedStartPositionForOffset(0));
  EXPECT_EQ(result->SnappedStartPositionForOffset(15),
            composite_result->SnappedStartPositionForOffset(15));
  EXPECT_EQ(result->SnappedStartPositionForOffset(30),
            composite_result->SnappedStartPositionForOffset(30));
  EXPECT_EQ(result->SnappedStartPositionForOffset(33),
            composite_result->SnappedStartPositionForOffset(33));
}

TEST_F(HarfBuzzShaperTest, ShapeResultCopyRangeIntoArabicThaiHanLatin) {
  Font font(font_description);

  UChar mixed_string[] = {0x628, 0x20, 0x64A, 0x629, 0x20, 0xE20, 0x65E5, 0x62};
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper{String(base::span(mixed_string))};
  const ShapeResult* result = shaper.Shape(&font, direction);

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(0, 4, composite_result);
  result->CopyRange(4, 6, composite_result);
  result->CopyRange(6, 8, composite_result);

  EXPECT_EQ(result->NumCharacters(), composite_result->NumCharacters());
  EXPECT_EQ(result->SnappedWidth(), composite_result->SnappedWidth());
  EXPECT_EQ(result->SnappedStartPositionForOffset(0),
            composite_result->SnappedStartPositionForOffset(0));
  EXPECT_EQ(result->SnappedStartPositionForOffset(1),
            composite_result->SnappedStartPositionForOffset(1));
  EXPECT_EQ(result->SnappedStartPositionForOffset(2),
            composite_result->SnappedStartPositionForOffset(2));
  EXPECT_EQ(result->SnappedStartPositionForOffset(3),
            composite_result->SnappedStartPositionForOffset(3));
  EXPECT_EQ(result->SnappedStartPositionForOffset(4),
            composite_result->SnappedStartPositionForOffset(4));
  EXPECT_EQ(result->SnappedStartPositionForOffset(5),
            composite_result->SnappedStartPositionForOffset(5));
  EXPECT_EQ(result->SnappedStartPositionForOffset(6),
            composite_result->SnappedStartPositionForOffset(6));
  EXPECT_EQ(result->SnappedStartPositionForOffset(7),
            composite_result->SnappedStartPositionForOffset(7));
  EXPECT_EQ(result->SnappedStartPositionForOffset(8),
            composite_result->SnappedStartPositionForOffset(8));
}

TEST_P(ShapeParameterTest, ShapeResultCopyRangeAcrossRuns) {
  Font font(font_description);

  // Create 3 runs:
  // [0]: 1 character.
  // [1]: 5 characters.
  // [2]: 2 character.
  String mixed_string(u"\u65E5Hello\u65E5\u65E5");
  TextDirection direction = GetParam();
  HarfBuzzShaper shaper(mixed_string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // CopyRange(5, 7) should copy 1 character from [1] and 1 from [2].
  ShapeResult* target =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result->CopyRange(5, 7, target);
  EXPECT_EQ(2u, target->NumCharacters());
}

TEST_P(ShapeParameterTest, ShapeResultCopyRangeContextMultiRuns) {
  Font font(font_description);

  // Create 2 runs:
  // [0]: 5 characters.
  // [1]: 4 character.
  String mixed_string(u"Hello\u65E5\u65E5\u65E5\u65E5");
  TextDirection direction = GetParam();
  HarfBuzzShaper shaper(mixed_string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  const ShapeResult* sub2to4 = result->SubRange(2, 4);
  EXPECT_EQ(2u, sub2to4->NumCharacters());
  const ShapeResult* sub5to9 = result->SubRange(5, 9);
  EXPECT_EQ(4u, sub5to9->NumCharacters());
}

TEST_F(HarfBuzzShaperTest, ShapeResultCopyRangeSegmentGlyphBoundingBox) {
  Font font(font_description);

  String string(u"THello worldL");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result1 = shaper.Shape(&font, direction, 0, 6);
  c
```