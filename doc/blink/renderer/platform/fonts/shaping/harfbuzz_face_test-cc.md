Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:**  The filename `harfbuzz_face_test.cc` and the inclusion of `<gtest/gtest.h>` immediately suggest this is a unit test file for something related to `HarfBuzzFace`. HarfBuzz is a known library for text shaping. "Face" in font terminology refers to a specific typeface (like bold or italic). So, the core purpose is likely testing how Chromium's Blink engine interacts with HarfBuzz to handle different font faces and character rendering, specifically concerning variation selectors.

2. **Examine Includes:** The `#include` directives provide clues about the file's dependencies and functionality:
    * `"third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"`: Confirms the testing of `HarfBuzzFace`.
    * `"hb.h"`: Includes the HarfBuzz library itself.
    * `"testing/gtest/include/gtest/gtest.h"`: Indicates the use of Google Test for unit testing.
    * Other Blink font-related headers (`Font.h`, `FontPlatformData.h`, `Glyph.h`, `variation_selector_mode.h`): Show the file's integration within the Blink font system.
    * Testing utilities (`FontTestHelpers.h`, `RuntimeEnabledFeaturesTestHelpers.h`, `UnitTestHelpers.h`): Indicate this is a controlled testing environment.

3. **Analyze Namespaces:** The `namespace blink { namespace { ... } }` structure is standard Blink practice for organizing code and creating anonymous namespaces for internal helpers.

4. **Understand Helper Functions:**  The functions defined outside the `TEST` blocks are crucial for setting up test scenarios:
    * `WPTFontPath`:  Locates font files within the Web Platform Tests directory. This suggests testing against real-world font data.
    * `GetGlyphForVariationSequenceFromFont`: This is the core helper. It takes a `Font`, a `character`, and a `variation_selector` and uses the `HarfBuzzFace` to get the glyph ID. The `EXPECT_TRUE(face_without_char)` indicates a check for a valid HarfBuzz face.
    * Several `GetGlyphForEmojiVSFromFont...` functions: These are specialized versions of the core helper, loading specific emoji fonts (with and without variation selector support) for testing emoji rendering. The names "VS15" and "VS16" hint at testing different variation selector standards for emojis.
    * `GetGlyphForStandardizedVSFromFontWithBaseCharOnly` and `GetGlyphForCJKVSFromFontWithVS`:  These test scenarios with specific character and variation selector combinations for Mongolian and CJK characters, respectively.

5. **Deconstruct the `TEST` Blocks:** Each `TEST(HarfBuzzFaceTest, ...)` block represents a specific test case. Analyze the name and the code within each block:
    * **Common Setup:** Many tests use `ScopedFontVariationSequencesForTest` and often `ScopedFontVariantEmojiForTest`. These likely enable or disable flags related to variation sequence and emoji support within the testing environment. This shows testing different configurations.
    * **`HarfBuzzFace::SetVariationSelectorMode(...)`:** This is a key function being tested, allowing control over how variation selectors are handled (`kUseSpecifiedVariationSelector`, `kIgnoreVariationSelector`, `kForceVariationSelector15`, `kForceVariationSelector16`, `kUseUnicodeDefaultPresentation`).
    * **Specific Character and Variation Selector Combinations:** Each test uses different character and variation selector values to test various scenarios. Look for constants like `kFullwidthExclamationMark`, `kVariationSelector2Character`, `kShakingFaceEmoji`, `kVariationSelector15Character`, `kVariationSelector16Character`.
    * **`EXPECT_...` Assertions:** The `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_NE` calls are standard Google Test assertions that verify the expected outcomes of the tests. Look for comparisons against `kUnmatchedVSGlyphId` (likely indicating no glyph found for the variation sequence).
    * **Conditional Logic (`if (!RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled())`)**:  Shows testing different feature flags and their impact.
    * **Platform-Specific Tests (`#if BUILDFLAG(IS_MAC) || ...`)**:  Indicates testing of platform-specific behavior, particularly for system fallback of emoji variation selectors.

6. **Identify Relationships to Web Technologies:** Consider how the tested functionality relates to JavaScript, HTML, and CSS:
    * **CSS:** Font selection using `font-family`, the rendering of specific glyphs, and the handling of Unicode variation selectors are all influenced by CSS. The test indirectly relates to how CSS requests for specific character representations are fulfilled by the font rendering engine.
    * **HTML:** The characters being tested would appear in the HTML content. The correct rendering of these characters based on font and variation selectors is essential for displaying the HTML accurately.
    * **JavaScript:** While not directly tested here, JavaScript could manipulate the text content, potentially inserting characters that rely on variation selectors. Understanding how these are rendered is important.

7. **Infer Logic and Assumptions:**  Based on the test cases, infer the logic being tested:
    * The `HarfBuzzFace` likely has logic to look up glyphs based on base characters and optional variation selectors.
    * Different modes of handling variation selectors are implemented and tested.
    * The presence or absence of variation selector data in the font file impacts the glyph lookup.
    * System fallback mechanisms for emoji rendering are being tested.

8. **Consider User/Programming Errors:** Think about how developers might misuse this functionality or encounter unexpected behavior:
    * Incorrectly assuming a font supports a specific variation selector.
    * Not accounting for different rendering behavior based on the operating system or browser.
    * Issues arising from missing font files or incorrect font configurations.

By following these steps, we can systematically analyze the C++ test file and extract its functionalities, relationships to web technologies, underlying logic, and potential error scenarios. The key is to combine understanding of the code structure, the included libraries, and the specific test cases to build a comprehensive picture of what the file is testing and why.
这个文件 `harfbuzz_face_test.cc` 是 Chromium Blink 引擎中用于测试 `HarfBuzzFace` 类的单元测试文件。 `HarfBuzzFace` 类是 Blink 中用来和 HarfBuzz 库交互，进行字体排版的关键组件。

以下是该文件的功能分解：

**主要功能:**

1. **测试 `HarfBuzzFace` 的基本功能:**  主要测试 `HarfBuzzFace` 类能否正确地从字体文件中获取字形 (glyph) ID。这包括给定一个字符和一个可选的变体选择符 (variation selector)，能否正确地找到对应的字形。

2. **测试变体选择符 (Variation Selectors) 的处理:**  该文件重点测试了在不同配置下，`HarfBuzzFace` 如何处理变体选择符。变体选择符是 Unicode 中的特殊字符，用于指定某些字符的不同表现形式，例如表情符号的文本形式和图形形式。

3. **测试不同类型的字体:**  测试中使用了多种字体，包括：
    * 带有变体选择符映射表的字体 (例如 `Noto Emoji`, `Noto Color Emoji`, `Noto Sans CJK JP`)
    * 不带变体选择符映射表的字体 (`NotoEmoji-Regular_without-cmap14-subset.ttf`, `Noto Sans Mongolian`)
    *  一个简单的占位字体 `Ahem` 用于测试字符不存在的情况。

4. **测试不同的变体选择符模式:**  通过 `HarfBuzzFace::SetVariationSelectorMode()` 设置不同的模式，测试在不同策略下，变体选择符的处理结果：
    * `kUseSpecifiedVariationSelector`:  使用指定的变体选择符查找字形。
    * `kIgnoreVariationSelector`:  忽略变体选择符，只查找基本字符的字形。
    * `kForceVariationSelector16`:  强制使用 `U+FE0F VARIATION SELECTOR-16` (用于表情符号的图形形式)。
    * `kForceVariationSelector15`:  强制使用 `U+FE0E VARIATION SELECTOR-15` (用于表情符号的文本形式)。
    * `kUseUnicodeDefaultPresentation`: 使用 Unicode 定义的默认呈现方式。

5. **测试系统回退表情符号变体选择符 (System Fallback Emoji VS):** 在特定平台 (Mac, Android, Windows) 上，测试当字体本身不包含某个表情符号的变体选择符时，系统是否能提供回退支持。

**与 JavaScript, HTML, CSS 的关系：**

该测试文件直接测试的是 Blink 引擎内部的字体排版逻辑，它间接地影响了 JavaScript, HTML, CSS 的功能，因为这三者最终都要通过 Blink 引擎来渲染文本。

* **CSS:**
    * **`font-family`:**  测试中使用了不同的 `font-family` 来加载不同的字体文件。CSS 中的 `font-family` 属性决定了浏览器使用哪个字体来渲染文本。如果 CSS 中指定了包含变体选择符的字符，`HarfBuzzFace` 的正确工作才能保证字符能以期望的形式显示出来。
        * **例子:** 如果 CSS 中设置了 `font-family: "Noto Emoji";` 并且 HTML 中包含了表情符号及其变体选择符，`HarfBuzzFace` 需要能正确地从 "Noto Emoji" 字体中找到对应的字形。

    * **字符渲染:** CSS 最终的目标是将字符渲染到屏幕上。`HarfBuzzFace` 负责确定给定字符和字体，应该使用哪个字形来绘制。对于包含变体选择符的字符，`HarfBuzzFace` 的行为直接影响了字符的显示形式 (例如，是显示为彩色表情符号还是黑白文本)。
        * **例子:**  用户在 CSS 中可能不会直接操作变体选择符，但如果字体支持并且浏览器正确处理，像 🚶‍♂️ (U+1F6B6 U+200D U+2642 U+FE0F) 这样的表情符号序列会被 `HarfBuzzFace` 处理，并根据字体和系统支持渲染成一个单独的彩色图形。

* **HTML:**
    * **文本内容:** HTML 文档包含了需要渲染的文本内容，其中包括可能带有变体选择符的字符。`HarfBuzzFace` 的测试涉及到如何处理这些字符。
        * **假设输入:** HTML 中包含文本 "😊" (U+1F60A) 或 "😊\uFE0F" (U+1F60A U+FE0F)。
        * **`HarfBuzzFace` 输出 (字形 ID):**  根据测试配置和字体，`HarfBuzzFace` 会返回不同的字形 ID，代表不同的渲染结果（例如，彩色表情符号的字形 ID 或单色文本形式的字形 ID）。

* **JavaScript:**
    * **动态修改文本内容:** JavaScript 可以动态地修改 HTML 的文本内容，包括插入带有变体选择符的字符。`HarfBuzzFace` 的正确性保证了这些动态插入的字符也能被正确渲染。
        * **例子:** JavaScript 代码 `element.textContent = '\uD83D\uDE0A\uFE0F';` (对应 "😊\uFE0F") 会在页面上显示一个带变体选择符的笑脸表情符号。`HarfBuzzFace` 需要能正确处理这个字符序列。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

* **字体:** "Noto Emoji" (包含变体选择符映射)
* **字符:** U+1F60E (笑脸戴墨镜)
* **变体选择符模式:** `kUseSpecifiedVariationSelector`
* **变体选择符:** U+FE0F (Variation Selector-16，通常用于表情符号的图形形式)

**预期输出:**  `HarfBuzzFace` 应该返回 "Noto Emoji" 字体中 U+1F60E 的彩色表情符号版本的字形 ID。测试中 `EXPECT_NE(glyph, kUnmatchedVSGlyphId);`  会验证返回的字形 ID 不是一个表示未找到的特殊值。

**假设输入 2:**

* **字体:** "Noto Emoji" (包含变体选择符映射)
* **字符:** U+1F60E (笑脸戴墨镜)
* **变体选择符模式:** `kForceVariationSelector15`
* **变体选择符:**  (实际传入的变体选择符会被忽略)

**预期输出:** `HarfBuzzFace` 应该返回 "Noto Emoji" 字体中 U+1F60E 的文本形式的字形 ID (如果存在)。测试中会验证返回的字形 ID 不是未找到的值，并且如果与 `kForceVariationSelector16` 的结果比较，可能会不同。

**用户或编程常见的使用错误:**

1. **错误地假设所有字体都支持变体选择符:** 开发者可能会假设所有字体都能正确渲染带有变体选择符的字符，但实际上很多字体并不包含这些映射。
    * **例子:**  如果网页使用了不支持变体选择符的字体来显示表情符号，即使 HTML 中包含了变体选择符，最终可能只会显示基本字符，或者显示为带有变体选择符的两个单独的符号。

2. **不理解不同变体选择符的作用:** 开发者可能不清楚 `U+FE0E` 和 `U+FE0F` 的区别，错误地使用了变体选择符，导致渲染结果不是预期的。
    * **例子:**  希望显示彩色表情符号，却使用了 `U+FE0E`，如果字体支持，可能会显示为单色文本形式。

3. **依赖于特定的平台或字体实现细节:**  某些变体选择符的行为可能在不同操作系统或不同字体中略有不同。过度依赖于特定平台的行为可能导致跨平台兼容性问题。
    * **例子:**  在某些旧版本的操作系统上，可能无法正确显示某些新的表情符号变体。

4. **在测试环境与生产环境中使用不同的字体或配置:**  如果在开发和测试阶段使用的字体与用户实际使用的字体不同，可能会导致在开发环境中看起来正常的功能，在用户环境中出现渲染问题。

总结来说，`harfbuzz_face_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地处理各种字体和字符，特别是涉及到 Unicode 变体选择符的情况，这直接影响了网页文本的正确显示，包括现代 Web 中常见的表情符号。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_face_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"

#include "hb.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/glyph.h"
#include "third_party/blink/renderer/platform/fonts/shaping/variation_selector_mode.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/googletest/src/googletest/include/gtest/gtest.h"

namespace blink {

namespace {

String WPTFontPath(const String& font_name) {
  return test::BlinkWebTestsDir() +
         "/external/wpt/css/css-fonts/resources/vs/" + font_name;
}

hb_codepoint_t GetGlyphForVariationSequenceFromFont(
    Font font,
    UChar32 character,
    UChar32 variation_selector) {
  const FontPlatformData& font_without_char_platform_data =
      font.PrimaryFont()->PlatformData();
  HarfBuzzFace* face_without_char =
      font_without_char_platform_data.GetHarfBuzzFace();
  EXPECT_TRUE(face_without_char);
  return face_without_char->HarfBuzzGetGlyphForTesting(character,
                                                       variation_selector);
}

hb_codepoint_t GetGlyphForEmojiVSFromFontWithVS15(UChar32 character,
                                                  UChar32 variation_selector) {
  Font font =
      test::CreateTestFont(AtomicString("Noto Emoji"),
                           WPTFontPath("NotoEmoji-Regular_subset.ttf"), 11);
  return GetGlyphForVariationSequenceFromFont(font, character,
                                              variation_selector);
}

hb_codepoint_t GetGlyphForEmojiVSFromFontWithVS16(UChar32 character,
                                                  UChar32 variation_selector) {
  Font font = test::CreateTestFont(
      AtomicString("Noto Color Emoji"),
      WPTFontPath("NotoColorEmoji-Regular_subset.ttf"), 11);
  return GetGlyphForVariationSequenceFromFont(font, character,
                                              variation_selector);
}

hb_codepoint_t GetGlyphForEmojiVSFromFontWithBaseCharOnly(
    UChar32 character,
    UChar32 variation_selector) {
  Font font = test::CreateTestFont(
      AtomicString("Noto Emoji Without VS"),
      WPTFontPath("NotoEmoji-Regular_without-cmap14-subset.ttf"), 11);
  return GetGlyphForVariationSequenceFromFont(font, character,
                                              variation_selector);
}

hb_codepoint_t GetGlyphForStandardizedVSFromFontWithBaseCharOnly() {
  UChar32 character = kMongolianLetterA;
  UChar32 variation_selector = kMongolianFreeVariationSelectorTwo;

  Font font = test::CreateTestFont(AtomicString("Noto Sans Mongolian"),
                                   blink::test::BlinkWebTestsFontsTestDataPath(
                                       "noto/NotoSansMongolian-regular.woff2"),
                                   11);
  return GetGlyphForVariationSequenceFromFont(font, character,
                                              variation_selector);
}

hb_codepoint_t GetGlyphForCJKVSFromFontWithVS() {
  UChar32 character = kFullwidthExclamationMark;
  UChar32 variation_selector = kVariationSelector2Character;

  Font font = test::CreateTestFont(
      AtomicString("Noto Sans CJK JP"),
      blink::test::BlinkWebTestsFontsTestDataPath(
          "noto/cjk/NotoSansCJKjp-Regular-subset-chws.otf"),
      11);
  return GetGlyphForVariationSequenceFromFont(font, character,
                                              variation_selector);
}

}  // namespace

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestFontWithVS) {
  ScopedFontVariationSequencesForTest scoped_feature(true);
  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  hb_codepoint_t glyph = GetGlyphForCJKVSFromFontWithVS();
  EXPECT_TRUE(glyph);
  EXPECT_NE(glyph, kUnmatchedVSGlyphId);
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestFontWithVS_IgnoreVS) {
  ScopedFontVariationSequencesForTest scoped_feature(true);
  HarfBuzzFace::SetVariationSelectorMode(kIgnoreVariationSelector);

  hb_codepoint_t glyph = GetGlyphForCJKVSFromFontWithVS();
  EXPECT_TRUE(glyph);
  EXPECT_NE(glyph, kUnmatchedVSGlyphId);
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestFontWithVS_VSFlagOff) {
  ScopedFontVariationSequencesForTest scoped_feature(false);
  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  hb_codepoint_t glyph = GetGlyphForCJKVSFromFontWithVS();
  EXPECT_TRUE(glyph);
  EXPECT_NE(glyph, kUnmatchedVSGlyphId);
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestFontWithBaseCharOnly) {
  ScopedFontVariationSequencesForTest scoped_feature(true);
  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  EXPECT_EQ(GetGlyphForStandardizedVSFromFontWithBaseCharOnly(),
            kUnmatchedVSGlyphId);
}

TEST(HarfBuzzFaceTest,
     HarfBuzzGetNominalGlyph_TestFontWithBaseCharOnly_IgnoreVS) {
  ScopedFontVariationSequencesForTest scoped_feature(true);
  HarfBuzzFace::SetVariationSelectorMode(kIgnoreVariationSelector);

  hb_codepoint_t glyph = GetGlyphForStandardizedVSFromFontWithBaseCharOnly();
  EXPECT_FALSE(glyph);
}

TEST(HarfBuzzFaceTest,
     HarfBuzzGetNominalGlyph_TestFontWithBaseCharOnly_VSFlagOff) {
  ScopedFontVariationSequencesForTest scoped_feature(false);
  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  hb_codepoint_t glyph = GetGlyphForStandardizedVSFromFontWithBaseCharOnly();
  EXPECT_FALSE(glyph);
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestFontWithoutBaseChar) {
  ScopedFontVariationSequencesForTest scoped_feature(true);
  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  UChar32 character = kFullwidthExclamationMark;
  UChar32 variation_selector = kVariationSelector2Character;

  Font font = test::CreateAhemFont(11);
  EXPECT_FALSE(GetGlyphForVariationSequenceFromFont(font, character,
                                                    variation_selector));
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestVariantEmojiEmoji) {
  ScopedFontVariationSequencesForTest scoped_variation_sequences_feature(true);
  ScopedFontVariantEmojiForTest scoped_variant_emoji_feature(true);

  HarfBuzzFace::SetVariationSelectorMode(kForceVariationSelector16);

  UChar32 character = kShakingFaceEmoji;
  UChar32 variation_selector = 0;

  hb_codepoint_t glyph_from_font_with_vs15 =
      GetGlyphForEmojiVSFromFontWithVS15(character, variation_selector);
  EXPECT_EQ(glyph_from_font_with_vs15, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_with_vs16 =
      GetGlyphForEmojiVSFromFontWithVS16(character, variation_selector);
  EXPECT_TRUE(glyph_from_font_with_vs16);
  EXPECT_NE(glyph_from_font_with_vs16, kUnmatchedVSGlyphId);

  if (!RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled()) {
    hb_codepoint_t glyph_from_font_without_vs =
        GetGlyphForEmojiVSFromFontWithBaseCharOnly(character,
                                                   variation_selector);
    EXPECT_EQ(glyph_from_font_without_vs, kUnmatchedVSGlyphId);
  }
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestVariantEmojiText) {
  ScopedFontVariationSequencesForTest scoped_variation_sequences_feature(true);
  ScopedFontVariantEmojiForTest scoped_variant_emoji_feature(true);

  HarfBuzzFace::SetVariationSelectorMode(kForceVariationSelector15);

  UChar32 character = kShakingFaceEmoji;
  UChar32 variation_selector = 0;

  hb_codepoint_t glyph_from_font_with_vs15 =
      GetGlyphForEmojiVSFromFontWithVS15(character, variation_selector);
  EXPECT_TRUE(glyph_from_font_with_vs15);
  EXPECT_NE(glyph_from_font_with_vs15, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_with_vs16 =
      GetGlyphForEmojiVSFromFontWithVS16(character, variation_selector);
  EXPECT_EQ(glyph_from_font_with_vs16, kUnmatchedVSGlyphId);

  if (!RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled()) {
    hb_codepoint_t glyph_from_font_without_vs =
        GetGlyphForEmojiVSFromFontWithBaseCharOnly(character,
                                                   variation_selector);
    EXPECT_EQ(glyph_from_font_without_vs, kUnmatchedVSGlyphId);
  }
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestVariantEmojiUnicode) {
  ScopedFontVariationSequencesForTest scoped_variation_sequences_feature(true);
  ScopedFontVariantEmojiForTest scoped_variant_emoji_feature(true);

  HarfBuzzFace::SetVariationSelectorMode(kUseUnicodeDefaultPresentation);

  UChar32 character = kShakingFaceEmoji;
  UChar32 variation_selector = 0;

  hb_codepoint_t glyph_from_font_with_vs15 =
      GetGlyphForEmojiVSFromFontWithVS15(character, variation_selector);
  EXPECT_EQ(glyph_from_font_with_vs15, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_with_vs16 =
      GetGlyphForEmojiVSFromFontWithVS16(character, variation_selector);
  EXPECT_TRUE(glyph_from_font_with_vs16);
  EXPECT_NE(glyph_from_font_with_vs16, kUnmatchedVSGlyphId);

  if (!RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled()) {
    hb_codepoint_t glyph_from_font_without_vs =
        GetGlyphForEmojiVSFromFontWithBaseCharOnly(character,
                                                   variation_selector);
    EXPECT_EQ(glyph_from_font_without_vs, kUnmatchedVSGlyphId);
  }
}

TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestVSOverrideVariantEmoji) {
  ScopedFontVariationSequencesForTest scoped_variation_sequences_feature(true);
  ScopedFontVariantEmojiForTest scoped_variant_emoji_feature(true);

  HarfBuzzFace::SetVariationSelectorMode(kForceVariationSelector16);

  UChar32 character = kShakingFaceEmoji;
  UChar32 variation_selector = kVariationSelector15Character;

  hb_codepoint_t glyph_from_font_with_vs15 =
      GetGlyphForEmojiVSFromFontWithVS15(character, variation_selector);
  EXPECT_TRUE(glyph_from_font_with_vs15);
  EXPECT_NE(glyph_from_font_with_vs15, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_with_vs16 =
      GetGlyphForEmojiVSFromFontWithVS16(character, variation_selector);
  EXPECT_EQ(glyph_from_font_with_vs16, kUnmatchedVSGlyphId);

  if (!RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled()) {
    hb_codepoint_t glyph_from_font_without_vs =
        GetGlyphForEmojiVSFromFontWithBaseCharOnly(character,
                                                   variation_selector);
    EXPECT_EQ(glyph_from_font_without_vs, kUnmatchedVSGlyphId);
  }
}

// Test emoji variation selectors support in system fallback. We are only
// enabling this feature on Windows, Android and Mac platforms.
#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
TEST(HarfBuzzFaceTest, HarfBuzzGetNominalGlyph_TestSystemFallbackEmojiVS) {
  ScopedFontVariationSequencesForTest scoped_variation_sequences_feature(true);
  ScopedFontVariantEmojiForTest scoped_variant_emoji_feature(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_system_emoji_vs_feature(
      true);

  HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);

  UChar32 character = kShakingFaceEmoji;

  hb_codepoint_t glyph_from_font_with_vs15 = GetGlyphForEmojiVSFromFontWithVS15(
      character, kVariationSelector15Character);
  EXPECT_TRUE(glyph_from_font_with_vs15);
  EXPECT_NE(glyph_from_font_with_vs15, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_with_vs16 = GetGlyphForEmojiVSFromFontWithVS16(
      character, kVariationSelector16Character);
  EXPECT_TRUE(glyph_from_font_with_vs16);
  EXPECT_NE(glyph_from_font_with_vs16, kUnmatchedVSGlyphId);

  hb_codepoint_t glyph_from_font_without_vs =
      GetGlyphForEmojiVSFromFontWithBaseCharOnly(character, 0);
  EXPECT_TRUE(glyph_from_font_without_vs);
  EXPECT_NE(glyph_from_font_without_vs, kUnmatchedVSGlyphId);
}
#endif

}  // namespace blink

"""

```