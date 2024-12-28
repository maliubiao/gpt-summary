Response:
The user wants a summary of the functionalities of the C++ code in `blink/renderer/platform/fonts/shaping/harfbuzz_shaper_test.cc`. I need to identify the main purposes of the tests within this file and highlight any connections to web technologies like JavaScript, HTML, and CSS. Since this is the final part of a three-part request, I should focus on summarizing the functionality revealed in this specific section.

Key functionalities observed in this part of the code:

1. **Safe-to-break testing:**  Extensive testing of `NextSafeToBreakOffset` and `PreviousSafeToBreakOffset` for various scenarios, including ligatures and different scripts (Latin, Arabic).
2. **Handling missing runs:** Testing scenarios where shaping results might have gaps or missing character ranges.
3. **Sub-range extraction:**  Testing the ability to extract sub-sections from a `ShapeResult`.
4. **ShapeResultView:** Testing the functionality of `ShapeResultView`, which provides a view over a portion of a `ShapeResult`.
5. **Kerning tests:** Verifying if kerning is applied correctly under different conditions (with and without subpixel rendering, horizontal and vertical text).
6. **Emoji handling:** Testing the callback mechanism for analyzing emoji clusters and broken clusters.
7. **Handling long grapheme clusters:** Testing the behavior when encountering extremely long sequences of combining characters.
8. **Cluster index order:**  Testing to ensure that character clusters are ordered correctly after shaping.

Connections to web technologies:

*   **JavaScript, HTML, CSS (indirectly):** The shaping process implemented and tested here is crucial for correctly rendering text on web pages. While this code doesn't directly interact with JavaScript, HTML, or CSS, its correctness affects how text styled with CSS is ultimately displayed in a browser after being processed by the rendering engine (Blink).

Assumptions and logical inferences:

*   The tests are designed to ensure the `HarfBuzzShaper` class correctly handles complex text layout scenarios, including ligatures, different writing directions, and grapheme clusters.
*   The "safe-to-break" functionality is important for line breaking and text editing.
*   Kerning affects the visual appearance of text and is a CSS feature.
*   Emoji rendering is a significant part of modern web content.

Potential user/programming errors:

*   Incorrectly calculating or assuming safe-to-break points without using the provided methods.
*   Manually splitting text without considering the complexities of grapheme clusters and ligatures.
这是`HarfBuzzShaperTest`测试文件的最后一部分，主要关注以下功能点的测试：

**1. 安全断点 (Safe To Break) 功能的深入测试:**

*   **测试包含拉丁连字的字符串的安全断点:**  验证在启用常见连字的情况下（如 "ffi", "ff"），`NextSafeToBreakOffset` 和 `PreviousSafeToBreakOffset` 方法是否能正确识别断点位置，即使这些字符组合成一个字形。
    *   **假设输入:** 字符串 "ffi ff"，启用了常见连字。
    *   **预期输出:** `NextSafeToBreakOffset` 在 "ffi" 之后返回 3，在空格之后返回 4，在 "ff" 之后返回 6。`PreviousSafeToBreakOffset` 反向计算断点位置。
*   **测试包含可选择连字的字符串的安全断点:**  验证在启用可选择连字的情况下（如 "RADDAYoVaDD"），断点是否出现在预期的位置，即使这些连字并非必须。
    *   **假设输入:** 字符串 "RADDAYoVaDD"，启用了可选择连字。
    *   **预期输出:** `NextSafeToBreakOffset` 返回预定义的断点位置，例如在 "RA" 之后，两个 "D" 之间等。
*   **通过插入零宽空格验证安全断点:**  通过在安全断点位置插入零宽空格，然后比较原始字符串和插入空格后的字符串的渲染宽度和字符位置，来验证这些位置是否真的是安全的断点。如果断点安全，插入零宽空格不应影响布局（例如，不会打断连字或调整字距）。
*   **测试阿拉伯语的安全断点:**  验证在阿拉伯语文本中，即使启用了连字，也能正确识别安全断点。
    *   **假设输入:** 阿拉伯语字符串 "كسر الاختبار" (测试失败)，启用了常见连字。
    *   **预期输出:** `NextSafeToBreakOffset` 和 `PreviousSafeToBreakOffset` 返回阿拉伯语连字和词语之间的正确断点位置。请注意，不同平台（例如 Apple）的输出可能存在差异，这是测试中需要考虑的。
*   **测试连续重复字符的安全断点:**  验证对于连续重复的字符（例如 "صصصصص"），安全断点是否正确地标记在整个序列的开头和结尾。
    *   **假设输入:** 阿拉伯语字符串 "صصصصص"。
    *   **预期输出:** `NextSafeToBreakOffset` 除第一个字符外都返回序列的末尾索引，`PreviousSafeToBreakOffset` 除最后一个字符外都返回序列的起始索引。

**2. 处理缺失字符 Run 的测试:**

*   **测试 `NextSafeToBreakOffset` 和 `PreviousSafeToBreakOffset` 在字符 Run 中存在缺失时的行为:**  创建一个人为制造的 `ShapeResult`，其中某些字符的 Run 信息缺失，然后测试安全断点方法是否能正确处理这种情况，跳过缺失的范围。
    *   **假设输入:**  一个 `ShapeResult`，表示索引 2 到 10 的字符串，但索引 6 和 7 的 Run 信息缺失。
    *   **预期输出:**  安全断点方法会跳过缺失的索引，例如 `NextSafeToBreakOffset(5)` 返回 6，`PreviousSafeToBreakOffset(5)` 返回 4。
*   **测试 `SubRange` 方法在字符 Run 中存在缺失时的行为:**  验证在提取子范围时，即使原始 `ShapeResult` 中存在缺失的 Run，子范围的 `StartIndex`, `EndIndex`, 和 `NumCharacters` 也能被正确计算。
*   **测试 `CopyRange` 方法在字符 Run 中不存在时的行为:**  创建一个没有 Run 信息的 `ShapeResult`，然后测试 `CopyRange` 方法是否能正确复制指定范围的信息。

**3. `ShapeResultView` 的测试:**

*   **测试 `ShapeResultView` 在字符 Run 中存在缺失时的行为:**  类似于 `SubRange` 的测试，但使用 `ShapeResultView` 来创建一个指定范围的视图，并验证其 `StartIndex`, `EndIndex`, 和 `NumCharacters` 是否正确。

**4. 字距调整 (Kerning) 的测试:**

*   **`KerningIsHappeningWorks` 测试:**  这是一个辅助函数，用于验证给定的字体和文本方向是否应用了字距调整。它通过比较启用和禁用字距调整时的字符位置来实现。
    *   **假设输入:** 包含可能存在字距调整的字符组合的字符串（例如 "AVOID"）。
    *   **预期输出:**  如果启用和禁用字距调整时的字符位置不同，则返回 `true`，否则返回 `false`。
*   **测试在禁用亚像素定位且没有字距调整的情况下，字符位置是否被四舍五入:** 验证当禁用亚像素定位时，即使没有应用字距调整，字符的位置也会被四舍五入到最接近的整数。
*   **测试在启用亚像素定位且没有字距调整的情况下，字符位置是否未被四舍五入:** 验证当启用亚像素定位时，在没有应用字距调整的情况下，字符的位置可以是非整数值。
*   **测试在禁用亚像素定位且有字距调整的情况下，字符位置是否被四舍五入:**  验证当禁用亚像素定位时，即使应用了字距调整，字符的位置也会被四舍五入。
*   **测试在启用亚像素定位且有字距调整的情况下，字符位置是否未被四舍五入:**  验证当启用亚像素定位时，如果应用了字距调整，字符的位置可以是非整数值。
*   **测试垂直排版时，无论是否启用亚像素定位，字符位置都被四舍五入:**  验证在垂直排版模式下，字符的位置总是会被四舍五入，不受亚像素定位设置的影响。

**5. Emoji 处理的测试:**

*   **`EmojiPercentage` 测试:**  测试 `HarfBuzzShaper` 的 emoji 指标回调函数，用于统计字符串中的 emoji 集群数量和无法正确形成的集群数量。这对于理解 emoji 的渲染情况非常重要。
    *   **假设输入:**  包含 emoji 字符的字符串，例如 "aa👩🏼‍❤️‍👨🏾😶👩🏼‍❤️‍👨🏾aa👩🏼‍❤️‍👨🏾😶👩🏼‍❤️‍👨🏾aa🫀🫀🥸🥸😶😶"。
    *   **预期输出:**  回调函数会被调用，并报告预期的集群数量和 broken 集群数量。具体的数量可能因平台和 emoji 字体支持而异。

**6. 处理过长字形集群的测试:**

*   **`OverlyLongGraphemeCluster` 测试:**  测试当遇到非常长的字形集群（例如，一个基本字符加上数千个组合字符）时，`HarfBuzzShaper` 的处理行为。
    *   **假设输入:**  包含字母 'e' 加上 35000 个音标符号，然后是字母 'X' 的字符串。
    *   **预期输出:**  字形会被拆分成多个 Run，第一个 Run 包含 'e' 和最大允许数量的音标符号，其余的音标符号被忽略或在后续的 Run 中处理。

**7. 乱序集群索引的测试:**

*   **`UnorderedClusterIndex` 测试:**  测试在某些特定字体下，HarfBuzz 是否会错误地交换字符集群的顺序。这旨在解决 HarfBuzz 本身的一个 bug。
    *   **假设输入:**  包含可能导致集群顺序错误的字符组合的字符串（例如 U+1DDE 和 U+A74A）。
    *   **预期输出:**  通过断言检查，确保生成的 `ShapeResult` 中的集群索引是按升序排列的。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个测试文件是 C++ 代码，直接测试 Blink 渲染引擎的底层字体排版功能，但它与 Web 技术息息相关：

*   **CSS 字体属性:**  测试中使用的 `FontDescription` 类对应于 CSS 中用于设置字体样式的属性，例如 `font-family`, `font-size`, `font-weight`, `font-style`, `font-variant-ligatures` 等。这些测试验证了 HarfBuzzShaper 在解析和应用这些 CSS 属性时的正确性。
*   **文本渲染:**  `HarfBuzzShaper` 的核心功能是将文本字符串转换为可以进行渲染的字形序列，这直接影响着网页上文本的最终显示效果。JavaScript 和 HTML 定义了要显示的文本内容，而 CSS 负责样式，`HarfBuzzShaper` 则负责按照这些指令进行精确的排版。
*   **连字 (Ligatures):**  测试中针对连字的测试确保了 CSS 中 `font-variant-ligatures` 属性（例如 `common-ligatures`, `discretionary-ligatures`) 能正确控制文本中连字的形成。
*   **断行和换行:**  安全断点功能对于浏览器如何进行文本的自动换行至关重要。这确保了文本在不同屏幕尺寸和布局下都能正确显示，不会在不合适的地方断开单词或连字。
*   **字距调整 (Kerning):**  测试字距调整的功能验证了 CSS 中 `font-kerning` 属性的实现是否正确，确保文本在视觉上更加美观和易读。
*   **Emoji 支持:**  现代网页中广泛使用 emoji，这些测试确保了 Blink 能够正确处理和渲染各种 emoji 字符和序列。

**常见的用户或编程错误 (与测试相关):**

虽然这些是单元测试，但它们揭示了在实际开发中可能出现的与文本渲染相关的问题：

*   **错误地假设文本可以在任意字符边界断开:**  开发者可能会错误地认为可以在任何字符之间进行断行或文本分割，而没有考虑到连字或复杂的字符组合。`HarfBuzzShaper` 的安全断点功能正是为了解决这个问题。
*   **没有正确处理不同语言的文本特性:**  例如，阿拉伯语等 RTL 语言的文本排版方式与英语等 LTR 语言不同，开发者需要了解这些差异并正确配置字体和文本方向。
*   **忽略了字距调整的重要性:**  在某些情况下，禁用字距调整可能会导致文本显示效果不佳。测试确保了 Blink 能够按照 CSS 的指示进行字距调整。
*   **对 Emoji 的支持不足:**  旧版本的浏览器或操作系统可能无法正确渲染所有 emoji，或者会将复杂的 emoji 序列拆分成多个单独的字符。这些测试有助于确保 Blink 能够提供一致且正确的 emoji 渲染体验。
*   **错误地处理组合字符:**  开发者可能会将组合字符（例如，带有音标的字符）视为单独的字符，而实际上它们应该被视为一个整体。`HarfBuzzShaper` 能够正确处理这些复杂的字符组合。

**总结来说，这个测试文件的主要功能是验证 Blink 渲染引擎中 `HarfBuzzShaper` 类的各种文本排版功能，包括安全断点、处理缺失字符、子范围提取、字距调整、Emoji 处理和处理复杂的字符组合。这些测试确保了 Blink 能够按照 CSS 的指示正确渲染各种语言和字符集的文本，为用户提供高质量的网页浏览体验。**

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_shaper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
onst ShapeResult* result2 =
      shaper.Shape(&font, direction, 6, string.length());

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, 6, composite_result);
  result2->CopyRange(6, string.length(), composite_result);

  const ShapeResult* result = shaper.Shape(&font, direction);
  EXPECT_EQ(result->Width(), composite_result->Width());
}

TEST_F(HarfBuzzShaperTest, SubRange) {
  Font font(font_description);

  String string(u"Hello world");
  TextDirection direction = TextDirection::kRtl;
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  const ShapeResult* sub_range = result->SubRange(4, 7);
  DCHECK_EQ(4u, sub_range->StartIndex());
  DCHECK_EQ(7u, sub_range->EndIndex());
  DCHECK_EQ(3u, sub_range->NumCharacters());
  DCHECK_EQ(result->Direction(), sub_range->Direction());
}

TEST_F(HarfBuzzShaperTest, SafeToBreakLatinCommonLigatures) {
  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;

  // MEgalopolis Extra has a lot of ligatures which this test relies on.
  Font testFont = blink::test::CreateTestFont(
      AtomicString("MEgalopolis"),
      blink::test::PlatformTestDataPath(
          "third_party/MEgalopolis/MEgalopolisExtra.woff"),
      16, &ligatures);

  String string = To16Bit("ffi ff");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&testFont, TextDirection::kLtr);

  EXPECT_EQ(0u, result->NextSafeToBreakOffset(0));  // At start of string.
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(1));  // At end of "ffi" ligature.
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(2));  // At end of "ffi" ligature.
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(3));  // At end of "ffi" ligature.
  EXPECT_EQ(4u, result->NextSafeToBreakOffset(4));  // After space.
  EXPECT_EQ(6u, result->NextSafeToBreakOffset(5));  // At end of "ff" ligature.
  EXPECT_EQ(6u, result->NextSafeToBreakOffset(6));  // At end of "ff" ligature.

  // Verify safe to break information in copied results to ensure that both
  // copying and multi-run break information works.
  ShapeResult* copied_result =
      MakeGarbageCollected<ShapeResult>(&testFont, 0, 0, TextDirection::kLtr);
  result->CopyRange(0, 3, copied_result);
  result->CopyRange(3, string.length(), copied_result);

  EXPECT_EQ(0u, copied_result->NextSafeToBreakOffset(0));
  EXPECT_EQ(3u, copied_result->NextSafeToBreakOffset(1));
  EXPECT_EQ(3u, copied_result->NextSafeToBreakOffset(2));
  EXPECT_EQ(3u, copied_result->NextSafeToBreakOffset(3));
  EXPECT_EQ(4u, copied_result->NextSafeToBreakOffset(4));
  EXPECT_EQ(6u, copied_result->NextSafeToBreakOffset(5));
  EXPECT_EQ(6u, copied_result->NextSafeToBreakOffset(6));
}

TEST_F(HarfBuzzShaperTest, SafeToBreakPreviousLatinCommonLigatures) {
  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;

  // MEgalopolis Extra has a lot of ligatures which this test relies on.
  Font testFont = blink::test::CreateTestFont(
      AtomicString("MEgalopolis"),
      blink::test::PlatformTestDataPath(
          "third_party/MEgalopolis/MEgalopolisExtra.woff"),
      16, &ligatures);

  String string = To16Bit("ffi ff");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&testFont, TextDirection::kLtr);

  EXPECT_EQ(6u, result->PreviousSafeToBreakOffset(6));  // At end of "ff" liga.
  EXPECT_EQ(4u, result->PreviousSafeToBreakOffset(5));  // At end of "ff" liga.
  EXPECT_EQ(4u, result->PreviousSafeToBreakOffset(4));  // After space.
  EXPECT_EQ(3u, result->PreviousSafeToBreakOffset(3));  // At end of "ffi" liga.
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(2));  // At start of string.
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(1));  // At start of string.
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(0));  // At start of string.

  // Verify safe to break information in copied results to ensure that both
  // copying and multi-run break information works.
  ShapeResult* copied_result =
      MakeGarbageCollected<ShapeResult>(&testFont, 0, 0, TextDirection::kLtr);
  result->CopyRange(0, 3, copied_result);
  result->CopyRange(3, string.length(), copied_result);

  EXPECT_EQ(6u, copied_result->PreviousSafeToBreakOffset(6));
  EXPECT_EQ(4u, copied_result->PreviousSafeToBreakOffset(5));
  EXPECT_EQ(4u, copied_result->PreviousSafeToBreakOffset(4));
  EXPECT_EQ(3u, copied_result->PreviousSafeToBreakOffset(3));
  EXPECT_EQ(0u, copied_result->PreviousSafeToBreakOffset(2));
  EXPECT_EQ(0u, copied_result->PreviousSafeToBreakOffset(1));
  EXPECT_EQ(0u, copied_result->PreviousSafeToBreakOffset(0));
}

TEST_F(HarfBuzzShaperTest, SafeToBreakLatinDiscretionaryLigatures) {
  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;
  ligatures.discretionary = FontDescription::kEnabledLigaturesState;

  // MEgalopolis Extra has a lot of ligatures which this test relies on.
  Font testFont = blink::test::CreateTestFont(
      AtomicString("MEgalopolis"),
      blink::test::PlatformTestDataPath(
          "third_party/MEgalopolis/MEgalopolisExtra.woff"),
      16, &ligatures);

  // $ ./hb-shape   --shaper=ot --features="dlig=1,kern" --show-flags
  // MEgalopolisExtra.ttf  "RADDAYoVaDD"
  // [R_A=0+1150|D=2+729|D=3+699|A=4+608#1|Y=5+608#1|o=6+696#1|V=7+652#1|a=8+657#1|D=9+729|D=10+729]
  // RA Ligature, unkerned D D, D A kerns, A Y kerns, Y o kerns, o V kerns, V a
  // kerns, no kerning with D.
  String test_word(u"RADDAYoVaDD");
  unsigned safe_to_break_positions[] = {2, 3, 9, 10};
  HarfBuzzShaper shaper(test_word);
  const ShapeResult* result = shaper.Shape(&testFont, TextDirection::kLtr);

  unsigned compare_safe_to_break_position = 0;
  for (unsigned i = 1; i < test_word.length() - 1; ++i) {
    EXPECT_EQ(safe_to_break_positions[compare_safe_to_break_position],
              result->NextSafeToBreakOffset(i));
    if (i == safe_to_break_positions[compare_safe_to_break_position])
      compare_safe_to_break_position++;
  }

  // Add zero-width spaces at some of the safe to break offsets.
  String inserted_zero_width_spaces(u"RA\u200BD\u200BDAYoVa\u200BD\u200BD");
  HarfBuzzShaper refShaper(inserted_zero_width_spaces);
  const ShapeResult* referenceResult =
      refShaper.Shape(&testFont, TextDirection::kLtr);

  // Results should be identical if it truly is safe to break at the designated
  // safe-to-break offsets because otherwise, the zero-width spaces would have
  // altered the text spacing, for example by breaking apart ligatures or
  // kerning pairs.
  EXPECT_EQ(result->SnappedWidth(), referenceResult->SnappedWidth());

  // Zero-width spaces were inserted, so we need to account for that by
  // offseting the index that we compare against.
  unsigned inserts_offset = 0;
  for (unsigned i = 0; i < test_word.length(); ++i) {
    if (i == safe_to_break_positions[inserts_offset])
      inserts_offset++;
    EXPECT_EQ(
        result->SnappedStartPositionForOffset(i),
        referenceResult->SnappedStartPositionForOffset(i + inserts_offset));
  }
}

// TODO(crbug.com/870712): This test fails due to font fallback differences on
// Android and Fuchsia.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_FUCHSIA)
#define MAYBE_SafeToBreakArabicCommonLigatures \
  DISABLED_SafeToBreakArabicCommonLigatures
#else
#define MAYBE_SafeToBreakArabicCommonLigatures SafeToBreakArabicCommonLigatures
#endif
TEST_F(HarfBuzzShaperTest, MAYBE_SafeToBreakArabicCommonLigatures) {
  Font font(font_description);

  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;

  // كسر الاختبار
  String string(
      u"\u0643\u0633\u0631\u0020\u0627\u0644\u0627\u062E\u062A\u0628\u0627"
      u"\u0631");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kRtl);

  EXPECT_EQ(0u, result->NextSafeToBreakOffset(0));
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(1));
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(2));
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(3));
  EXPECT_EQ(4u, result->NextSafeToBreakOffset(4));
#if BUILDFLAG(IS_APPLE)
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(5));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(6));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(7));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(8));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(9));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(10));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(11));
#else
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(5));
  EXPECT_EQ(7u, result->NextSafeToBreakOffset(6));
  EXPECT_EQ(7u, result->NextSafeToBreakOffset(7));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(8));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(9));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(10));
  EXPECT_EQ(11u, result->NextSafeToBreakOffset(11));
#endif
  EXPECT_EQ(12u, result->NextSafeToBreakOffset(12));

  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(0));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(1));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(2));
  EXPECT_EQ(3u, result->PreviousSafeToBreakOffset(3));
  EXPECT_EQ(4u, result->PreviousSafeToBreakOffset(4));
#if BUILDFLAG(IS_APPLE)
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(5));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(6));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(7));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(8));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(9));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(10));
  EXPECT_EQ(11u, result->PreviousSafeToBreakOffset(11));
#else
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(5));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(6));
  EXPECT_EQ(7u, result->PreviousSafeToBreakOffset(7));
  EXPECT_EQ(7u, result->PreviousSafeToBreakOffset(8));
  EXPECT_EQ(7u, result->PreviousSafeToBreakOffset(9));
  EXPECT_EQ(7u, result->PreviousSafeToBreakOffset(10));
  EXPECT_EQ(11u, result->PreviousSafeToBreakOffset(11));
#endif
  EXPECT_EQ(12u, result->PreviousSafeToBreakOffset(12));
}

// http://crbug.com/1170334
TEST_F(HarfBuzzShaperTest, SafeToBreakU0635) {
  Font font(font_description);

  FontDescription::VariantLigatures ligatures;
  ligatures.common = FontDescription::kEnabledLigaturesState;

  // Five U+0635. This sequence should be rendered once.
  String string(u"\u0635\u0635\u0635\u0635\u0635");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kRtl);

  EXPECT_EQ(0u, result->NextSafeToBreakOffset(0));
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(1));
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(2));
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(3));
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(4));
  EXPECT_EQ(5u, result->NextSafeToBreakOffset(5));

  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(0));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(1));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(2));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(3));
  EXPECT_EQ(0u, result->PreviousSafeToBreakOffset(4));
  EXPECT_EQ(5u, result->PreviousSafeToBreakOffset(5));
}

// TODO(layout-dev): Expand RTL test coverage and add tests for mixed
// directionality strings.

// Test when some characters are missing in |runs_|.
TEST_P(ShapeParameterTest, SafeToBreakMissingRun) {
  TextDirection direction = GetParam();
  const ShapeResult* result = CreateMissingRunResult(direction);
#if DCHECK_IS_ON()
  result->CheckConsistency();
#endif

  EXPECT_EQ(2u, result->StartIndex());
  EXPECT_EQ(10u, result->EndIndex());

  EXPECT_EQ(2u, result->NextSafeToBreakOffset(2));
  EXPECT_EQ(3u, result->NextSafeToBreakOffset(3));
  EXPECT_EQ(4u, result->NextSafeToBreakOffset(4));
  EXPECT_EQ(6u, result->NextSafeToBreakOffset(5));
  EXPECT_EQ(8u, result->NextSafeToBreakOffset(6));
  EXPECT_EQ(8u, result->NextSafeToBreakOffset(7));
  EXPECT_EQ(8u, result->NextSafeToBreakOffset(8));
  EXPECT_EQ(10u, result->NextSafeToBreakOffset(9));

  EXPECT_EQ(2u, result->PreviousSafeToBreakOffset(2));
  EXPECT_EQ(3u, result->PreviousSafeToBreakOffset(3));
  EXPECT_EQ(4u, result->PreviousSafeToBreakOffset(4));
  EXPECT_EQ(4u, result->PreviousSafeToBreakOffset(5));
  EXPECT_EQ(6u, result->PreviousSafeToBreakOffset(6));
  EXPECT_EQ(6u, result->PreviousSafeToBreakOffset(7));
  EXPECT_EQ(8u, result->PreviousSafeToBreakOffset(8));
  EXPECT_EQ(8u, result->PreviousSafeToBreakOffset(9));
}

TEST_P(ShapeParameterTest, CopyRangeMissingRun) {
  TextDirection direction = GetParam();
  const ShapeResult* result = CreateMissingRunResult(direction);

  // 6 and 7 are missing but NumCharacters() should be 4.
  const ShapeResult* sub = result->SubRange(5, 9);
  EXPECT_EQ(sub->StartIndex(), 5u);
  EXPECT_EQ(sub->EndIndex(), 9u);
  EXPECT_EQ(sub->NumCharacters(), 4u);

  // The end is missing.
  sub = result->SubRange(5, 7);
  EXPECT_EQ(sub->StartIndex(), 5u);
  EXPECT_EQ(sub->EndIndex(), 7u);
  EXPECT_EQ(sub->NumCharacters(), 2u);

  // The start is missing.
  sub = result->SubRange(7, 9);
  EXPECT_EQ(sub->StartIndex(), 7u);
  EXPECT_EQ(sub->EndIndex(), 9u);
  EXPECT_EQ(sub->NumCharacters(), 2u);
}

TEST_P(ShapeParameterTest, CopyRangeNoRuns) {
  Font font(font_description);

  TextDirection direction = GetParam();
  const ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 2, direction);

  const ShapeResult* sub0 = result->SubRange(0, 1);
  EXPECT_EQ(sub0->StartIndex(), 0u);
  EXPECT_EQ(sub0->EndIndex(), 1u);
  EXPECT_EQ(sub0->NumCharacters(), 1u);

  const ShapeResult* sub1 = result->SubRange(1, 2);
  EXPECT_EQ(sub1->StartIndex(), 1u);
  EXPECT_EQ(sub1->EndIndex(), 2u);
  EXPECT_EQ(sub1->NumCharacters(), 1u);

  HeapVector<Member<ShapeResult>> range_results;
  HeapVector<ShapeResult::ShapeRange> ranges;
  range_results.push_back(ShapeResult::CreateEmpty(*result));
  ranges.push_back(ShapeResult::ShapeRange{0, 1, range_results[0].Get()});
  result->CopyRanges(ranges.data(), ranges.size());
  for (unsigned i = 0; i < ranges.size(); i++) {
    const ShapeResult::ShapeRange& range = ranges[i];
    const ShapeResult& range_result = *range_results[i];
    EXPECT_EQ(range_result.StartIndex(), range.start);
    EXPECT_EQ(range_result.EndIndex(), range.end);
    EXPECT_EQ(range_result.NumCharacters(), range.end - range.start);
  }
}

TEST_P(ShapeParameterTest, ShapeResultViewMissingRun) {
  TextDirection direction = GetParam();
  const ShapeResult* result = CreateMissingRunResult(direction);

  // 6 and 7 are missing but NumCharacters() should be 4.
  ShapeResultView* view = ShapeResultView::Create(result, 5, 9);
  EXPECT_EQ(view->StartIndex(), 5u);
  EXPECT_EQ(view->EndIndex(), 9u);
  EXPECT_EQ(view->NumCharacters(), 4u);

  // The end is missing.
  view = ShapeResultView::Create(result, 5, 7);
  EXPECT_EQ(view->StartIndex(), 5u);
  EXPECT_EQ(view->EndIndex(), 7u);
  EXPECT_EQ(view->NumCharacters(), 2u);

  // The start is missing.
  view = ShapeResultView::Create(result, 7, 9);
  EXPECT_EQ(view->StartIndex(), 7u);
  EXPECT_EQ(view->EndIndex(), 9u);
  EXPECT_EQ(view->NumCharacters(), 2u);
}

// Call this to ensure your test string has some kerning going on.
static bool KerningIsHappening(const FontDescription& font_description,
                               TextDirection direction,
                               const String& str) {
  FontDescription no_kern = font_description;
  no_kern.SetKerning(FontDescription::kNoneKerning);

  FontDescription kern = font_description;
  kern.SetKerning(FontDescription::kAutoKerning);

  Font font_no_kern(no_kern);
  Font font_kern(kern);

  HarfBuzzShaper shaper(str);

  const ShapeResult* result_no_kern = shaper.Shape(&font_no_kern, direction);
  const ShapeResult* result_kern = shaper.Shape(&font_kern, direction);

  for (unsigned i = 0; i < str.length(); i++) {
    if (result_no_kern->PositionForOffset(i) !=
        result_kern->PositionForOffset(i))
      return true;
  }
  return false;
}

TEST_F(HarfBuzzShaperTest, KerningIsHappeningWorks) {
  EXPECT_TRUE(
      KerningIsHappening(font_description, TextDirection::kLtr, u"AVOID"));
  EXPECT_FALSE(
      KerningIsHappening(font_description, TextDirection::kLtr, u"NOID"));

  // We won't kern vertically with the default font.
  font_description.SetOrientation(FontOrientation::kVerticalUpright);

  EXPECT_FALSE(
      KerningIsHappening(font_description, TextDirection::kLtr, u"AVOID"));
  EXPECT_FALSE(
      KerningIsHappening(font_description, TextDirection::kLtr, u"NOID"));
}

TEST_F(HarfBuzzShaperTest,
       ShapeHorizontalWithoutSubpixelPositionWithoutKerningIsRounded) {
  Font font(font_description);
  ScopedSubpixelOverride subpixel_override(false);

  String string(u"NOID");
  TextDirection direction = TextDirection::kLtr;
  ASSERT_FALSE(KerningIsHappening(font_description, direction, string));

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    EXPECT_EQ(round(position), position)
        << "Position not rounded at offset " << i;
  }
}

#if BUILDFLAG(IS_ANDROID)
#define MAYBE_ShapeHorizontalWithSubpixelPositionWithoutKerningIsNotRounded \
  DISABLED_ShapeHorizontalWithSubpixelPositionWithoutKerningIsNotRounded
#else
#define MAYBE_ShapeHorizontalWithSubpixelPositionWithoutKerningIsNotRounded \
  ShapeHorizontalWithSubpixelPositionWithoutKerningIsNotRounded
#endif
TEST_F(HarfBuzzShaperTest,
       MAYBE_ShapeHorizontalWithSubpixelPositionWithoutKerningIsNotRounded) {
  Font font(font_description);
  ScopedSubpixelOverride subpixel_override(true);

  String string(u"NOID");
  TextDirection direction = TextDirection::kLtr;
  ASSERT_FALSE(KerningIsHappening(font_description, direction, string));

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    if (round(position) != position)
      return;
  }

  EXPECT_TRUE(false) << "No unrounded positions found";
}

TEST_F(HarfBuzzShaperTest,
       ShapeHorizontalWithoutSubpixelPositionWithKerningIsRounded) {
  ScopedSubpixelOverride subpixel_override(false);

  // The verification whether a particular shaping routine is performing
  // kerning can be flaky when subpixel if OFF - see KerningIsHappening().
  // For instance, if the position of a character is say `7.55` with subpixel
  // ON, it gets rounded to `8` with subpixel position OFF, and the comparison
  // in KerningIsHappening() fails, although kerning is effectively happening.
  //
  // Hence, this test leverages the uses of a particular font (Arial) where the
  // result is reliable cross platform (linux, mac, ios, etc).
  //
  // [1] RoundHarfBuzzPosition() @harfbuzz_shaper.cc
  FontDescription font_description_copy(font_description);
  font_description_copy.SetFamily(
      FontFamily(font_family_names::kArial, FontFamily::Type::kFamilyName));
  Font font = Font(font_description_copy);

  String string(u"AVOID");
  TextDirection direction = TextDirection::kLtr;
  ASSERT_TRUE(KerningIsHappening(font_description_copy, direction, string));

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    EXPECT_EQ(round(position), position)
        << "Position not rounded at offset " << i;
  }
}

#if BUILDFLAG(IS_ANDROID)
#define MAYBE_ShapeHorizontalWithSubpixelPositionWithKerningIsNotRounded \
  DISABLED_ShapeHorizontalWithSubpixelPositionWithKerningIsNotRounded
#else
#define MAYBE_ShapeHorizontalWithSubpixelPositionWithKerningIsNotRounded \
  ShapeHorizontalWithSubpixelPositionWithKerningIsNotRounded
#endif
TEST_F(HarfBuzzShaperTest,
       MAYBE_ShapeHorizontalWithSubpixelPositionWithKerningIsNotRounded) {
  Font font(font_description);
  ScopedSubpixelOverride subpixel_override(true);

  String string(u"AVOID");
  TextDirection direction = TextDirection::kLtr;
  ASSERT_TRUE(KerningIsHappening(font_description, direction, string));

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    if (round(position) != position)
      return;
  }

  EXPECT_TRUE(false) << "No unrounded positions found";
}

TEST_F(HarfBuzzShaperTest, ShapeVerticalWithoutSubpixelPositionIsRounded) {
  ScopedSubpixelOverride subpixel_override(false);

  font_description.SetOrientation(FontOrientation::kVerticalUpright);
  Font font(font_description);

  String string(u"\u65E5\u65E5\u65E5");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    EXPECT_EQ(round(position), position)
        << "Position not rounded at offset " << i;
  }
}

TEST_F(HarfBuzzShaperTest, ShapeVerticalWithSubpixelPositionIsRounded) {
  ScopedSubpixelOverride subpixel_override(true);

  font_description.SetOrientation(FontOrientation::kVerticalUpright);
  Font font(font_description);

  String string(u"\u65E5\u65E5\u65E5");
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Vertical text is never subpixel positioned.
  for (unsigned i = 0; i < string.length(); i++) {
    float position = result->PositionForOffset(i);
    EXPECT_EQ(round(position), position)
        << "Position not rounded at offset " << i;
  }
}

// Broken on Apple platforms: https://crbug.com/1194323
#if BUILDFLAG(IS_APPLE)
#define MAYBE_EmojiPercentage DISABLED_EmojiPercentage
#else
#define MAYBE_EmojiPercentage EmojiPercentage
#endif
TEST_F(HarfBuzzShaperTest, MAYBE_EmojiPercentage) {
#if BUILDFLAG(IS_WIN)
  if (base::win::OSInfo::GetInstance()->version() >=
      base::win::Version::WIN11) {
    GTEST_SKIP() << "Broken on WIN11 and greater: https://crbug.com/1286133";
  }
#endif
  // This test relies on Noto Color Emoji from the third_party directory to not
  // contain sequences and single codepoint emoji from Unicode 13 and 13.1 such
  // as:
  // * Couple with Heart: Woman, Man, Medium-Light Skin Tone, Medium-Dark Skin
  // Tone
  // * Disguised Face U+1F978
  // * Anatomical Heart U+1FAC0
  String string(
      u"aa👩🏼‍❤️‍👨🏾😶👩🏼‍❤️‍👨🏾aa👩🏼‍❤️‍👨🏾😶"
      u"👩🏼‍❤️‍👨🏾aa🫀🫀🥸🥸😶😶");

  struct Expectation {
    unsigned expected_clusters;
    unsigned expected_broken_clusters;
  };

  Expectation expectations[] = {{3, 2}, {3, 2}, {6, 4}};
#if BUILDFLAG(IS_ANDROID)
  // On Android 11, SDK level 30, fallback occurs to an emoji
  // font that has coverage for the last segment. Adjust the expectation.
  if (base::android::BuildInfo::GetInstance()->sdk_int() >=
      base::android::SdkVersion::SDK_VERSION_R) {
    expectations[2].expected_broken_clusters = 0;
  }
#endif
  unsigned num_calls = 0;
  HarfBuzzShaper::EmojiMetricsCallback metrics_callback =
      base::BindLambdaForTesting(
          [&](unsigned num_clusters, unsigned num_broken_clusters) {
            CHECK_EQ(num_clusters, expectations[num_calls].expected_clusters);
            CHECK_EQ(num_broken_clusters,
                     expectations[num_calls].expected_broken_clusters);

            num_calls++;
          });
  HarfBuzzShaper shaper(string, metrics_callback);
  Font emoji_font = CreateNotoColorEmoji();
  shaper.Shape(&emoji_font, TextDirection::kLtr);
  CHECK_EQ(num_calls, std::size(expectations));
}

// https://crbug.com/1255482
TEST_F(HarfBuzzShaperTest, OverlyLongGraphemeCluster) {
  Font font(font_description);

  // Letter 'e' with 35000 diacritics, followed by letter 'X'
  StringBuilder builder;
  builder.Append('e');
  for (unsigned i = 0; i < 35000; ++i)
    builder.Append(kCombiningAcuteAccentCharacter);
  builder.Append('X');
  String string = builder.ToString();

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);

  ASSERT_EQ(2u, runs.size());

  // The first run contains a glyph 'é' with 32767 diacritic glyphs, reaching
  // the maximum allowed number of glyphs per run. The remaining 2232
  // diacritics are abandoned.
  EXPECT_EQ(0u, runs[0].start_index);
  EXPECT_EQ(35001u, runs[0].num_characters);
  EXPECT_EQ(32768u, runs[0].num_glyphs);

  // The second run consists of a single glyph 'X'.
  EXPECT_EQ(35001u, runs[1].start_index);
  EXPECT_EQ(1u, runs[1].num_characters);
  EXPECT_EQ(1u, runs[1].num_glyphs);
}

// HarfBuzz should not swap the ordering for some fonts.
//
// In general, for cluster levels 0 and 1, if clusters are not in ascending
// order (either LTR or RTL based on buffer direction), then it is a bug that
// needs to be fixed.
// https://github.com/harfbuzz/harfbuzz/issues/3553 crbug.com/1319078
TEST_F(HarfBuzzShaperTest, UnorderedClusterIndex) {
  // The first two characters may be swapped, producing [1, 0].
  // U+1DDE COMBINING LATIN LETTER SMALL CAPITAL L
  // U+A74A LATIN CAPITAL LETTER O WITH LONG STROKE OVERLAY
  String string(u"\u1DDE\uA74A");

  // The symptom was found on Mac, but it may occur on other platforms.
  // Setting the font family is not strictly necessary as fonts automatically
  // fallback, but it helps keeping the whole string in a run (i.e., shapes
  // surrounding characters with the same font.)
  font_description.SetFamily(
      FontFamily(AtomicString("Geneva"), FontFamily::Type::kFamilyName));
  Font font(font_description);

  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
#if DCHECK_IS_ON()
  result->CheckConsistency();
#endif
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);
  EXPECT_GE(runs.size(), 1u);
}

}  // namespace blink

"""


```