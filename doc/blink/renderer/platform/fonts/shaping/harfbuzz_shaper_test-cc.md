Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine.
Specifically, they want to understand the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning within the code (with examples), common usage errors, and a general summary of the file's purpose.

Here's a breakdown of how to address each point:

1. **Functionality:**  The file is a test suite (`_test.cc`) for `harfbuzz_shaper.h`. This means it tests the HarfBuzzShaper class, which is responsible for text shaping using the HarfBuzz library. Text shaping is the process of converting a sequence of characters into a sequence of glyphs for rendering, considering factors like ligatures, kerning, and script-specific rules.

2. **Relationship to JavaScript, HTML, CSS:**
    *   **JavaScript:** While this C++ code doesn't directly interact with JavaScript, the results of text shaping are used when rendering text in a web page, which JavaScript can manipulate. For example, if JavaScript dynamically adds text to the DOM, the shaping engine will be used to determine how that text is displayed.
    *   **HTML:**  HTML provides the structure of a web page, including the text content that needs to be shaped. The `harfbuzz_shaper` is involved in rendering the text within HTML elements.
    *   **CSS:** CSS styles how text is rendered, including font family, size, weight, and more. These CSS properties influence the font data used by the `harfbuzz_shaper`. For instance, different fonts have different glyph sets and shaping rules.

3. **Logical Reasoning (with examples):** The test file contains various test cases. Each test case sets up specific input (strings, font configurations) and asserts that the output of the `HarfBuzzShaper` matches the expected behavior.
    *   **Input:** A string of characters and a font.
    *   **Output:** A `ShapeResult` object, which contains information about the shaped text, including glyphs, positions, and other properties.
    *   **Example:** The `ResolveCandidateRunsLatin` test checks if a simple Latin string is shaped into a single run with the correct script.

4. **Common Usage Errors:**  Since this is a test file, it primarily targets errors in the `HarfBuzzShaper` implementation. However, it can indirectly highlight potential errors when *using* the shaping functionality.
    *   **Example:**  If a font doesn't support certain characters, the shaper might substitute a "missing glyph" character. This could indicate a developer's error in choosing an inappropriate font for the desired text.

5. **Summary of Functionality:** The core function of this file is to rigorously test the `HarfBuzzShaper` class to ensure it correctly shapes text for various scripts, font variations, and edge cases.

Let's formulate the response based on these points.
这个C++源代码文件 `harfbuzz_shaper_test.cc` 是 Chromium Blink 引擎中用于测试 `HarfBuzzShaper` 类的单元测试文件。 `HarfBuzzShaper` 的主要功能是使用 HarfBuzz 库对文本进行 **塑形 (shaping)**。文本塑形是将字符序列转换为用于渲染的字形序列的过程，它考虑了字体特性、语言规则（例如，从右到左的语言）、连字、字距调整等。

**功能归纳:**

该文件的主要功能是验证 `HarfBuzzShaper` 类的各种功能是否按预期工作，涵盖了以下方面：

1. **基本文本塑形:** 测试针对不同脚本（如拉丁文、梵文、阿拉伯文、中文等）的文本塑形是否能正确识别脚本并应用相应的塑形规则。
2. **分段塑形:** 测试将一段文本分成多个片段进行塑形，最终结果是否与一次性塑形整个文本一致。这模拟了在网页渲染中，文本内容可能被分割在不同的 HTML 元素或文本节点中的情况。
3. **特殊字符处理:** 测试对特殊字符（如零宽空格、制表符、Unicode 变体序列等）的处理是否正确。
4. **字体特性支持:** 测试是否正确应用了字体的一些特性，例如小型大写字母 (`small-caps`)。
5. **垂直排版:** 测试在垂直排版模式下，文本是否按照垂直方向进行塑形。
6. **最大字形数限制:** 测试在处理非常长的文本时，是否能正确处理达到最大字形数限制的情况。
7. **缺失字形处理:** 测试当文本中包含字体不支持的字符时，塑形器如何处理。
8. **表情符号处理:** 测试对 emoji 表情符号的处理，包括带有变体选择器的 emoji。
9. **子像素渲染控制:** 测试是否能根据设置控制子像素渲染。

**与 JavaScript, HTML, CSS 的关系:**

`HarfBuzzShaper` 处于 Blink 渲染引擎的底层，负责处理文本的最终渲染表示。它与 JavaScript, HTML, CSS 的功能存在间接但重要的关系：

*   **HTML:** HTML 提供了网页的结构和文本内容。`HarfBuzzShaper` 负责将 HTML 中包含的文本内容，根据指定的字体和样式，转换成可以绘制的字形。例如，当浏览器解析到 `<p>你好世界</p>` 时，`HarfBuzzShaper` 会被用来处理 "你好世界" 这段文本。
*   **CSS:** CSS 负责定义网页的样式，包括字体族、字号、字体粗细、是否斜体等。这些 CSS 属性会影响 `HarfBuzzShaper` 的行为。例如，CSS 中 `font-family: Arial, sans-serif;`  会告知 `HarfBuzzShaper` 优先使用 Arial 字体进行塑形，如果 Arial 不支持某些字符，则会回退到 sans-serif 字体。`font-variant-caps: small-caps;`  会指示 `HarfBuzzShaper` 将文本塑形为小型大写字母（前提是字体支持）。
*   **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式。当 JavaScript 修改了文本内容或者影响文本样式的 CSS 属性时，Blink 渲染引擎会重新调用 `HarfBuzzShaper` 对受影响的文本进行重新塑形。例如，如果 JavaScript 通过 `element.textContent = "新的文本";` 修改了元素的内容，或者通过 `element.style.fontFamily = "Times New Roman";` 修改了字体，`HarfBuzzShaper` 都会参与到后续的渲染更新过程中。

**逻辑推理举例 (假设输入与输出):**

假设我们有以下输入：

*   **输入文本:** "你好"
*   **字体:**  一个支持中文的字体，比如 "SimSun"
*   **文本方向:** 从左到右 (LTR)

`HarfBuzzShaper` 的逻辑推理过程大致如下：

1. **识别脚本:**  识别 "你好" 这两个字符属于中文 (Han) 脚本。
2. **选择字形:** 根据 "SimSun" 字体的字形表，找到 "你" 和 "好" 对应的字形 (glyphs)。
3. **应用排版规则:**  对于中文，通常的排版规则是水平排列，字形之间可能存在微小的间距调整（字偶距 kerning，如果字体支持）。
4. **生成 `ShapeResult`:**  创建一个 `ShapeResult` 对象，其中包含：
    *   字形的 ID 序列
    *   每个字形的位置信息 (x, y 偏移)
    *   每个字形的宽度信息
    *   运行信息 (run info)，指示文本段的起始索引、字符数、字形数以及脚本类型。

**假设输出 (简化):**

```
ShapeResult {
  glyphs: [glyph_id_for_你, glyph_id_for_好],
  advances: [width_of_你, width_of_好],
  offsets: [(0, 0), (width_of_你, 0)],
  run_info: { start_index: 0, num_characters: 2, num_glyphs: 2, script: HB_SCRIPT_HAN }
}
```

**用户或编程常见的使用错误举例:**

虽然 `harfbuzz_shaper_test.cc` 是测试代码，但它可以间接反映出一些用户或编程中可能出现的错误：

1. **使用了不支持特定字符的字体:**  例如，如果尝试用一个只包含拉丁字符的字体来渲染中文文本，`HarfBuzzShaper` 可能会使用 "missing glyph" (通常显示为一个方框) 来代替不支持的字符。这可能是因为开发者在 CSS 中指定了错误的 `font-family`。
    *   **假设输入:** 文本 "你好", 字体 "Arial" (在某些系统中可能不完全支持中文)
    *   **可能输出:** `ShapeResult` 中会包含 "missing glyph" 的字形 ID。

2. **错误的文本方向设置:** 对于从右到左的语言（如阿拉伯语或希伯来语），如果文本方向设置错误（例如，设置为 LTR），`HarfBuzzShaper` 可能会错误地排列字符。这可能是因为在处理包含双向文本（既有从左到右的字符，也有从右到左的字符）时，没有正确处理文本方向。

3. **过长的文本导致性能问题:**  虽然 `HarfBuzzShaper` 做了优化，但对于非常长的文本，如果没有进行适当的分段处理，一次性进行塑形可能会消耗较多的计算资源，导致页面渲染性能下降。

**功能归纳:**

总而言之，`blink/renderer/platform/fonts/shaping/harfbuzz_shaper_test.cc` 这个文件的核心功能是 **验证 `HarfBuzzShaper` 类在 Chromium Blink 引擎中对各种文本进行正确塑形的能力**。它通过大量的测试用例来覆盖不同的文本场景、字体特性和语言规则，确保文本能够按照预期的方式渲染在网页上。 这对于保证网页的正确显示至关重要，特别是在处理多语言内容和复杂排版需求时。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_shaper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"

#include <unicode/uscript.h>

#include "base/check.h"
#include "base/test/bind.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_priority.h"
#include "third_party/blink/renderer/platform/fonts/font_test_utilities.h"
#include "third_party/blink/renderer/platform/fonts/font_variant_emoji.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#endif

#if BUILDFLAG(IS_MAC)
#include "base/mac/mac_util.h"
#endif

#if BUILDFLAG(IS_WIN)
#include "base/win/windows_version.h"
#endif

using testing::ElementsAre;

namespace blink {

namespace {

const ShapeResultTestInfo* TestInfo(const ShapeResult* result) {
  return static_cast<const ShapeResultTestInfo*>(result);
}

// Test helper to compare all RunInfo with the expected array.
struct ShapeResultRunData {
  unsigned start_index;
  unsigned num_characters;
  unsigned num_glyphs;
  hb_script_t script;

  static Vector<ShapeResultRunData> Get(const ShapeResult* result) {
    const ShapeResultTestInfo* test_info = TestInfo(result);
    const unsigned num_runs = test_info->NumberOfRunsForTesting();
    Vector<ShapeResultRunData> runs(num_runs);
    for (unsigned i = 0; i < num_runs; i++) {
      ShapeResultRunData& run = runs[i];
      test_info->RunInfoForTesting(i, run.start_index, run.num_characters,
                                   run.num_glyphs, run.script);
    }
    return runs;
  }
};

bool operator==(const ShapeResultRunData& x, const ShapeResultRunData& y) {
  return x.start_index == y.start_index &&
         x.num_characters == y.num_characters && x.num_glyphs == y.num_glyphs &&
         x.script == y.script;
}

void operator<<(std::ostream& output, const ShapeResultRunData& x) {
  output << "{ start_index=" << x.start_index
         << ", num_characters=" << x.num_characters
         << ", num_glyphs=" << x.num_glyphs << ", script=" << x.script << " }";
}

// Create a string of the specified length, filled with |ch|.
String CreateStringOf(UChar ch, unsigned length) {
  UChar* data;
  String string(StringImpl::CreateUninitialized(length, data));
  string.Fill(ch);
  return string;
}

}  // namespace

class HarfBuzzShaperTest : public FontTestBase {
 protected:
  void SetUp() override { font_description.SetComputedSize(12.0); }

  void TearDown() override {}

  void SelectDevanagariFont() {
    // Mac
    scoped_refptr<SharedFontFamily> itf = SharedFontFamily::Create(
        AtomicString("ITF Devanagari"), FontFamily::Type::kFamilyName);
    // Linux
    scoped_refptr<SharedFontFamily> lohit =
        SharedFontFamily::Create(AtomicString("Lohit Devanagari"),
                                 FontFamily::Type::kFamilyName, std::move(itf));
    // Windows 7
    scoped_refptr<SharedFontFamily> mangal = SharedFontFamily::Create(
        AtomicString("Mangal"), FontFamily::Type::kFamilyName,
        std::move(lohit));
    // Windows 10
    font_description.SetFamily(FontFamily(AtomicString("Nirmala UI"),
                                          FontFamily::Type::kFamilyName,
                                          std::move(mangal)));
  }

  Font CreateAhem(float size) {
    FontDescription::VariantLigatures ligatures;
    return blink::test::CreateTestFont(
        AtomicString("Ahem"), blink::test::PlatformTestDataPath("Ahem.woff"),
        size, &ligatures);
  }

  Font CreateNotoColorEmoji(
      FontVariantEmoji variant_emoji = kNormalVariantEmoji) {
    return blink::test::CreateTestFont(
        AtomicString("NotoColorEmoji"),
        blink::test::BlinkWebTestsDir() +
            "/third_party/NotoColorEmoji/NotoColorEmoji.ttf",
        12, nullptr, variant_emoji);
  }

  Font CreateNotoEmoji(FontVariantEmoji variant_emoji = kNormalVariantEmoji) {
    return blink::test::CreateTestFont(
        AtomicString("NotoEmoji"),
        blink::test::BlinkWebTestsDir() +
            "/third_party/NotoEmoji/NotoEmoji-Regular.subset.ttf",
        12, nullptr, variant_emoji);
  }

  // Hardcoded font names created with `CreateNotoEmoji` and
  // `CreateNotoColorEmoji`.
  const char* kNotoEmojiFontName = "Noto Emoji";
  const char* kNotoColorEmojiFontName = "Noto Color Emoji";

#if BUILDFLAG(IS_MAC)
  const char* kSystemColorEmojiFont = "Apple Color Emoji";
#elif BUILDFLAG(IS_ANDROID)
  const char* kSystemColorEmojiFont = "Noto Color Emoji";
#elif BUILDFLAG(IS_WIN)
  const char* kSystemColorEmojiFont = "Segoe UI Emoji";
#endif

#if BUILDFLAG(IS_MAC)
  const char* kSystemMonoEmojiFont = "Apple Symbols";
  const char* kSystemMonoTextDefaultEmojiFont = "Hiragino Mincho ProN";
#elif BUILDFLAG(IS_ANDROID)
  const char* kSystemMonoEmojiFont = "Noto Sans Symbols";
#elif BUILDFLAG(IS_WIN)
  const char* kSystemMonoEmojiFont = "Segoe UI Symbol";
#endif

  String GetShapedFontFamilyNameForEmojiVS(Font& font, String text) {
    DCHECK(text.length() == 1 ||
           (text.length() == 2 &&
            (text.EndsWith(u"\ufe0e") || text.EndsWith(u"\ufe0f"))));
    HeapVector<ShapeResult::RunFontData> run_font_data;
    HarfBuzzShaper shaper(text);
    const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
    result->GetRunFontData(&run_font_data);
    EXPECT_EQ(run_font_data.size(), 1u);
    return run_font_data[0].font_data_->PlatformData().FontFamilyName();
  }

  StringView MaybeStripFontationsSuffix(const String& font_name) {
    wtf_size_t found_index = font_name.ReverseFind(" (Fontations)");
    if (found_index != WTF::kNotFound) {
      return StringView(font_name, 0, found_index);
    } else {
      return font_name;
    }
  }

  const ShapeResult* SplitRun(ShapeResult* shape_result, unsigned offset) {
    unsigned length = shape_result->NumCharacters();
    const ShapeResult* run2 = shape_result->SubRange(offset, length);
    shape_result = shape_result->SubRange(0, offset);
    run2->CopyRange(offset, length, shape_result);
    return shape_result;
  }

  const ShapeResult* CreateMissingRunResult(TextDirection direction) {
    Font font(font_description);
    ShapeResult* result =
        MakeGarbageCollected<ShapeResult>(&font, 2, 8, direction);
    result->InsertRunForTesting(2, 1, direction, {0});
    result->InsertRunForTesting(3, 3, direction, {0, 1});
    // The character index 6 and 7 is missing.
    result->InsertRunForTesting(8, 2, direction, {0});
    return result;
  }

  FontCachePurgePreventer font_cache_purge_preventer;
  FontDescription font_description;
  unsigned start_index_ = 0;
  unsigned num_characters_ = 0;
  unsigned num_glyphs_ = 0;
  hb_script_t script_ = HB_SCRIPT_INVALID;
};

class ScopedSubpixelOverride {
 public:
  explicit ScopedSubpixelOverride(bool b) {
    prev_subpixel_allowed_ =
        WebTestSupport::IsTextSubpixelPositioningAllowedForTest();
    prev_antialias_ = WebTestSupport::IsFontAntialiasingEnabledForTest();
    prev_fd_subpixel_ = FontDescription::SubpixelPositioning();

    if (b) {
      // Allow subpixel positioning.
      WebTestSupport::SetTextSubpixelPositioningAllowedForTest(true);

      // Now, enable subpixel positioning in platform-specific ways.

      // Mac always enables subpixel positioning.

      // On Windows, subpixel positioning also requires antialiasing.
      WebTestSupport::SetFontAntialiasingEnabledForTest(true);

      // On platforms other than Windows and Mac this needs to be set as
      // well.
      FontDescription::SetSubpixelPositioning(true);
    } else {
      // Explicitly disallow all subpixel positioning.
      WebTestSupport::SetTextSubpixelPositioningAllowedForTest(false);
    }
  }
  ~ScopedSubpixelOverride() {
    FontDescription::SetSubpixelPositioning(prev_fd_subpixel_);
    WebTestSupport::SetFontAntialiasingEnabledForTest(prev_antialias_);
    WebTestSupport::SetTextSubpixelPositioningAllowedForTest(
        prev_subpixel_allowed_);

    // Fonts cached with a different subpixel positioning state are not
    // automatically invalidated and need to be cleared between test
    // runs.
    FontCache::Get().Invalidate();
  }

 private:
  bool prev_subpixel_allowed_;
  bool prev_antialias_;
  bool prev_fd_subpixel_;
  // Web test mode (which is enabled by default for unit tests) is required
  // for all WebTestSupport settings to have effects.
  ScopedWebTestMode web_test_mode_{true};
};

class ShapeParameterTest : public HarfBuzzShaperTest,
                           public testing::WithParamInterface<TextDirection> {
 protected:
  const ShapeResult* ShapeWithParameter(HarfBuzzShaper* shaper) {
    Font font(font_description);
    TextDirection direction = GetParam();
    return shaper->Shape(&font, direction);
  }
};

INSTANTIATE_TEST_SUITE_P(HarfBuzzShaperTest,
                         ShapeParameterTest,
                         testing::Values(TextDirection::kLtr,
                                         TextDirection::kRtl));

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsLatin) {
  Font font(font_description);

  String latin_common = To16Bit("ABC DEF.");
  HarfBuzzShaper shaper(latin_common);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  EXPECT_EQ(1u, TestInfo(result)->NumberOfRunsForTesting());
  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(0, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(0u, start_index_);
  EXPECT_EQ(8u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_LATIN, script_);
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsLeadingCommon) {
  Font font(font_description);

  String leading_common = To16Bit("... test");
  HarfBuzzShaper shaper(leading_common);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  EXPECT_EQ(1u, TestInfo(result)->NumberOfRunsForTesting());
  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(0, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(0u, start_index_);
  EXPECT_EQ(8u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_LATIN, script_);
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsUnicodeVariants) {
  Font font(font_description);

  struct {
    const char* name;
    UChar string[4];
    unsigned length;
    hb_script_t script;
  } testlist[] = {
      {"Standard Variants text style", {0x30, 0xFE0E}, 2, HB_SCRIPT_COMMON},
      {"Standard Variants emoji style", {0x203C, 0xFE0F}, 2, HB_SCRIPT_COMMON},
      {"Standard Variants of Ideograph", {0x4FAE, 0xFE00}, 2, HB_SCRIPT_HAN},
      {"Ideographic Variants", {0x3402, 0xDB40, 0xDD00}, 3, HB_SCRIPT_HAN},
      {"Not-defined Variants", {0x41, 0xDB40, 0xDDEF}, 3, HB_SCRIPT_LATIN},
  };
  for (auto& test : testlist) {
    HarfBuzzShaper shaper(test.string);
    const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

    EXPECT_EQ(1u, TestInfo(result)->NumberOfRunsForTesting()) << test.name;
    ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(0, start_index_,
                                                    num_glyphs_, script_))
        << test.name;
    EXPECT_EQ(0u, start_index_) << test.name;
    if (num_glyphs_ == 2) {
      // If the specified VS is not in the font, it's mapped to .notdef.
      // then hb_ot_hide_default_ignorables() swaps it to a space with
      // zero-advance.
      // http://lists.freedesktop.org/archives/harfbuzz/2015-May/004888.html
      EXPECT_EQ(TestInfo(result)->FontDataForTesting(0)->SpaceGlyph(),
                TestInfo(result)->GlyphForTesting(0, 1))
          << test.name;
      EXPECT_EQ(0.f, TestInfo(result)->AdvanceForTesting(0, 1)) << test.name;
    } else {
      EXPECT_EQ(1u, num_glyphs_) << test.name;
    }
    EXPECT_EQ(test.script, script_) << test.name;
  }
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsDevanagariCommon) {
  SelectDevanagariFont();
  Font font(font_description);

  UChar devanagari_common_string[] = {0x915, 0x94d, 0x930, 0x28, 0x20, 0x29};
  String devanagari_common_latin{base::span(devanagari_common_string)};
  HarfBuzzShaper shaper(devanagari_common_latin);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  // Depending on font coverage we cannot assume that all text is in one
  // run, the parenthesis U+0029 may be in a separate font.
  EXPECT_GT(TestInfo(result)->NumberOfRunsForTesting(), 0u);
  EXPECT_LE(TestInfo(result)->NumberOfRunsForTesting(), 2u);

  // Common part of the run must be resolved as Devanagari.
  for (unsigned i = 0; i < TestInfo(result)->NumberOfRunsForTesting(); ++i) {
    ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(i, start_index_,
                                                    num_glyphs_, script_));
    EXPECT_EQ(HB_SCRIPT_DEVANAGARI, script_);
  }
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsDevanagariCommonLatinCommon) {
  SelectDevanagariFont();
  Font font(font_description);

  UChar devanagari_common_latin_string[] = {0x915, 0x94d, 0x930, 0x20,
                                            0x61,  0x62,  0x2E};
  HarfBuzzShaper shaper{String(base::span(devanagari_common_latin_string))};
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  // Ensure that there are only two scripts, Devanagari first, then Latin.
  EXPECT_GT(TestInfo(result)->NumberOfRunsForTesting(), 0u);
  EXPECT_LE(TestInfo(result)->NumberOfRunsForTesting(), 3u);

  bool finished_devanagari = false;
  for (unsigned i = 0; i < TestInfo(result)->NumberOfRunsForTesting(); ++i) {
    ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(i, start_index_,
                                                    num_glyphs_, script_));
    finished_devanagari = finished_devanagari | (script_ == HB_SCRIPT_LATIN);
    EXPECT_EQ(script_,
              finished_devanagari ? HB_SCRIPT_LATIN : HB_SCRIPT_DEVANAGARI);
  }
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsArabicThaiHanLatin) {
  Font font(font_description);

  UChar mixed_string[] = {0x628, 0x64A, 0x629, 0xE20, 0x65E5, 0x62};
  HarfBuzzShaper shaper{String(base::span(mixed_string))};
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);

  EXPECT_EQ(4u, TestInfo(result)->NumberOfRunsForTesting());
  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(0, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(0u, start_index_);
  EXPECT_EQ(3u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_ARABIC, script_);

  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(1, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(3u, start_index_);
  EXPECT_EQ(1u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_THAI, script_);

  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(2, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(4u, start_index_);
  EXPECT_EQ(1u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_HAN, script_);

  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(3, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(5u, start_index_);
  EXPECT_EQ(1u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_LATIN, script_);
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsArabicThaiHanLatinTwice) {
  Font font(font_description);

  UChar mixed_string[] = {0x628, 0x64A, 0x629, 0xE20, 0x65E5, 0x62};
  HarfBuzzShaper shaper{String(base::span(mixed_string))};
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  EXPECT_EQ(4u, TestInfo(result)->NumberOfRunsForTesting());

  // Shape again on the same shape object and check the number of runs.
  // Should be equal if no state was retained between shape calls.
  const ShapeResult* result2 = shaper.Shape(&font, TextDirection::kLtr);
  EXPECT_EQ(4u, TestInfo(result2)->NumberOfRunsForTesting());
}

TEST_F(HarfBuzzShaperTest, ResolveCandidateRunsArabic) {
  Font font(font_description);

  UChar arabic_string[] = {0x628, 0x64A, 0x629};
  HarfBuzzShaper shaper{String(base::span(arabic_string))};
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kRtl);

  EXPECT_EQ(1u, TestInfo(result)->NumberOfRunsForTesting());
  ASSERT_TRUE(TestInfo(result)->RunInfoForTesting(0, start_index_, num_glyphs_,
                                                  script_));
  EXPECT_EQ(0u, start_index_);
  EXPECT_EQ(3u, num_glyphs_);
  EXPECT_EQ(HB_SCRIPT_ARABIC, script_);
}

// This is a simplified test and doesn't accuratly reflect how the shape range
// is to be used. If you instead of the string you imagine the following HTML:
// <div>Hello <span>World</span>!</div>
// It better reflects the intended use where the range given to each shape call
// corresponds to the text content of a TextNode.
TEST_F(HarfBuzzShaperTest, ShapeLatinSegment) {
  Font font(font_description);

  String string(base::span_from_cstring("Hello World!"));
  TextDirection direction = TextDirection::kLtr;

  HarfBuzzShaper shaper(string);
  const ShapeResult* combined = shaper.Shape(&font, direction);
  const ShapeResult* first = shaper.Shape(&font, direction, 0, 6);
  const ShapeResult* second = shaper.Shape(&font, direction, 6, 11);
  const ShapeResult* third = shaper.Shape(&font, direction, 11, 12);

  ASSERT_TRUE(TestInfo(first)->RunInfoForTesting(
      0, start_index_, num_characters_, num_glyphs_, script_));
  EXPECT_EQ(0u, start_index_);
  EXPECT_EQ(6u, num_characters_);
  ASSERT_TRUE(TestInfo(second)->RunInfoForTesting(
      0, start_index_, num_characters_, num_glyphs_, script_));
  EXPECT_EQ(6u, start_index_);
  EXPECT_EQ(5u, num_characters_);
  ASSERT_TRUE(TestInfo(third)->RunInfoForTesting(
      0, start_index_, num_characters_, num_glyphs_, script_));
  EXPECT_EQ(11u, start_index_);
  EXPECT_EQ(1u, num_characters_);

  HarfBuzzShaper shaper2(string.Substring(0, 6));
  const ShapeResult* first_reference = shaper2.Shape(&font, direction);

  HarfBuzzShaper shaper3(string.Substring(6, 5));
  const ShapeResult* second_reference = shaper3.Shape(&font, direction);

  HarfBuzzShaper shaper4(string.Substring(11, 1));
  const ShapeResult* third_reference = shaper4.Shape(&font, direction);

  // Width of each segment should be the same when shaped using start and end
  // offset as it is when shaping the three segments using separate shaper
  // instances.
  // A full pixel is needed for tolerance to account for kerning on some
  // platforms.
  ASSERT_NEAR(first_reference->Width(), first->Width(), 1);
  ASSERT_NEAR(second_reference->Width(), second->Width(), 1);
  ASSERT_NEAR(third_reference->Width(), third->Width(), 1);

  // Width of shape results for the entire string should match the combined
  // shape results from the three segments.
  float total_width = first->Width() + second->Width() + third->Width();
  ASSERT_NEAR(combined->Width(), total_width, 1);
}

// Represents the case where a part of a cluster has a different color.
// <div>0x647<span style="color: red;">0x64A</span></
// Cannot be enabled on Apple yet, compare
// https:// https://github.com/harfbuzz/harfbuzz/issues/1415
#if BUILDFLAG(IS_APPLE)
#define MAYBE_ShapeArabicWithContext DISABLED_ShapeArabicWithContext
#else
#define MAYBE_ShapeArabicWithContext ShapeArabicWithContext
#endif
TEST_F(HarfBuzzShaperTest, MAYBE_ShapeArabicWithContext) {
  Font font(font_description);

  UChar arabic_string[] = {0x647, 0x64A};
  HarfBuzzShaper shaper{String(base::span(arabic_string))};

  const ShapeResult* combined = shaper.Shape(&font, TextDirection::kRtl);

  const ShapeResult* first = shaper.Shape(&font, TextDirection::kRtl, 0, 1);
  const ShapeResult* second = shaper.Shape(&font, TextDirection::kRtl, 1, 2);

  // Combined width should be the same when shaping the two characters
  // separately as when shaping them combined.
  ASSERT_NEAR(combined->Width(), first->Width() + second->Width(), 0.1);
}

TEST_F(HarfBuzzShaperTest, ShapeTabulationCharacters) {
  Font font(font_description);

  const unsigned length = HarfBuzzRunGlyphData::kMaxCharacters * 2 + 1;
  const ShapeResult* result = ShapeResult::CreateForTabulationCharacters(
      &font, TextDirection::kLtr, TabSize(8), 0.f, 0, length);
  EXPECT_EQ(result->NumCharacters(), length);
  EXPECT_EQ(result->NumGlyphs(), length);
}

TEST_F(HarfBuzzShaperTest, ShapeVerticalUpright) {
  font_description.SetOrientation(FontOrientation::kVerticalUpright);
  Font font(font_description);

  // This string should create 2 runs, ideographic and Latin, both in upright.
  String string(u"\u65E5\u65E5\u65E5lllll");
  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Shape each run and merge them using CopyRange. Width() should match.
  const ShapeResult* result1 = shaper.Shape(&font, direction, 0, 3);
  const ShapeResult* result2 =
      shaper.Shape(&font, direction, 3, string.length());

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, 3, composite_result);
  result2->CopyRange(3, string.length(), composite_result);

  EXPECT_EQ(result->Width(), composite_result->Width());
}

TEST_F(HarfBuzzShaperTest, ShapeVerticalUprightIdeograph) {
  font_description.SetOrientation(FontOrientation::kVerticalUpright);
  Font font(font_description);

  // This string should create one ideograph run.
  String string(u"\u65E5\u65E6\u65E0\u65D3\u65D0");
  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Shape each run and merge them using CopyRange. Width() should match.
  const ShapeResult* result1 = shaper.Shape(&font, direction, 0, 3);
  const ShapeResult* result2 =
      shaper.Shape(&font, direction, 3, string.length());

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, 3, composite_result);
  result2->CopyRange(3, string.length(), composite_result);

  // Rounding of x and width may be off by ~0.1 on Mac.
  float tolerance = 0.1f;
  EXPECT_NEAR(result->Width(), composite_result->Width(), tolerance);
}

TEST_F(HarfBuzzShaperTest, RangeShapeSmallCaps) {
  // Test passes if no assertion is hit of the ones below, but also the newly
  // introduced one in HarfBuzzShaper::ShapeSegment: DCHECK_GT(shape_end,
  // shape_start) is not hit.
  font_description.SetVariantCaps(FontDescription::kSmallCaps);
  font_description.SetComputedSize(12.0);
  Font font(font_description);

  // Shaping index 2 to 3 means that case splitting for small caps splits before
  // character index 2 since the initial 'a' needs to be uppercased, but the
  // space character does not need to be uppercased. This triggered
  // crbug.com/817271.
  String string(u"a aa");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr, 2, 3);
  EXPECT_EQ(1u, result->NumCharacters());

  string = u"aa a";
  HarfBuzzShaper shaper_two(string);
  result = shaper_two.Shape(&font, TextDirection::kLtr, 3, 4);
  EXPECT_EQ(1u, result->NumCharacters());

  string = u"a aa";
  HarfBuzzShaper shaper_three(string);
  result = shaper_three.Shape(&font, TextDirection::kLtr, 1, 2);
  EXPECT_EQ(1u, result->NumCharacters());

  string = u"aa aa aa aa aa aa aa aa aa aa";
  HarfBuzzShaper shaper_four(string);
  result = shaper_four.Shape(&font, TextDirection::kLtr, 21, 23);
  EXPECT_EQ(2u, result->NumCharacters());

  string = u"aa aa aa aa aa aa aa aa aa aa";
  HarfBuzzShaper shaper_five(string);
  result = shaper_five.Shape(&font, TextDirection::kLtr, 27, 29);
  EXPECT_EQ(2u, result->NumCharacters());
}

TEST_F(HarfBuzzShaperTest, ShapeVerticalMixed) {
  font_description.SetOrientation(FontOrientation::kVerticalMixed);
  Font font(font_description);

  // This string should create 2 runs, ideographic in upright and Latin in
  // rotated horizontal.
  String string(u"\u65E5\u65E5\u65E5lllll");
  TextDirection direction = TextDirection::kLtr;
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, direction);

  // Shape each run and merge them using CopyRange. Width() should match.
  const ShapeResult* result1 = shaper.Shape(&font, direction, 0, 3);
  const ShapeResult* result2 =
      shaper.Shape(&font, direction, 3, string.length());

  ShapeResult* composite_result =
      MakeGarbageCollected<ShapeResult>(&font, 0, 0, direction);
  result1->CopyRange(0, 3, composite_result);
  result2->CopyRange(3, string.length(), composite_result);

  EXPECT_EQ(result->Width(), composite_result->Width());
}

class ShapeStringTest : public HarfBuzzShaperTest,
                        public testing::WithParamInterface<const char16_t*> {};

INSTANTIATE_TEST_SUITE_P(HarfBuzzShaperTest,
                         ShapeStringTest,
                         testing::Values(
                             // U+FFF0 is not assigned as of Unicode 10.0.
                             u"\uFFF0",
                             u"\uFFF0Hello",
                             // U+00AD SOFT HYPHEN often does not have glyphs.
                             u"\u00AD"));

TEST_P(ShapeStringTest, MissingGlyph) {
  Font font(font_description);

  String string(GetParam());
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  EXPECT_EQ(0u, result->StartIndex());
  EXPECT_EQ(string.length(), result->EndIndex());
}

// Test splitting runs by kMaxCharacterIndex using a simple string that has code
// point:glyph:cluster are all 1:1.
TEST_P(ShapeParameterTest, MaxGlyphsSimple) {
  const unsigned length = HarfBuzzRunGlyphData::kMaxCharacters + 1;
  String string = CreateStringOf('X', length);
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = ShapeWithParameter(&shaper);
  EXPECT_EQ(length, result->NumCharacters());
  EXPECT_EQ(length, result->NumGlyphs());
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);
  EXPECT_THAT(
      runs,
      IsLtr(GetParam())
          ? testing::ElementsAre(
                ShapeResultRunData{0, length - 1, length - 1, HB_SCRIPT_LATIN},
                ShapeResultRunData{length - 1, 1, 1, HB_SCRIPT_LATIN})
          : testing::ElementsAre(
                ShapeResultRunData{1, length - 1, length - 1, HB_SCRIPT_LATIN},
                ShapeResultRunData{0, 1, 1, HB_SCRIPT_LATIN}));
}

// 'X' + U+0300 COMBINING GRAVE ACCENT is a cluster, but most fonts do not have
// a pre-composed glyph for it, so code points and glyphs are 1:1. Because the
// length is "+1" and the last character is combining, this string does not hit
// kMaxCharacterIndex but hits kMaxCharacters.
TEST_P(ShapeParameterTest, MaxGlyphsClusterLatin) {
  const unsigned length = HarfBuzzRunGlyphData::kMaxCharacters + 1;
  String string = CreateStringOf('X', length);
  string.replace(1, 1, u"\u0300");  // U+0300 COMBINING GRAVE ACCENT
  string.replace(length - 2, 2, u"Z\u0300");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = ShapeWithParameter(&shaper);
  EXPECT_EQ(length, result->NumCharacters());
  EXPECT_EQ(length, result->NumGlyphs());
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);
  EXPECT_THAT(
      runs,
      IsLtr(GetParam())
          ? testing::ElementsAre(
                ShapeResultRunData{0, length - 2, length - 2, HB_SCRIPT_LATIN},
                ShapeResultRunData{length - 2, 2u, 2u, HB_SCRIPT_LATIN})
          : testing::ElementsAre(
                ShapeResultRunData{2, length - 2, length - 2, HB_SCRIPT_LATIN},
                ShapeResultRunData{0, 2, 2, HB_SCRIPT_LATIN}));
}

// Same as MaxGlyphsClusterLatin, but by making the length "+2", this string
// hits kMaxCharacterIndex.
TEST_P(ShapeParameterTest, MaxGlyphsClusterLatin2) {
  const unsigned length = HarfBuzzRunGlyphData::kMaxCharacters + 2;
  String string = CreateStringOf('X', length);
  string.replace(1, 1, u"\u0300");  // U+0300 COMBINING GRAVE ACCENT
  string.replace(length - 2, 2, u"Z\u0300");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = ShapeWithParameter(&shaper);
  EXPECT_EQ(length, result->NumCharacters());
  EXPECT_EQ(length, result->NumGlyphs());
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);
  EXPECT_THAT(
      runs,
      IsLtr(GetParam())
          ? testing::ElementsAre(
                ShapeResultRunData{0, length - 2, length - 2, HB_SCRIPT_LATIN},
                ShapeResultRunData{length - 2, 2u, 2u, HB_SCRIPT_LATIN})
          : testing::ElementsAre(
                ShapeResultRunData{2, length - 2, length - 2, HB_SCRIPT_LATIN},
                ShapeResultRunData{0, 2u, 2u, HB_SCRIPT_LATIN}));
}

TEST_P(ShapeParameterTest, MaxGlyphsClusterDevanagari) {
  const unsigned length = HarfBuzzRunGlyphData::kMaxCharacters + 1;
  String string = CreateStringOf(0x930, length);
  string.replace(0, 3, u"\u0930\u093F\u0902");
  string.replace(length - 3, 3, u"\u0930\u093F\u0902");
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = ShapeWithParameter(&shaper);
  EXPECT_EQ(length, result->NumCharacters());
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_FUCHSIA)
  // Linux and Fuchsia use Lohit Devanagari. When using that font the shaper
  // returns 32767 glyphs instead of 32769.
  // TODO(crbug.com/933551): Add Noto Sans Devanagari to
  // //third_party/test_fonts and use it here.
  if (result->NumGlyphs() != length)
    return;
#endif
  EXPECT_EQ(length, result->NumGlyphs());
  Vector<ShapeResultRunData> runs = ShapeResultRunData::Get(result);
  EXPECT_THAT(
      runs,
      IsLtr(GetParam())
          ? testing::ElementsAre(
                ShapeResultRunData{0, length - 3, length - 3,
                                   HB_SCRIPT_DEVANAGARI},
                ShapeResultRunData{length - 3, 3u, 3u, HB_SCRIPT_DEVANAGARI})
          : testing::ElementsAre(
                ShapeResultRunData{3, length - 3, length - 3,
                                   HB_SCRIPT_DEVANAGARI},
                ShapeResultRunData{0, 3u, 3u, HB_SCRIPT_DEVANAGARI}));
}

TEST_P(ShapeParameterTest, ZeroWidthSpace) {
  UChar string[] = {kZeroWidthSpaceCharacter,
                    kZeroWidthSpaceCharacter,
                    0x0627,
                    0x0631,
                    0x062F,
                    0x0648,
                    kZeroWidthSpaceCharacter,
                    kZeroWidthSpaceCharacter};
  HarfBuzzShaper shaper{String(base::span(string))};
  const ShapeResult* result = ShapeWithParameter(&shaper);
  EXPECT_EQ(0u, result->StartIndex());
  EXPECT_EQ(std::size(string), result->EndIndex());
#if DCHECK_IS_ON()
  result->CheckConsistency();
#endif
}

TEST_F(HarfBuzzShaperTest, IdeographicSpace) {
  Font font(font_description);

  String string(
      u"\u3001"    // IDEOGRAPHIC COMMA
      u"\u3000");  // IDEOGRAPHIC SPACE
  HarfBuzzShaper shaper(string);
  const ShapeResult* result = shaper.Shape(&font, TextDirection::kLtr);
  HeapVector<ShapeResult::RunFontData> run_font_data;
  result->GetRunFontData(&run_font_data);
  EXPECT_EQ(run_font_data.size(), 1u);
}

#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
TEST_F(HarfBuzzShaperTest, SystemEmojiVS15) {
  ScopedFontVariationSequencesForTest scoped_feature_vs(true);
  ScopedSystemFallbackEmojiVSSupportForTest scoped_feature_system_emoji_vs(
      true);

  Font mono_font = CreateNotoEmoji()
"""


```