Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of `font_description_test.cc`, its relation to web technologies (JS/HTML/CSS), logic analysis with input/output examples, and common usage errors.

2. **Identify the Core Subject:** The file name immediately tells us it's testing `FontDescription`. This class likely holds information about font properties (size, weight, family, etc.).

3. **Recognize the Test Framework:**  The presence of `TEST_F` and the inheritance from `FontTestBase` strongly suggest a testing framework (likely Google Test, which is common in Chromium). This means the file's primary function is to *verify the behavior* of the `FontDescription` class.

4. **Scan the Includes:** The `#include` directives provide valuable clues:
    * `"third_party/blink/renderer/platform/fonts/font_description.h"`: Confirms we're testing the `FontDescription` class itself.
    * `"third_party/blink/renderer/platform/testing/font_test_base.h"`: Reinforces the testing aspect and might offer common test utilities.
    * `"third_party/blink/renderer/platform/wtf/hash_map.h"` and `"third_party/blink/renderer/platform/wtf/vector.h"`:  Indicates that `FontDescription` likely involves hash maps and vectors internally, which is relevant for caching and managing font variations.

5. **Analyze Individual Tests (The Heart of the Functionality):**  Go through each `TEST_F` function and decipher its purpose:

    * **`TestHashCollision`:**  This test explicitly checks for hash collisions among different combinations of font weight, stretch, and slope. The goal is to ensure the hashing algorithm used for `FontDescription` properties is robust and avoids accidental collisions that could lead to incorrect font matching.

    * **`VariationSettingsIdenticalCacheKey` and `VariationSettingsDifferentCacheKey`:** These tests focus on how font variation settings (like specific glyph variations) affect the cache key of a `FontDescription`. They verify that identical settings produce the same key and different settings produce different keys, which is crucial for efficient font caching.

    * **`PaletteDifferentCacheKey`:**  Similar to variation settings, this checks how different font palettes (color schemes within a font) impact the cache key.

    * **`VariantAlternatesDifferentCacheKey` and `VariantEmojiDifferentCacheKey`:** These tests follow the same pattern, ensuring that different font variant alternates (e.g., historical forms) and emoji variations result in distinct cache keys.

    * **`AllFeaturesHash`:** This is a comprehensive test. It systematically changes each relevant property of a `FontDescription` and verifies that each change results in a different hash value. This ensures that the hash function considers all relevant font properties. It also checks that subsequent calls with the same properties yield the same hash (stability).

    * **`FontFamiliesHash`:**  This specifically tests how different font family lists (including fallbacks) affect the hash.

    * **`GenericFamilyDifferentHash`:** This addresses a specific bug/edge case where a generic family name (like "serif") and a literal family name ("serif") should be treated distinctly.

    * **`ToString`:** This verifies the `ToString()` method of `FontDescription`, ensuring it produces a human-readable representation of the font's properties.

    * **`DefaultHashTrait`:**  This test verifies that `FontDescription` can be used as a key in a `HashMap` correctly, meaning its default hashing and equality comparison work as expected.

    * **`NegativeZeroEmFontSize`:**  This tests a specific edge case with negative zero in font sizes, ensuring that `-0.0em` and `0.0em` are treated as equivalent.

6. **Relate to Web Technologies (JS/HTML/CSS):**  Think about how these font properties are exposed in web development:

    * **CSS:**  Many of the properties being tested directly correspond to CSS properties: `font-family`, `font-size`, `font-weight`, `font-style`, `font-stretch`, `font-variant`, `font-feature-settings`, `font-variation-settings`, etc.

    * **JavaScript:** While JS doesn't directly manipulate `FontDescription` objects, it interacts with the rendering engine. Changes to CSS styles via JS will eventually lead to the creation or modification of `FontDescription` objects internally. The Canvas API and related font metrics methods also rely on the underlying font handling.

    * **HTML:** HTML provides the structure, and the styling applied via CSS (either inline or in stylesheets) dictates the font properties, ultimately influencing the `FontDescription`.

7. **Provide Examples (Input/Output):**  For logic-based tests (like the cache key tests), think about concrete scenarios:

    * **Identical Variation Settings:** Two CSS rules with the same `font-variation-settings` should result in the same cache key.
    * **Different Variation Settings:** Two CSS rules with different `font-variation-settings` should have different cache keys.

8. **Identify Potential User/Programming Errors:**  Consider common mistakes developers might make:

    * **Misspelling font family names:**  This would lead to a different `FontDescription` and potentially a fallback font being used.
    * **Incorrectly specifying `font-variation-settings`:**  Typos or incorrect axis values would lead to different font renderings.
    * **Not understanding the impact of font variants:**  Developers might not realize the subtle differences between various font variants and how they affect rendering.

9. **Structure the Answer:** Organize the findings logically:

    * Start with a high-level summary of the file's purpose.
    * List the specific functionalities tested, drawing from the individual test cases.
    * Explain the connections to web technologies with concrete examples.
    * Provide input/output examples for clarity.
    * Highlight common user/programming errors related to font specifications.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Make sure the examples are easy to understand and the explanations are concise. For instance, initially, I might just say "tests font properties," but refining it to "tests various properties of the `FontDescription` class, such as font family, size, weight, style, stretch, and advanced typographic features" is more informative.这是目录为 `blink/renderer/platform/fonts/font_description_test.cc` 的 Chromium Blink 引擎源代码文件。根据文件名和文件内容，我们可以分析出它的功能以及与 JavaScript, HTML, CSS 的关系。

**文件功能:**

该文件是一个 C++ 单元测试文件，用于测试 `blink::FontDescription` 类的功能。`FontDescription` 类在 Blink 渲染引擎中用于描述字体属性，例如字体族、大小、粗细、样式、拉伸、变体等等。

具体来说，该文件中的测试用例主要验证了以下 `FontDescription` 类的行为：

1. **哈希值 (Hash) 的计算:**
   - `TestHashCollision`:  验证在不同的字体属性组合下，`StyleHashWithoutFamilyList()` 方法生成的哈希值是否会发生冲突。这对于高效地存储和查找字体描述信息至关重要，例如在字体缓存中。
   - `AllFeaturesHash`: 详细测试了修改 `FontDescription` 对象的各种属性（例如大小、粗细、样式、拉伸、变体、字距、词距等）后，`GetHash()` 方法返回的哈希值是否会发生变化，并且对于相同的属性值是否返回相同的哈希值。这保证了哈希的稳定性，用于判断两个 `FontDescription` 对象是否相等。
   - `FontFamiliesHash`: 测试了字体族列表的不同（包括顺序、名称等）对哈希值的影响。
   - `GenericFamilyDifferentHash`:  验证了通用字体族名称（例如 `serif`）和具体的字体族名称（例如 `"serif"`) 在哈希计算中被区分对待。

2. **缓存键 (Cache Key) 的生成:**
   - `VariationSettingsIdenticalCacheKey` 和 `VariationSettingsDifferentCacheKey`: 测试了字体变体设置 (`FontVariationSettings`) 对缓存键的影响。如果两个 `FontDescription` 对象的变体设置相同，它们的缓存键也应该相同；反之则不同。
   - `PaletteDifferentCacheKey`: 测试了字体调色板 (`FontPalette`) 对缓存键的影响。不同的调色板应该生成不同的缓存键。
   - `VariantAlternatesDifferentCacheKey`: 测试了字体变体交替 (`FontVariantAlternates`) 设置对缓存键的影响。不同的交替设置应生成不同的缓存键。
   - `VariantEmojiDifferentCacheKey`: 测试了 Emoji 变体 (`FontVariantEmoji`) 设置对缓存键的影响。不同的 Emoji 变体应生成不同的缓存键。

3. **对象的相等性比较:**
   - 上述涉及到缓存键的测试也隐含地测试了 `FontDescription` 对象的相等性比较操作符 (`==`)。

4. **`ToString()` 方法:**
   - `ToString`: 测试了 `ToString()` 方法是否能够正确地将 `FontDescription` 对象的所有属性以字符串的形式输出，方便调试和日志记录。

5. **作为哈希表键的使用:**
   - `DefaultHashTrait`:  验证了 `FontDescription` 类可以作为 `HashMap` 的键使用，这意味着它的默认哈希和相等性比较特性是正确的。

6. **特定边界情况的处理:**
   - `NegativeZeroEmFontSize`: 测试了当 `font-size` 设置为 `-0.0em` 时，`FontDescription` 对象是否与 `0.0em` 的情况相等，以及它们的哈希值是否相同。这处理了 CSS 中可能出现的边界情况。

**与 JavaScript, HTML, CSS 的关系:**

`FontDescription` 类是 Blink 渲染引擎处理字体样式的基础。用户通过 HTML 和 CSS 定义的字体样式，最终会被解析并转换成 `FontDescription` 对象，供渲染引擎使用。JavaScript 可以动态修改元素的 CSS 样式，从而间接地影响 `FontDescription` 对象。

**举例说明:**

1. **CSS `font-family` 属性:**
   - **假设输入 (CSS):**
     ```css
     .my-text {
       font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
     }
     ```
   - **内部处理 (C++ `FontDescription`):**  Blink 渲染引擎会解析这段 CSS，创建一个 `FontDescription` 对象，其字体族列表会包含 "Helvetica Neue"、"Helvetica"、"Arial" 和 "sans-serif" (作为通用字体族)。`FontFamiliesHash` 测试就是为了验证这种字体族列表在哈希计算中的行为。

2. **CSS `font-weight` 和 `font-style` 属性:**
   - **假设输入 (CSS):**
     ```css
     .bold-italic {
       font-weight: bold;
       font-style: italic;
     }
     ```
   - **内部处理 (C++ `FontDescription`):**  对应的 `FontDescription` 对象会设置相应的 `weight` 和 `style` 属性。`TestHashCollision` 和 `AllFeaturesHash` 测试确保了不同的 `weight` 和 `style` 组合会产生不同的哈希值。

3. **CSS `font-variation-settings` 属性:**
   - **假设输入 (CSS):**
     ```css
     .variable-font {
       font-family: "MyVariableFont";
       font-variation-settings: "wght" 500, "slnt" -10;
     }
     ```
   - **内部处理 (C++ `FontDescription`):**  `FontVariationSettings` 对象会被创建并添加到 `FontDescription` 中，包含 "wght" 轴的值 500 和 "slnt" 轴的值 -10。 `VariationSettingsIdenticalCacheKey` 和 `VariationSettingsDifferentCacheKey` 测试保证了具有相同或不同 `font-variation-settings` 的 `FontDescription` 对象会产生相同或不同的缓存键。

4. **JavaScript 动态修改 CSS:**
   - **假设输入 (JavaScript):**
     ```javascript
     const element = document.querySelector('.my-text');
     element.style.fontSize = '16px';
     ```
   - **内部处理 (C++ `FontDescription`):**  当 JavaScript 修改元素的 `font-size` 属性后，渲染引擎会更新与该元素关联的 `FontDescription` 对象，其 `specified_size` 属性会被设置为 16.0。`AllFeaturesHash` 测试确保了 `specified_size` 的变化会影响 `GetHash()` 的结果。

**逻辑推理的假设输入与输出:**

* **假设输入:** 两个 `FontDescription` 对象 `a` 和 `b`，它们的字体族列表相同，但字体大小不同。
* **输出:**  `a.GetHash()` 的值应该不等于 `b.GetHash()` 的值。 这是由 `AllFeaturesHash` 测试覆盖的逻辑。

* **假设输入:** 两个 `FontDescription` 对象 `a` 和 `b`，它们的 `font-variation-settings` 属性相同。
* **输出:** `a.CacheKey(...)` 应该等于 `b.CacheKey(...)`。 这是 `VariationSettingsIdenticalCacheKey` 测试覆盖的逻辑。

**用户或编程常见的使用错误:**

1. **拼写错误的字体族名称:**
   - **错误示例 (CSS):** `font-family: Helvetca;` (正确的拼写是 Helvetica)
   - **后果:** 渲染引擎无法找到名为 "Helvetca" 的字体，可能会使用后备字体或者默认字体。这会导致实际渲染的字体与用户的预期不符。

2. **不理解 `font-variation-settings` 的语法:**
   - **错误示例 (CSS):** `font-variation-settings: wght=500, slnt=-10;` (正确的语法是使用引号)
   - **后果:** 浏览器可能无法正确解析 `font-variation-settings` 属性，导致可变字体没有按照预期进行调整。`VariationSettingsDifferentCacheKey` 的测试间接提醒开发者，错误的语法可能导致与预期不同的字体渲染。

3. **过度依赖通用字体族:**
   - **错误示例 (CSS):** `font-family: sans-serif;`
   - **后果:** 在不同的操作系统和浏览器上，`sans-serif` 通用字体族可能对应不同的实际字体，导致在不同平台上显示效果不一致。

4. **在 JavaScript 中修改字体样式时出现类型错误:**
   - **错误示例 (JavaScript):** `element.style.fontSize = 16;` (应该使用字符串 "16px")
   - **后果:** 浏览器可能无法正确解析该值，导致字体大小没有生效。

5. **没有考虑字体加载的异步性:**
   - **错误示例 (JavaScript):**  在字体完全加载之前就尝试获取元素的字体相关信息。
   - **后果:** 可能获取到错误的字体信息，因为字体还没有完全加载和应用。

总而言之，`font_description_test.cc` 文件是 Blink 引擎中保证字体描述功能正确性的重要组成部分。它通过各种测试用例，验证了 `FontDescription` 类的核心功能，并间接地关联到 Web 开发中使用的 HTML、CSS 和 JavaScript 相关的字体样式设置。 理解这些测试用例可以帮助开发者更好地理解浏览器内部如何处理字体，并避免常见的字体使用错误。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/font_description_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/font_description.h"

#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class FontDescriptionTest : public FontTestBase {};

TEST_F(FontDescriptionTest, TestHashCollision) {
  FontSelectionValue weights[] = {
      FontSelectionValue(100), FontSelectionValue(200),
      FontSelectionValue(300), FontSelectionValue(400),
      FontSelectionValue(500), FontSelectionValue(600),
      FontSelectionValue(700), FontSelectionValue(800),
      FontSelectionValue(900)};
  FontSelectionValue stretches[]{
      kUltraCondensedWidthValue, kExtraCondensedWidthValue,
      kCondensedWidthValue,      kSemiCondensedWidthValue,
      kNormalWidthValue,         kSemiExpandedWidthValue,
      kExpandedWidthValue,       kExtraExpandedWidthValue,
      kUltraExpandedWidthValue};

  FontSelectionValue slopes[] = {kNormalSlopeValue, kItalicSlopeValue};

  FontDescription source;
  WTF::Vector<unsigned> hashes;
  for (size_t i = 0; i < std::size(weights); i++) {
    source.SetWeight(weights[i]);
    for (size_t j = 0; j < std::size(stretches); j++) {
      source.SetStretch(stretches[j]);
      for (size_t k = 0; k < std::size(slopes); k++) {
        source.SetStyle(slopes[k]);
        unsigned hash = source.StyleHashWithoutFamilyList();
        ASSERT_FALSE(hashes.Contains(hash));
        hashes.push_back(hash);
      }
    }
  }
}

TEST_F(FontDescriptionTest, VariationSettingsIdenticalCacheKey) {
  FontDescription a;
  FontDescription b(a);

  scoped_refptr<FontVariationSettings> settings_a =
      FontVariationSettings::Create();
  settings_a->Append(FontVariationAxis(AtomicString("test"), 1));

  scoped_refptr<FontVariationSettings> settings_b =
      FontVariationSettings::Create();
  settings_b->Append(FontVariationAxis(AtomicString("test"), 1));

  ASSERT_EQ(*settings_a, *settings_b);

  a.SetVariationSettings(settings_a);
  b.SetVariationSettings(settings_b);

  ASSERT_EQ(a, b);

  FontFaceCreationParams test_creation_params;
  FontCacheKey cache_key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey cache_key_b = b.CacheKey(test_creation_params, false);

  ASSERT_EQ(cache_key_a, cache_key_b);
}

TEST_F(FontDescriptionTest, VariationSettingsDifferentCacheKey) {
  FontDescription a;
  FontDescription b(a);

  scoped_refptr<FontVariationSettings> settings_a =
      FontVariationSettings::Create();
  settings_a->Append(FontVariationAxis(AtomicString("test"), 1));

  scoped_refptr<FontVariationSettings> settings_b =
      FontVariationSettings::Create();
  settings_b->Append(FontVariationAxis(AtomicString("0000"), 1));

  ASSERT_NE(*settings_a, *settings_b);

  a.SetVariationSettings(settings_a);
  b.SetVariationSettings(settings_b);

  ASSERT_NE(a, b);

  FontFaceCreationParams test_creation_params;

  FontCacheKey cache_key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey cache_key_b = b.CacheKey(test_creation_params, false);

  ASSERT_NE(cache_key_a, cache_key_b);

  scoped_refptr<FontVariationSettings> second_settings_a =
      FontVariationSettings::Create();
  second_settings_a->Append(FontVariationAxis(AtomicString("test"), 1));

  scoped_refptr<FontVariationSettings> second_settings_b =
      FontVariationSettings::Create();

  ASSERT_NE(*second_settings_a, *second_settings_b);

  a.SetVariationSettings(second_settings_a);
  b.SetVariationSettings(second_settings_b);

  ASSERT_NE(a, b);

  FontCacheKey second_cache_key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey second_cache_key_b = b.CacheKey(test_creation_params, false);

  ASSERT_NE(second_cache_key_a, second_cache_key_b);
}

TEST_F(FontDescriptionTest, PaletteDifferentCacheKey) {
  FontDescription a;
  FontDescription b(a);

  scoped_refptr<FontPalette> palette_a =
      FontPalette::Create(FontPalette::kLightPalette);

  scoped_refptr<FontPalette> palette_b =
      FontPalette::Create(FontPalette::kDarkPalette);

  ASSERT_NE(*palette_a, *palette_b);

  a.SetFontPalette(palette_a);
  b.SetFontPalette(palette_b);

  ASSERT_NE(a, b);

  FontFaceCreationParams test_creation_params;

  FontCacheKey cache_key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey cache_key_b = b.CacheKey(test_creation_params, false);

  ASSERT_NE(cache_key_a, cache_key_b);
}

TEST_F(FontDescriptionTest, VariantAlternatesDifferentCacheKey) {
  FontDescription a;
  FontDescription b(a);

  scoped_refptr<FontVariantAlternates> variants_a =
      FontVariantAlternates::Create();
  variants_a->SetHistoricalForms();

  scoped_refptr<FontVariantAlternates> variants_b =
      FontVariantAlternates::Create();
  variants_b->SetStyleset({AtomicString("foo"), AtomicString("bar")});

  ASSERT_NE(*variants_a, *variants_b);
  ASSERT_EQ(*variants_a, *variants_a);
  a.SetFontVariantAlternates(variants_a);
  b.SetFontVariantAlternates(variants_b);

  ASSERT_NE(a, b);

  FontFaceCreationParams test_creation_params;
  FontCacheKey key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey key_b = b.CacheKey(test_creation_params, false);

  ASSERT_NE(key_a, key_b);
}

TEST_F(FontDescriptionTest, VariantEmojiDifferentCacheKey) {
  FontDescription a;
  FontDescription b(a);

  FontVariantEmoji variant_emoji_a = kEmojiVariantEmoji;
  FontVariantEmoji variant_emoji_b = kUnicodeVariantEmoji;

  a.SetVariantEmoji(variant_emoji_a);
  b.SetVariantEmoji(variant_emoji_b);

  ASSERT_NE(a, b);

  FontFaceCreationParams test_creation_params;
  FontCacheKey key_a = a.CacheKey(test_creation_params, false);
  FontCacheKey key_b = b.CacheKey(test_creation_params, false);

  ASSERT_NE(key_a, key_b);
}

TEST_F(FontDescriptionTest, AllFeaturesHash) {
  FontDescription font_description;
  font_description.SetFamily(
      FontFamily(font_family_names::kSerif, FontFamily::Type::kGenericFamily));
  unsigned key_a = font_description.GetHash();

  // Test every relevant property except font families, which are tested in
  // CompositeKeyFontFamilies. Check that the key is different from
  // a description without the property change and that it is the same upon
  // re-query (i.e. that the key is stable).
  font_description.SetComputedSize(15.0);
  unsigned key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetSpecifiedSize(16.0);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetAdjustedSize(17.0);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontSizeAdjust font_size_adjust(1.2, FontSizeAdjust::Metric::kCapHeight);
  font_description.SetSizeAdjust(font_size_adjust);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontSelectionValue font_selection_value(8);
  font_description.SetStyle(font_selection_value);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontSelectionValue font_selection_value_weight(1);
  font_description.SetWeight(font_selection_value_weight);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontSelectionValue font_selection_value_stretch(1.2f);
  font_description.SetStretch(font_selection_value_stretch);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetVariantCaps(FontDescription::kPetiteCaps);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontVariantEastAsian font_variant_east_asian =
      FontVariantEastAsian::InitializeFromUnsigned(57u);
  font_description.SetVariantEastAsian(font_variant_east_asian);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontDescription::VariantLigatures variant_ligatures(
      FontDescription::kEnabledLigaturesState);
  font_description.SetVariantLigatures(variant_ligatures);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  FontVariantNumeric font_variant_numeric =
      FontVariantNumeric::InitializeFromUnsigned(171u);
  font_description.SetVariantNumeric(font_variant_numeric);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetIsAbsoluteSize(true);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetGenericFamily(FontDescription::kSerifFamily);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetKerning(FontDescription::kNormalKerning);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetKeywordSize(5);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetFontSmoothing(kAntialiased);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetFontOpticalSizing(kNoneOpticalSizing);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetTextRendering(kOptimizeLegibility);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetOrientation(FontOrientation::kVerticalMixed);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetWidthVariant(kHalfWidth);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetLocale(&LayoutLocale::GetSystem());
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetSyntheticBold(true);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetSyntheticItalic(true);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetFontSynthesisWeight(
      FontDescription::kNoneFontSynthesisWeight);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetFontSynthesisStyle(
      FontDescription::kNoneFontSynthesisStyle);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetFontSynthesisSmallCaps(
      FontDescription::kNoneFontSynthesisSmallCaps);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  scoped_refptr<FontFeatureSettings> font_feature_setting =
      FontFeatureSettings::Create();
  font_feature_setting->Append(FontFeature(AtomicString("1234"), 2));
  font_description.SetFeatureSettings(font_feature_setting);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  scoped_refptr<FontVariationSettings> font_variation_setting =
      FontVariationSettings::Create();
  font_variation_setting->Append(FontVariationAxis(AtomicString("1234"), 1.5f));
  font_description.SetVariationSettings(font_variation_setting);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetVariantPosition(FontDescription::kSubVariantPosition);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetWordSpacing(1.2);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetLetterSpacing(0.9);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  font_description.SetSubpixelAscentDescent(true);
  key_b = font_description.GetHash();
  EXPECT_NE(key_a, key_b);
  key_a = font_description.GetHash();
  EXPECT_EQ(key_a, key_b);

  // HashCategory does not matter for the key
  // FontVariantAlternates is not used in the key
}

TEST_F(FontDescriptionTest, FontFamiliesHash) {
  // One family in both descriptors
  FontDescription a;
  FontDescription b(a);

  a.SetFamily(
      FontFamily(font_family_names::kSerif, FontFamily::Type::kGenericFamily));
  b.SetFamily(
      FontFamily(font_family_names::kSerif, FontFamily::Type::kGenericFamily));

  unsigned key_a = a.GetHash();
  unsigned key_b = b.GetHash();

  EXPECT_EQ(key_a, key_b);

  // Differing family lists
  scoped_refptr<SharedFontFamily> next_family_a = SharedFontFamily::Create(
      AtomicString("CustomFont1"), FontFamily::Type::kFamilyName);
  a.SetFamily(FontFamily(font_family_names::kSerif,
                         FontFamily::Type::kGenericFamily, next_family_a));
  key_a = a.GetHash();
  EXPECT_NE(key_a, key_b);

  // Same family lists with multiple entries
  scoped_refptr<SharedFontFamily> next_family_b = SharedFontFamily::Create(
      AtomicString("CustomFont1"), FontFamily::Type::kFamilyName);
  b.SetFamily(FontFamily(font_family_names::kSerif,
                         FontFamily::Type::kGenericFamily, next_family_b));
  key_b = b.GetHash();
  EXPECT_EQ(key_a, key_b);

  // Same number of entries, different names
  next_family_a = SharedFontFamily::Create(AtomicString("CustomFont1a"),
                                           FontFamily::Type::kFamilyName);
  a.SetFamily(FontFamily(font_family_names::kSerif,
                         FontFamily::Type::kGenericFamily, next_family_a));
  key_a = a.GetHash();
  next_family_b = SharedFontFamily::Create(AtomicString("CustomFont1b"),
                                           FontFamily::Type::kFamilyName);
  b.SetFamily(FontFamily(font_family_names::kSerif,
                         FontFamily::Type::kGenericFamily, next_family_b));
  key_b = b.GetHash();
  EXPECT_NE(key_a, key_b);
}

TEST_F(FontDescriptionTest, GenericFamilyDifferentHash) {
  // Verify that we correctly distinguish between an unquoted
  // CSS generic family and a quoted family name.
  // See crbug.com/1408485
  FontDescription a;
  FontDescription b(a);

  a.SetFamily(
      FontFamily(font_family_names::kSerif, FontFamily::Type::kGenericFamily));
  b.SetFamily(
      FontFamily(font_family_names::kSerif, FontFamily::Type::kFamilyName));

  unsigned key_a = a.GetHash();
  unsigned key_b = b.GetHash();

  ASSERT_NE(key_a, key_b);
}

TEST_F(FontDescriptionTest, ToString) {
  FontDescription description;

  description.SetFamily(
      FontFamily(AtomicString("A"), FontFamily::Type::kFamilyName,
                 SharedFontFamily::Create(AtomicString("B"),
                                          FontFamily::Type::kFamilyName)));

  description.SetLocale(LayoutLocale::Get(AtomicString("no")));

  scoped_refptr<FontVariationSettings> variation_settings =
      FontVariationSettings::Create();
  variation_settings->Append(FontVariationAxis{AtomicString("aaaa"), 42});
  variation_settings->Append(FontVariationAxis{AtomicString("bbbb"), 8118});
  description.SetVariationSettings(variation_settings);

  scoped_refptr<FontFeatureSettings> feature_settings = FontFeatureSettings::Create();
  feature_settings->Append(FontFeature{AtomicString("cccc"), 76});
  feature_settings->Append(FontFeature{AtomicString("dddd"), 94});
  description.SetFeatureSettings(feature_settings);

  description.SetSpecifiedSize(1.1f);
  description.SetComputedSize(2.2f);
  description.SetAdjustedSize(3.3f);
  description.SetSizeAdjust(
      FontSizeAdjust(4.4f, FontSizeAdjust::Metric::kCapHeight));
  description.SetLetterSpacing(5.5f);
  description.SetWordSpacing(6.6f);

  description.SetStyle(FontSelectionValue(31.5));
  description.SetWeight(FontSelectionValue(32.6));
  description.SetStretch(FontSelectionValue(33.7));

  description.SetTextRendering(kOptimizeLegibility);

  EXPECT_EQ(
      "family_list=[A, B], feature_settings=[cccc=76,dddd=94], "
      "variation_settings=[aaaa=42,bbbb=8118], locale=no, "
      "specified_size=1.100000, computed_size=2.200000, "
      "adjusted_size=3.300000, size_adjust=cap-height 4.4, "
      "letter_spacing=5.500000, word_spacing=6.600000, "
      "font_selection_request=[weight=32.500000, width=33.500000, "
      "slope=31.500000], typesetting_features=[Kerning,Ligatures], "
      "orientation=Horizontal, width_variant=Regular, variant_caps=Normal, "
      "is_absolute_size=false, generic_family=None, kerning=Auto, "
      "variant_ligatures=[common=Normal, discretionary=Normal, "
      "historical=Normal, contextual=Normal], keyword_size=0, "
      "font_smoothing=Auto, text_rendering=OptimizeLegibility, "
      "synthetic_bold=false, synthetic_italic=false, "
      "subpixel_positioning=false, subpixel_ascent_descent=false, "
      "variant_numeric=[numeric_figure=NormalFigure, "
      "numeric_spacing=NormalSpacing, numeric_fraction=Normal, ordinal=Off, "
      "slashed_zero=Off], variant_east_asian=[form=Normal, width=Normal, "
      "ruby=false], font_optical_sizing=Auto, font_synthesis_weight=Auto, "
      "font_synthesis_style=Auto, font_synthesis_small_caps=Auto, "
      "font_variant_position=Normal, font_variant_emoji=Normal",
      description.ToString());
}

// Verifies the correctness of the default hash trait of FontDescription.
TEST_F(FontDescriptionTest, DefaultHashTrait) {
  HashMap<FontDescription, int> map;

  FontDescription description1;

  FontDescription description2;
  description1.SetWeight(FontSelectionValue(100));

  FontDescription description3;
  description3.SetFamily(
      FontFamily(AtomicString("A"), FontFamily::Type::kFamilyName,
                 SharedFontFamily::Create(AtomicString("B"),
                                          FontFamily::Type::kFamilyName)));

  EXPECT_TRUE(map.insert(description1, 1).is_new_entry);
  EXPECT_FALSE(map.insert(description1, 1).is_new_entry);
  EXPECT_EQ(1u, map.size());

  EXPECT_TRUE(map.insert(description2, 2).is_new_entry);
  EXPECT_FALSE(map.insert(description2, 2).is_new_entry);
  EXPECT_EQ(2u, map.size());

  EXPECT_TRUE(map.insert(description3, 3).is_new_entry);
  EXPECT_FALSE(map.insert(description3, 3).is_new_entry);
  EXPECT_EQ(3u, map.size());

  EXPECT_EQ(1, map.at(description1));
  EXPECT_EQ(2, map.at(description2));
  EXPECT_EQ(3, map.at(description3));

  FontDescription not_in_map;
  not_in_map.SetWeight(FontSelectionValue(200));
  EXPECT_FALSE(map.Contains(not_in_map));

  map.erase(description2);
  EXPECT_EQ(2u, map.size());
  EXPECT_TRUE(map.Contains(description1));
  EXPECT_FALSE(map.Contains(description2));
  EXPECT_TRUE(map.Contains(description3));

  map.erase(description3);
  EXPECT_EQ(1u, map.size());
  EXPECT_TRUE(map.Contains(description1));
  EXPECT_FALSE(map.Contains(description2));
  EXPECT_FALSE(map.Contains(description3));

  map.erase(description1);
  EXPECT_EQ(0u, map.size());
  EXPECT_FALSE(map.Contains(description1));
  EXPECT_FALSE(map.Contains(description2));
  EXPECT_FALSE(map.Contains(description3));
}

// https://crbug.com/1081017
TEST_F(FontDescriptionTest, NegativeZeroEmFontSize) {
  // 'font-size: -0.0em' sets the following
  FontDescription description1;
  description1.SetSpecifiedSize(-0.0);

  FontDescription description2;
  description2.SetSpecifiedSize(0.0);

  // Equal font descriptions must have equal hash values
  EXPECT_EQ(description1, description2);
  EXPECT_EQ(description1.GetHash(), description2.GetHash());
}

}  // namespace blink

"""

```