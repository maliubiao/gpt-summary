Response:
Let's break down the thought process for analyzing the `font_description.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (HTML, CSS, JavaScript), examples, logical reasoning (input/output), and common usage errors.

2. **Identify the Core Purpose:** The filename `font_description.cc` strongly suggests that this file is responsible for representing and managing font properties within the Blink rendering engine.

3. **Examine the Header:**  The copyright notices indicate its origins and licensing. The `#include` statements reveal dependencies:
    *  `<font_description.h>`: This is the most crucial, suggesting this `.cc` file implements the interface defined in the `.h` file.
    *  Various platform-related headers (`language.h`, `wtf/*`) point to fundamental data structures and utilities within Blink.
    *  `third_party/blink/public/platform/web_font_description.h`:  This links the internal representation to a public API, hinting at how external code might interact with font descriptions.
    *  `build/build_config.h`: Indicates platform-specific compilation logic.
    *  `base/memory/values_equivalent.h`: Suggests functionality for comparing objects with potentially complex internal state.

4. **Analyze the Class Definition (`FontDescription`):** This is the heart of the file. Look for:
    * **Member Variables:** These store the font properties. Notice names like `family_list_`, `specified_size_`, `computed_size_`, `font_weight_`, `font_style_`, `letter_spacing_`, etc. These directly map to CSS font properties.
    * **Constructors:** How `FontDescription` objects are created (default, copy, deleted value).
    * **Operator Overloads (`==`, `=`)**: How comparisons and assignments are handled. The `==` operator is particularly important for understanding how font descriptions are considered equivalent. The complex comparison logic involving `scoped_refptr` for feature and variation settings indicates that direct pointer comparison isn't enough and their *content* needs to be compared.
    * **Methods (Functions):** These implement the logic for manipulating and accessing font properties. Categorize them:
        * **Getters/Setters:** Methods like `Weight()`, `SetWeight()`, `Size()`, `SetSize()`, etc.
        * **Calculations/Transformations:**  `LighterWeight()`, `BolderWeight()`, `LargerSize()`, `SmallerSize()`, `EffectiveFontSize()`, `AdjustedSpecifiedSize()`, `SizeAdjustedFontDescription()`. These show how font properties can be derived or modified.
        * **Key Generation:**  `CacheKey()` is vital for understanding how font descriptions are used in font caching, a performance optimization. The parameters to `CacheKey` are significant.
        * **Feature/Variation Handling:** `SetVariantCaps()`, `SetVariantLigatures()`, `SetVariantNumeric()`. These deal with OpenType font features.
        * **Skia Integration:** `SkiaFontStyle()`, `UpdateFromSkiaFontStyle()`. This reveals the connection to the Skia graphics library used for rendering.
        * **Debugging/String Representation:** `ToString()` methods are crucial for logging and debugging.
        * **Internal Logic:** `UpdateTypesettingFeatures()`, `UpdateSyntheticOblique()`.

5. **Connect to Web Technologies:** Based on the identified member variables and methods:
    * **CSS:**  The variable names and functionalities directly correspond to CSS font properties (e.g., `font-family`, `font-size`, `font-weight`, `font-style`, `letter-spacing`, `word-spacing`, `font-variant`, `font-feature-settings`, `font-variation-settings`).
    * **HTML:** Font descriptions are used to style text within HTML elements.
    * **JavaScript:**  JavaScript can interact with font styles through the CSSOM (CSS Object Model). While this file doesn't directly *execute* JavaScript, it provides the underlying representation that JavaScript manipulates.

6. **Logical Reasoning (Input/Output):** Choose a representative method, like `LighterWeight()`. Provide a clear input (a font weight value) and the expected output based on the CSS specification. This demonstrates an understanding of the function's behavior.

7. **Common Usage Errors:** Think about how developers might misuse or misunderstand font properties in CSS:
    * **Incorrect `font-weight` or `font-style` syntax.**
    * **Conflicting font properties.**
    * **Assuming a specific font is available.**
    * **Misunderstanding relative font sizes (`em`, `rem`).**
    * **Ignoring font loading and fallback mechanisms.**

8. **Structure the Answer:**  Organize the information logically:
    * **Overall Functionality:** Start with a high-level summary.
    * **Key Features:** Detail the important aspects and responsibilities.
    * **Relationship to Web Technologies:**  Explicitly connect to HTML, CSS, and JavaScript with examples.
    * **Logical Reasoning:** Provide input/output examples.
    * **Common Usage Errors:** Illustrate potential mistakes.

9. **Refine and Review:** Ensure clarity, accuracy, and completeness. Double-check the code snippets and explanations. Make sure the examples are relevant and easy to understand. For instance, initially, I might just list the member variables. But the refined thought is to *explain* how those variables relate to CSS properties. Similarly, for methods, not just listing them, but categorizing them by function is more helpful.
根据提供的 Chromium Blink 引擎源代码文件 `font_description.cc`，我们可以列举出它的主要功能如下：

**核心功能:**

1. **表示和管理字体描述信息:** 该文件定义了 `FontDescription` 类，这个类是 Blink 引擎中用于表示和存储字体各种属性的核心数据结构。这些属性包括：
    * **字体族 (Font Family):**  例如 "Arial", "Times New Roman", "serif", "sans-serif" 等。
    * **字体大小 (Font Size):** 包括指定的像素大小、计算后的大小、调整后的大小以及相关的关键字大小（例如 `small`, `large`）。
    * **字重 (Font Weight):** 例如 `normal`, `bold`, `100`, `900` 等。
    * **字体样式 (Font Style):** 例如 `normal`, `italic`, `oblique`。
    * **字体拉伸 (Font Stretch):** 例如 `condensed`, `expanded` 等。
    * **字母间距 (Letter Spacing)。**
    * **单词间距 (Word Spacing)。**
    * **语言区域 (Locale):** 用于处理不同语言的排版规则。
    * **OpenType 功能 (Feature Settings, Variation Settings):**  允许指定字体的高级排版特性，例如连字、小型大写字母等。
    * **字体调色板 (Font Palette):** 用于彩色字体的调色板信息。
    * **字体变体候选项 (Font Variant Alternates)。**
    * **字体的显示方向 (Orientation):** 水平或垂直。
    * **字体的微调 (Size Adjust)。**
    * **字体的渲染选项 (Font Smoothing, Text Rendering)。**
    * **是否合成粗体/斜体 (Synthetic Bold/Italic)。**
    * **是否使用亚像素定位 (Subpixel Text Positioning)。**
    * **等等。**

2. **提供字体属性的访问和修改方法:**  `FontDescription` 类提供了大量的 getter 和 setter 方法来访问和修改上述的字体属性。例如 `Weight()`, `SetWeight()`, `Size()`, `SetSize()`, `Family()`, `SetFamily()` 等。

3. **实现字体属性的逻辑计算:**  该文件包含一些用于计算或调整字体属性的方法，例如：
    * `LighterWeight()` 和 `BolderWeight()`: 根据 CSS 规范计算更轻或更重的字重。
    * `LargerSize()` 和 `SmallerSize()`: 根据相对大小关键字计算更大的或更小的字体大小。
    * `EffectiveFontSize()`:  计算用于字体缓存的有效字体大小。
    * `AdjustedSpecifiedSize()`:  计算经过 `font-size-adjust` 调整后的指定大小。
    * `SizeAdjustedFontDescription()`:  创建一个应用了 `size-adjust` 描述符的新 `FontDescription` 对象。

4. **支持字体缓存:**  `CacheKey()` 方法生成用于字体缓存的键值，该键值包含了影响字体选择的关键属性。这有助于提高字体查找和渲染的性能。

5. **与 Skia 图形库集成:**  `SkiaFontStyle()` 和 `UpdateFromSkiaFontStyle()` 方法用于在 `FontDescription` 和 Skia 图形库的字体风格表示 (`SkFontStyle`) 之间进行转换。Skia 是 Chromium 用于渲染图形的底层库。

6. **提供调试和日志输出:**  `ToString()` 方法用于生成 `FontDescription` 对象的字符串表示，方便调试和日志记录。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`FontDescription` 类是 Blink 引擎内部表示 CSS 样式中字体相关属性的核心，因此它与 Javascript, HTML, CSS 的功能紧密相关：

* **CSS:**  `FontDescription` 类直接对应于 CSS 中与字体相关的属性。当浏览器解析 CSS 样式时，会创建 `FontDescription` 对象来存储这些属性。
    * **例子:**  CSS 规则 `font-family: "Arial", sans-serif; font-size: 16px; font-weight: bold;`  在 Blink 内部会被解析并存储到 `FontDescription` 对象的 `family_list_`, `specified_size_`, `font_selection_request_` (用于存储字重) 等成员变量中。

* **HTML:** HTML 元素通过 CSS 样式来指定其文本的字体。`FontDescription` 最终会被用于渲染 HTML 元素中的文本。
    * **例子:**  一个 `<div>` 元素的 style 属性设置为 `style="font-family: 'Courier New';"`,  浏览器会创建一个 `FontDescription` 对象，其 `family_list_` 成员将包含 "Courier New"。

* **Javascript:** Javascript 可以通过 DOM API 和 CSSOM (CSS Object Model) 来读取和修改元素的样式，包括字体相关的属性。这些操作最终会影响到 Blink 内部的 `FontDescription` 对象。
    * **例子:**  Javascript 代码 `element.style.fontWeight = 'lighter';`  执行后，浏览器会查找该元素的 `FontDescription` 对象，并调用相应的 setter 方法（例如，修改 `font_selection_request_`）来更新字重。
    * **例子:**  Javascript 代码 `window.getComputedStyle(element).getPropertyValue('font-size');`  会返回元素最终计算出的字体大小，这个值可能来自于 `FontDescription` 对象的 `computed_size_` 或 `adjusted_size_`。

**逻辑推理的假设输入与输出举例:**

* **假设输入:**  一个 `FontDescription` 对象，其 `font_selection_request_.weight` (字重) 为 `kNormalWeightValue` (400)。
* **调用方法:** `LighterWeight(font_description.Weight())`
* **输出:**  `FontSelectionValue(100)`。
    * **推理:**  根据 `LighterWeight()` 方法的逻辑，当输入字重在 [350, 550) 范围内时，会返回 100。

* **假设输入:** 一个 `FontDescription` 对象，其 `specified_size_` 为 16.0，`computed_size_` 为 16.0， 并且设置了 `size_adjust_` 为 0.8。
* **调用方法:** `AdjustedSpecifiedSize()`
* **输出:** 12.8。
    * **推理:** `AdjustedSpecifiedSize()` 的计算公式是 `SpecifiedSize() * (AdjustedSize() / ComputedSize())`。由于设置了 `size_adjust_`，`AdjustedSize()` 应该基于 `ComputedSize()` 和 `size_adjust_` 计算得出，但具体计算方式可能在其他地方实现。假设最终 `AdjustedSize()` 计算为 12.8 (16.0 * 0.8)，那么输出就是 16.0 * (12.8 / 16.0) = 12.8。

**用户或编程常见的使用错误举例:**

1. **CSS 中指定了不存在的字体族:**
    * **错误:** `font-family: "NonExistentFont";`
    * **后果:** 浏览器会根据 CSS 的字体回退机制，尝试使用后续指定的字体，或者使用默认的衬线或非衬线字体。`FontDescription` 对象会存储这个不存在的字体名，但在实际渲染时会使用不同的字体。

2. **CSS 中 `font-weight` 或 `font-style` 的值与实际字体文件不匹配:**
    * **错误:**  CSS 中设置 `font-weight: bold;`，但所选的字体族没有提供粗体变体。
    * **后果:** 浏览器可能会尝试合成粗体效果，或者回退到字体的普通字重。`FontDescription` 对象会存储请求的字重 (bold)，但最终渲染的字体可能不是真正的粗体。

3. **JavaScript 中修改样式时使用了错误的属性名或值:**
    * **错误:**  `element.style.fontWeght = 'bolder';` (拼写错误) 或者 `element.style.fontSize = 'abc';` (无效值)。
    * **后果:**  这些修改可能不会生效，或者导致浏览器解析错误。`FontDescription` 对象可能不会被正确更新，或者会包含无效的数据。

4. **过度依赖客户端字体:**
    * **错误:**  网页设计者假设所有用户的设备上都安装了特定的自定义字体。
    * **后果:**  如果用户设备上没有安装该字体，浏览器将无法找到匹配的字体文件，最终会使用回退字体，导致页面显示效果与设计不符。`FontDescription` 对象会存储请求的字体名，但在实际渲染时会使用不同的字体。

5. **混淆了相对字体大小单位:**
    * **错误:**  在不同的上下文中使用 `em` 或 `rem` 单位时，没有正确理解它们的参照物（父元素或根元素）。
    * **后果:**  可能导致字体大小与预期不符，影响页面布局和可读性。`FontDescription` 对象存储的计算后字体大小会受到上下文的影响。

总而言之，`font_description.cc` 文件中定义的 `FontDescription` 类是 Blink 引擎处理字体信息的核心，它连接了 CSS 样式、HTML 结构和 JavaScript 操作，并为最终的文本渲染提供了必要的数据基础。理解 `FontDescription` 的功能有助于理解浏览器如何处理网页中的字体样式。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/font_description.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2007 Nicholas Shanks <contact@nickshanks.com>
 * Copyright (C) 2008 Apple Inc. All rights reserved.
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
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#include "base/memory/values_equivalent.h"
#include "build/build_config.h"
#include "third_party/blink/public/platform/web_font_description.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#endif

namespace blink {

struct SameSizeAsFontDescription {
  DISALLOW_NEW();
  FontFamily family_list;
  scoped_refptr<FontFeatureSettings> feature_settings_;
  scoped_refptr<FontVariationSettings> variation_settings_;
  scoped_refptr<FontPalette> palette_;
  scoped_refptr<FontVariantAlternates> font_variant_alternates_;
  AtomicString locale;
  float sizes[5];
  FontSizeAdjust size_adjust_;
  FontSelectionRequest selection_request_;
  FieldsAsUnsignedType bitfields;
};

ASSERT_SIZE(FontDescription, SameSizeAsFontDescription);

bool FontDescription::use_subpixel_text_positioning_ = false;

// static
FontDescription FontDescription::CreateHashTableEmptyValue() {
  FontDescription result;
  memset(&result, 0, sizeof(FontDescription));
  DCHECK(result.IsHashTableEmptyValue());
  return result;
}

FontDescription::FontDescription(WTF::HashTableDeletedValueType) {
  memset(this, 0, sizeof(FontDescription));
  fields_.hash_category_ = kHashDeletedValue;
}

FontDescription::FontDescription()
    : specified_size_(0),
      computed_size_(0),
      adjusted_size_(0),
      letter_spacing_(0),
      word_spacing_(0),
      font_selection_request_(kNormalWeightValue,
                              kNormalWidthValue,
                              kNormalSlopeValue) {
  fields_as_unsigned_.parts[0] = 0;
  fields_as_unsigned_.parts[1] = 0;
  fields_.orientation_ = static_cast<unsigned>(FontOrientation::kHorizontal);
  fields_.width_variant_ = kRegularWidth;
  fields_.variant_caps_ = kCapsNormal;
  fields_.is_absolute_size_ = false;
  fields_.generic_family_ = kNoFamily;
  fields_.kerning_ = kAutoKerning;
  fields_.common_ligatures_state_ = kNormalLigaturesState;
  fields_.discretionary_ligatures_state_ = kNormalLigaturesState;
  fields_.historical_ligatures_state_ = kNormalLigaturesState;
  fields_.contextual_ligatures_state_ = kNormalLigaturesState;
  fields_.keyword_size_ = 0;
  fields_.font_smoothing_ = kAutoSmoothing;
  fields_.text_rendering_ = kAutoTextRendering;
  fields_.synthetic_bold_ = false;
  fields_.synthetic_italic_ = false;
  fields_.subpixel_text_position_ = use_subpixel_text_positioning_;
  fields_.typesetting_features_ = 0;
  fields_.variant_numeric_ = FontVariantNumeric().fields_as_unsigned_;
  fields_.subpixel_ascent_descent_ = false;
  fields_.font_optical_sizing_ = OpticalSizing::kAutoOpticalSizing;
  fields_.hash_category_ = kHashRegularValue;
  fields_.font_synthesis_weight_ = kAutoFontSynthesisWeight;
  fields_.font_synthesis_style_ = kAutoFontSynthesisStyle;
  fields_.font_synthesis_small_caps_ = kAutoFontSynthesisSmallCaps;
  fields_.variant_position_ = kNormalVariantPosition;
  fields_.variant_emoji_ = kNormalVariantEmoji;
  static_assert(static_cast<unsigned>(TextSpacingTrim::kInitial) == 0);
}

FontDescription::FontDescription(const FontDescription&) = default;

FontDescription& FontDescription::operator=(const FontDescription&) = default;

bool FontDescription::operator==(const FontDescription& other) const {
  return family_list_ == other.family_list_ && locale_ == other.locale_ &&
         specified_size_ == other.specified_size_ &&
         computed_size_ == other.computed_size_ &&
         adjusted_size_ == other.adjusted_size_ &&
         size_adjust_ == other.size_adjust_ &&
         letter_spacing_ == other.letter_spacing_ &&
         word_spacing_ == other.word_spacing_ &&
         font_selection_request_ == other.font_selection_request_ &&
         fields_as_unsigned_.parts[0] == other.fields_as_unsigned_.parts[0] &&
         fields_as_unsigned_.parts[1] == other.fields_as_unsigned_.parts[1] &&
         (feature_settings_ == other.feature_settings_ ||
          (feature_settings_ && other.feature_settings_ &&
           *feature_settings_ == *other.feature_settings_)) &&
         (variation_settings_ == other.variation_settings_ ||
          (variation_settings_ && other.variation_settings_ &&
           *variation_settings_ == *other.variation_settings_)) &&
         base::ValuesEquivalent(font_palette_, other.font_palette_) &&
         base::ValuesEquivalent(font_variant_alternates_,
                                other.font_variant_alternates_);
}

// Compute a 'lighter' weight per
// https://drafts.csswg.org/css-fonts-4/#font-weight-prop
FontSelectionValue FontDescription::LighterWeight(FontSelectionValue weight) {
  DCHECK(weight >= FontSelectionValue(1) && weight <= FontSelectionValue(1000));
  // [1, 100) => No change
  if (weight < FontSelectionValue(100))
    return weight;
  // [100, 550) => 100
  if (weight < FontSelectionValue(550))
    return FontSelectionValue(100);
  // [550, 750) => 400
  if (weight < FontSelectionValue(750))
    return FontSelectionValue(400);
  // [750, 1000] => 700
  return FontSelectionValue(700);
}

// Compute a 'bolder' weight per
// https://drafts.csswg.org/css-fonts-4/#font-weight-prop
FontSelectionValue FontDescription::BolderWeight(FontSelectionValue weight) {
  DCHECK(weight >= FontSelectionValue(1) && weight <= FontSelectionValue(1000));
  // [1, 350) => 400
  if (weight < FontSelectionValue(350))
    return FontSelectionValue(400);
  // [350, 550) => 700
  if (weight < FontSelectionValue(550))
    return FontSelectionValue(700);
  // [550, 900) => 900
  if (weight < FontSelectionValue(900))
    return FontSelectionValue(900);
  // [900, 1000] => No change
  return weight;
}

FontDescription::Size FontDescription::LargerSize(const Size& size) {
  return Size(0, size.value * 1.2, size.is_absolute);
}

FontDescription::Size FontDescription::SmallerSize(const Size& size) {
  return Size(0, size.value / 1.2, size.is_absolute);
}

FontSelectionRequest FontDescription::GetFontSelectionRequest() const {
  return font_selection_request_;
}

FontDescription::VariantLigatures FontDescription::GetVariantLigatures() const {
  VariantLigatures ligatures;

  ligatures.common = CommonLigaturesState();
  ligatures.discretionary = DiscretionaryLigaturesState();
  ligatures.historical = HistoricalLigaturesState();
  ligatures.contextual = ContextualLigaturesState();

  return ligatures;
}

void FontDescription::SetVariantCaps(FontVariantCaps variant_caps) {
  fields_.variant_caps_ = variant_caps;

  UpdateTypesettingFeatures();
}

void FontDescription::SetVariantEastAsian(
    const FontVariantEastAsian variant_east_asian) {
  fields_.variant_east_asian_ = variant_east_asian.fields_as_unsigned_;
}

void FontDescription::SetVariantLigatures(const VariantLigatures& ligatures) {
  fields_.common_ligatures_state_ = ligatures.common;
  fields_.discretionary_ligatures_state_ = ligatures.discretionary;
  fields_.historical_ligatures_state_ = ligatures.historical;
  fields_.contextual_ligatures_state_ = ligatures.contextual;

  UpdateTypesettingFeatures();
}

void FontDescription::SetVariantNumeric(
    const FontVariantNumeric& variant_numeric) {
  fields_.variant_numeric_ = variant_numeric.fields_as_unsigned_;

  UpdateTypesettingFeatures();
}

float FontDescription::EffectiveFontSize() const {
  // Ensure that the effective precision matches the font-cache precision.
  // This guarantees that the same precision is used regardless of cache status.
  // Note: HasSizeAdjust() is for the font-size-adjust property, not for the
  // size-adjust descriptor.
  float computed_or_adjusted_size =
      HasSizeAdjust() || fields_.has_size_adjust_descriptor_ ? AdjustedSize()
                                                             : ComputedSize();
  return floorf(computed_or_adjusted_size *
                FontCacheKey::PrecisionMultiplier()) /
         FontCacheKey::PrecisionMultiplier();
}

float FontDescription::AdjustedSpecifiedSize() const {
  if (HasSizeAdjust() || fields_.has_size_adjust_descriptor_) {
    return SpecifiedSize() * (AdjustedSize() / ComputedSize());
  } else {
    return SpecifiedSize();
  }
}

FontDescription FontDescription::SizeAdjustedFontDescription(
    float size_adjust) const {
  // See note in: https://www.w3.org/TR/css-fonts-5/#font-size-adjust-prop
  // When the font-size-adjust property is applied while a size-adjust
  // descriptor is set, the latter must not have an effect
  if (HasSizeAdjust())
    return *this;

  // size-adjust should be applied at most once.
  DCHECK(!fields_.has_size_adjust_descriptor_);
  FontDescription result(*this);
  result.SetAdjustedSize(ComputedSize() * size_adjust);
  result.fields_.has_size_adjust_descriptor_ = true;
  return result;
}

FontCacheKey FontDescription::CacheKey(
    const FontFaceCreationParams& creation_params,
    bool is_unique_match) const {
  unsigned options =
      static_cast<unsigned>(fields_.variant_emoji_) << 10 |         // bit 11-12
      static_cast<unsigned>(fields_.font_synthesis_style_) << 9 |   // bit 10
      static_cast<unsigned>(fields_.font_synthesis_weight_) << 8 |  // bit 9
      static_cast<unsigned>(fields_.font_optical_sizing_) << 7 |    // bit 8
      static_cast<unsigned>(fields_.synthetic_italic_) << 6 |       // bit 7
      static_cast<unsigned>(fields_.synthetic_bold_) << 5 |         // bit 6
      static_cast<unsigned>(fields_.text_rendering_) << 3 |         // bits 4-5
      static_cast<unsigned>(fields_.orientation_) << 1 |            // bit 2-3
      static_cast<unsigned>(fields_.subpixel_text_position_);       // bit 1

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  float device_scale_factor_for_key = FontCache::DeviceScaleFactor();
#else
  float device_scale_factor_for_key = 1.0f;
#endif
  FontCacheKey cache_key(creation_params, EffectiveFontSize(),
                         options | font_selection_request_.GetHash() << 13,
                         device_scale_factor_for_key, size_adjust_,
                         variation_settings_, font_palette_,
                         font_variant_alternates_, is_unique_match);
#if BUILDFLAG(IS_ANDROID)
  if (const LayoutLocale* locale = Locale()) {
    if (FontCache::GetLocaleSpecificFamilyName(creation_params.Family()))
      cache_key.SetLocale(AtomicString(locale->LocaleForSkFontMgr()));
  }
#endif  // BUILDFLAG(IS_ANDROID)
  return cache_key;
}

void FontDescription::UpdateTypesettingFeatures() {
  fields_.typesetting_features_ = 0;

  switch (TextRendering()) {
    case kAutoTextRendering:
      break;
    case kOptimizeSpeed:
      fields_.typesetting_features_ &= ~(blink::kKerning | kLigatures);
      break;
    case kGeometricPrecision:
    case kOptimizeLegibility:
      fields_.typesetting_features_ |= blink::kKerning | kLigatures;
      break;
  }

  switch (GetKerning()) {
    case FontDescription::kNoneKerning:
      fields_.typesetting_features_ &= ~blink::kKerning;
      break;
    case FontDescription::kNormalKerning:
      fields_.typesetting_features_ |= blink::kKerning;
      break;
    case FontDescription::kAutoKerning:
      break;
  }

  // As per CSS (https://drafts.csswg.org/css-text/#letter-spacing-property),
  // When the effective letter-spacing between two characters is not zero (due
  // to either justification or non-zero computed letter-spacing), user agents
  // should not apply optional ligatures.
  if (letter_spacing_ == 0) {
    switch (CommonLigaturesState()) {
      case FontDescription::kDisabledLigaturesState:
        fields_.typesetting_features_ &= ~blink::kLigatures;
        break;
      case FontDescription::kEnabledLigaturesState:
        fields_.typesetting_features_ |= blink::kLigatures;
        break;
      case FontDescription::kNormalLigaturesState:
        break;
    }

    if (DiscretionaryLigaturesState() ==
            FontDescription::kEnabledLigaturesState ||
        HistoricalLigaturesState() == FontDescription::kEnabledLigaturesState ||
        ContextualLigaturesState() == FontDescription::kEnabledLigaturesState) {
      fields_.typesetting_features_ |= blink::kLigatures;
    }
  }

  if (VariantCaps() != kCapsNormal)
    fields_.typesetting_features_ |= blink::kCaps;
}

namespace {

// This converts -0.0 to 0.0, so that they have the same hash value. This
// ensures that equal FontDescription have the same hash value.
float NormalizeSign(float number) {
  if (number == 0.0) [[unlikely]] {
    return 0.0;
  }
  return number;
}

}  // namespace

unsigned FontDescription::StyleHashWithoutFamilyList() const {
  unsigned hash = 0;
  const FontFeatureSettings* settings = FeatureSettings();
  if (settings) {
    unsigned num_features = settings->size();
    for (unsigned i = 0; i < num_features; ++i) {
      WTF::AddIntToHash(hash, settings->at(i).Tag());
      WTF::AddIntToHash(hash, settings->at(i).Value());
    }
  }

  if (VariationSettings()) {
    WTF::AddIntToHash(hash, VariationSettings()->GetHash());
  }

  if (font_palette_) {
    WTF::AddIntToHash(hash, font_palette_->GetHash());
  }

  if (locale_) {
    const AtomicString& locale = locale_->LocaleString();
    WTF::AddIntToHash(hash, locale.Hash());
  }

  WTF::AddFloatToHash(hash, NormalizeSign(specified_size_));
  WTF::AddFloatToHash(hash, NormalizeSign(computed_size_));
  WTF::AddFloatToHash(hash, NormalizeSign(adjusted_size_));
  WTF::AddFloatToHash(hash, NormalizeSign(letter_spacing_));
  WTF::AddFloatToHash(hash, NormalizeSign(word_spacing_));
  WTF::AddIntToHash(hash, fields_as_unsigned_.parts[0]);
  WTF::AddIntToHash(hash, fields_as_unsigned_.parts[1]);
  WTF::AddIntToHash(hash, font_selection_request_.GetHash());
  WTF::AddIntToHash(hash, size_adjust_.GetHash());

  return hash;
}

unsigned FontDescription::GetHash() const {
  unsigned hash = StyleHashWithoutFamilyList();
  for (const FontFamily* family = &family_list_; family;
       family = family->Next()) {
    if (family->FamilyName().empty())
      continue;
    WTF::AddIntToHash(hash, family->FamilyIsGeneric());
    WTF::AddIntToHash(hash, WTF::GetHash(family->FamilyName()));
  }
  return hash;
}

void FontDescription::SetOrientation(FontOrientation orientation) {
  fields_.orientation_ = static_cast<unsigned>(orientation);
  UpdateSyntheticOblique();
}

void FontDescription::SetStyle(FontSelectionValue value) {
  font_selection_request_.slope = value;
  original_slope = value;
  UpdateSyntheticOblique();
}

void FontDescription::UpdateSyntheticOblique() {
  // Doing synthetic oblique for vertical writing mode with upright text
  // orientation when negative angle parameter of "oblique" keyword, e.g.
  // "font-style: oblique -15deg" for simulating "tts:fontShear"[1][2], we
  // need to have normal font style instead of italic/oblique.
  // [1]
  // https://www.w3.org/TR/2018/REC-ttml2-20181108/#style-attribute-fontShear
  // [2] See http://crbug.com/1112923
  fields_.synthetic_oblique_ =
      IsVerticalAnyUpright() && original_slope < FontSelectionValue(0);
  font_selection_request_.slope =
      fields_.synthetic_oblique_ ? kNormalSlopeValue : original_slope;
}

SkFontStyle FontDescription::SkiaFontStyle() const {
  // FIXME(drott): This is a lossy conversion, compare
  // https://bugs.chromium.org/p/skia/issues/detail?id=6844
  int skia_width = SkFontStyle::kNormal_Width;
  if (Stretch() <= kUltraCondensedWidthValue) {
    skia_width = SkFontStyle::kUltraCondensed_Width;
  }
  if (Stretch() <= kExtraCondensedWidthValue) {
    skia_width = SkFontStyle::kExtraCondensed_Width;
  }
  if (Stretch() <= kCondensedWidthValue) {
    skia_width = SkFontStyle::kCondensed_Width;
  }
  if (Stretch() <= kSemiCondensedWidthValue) {
    skia_width = SkFontStyle::kSemiCondensed_Width;
  }
  if (Stretch() >= kSemiExpandedWidthValue) {
    skia_width = SkFontStyle::kSemiExpanded_Width;
  }
  if (Stretch() >= kExpandedWidthValue) {
    skia_width = SkFontStyle::kExpanded_Width;
  }
  if (Stretch() >= kExtraExpandedWidthValue) {
    skia_width = SkFontStyle::kExtraExpanded_Width;
  }
  if (Stretch() >= kUltraExpandedWidthValue) {
    skia_width = SkFontStyle::kUltraExpanded_Width;
  }

  SkFontStyle::Slant slant = SkFontStyle::kUpright_Slant;
  FontSelectionValue style = Style();
  if (style > kNormalSlopeValue && style <= kItalicThreshold) {
    slant = SkFontStyle::kItalic_Slant;
  }
  if (style > kItalicThreshold) {
    slant = SkFontStyle::kOblique_Slant;
  }

  int skia_weight = SkFontStyle::kNormal_Weight;
  if (Weight() >= kMinWeightValue && Weight() <= kMaxWeightValue) {
    skia_weight = static_cast<int>(Weight());
  }

  return SkFontStyle(skia_weight, skia_width, slant);
}

void FontDescription::UpdateFromSkiaFontStyle(const SkFontStyle& font_style) {
  SetWeight(FontSelectionValue(font_style.weight()));

  switch (font_style.width()) {
    case (SkFontStyle::kUltraCondensed_Width):
      SetStretch(kUltraCondensedWidthValue);
      break;
    case (SkFontStyle::kExtraCondensed_Width):
      SetStretch(kExtraCondensedWidthValue);
      break;
    case (SkFontStyle::kCondensed_Width):
      SetStretch(kCondensedWidthValue);
      break;
    case (SkFontStyle::kSemiCondensed_Width):
      SetStretch(kSemiCondensedWidthValue);
      break;
    case (SkFontStyle::kSemiExpanded_Width):
      SetStretch(kSemiExpandedWidthValue);
      break;
    case (SkFontStyle::kExpanded_Width):
      SetStretch(kExpandedWidthValue);
      break;
    case (SkFontStyle::kExtraExpanded_Width):
      SetStretch(kExtraExpandedWidthValue);
      break;
    case (SkFontStyle::kUltraExpanded_Width):
      SetStretch(kUltraExpandedWidthValue);
      break;
  }

  if (font_style.slant() == SkFontStyle::kOblique_Slant)
    SetStyle(kItalicSlopeValue);
  else
    SetStyle(kNormalSlopeValue);
}

int FontDescription::MinimumPrefixWidthToHyphenate() const {
  // If the maximum width available for the prefix before the hyphen is small,
  // then it is very unlikely that an hyphenation opportunity exists, so do not
  // bother to look for it.  These are heuristic numbers for performance added
  // in http://wkb.ug/45606
  const int kMinimumPrefixWidthNumerator = 5;
  const int kMinimumPrefixWidthDenominator = 4;
  return ComputedPixelSize() * kMinimumPrefixWidthNumerator /
         kMinimumPrefixWidthDenominator;
}

String FontDescription::ToString(GenericFamilyType familyType) {
  switch (familyType) {
    case GenericFamilyType::kNoFamily:
      return "None";
    case GenericFamilyType::kStandardFamily:
      return "Standard";
    case GenericFamilyType::kWebkitBodyFamily:
      return "WebkitBody";
    case GenericFamilyType::kSerifFamily:
      return "Serif";
    case GenericFamilyType::kSansSerifFamily:
      return "SansSerif";
    case GenericFamilyType::kMonospaceFamily:
      return "Monospace";
    case GenericFamilyType::kCursiveFamily:
      return "Cursive";
    case GenericFamilyType::kFantasyFamily:
      return "Fantasy";
  }
  return "Unknown";
}

String FontDescription::ToString(LigaturesState state) {
  switch (state) {
    case LigaturesState::kNormalLigaturesState:
      return "Normal";
    case LigaturesState::kDisabledLigaturesState:
      return "Disabled";
    case LigaturesState::kEnabledLigaturesState:
      return "Enabled";
  }
  return "Unknown";
}

String FontDescription::ToString(Kerning kerning) {
  switch (kerning) {
    case Kerning::kAutoKerning:
      return "Auto";
    case Kerning::kNormalKerning:
      return "Normal";
    case Kerning::kNoneKerning:
      return "None";
  }
  return "Unknown";
}

String FontDescription::ToString(FontSelectionValue selection_value) {
  if (selection_value == kUltraCondensedWidthValue) {
    return "Ultra-Condensed";
  } else if (selection_value == kExtraCondensedWidthValue) {
    return "Extra-Condensed";
  } else if (selection_value == kCondensedWidthValue) {
    return "Condensed";
  } else if (selection_value == kSemiCondensedWidthValue) {
    return "Semi-Condensed";
  } else if (selection_value == kNormalWidthValue) {
    return "Normal";
  } else if (selection_value == kSemiExpandedWidthValue) {
    return "Semi-Expanded";
  } else if (selection_value == kExpandedWidthValue) {
    return "Expanded";
  } else if (selection_value == kExtraExpandedWidthValue) {
    return "Extra-Expanded";
  } else if (selection_value == kUltraExpandedWidthValue) {
    return "Ultra-Expanded";
  }

  return "Unknown";
}

String FontDescription::ToString(FontVariantCaps variant) {
  switch (variant) {
    case FontVariantCaps::kCapsNormal:
      return "Normal";
    case FontVariantCaps::kSmallCaps:
      return "SmallCaps";
    case FontVariantCaps::kAllSmallCaps:
      return "AllSmallCaps";
    case FontVariantCaps::kPetiteCaps:
      return "PetiteCaps";
    case FontVariantCaps::kAllPetiteCaps:
      return "AllPetiteCaps";
    case FontVariantCaps::kUnicase:
      return "Unicase";
    case FontVariantCaps::kTitlingCaps:
      return "TitlingCaps";
  }
  return "Unknown";
}

String FontDescription::ToStringForIdl(FontVariantCaps variant) {
  switch (variant) {
    case FontVariantCaps::kCapsNormal:
      return "normal";
    case FontVariantCaps::kSmallCaps:
      return "small-caps";
    case FontVariantCaps::kAllSmallCaps:
      return "all-small-caps";
    case FontVariantCaps::kPetiteCaps:
      return "petite-caps";
    case FontVariantCaps::kAllPetiteCaps:
      return "all-petite-caps";
    case FontVariantCaps::kUnicase:
      return "unicase";
    case FontVariantCaps::kTitlingCaps:
      return "titling-caps";
  }
  return "Unknown";
}

String FontDescription::ToString(FontSynthesisWeight font_synthesis_weight) {
  switch (font_synthesis_weight) {
    case FontSynthesisWeight::kAutoFontSynthesisWeight:
      return "Auto";
    case FontSynthesisWeight::kNoneFontSynthesisWeight:
      return "None";
  }
  return "Unknown";
}

String FontDescription::ToString(FontSynthesisStyle font_synthesis_style) {
  switch (font_synthesis_style) {
    case FontSynthesisStyle::kAutoFontSynthesisStyle:
      return "Auto";
    case FontSynthesisStyle::kNoneFontSynthesisStyle:
      return "None";
  }
  return "Unknown";
}

String FontDescription::ToString(
    FontSynthesisSmallCaps font_synthesis_small_caps) {
  switch (font_synthesis_small_caps) {
    case FontSynthesisSmallCaps::kAutoFontSynthesisSmallCaps:
      return "Auto";
    case FontSynthesisSmallCaps::kNoneFontSynthesisSmallCaps:
      return "None";
  }
  return "Unknown";
}

String FontDescription::VariantLigatures::ToString() const {
  return String::Format(
      "common=%s, discretionary=%s, historical=%s, contextual=%s",
      FontDescription::ToString(static_cast<LigaturesState>(common))
          .Ascii()
          .data(),
      FontDescription::ToString(static_cast<LigaturesState>(discretionary))
          .Ascii()
          .data(),
      FontDescription::ToString(static_cast<LigaturesState>(historical))
          .Ascii()
          .data(),
      FontDescription::ToString(static_cast<LigaturesState>(contextual))
          .Ascii()
          .data());
}

String FontDescription::Size::ToString() const {
  return String::Format(
      "keyword_size=%u, specified_size=%f, is_absolute_size=%s", keyword, value,
      is_absolute ? "true" : "false");
}

String FontDescription::FamilyDescription::ToString() const {
  return String::Format(
      "generic_family=%s, family=[%s]",
      FontDescription::ToString(generic_family).Ascii().c_str(),
      family.ToString().Ascii().c_str());
}

String FontDescription::ToString(FontVariantPosition variant_position) {
  switch (variant_position) {
    case FontVariantPosition::kNormalVariantPosition:
      return "Normal";
    case FontVariantPosition::kSubVariantPosition:
      return "Sub";
    case FontVariantPosition::kSuperVariantPosition:
      return "Super";
  }
  return "Unknown";
}

static const char* ToBooleanString(bool value) {
  return value ? "true" : "false";
}

String FontDescription::ToString() const {
  return String::Format(
      "family_list=[%s], feature_settings=[%s], variation_settings=[%s], "
      "locale=%s, "
      "specified_size=%f, computed_size=%f, adjusted_size=%f, "
      "size_adjust=%s, letter_spacing=%f, word_spacing=%f, "
      "font_selection_request=[%s], "
      "typesetting_features=[%s], "
      "orientation=%s, width_variant=%s, variant_caps=%s, "
      "is_absolute_size=%s, generic_family=%s, kerning=%s, "
      "variant_ligatures=[%s], "
      "keyword_size=%u, font_smoothing=%s, text_rendering=%s, "
      "synthetic_bold=%s, synthetic_italic=%s, subpixel_positioning=%s, "
      "subpixel_ascent_descent=%s, variant_numeric=[%s], "
      "variant_east_asian=[%s], font_optical_sizing=%s, "
      "font_synthesis_weight=%s, font_synthesis_style=%s, "
      "font_synthesis_small_caps=%s, font_variant_position=%s, "
      "font_variant_emoji=%s",
      family_list_.ToString().Ascii().c_str(),
      (feature_settings_ ? feature_settings_->ToString().Ascii().c_str() : ""),
      (variation_settings_ ? variation_settings_->ToString().Ascii().c_str()
                           : ""),
      // TODO(wkorman): Locale has additional internal fields such as
      // hyphenation and script. Consider adding a more detailed
      // string method.
      (locale_ ? locale_->LocaleString().Ascii().c_str() : ""), specified_size_,
      computed_size_, adjusted_size_, size_adjust_.ToString().Ascii().c_str(),
      letter_spacing_, word_spacing_,
      font_selection_request_.ToString().Ascii().c_str(),
      blink::ToString(
          static_cast<TypesettingFeatures>(fields_.typesetting_features_))
          .Ascii()
          .data(),
      blink::ToString(Orientation()).Ascii().c_str(),
      blink::ToString(WidthVariant()).Ascii().c_str(),
      FontDescription::ToString(VariantCaps()).Ascii().c_str(),
      ToBooleanString(IsAbsoluteSize()),
      FontDescription::ToString(GenericFamily()).Ascii().c_str(),
      FontDescription::ToString(Kerning()).Ascii().c_str(),
      GetVariantLigatures().ToString().Ascii().c_str(), KeywordSize(),
      blink::ToString(FontSmoothing()).Ascii().c_str(),
      blink::ToString(TextRendering()).Ascii().c_str(),
      ToBooleanString(IsSyntheticBold()), ToBooleanString(IsSyntheticItalic()),
      ToBooleanString(UseSubpixelPositioning()),
      ToBooleanString(SubpixelAscentDescent()),
      VariantNumeric().ToString().Ascii().c_str(),
      VariantEastAsian().ToString().Ascii().c_str(),
      blink::ToString(FontOpticalSizing()).Ascii().c_str(),
      FontDescription::ToString(GetFontSynthesisWeight()).Ascii().c_str(),
      FontDescription::ToString(GetFontSynthesisStyle()).Ascii().c_str(),
      FontDescription::ToString(GetFontSynthesisSmallCaps()).Ascii().c_str(),
      FontDescription::ToString(VariantPosition()).Ascii().c_str(),
      blink::ToString(VariantEmoji()).Ascii().c_str());
}

}  // namespace blink

"""

```