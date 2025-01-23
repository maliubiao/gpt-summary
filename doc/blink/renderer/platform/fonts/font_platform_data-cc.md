Response:
Let's break down the thought process for analyzing the `FontPlatformData.cc` file.

1. **Understand the Goal:** The primary objective is to describe the functionality of this specific source file in the Chromium Blink rendering engine. This includes identifying its role, its relationships to web technologies (HTML, CSS, JavaScript), any logical reasoning, and potential user/programmer errors.

2. **Initial Scan and High-Level Understanding:**  The filename `font_platform_data.cc` immediately suggests this file deals with font-related information at a platform level within the rendering engine. The includes (`#include`) provide initial clues about dependencies:
    * `hb.h`, `hb-ot.h`: HarfBuzz, a font shaping library. This is a strong indicator of the file's involvement in how text is rendered.
    * `SkFont.h`, `SkTypeface.h`: Skia, the graphics library used by Chrome. This confirms interaction with the underlying graphics system.
    * Various Blink-specific headers (e.g., `FontCache.h`, `harfbuzz_face.h`): Shows its integration within Blink's font management system.

3. **Deconstruct the Class Definition:** The core of the file is the `FontPlatformData` class. Examine its members:
    * `typeface_`: `sk_sp<SkTypeface>` - Represents the actual font data.
    * `text_size_`: `float` - The size of the font.
    * `synthetic_bold_`, `synthetic_italic_`: `bool` - Indicate if bold or italic styling is applied artificially.
    * `text_rendering_`: `TextRenderingMode` -  Related to rendering quality (e.g., `geometric-precision`).
    * `resolved_font_features_`:  Deals with OpenType font features.
    * `orientation_`:  Font orientation (horizontal/vertical).
    * `style_`: `WebFontRenderStyle` -  Platform-specific rendering hints.
    * `harfbuzz_face_`:  A wrapper around HarfBuzz data for this font.

4. **Analyze Key Methods and Their Purpose:** Go through the methods to understand their roles:
    * **Constructors:** Handle initialization with different parameters. Notice the logic for querying system font rendering styles (especially for Linux).
    * `operator==`: Defines how to compare `FontPlatformData` objects for equality. This is important for caching and optimization.
    * `UniqueID()`:  Gets a unique identifier for the typeface.
    * `FontFamilyName()`: Retrieves the font's family name.
    * `IsAhem()`: Checks if the font is the "Ahem" test font.
    * `GetHarfBuzzFace()`:  Provides access to the HarfBuzz representation.
    * `GetHash()`:  Calculates a hash value for the font data, used for efficient storage and lookup.
    * `CreateSkFont()`: Creates a Skia `SkFont` object from the `FontPlatformData`. This is a crucial step in the rendering pipeline.
    * `ComputeTypefaceDigest()`:  Calculates a digest (hash) of the font's internal tables. This is important for font identification and privacy.
    * `GetPostScriptName()`:  Retrieves the PostScript name of the font.

5. **Identify Relationships to Web Technologies:** Think about how the information in `FontPlatformData` relates to HTML, CSS, and JavaScript:
    * **CSS:**
        * `font-family`: Directly maps to the `FontFamilyName()`.
        * `font-size`:  Corresponds to `text_size_`.
        * `font-weight`, `font-style`: Influence `synthetic_bold_` and `synthetic_italic_`.
        * `text-rendering`: Maps to `text_rendering_`.
        * Font features (e.g., `font-variant-ligatures`): Related to `resolved_font_features_` and HarfBuzz interaction.
    * **HTML:**  Specifies the text content that will be rendered using these font properties.
    * **JavaScript:** While this file doesn't directly execute JavaScript, JavaScript can manipulate the DOM and CSS styles, indirectly affecting the `FontPlatformData` used for rendering.

6. **Look for Logical Reasoning and Assumptions:**
    * The Linux-specific code using `kOptimizeLinuxFonts` demonstrates reasoning about performance optimization based on the observation that fontconfig lookups can be slow. The assumption is that normalizing font family names and ignoring text size for style lookups will improve performance.
    * The handling of `WebTestSupport` shows an awareness of testing scenarios and the need to control font rendering behavior in tests.

7. **Consider Potential Errors:** Think about common mistakes developers might make or issues that could arise:
    * Incorrect font family names in CSS.
    * Issues with web font loading and availability.
    * Performance problems related to excessive font lookups (addressed by the Linux optimization).
    * Inconsistent rendering across platforms due to different system font configurations.

8. **Structure the Output:** Organize the findings into logical sections:
    * **Functionality:**  A concise summary of the file's purpose.
    * **Relationship to Web Technologies:**  Specific examples linking the code to HTML, CSS, and JavaScript.
    * **Logical Reasoning:**  Highlight any significant logic or optimizations.
    * **Common Errors:**  Point out potential pitfalls.
    * **Hypothetical Examples:** Illustrate how different inputs to the class might affect its state and behavior (this helps solidify understanding).

9. **Refine and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the Skia aspects.
* **Correction:** Realize the HarfBuzz integration is equally, if not more, important for text shaping and advanced typography features.
* **Initial thought:**  Overlook the conditional compilation (`#if BUILDFLAG(...)`).
* **Correction:** Pay attention to how the code differs across operating systems, especially regarding system font rendering styles.
* **Initial thought:** Not explicitly connect font features to CSS properties.
* **Correction:** Make the explicit link to properties like `font-variant-ligatures`.

By following this systematic approach, one can effectively analyze and understand the functionality of a complex source code file like `font_platform_data.cc`.
好的，让我们来详细分析一下 `blink/renderer/platform/fonts/font_platform_data.cc` 这个文件。

**文件功能概述**

`font_platform_data.cc` 文件定义了 `FontPlatformData` 类，这个类在 Chromium Blink 渲染引擎中扮演着核心角色，它封装了渲染文本所需的**平台相关的字体信息**。  你可以将其理解为描述一个特定字体的关键属性的结构体或对象，这些属性是操作系统和底层图形库（如 Skia 和 HarfBuzz）理解和渲染字体所必需的。

**主要功能点:**

1. **字体表示:** `FontPlatformData` 存储了字体的核心信息，包括：
   - `typeface_`:  指向 Skia `SkTypeface` 对象的智能指针，代表了实际的字体数据（如 TrueType 或 OpenType 文件）。
   - `text_size_`: 字体的大小。
   - `synthetic_bold_`, `synthetic_italic_`: 布尔值，指示是否通过算法合成粗体或斜体效果。
   - `text_rendering_`:  文本渲染模式，影响抗锯齿和亚像素渲染等。
   - `orientation_`: 字体的书写方向（水平或垂直）。
   - `resolved_font_features_`:  解析后的 OpenType 字体特性设置。
   - `style_`: `WebFontRenderStyle` 对象，包含了平台相关的字体渲染风格设置，例如是否使用亚像素定位、 hinting 方式等。
   - `family_`: 字体族名称 (在非 Windows 和 macOS 平台使用)。

2. **平台相关性处理:**  该类负责处理不同操作系统下字体处理的差异。例如，在 Linux 系统上，它会尝试优化字体查找以提升性能（通过 `kOptimizeLinuxFonts` feature flag）。它会查询系统字体渲染风格，并根据平台特性进行调整。

3. **与 Skia 集成:**  `FontPlatformData` 直接关联到 Skia 图形库，它持有 `SkTypeface` 对象，并提供了创建 `SkFont` 对象的方法 (`CreateSkFont`)，SkFont 是 Skia 中用于绘制文本的类。

4. **与 HarfBuzz 集成:**  通过 `harfbuzz_face_` 成员，`FontPlatformData` 与 HarfBuzz 字体塑形引擎集成。HarfBuzz 负责处理复杂的文本布局，例如连字、字距调整、变体选择等。 `GetHarfBuzzFace()` 方法返回一个 `HarfBuzzFace` 对象，该对象封装了 HarfBuzz 需要的字体数据。

5. **字体唯一性标识:**  提供了 `UniqueID()` 方法来获取字体的唯一 ID，这对于字体缓存和比较非常重要。

6. **字体信息查询:**  提供了获取字体族名称 (`FontFamilyName()`) 和 PostScript 名称 (`GetPostScriptName()`) 的方法。

7. **字体包含字符判断:**  在非 macOS 平台，提供了 `FontContainsCharacter()` 方法来判断字体是否包含某个 Unicode 字符。

8. **字体指纹计算:**  `ComputeTypefaceDigest()` 方法计算字体的“指纹”，通过提取字体文件中关键表的哈希值来实现。这可以用于字体识别和隐私保护。

**与 JavaScript, HTML, CSS 的关系**

`FontPlatformData` 虽然是 C++ 代码，但它直接支撑着浏览器渲染引擎处理 HTML、CSS 中定义的字体样式，并最终影响 JavaScript 操作 DOM 后文本的显示效果。

**举例说明:**

1. **CSS `font-family`:**
   - **假设输入 (CSS):** `p { font-family: "Arial", sans-serif; }`
   - **逻辑推理:** 当浏览器解析到这段 CSS 时，渲染引擎会尝试查找 "Arial" 字体。如果找到，会创建一个 `FontPlatformData` 对象，其中 `FontFamilyName()` 返回 "Arial"，并且 `typeface_` 指向 "Arial" 的 `SkTypeface` 对象。如果找不到 "Arial"，则会尝试 "sans-serif" 等通用字体族。

2. **CSS `font-size`:**
   - **假设输入 (CSS):** `h1 { font-size: 24px; }`
   - **逻辑推理:**  当渲染引擎处理 `h1` 标签内的文本时，会创建一个 `FontPlatformData` 对象，其 `text_size_` 成员会被设置为 24。

3. **CSS `font-weight: bold`:**
   - **假设输入 (CSS):** `strong { font-weight: bold; }`
   - **逻辑推理:**  如果系统找到了 "Arial Bold" 这样的粗体变体字体，`typeface_` 会指向该粗体字体的 `SkTypeface`。 如果没有找到，`synthetic_bold_` 可能会被设置为 `true`，指示需要通过算法来模拟粗体效果。

4. **CSS `text-rendering: geometricPrecision`:**
   - **假设输入 (CSS):** `canvas { text-rendering: geometricPrecision; }`
   - **逻辑推理:**  这会影响 `FontPlatformData` 的 `text_rendering_` 成员。在某些平台上，例如 Linux，这可能会导致 `style_` 中的亚像素定位 (`use_subpixel_positioning`) 被启用，并且 hinting 被禁用，以追求更高的几何精度。

5. **JavaScript 操作字体:**
   - **假设输入 (JavaScript):** `document.body.style.fontFamily = "Times New Roman";`
   - **逻辑推理:**  当 JavaScript 修改元素的 `fontFamily` 样式时，渲染引擎会重新计算该元素的文本渲染属性，并可能创建一个新的 `FontPlatformData` 对象来反映新的字体设置。

**逻辑推理举例:**

- **假设输入:**  在 Linux 系统上，CSS 中指定了 `font-family: "Arial"`，字体大小为 16px。
- **逻辑推理:**  如果 `kOptimizeLinuxFonts` feature flag 启用，引擎在查询系统字体渲染风格时，可能会忽略字体大小 (16px)，并使用归一化后的字体族名 "Arial" 进行查询，以减少潜在的重复且耗时的字体查找。
- **预期输出:**  `FontPlatformData` 对象会被创建，其 `family_` 为 "Arial"，`text_size_` 为 16，并且 `style_` 包含了从系统查询到的 "Arial" 字体族的通用渲染风格设置，而不仅仅是 16px 大小的风格。

**用户或编程常见的使用错误举例:**

1. **拼写错误的字体族名称:**
   - **错误示例 (CSS):** `p { font-family: "Ariial"; }`
   - **结果:**  浏览器可能无法找到名为 "Ariial" 的字体，最终会回退到默认字体或在 `font-family` 列表中指定的下一个字体。这会导致用户看到的字体与预期不符。

2. **过度依赖合成粗体/斜体:**
   - **问题:**  虽然浏览器可以合成粗体和斜体，但其效果通常不如字体本身提供的粗体和斜体字形好。
   - **结果:**  文本渲染质量可能会下降，笔画可能显得模糊或变形。开发者应该尽量使用包含所需字重的字体文件。

3. **不理解 `text-rendering` 的影响:**
   - **错误使用:**  在所有场景都使用 `text-rendering: geometricPrecision`。
   - **结果:**  虽然 `geometricPrecision` 可以提高文本的几何精度，但可能会牺牲一定的渲染性能，并且在小字号下可能看起来不太清晰。开发者应该根据具体需求选择合适的 `text-rendering` 值。

4. **在 JavaScript 中频繁修改字体样式:**
   - **问题:**  频繁地修改元素的字体样式会导致渲染引擎不断地创建和销毁 `FontPlatformData` 对象，并重新进行布局和绘制。
   - **结果:**  可能导致页面性能下降，尤其是在涉及大量文本的场景中。应该尽量减少不必要的字体样式修改。

**总结**

`font_platform_data.cc` 中的 `FontPlatformData` 类是 Blink 渲染引擎中处理字体的核心组件。它封装了平台相关的字体信息，并负责与 Skia 和 HarfBuzz 等底层库进行交互。它直接受到 HTML 和 CSS 中字体样式声明的影响，并最终决定了网页上文本的渲染效果。理解其功能对于深入了解浏览器如何处理字体以及进行性能优化至关重要。

### 提示词
```
这是目录为blink/renderer/platform/fonts/font_platform_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Brent Fulgham
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"

#include "base/feature_list.h"
#include "build/build_config.h"
#include "hb-ot.h"
#include "hb.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/platform/linux/web_sandbox_support.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_font_cache.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_font_data.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/skia/include/core/SkData.h"
#include "third_party/skia/include/core/SkFont.h"
#include "third_party/skia/include/core/SkTypeface.h"

#if BUILDFLAG(IS_MAC)
#include "third_party/skia/include/ports/SkTypeface_mac.h"
#endif

namespace blink {
namespace {

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
// Getting the system font render style takes a significant amount of time on
// Linux because looking up fonts using fontconfig can be very slow. We fetch
// the render style for each font family and text size, while it's very
// unlikely that different text sizes for the same font family will have
// different render styles. In addition, sometimes the font family name is not
// normalized, so we may look up both "Arial" and "arial" which causes an
// additional fontconfig lookup. This feature enables normalizing the font
// family name and not using the text size for looking up the system render
// style, which will hopefully result in a large decrease in the number of slow
// fontconfig lookups.
BASE_FEATURE(kOptimizeLinuxFonts,
             "OptimizeLinuxFonts",
             base::FEATURE_DISABLED_BY_DEFAULT);
#endif  //  BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)

}  // namespace

FontPlatformData::FontPlatformData(WTF::HashTableDeletedValueType)
    : is_hash_table_deleted_value_(true) {}

FontPlatformData::FontPlatformData() = default;

FontPlatformData::FontPlatformData(const FontPlatformData& source)
    : typeface_(source.typeface_),
#if !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_MAC)
      family_(source.family_),
#endif
      text_size_(source.text_size_),
      synthetic_bold_(source.synthetic_bold_),
      synthetic_italic_(source.synthetic_italic_),
      avoid_embedded_bitmaps_(source.avoid_embedded_bitmaps_),
      text_rendering_(source.text_rendering_),
      orientation_(source.orientation_),
      resolved_font_features_(source.resolved_font_features_)
#if !BUILDFLAG(IS_MAC)
      ,
      style_(source.style_)
#endif
{
}

FontPlatformData::FontPlatformData(const FontPlatformData& src, float text_size)
    : FontPlatformData(src.typeface_,
#if !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_MAC)
                       src.family_.data(),
#else
                       std::string(),
#endif
                       text_size,
                       src.synthetic_bold_,
                       src.synthetic_italic_,
                       src.text_rendering_,
                       src.resolved_font_features_,
                       src.orientation_) {
}

FontPlatformData::FontPlatformData(sk_sp<SkTypeface> typeface,
                                   const std::string& family,
                                   float text_size,
                                   bool synthetic_bold,
                                   bool synthetic_italic,
                                   TextRenderingMode text_rendering,
                                   ResolvedFontFeatures resolved_font_features,
                                   FontOrientation orientation)
    : typeface_(typeface),
#if !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_MAC)
      family_(family),
#endif  // !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_MAC)
      text_size_(text_size),
      synthetic_bold_(synthetic_bold),
      synthetic_italic_(synthetic_italic),
      text_rendering_(text_rendering),
      orientation_(orientation),
      resolved_font_features_(std::move(resolved_font_features)) {
#if !BUILDFLAG(IS_MAC)
  style_ = WebFontRenderStyle::GetDefault();
#if !BUILDFLAG(IS_WIN)
  WebFontRenderStyle system_style;
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  bool override_font_name_and_size =
      base::FeatureList::IsEnabled(kOptimizeLinuxFonts);
#else
  bool override_font_name_and_size = false;
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  if (override_font_name_and_size) {
    system_style = QuerySystemRenderStyle(
        FontFamilyName().Utf8(), 0, typeface_->fontStyle(), text_rendering);
  } else {
    system_style = QuerySystemRenderStyle(
        family, text_size, typeface_->fontStyle(), text_rendering);
  }

  // In web tests, ignore system preference for subpixel positioning,
  // or explicitly disable if requested.
  if (WebTestSupport::IsRunningWebTest()) {
    system_style.use_subpixel_positioning =
        WebTestSupport::IsTextSubpixelPositioningAllowedForTest()
            ? WebFontRenderStyle::kNoPreference
            : 0;
  }
#else
  auto system_style = QuerySystemForRenderStyle();
#endif  // !BUILDFLAG(IS_WIN)
  style_.OverrideWith(system_style);
#endif  // !BUILDFLAG(IS_MAC)
}

FontPlatformData::~FontPlatformData() = default;

void FontPlatformData::Trace(Visitor* visitor) const {
  visitor->Trace(harfbuzz_face_);
}

#if BUILDFLAG(IS_MAC)
CTFontRef FontPlatformData::CtFont() const {
  return SkTypeface_GetCTFontRef(typeface_.get());
}
#endif

bool FontPlatformData::operator==(const FontPlatformData& a) const {
  // If either of the typeface pointers are null then we test for pointer
  // equality. Otherwise, we call SkTypeface::Equal on the valid pointers.
  bool typefaces_equal = false;
  if (!Typeface() || !a.Typeface())
    typefaces_equal = Typeface() == a.Typeface();
  else
    typefaces_equal = SkTypeface::Equal(Typeface(), a.Typeface());

  return typefaces_equal && text_size_ == a.text_size_ &&
         is_hash_table_deleted_value_ == a.is_hash_table_deleted_value_ &&
         synthetic_bold_ == a.synthetic_bold_ &&
         synthetic_italic_ == a.synthetic_italic_ &&
         avoid_embedded_bitmaps_ == a.avoid_embedded_bitmaps_ &&
         text_rendering_ == a.text_rendering_ &&
         resolved_font_features_ == a.resolved_font_features_ &&
#if !BUILDFLAG(IS_MAC)
         style_ == a.style_ &&
#endif
         orientation_ == a.orientation_;
}

SkTypefaceID FontPlatformData::UniqueID() const {
  return Typeface()->uniqueID();
}

String FontPlatformData::FontFamilyName() const {
  DCHECK(Typeface());
  SkTypeface::LocalizedStrings* font_family_iterator =
      Typeface()->createFamilyNameIterator();
  SkTypeface::LocalizedString localized_string;
  while (font_family_iterator->next(&localized_string) &&
         !localized_string.fString.size()) {
  }
  font_family_iterator->unref();
  return String::FromUTF8(base::as_byte_span(localized_string.fString));
}

bool FontPlatformData::IsAhem() const {
  return EqualIgnoringASCIICase(FontFamilyName(), "ahem") ||
         EqualIgnoringASCIICase(FontFamilyName(), "ahem (fontations)");
}

SkTypeface* FontPlatformData::Typeface() const {
  return typeface_.get();
}

HarfBuzzFace* FontPlatformData::GetHarfBuzzFace() const {
  if (!harfbuzz_face_) {
    harfbuzz_face_ = MakeGarbageCollected<HarfBuzzFace>(this, UniqueID());
  }

  return harfbuzz_face_.Get();
}

bool FontPlatformData::HasSpaceInLigaturesOrKerning(
    TypesettingFeatures features) const {
  HarfBuzzFace* hb_face = GetHarfBuzzFace();
  if (!hb_face)
    return false;

  return hb_face->HasSpaceInLigaturesOrKerning(features);
}

unsigned FontPlatformData::GetHash() const {
  unsigned h = UniqueID();
  h ^= 0x01010101 * ((static_cast<int>(is_hash_table_deleted_value_) << 3) |
                     (static_cast<int>(orientation_) << 2) |
                     (static_cast<int>(synthetic_bold_) << 1) |
                     static_cast<int>(synthetic_italic_));

  // This memcpy is to avoid a reinterpret_cast that breaks strict-aliasing
  // rules. Memcpy is generally optimized enough so that performance doesn't
  // matter here.
  uint32_t text_size_bytes;
  memcpy(&text_size_bytes, &text_size_, sizeof(uint32_t));
  h ^= text_size_bytes;

  return h;
}

#if !BUILDFLAG(IS_MAC)
bool FontPlatformData::FontContainsCharacter(UChar32 character) const {
  return CreateSkFont().unicharToGlyph(character);
}
#endif

#if !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN)
// static
WebFontRenderStyle FontPlatformData::QuerySystemRenderStyle(
    const std::string& family,
    float text_size,
    SkFontStyle font_style,
    TextRenderingMode text_rendering) {
  WebFontRenderStyle result;

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_IOS)
  // If the font name is missing (i.e. probably a web font) or the sandbox is
  // disabled, use the system defaults.
  if (family.length() && Platform::Current()->GetSandboxSupport()) {
    bool is_bold = font_style.weight() >= SkFontStyle::kSemiBold_Weight;
    bool is_italic = font_style.slant() != SkFontStyle::kUpright_Slant;
    Platform::Current()->GetSandboxSupport()->GetWebFontRenderStyleForStrike(
        family.data(), text_size, is_bold, is_italic,
        FontCache::DeviceScaleFactor(), &result);
  }

  // If `text-rendering: geometric-precision`, use subpixel positioning.
  // https://svgwg.org/svg2-draft/painting.html#TextRenderingProperty
  //
  // TODO(crbug.com/1327530): For now, do this only for Linux/Cros to minimize
  // the impact, and because they're the only platform that adjust these
  // settings by different device scale factors. See the doc link in the crbug.
  if (text_rendering == TextRenderingMode::kGeometricPrecision &&
      result.use_anti_alias) {
    result.use_subpixel_positioning = true;
    result.use_hinting = false;
    // 0 means HINTING_NONE, see |ConvertHinting| in font_service_app.cc.
    result.hint_style = 0;
  }
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_FUCHSIA) &&
        // !BUILDFLAG(IS_IOS)

  return result;
}
#endif  // !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN)

#if !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_IOS)
SkFont FontPlatformData::CreateSkFont(const FontDescription*) const {
  SkFont font(typeface_);
  style_.ApplyToSkFont(&font);

  const float ts = text_size_ >= 0 ? text_size_ : 12;
  font.setSize(SkFloatToScalar(ts));
  font.setEmbolden(synthetic_bold_);
  font.setSkewX(synthetic_italic_ ? -SK_Scalar1 / 4 : 0);

  font.setEmbeddedBitmaps(!avoid_embedded_bitmaps_);

  if (RuntimeEnabledFeatures::DisableAhemAntialiasEnabled() && IsAhem()) {
    font.setEdging(SkFont::Edging::kAlias);
  }

  return font;
}
#endif  // !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN) && !BUILDFLAG(IS_IOS)

IdentifiableToken FontPlatformData::ComputeTypefaceDigest() const {
  DCHECK(typeface_);
  int table_count = typeface_->countTables();

  // If no tables are found, return 0, to make it clearer that no identifiable
  // information was available.
  if (!table_count)
    return 0;

  IdentifiableTokenBuilder builder;
  builder.AddValue(table_count);

  Vector<SkFontTableTag> all_table_tags(table_count);
  int tags_copied = typeface_->getTableTags(all_table_tags.data());
  DCHECK_EQ(tags_copied, table_count);

  // The tags are probably already sorted, but let's make sure.
  std::sort(all_table_tags.begin(), all_table_tags.end());
  for (SkFontTableTag table_tag : all_table_tags) {
    builder.AddValue(table_tag).AddValue(typeface_->getTableSize(table_tag));
  }

  // These tables should both be small enough to compute a digest quickly and
  // varied enough to ensure that different fonts have distinct hashes.
  constexpr SkFontTableTag kTablesToFullyDigest[] = {
      SkSetFourByteTag('c', 'm', 'a', 'p'),
      SkSetFourByteTag('h', 'e', 'a', 'd'),
      SkSetFourByteTag('n', 'a', 'm', 'e'),
  };
  for (SkFontTableTag table_tag : kTablesToFullyDigest) {
    base::span<const uint8_t> table_data_span;
    sk_sp<SkData> table_data = typeface_->copyTableData(table_tag);
    if (table_data) {
      table_data_span =
          base::span<const uint8_t>(table_data->bytes(), table_data->size());
    }
    builder.AddAtomic(table_data_span);
  }

  return builder.GetToken();  // hasher.GetHash();
}

String FontPlatformData::GetPostScriptName() const {
  if (!typeface_)
    return String();

  SkString postscript_name;
  bool success = typeface_->getPostScriptName(&postscript_name);
  return success ? postscript_name.c_str() : String();
}

}  // namespace blink
```