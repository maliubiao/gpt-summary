Response:
Let's break down the thought process to analyze the given C++ code snippet and answer the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of the `font_cache_skia_win.cc` file in the Chromium Blink rendering engine. Specifically, they're interested in:

* **Core Functionality:** What does this code do?
* **Relationship to Web Technologies:** How does it connect to JavaScript, HTML, and CSS?
* **Logical Reasoning:**  Can we infer behavior based on inputs and outputs?
* **Common Errors:** What mistakes might developers or users make related to this code?

**2. Initial Code Scan and Keyword Identification:**

I'll start by quickly scanning the code for important keywords and class names:

* `FontCache`: This is central. The file name itself suggests it's a Windows-specific implementation of font caching.
* `Skia`:  The filename and includes (`third_party/skia/...`) confirm this file utilizes the Skia graphics library for font handling.
* `windows.h`:  Indicates platform-specific Windows API usage.
* `FontDescription`, `FontPlatformData`, `SimpleFontData`, `FontFaceCreationParams`: These strongly suggest the file deals with describing, creating, and managing font data.
* `GetFallbackFamily`, `PlatformFallbackFontForCharacter`, `GetDWriteFallbackFamily`:  Highlights the important aspect of font fallback when a requested font isn't available.
* `CreateFontPlatformData`, `CreateTypeface`: Points to the creation of actual font objects.
* `AtomicString`: A Chromium string class, likely used for efficiency.
* `LayoutLocale`:  Suggests language/locale awareness in font selection.
* `WebFontPrewarmer`:  Indicates optimization for loading web fonts.

**3. Inferring High-Level Functionality:**

Based on the keywords, I can infer the primary function of this file:

* **Windows-Specific Font Caching:**  It manages a cache of font data, optimized for the Windows operating system.
* **Skia Integration:** It leverages Skia to handle the low-level details of font rendering and access.
* **Font Fallback:** It implements logic to find alternative fonts when the requested font isn't available, considering language and script.
* **Font Creation:** It provides mechanisms to create `FontPlatformData` objects, which are platform-specific representations of fonts.
* **System Font Information:** It stores and retrieves information about system fonts (menu, caption, status).

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

Now, how does this relate to the web?

* **CSS Font Properties:** When a browser encounters CSS properties like `font-family`, `font-size`, `font-weight`, and `font-style`, this code plays a role in finding and creating the appropriate font.
* **Character Rendering:** When the browser needs to render text on the screen (from HTML content), this code is responsible for providing the font data required to draw the glyphs.
* **JavaScript Font Manipulation (Indirectly):** While JavaScript doesn't directly interact with this C++ code, JavaScript can trigger layout and rendering changes that will eventually lead to this code being executed. For example, dynamically changing CSS styles involving fonts.
* **Web Fonts:** The `WebFontPrewarmer` suggests this code is involved in optimizing the loading and usage of fonts downloaded from the web.

**5. Developing Examples and Scenarios:**

To illustrate the connection to web technologies, I'll create concrete examples:

* **CSS `font-family`:** If the CSS is `font-family: "Arial", sans-serif;`, and "Arial" is not found, this code will attempt to find a suitable "sans-serif" fallback.
* **Unicode Characters:** If the HTML contains a Chinese character, this code (specifically the fallback logic) will try to find a font that can display it correctly.
* **JavaScript and Dynamic Font Changes:** If JavaScript changes an element's `font-family`, this code will be invoked to fetch or create the new font.

**6. Reasoning and Assumptions (Input/Output):**

I'll consider the logical flow within the code, making assumptions about inputs and outputs:

* **Input:** A `FontDescription` object (containing family, size, weight, style, etc.) and a Unicode code point.
* **Output:** A `SimpleFontData` object (or `nullptr` if no suitable font is found).
* **Assumption:** The `FontCache` maintains an internal cache of already created fonts.

**Example of Reasoning:**

* **Scenario:**  Trying to render the character '你好' (Chinese for "hello") with the font "MyCustomFont".
* **Input:** `FontDescription` for "MyCustomFont", code points for '你' and '好'.
* **Logic:**
    1. The code first tries to find "MyCustomFont".
    2. If not found, the fallback mechanism kicks in.
    3. The `FallbackLocaleForCharacter` function will likely determine the locale is Chinese.
    4. `GetDWriteFallbackFamily` (or the hardcoded list) will search for fonts that support Chinese characters.
    5. A suitable font like "SimSun" might be selected.
* **Output:**  A `SimpleFontData` object for "SimSun" (if successful), allowing the characters to be rendered.

**7. Identifying Potential Errors:**

I'll consider common mistakes related to font handling:

* **Incorrect Font Names:** Specifying a font name that doesn't exist on the system.
* **Missing Character Support:** Using a font that doesn't contain the required glyphs.
* **Web Font Loading Issues:**  Problems with downloading or applying web fonts.
* **Case Sensitivity:** While the code tries to handle case-insensitive matching, users might still make case errors in CSS.
* **Locale Mismatch:**  If the system locale or language settings are incorrect, the font fallback might choose an inappropriate font.

**8. Structuring the Answer:**

Finally, I'll organize the information into a clear and comprehensive answer, covering all aspects of the user's request:

* **Functionality Overview:** Start with a concise summary of the file's purpose.
* **Detailed Function Breakdown:** Explain the key functions and their roles.
* **Relationship to Web Technologies:** Provide specific examples of how the code interacts with HTML, CSS, and JavaScript.
* **Logical Reasoning Examples:** Illustrate the font fallback process with a scenario.
* **Common Usage Errors:**  List potential mistakes that users or developers might make.

By following these steps, I can systematically analyze the code, understand its purpose, and provide a well-reasoned and informative answer to the user's request.
这是一个定义在 Chromium Blink 渲染引擎中，针对 Windows 平台，使用 Skia 图形库实现的字体缓存 (`FontCache`) 相关功能的文件。它的主要职责是管理和提供在 Windows 系统上渲染网页文本时所需的字体数据。

以下是 `font_cache_skia_win.cc` 的主要功能：

**1. 字体缓存管理:**

* **存储系统字体信息:**  缓存 Windows 系统默认的菜单字体、小标题字体和状态栏字体的名称和高度。这些信息用于在某些情况下提供默认的界面字体。
* **字体查找和创建:**  根据 `FontDescription` (包含字体族名、大小、粗细、样式等信息) 和 `FontFaceCreationParams` 来查找或创建 `FontPlatformData` 对象。`FontPlatformData` 是 Skia 字体库对特定字体的封装。
* **字体预热:**  提供 `PrewarmFamily` 函数，用于提前加载指定的字体族，以优化后续的字体查找速度。这对于常用的 Web 字体非常有用。

**2. 字体回退 (Font Fallback):**

* **硬编码回退列表:**  维护一个硬编码的字体列表 (`kCjkFonts`, `kCommonFonts`)，用于在找不到指定字体时作为备选字体。这个列表包含了覆盖广泛字符集的字体，特别是针对 CJK (中文、日文、韩文) 字符。
* **DWrite API 回退:**  利用 Windows 的 DirectWrite API (通过 Skia 接口) 来进行字体回退。当硬编码列表无法找到合适的字体时，或者开启了 `LegacyWindowsDWriteFontFallbackEnabled` 特性时，会调用 DirectWrite 来查找支持特定字符的字体。
* **基于字符的回退:**  `PlatformFallbackFontForCharacter` 函数是核心的字体回退逻辑。它会根据要渲染的字符 (codepoint) 和字体回退优先级，尝试查找合适的字体。
* **考虑语言区域 (Locale):**  在字体回退过程中，会考虑当前的语言区域 (`LayoutLocale`)，以便找到更符合用户语言习惯的字体。对于 CJK 字符，会优先使用能明确区分汉字变体的语言区域。
* **处理 Emoji:**  针对 Emoji 字符，有专门的处理逻辑，例如区分 Emoji Presentation 和 Text Presentation，并尝试使用相应的 Emoji 字体。

**3. `FontPlatformData` 的创建:**

* **`CreateFontPlatformData`:**  根据 `FontDescription` 和 `FontFaceCreationParams` 创建 `FontPlatformData` 对象。它会使用 Skia 的 API (`SkTypeface::MakeFromName`, `SkTypeface::MakeFromFile`) 来加载字体。
* **处理字体变体:**  能识别字体名称中的粗细 (如 "Arial Bold") 和宽度 (如 "Arial Condensed") 后缀，并尝试匹配相应的字体变体。
* **合成粗体和斜体:**  如果请求的字体没有对应的粗体或斜体版本，并且允许合成 (`SyntheticBoldAllowed`, `SyntheticItalicAllowed`)，则会创建带有合成效果的 `FontPlatformData`。

**4. 与 JavaScript, HTML, CSS 的关系:**

这个文件直接影响浏览器如何渲染网页上的文本，而网页上的文本样式是由 HTML 和 CSS 控制的。JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响到这个文件的行为。

**举例说明:**

* **CSS `font-family`:**  当 CSS 中指定 `font-family: "微软雅黑";` 时，Blink 引擎会调用 `FontCache` 的相关方法来查找名为 "微软雅黑" 的字体。如果找不到，就会触发字体回退机制，尝试使用 `font_cache_skia_win.cc` 中定义的回退策略来选择一个合适的替代字体。
* **HTML 中的 Unicode 字符:** 如果 HTML 中包含了中文汉字 `你好`，并且当前选择的字体不支持这些字符，`PlatformFallbackFontForCharacter` 函数会被调用，根据字符的 Unicode 值和当前的语言区域，查找支持中文的字体，例如 "宋体" 或 "黑体"。
* **JavaScript 动态修改字体:**  如果 JavaScript 代码通过修改元素的 `style.fontFamily` 属性来改变字体，例如 `element.style.fontFamily = "Impact";`，Blink 引擎会再次调用 `FontCache` 来获取 "Impact" 字体的 `FontPlatformData`。
* **Web Fonts (`@font-face`):** 当网页使用 `@font-face` 引入 Web 字体时，`FontCache` 会负责缓存这些下载的字体数据，以便后续快速使用。 `WebFontPrewarmer` 可以在字体下载完成后提前加载，提升渲染性能。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `FontDescription`:  `{ family: " несуществующий шрифт ", size: 16, weight: 400, style: normal, locale: "ru-RU" }` (一个不存在的字体，俄语区域)
* 要渲染的字符:  俄语字符 "Привет" (你好)

**输出:**

由于 "несуществующий шрифт" (不存在的字体) 在系统中找不到，`FontCache` 会启动回退机制。

1. **硬编码列表:** 可能会尝试在 `kCommonFonts` 中查找支持俄语字符的字体，例如 "Arial Unicode MS"。
2. **DWrite API 回退:**  如果硬编码列表没有合适的字体，或者启用了 DWrite 回退，则会调用 DirectWrite API，根据俄语区域设置，查找系统中可用的支持俄语字符的字体，例如 "Tahoma" 或 "Times New Roman"。

**最终输出:**  很可能是 "Tahoma" 或 "Times New Roman" 的 `FontPlatformData` 对象，因为这些字体通常都支持西里尔字母。

**涉及用户或编程常见的使用错误:**

* **CSS 中指定了不存在的字体名称:**  用户在 CSS 中写了 `font-family: "MyCustomFont";`，但用户的操作系统上并没有安装名为 "MyCustomFont" 的字体。这会导致浏览器使用回退字体，可能与设计预期不符。
* **没有考虑字符覆盖范围:** 开发者可能使用了某种字体，但该字体并不支持网页上需要显示的特定字符 (例如，使用只支持拉丁字母的字体显示中文)。这会导致出现 "豆腐块" (□) 或其他替代字符。
* **Web 字体加载失败:**  如果 `@font-face` 声明的 Web 字体因为网络问题或其他原因加载失败，浏览器将无法使用该字体，并回退到其他字体。开发者需要确保 Web 字体的正确加载。
* **语言区域设置不当:**  在某些复杂的国际化场景下，如果系统的语言区域设置不正确，可能会导致字体回退选择的字体不符合用户的期望。
* **忽略了合成粗体/斜体的影响:**  依赖浏览器合成粗体或斜体可能导致渲染效果不佳，尤其是在笔画较细的字体上。开发者应该尽量提供完整的字体变体。

总而言之，`font_cache_skia_win.cc` 是 Blink 引擎在 Windows 平台上进行字体管理和渲染的关键组成部分。它负责高效地查找、创建和回退字体，确保网页文本能够正确、美观地显示。 理解其功能有助于开发者更好地理解浏览器如何处理字体，并避免常见的字体相关问题。

### 提示词
```
这是目录为blink/renderer/platform/fonts/win/font_cache_skia_win.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007 Apple Computer, Inc.
 * Copyright (c) 2006, 2007, 2008, 2009, 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <windows.h>  // For GetACP()

#include <unicode/uscript.h>

#include <memory>
#include <string>
#include <utility>

#include "base/debug/alias.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/platform/web_font_prewarmer.h"
#include "third_party/blink/renderer/platform/fonts/bitmap_glyphs_block_list.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_face_creation_params.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_priority.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/win/font_fallback_win.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/layout_locale.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "third_party/skia/include/core/SkFontMgr.h"
#include "third_party/skia/include/core/SkStream.h"
#include "third_party/skia/include/ports/SkTypeface_win.h"

namespace blink {

WebFontPrewarmer* FontCache::prewarmer_ = nullptr;

// Cached system font metrics.
AtomicString* FontCache::menu_font_family_name_ = nullptr;
int32_t FontCache::menu_font_height_ = 0;
AtomicString* FontCache::small_caption_font_family_name_ = nullptr;
int32_t FontCache::small_caption_font_height_ = 0;
AtomicString* FontCache::status_font_family_name_ = nullptr;
int32_t FontCache::status_font_height_ = 0;

namespace {

int32_t EnsureMinimumFontHeightIfNeeded(int32_t font_height) {
  // Adjustment for codepage 936 to make the fonts more legible in Simplified
  // Chinese.  Please refer to LayoutThemeFontProviderWin.cpp for more
  // information.
  return ((font_height < 12.0f) && (GetACP() == 936)) ? 12.0f : font_height;
}

static const char kChineseSimplified[] = "zh-Hant";

// For Windows out-of-process fallback calls, there is a limiation: only one
// passed locale is taken into account when requesting a fallback font from the
// DWrite API via Skia API. If we request fallback for a Han ideograph without a
// disambiguating locale, results from DWrite are unpredictable and caching such
// a font under the ambiguous locale leads to returning wrong fonts for
// subsequent requests in font_fallback_win, hence prioritize a
// Han-disambiguating locale for CJK characters.
const LayoutLocale* FallbackLocaleForCharacter(
    const FontDescription& font_description,
    const FontFallbackPriority& fallback_priority,
    const UChar32 codepoint) {
  if (IsEmojiPresentationEmoji(fallback_priority)) {
    return LayoutLocale::Get(AtomicString(kColorEmojiLocale));
  } else if (RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled() &&
             IsTextPresentationEmoji(fallback_priority)) {
    return LayoutLocale::Get(AtomicString(kMonoEmojiLocale));
  }

  UErrorCode error_code = U_ZERO_ERROR;
  const UScriptCode char_script = uscript_getScript(codepoint, &error_code);
  if (U_SUCCESS(error_code) && char_script == USCRIPT_HAN) {
    // If we were unable to disambiguate the requested Han ideograph from the
    // content locale, the Accept-Language headers or system locale, assume it's
    // simplified Chinese. It's important to pass a CJK locale to the fallback
    // call in order to avoid priming the browser side cache incorrectly with an
    // ambiguous locale for Han fallback requests.
    const LayoutLocale* han_locale =
        LayoutLocale::LocaleForHan(font_description.Locale());
    return han_locale ? han_locale
                      : LayoutLocale::Get(AtomicString(kChineseSimplified));
  }

  return font_description.Locale() ? font_description.Locale()
                                   : &LayoutLocale::GetDefault();
}

}  // namespace

// static
void FontCache::PrewarmFamily(const AtomicString& family_name) {
  DCHECK(IsMainThread());

  if (!prewarmer_)
    return;

  DEFINE_STATIC_LOCAL(HashSet<AtomicString>, prewarmed_families, ());
  const auto result = prewarmed_families.insert(family_name);
  if (!result.is_new_entry)
    return;

  prewarmer_->PrewarmFamily(family_name);
}

//static
void FontCache::SetSystemFontFamily(const AtomicString&) {
  // TODO(https://crbug.com/808221) Use this instead of
  // SetMenuFontMetrics for the system font family.
  NOTREACHED();
}

// static
const AtomicString& FontCache::SystemFontFamily() {
  return MenuFontFamily();
}

// static
void FontCache::SetMenuFontMetrics(const AtomicString& family_name,
                                   int32_t font_height) {
  menu_font_family_name_ = new AtomicString(family_name);
  menu_font_height_ = EnsureMinimumFontHeightIfNeeded(font_height);
}

// static
void FontCache::SetSmallCaptionFontMetrics(const AtomicString& family_name,
                                           int32_t font_height) {
  small_caption_font_family_name_ = new AtomicString(family_name);
  small_caption_font_height_ = EnsureMinimumFontHeightIfNeeded(font_height);
}

// static
void FontCache::SetStatusFontMetrics(const AtomicString& family_name,
                                     int32_t font_height) {
  status_font_family_name_ = new AtomicString(family_name);
  status_font_height_ = EnsureMinimumFontHeightIfNeeded(font_height);
}

// TODO(https://crbug.com/976737): This function is deprecated and only intended
// to run in parallel with the API based OOP font fallback calls to compare the
// results and track them in UMA for a while until we decide to remove this
// completely.
const SimpleFontData* FontCache::GetFallbackFamilyNameFromHardcodedChoices(
    const FontDescription& font_description,
    UChar32 codepoint,
    FontFallbackPriority fallback_priority) {
  UScriptCode script;
  DCHECK(font_manager_);
  if (const AtomicString fallback_family =
          GetFallbackFamily(codepoint, font_description.GenericFamily(),
                            font_description.Locale(), fallback_priority,
                            *font_manager_, script)) {
    FontFaceCreationParams create_by_family =
        FontFaceCreationParams(fallback_family);
    const FontPlatformData* data =
        GetFontPlatformData(font_description, create_by_family);
    if (data && data->FontContainsCharacter(codepoint)) {
      return FontDataFromFontPlatformData(data);
    }
  }

  // If instantiating the returned fallback family was not successful, probe for
  // a set of potential fonts with wide coverage.

  // Last resort font list : PanUnicode. CJK fonts have a pretty
  // large repertoire. Eventually, we need to scan all the fonts
  // on the system to have a Firefox-like coverage.
  // Make sure that all of them are lowercased.
  const static UChar* const kCjkFonts[] = {
      u"arial unicode ms", u"ms pgothic", u"simsun", u"gulim", u"pmingliu",
      u"wenquanyi zen hei",  // Partial CJK Ext. A coverage but more widely
                             // known to Chinese users.
      u"ar pl shanheisun uni", u"ar pl zenkai uni",
      u"han nom a",  // Complete CJK Ext. A coverage.
      u"code2000"    // Complete CJK Ext. A coverage.
      // CJK Ext. B fonts are not listed here because it's of no use
      // with our current non-BMP character handling because we use
      // Uniscribe for it and that code path does not go through here.
  };

  const static UChar* const kCommonFonts[] = {
      u"tahoma", u"arial unicode ms", u"lucida sans unicode",
      u"microsoft sans serif", u"palatino linotype",
      // Six fonts below (and code2000 at the end) are not from MS, but
      // once installed, cover a very wide range of characters.
      u"dejavu serif", u"dejavu sasns", u"freeserif", u"freesans", u"gentium",
      u"gentiumalt", u"ms pgothic", u"simsun", u"gulim", u"pmingliu",
      u"code2000"};

  const UChar* const* pan_uni_fonts = nullptr;
  int num_fonts = 0;
  if (script == USCRIPT_HAN) {
    pan_uni_fonts = kCjkFonts;
    num_fonts = std::size(kCjkFonts);
  } else {
    pan_uni_fonts = kCommonFonts;
    num_fonts = std::size(kCommonFonts);
  }
  // Font returned from getFallbackFamily may not cover |character|
  // because it's based on script to font mapping. This problem is
  // critical enough for non-Latin scripts (especially Han) to
  // warrant an additional (real coverage) check with fontCotainsCharacter.
  for (int i = 0; i < num_fonts; ++i) {
    FontFaceCreationParams create_by_family =
        FontFaceCreationParams(AtomicString(pan_uni_fonts[i]));
    const FontPlatformData* data =
        GetFontPlatformData(font_description, create_by_family);
    if (data && data->FontContainsCharacter(codepoint))
      return FontDataFromFontPlatformData(data);
  }
  return nullptr;
}

const SimpleFontData* FontCache::GetDWriteFallbackFamily(
    const FontDescription& font_description,
    UChar32 codepoint,
    FontFallbackPriority fallback_priority) {
  const LayoutLocale* fallback_locale = FallbackLocaleForCharacter(
      font_description, fallback_priority, codepoint);
  DCHECK(fallback_locale);

  const std::string family_name = font_description.Family().FamilyName().Utf8();

  Bcp47Vector locales;
  locales.push_back(fallback_locale->LocaleForSkFontMgr());
  sk_sp<SkTypeface> typeface(font_manager_->matchFamilyStyleCharacter(
      family_name.c_str(), font_description.SkiaFontStyle(), locales.data(),
      locales.size(), codepoint));

  if (!typeface) {
    return nullptr;
  }

  SkString skia_family;
  typeface->getFamilyName(&skia_family);
  FontDescription fallback_updated_font_description(font_description);
  fallback_updated_font_description.UpdateFromSkiaFontStyle(
      typeface->fontStyle());
  const FontFaceCreationParams create_by_family(ToAtomicString(skia_family));
  const FontPlatformData* data =
      GetFontPlatformData(fallback_updated_font_description, create_by_family);
  if (!data || !data->FontContainsCharacter(codepoint)) {
    return nullptr;
  }
  return FontDataFromFontPlatformData(data);
}

// Given the desired base font, this will create a SimpleFontData for a specific
// font that can be used to render the given range of characters.
const SimpleFontData* FontCache::PlatformFallbackFontForCharacter(
    const FontDescription& font_description,
    UChar32 character,
    const SimpleFontData* original_font_data,
    FontFallbackPriority fallback_priority) {
  TRACE_EVENT0("ui", "FontCache::PlatformFallbackFontForCharacter");

  // First try the specified font with standard style & weight.
  if (!IsEmojiPresentationEmoji(fallback_priority) &&
      (font_description.Style() == kItalicSlopeValue ||
       font_description.Weight() >= kBoldWeightValue)) {
    const SimpleFontData* font_data =
        FallbackOnStandardFontStyle(font_description, character);
    if (font_data)
      return font_data;
  }

  FontFallbackPriority fallback_priority_with_emoji_text = fallback_priority;
  if (RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled() &&
      fallback_priority == FontFallbackPriority::kText &&
      Character::IsEmoji(character)) {
    fallback_priority_with_emoji_text = FontFallbackPriority::kEmojiText;
  }

  const SimpleFontData* hardcoded_list_fallback_font =
      GetFallbackFamilyNameFromHardcodedChoices(
          font_description, character, fallback_priority_with_emoji_text);

  // Fall through to running the API-based fallback.
  if (RuntimeEnabledFeatures::LegacyWindowsDWriteFontFallbackEnabled() ||
      !hardcoded_list_fallback_font) {
    return GetDWriteFallbackFamily(font_description, character,
                                   fallback_priority_with_emoji_text);
  }

  return hardcoded_list_fallback_font;
}

static inline bool DeprecatedEqualIgnoringCase(const AtomicString& a,
                                               const SkString& b) {
  return DeprecatedEqualIgnoringCase(a, ToAtomicString(b));
}

static bool TypefacesMatchesFamily(const SkTypeface* tf,
                                   const AtomicString& family) {
  SkTypeface::LocalizedStrings* actual_families =
      tf->createFamilyNameIterator();
  bool matches_requested_family = false;
  SkTypeface::LocalizedString actual_family;

  while (actual_families->next(&actual_family)) {
    if (DeprecatedEqualIgnoringCase(family, actual_family.fString)) {
      matches_requested_family = true;
      break;
    }
  }
  actual_families->unref();

  // getFamilyName may return a name not returned by the
  // createFamilyNameIterator.
  // Specifically in cases where Windows substitutes the font based on the
  // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes registry
  // entries.
  if (!matches_requested_family) {
    SkString family_name;
    tf->getFamilyName(&family_name);
    if (DeprecatedEqualIgnoringCase(family, family_name))
      matches_requested_family = true;
  }

  return matches_requested_family;
}

static bool TypefacesHasWeightSuffix(const AtomicString& family,
                                     AtomicString& adjusted_name,
                                     FontSelectionValue& variant_weight) {
  struct FamilyWeightSuffix {
    const UChar* suffix;
    wtf_size_t length;
    FontSelectionValue weight;
  };
  // Mapping from suffix to weight from the DirectWrite documentation.
  // http://msdn.microsoft.com/en-us/library/windows/desktop/dd368082.aspx
  const static FamilyWeightSuffix kVariantForSuffix[] = {
      {u" thin", 5, FontSelectionValue(100)},
      {u" extralight", 11, FontSelectionValue(200)},
      {u" ultralight", 11, FontSelectionValue(200)},
      {u" light", 6, FontSelectionValue(300)},
      {u" regular", 8, FontSelectionValue(400)},
      {u" medium", 7, FontSelectionValue(500)},
      {u" demibold", 9, FontSelectionValue(600)},
      {u" semibold", 9, FontSelectionValue(600)},
      {u" extrabold", 10, FontSelectionValue(800)},
      {u" ultrabold", 10, FontSelectionValue(800)},
      {u" black", 6, FontSelectionValue(900)},
      {u" heavy", 6, FontSelectionValue(900)}};
  size_t num_variants = std::size(kVariantForSuffix);
  for (size_t i = 0; i < num_variants; i++) {
    const FamilyWeightSuffix& entry = kVariantForSuffix[i];
    if (family.EndsWith(entry.suffix, kTextCaseUnicodeInsensitive)) {
      String family_name = family.GetString();
      family_name.Truncate(family.length() - entry.length);
      adjusted_name = AtomicString(family_name);
      variant_weight = entry.weight;
      return true;
    }
  }

  return false;
}

static bool TypefacesHasStretchSuffix(const AtomicString& family,
                                      AtomicString& adjusted_name,
                                      FontSelectionValue& variant_stretch) {
  struct FamilyStretchSuffix {
    const UChar* suffix;
    wtf_size_t length;
    FontSelectionValue stretch;
  };
  // Mapping from suffix to stretch value from the DirectWrite documentation.
  // http://msdn.microsoft.com/en-us/library/windows/desktop/dd368078.aspx
  // Also includes Narrow as a synonym for Condensed to to support Arial
  // Narrow and other fonts following the same naming scheme.
  const static FamilyStretchSuffix kVariantForSuffix[] = {
      {u" ultracondensed", 15, kUltraCondensedWidthValue},
      {u" extracondensed", 15, kExtraCondensedWidthValue},
      {u" condensed", 10, kCondensedWidthValue},
      {u" narrow", 7, kCondensedWidthValue},
      {u" semicondensed", 14, kSemiCondensedWidthValue},
      {u" semiexpanded", 13, kSemiExpandedWidthValue},
      {u" expanded", 9, kExpandedWidthValue},
      {u" extraexpanded", 14, kExtraExpandedWidthValue},
      {u" ultraexpanded", 14, kUltraExpandedWidthValue}};
  size_t num_variants = std::size(kVariantForSuffix);
  for (size_t i = 0; i < num_variants; i++) {
    const FamilyStretchSuffix& entry = kVariantForSuffix[i];
    if (family.EndsWith(entry.suffix, kTextCaseUnicodeInsensitive)) {
      String family_name = family.GetString();
      family_name.Truncate(family.length() - entry.length);
      adjusted_name = AtomicString(family_name);
      variant_stretch = entry.stretch;
      return true;
    }
  }

  return false;
}

const FontPlatformData* FontCache::CreateFontPlatformData(
    const FontDescription& font_description,
    const FontFaceCreationParams& creation_params,
    float font_size,
    AlternateFontName alternate_font_name) {
  TRACE_EVENT0("ui", "FontCache::CreateFontPlatformData");

  DCHECK_EQ(creation_params.CreationType(), kCreateFontByFamily);
  sk_sp<SkTypeface> typeface;

  std::string name;

  if (alternate_font_name == AlternateFontName::kLocalUniqueFace &&
      RuntimeEnabledFeatures::FontSrcLocalMatchingEnabled()) {
    typeface = CreateTypefaceFromUniqueName(creation_params);

    // We do not need to try any heuristic around the font name, as below, for
    // family matching.
    if (!typeface)
      return nullptr;

  } else {
    typeface = CreateTypeface(font_description, creation_params, name);

    // For a family match, Windows will always give us a valid pointer here,
    // even if the face name is non-existent. We have to double-check and see if
    // the family name was really used.
    if (!typeface ||
        !TypefacesMatchesFamily(typeface.get(), creation_params.Family())) {
      AtomicString adjusted_name;
      FontSelectionValue variant_weight;
      FontSelectionValue variant_stretch;

      // TODO: crbug.com/627143 LocalFontFaceSource.cpp, which implements
      // retrieving src: local() font data uses getFontData, which in turn comes
      // here, to retrieve fonts from the cache and specifies the argument to
      // local() as family name. So we do not match by full font name or
      // postscript name as the spec says:
      // https://drafts.csswg.org/css-fonts-3/#src-desc

      // Prevent one side effect of the suffix translation below where when
      // matching local("Roboto Regular") it tries to find the closest match
      // even though that can be a bold font in case of Roboto Bold.
      if (alternate_font_name == AlternateFontName::kLocalUniqueFace) {
        return nullptr;
      }

      if (alternate_font_name == AlternateFontName::kLastResort) {
        if (!typeface)
          return nullptr;
      } else if (TypefacesHasWeightSuffix(creation_params.Family(),
                                          adjusted_name, variant_weight)) {
        FontFaceCreationParams adjusted_params(adjusted_name);
        FontDescription adjusted_font_description = font_description;
        adjusted_font_description.SetWeight(variant_weight);
        typeface =
            CreateTypeface(adjusted_font_description, adjusted_params, name);
        if (!typeface ||
            !TypefacesMatchesFamily(typeface.get(), adjusted_name)) {
          return nullptr;
        }

      } else if (TypefacesHasStretchSuffix(creation_params.Family(),
                                           adjusted_name, variant_stretch)) {
        FontFaceCreationParams adjusted_params(adjusted_name);
        FontDescription adjusted_font_description = font_description;
        adjusted_font_description.SetStretch(variant_stretch);
        typeface =
            CreateTypeface(adjusted_font_description, adjusted_params, name);
        if (!typeface ||
            !TypefacesMatchesFamily(typeface.get(), adjusted_name)) {
          return nullptr;
        }
      } else {
        return nullptr;
      }
    }
  }

  bool synthetic_bold_requested =
      (font_description.Weight() >= kBoldThreshold && !typeface->isBold()) ||
      font_description.IsSyntheticBold();

  bool synthetic_italic_requested =
      ((font_description.Style() == kItalicSlopeValue) &&
       !typeface->isItalic()) ||
      font_description.IsSyntheticItalic();

  FontPlatformData* result = MakeGarbageCollected<FontPlatformData>(
      typeface, name.data(), font_size,
      synthetic_bold_requested && font_description.SyntheticBoldAllowed(),
      synthetic_italic_requested && font_description.SyntheticItalicAllowed(),
      font_description.TextRendering(), ResolvedFontFeatures(),
      font_description.Orientation());

  result->SetAvoidEmbeddedBitmaps(
      BitmapGlyphsBlockList::ShouldAvoidEmbeddedBitmapsForTypeface(*typeface));

  return result;
}

}  // namespace blink
```