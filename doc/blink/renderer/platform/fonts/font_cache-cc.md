Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The goal is to analyze the `font_cache.cc` file in Blink and describe its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples, demonstrate logical reasoning with input/output, and highlight common usage errors.

2. **Initial Skim and Keyword Spotting:**  I quickly scan the code for important terms and concepts: `FontCache`, `FontDescription`, `FontPlatformData`, `SimpleFontData`, `SkFontMgr`, `ShapeCache`, `Fallback`, `GetFontPlatformData`, `GetFontData`, `Invalidate`,  `SystemFontFamily`, and includes like `third_party/blink/public/common/features.h`. This gives me a high-level idea of the file's purpose – managing fonts.

3. **Identify Key Functionality Areas:** Based on the skim, I categorize the functionalities:
    * **Font Loading and Management:**  This is central. Keywords like `GetFontPlatformData`, `GetFontData`, `SetFontManager`, and the interaction with `SkFontMgr` point to this.
    * **Caching:** The name `FontCache` itself suggests caching. I look for data structures used for storage (`font_platform_data_cache_`, `font_data_cache_`, `fallback_list_shaper_cache_`).
    * **Fallback Mechanism:** The presence of `FallbackFontForCharacter`, `FontFallbackMap`, and mentions of emoji locales indicate this.
    * **Invalidation and Purging:**  Methods like `Invalidate`, `Purge`, and the `FontCacheClient` point to managing the cache's lifecycle.
    * **System Fonts:**  `SystemFontPlatformData` and `SystemFontFamily` are relevant here.
    * **Shape Caching:** `ShapeCache` and related methods are important for text rendering optimization.
    * **Configuration/Features:** Includes of feature flags and conditional compilation (`#if BUILDFLAG`) indicate configurable behavior.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where I connect the backend code to frontend concepts:
    * **CSS:** Font properties in CSS (`font-family`, `font-weight`, `font-style`, `font-size`) directly influence the `FontDescription` objects created and used by the cache. The `families` string in `FirstAvailableOrFirst` relates to the order of font families specified in CSS.
    * **HTML:** The content of HTML elements is what gets rendered using these fonts. The fallback mechanism is crucial when characters in the HTML don't exist in the specified font.
    * **JavaScript:** While JavaScript doesn't directly interact with `FontCache` at this low level, it can indirectly influence it by manipulating the DOM and CSS, which in turn triggers font loading and rendering. APIs like `document.fonts` (though not directly in this file) are related.

5. **Construct Examples:** For each relationship, I create concrete examples:
    * **CSS:** A simple CSS rule showing how `font-family` affects font loading.
    * **HTML:** An example demonstrating the need for fallback when a character isn't in the primary font.

6. **Logical Reasoning (Input/Output):**  I think about the flow of data:
    * **Input:** A `FontDescription` object (derived from CSS), a character code.
    * **Processing:** The `FontCache` searches its caches, interacts with the font manager (`SkFontMgr`), and applies fallback logic.
    * **Output:** A `SimpleFontData` object, which contains the actual font data to render the character.

7. **Identify Common Usage Errors (from a developer perspective, even though it's internal code):**  I consider scenarios where things might go wrong or be inefficient:
    * **Incorrect Font Family Names:**  Typos in CSS `font-family`.
    * **Missing Font Files:**  Requesting a font that's not installed on the user's system.
    * **Excessive Font Variations:** Using too many different weights and styles can increase memory usage.
    * **Performance Issues:**  Inefficient cache invalidation or lack of proper font hinting.

8. **Structure the Answer:** I organize the information logically:
    * Start with a clear summary of the file's purpose.
    * Detail the key functionalities.
    * Explain the relationship with web technologies with examples.
    * Provide the input/output example.
    * List common usage errors.
    * Briefly mention any logical reasoning within the code (like the locale prioritization for font lookup).

9. **Refine and Elaborate:** I go back through my initial thoughts and add more detail and context where needed, explaining technical terms and ensuring clarity. For instance, clarifying the role of `SkFontMgr`. I also make sure to address all parts of the original request.

This iterative process of skimming, categorizing, connecting, exemplifying, reasoning, and structuring helps me build a comprehensive and accurate answer to the request. The focus is on explaining the *what*, *why*, and *how* of the `font_cache.cc` file in relation to its role in a web browser.
这是一个位于 Chromium Blink 渲染引擎中的 `font_cache.cc` 文件。它的核心功能是**管理和缓存字体数据**，以提高网页渲染的效率。  它负责查找、加载、存储和提供字体信息，使得 Blink 引擎能够快速地找到并使用所需的字体来渲染文本。

下面详细列举一下它的功能，并说明它与 JavaScript、HTML、CSS 的关系，以及一些逻辑推理和常见错误：

**功能列举:**

1. **字体数据缓存:** 这是 `FontCache` 的主要功能。它缓存了已经加载过的字体数据（`SimpleFontData` 和 `FontPlatformData`），避免了重复加载相同的字体，从而提高了性能。
    * `font_platform_data_cache_`:  缓存平台相关的字体数据，例如特定操作系统上的字体句柄。
    * `font_data_cache_`: 缓存经过处理的、可供 Blink 使用的字体数据。
    * `fallback_list_shaper_cache_`: 缓存 fallback 字体列表的 shaping 结果，用于优化复杂文本的渲染。

2. **字体查找与加载:**  当需要渲染文本时，`FontCache` 负责根据 `FontDescription`（包含了字体族、字重、字号等信息）查找相应的字体数据。如果缓存中没有，它会调用底层的平台相关的接口来加载字体。
    * `GetFontPlatformData()`:  根据 `FontDescription` 和 `FontFaceCreationParams` (描述了如何创建字体，例如通过字体族名或唯一名称) 获取平台相关的字体数据。
    * 与 `SkFontMgr` 交互：`FontCache` 使用 Skia 图形库的 `SkFontMgr` 来管理和访问系统字体。

3. **字体回退 (Fallback):**  当指定的字体中缺少某个字符时，`FontCache` 负责查找并使用备用字体来显示该字符。
    * `FallbackFontForCharacter()`:  根据字符和优先级，查找合适的备用字体。
    * `FontFallbackMap`:  维护字体回退的规则和映射关系。

4. **系统字体管理:**  `FontCache` 可以获取和使用系统默认字体。
    * `SystemFontPlatformData()`: 获取系统默认字体的平台数据。

5. **Shape 缓存管理:**  为了优化复杂文本的渲染（例如包含连字、组合字符的文本），`FontCache` 缓存了文本 shaping 的结果。
    * `GetShapeCache()`: 获取指定 fallback 列表对应的 shape 缓存。
    * `PurgeFallbackListShaperCache()`: 清理 shape 缓存。

6. **缓存失效与清理:**  当字体相关的系统设置发生变化时，`FontCache` 需要失效其缓存，以确保使用最新的字体信息。
    * `Invalidate()`:  失效字体缓存，并通知相关的客户端。
    * `Purge()`:  清理缓存。

7. **性能监控:**  `FontCache` 包含一些用于性能监控的代码，例如记录字体回退的时间。

8. **支持特定语言环境:**  `FontCache` 考虑了语言环境 (locale) 对字体选择的影响，例如为 Emoji 提供特定的字体。
    * `GetBcp47LocaleForRequest()`:  根据 `FontDescription` 和优先级获取 BCP 47 语言代码列表，用于 Skia 的字体查找。

9. **预加载系统字体 (可选):**  在某些情况下，`FontCache` 可以预先加载一些常用的系统字体，进一步提高性能。

**与 JavaScript, HTML, CSS 的关系:**

`FontCache` 位于渲染引擎的底层，与前端技术 (JavaScript, HTML, CSS) 的交互是间接的，但至关重要。

* **CSS:**
    * **`font-family` 属性:**  CSS 的 `font-family` 属性指定了要使用的字体族。当浏览器解析到这个属性时，会创建 `FontDescription` 对象，并调用 `FontCache` 来查找或加载相应的字体。
    * **`font-weight`, `font-style`, `font-size` 等属性:** 这些属性也会影响 `FontDescription` 的创建，从而影响 `FontCache` 的查找过程。
    * **`@font-face` 规则:**  `@font-face` 允许网页嵌入自定义字体。`FontCache` 负责加载和管理这些自定义字体。

    **举例:**

    ```css
    /* CSS 规则 */
    .my-text {
      font-family: "Arial", "Helvetica", sans-serif;
      font-weight: bold;
      font-size: 16px;
    }
    ```

    当浏览器渲染应用了上述 CSS 规则的 HTML 元素时，`FontCache` 会：
    1. 根据 `font-family` 的顺序，尝试查找 "Arial"。如果找到，就使用 "Arial" 的粗体、16px 版本。
    2. 如果 "Arial" 不存在，则尝试查找 "Helvetica"。
    3. 如果 "Helvetica" 也不存在，则使用默认的 sans-serif 字体。

* **HTML:**
    * HTML 元素的内容需要用字体来渲染。`FontCache` 提供的字体数据最终用于将文本绘制到屏幕上。

    **举例:**

    ```html
    <!-- HTML 元素 -->
    <p class="my-text">This is some text.</p>
    ```

    `FontCache` 负责提供 "This is some text." 这段文本所需要的字体信息，以便浏览器能够正确显示它。

* **JavaScript:**
    * JavaScript 通常不直接操作 `FontCache`。
    * JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改可能会触发 `FontCache` 的操作。例如，通过 JavaScript 动态地改变元素的 `font-family`，会导致 `FontCache` 查找新的字体。
    * `document.fonts` API (虽然不在 `font_cache.cc` 中实现) 允许 JavaScript 查询和加载字体，这与 `FontCache` 的功能相关。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **`FontDescription` 对象:**  指定了字体族为 "MyCustomFont"，字重为 700 (bold)，字号为 18px。
2. **待渲染的字符:**  Unicode 字符 U+4E00 (一个汉字)。

**处理过程 (逻辑推理):**

1. `FontCache::GetFontData()` 被调用，传入 `FontDescription` 和字体族名 "MyCustomFont"。
2. `FontCache` 首先检查其缓存 (`font_data_cache_`) 是否已经存在 "MyCustomFont" 的粗体、18px 版本的数据。
3. 如果缓存未命中，`FontCache::GetFontPlatformData()` 被调用，尝试获取平台相关的 "MyCustomFont" 的字体数据。
4. 如果平台字体数据也未找到，但 CSS 中可能通过 `@font-face` 定义了 "MyCustomFont"，`FontCache` 可能会尝试加载该自定义字体。
5. 如果 "MyCustomFont" 最终无法找到，且字符 U+4E00 不在默认字体中，`FontCache::FallbackFontForCharacter()` 将被调用。
6. `FallbackFontForCharacter()` 会根据预定义的规则和优先级，查找能够显示 U+4E00 的备用字体（例如，系统中的中文字体）。
7. 最终，`FontCache` 返回一个 `SimpleFontData` 对象，其中包含了用于渲染字符 U+4E00 的字体数据（可能是 "MyCustomFont" 的数据，也可能是备用字体的数据）。

**假设输出:**

一个指向 `SimpleFontData` 对象的指针，该对象包含了可以渲染字符 U+4E00 的字体数据。这个 `SimpleFontData` 对象可能来自 "MyCustomFont" 或者一个合适的 fallback 字体。

**涉及用户或者编程常见的使用错误:**

1. **CSS 中指定了不存在的字体族名:**

   ```css
   .my-element {
     font-family: "NonExistentFont";
   }
   ```

   **结果:**  `FontCache` 无法找到 "NonExistentFont"，最终会使用浏览器默认的字体或者 CSS 中指定的 fallback 字体。用户可能看到与预期不同的字体。

2. **自定义字体文件路径错误 (在使用 `@font-face` 时):**

   ```css
   @font-face {
     font-family: "MyCustomFont";
     src: url("fonts/MyCustomFont.woff2"); /* 路径可能不正确 */
   }
   ```

   **结果:**  `FontCache` 无法加载字体文件，导致使用该自定义字体的文本无法正确显示，可能会回退到其他字体。

3. **使用过多的字体变体 (weights/styles):**

   ```css
   .text-bold { font-weight: bold; }
   .text-italic { font-style: italic; }
   /* ... 更多变体 ... */
   ```

   **结果:**  `FontCache` 需要加载和缓存更多的字体数据，可能增加内存消耗和加载时间。

4. **在不支持某些 Unicode 字符的字体中尝试显示这些字符:**

   ```css
   .emoji-text { font-family: "Arial"; }
   ```

   **结果:**  如果 "Arial" 字体不包含某些 Emoji 字符，`FontCache` 会触发字体回退机制，寻找包含这些 Emoji 的字体来显示。用户看到的可能是不同的 Emoji 样式，取决于回退到的字体。

5. **频繁地动态修改元素的 `font-family`:**

   ```javascript
   // JavaScript 代码
   const element = document.getElementById('my-element');
   setInterval(() => {
     element.style.fontFamily = Math.random() > 0.5 ? 'Arial' : 'Verdana';
   }, 100);
   ```

   **结果:**  `FontCache` 需要频繁地查找和加载不同的字体，可能导致性能下降和不必要的资源消耗。

总而言之，`blink/renderer/platform/fonts/font_cache.cc` 是 Blink 引擎中负责高效管理和提供字体信息的关键组件，它直接影响着网页文本的渲染效果和性能。理解它的功能有助于开发者更好地理解浏览器如何处理字体，并避免一些常见的与字体相关的错误。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/font_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2006, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Nicholas Shanks <webkit@nickshanks.com>
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

#include "third_party/blink/renderer/platform/fonts/font_cache.h"

#include <limits>
#include <memory>

#include "base/debug/alias.h"
#include "base/feature_list.h"
#include "base/strings/escape.h"
#include "base/system/sys_info.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "skia/ext/font_utils.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/alternate_font_family.h"
#include "third_party/blink/renderer/platform/fonts/font_cache_client.h"
#include "third_party/blink/renderer/platform/fonts/font_data_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_map.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_priority.h"
#include "third_party/blink/renderer/platform/fonts/font_global_context.h"
#include "third_party/blink/renderer/platform/fonts/font_performance.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_unique_name_lookup.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/web_memory_allocator_dump.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/web_process_memory_dump.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/font_list.h"

#if BUILDFLAG(IS_WIN)
#include "third_party/skia/include/ports/SkTypeface_win.h"
#endif

namespace blink {

const char kColorEmojiLocale[] = "und-Zsye";
const char kMonoEmojiLocale[] = "und-Zsym";

#if BUILDFLAG(IS_ANDROID)
extern const char kNotoColorEmojiCompat[] = "Noto Color Emoji Compat";
#endif

SkFontMgr* FontCache::static_font_manager_ = nullptr;

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
float FontCache::device_scale_factor_ = 1.0;
#endif

#if BUILDFLAG(IS_WIN)
bool FontCache::antialiased_text_enabled_ = false;
bool FontCache::lcd_text_enabled_ = false;
static bool should_use_test_font_mgr = false;
#endif  // BUILDFLAG(IS_WIN)

FontCache& FontCache::Get() {
  return FontGlobalContext::GetFontCache();
}

FontCache::FontCache() : font_manager_(sk_ref_sp(static_font_manager_)) {
#if BUILDFLAG(IS_WIN)
  if (!font_manager_ || should_use_test_font_mgr) {
    // This code path is only for unit tests. This SkFontMgr does not work in
    // sandboxed environments, but injecting this initialization code to all
    // unit tests isn't easy.
    font_manager_ = SkFontMgr_New_DirectWrite();
    // Set |is_test_font_mgr_| to capture if this is not happening in the
    // production code. crbug.com/561873
    is_test_font_mgr_ = true;

    // Tests[1][2] construct |FontCache| without |static_font_manager|, but
    // these tests install font manager with dwrite proxy even if they don't
    // have remote end in browser.
    // [1] HtmlBasedUsernameDetectorTest.UserGroupAttributes
    // [2] RenderViewImplTest.OnDeleteSurroundingTextInCodePoints
    should_use_test_font_mgr = true;
  }
  DCHECK(font_manager_.get());
#endif
}

FontCache::~FontCache() = default;

void FontCache::Trace(Visitor* visitor) const {
  visitor->Trace(font_cache_clients_);
  visitor->Trace(font_platform_data_cache_);
  visitor->Trace(fallback_list_shaper_cache_);
  visitor->Trace(font_data_cache_);
  visitor->Trace(font_fallback_map_);
}

#if !BUILDFLAG(IS_MAC)
const FontPlatformData* FontCache::SystemFontPlatformData(
    const FontDescription& font_description) {
  const AtomicString& family = FontCache::SystemFontFamily();
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_FUCHSIA) || \
    BUILDFLAG(IS_IOS)
  if (family.empty() || family == font_family_names::kSystemUi)
    return nullptr;
#else
  DCHECK(!family.empty() && family != font_family_names::kSystemUi);
#endif
  return GetFontPlatformData(font_description, FontFaceCreationParams(family),
                             AlternateFontName::kNoAlternate);
}
#endif

const FontPlatformData* FontCache::GetFontPlatformData(
    const FontDescription& font_description,
    const FontFaceCreationParams& creation_params,
    AlternateFontName alternate_font_name) {
  TRACE_EVENT0("fonts", "FontCache::GetFontPlatformData");

  if (!platform_init_) {
    platform_init_ = true;
    PlatformInit();
  }

#if !BUILDFLAG(IS_MAC)
  if (creation_params.CreationType() == kCreateFontByFamily &&
      creation_params.Family() == font_family_names::kSystemUi) {
    return SystemFontPlatformData(font_description);
  }
#endif

  return font_platform_data_cache_.GetOrCreateFontPlatformData(
      this, font_description, creation_params, alternate_font_name);
}

ShapeCache* FontCache::GetShapeCache(const FallbackListCompositeKey& key) {
  auto result = fallback_list_shaper_cache_.insert(key, nullptr);
  if (result.is_new_entry) {
    result.stored_value->value = MakeGarbageCollected<ShapeCache>();
  }
  return result.stored_value->value.Get();
}

void FontCache::SetFontManager(sk_sp<SkFontMgr> font_manager) {
  DCHECK(!static_font_manager_);
  static_font_manager_ = font_manager.release();
}

void FontCache::AcceptLanguagesChanged(const String& accept_languages) {
  LayoutLocale::AcceptLanguagesChanged(accept_languages);
  Get().InvalidateShapeCache();
}

const SimpleFontData* FontCache::GetFontData(
    const FontDescription& font_description,
    const AtomicString& family,
    AlternateFontName altername_font_name) {
  if (const FontPlatformData* platform_data = GetFontPlatformData(
          font_description,
          FontFaceCreationParams(
              AdjustFamilyNameToAvoidUnsupportedFonts(family)),
          altername_font_name)) {
    return FontDataFromFontPlatformData(
        platform_data, font_description.SubpixelAscentDescent());
  }

  return nullptr;
}

const SimpleFontData* FontCache::FontDataFromFontPlatformData(
    const FontPlatformData* platform_data,
    bool subpixel_ascent_descent) {
  return font_data_cache_.Get(platform_data, subpixel_ascent_descent);
}

bool FontCache::IsPlatformFamilyMatchAvailable(
    const FontDescription& font_description,
    const AtomicString& family) {
  return GetFontPlatformData(
      font_description,
      FontFaceCreationParams(AdjustFamilyNameToAvoidUnsupportedFonts(family)),
      AlternateFontName::kNoAlternate);
}

bool FontCache::IsPlatformFontUniqueNameMatchAvailable(
    const FontDescription& font_description,
    const AtomicString& unique_font_name) {
  return GetFontPlatformData(font_description,
                             FontFaceCreationParams(unique_font_name),
                             AlternateFontName::kLocalUniqueFace);
}

String FontCache::FirstAvailableOrFirst(const String& families) {
  // The conversions involve at least two string copies, and more if non-ASCII.
  // For now we prefer shared code over the cost because a) inputs are
  // only from grd/xtb and all ASCII, and b) at most only a few times per
  // setting change/script.
  return String::FromUTF8(
      gfx::FontList::FirstAvailableOrFirst(families.Utf8().c_str()));
}

const SimpleFontData* FontCache::FallbackFontForCharacter(
    const FontDescription& description,
    UChar32 lookup_char,
    const SimpleFontData* font_data_to_substitute,
    FontFallbackPriority fallback_priority) {
  TRACE_EVENT0("fonts", "FontCache::FallbackFontForCharacter");

  // In addition to PUA, do not perform fallback for non-characters either. Some
  // of these are sentinel characters to detect encodings and do appear on
  // websites. More details on
  // http://www.unicode.org/faq/private_use.html#nonchar1 - See also
  // crbug.com/862352 where performing fallback for U+FFFE causes a memory
  // regression.
  if (Character::IsPrivateUse(lookup_char) ||
      Character::IsNonCharacter(lookup_char))
    return nullptr;
  base::ElapsedTimer timer;
  const SimpleFontData* result = PlatformFallbackFontForCharacter(
      description, lookup_char, font_data_to_substitute, fallback_priority);
  FontPerformance::AddSystemFallbackFontTime(timer.Elapsed());
  return result;
}

void FontCache::PurgeFallbackListShaperCache() {
  TRACE_EVENT0("fonts,ui", "FontCache::PurgeFallbackListShaperCache");
  for (auto& shape_cache : fallback_list_shaper_cache_.Values()) {
    shape_cache->Clear();
  }
}

void FontCache::InvalidateShapeCache() {
  PurgeFallbackListShaperCache();
}

void FontCache::Purge() {
  // Ideally we should never be forcing the purge while the
  // FontCachePurgePreventer is in scope, but we call purge() at any timing
  // via MemoryPressureListenerRegistry.
  if (purge_prevent_count_)
    return;

  PurgeFallbackListShaperCache();
}

void FontCache::AddClient(FontCacheClient* client) {
  CHECK(client);
  DCHECK(!font_cache_clients_.Contains(client));
  font_cache_clients_.insert(client);
}

uint16_t FontCache::Generation() {
  return generation_;
}

void FontCache::Invalidate() {
  TRACE_EVENT0("fonts,ui", "FontCache::Invalidate");
  font_platform_data_cache_.Clear();
  font_data_cache_.Clear();
  generation_++;

  for (const auto& client : font_cache_clients_) {
    client->FontCacheInvalidated();
  }

  Purge();
}

void FontCache::CrashWithFontInfo(const FontDescription* font_description) {
  SkFontMgr* font_mgr = nullptr;
  int num_families = std::numeric_limits<int>::min();
  bool is_test_font_mgr = false;
  if (FontGlobalContext::TryGet()) {
    FontCache& font_cache = FontGlobalContext::GetFontCache();
#if BUILDFLAG(IS_WIN)
    is_test_font_mgr = font_cache.is_test_font_mgr_;
#endif
    font_mgr = font_cache.font_manager_.get();
    if (font_mgr)
      num_families = font_mgr->countFamilies();
  }

  // In production, these 3 font managers must match.
  // They don't match in unit tests or in single process mode.
  SkFontMgr* static_font_mgr = static_font_manager_;
  SkFontMgr* skia_default_font_mgr = skia::DefaultFontMgr().get();
  base::debug::Alias(&font_mgr);
  base::debug::Alias(&static_font_mgr);
  base::debug::Alias(&skia_default_font_mgr);

  FontDescription font_description_copy = *font_description;
  base::debug::Alias(&font_description_copy);
  base::debug::Alias(&is_test_font_mgr);
  base::debug::Alias(&num_families);

  CHECK(false);
}

void FontCache::DumpShapeResultCache(
    base::trace_event::ProcessMemoryDump* memory_dump) {
  DCHECK(IsMainThread());
  base::trace_event::MemoryAllocatorDump* dump =
      memory_dump->CreateAllocatorDump("font_caches/shape_caches");
  size_t shape_result_cache_size = 0;
  for (const auto& shape_cache : fallback_list_shaper_cache_.Values()) {
    shape_result_cache_size += shape_cache->ByteSize();
  }
  dump->AddScalar("size", "bytes", shape_result_cache_size);
  memory_dump->AddSuballocation(dump->guid(),
                                WTF::Partitions::kAllocatedObjectPoolName);
}

sk_sp<SkTypeface> FontCache::CreateTypefaceFromUniqueName(
    const FontFaceCreationParams& creation_params) {
  FontUniqueNameLookup* unique_name_lookup =
      FontGlobalContext::Get().GetFontUniqueNameLookup();
  DCHECK(unique_name_lookup);
  sk_sp<SkTypeface> uniquely_identified_font =
      unique_name_lookup->MatchUniqueName(creation_params.Family());
  if (uniquely_identified_font) {
    return uniquely_identified_font;
  }
  return nullptr;
}

// static
FontCache::Bcp47Vector FontCache::GetBcp47LocaleForRequest(
    const FontDescription& font_description,
    FontFallbackPriority fallback_priority) {
  Bcp47Vector result;

  // Fill in the list of locales in the reverse priority order.
  // Skia expects the highest array index to be the first priority.
  const LayoutLocale* content_locale = font_description.Locale();
  if (const LayoutLocale* han_locale =
          LayoutLocale::LocaleForHan(content_locale)) {
    result.push_back(han_locale->LocaleForHanForSkFontMgr());
  }
  result.push_back(LayoutLocale::GetDefault().LocaleForSkFontMgr());
  if (content_locale)
    result.push_back(content_locale->LocaleForSkFontMgr());

  if (IsEmojiPresentationEmoji(fallback_priority)) {
    result.push_back(kColorEmojiLocale);
  } else if (IsTextPresentationEmoji(fallback_priority)) {
    result.push_back(kMonoEmojiLocale);
  }
  return result;
}

// TODO(crbug/342967843): In WebTest, Fuchsia initializes fonts by calling
// `skia::InitializeSkFontMgrForTest();` expecting that other code doesn't
// initialize SkFontMgr beforehand. But `FontCache::MaybePreloadSystemFonts()`
// breaks this expectation. So we don't provide
// `FontCache::MaybePreloadSystemFonts()` feature for Fuchsia for now.
#if BUILDFLAG(IS_FUCHSIA)
// static
void FontCache::MaybePreloadSystemFonts() {}
#else
// static
void FontCache::MaybePreloadSystemFonts() {
  static bool initialized = false;
  if (initialized) {
    return;
  }

  initialized = true;
  CHECK(IsMainThread());

  if (!base::FeatureList::IsEnabled(features::kPreloadSystemFonts)) {
    return;
  }

  const int kPhysicalMemoryGB =
      base::SysInfo::AmountOfPhysicalMemoryMB() / 1024;

  if (kPhysicalMemoryGB < features::kPreloadSystemFontsRequiredMemoryGB.Get()) {
    return;
  }

  std::unique_ptr<JSONArray> targets =
      JSONArray::From(ParseJSON(String::FromUTF8(
          base::UnescapeURLComponent(features::kPreloadSystemFontsTargets.Get(),
                                     base::UnescapeRule::SPACES))));

  if (!targets) {
    return;
  }

  const LayoutLocale& locale = LayoutLocale::GetDefault();

  for (wtf_size_t i = 0; i < targets->size(); ++i) {
    JSONObject* target = JSONObject::Cast(targets->at(i));
    bool success = true;
    String family;
    success &= target->GetString("family", &family);
    int weight;
    success &= target->GetInteger("weight", &weight);
    double specified_size;
    success &= target->GetDouble("size", &specified_size);
    double computed_size;
    success &= target->GetDouble("csize", &computed_size);
    String text;
    success &= target->GetString("text", &text);
    if (success) {
      TRACE_EVENT("fonts", "PreloadSystemFonts", "family", family, "weight",
                  weight, "specified_size", specified_size, "computed_size",
                  computed_size, "text", text);
      FontDescription font_description;
      const AtomicString family_atomic_string(family);
      FontFamily font_family(family_atomic_string,
                             FontFamily::Type::kFamilyName);
      font_description.SetFamily(font_family);
      font_description.SetWeight(FontSelectionValue(weight));
      font_description.SetLocale(&locale);
      font_description.SetSpecifiedSize(
          base::saturated_cast<float>(specified_size));
      font_description.SetComputedSize(
          base::saturated_cast<float>(computed_size));
      font_description.SetGenericFamily(FontDescription::kSansSerifFamily);
      const SimpleFontData* simple_font_data =
          FontCache::Get().GetFontData(font_description, AtomicString(family));
      if (simple_font_data) {
        for (UChar32 c : text) {
          Glyph glyph = simple_font_data->GlyphForCharacter(c);
          std::ignore = simple_font_data->BoundsForGlyph(glyph);
        }
      }
    }
  }
}
#endif  // BUILDFLAG(IS_FUCHSIA)

FontFallbackMap& FontCache::GetFontFallbackMap() {
  if (!font_fallback_map_) {
    font_fallback_map_ = MakeGarbageCollected<FontFallbackMap>(nullptr);
    AddClient(font_fallback_map_);
  }
  return *font_fallback_map_;
}

}  // namespace blink

"""

```