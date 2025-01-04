Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for an explanation of the `harfbuzz_face.cc` file, its functionalities, relationships to web technologies, potential for logical errors, and common usage mistakes.

2. **Identify Key Areas:**  Based on the request and the file's name, the core areas to focus on are:
    * HarfBuzz integration.
    * Font handling.
    * Potential connections to JavaScript, HTML, and CSS.
    * Logic within the code.
    * Potential user/programmer errors.

3. **Initial Code Scan (High-Level):**  Read through the code, noting the included headers and namespaces. This provides a preliminary understanding of the technologies involved.
    * `<hb.h>`, `<hb-cplusplus.hh>`, `<hb-ot.h>` clearly indicate HarfBuzz usage for text shaping.
    * Headers like `FontCache.h`, `FontPlatformData.h`, `SimpleFontData.h`, `SkPaint.h`, `SkTypeface.h` point to font management within the Blink rendering engine, utilizing Skia for graphics.
    * The `blink` namespace confirms this is Chromium/Blink-specific code.

4. **Focus on the `HarfBuzzFace` Class:** The filename suggests this class is central. Examine its members and methods.
    * `platform_data_`: A pointer to `FontPlatformData`, likely holding information about the font (family, size, etc.).
    * `harfbuzz_font_data_`:  A pointer to `HarfBuzzFontData`, suggesting a container for HarfBuzz-specific font information.
    * Constructor: Takes `FontPlatformData` and a unique ID, initializes `harfbuzz_font_data_`.
    * `Trace`:  Likely for debugging and memory management.
    * `GetVariationSelectorMode`, `SetVariationSelectorMode`:  Indicate handling of Unicode variation selectors, important for emoji and complex scripts.
    * `GetScaledFont`: Suggests the ability to retrieve a HarfBuzz font object, potentially with scaling and range restrictions.
    * `HbGlyphForCharacter`, `HarfBuzzGetGlyphForTesting`:  Methods to get glyph IDs for characters.
    * `HasSpaceInLigaturesOrKerning`:  Indicates logic to check for space glyphs in OpenType tables.
    * `UnitsPerEmFromHeadTable`: Gets units per em from the font's `head` table.
    * `ShouldSubpixelPosition`:  Determines if subpixel positioning should be used.
    * `VerticalData`:  Accesses vertical font metrics.
    * `Init`: Likely for static initialization.

5. **Analyze Helper Functions and Static Members:** These provide supporting functionality.
    * `TypefaceHasAnySupportedColorTable`: Checks for color font tables (CPAL, COLR, CBDT, CBLC, sbix), crucial for rendering color fonts like emojis.
    * `HarfBuzzGetGlyph`:  The core function for retrieving a glyph ID for a given Unicode codepoint, potentially considering variation selectors. This is a key point for interaction with the underlying font data.
    * `HarfBuzzGetNominalGlyph`: A simpler version of `HarfBuzzGetGlyph` without variation selectors.
    * Functions for getting horizontal and vertical advances and origins (`HarfBuzzGetGlyphHorizontalAdvance`, etc.): These are used by HarfBuzz to determine glyph placement.
    * `HarfBuzzGetGlyphExtents`: Gets the bounding box of a glyph.
    * `GetSpaceGlyph`:  Retrieves the glyph ID for the space character.
    * `HarfBuzzSkiaGetTable`:  Fetches font table data.
    * `CreateFace`: Creates a HarfBuzz face object from `FontPlatformData`.
    * `CreateHarfBuzzFontData`: Creates the `HarfBuzzFontData` object, setting up HarfBuzz font functions.
    * `HarfBuzzFontCache`:  A cache to reuse `HarfBuzzFontData` objects.
    * `HarfBuzzSkiaFontFuncs`: A singleton to manage the HarfBuzz font function table, potentially handling platform-specific differences (like the macOS `trak` table handling).

6. **Connect to Web Technologies:** Consider how these functionalities relate to the browser's rendering process.
    * **JavaScript:** JavaScript can manipulate text content, which eventually needs to be rendered. The font used and how it's shaped is relevant.
    * **HTML:**  HTML defines the structure of the document, including the text to be displayed. Font selection happens through CSS, but the actual shaping is done by code like this.
    * **CSS:** CSS properties like `font-family`, `font-size`, `font-style`, and increasingly, `font-variation-settings` directly influence the `FontPlatformData` passed to `HarfBuzzFace`. Emoji presentation (text vs. emoji) is also affected by CSS and the browser's default behavior.

7. **Identify Logical Inferences and Potential Issues:**
    * **Variation Selectors:** The code has explicit logic for handling variation selectors, crucial for correct emoji rendering and some language scripts. Incorrect handling could lead to wrong glyphs being displayed.
    * **Color Fonts:** The detection of color font tables suggests support for rendering colored glyphs.
    * **Platform Differences:** The `#if BUILDFLAG(IS_APPLE)` sections highlight platform-specific handling, which could introduce inconsistencies if not managed carefully. The handling of the `trak` table on macOS is a specific example.
    * **Caching:** The `HarfBuzzFontCache` is for performance, but cache invalidation issues could lead to using outdated font data.
    * **Fallback Fonts:** The logic within `HarfBuzzGetGlyph` regarding system fallback fonts and variation selectors indicates a complex process to find the correct glyph.

8. **Consider User and Programmer Errors:**
    * **Missing Fonts:** If the requested font is not available, the browser relies on fallback mechanisms. This code plays a part in that process.
    * **Incorrect CSS:** Specifying a font that doesn't support certain characters or variation sequences will rely on the robustness of the shaping engine.
    * **Programmer Errors:** Incorrectly implementing the HarfBuzz callbacks or mishandling font data could lead to crashes or rendering issues. The `DCHECK` statements suggest internal consistency checks.

9. **Structure the Explanation:** Organize the findings into logical sections as requested:
    * File functionality.
    * Relationship to JavaScript, HTML, CSS (with examples).
    * Logical inferences (with assumed inputs/outputs).
    * User/programmer errors (with examples).

10. **Refine and Elaborate:** Go back through the analysis and add more details and explanations. For instance, clarify the purpose of specific functions, explain the implications of certain logic, and provide concrete examples for the web technology interactions. The explanation of variation selectors and the macOS `trak` table handling are good examples of where more detail is helpful.

By following this process, which involves understanding the code's purpose, identifying key components, analyzing individual functions, connecting to the broader context, and considering potential issues, a comprehensive explanation of the `harfbuzz_face.cc` file can be constructed.
好的，让我们详细分析一下 `blink/renderer/platform/fonts/shaping/harfbuzz_face.cc` 这个文件。

**文件功能总览:**

`harfbuzz_face.cc` 文件是 Chromium Blink 渲染引擎中负责字体 **塑形 (shaping)** 的关键组件。它主要作用是作为 Blink 的字体系统和 HarfBuzz 库之间的桥梁。HarfBuzz 是一个开源的文本塑形引擎，负责将字符序列转换成排版好的字形序列，并确定每个字形的位置。

更具体地说，`HarfBuzzFace` 类封装了与单个字体 Face (可以理解为字体的某种特定风格，例如 Regular, Bold) 相关的 HarfBuzz 数据和操作。它管理着如何从 Blink 的字体表示 (`FontPlatformData`) 中提取 HarfBuzz 所需的信息，并提供用于与 HarfBuzz 交互的接口。

**核心功能分解:**

1. **HarfBuzz Face 的创建和管理:**
   - `HarfBuzzFace` 类本身代表一个 HarfBuzz face 的封装。
   - 构造函数 `HarfBuzzFace(const FontPlatformData* platform_data, uint64_t unique_id)` 接收 Blink 的字体平台数据 (`FontPlatformData`) 和一个唯一 ID。它使用 `HarfBuzzFontCache` 来获取或创建一个 `HarfBuzzFontData` 对象，后者包含了 HarfBuzz 所需的更底层的字体数据。
   - `CreateFace(const FontPlatformData* platform_data)` 函数负责根据 `FontPlatformData` 创建一个 HarfBuzz 的 `hb_face_t` 对象。这可能涉及直接从 Skia 的 `SkTypeface` 创建，或者从字体文件中读取表数据。
   - `CreateHarfBuzzFontData(hb_face_t* face, SkTypeface* typeface)` 函数创建 `HarfBuzzFontData` 对象，它包含 HarfBuzz 的 `hb_font_t` (基于 `hb_face_t`)，并设置了用于获取字形、字形属性（如宽度、高度、偏移等）的回调函数。

2. **字形 (Glyph) 获取:**
   - `HarfBuzzGetGlyph` 是一个关键的回调函数，它被 HarfBuzz 调用以获取给定 Unicode 码点 (character) 和可选的变体选择器 (variation_selector) 的字形 ID。
   - 这个函数会考虑以下情况：
     - 检查 `HarfBuzzFontData` 中是否定义了 Unicode 范围限制。
     - 特殊处理行分隔符和段落分隔符，将其替换为空格。
     - 处理 Unicode 变体序列 (Variation Sequences)，特别是对于 Emoji 的文本和表情符号呈现。
     - 在 macOS 上，对于某些系统字体可能缺失的连字符，会尝试从 Skia 的 `SkTypeface` 中合成字形 ID。
   - `HarfBuzzGetNominalGlyph` 是一个简化版本，不考虑变体选择器。

3. **字形属性获取:**
   - `HarfBuzzGetGlyphHorizontalAdvance` 和 `HarfBuzzGetGlyphHorizontalAdvances` 获取字形的水平前进宽度。
   - `HarfBuzzGetGlyphVerticalOrigin` 获取字形的垂直排版原点 (用于垂直排版)。
   - `HarfBuzzGetGlyphVerticalAdvance` 获取字形的垂直前进高度。
   - `HarfBuzzGetGlyphExtents` 获取字形的边界信息 (如 bounding box)。

4. **OpenType 特性检测:**
   - `HasSpaceInLigaturesOrKerning(TypesettingFeatures features)` 检查空格字符是否参与到字体的连字 (ligatures) 或字距调整 (kerning) 规则中。这有助于 Blink 优化文本排版。

5. **字体缩放和变体:**
   - `GetScaledFont(const UnicodeRangeSet* range_set, VerticalLayoutCallbacks vertical_layout, float specified_size)` 返回一个按指定大小缩放的 HarfBuzz 字体对象 (`hb_font_t`)。它可以限制支持的 Unicode 范围，并处理垂直排版的需求。
   - `GetVariationSelectorMode` 和 `SetVariationSelectorMode` 用于控制如何处理 Unicode 变体选择器，这对于正确渲染 Emoji 和一些复杂的文字至关重要。

6. **其他辅助功能:**
   - `UnitsPerEmFromHeadTable()` 获取字体 "head" 表中的每 em 单位数。
   - `ShouldSubpixelPosition()` 返回是否应该使用亚像素定位。
   - `Init()` 进行静态初始化，例如获取 `HarfBuzzSkiaFontFuncs` 的实例。

**与 JavaScript, HTML, CSS 的关系:**

`harfbuzz_face.cc` 的功能是浏览器渲染引擎内部的，它直接响应由 JavaScript, HTML, CSS 驱动的文本渲染请求。

* **HTML:** HTML 定义了文本内容。当浏览器解析 HTML 时，它会知道需要渲染哪些字符。
* **CSS:** CSS 负责指定文本的样式，包括 `font-family` (字体族), `font-size` (字体大小), `font-weight` (字体粗细), `font-style` (字体风格) 等。这些 CSS 属性最终会影响到 `FontPlatformData` 的创建，并被传递到 `HarfBuzzFace`。例如，`font-family` 决定了使用哪个字体文件，`font-size` 决定了 `GetScaledFont` 中需要设置的缩放比例。
* **JavaScript:** JavaScript 可以动态地修改 HTML 内容和 CSS 样式。当 JavaScript 改变文本内容或字体样式时，渲染引擎会重新进行布局和绘制，其中就包括调用 `HarfBuzzFace` 来对新的文本进行塑形。

**举例说明:**

1. **HTML:**
   ```html
   <p style="font-family: 'Noto Sans', sans-serif; font-size: 16px;">你好世界</p>
   ```
   当渲染这段 HTML 时，Blink 会查找名为 "Noto Sans" 的字体。`HarfBuzzFace` 会基于 "Noto Sans" 字体的 `FontPlatformData` 创建，并使用 HarfBuzz 对 "你好世界" 这四个字符进行塑形，确定每个字符应该使用哪个字形，以及它们的位置。

2. **CSS (Emoji 变体):**
   ```css
   /* 使用文本呈现的 Emoji */
   .text-emoji { font-variation-settings: 't variation' 1; }

   /* 使用表情符号呈现的 Emoji */
   .emoji-presentation { font-variation-settings: 't variation' 0; }
   ```
   CSS 的 `font-variation-settings` 属性可以影响 Emoji 的呈现方式。当应用这些样式时，`HarfBuzzFace::GetVariationSelectorMode` 和 `HarfBuzzGetGlyph` 会根据设置选择不同的字形（文本或彩色 Emoji）。例如，对于 "U+263A WHITE SMILING FACE"，可能存在一个黑白文本字形和一个彩色 Emoji 字形。

3. **JavaScript (动态修改文本):**
   ```javascript
   const paragraph = document.querySelector('p');
   paragraph.textContent = '新的文字';
   ```
   当 JavaScript 修改 `textContent` 时，浏览器会重新渲染该段落。`HarfBuzzFace` 会被调用来对 "新的文字" 进行塑形，可能使用与之前相同的字体，也可能因为 CSS 的改变而使用不同的字体。

**逻辑推理 (假设输入与输出):**

假设我们有一个简单的场景：

**假设输入:**

* **字符序列:** "fi"
* **字体:** 启用了标准连字的 OpenType 字体 (例如，支持 "fi" 连字的字体)。
* **CSS:** `font-family: 'MyFont';`

**逻辑推理过程:**

1. Blink 的布局引擎确定需要渲染 "fi"。
2. 字体选择器找到 "MyFont" 并创建对应的 `FontPlatformData`。
3. 创建 `HarfBuzzFace` 对象。
4. 塑形引擎调用 `HarfBuzzFace::GetScaledFont()` 获取 HarfBuzz 字体对象。
5. 塑形引擎调用 HarfBuzz 的塑形函数，HarfBuzz 内部会调用 `HarfBuzzGetGlyph` 获取 'f' 和 'i' 的字形 ID。
6. 由于字体支持 "fi" 连字，HarfBuzz 的连字查找 (在 OpenType GSUB 表中) 会匹配 "f" 和 "i"，并可能输出一个单独的 "fi" 连字字形 ID，而不是两个独立的字形 ID。
7. HarfBuzz 还会计算字形的位置信息。

**假设输出:**

* **字形序列:**  一个代表 "fi" 连字的字形 ID (而不是 'f' 和 'i' 两个独立的字形 ID)。
* **字形位置:**  该连字字形在渲染区域中的坐标。

**常见的使用错误 (用户或编程):**

1. **用户错误 (CSS):**
   - **指定了不支持所需字符的字体:**  例如，指定一个只包含英文字符的字体来显示中文，会导致显示为占位符 (豆腐块)。`HarfBuzzFace` 会尝试查找字形，但找不到。
   - **错误地配置 `font-variation-settings`:**  对于可变字体，如果 `font-variation-settings` 设置不正确，可能无法得到预期的字形。
   - **依赖于不存在的连字:**  用户可能期望某些连字能够自动出现，但如果所选字体不支持这些连字，则不会生效。`HarfBuzzFace::HasSpaceInLigaturesOrKerning` 可以帮助判断字体是否具有连字能力。

2. **编程错误 (Blink 引擎开发者):**
   - **`HarfBuzzGetGlyph` 实现错误:**  如果在 `HarfBuzzGetGlyph` 中没有正确处理变体选择器或特殊字符，可能导致 Emoji 或其他复杂文本的渲染错误。
   - **字体缓存管理错误:**  如果 `HarfBuzzFontCache` 管理不当，可能导致使用过期的或错误的字体数据。
   - **HarfBuzz 配置错误:**  如果在创建 `hb_font_t` 时配置不正确，例如没有正确设置缩放比例或变体信息，会导致渲染结果不正确。
   - **内存管理错误:**  在 `HarfBuzzSkiaGetTable` 中分配的内存需要正确释放，否则会导致内存泄漏。

**总结:**

`harfbuzz_face.cc` 是 Blink 渲染引擎中至关重要的一个文件，它将 Blink 的字体系统与强大的文本塑形引擎 HarfBuzz 连接起来。它负责字形的查找、属性的获取，并处理复杂的文本特性，如连字和变体选择。理解这个文件的功能有助于理解浏览器如何将文本内容转化为最终在屏幕上呈现的图像。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_face.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (c) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"

// clang-format off
#include <hb.h>
#include <hb-cplusplus.hh>
#include <hb-ot.h>
// clang-format on

#include <memory>

#include "base/memory/ptr_util.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_global_context.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face_from_typeface.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_font_cache.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_font_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/variation_selector_mode.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/skia/skia_text_metrics.h"
#include "third_party/blink/renderer/platform/fonts/unicode_range_set.h"
#include "third_party/blink/renderer/platform/resolution_units.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "third_party/skia/include/core/SkPaint.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkPoint.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkTypeface.h"

namespace blink {

namespace {

SkFontTableTag kCpalTag = SkSetFourByteTag('C', 'P', 'A', 'L');
SkFontTableTag kColrTag = SkSetFourByteTag('C', 'O', 'L', 'R');
SkFontTableTag kSbixTag = SkSetFourByteTag('s', 'b', 'i', 'x');
SkFontTableTag kCbdtTag = SkSetFourByteTag('C', 'B', 'D', 'T');
SkFontTableTag kCblcTag = SkSetFourByteTag('C', 'B', 'L', 'C');

bool TypefaceHasAnySupportedColorTable(const SkTypeface* typeface) {
  if (!typeface) {
    return false;
  }
  const int num_tags = typeface->countTables();
  if (!num_tags) {
    return false;
  }
  std::unique_ptr<SkFontTableTag[]> tags(new SkFontTableTag[num_tags]);
  const int returned_tags = typeface->getTableTags(tags.get());
  if (!returned_tags) {
    return false;
  }
  bool has_cpal = false;
  bool has_colr = false;
  bool has_cbdt = false;
  bool has_cblc = false;
  for (int i = 0; i < returned_tags; i++) {
    SkFontTableTag tag = tags[i];
    if (tag == kSbixTag) {
      return true;
    }
    if (tag == kCpalTag) {
      if (has_colr) {
        return true;
      }
      has_cpal = true;
    } else if (tag == kColrTag) {
      if (has_cpal) {
        return true;
      }
      has_colr = true;
    } else if (tag == kCbdtTag) {
      if (has_cblc) {
        return true;
      }
      has_cbdt = true;
    } else if (tag == kCblcTag) {
      if (has_cbdt) {
        return true;
      }
      has_cblc = true;
    }
  }
  return false;
}

}  // namespace

HarfBuzzFace::HarfBuzzFace(const FontPlatformData* platform_data,
                           uint64_t unique_id)
    : platform_data_(platform_data),
      harfbuzz_font_data_(FontGlobalContext::GetHarfBuzzFontCache().GetOrCreate(
          unique_id,
          platform_data)) {}

void HarfBuzzFace::Trace(Visitor* visitor) const {
  visitor->Trace(platform_data_);
  visitor->Trace(harfbuzz_font_data_);
}

VariationSelectorMode& GetIgnoreVariationSelectorModeRef() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(WTF::ThreadSpecific<VariationSelectorMode>,
                                  variation_selector_mode, ());
  return *variation_selector_mode;
}

VariationSelectorMode HarfBuzzFace::GetVariationSelectorMode() {
  return GetIgnoreVariationSelectorModeRef();
}

void HarfBuzzFace::SetVariationSelectorMode(VariationSelectorMode value) {
  // Ignore variation selectors mode should be on only when the
  // FontVariationSequences runtime flag is enabled.
  DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled() ||
         !ShouldIgnoreVariationSelector(value));
  DCHECK(RuntimeEnabledFeatures::FontVariantEmojiEnabled() ||
         !UseFontVariantEmojiVariationSelector(value));
  GetIgnoreVariationSelectorModeRef() = value;
}

static hb_bool_t HarfBuzzGetGlyph(hb_font_t* hb_font,
                                  void* font_data,
                                  hb_codepoint_t unicode,
                                  hb_codepoint_t variation_selector,
                                  hb_codepoint_t* glyph,
                                  void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);

  CHECK(hb_font_data);
  if (hb_font_data->range_set_ &&
      !hb_font_data->range_set_->Contains(unicode)) {
    return false;
  }

  // If the system fonts do not have a glyph coverage for line separator
  // (0x2028) or paragraph separator (0x2029), missing glyph would be displayed
  // in Chrome instead. If the system font has l-sep and p-sep symbols for the
  // 0x2028 and 0x2029 codepoints, they will be displayed, see
  // https://crbug.com/550275. To prevent that, we are replacing line and
  // paragraph separators with space, as it is said in unicode specification,
  // compare: https://www.unicode.org/faq/unsup_char.html#2.
  if (unicode == kLineSeparator || unicode == kParagraphSeparator) {
    unicode = kSpaceCharacter;
  }

  bool consider_variation_selector = false;
  bool is_variation_sequence = false;

  // Emoji System Fonts on Mac, Win and Android either do not have cmap 14
  // subtable or it does not include all emojis from their cmap table. We use
  // cmap 14 subtable to identify whether there is a colored (emoji
  // presentation) or a monochromatic (text presentation) glyph in the font.
  // This may lead to the cases when we will not be able to get the glyph ID
  // for the requested variation sequence using fallback system font and will
  // continue the second shaping fallback list pass ignoring variation
  // selectors and may end up using web font with wrong emoji presentation
  // instead of using system font with the correct presentation. To prevent that
  // once we reached system fallback fonts, we can ignore emoji variation
  // selectors since we will get the font with the correct presentation relying
  // on FontFallbackPriority in `FontCache::PlatformFallbackFontForCharacter`.
  VariationSelectorMode variation_selector_mode =
      HarfBuzzFace::GetVariationSelectorMode();
  if (RuntimeEnabledFeatures::FontVariationSequencesEnabled()) {
    if (!ShouldIgnoreVariationSelector(variation_selector_mode) &&
        Character::IsUnicodeVariationSelector(variation_selector) &&
        Character::IsVariationSequence(unicode, variation_selector)) {
      is_variation_sequence = true;
      consider_variation_selector = true;
    } else if (RuntimeEnabledFeatures::FontVariantEmojiEnabled() &&
               UseFontVariantEmojiVariationSelector(variation_selector_mode) &&
               Character::IsEmoji(unicode)) {
      consider_variation_selector = true;
    }
  }

  bool text_presentation_requested = false;
  bool emoji_presentation_requested = false;

  // Variation sequences are a special case because we want to distinguish
  // between the cases when we found a glyph for the whole variation sequence in
  // cmap format 14 subtable and when we found only a base character of the
  // variation sequence. In the latter case we set the glyph value to
  // `kUnmatchedVSGlyphId`.
  if (consider_variation_selector) {
    if (!is_variation_sequence) {
      if (variation_selector_mode == kForceVariationSelector15 ||
          (variation_selector_mode == kUseUnicodeDefaultPresentation &&
           Character::IsEmojiTextDefault(unicode))) {
        variation_selector = kVariationSelector15Character;
      } else if (variation_selector_mode == kForceVariationSelector16 ||
                 (variation_selector_mode == kUseUnicodeDefaultPresentation &&
                  Character::IsEmojiEmojiDefault(unicode))) {
        variation_selector = kVariationSelector16Character;
      }
    }

    text_presentation_requested =
        (variation_selector == kVariationSelector15Character);
    emoji_presentation_requested =
        (variation_selector == kVariationSelector16Character);

    hb_bool_t hb_has_vs_glyph = hb_font_get_variation_glyph(
        hb_font_get_parent(hb_font), unicode, variation_selector, glyph);
    if (hb_has_vs_glyph) {
      // Found a glyph for variation sequence, no need to look for a base
      // character, can just return.
      return true;
    }
    // Unable to find a glyph for variation sequence, now we need to look
    // for a glyph for the base character from variation sequence.
    variation_selector = 0;
  }

  hb_bool_t hb_has_base_glyph = hb_font_get_glyph(
      hb_font_get_parent(hb_font), unicode, variation_selector, glyph);

  if (consider_variation_selector && hb_has_base_glyph) {
    // Unable to find a glyph for variation sequence, but found a glyph for
    // the base character from variation sequence ignoring variation selector.
    // We use `TypefaceHasAnySupportedColorTable` to check whether a typeface
    // has colored table and based on that we make an assumption whether a font
    // has a colored or monochromatic glyph for base character from variation
    // sequence. We set `glyph` to `kUnmatchedVSGlyphId` only when font has a
    // wrong presentation for base character.
    if (RuntimeEnabledFeatures::SystemFallbackEmojiVSSupportEnabled() &&
        (text_presentation_requested || emoji_presentation_requested)) {
      SkTypeface* typeface = hb_font_data->font_.getTypeface();
      // TODO(https://bugs.skia.org/374078818): Ideally we also want to check
      // weather the base codepoint is present in the found color table,
      // requested API from Skia.
      bool has_color_table = TypefaceHasAnySupportedColorTable(typeface);
      if ((has_color_table && text_presentation_requested) ||
          (!has_color_table && emoji_presentation_requested)) {
        *glyph = kUnmatchedVSGlyphId;
      }
    } else {
      *glyph = kUnmatchedVSGlyphId;
    }
  }

// MacOS CoreText API synthesizes GlyphID for several unicode codepoints,
// for example, hyphens and separators for some fonts. HarfBuzz does not
// synthesize such glyphs, and as it's not found from the last resort font, we
// end up with displaying tofu, see https://crbug.com/1267606 for details.
// Chrome uses Times as last resort fallback font and in Times the only visible
// synthesizing characters are hyphen (0x2010) and non-breaking hyphen (0x2011).
// For performance reasons, we limit this fallback lookup to the specific
// missing glyphs for hyphens and only to Mac OS, where we're facing this issue.
#if BUILDFLAG(IS_APPLE)
  if (!hb_has_base_glyph) {
    SkTypeface* typeface = hb_font_data->font_.getTypeface();
    if (!typeface) {
      return false;
    }
    if (unicode == kHyphenCharacter || unicode == kNonBreakingHyphen) {
      SkGlyphID sk_glyph_id = typeface->unicharToGlyph(unicode);
      *glyph = sk_glyph_id;
      return sk_glyph_id;
    }
  }
#endif
  return hb_has_base_glyph;
}

static hb_bool_t HarfBuzzGetNominalGlyph(hb_font_t* hb_font,
                                         void* font_data,
                                         hb_codepoint_t unicode,
                                         hb_codepoint_t* glyph,
                                         void* user_data) {
  return HarfBuzzGetGlyph(hb_font, font_data, unicode, 0, glyph, user_data);
}

static hb_position_t HarfBuzzGetGlyphHorizontalAdvance(hb_font_t* hb_font,
                                                       void* font_data,
                                                       hb_codepoint_t glyph,
                                                       void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);
  hb_position_t advance = 0;

  SkFontGetGlyphWidthForHarfBuzz(hb_font_data->font_, glyph, &advance);
  return advance;
}

static void HarfBuzzGetGlyphHorizontalAdvances(
    hb_font_t* font,
    void* font_data,
    unsigned count,
    const hb_codepoint_t* first_glyph,
    unsigned int glyph_stride,
    hb_position_t* first_advance,
    unsigned int advance_stride,
    void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);
  SkFontGetGlyphWidthForHarfBuzz(hb_font_data->font_, count, first_glyph,
                                 glyph_stride, first_advance, advance_stride);
}

static hb_bool_t HarfBuzzGetGlyphVerticalOrigin(hb_font_t* hb_font,
                                                void* font_data,
                                                hb_codepoint_t glyph,
                                                hb_position_t* x,
                                                hb_position_t* y,
                                                void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);
  OpenTypeVerticalData* vertical_data = hb_font_data->VerticalData();
  if (!vertical_data) {
    return false;
  }

  float result[] = {0, 0};
  Glyph the_glyph = glyph;
  vertical_data->GetVerticalTranslationsForGlyphs(hb_font_data->font_,
                                                  &the_glyph, 1, result);
  *x = SkiaScalarToHarfBuzzPosition(-result[0]);
  *y = SkiaScalarToHarfBuzzPosition(-result[1]);
  return true;
}

static hb_position_t HarfBuzzGetGlyphVerticalAdvance(hb_font_t* hb_font,
                                                     void* font_data,
                                                     hb_codepoint_t glyph,
                                                     void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);
  OpenTypeVerticalData* vertical_data = hb_font_data->VerticalData();
  if (!vertical_data) {
    return SkiaScalarToHarfBuzzPosition(hb_font_data->height_fallback_);
  }

  Glyph the_glyph = glyph;
  float advance_height = -vertical_data->AdvanceHeight(the_glyph);
  return SkiaScalarToHarfBuzzPosition(SkFloatToScalar(advance_height));
}

static hb_bool_t HarfBuzzGetGlyphExtents(hb_font_t* hb_font,
                                         void* font_data,
                                         hb_codepoint_t glyph,
                                         hb_glyph_extents_t* extents,
                                         void* user_data) {
  HarfBuzzFontData* hb_font_data =
      reinterpret_cast<HarfBuzzFontData*>(font_data);

  SkFontGetGlyphExtentsForHarfBuzz(hb_font_data->font_, glyph, extents);
  return true;
}

static inline bool TableHasSpace(hb_face_t* face,
                                 hb_set_t* glyphs,
                                 hb_tag_t tag,
                                 hb_codepoint_t space) {
  unsigned count = hb_ot_layout_table_get_lookup_count(face, tag);
  for (unsigned i = 0; i < count; i++) {
    hb_ot_layout_lookup_collect_glyphs(face, tag, i, glyphs, glyphs, glyphs,
                                       nullptr);
    if (hb_set_has(glyphs, space)) {
      return true;
    }
  }
  return false;
}

static bool GetSpaceGlyph(hb_font_t* font, hb_codepoint_t& space) {
  return hb_font_get_nominal_glyph(font, kSpaceCharacter, &space);
}

bool HarfBuzzFace::HasSpaceInLigaturesOrKerning(TypesettingFeatures features) {
  const hb_codepoint_t kInvalidCodepoint = static_cast<hb_codepoint_t>(-1);
  hb_codepoint_t space = kInvalidCodepoint;

  hb::unique_ptr<hb_set_t> glyphs(hb_set_create());

  hb_font_t* unscaled_font = harfbuzz_font_data_->unscaled_font_.get();

  // Check whether computing is needed and compute for gpos/gsub.
  if (features & kKerning &&
      harfbuzz_font_data_->space_in_gpos_ ==
          HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kUnknown) {
    if (space == kInvalidCodepoint && !GetSpaceGlyph(unscaled_font, space)) {
      return false;
    }
    // Compute for gpos.
    hb_face_t* face = hb_font_get_face(unscaled_font);
    DCHECK(face);
    harfbuzz_font_data_->space_in_gpos_ =
        hb_ot_layout_has_positioning(face) &&
                TableHasSpace(face, glyphs.get(), HB_OT_TAG_GPOS, space)
            ? HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kPresent
            : HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kNotPresent;
  }

  hb_set_clear(glyphs.get());

  if (features & kLigatures &&
      harfbuzz_font_data_->space_in_gsub_ ==
          HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kUnknown) {
    if (space == kInvalidCodepoint && !GetSpaceGlyph(unscaled_font, space)) {
      return false;
    }
    // Compute for gpos.
    hb_face_t* face = hb_font_get_face(unscaled_font);
    DCHECK(face);
    harfbuzz_font_data_->space_in_gsub_ =
        hb_ot_layout_has_substitution(face) &&
                TableHasSpace(face, glyphs.get(), HB_OT_TAG_GSUB, space)
            ? HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kPresent
            : HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kNotPresent;
  }

  return (features & kKerning &&
          harfbuzz_font_data_->space_in_gpos_ ==
              HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kPresent) ||
         (features & kLigatures &&
          harfbuzz_font_data_->space_in_gsub_ ==
              HarfBuzzFontData::SpaceGlyphInOpenTypeTables::kPresent);
}

unsigned HarfBuzzFace::UnitsPerEmFromHeadTable() {
  hb_face_t* face = hb_font_get_face(harfbuzz_font_data_->unscaled_font_.get());
  return hb_face_get_upem(face);
}

Glyph HarfBuzzFace::HbGlyphForCharacter(UChar32 character) {
  hb_codepoint_t glyph = 0;
  HarfBuzzGetNominalGlyph(harfbuzz_font_data_->unscaled_font_.get(),
                          harfbuzz_font_data_, character, &glyph, nullptr);
  return glyph;
}

hb_codepoint_t HarfBuzzFace::HarfBuzzGetGlyphForTesting(
    UChar32 character,
    UChar32 variation_selector) {
  hb_codepoint_t glyph = 0;
  HarfBuzzGetGlyph(harfbuzz_font_data_->unscaled_font_.get(),
                   harfbuzz_font_data_, character, variation_selector, &glyph,
                   nullptr);
  return glyph;
}

bool HarfBuzzFace::ShouldSubpixelPosition() {
  return harfbuzz_font_data_->font_.isSubpixel();
}

// `HarfBuzzSkiaFontFuncs` is shared hb_font_funcs_t`s among threads for
// calculating horizontal advances functions.
class HarfBuzzSkiaFontFuncs final {
 public:
  static HarfBuzzSkiaFontFuncs& Get() {
    DEFINE_THREAD_SAFE_STATIC_LOCAL(HarfBuzzSkiaFontFuncs, shared_hb_funcs, ());
    return shared_hb_funcs;
  }

#if BUILDFLAG(IS_APPLE)
  HarfBuzzSkiaFontFuncs()
      : hb_font_funcs_skia_advances_(
            CreateFontFunctions(kSkiaHorizontalAdvances)),
        hb_font_funcs_harfbuzz_advances_(
            CreateFontFunctions(kHarfBuzzHorizontalAdvances)) {}

  ~HarfBuzzSkiaFontFuncs() {
    hb_font_funcs_destroy(hb_font_funcs_skia_advances_);
    hb_font_funcs_destroy(hb_font_funcs_harfbuzz_advances_);
  }

  hb_font_funcs_t* GetFunctions(SkTypeface* typeface) {
    bool has_trak = false;
    bool has_sbix = false;

    const int num_tags = typeface->countTables();

    Vector<SkFontTableTag> tags(num_tags);

    const int returned_tags = typeface->getTableTags(tags.data());
    DCHECK_EQ(num_tags, returned_tags);

    for (auto& tag : tags) {
      if (tag == SkSetFourByteTag('t', 'r', 'a', 'k')) {
        has_trak = true;
      }
      if (tag == SkSetFourByteTag('s', 'b', 'i', 'x')) {
        has_sbix = true;
      }
    }

    return has_trak && !has_sbix ? hb_font_funcs_harfbuzz_advances_
                                 : hb_font_funcs_skia_advances_;
  }
#else
  HarfBuzzSkiaFontFuncs()
      : hb_font_funcs_skia_advances_(
            CreateFontFunctions(kSkiaHorizontalAdvances)) {}

  ~HarfBuzzSkiaFontFuncs() {
    hb_font_funcs_destroy(hb_font_funcs_skia_advances_);
  }

  hb_font_funcs_t* GetFunctions(SkTypeface*) {
    return hb_font_funcs_skia_advances_;
  }
#endif

  HarfBuzzSkiaFontFuncs(const HarfBuzzSkiaFontFuncs&) = delete;
  HarfBuzzSkiaFontFuncs(HarfBuzzSkiaFontFuncs&&) = delete;

  HarfBuzzSkiaFontFuncs& operator=(const HarfBuzzSkiaFontFuncs&) = delete;
  HarfBuzzSkiaFontFuncs& operator=(HarfBuzzSkiaFontFuncs&&) = delete;

 private:
  enum HorizontalAdvanceSource {
    kSkiaHorizontalAdvances,
#if BUILDFLAG(IS_APPLE)
    kHarfBuzzHorizontalAdvances,
#endif
  };

  static hb_font_funcs_t* CreateFontFunctions(
      HorizontalAdvanceSource advance_source) {
    hb_font_funcs_t* funcs = hb_font_funcs_create();

    if (advance_source == kSkiaHorizontalAdvances) {
      hb_font_funcs_set_glyph_h_advance_func(
          funcs, HarfBuzzGetGlyphHorizontalAdvance, nullptr, nullptr);
      hb_font_funcs_set_glyph_h_advances_func(
          funcs, HarfBuzzGetGlyphHorizontalAdvances, nullptr, nullptr);
    }
    hb_font_funcs_set_variation_glyph_func(funcs, HarfBuzzGetGlyph, nullptr,
                                           nullptr);
    hb_font_funcs_set_nominal_glyph_func(funcs, HarfBuzzGetNominalGlyph,
                                         nullptr, nullptr);
    // TODO(crbug.com/899718): Replace vertical metrics callbacks with
    // HarfBuzz VORG/VMTX internal implementation by deregistering those.
    hb_font_funcs_set_glyph_v_advance_func(
        funcs, HarfBuzzGetGlyphVerticalAdvance, nullptr, nullptr);
    hb_font_funcs_set_glyph_v_origin_func(funcs, HarfBuzzGetGlyphVerticalOrigin,
                                          nullptr, nullptr);
    hb_font_funcs_set_glyph_extents_func(funcs, HarfBuzzGetGlyphExtents,
                                         nullptr, nullptr);

    hb_font_funcs_make_immutable(funcs);
    return funcs;
  }

  hb_font_funcs_t* const hb_font_funcs_skia_advances_;
#if BUILDFLAG(IS_APPLE)
  hb_font_funcs_t* const hb_font_funcs_harfbuzz_advances_;
#endif
};

static hb_blob_t* HarfBuzzSkiaGetTable(hb_face_t* face,
                                       hb_tag_t tag,
                                       void* user_data) {
  SkTypeface* typeface = reinterpret_cast<SkTypeface*>(user_data);

  const wtf_size_t table_size =
      base::checked_cast<wtf_size_t>(typeface->getTableSize(tag));
  if (!table_size) {
    return nullptr;
  }

  char* buffer = reinterpret_cast<char*>(WTF::Partitions::FastMalloc(
      table_size, WTF_HEAP_PROFILER_TYPE_NAME(HarfBuzzFontData)));
  if (!buffer) {
    return nullptr;
  }
  size_t actual_size = typeface->getTableData(tag, 0, table_size, buffer);
  if (table_size != actual_size) {
    WTF::Partitions::FastFree(buffer);
    return nullptr;
  }
  return hb_blob_create(const_cast<char*>(buffer), table_size,
                        HB_MEMORY_MODE_WRITABLE, buffer,
                        WTF::Partitions::FastFree);
}

// TODO(yosin): We should move |CreateFace()| to "harfbuzz_font_cache.cc".
static hb::unique_ptr<hb_face_t> CreateFace(
    const FontPlatformData* platform_data) {
  hb::unique_ptr<hb_face_t> face;

  sk_sp<SkTypeface> typeface = sk_ref_sp(platform_data->Typeface());
  CHECK(typeface);
#if !BUILDFLAG(IS_APPLE)
  face = HbFaceFromSkTypeface(typeface);
#endif

  // Fallback to table copies if there is no in-memory access.
  if (!face) {
    face = hb::unique_ptr<hb_face_t>(hb_face_create_for_tables(
        HarfBuzzSkiaGetTable, typeface.get(), nullptr));
  }

  DCHECK(face);
  return face;
}

namespace {

HarfBuzzFontData* CreateHarfBuzzFontData(hb_face_t* face,
                                         SkTypeface* typeface) {
  hb::unique_ptr<hb_font_t> ot_font(hb_font_create(face));
  hb_ot_font_set_funcs(ot_font.get());

  int axis_count = typeface->getVariationDesignPosition(nullptr, 0);
  if (axis_count > 0) {
    Vector<SkFontArguments::VariationPosition::Coordinate> axis_values;
    axis_values.resize(axis_count);
    if (typeface->getVariationDesignPosition(axis_values.data(),
                                             axis_values.size()) > 0) {
      hb_font_set_variations(
          ot_font.get(), reinterpret_cast<hb_variation_t*>(axis_values.data()),
          axis_values.size());
    }
  }

  // Creating a sub font means that non-available functions
  // are found from the parent.
  hb_font_t* const unscaled_font = hb_font_create_sub_font(ot_font.get());
  HarfBuzzFontData* data =
      MakeGarbageCollected<HarfBuzzFontData>(unscaled_font);
  hb_font_set_funcs(unscaled_font,
                    HarfBuzzSkiaFontFuncs::Get().GetFunctions(typeface), data,
                    nullptr);
  return data;
}

}  // namespace

HarfBuzzFontData* HarfBuzzFontCache::GetOrCreate(
    uint64_t unique_id,
    const FontPlatformData* platform_data) {
  const auto& result = font_map_.insert(unique_id, nullptr);
  if (result.is_new_entry) {
    hb::unique_ptr<hb_face_t> face = CreateFace(platform_data);
    result.stored_value->value =
        CreateHarfBuzzFontData(face.get(), platform_data->Typeface());
  }
  return result.stored_value->value.Get();
}

static_assert(
    std::is_same<decltype(SkFontArguments::VariationPosition::Coordinate::axis),
                 decltype(hb_variation_t::tag)>::value &&
        std::is_same<
            decltype(SkFontArguments::VariationPosition::Coordinate::value),
            decltype(hb_variation_t::value)>::value &&
        sizeof(SkFontArguments::VariationPosition::Coordinate) ==
            sizeof(hb_variation_t),
    "Skia and HarfBuzz Variation parameter types must match in structure and "
    "size.");

const OpenTypeVerticalData& HarfBuzzFace::VerticalData() const {
  // Ensure `HarfBuzzFontData` and its `OpenTypeVerticalData` is up-to-date,
  // with `kPrepareForVerticalLayout`, even when this font isn't used for
  // vertical flow. See `GetScaledFont()`.
  harfbuzz_font_data_->UpdateFallbackMetricsAndScale(
      *platform_data_, HarfBuzzFace::kPrepareForVerticalLayout);
  return *harfbuzz_font_data_->VerticalData();
}

hb_font_t* HarfBuzzFace::GetScaledFont(const UnicodeRangeSet* range_set,
                                       VerticalLayoutCallbacks vertical_layout,
                                       float specified_size) const {
  harfbuzz_font_data_->range_set_ = range_set;
  harfbuzz_font_data_->UpdateFallbackMetricsAndScale(*platform_data_,
                                                     vertical_layout);

  int scale = SkiaScalarToHarfBuzzPosition(platform_data_->size());
  hb_font_t* unscaled_font = harfbuzz_font_data_->unscaled_font_.get();
  hb_font_set_scale(unscaled_font, scale, scale);
  // See contended discussion in https://github.com/harfbuzz/harfbuzz/pull/1484
  // Setting ptem here is critical for HarfBuzz to know where to lookup spacing
  // offset in the AAT trak table, the unit pt in ptem here means "CoreText"
  // points. After discussion on the pull request and with Apple developers, the
  // meaning of HarfBuzz' hb_font_set_ptem API was changed to expect the
  // equivalent of CSS pixels here.
  hb_font_set_ptem(unscaled_font, specified_size > 0 ? specified_size
                                                     : platform_data_->size());

  return unscaled_font;
}

hb_font_t* HarfBuzzFace::GetScaledFont() const {
  return GetScaledFont(nullptr, HarfBuzzFace::kNoVerticalLayout,
                       platform_data_->size());
}

void HarfBuzzFace::Init() {
  DCHECK(IsMainThread());
  HarfBuzzSkiaFontFuncs::Get();
}

}  // namespace blink

"""

```