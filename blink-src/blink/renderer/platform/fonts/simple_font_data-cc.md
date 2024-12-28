Response:
Let's break down the thought process for analyzing the `simple_font_data.cc` file and answering the prompt.

**1. Initial Understanding of the File's Purpose (Based on Filename and Path):**

* **Filename:** `simple_font_data.cc` strongly suggests this file manages basic font information. "Simple" likely means it handles core, fundamental aspects rather than complex font rendering or layout algorithms.
* **Path:** `blink/renderer/platform/fonts/`  This path is crucial.
    * `blink/renderer`:  Indicates this is part of the Blink rendering engine.
    * `platform`:  Suggests it interacts with platform-specific font APIs (like FreeType or CoreText via Skia).
    * `fonts`:  Confirms its central role in font management.

**2. Examining the Copyright and License:**

* The standard copyright and BSD-style license are common in Chromium/Blink. While not directly functional, they indicate the open-source nature and redistribution terms.

**3. Analyzing Includes:**

The `#include` directives provide valuable clues about the file's dependencies and functionalities. I'd group them mentally:

* **Core C++:** `<unicode/utf16.h>`, `<algorithm>`, `<memory>`, `<utility>`  These are standard C++ headers for string handling, algorithms, memory management, and utility classes.
* **Blink Platform:**  This is where the real action is:
    * `"third_party/blink/renderer/platform/fonts/simple_font_data.h"`: The header file for this source file. It defines the `SimpleFontData` class interface.
    * `"third_party/blink/renderer/platform/font_family_names.h"`: Likely contains constants for standard font family names.
    * `"third_party/blink/renderer/platform/fonts/font_description.h"`:  Describes font properties like size, style, weight, etc.
    * `"third_party/blink/renderer/platform/fonts/opentype/...`":  Indicates support for OpenType font features like baselines and vertical metrics.
    * `"third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"`:  Highlights the use of HarfBuzz for complex text shaping (handling ligatures, kerning, etc.).
    * `"third_party/blink/renderer/platform/fonts/skia/skia_text_metrics.h"`: Shows integration with Skia for font metrics.
    * `"third_party/blink/renderer/platform/wtf/...`":  Includes WTF (Web Template Framework) utilities like allocators and string handling.
* **Third-Party Libraries:**
    * `"skia/ext/font_utils.h"`:  Skia-specific utilities for fonts.
    * `"third_party/skia/include/core/SkFont.h"`, etc.:  Core Skia graphics library headers, especially for font handling.
    * `"v8/include/v8.h"`:  Integration with the V8 JavaScript engine (important for relating to JavaScript).
    * `"third_party/freetype_buildflags.h"` and the FreeType includes: Indicates the use of FreeType for font rendering (or potentially other font backends).
* **Operating System/Graphics:**
    * `"build/build_config.h"`:  Build-related configurations.
    * `"ui/gfx/geometry/rect_f.h"`, `"ui/gfx/geometry/skia_conversions.h"`:  Defines rectangle structures and conversion between Skia and gfx types.
    * `"base/memory/ptr_util.h"`, `"base/numerics/byte_conversions.h"`:  Base library utilities for memory and byte manipulation.

**4. Examining Class Definition and Member Variables:**

* **`SimpleFontData` Class:** The core of the file.
* **`platform_data_`:**  A pointer to `FontPlatformData`, representing the underlying platform-specific font representation.
* **`font_`:** A `SkFont` object, Skia's representation of a font.
* **`custom_font_data_`:**  Handles custom font data (likely for `@font-face`).
* **`font_metrics_`:** Stores calculated font metrics (ascent, descent, etc.).
* **Caching:**  Members like `small_caps_`, `emphasis_mark_`, `normalized_typo_ascent_descent_`, `ideographic_advance_width_`, etc., along with the `han_kerning_cache_`, indicate caching of computed values for performance.

**5. Analyzing Key Methods and Their Functionality:**

* **Constructor (`SimpleFontData(...)`)**: Initializes the object, creates the `SkFont`, and calls `PlatformInit` and `PlatformGlyphInit`.
* **Destructor (`~SimpleFontData()`)**:  Decreases the external memory counter.
* **`PlatformInit(...)`**:  Calculates and sets font metrics using Skia APIs. Handles overrides.
* **`PlatformGlyphInit()`**:  Retrieves glyph IDs for common characters like space and zero.
* **`FontDataForCharacter(...)`**:  Determines the appropriate font data for a given character (important for font fallback).
* **`GlyphForCharacter(...)`**:  Maps a Unicode code point to a glyph ID using HarfBuzz.
* **`SmallCapsFontData(...)`, `EmphasisMarkFontData(...)`, `CreateScaledFontData(...)`**:  Creates derived font data for specific styles.
* **`MetricsOverriddenFontData(...)`**:  Creates a copy with overridden metrics.
* **`NormalizedTypoAscentAndDescent(...)`**:  Calculates normalized ascent and descent based on OpenType tables or fallbacks.
* **`VerticalPosition(...)`**:  Calculates vertical positions related to the font (top, bottom, em-height).
* **`IdeographicAdvanceWidth/Height/InlineSize()`**: Calculates metrics related to ideographic characters.
* **`HanKerningData(...)`**:  Handles kerning for Han characters (Chinese, Japanese, Korean).
* **`PlatformBoundsForGlyph(...)`, `BoundsForGlyphs(...)`, `WidthForGlyph(...)`**:  Retrieves glyph bounds and widths using Skia.

**6. Identifying Relationships with JavaScript, HTML, and CSS:**

* **JavaScript:**  The `v8::Isolate` interactions are key. This file informs the JavaScript engine about font metrics, which affects text rendering and layout calculations performed in JavaScript. For instance, JavaScript might query the width of text elements.
* **HTML:**  The font data directly affects how text is rendered on HTML pages. The font family, size, style, and weight specified in HTML translate to the data managed by this class.
* **CSS:**  CSS properties like `font-family`, `font-size`, `font-style`, `font-weight`, `line-height`, `letter-spacing`, etc., are all used to determine which `SimpleFontData` object to use and how to render text. The calculations in this file are essential for implementing these CSS properties correctly.

**7. Formulating Examples and Identifying Potential Errors:**

* **Logic Inference:**  Focus on methods that perform calculations based on inputs (e.g., `NormalizedTypoAscentAndDescent`). Consider edge cases and how the code handles them.
* **User/Programming Errors:** Think about common mistakes when working with fonts in web development (e.g., specifying a font that doesn't exist, incorrect CSS values, relying on default font behavior).

**8. Structuring the Answer:**

Organize the information logically based on the prompt's requests:

* **Functionality:** Provide a high-level overview and then delve into specific functionalities based on the methods.
* **Relationships with JavaScript, HTML, CSS:**  Explain the connections with clear examples of how each technology interacts with the font data.
* **Logic Inference:**  Present the assumptions, inputs, and outputs for specific methods.
* **Common Errors:**  List potential user and programming errors related to font usage.

By following this systematic approach, I could effectively analyze the provided code and generate a comprehensive and accurate answer to the prompt. The key is to combine code inspection with an understanding of the broader context of a web browser's rendering engine.
好的，让我们来分析一下 `blink/renderer/platform/fonts/simple_font_data.cc` 这个文件。

**文件功能概要:**

`simple_font_data.cc` 文件定义了 `SimpleFontData` 类，它是 Blink 渲染引擎中用于存储和管理单个特定字体实例（包含字体族、字号、粗细、斜体等属性）相关数据的核心类。  它扮演着以下关键角色：

1. **存储字体平台数据:**  它持有 `FontPlatformData` 类型的成员变量 `platform_data_`，该对象封装了底层操作系统或图形库（如 Skia 或 CoreText）提供的字体数据句柄。
2. **缓存 Skia 字体对象:** 它创建并持有一个 `SkFont` 类型的成员变量 `font_`，这是 Skia 图形库中代表字体的对象，用于执行实际的字形绘制和度量。
3. **管理自定义字体数据:**  它包含一个 `CustomFontData` 类型的成员变量 `custom_font_data_`，用于存储通过 `@font-face` 规则加载的自定义字体的信息。
4. **计算和缓存字体度量:**  它负责计算并缓存各种重要的字体度量信息，例如：
    * 字体的 ascent（基线以上高度）、descent（基线以下高度）、cap height（大写字母高度）、x-height（小写字母 x 的高度）。
    * 下划线位置和粗细。
    * 行间距（line gap）和行高（line spacing）。
    * 空格字符的宽度 (`space_width_`)。
    * 平均字符宽度 (`avg_char_width_`) 和最大字符宽度 (`max_char_width_`)。
    * 表意字符的宽度和高度。
5. **提供字形查找功能:**  通过 `GlyphForCharacter()` 方法，根据 Unicode 码点查找对应的字形 ID（Glyph）。
6. **支持派生字体数据:**  提供创建小体大写（small caps）和着重号（emphasis mark）等派生字体数据的能力。
7. **处理字体度量覆盖:**  允许通过 `FontMetricsOverride` 对象覆盖默认的字体度量值。
8. **处理标准化排版 Ascent 和 Descent:**  计算和缓存标准化的 typo ascent 和 descent，这对于跨平台文本布局的一致性很重要。
9. **提供垂直方向定位信息:**  提供 `VerticalPosition()` 方法，用于获取字体在垂直方向上的特定位置，例如文本顶部、文本底部、em 高度的顶部和底部。
10. **处理 CJK 字体的度量:**  计算和缓存表意字符的宽度和高度，用于 CJK 文本的布局。
11. **处理韩文避头尾规则 (Han Kerning):**  提供 `HanKerningData()` 方法来获取用于韩文避头尾规则的字体数据。
12. **获取字形的边界和宽度:**  提供 `PlatformBoundsForGlyph()`, `BoundsForGlyphs()`, 和 `WidthForGlyph()` 方法来获取字形的边界和宽度信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SimpleFontData` 类是 Blink 渲染引擎处理文本渲染的核心部分，因此与 JavaScript, HTML, CSS 都有着密切的关系：

* **HTML:** HTML 定义了网页的结构和内容，其中包括文本内容。浏览器在解析 HTML 时，会遇到需要渲染的文本。`SimpleFontData` 负责提供渲染这些文本所需的字体信息。

    * **例子:** 当 HTML 中存在 `<p style="font-family: Arial; font-size: 16px;">Hello World</p>` 时，Blink 引擎会根据 `font-family` 和 `font-size` 属性找到或创建对应的 `SimpleFontData` 对象，然后使用其提供的数据来渲染 "Hello World" 这段文本。

* **CSS:** CSS 负责控制网页的样式，包括文本的字体、大小、颜色、行高等。CSS 样式规则会影响 `SimpleFontData` 对象的选择和创建，以及其中字体度量值的计算。

    * **例子:**
        * **`font-family`:** CSS 的 `font-family` 属性决定了使用哪个字体族。Blink 会根据这个属性查找合适的 `SimpleFontData`。
        * **`font-size`:** CSS 的 `font-size` 属性决定了字体的大小。`SimpleFontData` 对象会存储特定字号的字体数据。
        * **`font-weight` 和 `font-style`:** 这些属性也会影响 `SimpleFontData` 对象的选择，例如选择粗体或斜体版本的字体。
        * **`line-height`:** CSS 的 `line-height` 属性会影响文本的行高，而 `SimpleFontData` 中计算的 `line spacing` 是计算行高的基础。
        * **`letter-spacing`:** 虽然 `SimpleFontData` 本身不直接处理 `letter-spacing`，但其提供的字符宽度信息是计算应用了 `letter-spacing` 后的文本布局的基础。
        * **`small-caps`:** CSS 的 `font-variant-caps: small-caps` 会触发 `SimpleFontData::SmallCapsFontData()` 方法的调用，创建并使用小体大写的字体数据。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响 `SimpleFontData` 的使用。此外，JavaScript 还可以通过 API（例如 `CanvasRenderingContext2D`）直接使用字体信息进行绘制操作。

    * **例子:**
        * **动态修改 CSS:** JavaScript 可以修改元素的 `style` 属性，例如 `element.style.fontSize = '20px'`; 这会导致浏览器重新查找或创建对应字号的 `SimpleFontData`。
        * **Canvas 绘制:**  在 Canvas 中使用 `context.font = 'bold 16px Arial'` 设置字体时，Canvas 内部会使用 `SimpleFontData` 来获取字体的度量信息，以便正确地绘制文本。
        * **测量文本尺寸:** JavaScript 可以使用 `element.offsetWidth`, `element.offsetHeight` 或 Canvas API 的 `measureText()` 方法来获取文本的尺寸，这些方法最终会依赖于 `SimpleFontData` 提供的字符宽度等信息。

**逻辑推理、假设输入与输出:**

让我们以 `SimpleFontData::NormalizedTypoAscentAndDescent()` 方法为例进行逻辑推理：

**假设输入:**

* 一个已经初始化的 `SimpleFontData` 对象，其 `platform_data_` 指向一个有效的 `FontPlatformData` 对象。
* 该 `FontPlatformData` 对象关联的字体可能包含 OS/2 表中的 `sTypoAscender` 和 `sTypoDescender` 值。

**逻辑推理步骤:**

1. **尝试从 OS/2 表获取:** 首先，该方法会尝试从字体的 OS/2 表中读取 `sTypoAscender` 和 `sTypoDescender` 的值。  这些值通常被字体设计者用来定义字体的排版高度。
2. **如果成功获取:** 如果成功读取到 `sTypoAscender` 和 `sTypoDescender` 并且这些值有效（例如，`typo_ascender > 0`），则会使用这些值来计算标准化的 typo ascent 和 descent。计算过程会确保 ascent 和 descent 的比例与原始值保持一致，并将它们的和缩放到字体的大小（em height）。
3. **如果获取失败:** 如果 OS/2 表中没有这些值，或者这些值无效，则会退回到使用 `GetFontMetrics().FloatAscent()` 和 `GetFontMetrics().FloatDescent()` 方法获取的字体度量值进行计算。
4. **最后的兜底:** 如果连字体度量值也无法得到有效的 ascent 和 descent，那么可能会使用一个默认值或者标记计算失败。

**预期输出:**

* 返回一个 `FontHeight` 结构体，包含计算出的标准化 typo ascent 和 descent 值。这两个值是 `LayoutUnit` 类型。

**假设输入与输出示例:**

* **假设输入:**  一个 "Arial" 字体，字号为 16px，其 OS/2 表中 `sTypoAscender` 为 1100，`sTypoDescender` 为 240。
* **输出:**  `NormalizedTypoAscentAndDescent()` 方法可能会计算出接近 `FontHeight{LayoutUnit(13), LayoutUnit(3)}` 的结果（具体数值取决于具体的计算和舍入方式）。这里假设标准化后的总高度接近 16px。

* **假设输入:** 一个没有 OS/2 表信息的字体 "CustomFont"，字号为 16px，其字体度量 ascent 为 12px，descent 为 4px。
* **输出:** `NormalizedTypoAscentAndDescent()` 方法可能会计算出 `FontHeight{LayoutUnit(12), LayoutUnit(4)}`。

**用户或编程常见的使用错误:**

1. **字体文件缺失或加载失败:**  如果 CSS 中指定的 `font-family` 对应的字体文件不存在或者加载失败，浏览器可能无法创建 `SimpleFontData` 对象，或者使用回退字体，导致渲染结果与预期不符。
    * **例子:** 用户在 CSS 中指定了 `font-family: "MyCustomFont";`，但 "MyCustomFont.woff2" 文件没有正确放置或加载，浏览器可能会使用默认字体渲染文本。

2. **指定了无效的字体属性:**  在 CSS 中指定了无效的 `font-weight` 或 `font-style` 值，可能导致浏览器找不到匹配的 `SimpleFontData` 对象。
    * **例子:** 用户指定了 `font-weight: 750;`，而该字体只有 `400` 和 `700` 两种粗细，浏览器可能会使用最接近的粗细进行渲染。

3. **过度依赖默认字体:**  开发者没有明确指定字体，导致浏览器使用默认字体。在不同操作系统或浏览器上，默认字体可能不同，导致页面在不同环境下显示效果不一致。

4. **错误理解字体度量单位:**  混淆了像素 (px), em, rem 等字体大小单位，导致布局错乱。`SimpleFontData` 中存储的度量值通常是基于像素单位或与字体大小相关的单位。

5. **自定义字体加载顺序问题:**  如果自定义字体加载较慢，可能会出现“字体闪烁”现象 (FOUT - Flash of Unstyled Text)，即先使用系统默认字体渲染，然后切换到自定义字体。这与 `SimpleFontData` 的创建和使用时机有关。

6. **在 Canvas 中使用未加载的字体:**  在 JavaScript 的 Canvas API 中使用 `context.font` 设置字体时，如果指定的字体尚未加载完成，可能会导致绘制失败或使用默认字体。

7. **假设所有字体都具有相同的度量:**  不同的字体即使字号相同，其 ascent、descent、字符宽度等度量值也可能不同。直接使用硬编码的数值进行布局可能会导致问题。应该依赖 `SimpleFontData` 提供的度量信息进行布局计算。

希望以上分析能够帮助你理解 `simple_font_data.cc` 文件的功能及其与前端技术的关系。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/simple_font_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2005, 2008, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Alexey Proskuryakov
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

#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"

#include <unicode/utf16.h>

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/numerics/byte_conversions.h"
#include "build/build_config.h"
#include "skia/ext/font_utils.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_baseline_metrics.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_vertical_data.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"
#include "third_party/blink/renderer/platform/fonts/skia/skia_text_metrics.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/freetype_buildflags.h"
#include "third_party/skia/include/core/SkFont.h"
#include "third_party/skia/include/core/SkFontMetrics.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkTypeface.h"
#include "third_party/skia/include/core/SkTypes.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "v8/include/v8.h"

#if !BUILDFLAG(USE_SYSTEM_FREETYPE) && BUILDFLAG(ENABLE_FREETYPE)
#include "third_party/freetype/src/src/autofit/afws-decl.h"
#endif

namespace blink {

constexpr float kSmallCapsFontSizeMultiplier = 0.7f;
constexpr float kEmphasisMarkFontSizeMultiplier = 0.5f;

#if !BUILDFLAG(USE_SYSTEM_FREETYPE) && BUILDFLAG(ENABLE_FREETYPE)
constexpr int32_t kFontObjectsMemoryConsumption =
    std::max(sizeof(AF_LatinMetricsRec), sizeof(AF_CJKMetricsRec));
#else
// sizeof(AF_LatinMetricsRec) = 2128
// TODO(drott): Measure a new number for Fontations.
constexpr int32_t kFontObjectsMemoryConsumption = 2128;
#endif

SimpleFontData::SimpleFontData(const FontPlatformData* platform_data,
                               const CustomFontData* custom_data,
                               bool subpixel_ascent_descent,
                               const FontMetricsOverride& metrics_override)
    : platform_data_(platform_data),
      font_(platform_data->size() ? platform_data->CreateSkFont()
                                  : skia::DefaultFont()),
      custom_font_data_(custom_data) {
  // Every time new SimpleFontData instance is created, Skia will ask
  // FreeType to get the metrics for glyphs by invoking
  // af_face_globals_get_metrics. There FT will allocate style_metrics_size
  // bytes of memory on the metrics. Depending on the used script,
  // style_metrics_size is equal to sizeof(AF_LatinMetricsRec) or to
  // sizeof(AF_CJKMetricsRec). GC is not aware of this allocation. So in
  // situations when we create a lot of Font objects in the small period of
  // time, memory usage will grow unboundedly without GC kicking in. To prevent
  // that we are informing GC about external allocated memory using
  // style_metrics_size as the font memory consumption.
  if (v8::Isolate* isolate = v8::Isolate::TryGetCurrent()) {
    external_memory_accounter_.Increase(isolate, kFontObjectsMemoryConsumption);
  }
  PlatformInit(subpixel_ascent_descent, metrics_override);
  PlatformGlyphInit();
}

SimpleFontData::~SimpleFontData() {
  if (v8::Isolate* isolate = v8::Isolate::TryGetCurrent()) {
    external_memory_accounter_.Decrease(isolate, kFontObjectsMemoryConsumption);
  }
}

void SimpleFontData::PlatformInit(bool subpixel_ascent_descent,
                                  const FontMetricsOverride& metrics_override) {
  if (!platform_data_->size()) {
    font_metrics_.Reset();
    avg_char_width_ = 0;
    max_char_width_ = 0;
    return;
  }

  SkFontMetrics metrics;

  font_.getMetrics(&metrics);

  float ascent;
  float descent;

  FontMetrics::AscentDescentWithHacks(
      ascent, descent, *platform_data_, font_, subpixel_ascent_descent,
      metrics_override.ascent_override, metrics_override.descent_override);

  font_metrics_.SetAscent(ascent);
  font_metrics_.SetDescent(descent);
  font_metrics_.SetCapHeight(metrics.fCapHeight);

  float skia_underline_value;
  if (metrics.hasUnderlinePosition(&skia_underline_value))
    font_metrics_.SetUnderlinePosition(skia_underline_value);
  if (metrics.hasUnderlineThickness(&skia_underline_value))
    font_metrics_.SetUnderlineThickness(skia_underline_value);

  float x_height;
  if (metrics.fXHeight) {
    x_height = metrics.fXHeight;
#if BUILDFLAG(IS_APPLE)
    // Mac OS CTFontGetXHeight reports the bounding box height of x,
    // including parts extending below the baseline and apparently no x-height
    // value from the OS/2 table. However, the CSS ex unit
    // expects only parts above the baseline, hence measuring the glyph:
    // http://www.w3.org/TR/css3-values/#ex-unit
    const Glyph x_glyph = GlyphForCharacter('x');
    if (x_glyph) {
      gfx::RectF glyph_bounds(BoundsForGlyph(x_glyph));
      // SkGlyph bounds, y down, based on rendering at (0,0).
      x_height = -glyph_bounds.y();
    }
#endif
    font_metrics_.SetXHeight(x_height);
  } else {
    x_height = ascent * 0.56;  // Best guess from Windows font metrics.
    font_metrics_.SetXHeight(x_height);
    font_metrics_.SetHasXHeight(false);
  }

  float line_gap;
  if (metrics_override.line_gap_override) {
    line_gap = *metrics_override.line_gap_override * platform_data_->size();
  } else {
    line_gap = SkScalarToFloat(metrics.fLeading);
  }
  font_metrics_.SetLineGap(line_gap);
  font_metrics_.SetLineSpacing(lroundf(ascent) + lroundf(descent) +
                               lroundf(line_gap));

// In WebKit/WebCore/platform/graphics/SimpleFontData.cpp, m_spaceWidth is
// calculated for us, but we need to calculate m_maxCharWidth and
// m_avgCharWidth in order for text entry widgets to be sized correctly.
#if BUILDFLAG(IS_WIN)
  max_char_width_ = SkScalarRoundToInt(metrics.fMaxCharWidth);

  // Older version of the DirectWrite API doesn't implement support for max
  // char width. Fall back on a multiple of the ascent. This is entirely
  // arbitrary but comes pretty close to the expected value in most cases.
  if (max_char_width_ < 1)
    max_char_width_ = ascent * 2;
#elif BUILDFLAG(IS_APPLE)
  // FIXME: The current avg/max character width calculation is not ideal,
  // it should check either the OS2 table or, better yet, query FontMetrics.
  // Sadly FontMetrics provides incorrect data on Mac at the moment.
  // https://crbug.com/420901
  max_char_width_ = std::max(avg_char_width_, font_metrics_.FloatAscent());
#else
  // Better would be to rely on either fMaxCharWidth or fAveCharWidth.
  // skbug.com/3087
  max_char_width_ = SkScalarRoundToInt(metrics.fXMax - metrics.fXMin);

#endif

#if !BUILDFLAG(IS_APPLE)
  if (metrics.fAvgCharWidth) {
    avg_char_width_ = SkScalarToFloat(metrics.fAvgCharWidth);
  } else {
#endif
    avg_char_width_ = x_height;
    const Glyph x_glyph = GlyphForCharacter('x');
    if (x_glyph) {
      avg_char_width_ = WidthForGlyph(x_glyph);
    }
#if !BUILDFLAG(IS_APPLE)
  }
#endif

  // Read baselines value from OpenType Table.
  OpenTypeBaselineMetrics m(PlatformData().GetHarfBuzzFace(),
                            PlatformData().Orientation());
  font_metrics_.SetIdeographicBaseline(m.OpenTypeIdeographicBaseline());
  font_metrics_.SetAlphabeticBaseline(m.OpenTypeAlphabeticBaseline());
  font_metrics_.SetHangingBaseline(m.OpenTypeHangingBaseline());
}

void SimpleFontData::PlatformGlyphInit() {
  const FontPlatformData& platform_data = PlatformData();
  SkTypeface* typeface = platform_data.Typeface();

  if (!typeface->countGlyphs()) {
    space_glyph_ = 0;
    space_width_ = 0;
    zero_glyph_ = 0;
    return;
  }

  // Nasty hack to determine if we should round or ceil space widths.
  // If the font is monospace or fake monospace we ceil to ensure that
  // every character and the space are the same width.  Otherwise we round.
  space_glyph_ = GlyphForCharacter(' ');
  float width = WidthForGlyph(space_glyph_);
  space_width_ = width;
  zero_glyph_ = GlyphForCharacter('0');
  font_metrics_.SetZeroWidth(WidthForGlyph(zero_glyph_));
}

const SimpleFontData* SimpleFontData::FontDataForCharacter(UChar32) const {
  return this;
}

Glyph SimpleFontData::GlyphForCharacter(UChar32 codepoint) const {
  HarfBuzzFace* harfbuzz_face = PlatformData().GetHarfBuzzFace();
  if (!harfbuzz_face)
    return 0;
  // Retrieve glyph coverage information via HarfBuzz' character-to-glyph
  // mapping instead of the SkTypeface backend implementation so that it matches
  // the coverage we use through HarfBuzz during shaping. These two can differ
  // in situations where the system API synthesizes certain glyphs, see
  // https://crbug.com/1267606 for details. This function is used in situations
  // where CSS or layout (ellipsis, hyphenation) requires knowledge about a
  // particular character, hence it's important that they match.
  return harfbuzz_face->HbGlyphForCharacter(codepoint);
}

bool SimpleFontData::IsSegmented() const {
  return false;
}

SimpleFontData* SimpleFontData::SmallCapsFontData(
    const FontDescription& font_description) const {
  if (!small_caps_) {
    small_caps_ =
        CreateScaledFontData(font_description, kSmallCapsFontSizeMultiplier);
  }
  return small_caps_;
}

SimpleFontData* SimpleFontData::EmphasisMarkFontData(
    const FontDescription& font_description) const {
  if (!emphasis_mark_) {
    emphasis_mark_ =
        CreateScaledFontData(font_description, kEmphasisMarkFontSizeMultiplier);
  }
  return emphasis_mark_;
}

SimpleFontData* SimpleFontData::CreateScaledFontData(
    const FontDescription& font_description,
    float scale_factor) const {
  const float scaled_size =
      lroundf(font_description.ComputedSize() * scale_factor);
  return MakeGarbageCollected<SimpleFontData>(
      MakeGarbageCollected<FontPlatformData>(*platform_data_, scaled_size),
      IsCustomFont() ? MakeGarbageCollected<CustomFontData>() : nullptr);
}

SimpleFontData* SimpleFontData::MetricsOverriddenFontData(
    const FontMetricsOverride& metrics_override) const {
  return MakeGarbageCollected<SimpleFontData>(
      platform_data_, custom_font_data_, false /* subpixel_ascent_descent */,
      metrics_override);
}

// Internal leadings can be distributed to ascent and descent.
// -------------------------------------------
//           | - Internal Leading (in ascent)
//           |--------------------------------
//  Ascent - |              |
//           |              |
//           |              | - Em height
// ----------|--------------|
//           |              |
// Descent - |--------------------------------
//           | - Internal Leading (in descent)
// -------------------------------------------
FontHeight SimpleFontData::NormalizedTypoAscentAndDescent(
    FontBaseline baseline_type) const {
  if (baseline_type == kAlphabeticBaseline) {
    if (!normalized_typo_ascent_descent_.ascent)
      ComputeNormalizedTypoAscentAndDescent();
    return normalized_typo_ascent_descent_;
  }
  const LayoutUnit normalized_height =
      LayoutUnit::FromFloatRound(PlatformData().size());
  return {normalized_height - normalized_height / 2, normalized_height / 2};
}

LayoutUnit SimpleFontData::NormalizedTypoAscent(
    FontBaseline baseline_type) const {
  return NormalizedTypoAscentAndDescent(baseline_type).ascent;
}

LayoutUnit SimpleFontData::NormalizedTypoDescent(
    FontBaseline baseline_type) const {
  return NormalizedTypoAscentAndDescent(baseline_type).descent;
}

static std::pair<int16_t, int16_t> TypoAscenderAndDescender(
    SkTypeface* typeface) {
  // TODO(kojii): This should move to Skia once finalized. We can then move
  // EmHeightAscender/Descender to FontMetrics.
  int16_t buffer[2];
  size_t size = typeface->getTableData(SkSetFourByteTag('O', 'S', '/', '2'), 68,
                                       sizeof(buffer), buffer);
  if (size == sizeof(buffer)) {
    // The buffer values are in big endian.
    return std::make_pair(base::ByteSwap(buffer[0]),
                          -base::ByteSwap(buffer[1]));
  }
  return std::make_pair(0, 0);
}

void SimpleFontData::ComputeNormalizedTypoAscentAndDescent() const {
  // Compute em height metrics from OS/2 sTypoAscender and sTypoDescender.
  SkTypeface* typeface = platform_data_->Typeface();
  auto [typo_ascender, typo_descender] = TypoAscenderAndDescender(typeface);
  if (typo_ascender > 0 &&
      TrySetNormalizedTypoAscentAndDescent(typo_ascender, typo_descender)) {
    return;
  }

  // As the last resort, compute em height metrics from our ascent/descent.
  const FontMetrics& font_metrics = GetFontMetrics();
  if (TrySetNormalizedTypoAscentAndDescent(font_metrics.FloatAscent(),
                                           font_metrics.FloatDescent())) {
    return;
  }

  // We shouldn't be here unless the height is zero or lower.
  DCHECK_LE(font_metrics.Height(), 0);
}

bool SimpleFontData::TrySetNormalizedTypoAscentAndDescent(float ascent,
                                                          float descent) const {
  const float height = ascent + descent;
  if (height <= 0 || ascent < 0 || ascent > height)
    return false;
  // While the OpenType specification recommends the sum of sTypoAscender and
  // sTypoDescender to equal 1em, most fonts do not follow. Most Latin fonts
  // set to smaller than 1em, and many tall scripts set to larger than 1em.
  // https://www.microsoft.com/typography/otspec/recom.htm#OS2
  // To ensure the sum of ascent and descent is the "em height", normalize by
  // keeping the ratio of sTypoAscender:sTypoDescender.
  // This matches to how Gecko computes "em height":
  // https://github.com/whatwg/html/issues/2470#issuecomment-291425136
  const float em_height = PlatformData().size();
  const LayoutUnit normalized_ascent =
      LayoutUnit::FromFloatRound(ascent * em_height / height);
  normalized_typo_ascent_descent_ = {
      normalized_ascent,
      LayoutUnit::FromFloatRound(em_height) - normalized_ascent};
  return true;
}

LayoutUnit SimpleFontData::VerticalPosition(
    FontVerticalPositionType position_type,
    FontBaseline baseline_type) const {
  switch (position_type) {
    case FontVerticalPositionType::TextTop:
      // Use Ascent, not FixedAscent, to match to how painter computes the
      // baseline position.
      return LayoutUnit(GetFontMetrics().Ascent(baseline_type));
    case FontVerticalPositionType::TextBottom:
      return LayoutUnit(-GetFontMetrics().Descent(baseline_type));
    case FontVerticalPositionType::TopOfEmHeight:
      return NormalizedTypoAscent(baseline_type);
    case FontVerticalPositionType::BottomOfEmHeight:
      return -NormalizedTypoDescent(baseline_type);
  }
  NOTREACHED();
}

const std::optional<float>& SimpleFontData::IdeographicAdvanceWidth() const {
  std::call_once(ideographic_advance_width_once_, [this] {
    // Use the advance of the CJK water character U+6C34 as the approximated
    // advance of fullwidth ideographic characters, as specified at
    // https://drafts.csswg.org/css-values-4/#ic.
    if (const Glyph cjk_water_glyph = GlyphForCharacter(kCjkWaterCharacter)) {
      ideographic_advance_width_ = WidthForGlyph(cjk_water_glyph);
    }
  });
  return ideographic_advance_width_;
}

const std::optional<float>& SimpleFontData::IdeographicAdvanceHeight() const {
  std::call_once(ideographic_advance_height_once_, [this] {
    if (const Glyph cjk_water_glyph = GlyphForCharacter(kCjkWaterCharacter)) {
      const HarfBuzzFace* hb_face = platform_data_->GetHarfBuzzFace();
      const OpenTypeVerticalData& vertical_data = hb_face->VerticalData();
      ideographic_advance_height_ =
          vertical_data.AdvanceHeight(cjk_water_glyph);
    }
  });
  return ideographic_advance_height_;
}

const std::optional<float>& SimpleFontData::IdeographicInlineSize() const {
  std::call_once(ideographic_inline_size_once_, [this] {
    // It should be computed without shaping; i.e., it doesn't include font
    // features, ligatures/kerning, nor `letter-spacing`.
    // https://github.com/w3c/csswg-drafts/issues/5498#issuecomment-686902802
    if (PlatformData().Orientation() != FontOrientation::kVerticalUpright) {
      ideographic_inline_size_ = IdeographicAdvanceWidth();
      return;
    }

    // Compute vertical advance if the orientation is `kVerticalUpright`.
    ideographic_inline_size_ = IdeographicAdvanceHeight();
  });
  return ideographic_inline_size_;
}

const HanKerning::FontData& SimpleFontData::HanKerningData(
    const LayoutLocale& locale,
    bool is_horizontal) const {
  for (const HanKerningCacheEntry& entry : han_kerning_cache_) {
    if (entry.locale == &locale && entry.is_horizontal == is_horizontal) {
      return entry.data;
    }
  }

  // The cache didn't hit. Shift the list and create a new entry at `[0]`.
  for (wtf_size_t i = 1; i < std::size(han_kerning_cache_); ++i) {
    han_kerning_cache_[i] = std::move(han_kerning_cache_[i - 1]);
  }
  HanKerningCacheEntry& new_entry = han_kerning_cache_[0];
  new_entry = {.locale = &locale,
               .is_horizontal = is_horizontal,
               .data = HanKerning::FontData(*this, locale, is_horizontal)};
  return new_entry.data;
}

gfx::RectF SimpleFontData::PlatformBoundsForGlyph(Glyph glyph) const {
  if (!platform_data_->size()) {
    return gfx::RectF();
  }

  static_assert(sizeof(glyph) == 2, "Glyph id should not be truncated.");

  SkRect bounds;
  SkFontGetBoundsForGlyph(font_, glyph, &bounds);
  return gfx::SkRectToRectF(bounds);
}

void SimpleFontData::BoundsForGlyphs(const Vector<Glyph, 256>& glyphs,
                                     Vector<SkRect, 256>* bounds) const {
  DCHECK_EQ(glyphs.size(), bounds->size());

  if (!platform_data_->size()) {
    return;
  }

  DCHECK_EQ(bounds->size(), glyphs.size());
  SkFontGetBoundsForGlyphs(font_, glyphs, bounds->data());
}

float SimpleFontData::WidthForGlyph(Glyph glyph) const {
  if (!platform_data_->size()) {
    return 0;
  }

  static_assert(sizeof(glyph) == 2, "Glyph id should not be truncated.");

  return SkFontGetWidthForGlyph(font_, glyph);
}

}  // namespace blink

"""

```