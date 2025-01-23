Response:
Let's break down the thought process for analyzing the provided C++ code and generating the response.

1. **Understanding the Goal:** The request asks for the functionality of `font_custom_platform_data.cc`, its relation to web technologies, logical inferences, and potential user errors.

2. **Initial Code Scan and High-Level Understanding:**  The first step is to skim the code, looking for key elements like:
    * Includes: These reveal dependencies and hints about the file's purpose. Seeing `<skia/include/core/SkTypeface.h>`, `web_font_decoder.h`, and `font_platform_data.h` strongly suggests this file deals with handling custom fonts (likely web fonts) and their representation within the Blink rendering engine.
    * Class Definition: The primary class is `FontCustomPlatformData`. This is the central focus.
    * Constructor/Destructor:  These often manage resources. The constructor increments an `external_memory_accounter_`, and the destructor decrements it, hinting at memory management related to the font data.
    * Methods: `GetFontPlatformData`, `GetVariationAxes`, `FamilyNameForInspector`, `Create`. These reveal the core functionalities.
    * Namespaces:  The code is within the `blink` namespace, confirming its role within the Chromium rendering engine.

3. **Analyzing Key Methods:**  The core of understanding the file lies in analyzing the purpose of its methods:

    * **`FontCustomPlatformData` (Constructor):**  Takes a `SkTypeface` and data size. The memory accounting suggests it's managing the memory used by the decoded font data.
    * **`~FontCustomPlatformData` (Destructor):**  Releases the accounted memory.
    * **`GetFontPlatformData`:**  This is the most complex method. It takes various font properties (size, bold, italic, variation settings, palette) as input and returns a `FontPlatformData`. The logic inside manipulates the underlying `SkTypeface` based on these properties, particularly for variable fonts and color palettes. The code explicitly deals with OpenType features like `wght`, `wdth`, `slnt`, and `opsz`. This is a critical part linking the low-level font representation to the higher-level CSS font properties.
    * **`GetVariationAxes`:**  Relatively straightforward. It delegates to `VariableAxesNames::GetVariationAxes`, indicating it retrieves information about the adjustable axes in variable fonts.
    * **`FamilyNameForInspector`:**  Fetches the font family name, prioritizing English language tags. This is important for developer tools and debugging.
    * **`Create` (two overloads):**  These methods are responsible for creating `FontCustomPlatformData` instances. One takes raw buffer data and uses `WebFontDecoder` to decode it, while the other takes an already decoded `SkTypeface`. This shows how custom fonts are loaded and processed.

4. **Connecting to Web Technologies (JavaScript, HTML, CSS):** Now, the key is to bridge the gap between this C++ code and the web.

    * **CSS:** The parameters of `GetFontPlatformData` directly correspond to CSS font properties: `font-size`, `font-weight`, `font-style`, `font-variation-settings`, `font-palette`. The logic within the method manipulates the `SkTypeface` based on these CSS values.
    * **HTML:**  While not directly interacting, HTML's `<style>` tags or inline styles are where these CSS properties are applied, triggering the font loading and rendering process that this C++ code is a part of.
    * **JavaScript:**  JavaScript can dynamically modify CSS styles, including font properties, which would indirectly lead to this code being executed. The comment about V8 integration in the constructor/destructor provides a more direct link – the memory accounting interacts with the JavaScript engine's garbage collection.

5. **Logical Inferences and Examples:**

    * **Variable Fonts:** The code heavily features logic for handling variable fonts (using tags like `wght`, `wdth`, `slnt`, `opsz`). The example showing how `font-variation-settings` affects the rendered font is a direct consequence of this code.
    * **Color Fonts/Palettes:** The code handles `font-palette`. The example demonstrates how different palette names in CSS lead to different color schemes due to this C++ logic.
    * **Optical Sizing:** The handling of the `opsz` tag shows how the browser can automatically adjust font rendering based on the font size, a feature controlled by the `font-optical-sizing` CSS property.

6. **User/Programming Errors:** Consider common mistakes developers might make related to custom fonts:

    * **Incorrect Font File:** Providing a corrupted or incompatible font file would cause the `WebFontDecoder` to fail, leading to the `ots_parse_message`.
    * **Invalid Variation Settings:**  Using incorrect tags or values in `font-variation-settings` might result in unexpected font rendering or the inability to apply the settings. The code includes logging for when variation settings can't be applied, indicating this potential issue.
    * **Incorrect Palette Name:** Providing a non-existent palette name in `font-palette` would result in the default palette being used.

7. **Structuring the Response:** Organize the information logically:

    * Start with a concise summary of the file's main purpose.
    * Detail the functionalities by describing the key methods.
    * Explain the relationships to JavaScript, HTML, and CSS with clear examples.
    * Provide logical inferences with hypothetical input/output scenarios.
    * List common user/programming errors and their potential causes.

8. **Refinement and Language:** Ensure the language is clear, concise, and uses correct technical terms. The examples should be easy to understand. The explanations of the C++ code should be at a level understandable to someone familiar with web development concepts, even if they aren't a C++ expert.

By following these steps, systematically analyzing the code, and connecting it to web development concepts, we can generate a comprehensive and accurate response to the request.
这个文件 `blink/renderer/platform/fonts/font_custom_platform_data.cc` 在 Chromium 的 Blink 渲染引擎中扮演着处理 **自定义字体** 的关键角色。它负责加载、解析和管理非系统自带的字体，例如通过 `@font-face` CSS 规则引入的 Web 字体。

以下是该文件的主要功能：

**1. 加载和解码自定义字体数据:**

*   该文件中的 `FontCustomPlatformData::Create` 方法负责接收表示字体文件的 `SharedBuffer` 对象。
*   它使用 `WebFontDecoder` 类来解码字体数据，将原始的字节流转换为可以被 Skia 图形库理解和渲染的 `SkTypeface` 对象。
*   解码过程中，如果字体文件存在错误（例如格式不正确），`WebFontDecoder` 会生成错误消息，该消息会被传递出去。

**2. 存储和管理解码后的字体数据:**

*   `FontCustomPlatformData` 类本身作为一个容器，存储着解码后的 `SkTypeface` 对象。
*   它还记录了字体数据的大小 (`data_size_`)，并使用 `external_memory_accounter_` 来通知 V8 引擎（JavaScript 引擎）关于这部分内存的使用情况，以便进行垃圾回收管理。

**3. 根据 CSS 属性生成 `FontPlatformData`:**

*   `GetFontPlatformData` 方法是该文件的核心功能之一。它接收一系列与字体相关的 CSS 属性作为输入，例如字体大小、粗细、斜体、字体变体设置（`font-variation-settings`）、字体调色板（`font-palette`）等。
*   基于这些属性，它可能会对底层的 `SkTypeface` 进行修改，例如应用可变字体轴（variable font axes）的设置或者选择特定的颜色调色板。
*   最终，它创建一个 `FontPlatformData` 对象并返回。`FontPlatformData` 是 Blink 中更通用的字体表示，会被用于实际的文本渲染。

**4. 处理可变字体 (Variable Fonts):**

*   该文件包含了处理可变字体的逻辑。通过解析 `font-variation-settings` CSS 属性，它可以提取出各个可变轴的值（例如 weight, width, slant, optical size）。
*   它使用 `SkFontArguments::VariationPosition` 来配置 `SkTypeface`，从而生成具有指定变体特征的字体实例。
*   它还考虑了 `font-optical-sizing` 属性，可以自动调整字体在不同尺寸下的外观。

**5. 处理颜色字体 (Color Fonts) 和调色板 (Palettes):**

*   该文件支持 OpenType 颜色字体，允许字体包含多个颜色定义。
*   它解析 `font-palette` 和 `font-palette-values` CSS 属性，允许开发者选择或自定义字体的颜色调色板。
*   它可以根据 CSS 的设置选择预定义的调色板，或者通过 `font-palette-values` 定义覆盖特定颜色的值。
*   对于可插值的调色板，它会根据设置计算出最终的颜色值。

**6. 提供字体变体轴信息:**

*   `GetVariationAxes` 方法返回字体支持的可变轴信息，这可以用于开发者工具或者其他需要了解字体特性的场景。

**7. 提供用于检查器的字体族名称:**

*   `FamilyNameForInspector` 方法返回字体的族名称，这主要用于浏览器开发者工具中显示字体信息。

**与 JavaScript, HTML, CSS 的关系:**

该文件与 JavaScript、HTML 和 CSS 的功能有着密切的关系，因为它负责处理通过这些技术定义的自定义字体。

**CSS:**

*   **`@font-face` 规则:**  这是触发 `FontCustomPlatformData` 使用的最直接方式。`@font-face` 规则定义了自定义字体的来源（`src`），以及其他属性，例如字体族名称（`font-family`）、粗细（`font-weight`）、样式（`font-style`）等。浏览器解析到 `@font-face` 规则时，会下载字体文件，并调用 `FontCustomPlatformData::Create` 来加载和解码字体。
    *   **假设输入:**  一个包含 `@font-face` 规则的 CSS 文件：
        ```css
        @font-face {
          font-family: 'MyCustomFont';
          src: url('my-custom-font.woff2');
          font-weight: bold;
          font-style: italic;
          font-variation-settings: 'wght' 700, 'slnt' 10;
          font-palette: light;
        }

        body {
          font-family: 'MyCustomFont', sans-serif;
          font-weight: bold;
          font-style: italic;
        }
        ```
    *   **输出 (在 `FontCustomPlatformData` 中发生的操作):**
        1. 下载 `my-custom-font.woff2` 文件。
        2. `FontCustomPlatformData::Create` 被调用，解码字体文件，创建 `SkTypeface` 对象。
        3. 当元素使用 `font-family: 'MyCustomFont'` 时，`GetFontPlatformData` 会被调用。
        4. `GetFontPlatformData` 会根据 `font-weight: bold`, `font-style: italic` 以及 `font-variation-settings: 'wght' 700, 'slnt' 10` 来调整 `SkTypeface` 的参数，生成一个粗体、斜体且具有指定可变轴值的 `FontPlatformData`。
        5. `GetFontPlatformData` 还会根据 `font-palette: light` 来选择或生成相应的颜色调色板。
*   **`font-variation-settings`:**  该 CSS 属性允许精细地控制可变字体的各个轴。`FontCustomPlatformData` 的逻辑会解析这些设置，并应用到 `SkTypeface` 上。
    *   **假设输入:**  `font-variation-settings: 'wdth' 150;`
    *   **输出:**  `GetFontPlatformData` 会创建一个宽度（width）轴值为 150 的 `FontPlatformData` 实例。
*   **`font-palette` 和 `font-palette-values`:** 这些 CSS 属性用于控制颜色字体的外观。`FontCustomPlatformData` 会解析这些属性，并根据设置选择或自定义字体的颜色。
    *   **假设输入:** `font-palette: dark;` 或者 `font-palette: --my-custom-palette;`
    *   **输出:** `GetFontPlatformData` 会尝试选择名为 "dark" 的预定义调色板，或者名为 "--my-custom-palette" 的自定义调色板。如果找到，生成的 `FontPlatformData` 将使用该调色板。

**HTML:**

*   HTML 文件通过 `<link>` 标签引入 CSS 文件，或者直接在 `<style>` 标签中定义 CSS 规则。这些 CSS 规则中可能包含 `@font-face` 声明，从而触发 `FontCustomPlatformData` 的工作。

**JavaScript:**

*   JavaScript 可以动态地修改元素的 CSS 样式，包括与字体相关的属性。当通过 JavaScript 设置或修改了影响自定义字体的 CSS 属性时，可能会导致重新调用 `GetFontPlatformData` 来获取新的 `FontPlatformData` 实例。
*   此外，文件中提到的 V8 集成是为了进行内存管理。当 `FontCustomPlatformData` 加载了新的字体数据时，它会通知 V8 引擎，以便 V8 的垃圾回收器能够跟踪这部分内存，防止内存泄漏。

**逻辑推理的假设输入与输出:**

假设我们有一个可变字体 "MyVariableFont" 支持 "wght" (粗细) 和 "slnt" (倾斜) 两个轴。

*   **假设输入 1 (CSS):**
    ```css
    body {
      font-family: 'MyVariableFont';
      font-variation-settings: 'wght' 400;
    }
    ```
    **输出:** `GetFontPlatformData` 会创建一个 `FontPlatformData` 实例，其底层的 `SkTypeface` 的 "wght" 轴被设置为 400，而 "slnt" 轴使用默认值。

*   **假设输入 2 (CSS):**
    ```css
    body {
      font-family: 'MyVariableFont';
      font-variation-settings: 'wght' 700, 'slnt' -10;
    }
    ```
    **输出:** `GetFontPlatformData` 会创建一个 `FontPlatformData` 实例，其底层的 `SkTypeface` 的 "wght" 轴被设置为 700，"slnt" 轴被设置为 -10。

*   **假设输入 3 (CSS，颜色字体):**
    假设 "MyColorFont" 是一个颜色字体，并且定义了一个名为 "vibrant" 的调色板。
    ```css
    body {
      font-family: 'MyColorFont';
      font-palette: vibrant;
    }
    ```
    **输出:** `GetFontPlatformData` 会创建一个 `FontPlatformData` 实例，并使用 "vibrant" 调色板来渲染字体。

**涉及用户或者编程常见的使用错误:**

1. **错误的字体文件路径:** 在 `@font-face` 规则中提供的 `src` 路径不正确，导致字体文件无法下载或加载。这会导致浏览器无法使用该自定义字体，通常会回退到默认字体。
    *   **例子:** `@font-face { font-family: 'MyFont'; src: url('fonts/myfont.woff'); }`，但 `myfont.woff` 文件实际上不在 `fonts` 目录下。
2. **字体文件格式不支持:** 浏览器可能不支持特定格式的字体文件（例如，旧版本的浏览器可能不支持 WOFF2）。
    *   **例子:**  只提供了 WOFF2 格式的字体，但在一个不支持 WOFF2 的旧版本浏览器上使用。
3. **`font-variation-settings` 语法错误或使用了不存在的轴:**  在 `font-variation-settings` 中使用了错误的标签或者设置了字体不支持的轴。这可能导致设置无效，或者浏览器忽略这些设置。
    *   **例子:** `font-variation-settings: 'wgth' 700;` (正确的标签是 'wght') 或者对一个静态字体设置了可变轴。
4. **`font-palette` 指定了不存在的调色板名称:**  在 `font-palette` 属性中使用了字体没有定义的调色板名称。这会导致使用默认的调色板。
    *   **例子:** `font-palette: non-existent-palette;`，但该字体没有名为 "non-existent-palette" 的调色板。
5. **`font-palette-values` 语法错误:** 在定义自定义调色板时使用了错误的语法，导致浏览器无法解析。
    *   **例子:**  `font-palette-values: --my-palette { base-color: red };` (缺少 `font-family`)。
6. **混合使用 `font-weight` 和 `font-variation-settings` 的 "wght" 轴:**  同时使用 `font-weight` 和 `font-variation-settings` 来控制字体的粗细可能会导致冲突或意外的结果，因为它们都影响字体的粗细。推荐使用 `font-variation-settings` 来更精确地控制可变字体的特性。

总而言之，`font_custom_platform_data.cc` 是 Blink 渲染引擎中处理自定义字体的核心组件，它负责将通过 CSS 定义的字体资源转化为浏览器可以理解和渲染的格式，并根据 CSS 属性进行调整，包括处理可变字体和颜色字体。理解这个文件的功能有助于理解浏览器如何加载和渲染网页上使用的各种字体。

### 提示词
```
这是目录为blink/renderer/platform/fonts/font_custom_platform_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2007 Apple Computer, Inc.
 * Copyright (c) 2007, 2008, 2009, Google Inc. All rights reserved.
 * Copyright (C) 2010 Company 100, Inc.
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

#include "third_party/blink/renderer/platform/fonts/font_custom_platform_data.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/opentype/font_format_check.h"
#include "third_party/blink/renderer/platform/fonts/opentype/font_settings.h"
#include "third_party/blink/renderer/platform/fonts/opentype/variable_axes_names.h"
#include "third_party/blink/renderer/platform/fonts/palette_interpolation.h"
#include "third_party/blink/renderer/platform/fonts/web_font_decoder.h"
#include "third_party/blink/renderer/platform/fonts/web_font_typeface_factory.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/skia/include/core/SkTypeface.h"
#include "v8/include/v8.h"

namespace {

constexpr SkFourByteTag kOpszTag = SkSetFourByteTag('o', 'p', 's', 'z');
constexpr SkFourByteTag kSlntTag = SkSetFourByteTag('s', 'l', 'n', 't');
constexpr SkFourByteTag kWdthTag = SkSetFourByteTag('w', 'd', 't', 'h');
constexpr SkFourByteTag kWghtTag = SkSetFourByteTag('w', 'g', 'h', 't');

std::optional<SkFontParameters::Variation::Axis>
RetrieveVariationDesignParametersByTag(sk_sp<SkTypeface> base_typeface,
                                       SkFourByteTag tag) {
  int axes_count = base_typeface->getVariationDesignParameters(nullptr, 0);
  if (axes_count <= 0)
    return std::nullopt;
  Vector<SkFontParameters::Variation::Axis> axes;
  axes.resize(axes_count);
  int axes_read =
      base_typeface->getVariationDesignParameters(axes.data(), axes_count);
  if (axes_read <= 0)
    return std::nullopt;
  for (auto& axis : axes) {
    if (axis.tag == tag) {
      return axis;
    }
  }
  return std::nullopt;
}

}  // namespace

namespace blink {

FontCustomPlatformData::FontCustomPlatformData(PassKey,
                                               sk_sp<SkTypeface> typeface,
                                               size_t data_size)
    : base_typeface_(std::move(typeface)), data_size_(data_size) {
  // The new instance of SkData was created while decoding. It stores data
  // from decoded font resource. GC is not aware of this allocation, so we
  // need to inform it.
  if (v8::Isolate* isolate = v8::Isolate::TryGetCurrent()) {
    external_memory_accounter_.Increase(isolate, data_size_);
  }
}

FontCustomPlatformData::~FontCustomPlatformData() {
  if (v8::Isolate* isolate = v8::Isolate::TryGetCurrent()) {
    // Safe cast since WebFontDecoder has max decompressed size of 128MB.
    external_memory_accounter_.Decrease(isolate, data_size_);
  }
}

const FontPlatformData* FontCustomPlatformData::GetFontPlatformData(
    float size,
    float adjusted_specified_size,
    bool bold,
    bool italic,
    const FontSelectionRequest& selection_request,
    const FontSelectionCapabilities& selection_capabilities,
    const OpticalSizing& optical_sizing,
    TextRenderingMode text_rendering,
    const ResolvedFontFeatures& resolved_font_features,
    FontOrientation orientation,
    const FontVariationSettings* variation_settings,
    const FontPalette* palette) const {
  DCHECK(base_typeface_);

  sk_sp<SkTypeface> return_typeface = base_typeface_;

  // Maximum axis count is maximum value for the OpenType USHORT,
  // which is a 16bit unsigned.
  // https://www.microsoft.com/typography/otspec/fvar.htm Variation
  // settings coming from CSS can have duplicate assignments and the
  // list can be longer than UINT16_MAX, but ignoring the length for
  // now, going with a reasonable upper limit. Deduplication is
  // handled by Skia with priority given to the last occuring
  // assignment.
  FontFormatCheck::VariableFontSubType font_sub_type =
      FontFormatCheck::ProbeVariableFont(base_typeface_);
  bool synthetic_bold = bold;
  bool synthetic_italic = italic;
  if (font_sub_type ==
          FontFormatCheck::VariableFontSubType::kVariableTrueType ||
      font_sub_type == FontFormatCheck::VariableFontSubType::kVariableCFF2) {
    Vector<SkFontArguments::VariationPosition::Coordinate, 0> variation;

    SkFontArguments::VariationPosition::Coordinate weight_coordinate = {
        kWghtTag, SkFloatToScalar(selection_capabilities.weight.clampToRange(
                      selection_request.weight))};
    std::optional<SkFontParameters::Variation::Axis> wght_parameters =
        RetrieveVariationDesignParametersByTag(base_typeface_, kWghtTag);
    if (selection_capabilities.weight.IsRangeSetFromAuto() && wght_parameters) {
      FontSelectionRange wght_range = {
          FontSelectionValue(wght_parameters->min),
          FontSelectionValue(wght_parameters->max)};
      weight_coordinate = {
          kWghtTag,
          SkFloatToScalar(wght_range.clampToRange(selection_request.weight))};
      synthetic_bold = bold && wght_range.maximum < kBoldThreshold &&
                       selection_request.weight >= kBoldThreshold;
    }

    SkFontArguments::VariationPosition::Coordinate width_coordinate = {
        kWdthTag, SkFloatToScalar(selection_capabilities.width.clampToRange(
                      selection_request.width))};
    std::optional<SkFontParameters::Variation::Axis> wdth_parameters =
        RetrieveVariationDesignParametersByTag(base_typeface_, kWdthTag);
    if (selection_capabilities.width.IsRangeSetFromAuto() && wdth_parameters) {
      FontSelectionRange wdth_range = {
          FontSelectionValue(wdth_parameters->min),
          FontSelectionValue(wdth_parameters->max)};
      width_coordinate = {
          kWdthTag,
          SkFloatToScalar(wdth_range.clampToRange(selection_request.width))};
    }
    // CSS and OpenType have opposite definitions of direction of slant
    // angle. In OpenType positive values turn counter-clockwise, negative
    // values clockwise - in CSS positive values are clockwise rotations /
    // skew. See note in https://drafts.csswg.org/css-fonts/#font-style-prop -
    // map value from CSS to OpenType here.
    SkFontArguments::VariationPosition::Coordinate slant_coordinate = {
        kSlntTag, SkFloatToScalar(-selection_capabilities.slope.clampToRange(
                      selection_request.slope))};
    std::optional<SkFontParameters::Variation::Axis> slnt_parameters =
        RetrieveVariationDesignParametersByTag(base_typeface_, kSlntTag);
    if (selection_capabilities.slope.IsRangeSetFromAuto() && slnt_parameters) {
      FontSelectionRange slnt_range = {
          FontSelectionValue(slnt_parameters->min),
          FontSelectionValue(slnt_parameters->max)};
      slant_coordinate = {
          kSlntTag,
          SkFloatToScalar(slnt_range.clampToRange(-selection_request.slope))};
      synthetic_italic = italic && slnt_range.maximum < kItalicSlopeValue &&
                         selection_request.slope >= kItalicSlopeValue;
    }

    variation.push_back(weight_coordinate);
    variation.push_back(width_coordinate);
    variation.push_back(slant_coordinate);

    bool explicit_opsz_configured = false;
    if (variation_settings && variation_settings->size() < UINT16_MAX) {
      variation.reserve(variation_settings->size() + variation.size());
      for (const auto& setting : *variation_settings) {
        if (setting.Tag() == kOpszTag)
          explicit_opsz_configured = true;
        SkFontArguments::VariationPosition::Coordinate setting_coordinate =
            {setting.Tag(), SkFloatToScalar(setting.Value())};
        variation.push_back(setting_coordinate);
      }
    }

    if (!explicit_opsz_configured) {
      if (optical_sizing == kAutoOpticalSizing) {
        SkFontArguments::VariationPosition::Coordinate opsz_coordinate = {
            kOpszTag, SkFloatToScalar(adjusted_specified_size)};
        variation.push_back(opsz_coordinate);
      } else if (optical_sizing == kNoneOpticalSizing) {
        // Explicitly set default value to avoid automatic application of
        // optical sizing as it seems to happen on SkTypeface on Mac.
        std::optional<SkFontParameters::Variation::Axis> opsz_parameters =
            RetrieveVariationDesignParametersByTag(return_typeface, kOpszTag);
        if (opsz_parameters) {
          float opszDefault = opsz_parameters->def;
          SkFontArguments::VariationPosition::Coordinate opsz_coordinate = {
              kOpszTag, SkFloatToScalar(opszDefault)};
          variation.push_back(opsz_coordinate);
        }
      }
    }

    SkFontArguments font_args;
    font_args.setVariationDesignPosition(
        {variation.data(), static_cast<int>(variation.size())});
    sk_sp<SkTypeface> sk_variation_font(base_typeface_->makeClone(font_args));

    if (sk_variation_font) {
      return_typeface = sk_variation_font;
    } else {
      SkString family_name;
      base_typeface_->getFamilyName(&family_name);
      // TODO: Surface this as a console message?
      LOG(ERROR) << "Unable for apply variation axis properties for font: "
                 << family_name.c_str();
    }
  }

  if (palette && !palette->IsNormalPalette()) {
    // TODO: Check applicability of font-palette-values according to matching
    // font family name, or should that be done at the CSS family level?

    SkFontArguments font_args;
    SkFontArguments::Palette sk_palette{0, nullptr, 0};

    Vector<FontPalette::FontPaletteOverride> color_overrides;
    std::optional<uint16_t> palette_index = std::nullopt;
    PaletteInterpolation palette_interpolation(base_typeface_);
    if (palette->IsInterpolablePalette()) {
      color_overrides =
          palette_interpolation.ComputeInterpolableFontPalette(palette);
      palette_index = 0;
    } else {
      color_overrides = *palette->GetColorOverrides();
      palette_index = palette_interpolation.RetrievePaletteIndex(palette);
    }

    std::unique_ptr<SkFontArguments::Palette::Override[]> sk_overrides;
    if (palette_index.has_value()) {
      sk_palette.index = *palette_index;

      if (color_overrides.size()) {
        sk_overrides = std::make_unique<SkFontArguments::Palette::Override[]>(
            color_overrides.size());
        for (wtf_size_t i = 0; i < color_overrides.size(); i++) {
          SkColor sk_color = color_overrides[i].color.toSkColor4f().toSkColor();
          sk_overrides[i] = {color_overrides[i].index, sk_color};
        }
        sk_palette.overrides = sk_overrides.get();
        sk_palette.overrideCount = color_overrides.size();
      }

      font_args.setPalette(sk_palette);
    }

    sk_sp<SkTypeface> palette_typeface(return_typeface->makeClone(font_args));
    if (palette_typeface) {
      return_typeface = palette_typeface;
    }
  }
  return MakeGarbageCollected<FontPlatformData>(
      std::move(return_typeface), std::string(), size,
      synthetic_bold && !base_typeface_->isBold(),
      synthetic_italic && !base_typeface_->isItalic(), text_rendering,
      resolved_font_features, orientation);
}

Vector<VariationAxis> FontCustomPlatformData::GetVariationAxes() const {
  return VariableAxesNames::GetVariationAxes(base_typeface_);
}

String FontCustomPlatformData::FamilyNameForInspector() const {
  SkTypeface::LocalizedStrings* font_family_iterator =
      base_typeface_->createFamilyNameIterator();
  SkTypeface::LocalizedString localized_string;
  while (font_family_iterator->next(&localized_string)) {
    // BCP 47 tags for English take precedent in font matching over other
    // localizations: https://drafts.csswg.org/css-fonts/#descdef-src.
    if (localized_string.fLanguage.equals("en") ||
        localized_string.fLanguage.equals("en-US")) {
      break;
    }
  }
  font_family_iterator->unref();
  return String::FromUTF8(base::as_byte_span(localized_string.fString));
}

FontCustomPlatformData* FontCustomPlatformData::Create(
    SharedBuffer* buffer,
    String& ots_parse_message) {
  DCHECK(buffer);
  WebFontDecoder decoder;
  sk_sp<SkTypeface> typeface = decoder.Decode(buffer);
  if (!typeface) {
    ots_parse_message = decoder.GetErrorString();
    return nullptr;
  }
  return Create(std::move(typeface), decoder.DecodedSize());
}

FontCustomPlatformData* FontCustomPlatformData::Create(
    sk_sp<SkTypeface> typeface,
    size_t data_size) {
  return MakeGarbageCollected<FontCustomPlatformData>(
      PassKey(), std::move(typeface), data_size);
}

}  // namespace blink
```