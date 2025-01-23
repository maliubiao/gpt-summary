Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding & Goal:**

The request asks for the *functionality* of the `style_builder_converter.cc` file in the Chromium Blink rendering engine. It also asks about its relationship to HTML, CSS, and JavaScript, along with examples, logic inferences, and common user errors. Crucially, it's labeled as "Part 1 of 5," implying we should focus on the *overall* purpose and the specific functions covered in this snippet.

**2. Core Observation - The "Converter" Name:**

The name "StyleBuilderConverter" immediately suggests its primary responsibility: *converting* CSS values into internal Blink style representations. This is a fundamental step in the rendering process.

**3. Examining the Includes:**

The included headers provide strong clues about the file's scope:

* **`core/css/...`**:  Many headers related to different CSS value types (colors, lengths, fonts, grids, etc.) and parsing. This reinforces the "conversion" idea.
* **`core/style/...`**: Headers related to Blink's internal style data structures (e.g., `ComputedStyle`, `StyleReflection`, `FontDescription`). This confirms the conversion *target*.
* **`core/frame/...`**: Headers for frame-related concepts (settings, documents). This hints that the conversion process needs context from the document.
* **`platform/...`**: Headers related to platform-specific utilities (fonts, geometry, etc.). This suggests the conversion might involve platform-dependent logic.
* **`third_party/...`**: External libraries being used.

**4. Analyzing the Code Structure:**

* **Namespace `blink`:**  Clearly part of the Blink rendering engine.
* **`kFinalStatePercentage`, `kMiddleStatePercentage`:** Constants related to percentages, likely used in calculations for certain CSS properties (e.g., gradients, mixes).
* **Internal Helper Functions (within the anonymous namespace):** Functions like `ConvertGridTrackBreadth`, `ValueListToAtomicStringVector`, `ResolveQuirkOrLinkOrFocusRingColor`. These are small, specific conversion utilities. They indicate that the main class handles more complex, higher-level conversions.
* **Public Methods of `StyleBuilderConverter`:** These are the primary functions performing the conversions (e.g., `ConvertBoxReflect`, `ConvertDynamicRangeLimit`, `ConvertClipPath`, `ConvertFontFamily`). The names directly correspond to CSS properties.
* **`StyleBuilderConverterBase`:**  A base class suggesting a potential hierarchy or separation of concerns, maybe for shared conversion logic.

**5. Connecting to CSS, HTML, and JavaScript:**

* **CSS:** The entire purpose revolves around processing CSS. Each `Convert...` function likely corresponds to a specific CSS property. The inclusion of CSS value headers makes this explicit.
* **HTML:**  The converted styles are ultimately applied to HTML elements. The code interacts with the document structure (through `StyleResolverState`). The examples involving `<a>` tags for `ConvertBoxReflect` and `clip-path` demonstrate this connection.
* **JavaScript:** JavaScript can manipulate CSS styles dynamically. While this file doesn't directly *execute* JavaScript, the conversions it performs are necessary for the browser to *reflect* JavaScript style changes. The example of using `element.style.clipPath` ties JavaScript manipulation to this conversion process.

**6. Inferring Logic and Examples:**

By examining the function names and their parameters, we can infer the input and output:

* **Input:** A `CSSValue` object representing a parsed CSS value.
* **Output:** An internal Blink style representation (e.g., `scoped_refptr<StyleReflection>`, `DynamicRangeLimit`, `ClipPathOperation*`, `FontDescription::FamilyDescription`).

Examples can be constructed by considering common CSS usage:

* **`ConvertBoxReflect`:**  CSS `box-reflect` property.
* **`ConvertClipPath`:** CSS `clip-path` property with `url()` or `polygon()`.
* **`ConvertFontFamily`:** CSS `font-family` property with various font names.

**7. Identifying Potential User Errors:**

Common CSS mistakes can lead to incorrect conversions:

* **Invalid CSS syntax:**  Incorrect units, typos, etc. The parser handles some of this, but invalid values might still reach the converter.
* **Using deprecated or non-standard CSS:**  The converter might not handle them, or handle them in a specific way.
* **Incorrect understanding of CSS property values:**  Users might provide values that are syntactically correct but semantically wrong for the intended effect.

**8. Tracing User Actions (Debugging Clues):**

The sequence of events leading to this code is the core rendering pipeline:

1. **User action:** Loads a webpage or interacts with it.
2. **HTML parsing:** The HTML is parsed into a DOM tree.
3. **CSS parsing:**  The browser fetches and parses CSS (from stylesheets, `<style>` tags, inline styles).
4. **Style resolution:** This is where `style_builder_converter.cc` plays a crucial role. The parsed CSS values are converted into internal style representations. This involves matching CSS rules to DOM elements and calculating the final styles.
5. **Layout:** The browser calculates the position and size of elements based on the computed styles.
6. **Painting:** The browser renders the elements to the screen.

**9. Focusing on "Part 1 of 5" and Summarization:**

Given that this is only part 1, the summary should focus on the *overall role* of the file and the specific types of conversions it handles in this initial section. Avoid going too deep into details that might be covered in later parts.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe it just converts simple values.
* **Correction:**  The presence of functions like `ConvertGridTrackBreadth` and `ConvertClipPath` shows it handles more complex CSS features.
* **Initial thought:**  It directly applies styles.
* **Correction:** It *converts* the values into a format that the style system can then use to *apply* styles. It's an intermediary step.
* **Consider the "unsafe buffers" comment:**  Note its presence and potential implication (memory safety), even if not fully understood without more context. Mention it as a technical detail.

By following this structured approach of examining the code's name, includes, structure, and connecting it to web technologies, we can arrive at a comprehensive understanding of the functionality of this C++ file, even without deep knowledge of the entire Blink codebase.
好的，我们来分析一下 `blink/renderer/core/css/resolver/style_builder_converter.cc` 这个文件的功能。

**文件功能归纳（针对提供的第1部分代码）:**

`style_builder_converter.cc` 的主要功能是将 **CSS 属性值 (Parsed CSS Values)** 转换为 **Blink 渲染引擎内部使用的样式数据结构 (Computed Style Data)**。它是一个关键的转换器，位于 CSS 解析和最终样式计算之间。

更具体地说，从提供的代码片段来看，这个文件的第一部分主要负责以下类型的转换：

* **复杂 CSS 值的转换:**  它处理各种复杂的 CSS 数据类型，例如：
    * `box-reflect` (盒子的反射效果)
    * `dynamic-range-limit` (动态范围限制)
    * `clip-path` (裁剪路径)
    * `filter` (滤镜效果)
    * `font-family` (字体族)
    * `font-kerning`, `font-variant-position`, `font-variant-emoji`, `font-optical-sizing` 等字体相关的属性
    * `font-feature-settings`, `font-variation-settings` (OpenType 字体特性和变体设置)
    * `font-palette` (字体调色板)
    * `font-size` (字体大小)
* **CSS 标识符到枚举值的转换:** 将 CSS 关键字（例如 `auto`, `none`, `serif`, `sans-serif`）转换为 Blink 内部使用的枚举值。
* **CSS 函数到内部数据结构的转换:**  处理 CSS 函数，例如 `url()` (用于 `clip-path`), `palette()` (用于 `font-palette`), `color-mix()` 等。
* **长度单位的转换:**  将 CSS 中不同的长度单位（例如 `px`, `em`, `rem`, `%`）转换为内部使用的 `Length` 类型。
* **颜色值的转换:**  虽然这部分代码没有直接展示颜色转换的函数，但引入了 `CSSColor` 等头文件，暗示了它也参与颜色值的处理。
* **处理特殊的 CSS 值:** 例如 `internal-quirk-inherit`, `-webkit-link`, `-webkit-activelink`, `-webkit-focus-ring-color` 这些浏览器特定的 CSS 值。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **CSS:** 这个文件的核心功能就是处理 CSS。它接收 CSS 解析器输出的 CSS 属性值，并将其转换为 Blink 可以理解和使用的格式。
   * **例子:** 当 CSS 规则中定义了 `clip-path: polygon(50% 0%, 0% 100%, 100% 100%);` 时，`ConvertClipPath` 函数会被调用，将这个多边形定义转换为 `ShapeClipPathOperation` 对象。

2. **HTML:**  CSS 样式最终会应用到 HTML 元素上。当浏览器解析 HTML 并构建 DOM 树后，会根据 CSS 规则计算每个元素的样式。`style_builder_converter.cc` 在这个过程中扮演着关键的桥梁作用，确保 CSS 样式能够正确地应用到相应的 HTML 元素。
   * **例子:**  如果一个 `<div>` 元素的 CSS `font-family` 设置为 `Arial, sans-serif`,  `ConvertFontFamily` 函数会将 "Arial" 和 "sans-serif" 转换为 `FontDescription::FamilyDescription` 对象，以便后续的字体匹配和渲染。

3. **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 修改样式时，例如使用 `element.style.clipPath = 'circle(50px)';`，浏览器需要重新解析和计算样式。 `style_builder_converter.cc` 会再次参与这个过程，将 JavaScript 设置的 CSS 值转换为内部表示。
   * **例子:** JavaScript 代码 `element.style.filter = 'blur(5px)';` 执行后，`ConvertFilterOperations` 函数会被调用，将 "blur(5px)" 转换为 `FilterOperations` 对象，用于后续的图形渲染。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 `CSSValue` 对象，表示 CSS 属性 `box-reflect: below 10px;`
* **输出:** 一个指向 `StyleReflection` 对象的智能指针，该对象内部存储了反射的方向 (below) 和偏移量 (10px)。

* **假设输入:** 一个 `CSSValue` 对象，表示 CSS 属性 `font-family: "Times New Roman", serif;`
* **输出:** 一个 `FontDescription::FamilyDescription` 对象，其中包含一个 `FontFamily` 链表，第一个节点是 "Times New Roman"，类型是 `kFamilyName`，第二个节点是 "serif"，类型是 `kGenericFamily`。

**用户或编程常见的使用错误:**

* **拼写错误的 CSS 关键字:** 如果用户在 CSS 中错误地拼写了关键字，例如 `filtter: blur(5px);`，CSS 解析器可能无法识别，导致样式无法应用。即使解析器可以识别（例如，作为自定义属性），`style_builder_converter.cc` 也可能无法正确处理，因为它依赖于预定义的 CSS 关键字。
* **使用了无效的 CSS 值:**  例如，对于 `clip-path` 属性，如果用户提供了一个不是有效形状函数或 `url()` 的值，`ConvertClipPath` 函数可能返回空指针或创建一个表示错误的内部对象。
* **类型不匹配的 CSS 值:** 某些 CSS 属性只接受特定类型的值。例如，`opacity` 应该是一个 0 到 1 之间的数字。如果用户提供了其他类型的值，转换器可能会抛出错误或使用默认值。
* **使用了浏览器不支持的 CSS 特性:**  如果用户使用了当前浏览器版本不支持的 CSS 属性或值，`style_builder_converter.cc` 中可能没有相应的转换逻辑，导致该样式被忽略。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中加载了一个网页。**
2. **浏览器开始解析 HTML 文件，构建 DOM 树。**
3. **浏览器遇到 `<link>` 标签或 `<style>` 标签，或者解析 HTML 元素的 `style` 属性，开始下载和解析 CSS。**
4. **CSS 解析器将 CSS 规则和属性值解析成 `CSSValue` 对象。**
5. **当需要计算一个元素的最终样式时，Blink 的样式解析器会遍历该元素适用的 CSS 规则。**
6. **对于每个 CSS 属性，样式系统会调用 `style_builder_converter.cc` 中相应的 `Convert...` 函数，将 `CSSValue` 转换为内部样式表示。**
7. **转换后的内部样式数据会被存储在 `ComputedStyle` 对象中，用于后续的布局和渲染。**

**总结 (针对第1部分):**

`blink/renderer/core/css/resolver/style_builder_converter.cc` (第1部分) 是 Blink 渲染引擎中负责将已解析的 CSS 属性值转换为内部样式数据结构的关键组件。它处理多种复杂的 CSS 属性，为后续的样式计算、布局和渲染奠定基础。这个文件直接关联着 CSS 语言，并通过处理应用于 HTML 元素的样式，间接地与 HTML 和 JavaScript 产生联系。理解这个文件的功能有助于理解浏览器如何将 CSS 代码转化为用户最终看到的网页。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_builder_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <algorithm>
#include <memory>
#include <utility>

#include "base/containers/adapters.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/core/css/basic_shape_functions.h"
#include "third_party/blink/renderer/core/css/css_alternate_value.h"
#include "third_party/blink/renderer/core/css/css_axis_value.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_color_mix_value.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_dynamic_range_limit_mix_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_feature_value.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_font_variation_value.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_light_dark_value_pair.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_palette_mix_value.h"
#include "third_party/blink/renderer/core/css/css_path_value.h"
#include "third_party/blink/renderer/core/css/css_pending_system_font_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_quad_value.h"
#include "third_party/blink/renderer/core/css/css_ratio_value.h"
#include "third_party/blink/renderer/core/css/css_reflect_value.h"
#include "third_party/blink/renderer/core/css/css_relative_color_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_scoped_keyword_value.h"
#include "third_party/blink/renderer/core/css/css_shadow_value.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/resolver/filter_operation_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/transform_builder.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/coord_box_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/geometry_box_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/offset_path_operation.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/reference_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/scoped_css_name.h"
#include "third_party/blink/renderer/core/style/scroll_start_data.h"
#include "third_party/blink/renderer/core/style/shape_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/shape_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/style_overflow_clip_margin.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/style/style_view_transition_group.h"
#include "third_party/blink/renderer/platform/fonts/font_palette.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_math_support.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

const double kFinalStatePercentage = 100.0;
const double kMiddleStatePercentage = 50.0;

namespace {

Length ConvertGridTrackBreadth(const StyleResolverState& state,
                               const CSSValue& value) {
  // Fractional unit.
  auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  if (primitive_value && primitive_value->IsFlex()) {
    return Length::Flex(primitive_value->ComputeValueInCanonicalUnit(
        state.CssToLengthConversionData()));
  }

  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value) {
    if (identifier_value->GetValueID() == CSSValueID::kMinContent) {
      return Length::MinContent();
    }
    if (identifier_value->GetValueID() == CSSValueID::kMaxContent) {
      return Length::MaxContent();
    }
  }

  return StyleBuilderConverter::ConvertLengthOrAuto(state, value);
}

Vector<AtomicString> ValueListToAtomicStringVector(
    const CSSValueList& value_list) {
  Vector<AtomicString> ret;
  for (auto list_entry : value_list) {
    const CSSCustomIdentValue& ident = To<CSSCustomIdentValue>(*list_entry);
    ret.push_back(ident.Value());
  }
  return ret;
}

AtomicString FirstEntryAsAtomicString(const CSSValueList& value_list) {
  DCHECK_EQ(value_list.length(), 1u);
  return To<CSSCustomIdentValue>(value_list.Item(0)).Value();
}

bool IsQuirkOrLinkOrFocusRingColor(CSSValueID value_id) {
  return value_id == CSSValueID::kInternalQuirkInherit ||
         value_id == CSSValueID::kWebkitLink ||
         value_id == CSSValueID::kWebkitActivelink ||
         value_id == CSSValueID::kWebkitFocusRingColor;
}

Color ResolveQuirkOrLinkOrFocusRingColor(
    CSSValueID value_id,
    const TextLinkColors& text_link_colors,
    mojom::blink::ColorScheme used_color_scheme,
    bool for_visited_link) {
  switch (value_id) {
    case CSSValueID::kInternalQuirkInherit:
      return text_link_colors.TextColor(used_color_scheme);
    case CSSValueID::kWebkitLink:
      return for_visited_link
                 ? text_link_colors.VisitedLinkColor(used_color_scheme)
                 : text_link_colors.LinkColor(used_color_scheme);
    case CSSValueID::kWebkitActivelink:
      return text_link_colors.ActiveLinkColor(used_color_scheme);
    case CSSValueID::kWebkitFocusRingColor:
      return LayoutTheme::GetTheme().FocusRingColor(used_color_scheme);
    default:
      NOTREACHED();
  }
}

}  // namespace

scoped_refptr<StyleReflection> StyleBuilderConverter::ConvertBoxReflect(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return ComputedStyleInitialValues::InitialBoxReflect();
  }

  const auto& reflect_value = To<cssvalue::CSSReflectValue>(value);
  scoped_refptr<StyleReflection> reflection = StyleReflection::Create();
  reflection->SetDirection(
      reflect_value.Direction()->ConvertTo<CSSReflectionDirection>());
  if (reflect_value.Offset()) {
    reflection->SetOffset(reflect_value.Offset()->ConvertToLength(
        state.CssToLengthConversionData()));
  }
  if (reflect_value.Mask()) {
    NinePieceImage mask = NinePieceImage::MaskDefaults();
    CSSToStyleMap::MapNinePieceImage(state, CSSPropertyID::kWebkitBoxReflect,
                                     *reflect_value.Mask(), mask);
    reflection->SetMask(mask);
  }

  return reflection;
}

DynamicRangeLimit StyleBuilderConverter::ConvertDynamicRangeLimit(
    StyleResolverState& state,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertDynamicRangeLimit(value);
}

DynamicRangeLimit StyleBuilderConverterBase::ConvertDynamicRangeLimit(
    const CSSValue& value) {
  if (auto* mix_value =
          DynamicTo<cssvalue::CSSDynamicRangeLimitMixValue>(value)) {
    float standard_mix_sum = 0.f;
    float constrained_high_mix_sum = 0.f;
    float fraction_sum = 0.f;
    for (size_t i = 0; i < mix_value->Limits().size(); ++i) {
      const DynamicRangeLimit limit =
          ConvertDynamicRangeLimit(*mix_value->Limits()[i]);
      const float fraction =
          0.01f * mix_value->Percentages()[i]->GetFloatValue();
      fraction_sum += fraction;
      standard_mix_sum += fraction * limit.standard_mix;
      constrained_high_mix_sum += fraction * limit.constrained_high_mix;
    }
    CHECK_NE(fraction_sum, 0.f);
    return DynamicRangeLimit(
        /*standard_mix=*/standard_mix_sum / fraction_sum,
        /*constrained_high_mix=*/constrained_high_mix_sum / fraction_sum);
  } else if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kHigh:
        return DynamicRangeLimit(cc::PaintFlags::DynamicRangeLimit::kHigh);
      case CSSValueID::kConstrainedHigh:
        return DynamicRangeLimit(
            cc::PaintFlags::DynamicRangeLimit::kConstrainedHigh);
      case CSSValueID::kStandard:
        return DynamicRangeLimit(cc::PaintFlags::DynamicRangeLimit::kStandard);
      default:
        break;
    }
  }
  return DynamicRangeLimit(cc::PaintFlags::DynamicRangeLimit::kHigh);
}

StyleSVGResource* StyleBuilderConverter::ConvertElementReference(
    StyleResolverState& state,
    const CSSValue& value,
    CSSPropertyID property_id) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  const auto& url_value = To<cssvalue::CSSURIValue>(value);
  SVGResource* resource =
      state.GetElementStyleResources().GetSVGResourceFromValue(property_id,
                                                               url_value);
  return MakeGarbageCollected<StyleSVGResource>(
      resource, url_value.ValueForSerialization());
}

LengthBox StyleBuilderConverter::ConvertClip(StyleResolverState& state,
                                             const CSSValue& value) {
  const CSSQuadValue& rect = To<CSSQuadValue>(value);

  return LengthBox(ConvertLengthOrAuto(state, *rect.Top()),
                   ConvertLengthOrAuto(state, *rect.Right()),
                   ConvertLengthOrAuto(state, *rect.Bottom()),
                   ConvertLengthOrAuto(state, *rect.Left()));
}

ClipPathOperation* StyleBuilderConverter::ConvertClipPath(
    StyleResolverState& state,
    const CSSValue& value) {
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    if (list->First().IsBasicShapeValue() || list->First().IsPathValue()) {
      const CSSValue& shape_value = list->First();
      const CSSIdentifierValue* geometry_box_value = nullptr;
      if (list->length() == 2) {
        geometry_box_value = DynamicTo<CSSIdentifierValue>(list->Item(1));
      }
      if (geometry_box_value) {
        UseCounter::Count(state.GetDocument(),
                          WebFeature::kClipPathGeometryBox);
      }
      // If <geometry-box> is omitted, default to border-box.
      GeometryBox geometry_box =
          geometry_box_value ? geometry_box_value->ConvertTo<GeometryBox>()
                             : GeometryBox::kBorderBox;
      return MakeGarbageCollected<ShapeClipPathOperation>(
          BasicShapeForValue(state, shape_value), geometry_box);
    }
    UseCounter::Count(state.GetDocument(), WebFeature::kClipPathGeometryBox);
    auto& geometry_box_value = To<CSSIdentifierValue>(list->First());
    GeometryBox geometry_box = geometry_box_value.ConvertTo<GeometryBox>();
    return MakeGarbageCollected<GeometryBoxClipPathOperation>(geometry_box);
  }

  if (const auto* url_value = DynamicTo<cssvalue::CSSURIValue>(value)) {
    SVGResource* resource =
        state.GetElementStyleResources().GetSVGResourceFromValue(
            CSSPropertyID::kClipPath, *url_value);
    return MakeGarbageCollected<ReferenceClipPathOperation>(
        url_value->ValueForSerialization(), resource);
  }
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  DCHECK(identifier_value &&
         identifier_value->GetValueID() == CSSValueID::kNone);
  return nullptr;
}

FilterOperations StyleBuilderConverter::ConvertFilterOperations(
    StyleResolverState& state,
    const CSSValue& value,
    CSSPropertyID property_id) {
  return FilterOperationResolver::CreateFilterOperations(state, value,
                                                         property_id);
}

FilterOperations StyleBuilderConverter::ConvertOffscreenFilterOperations(
    const CSSValue& value,
    const Font& font) {
  return FilterOperationResolver::CreateOffscreenFilterOperations(value, font);
}

static FontDescription::GenericFamilyType ConvertGenericFamily(
    CSSValueID value_id) {
  switch (value_id) {
    case CSSValueID::kWebkitBody:
      return FontDescription::kWebkitBodyFamily;
    case CSSValueID::kSerif:
      return FontDescription::kSerifFamily;
    case CSSValueID::kSansSerif:
      return FontDescription::kSansSerifFamily;
    case CSSValueID::kCursive:
      return FontDescription::kCursiveFamily;
    case CSSValueID::kFantasy:
      return FontDescription::kFantasyFamily;
    case CSSValueID::kMonospace:
      return FontDescription::kMonospaceFamily;
    default:
      return FontDescription::kNoFamily;
  }
}

static bool ConvertFontFamilyName(
    const CSSValue& value,
    FontDescription::GenericFamilyType& generic_family,
    AtomicString& family_name,
    FontBuilder* font_builder,
    const Document* document_for_count) {
  if (auto* font_family_value = DynamicTo<CSSFontFamilyValue>(value)) {
    generic_family = FontDescription::kNoFamily;
    family_name = font_family_value->Value();
  } else if (font_builder) {
    // TODO(crbug.com/1065468): Get rid of GenericFamilyType.
    auto cssValueID = To<CSSIdentifierValue>(value).GetValueID();
    generic_family = ConvertGenericFamily(cssValueID);
    if (generic_family != FontDescription::kNoFamily) {
      family_name = font_builder->GenericFontFamilyName(generic_family);
      if (document_for_count && cssValueID == CSSValueID::kWebkitBody &&
          !family_name.empty()) {
        // TODO(crbug.com/1065468): Remove this counter when it's no longer
        // necessary.
        document_for_count->CountUse(
            WebFeature::kFontBuilderCSSFontFamilyWebKitPrefixBody);
      }
    } else if (cssValueID == CSSValueID::kSystemUi) {
      family_name = font_family_names::kSystemUi;
    } else if (cssValueID == CSSValueID::kMath) {
      family_name = font_family_names::kMath;
    }
    // Something went wrong with the conversion or retrieving the name from
    // preferences for the specific generic family.
    if (family_name.empty()) {
      return false;
    }
  }

  // Empty font family names (converted from CSSFontFamilyValue above) are
  // acceptable for defining and matching against
  // @font-faces, compare https://github.com/w3c/csswg-drafts/issues/4510.
  return !family_name.IsNull();
}

FontDescription::FamilyDescription StyleBuilderConverterBase::ConvertFontFamily(
    const CSSValue& value,
    FontBuilder* font_builder,
    const Document* document_for_count) {
  FontDescription::FamilyDescription desc(FontDescription::kNoFamily);

  if (const auto* system_font =
          DynamicTo<cssvalue::CSSPendingSystemFontValue>(value)) {
    desc.family = FontFamily(system_font->ResolveFontFamily(),
                             FontFamily::Type::kFamilyName);
    return desc;
  }

#if BUILDFLAG(IS_MAC)
  bool count_blink_mac_system_font = false;
#endif

  AtomicString family_name;
  FontFamily::Type family_type = FontFamily::Type::kFamilyName;
  scoped_refptr<SharedFontFamily> next;
  bool has_value = false;

  for (auto& family : base::Reversed(To<CSSValueList>(value))) {
    AtomicString next_family_name;
    FontDescription::GenericFamilyType generic_family =
        FontDescription::kNoFamily;

    if (!ConvertFontFamilyName(*family, generic_family, next_family_name,
                               font_builder, document_for_count)) {
      continue;
    }

    // TODO(crbug.com/1065468): Get rid of GenericFamilyType.
    const bool is_generic = generic_family != FontDescription::kNoFamily ||
                            IsA<CSSIdentifierValue>(*family);

    // Take the previous value and wrap it in a `SharedFontFamily` adding to
    // the linked list.
    if (has_value) {
      next =
          SharedFontFamily::Create(family_name, family_type, std::move(next));
    }
    family_name = next_family_name;
    family_type = is_generic ? FontFamily::Type::kGenericFamily
                             : FontFamily::Type::kFamilyName;
    has_value = true;

#if BUILDFLAG(IS_MAC)
    // TODO(https://crbug.com/554590): Remove this counter when it's no longer
    // necessary.
    if (IsA<CSSFontFamilyValue>(*family) &&
        family_name == FontCache::LegacySystemFontFamily()) {
      count_blink_mac_system_font = true;
      family_name = font_family_names::kSystemUi;
    } else if (is_generic && family_name == font_family_names::kSystemUi) {
      // If system-ui comes before BlinkMacSystemFont don't use-count.
      count_blink_mac_system_font = false;
    }
#endif

    if (desc.generic_family == FontDescription::GenericFamilyType::kNoFamily) {
      desc.generic_family = generic_family;
    }
  }

#if BUILDFLAG(IS_MAC)
  if (document_for_count && count_blink_mac_system_font) {
    document_for_count->CountUse(WebFeature::kBlinkMacSystemFont);
  }
#endif

  desc.family = FontFamily(family_name, family_type, std::move(next));
  return desc;
}

FontDescription::FamilyDescription StyleBuilderConverter::ConvertFontFamily(
    StyleResolverState& state,
    const CSSValue& value) {
  // TODO(crbug.com/336876): Use the correct tree scope.
  state.GetFontBuilder().SetFamilyTreeScope(&state.GetDocument());
  return StyleBuilderConverterBase::ConvertFontFamily(
      value,
      state.GetDocument().GetSettings() ? &state.GetFontBuilder() : nullptr,
      &state.GetDocument());
}

FontDescription::Kerning StyleBuilderConverter::ConvertFontKerning(
    StyleResolverState&,
    const CSSValue& value) {
  // When the font shorthand is specified, font-kerning property should
  // be reset to it's initial value.In this case, the CSS parser uses a special
  // value CSSPendingSystemFontValue to defer resolution of system font
  // properties. The auto generated converter does not handle this incoming
  // value.
  if (value.IsPendingSystemFontValue()) {
    return FontDescription::kAutoKerning;
  }

  CSSValueID value_id = To<CSSIdentifierValue>(value).GetValueID();
  switch (value_id) {
    case CSSValueID::kAuto:
      return FontDescription::kAutoKerning;
    case CSSValueID::kNormal:
      return FontDescription::kNormalKerning;
    case CSSValueID::kNone:
      return FontDescription::kNoneKerning;
    default:
      NOTREACHED();
  }
}

FontDescription::FontVariantPosition
StyleBuilderConverter::ConvertFontVariantPosition(StyleResolverState&,
                                                  const CSSValue& value) {
  // When the font shorthand is specified, font-variant-position property should
  // be reset to it's initial value. In this case, the CSS parser uses a special
  // value CSSPendingSystemFontValue to defer resolution of system font
  // properties. The auto generated converter does not handle this incoming
  // value.
  if (value.IsPendingSystemFontValue()) {
    return FontDescription::kNormalVariantPosition;
  }

  CSSValueID value_id = To<CSSIdentifierValue>(value).GetValueID();
  switch (value_id) {
    case CSSValueID::kNormal:
      return FontDescription::kNormalVariantPosition;
    case CSSValueID::kSub:
      return FontDescription::kSubVariantPosition;
    case CSSValueID::kSuper:
      return FontDescription::kSuperVariantPosition;
    default:
      NOTREACHED();
  }
}

FontVariantEmoji StyleBuilderConverter::ConvertFontVariantEmoji(
    StyleResolverState&,
    const CSSValue& value) {
  // When the font shorthand is specified, font-variant-emoji property should
  // be reset to it's initial value. In this case, the CSS parser uses a special
  // value CSSPendingSystemFontValue to defer resolution of system font
  // properties. The auto generated converter does not handle this incoming
  // value.
  if (value.IsPendingSystemFontValue()) {
    return kNormalVariantEmoji;
  }

  return To<CSSIdentifierValue>(value).ConvertTo<FontVariantEmoji>();
}

OpticalSizing StyleBuilderConverter::ConvertFontOpticalSizing(
    StyleResolverState&,
    const CSSValue& value) {
  // When the font shorthand is specified, font-optical-sizing property should
  // be reset to it's initial value. In this case, the CSS parser uses a special
  // value CSSPendingSystemFontValue to defer resolution of system font
  // properties. The auto generated converter does not handle this incoming
  // value.
  if (value.IsPendingSystemFontValue()) {
    return kAutoOpticalSizing;
  }

  CSSValueID value_id = To<CSSIdentifierValue>(value).GetValueID();
  switch (value_id) {
    case CSSValueID::kAuto:
      return kAutoOpticalSizing;
    case CSSValueID::kNone:
      return kNoneOpticalSizing;
    default:
      NOTREACHED();
  }
}

scoped_refptr<FontFeatureSettings>
StyleBuilderConverter::ConvertFontFeatureSettings(StyleResolverState& state,
                                                  const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return FontBuilder::InitialFeatureSettings();
  }

  if (value.IsPendingSystemFontValue()) {
    return FontBuilder::InitialFeatureSettings();
  }

  const auto& list = To<CSSValueList>(value);
  scoped_refptr<FontFeatureSettings> settings = FontFeatureSettings::Create();
  int len = list.length();
  for (int i = 0; i < len; ++i) {
    const auto& feature = To<cssvalue::CSSFontFeatureValue>(list.Item(i));
    settings->Append(FontFeature(feature.Tag(), feature.Value()));
  }
  return settings;
}

static bool CompareTags(FontVariationAxis a, FontVariationAxis b) {
  return a.Tag() < b.Tag();
}

scoped_refptr<FontVariationSettings>
StyleBuilderConverter::ConvertFontVariationSettings(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return FontBuilder::InitialVariationSettings();
  }

  if (value.IsPendingSystemFontValue()) {
    return FontBuilder::InitialVariationSettings();
  }

  const auto& list = To<CSSValueList>(value);
  int len = list.length();
  HashMap<uint32_t, float> axes;
  // Use a temporary HashMap to remove duplicate tags, keeping the last
  // occurrence of each.
  for (int i = 0; i < len; ++i) {
    const auto& feature = To<cssvalue::CSSFontVariationValue>(list.Item(i));
    axes.Set(AtomicStringToFourByteTag(feature.Tag()), feature.Value());
  }
  scoped_refptr<FontVariationSettings> settings =
      FontVariationSettings::Create();
  for (auto& axis : axes) {
    settings->Append(FontVariationAxis(axis.key, axis.value));
  }
  std::sort(settings->begin(), settings->end(), CompareTags);
  return settings;
}

scoped_refptr<FontPalette> StyleBuilderConverter::ConvertFontPalette(
    StyleResolverState& state,
    const CSSValue& value) {
  return StyleBuilderConverterBase::ConvertFontPalette(
      state.CssToLengthConversionData(), value);
}

scoped_refptr<FontPalette> StyleBuilderConverterBase::ConvertPaletteMix(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  auto* palette_mix_value = DynamicTo<cssvalue::CSSPaletteMixValue>(value);
  if (palette_mix_value) {
    scoped_refptr<FontPalette> palette1 =
        ConvertFontPalette(length_resolver, palette_mix_value->Palette1());
    if (palette1 == nullptr) {
      // Use normal palette.
      palette1 = FontPalette::Create();
    }
    scoped_refptr<FontPalette> palette2 =
        ConvertFontPalette(length_resolver, palette_mix_value->Palette2());
    if (palette2 == nullptr) {
      palette2 = FontPalette::Create();
    }

    Color::ColorSpace color_space =
        palette_mix_value->ColorInterpolationSpace();
    Color::HueInterpolationMethod hue_interpolation_method =
        palette_mix_value->HueInterpolationMethod();

    double alpha_multiplier;
    double normalized_percentage;
    if (cssvalue::CSSColorMixValue::NormalizePercentages(
            palette_mix_value->Percentage1(), palette_mix_value->Percentage2(),
            normalized_percentage, alpha_multiplier, length_resolver)) {
      double percentage1 = kMiddleStatePercentage;
      double percentage2 = kMiddleStatePercentage;
      if (palette_mix_value->Percentage1() &&
          palette_mix_value->Percentage2()) {
        percentage1 = palette_mix_value->Percentage1()->ComputePercentage(
            length_resolver);
        percentage2 = palette_mix_value->Percentage2()->ComputePercentage(
            length_resolver);
      } else if (palette_mix_value->Percentage1()) {
        percentage1 = palette_mix_value->Percentage1()->ComputePercentage(
            length_resolver);
        percentage2 = kFinalStatePercentage - percentage1;
      } else if (palette_mix_value->Percentage2()) {
        percentage2 = palette_mix_value->Percentage2()->ComputePercentage(
            length_resolver);
        percentage1 = kFinalStatePercentage - percentage2;
      }
      return FontPalette::Mix(palette1, palette2, percentage1, percentage2,
                              normalized_percentage, alpha_multiplier,
                              color_space, hue_interpolation_method);
    }
  }
  return nullptr;
}

scoped_refptr<FontPalette> StyleBuilderConverterBase::ConvertFontPalette(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kNormal) {
    return nullptr;
  }

  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kDark) {
    return FontPalette::Create(FontPalette::kDarkPalette);
  }

  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kLight) {
    return FontPalette::Create(FontPalette::kLightPalette);
  }

  auto* custom_identifier = DynamicTo<CSSCustomIdentValue>(value);
  if (custom_identifier) {
    return FontPalette::Create(custom_identifier->Value());
  }

  return ConvertPaletteMix(length_resolver, value);
}

float MathScriptScaleFactor(StyleResolverState& state) {
  int a = state.ParentStyle()->MathDepth();
  int b = state.StyleBuilder().MathDepth();
  if (b == a) {
    return 1.0;
  }
  bool invertScaleFactor = false;
  if (b < a) {
    std::swap(a, b);
    invertScaleFactor = true;
  }

  // Determine the scale factors from the inherited font.
  float defaultScaleDown = 0.71;
  int exponent = b - a;
  float scaleFactor = 1.0;
  if (const SimpleFontData* font_data =
          state.ParentStyle()->GetFont().PrimaryFont()) {
    HarfBuzzFace* parent_harfbuzz_face =
        font_data->PlatformData().GetHarfBuzzFace();
    if (OpenTypeMathSupport::HasMathData(parent_harfbuzz_face)) {
      float scriptPercentScaleDown =
          OpenTypeMathSupport::MathConstant(
              parent_harfbuzz_face,
              OpenTypeMathSupport::MathConstants::kScriptPercentScaleDown)
              .value_or(0);
      // Note: zero can mean both zero for the math constant and the fallback.
      if (!scriptPercentScaleDown) {
        scriptPercentScaleDown = defaultScaleDown;
      }
      float scriptScriptPercentScaleDown =
          OpenTypeMathSupport::MathConstant(
              parent_harfbuzz_face,
              OpenTypeMathSupport::MathConstants::kScriptScriptPercentScaleDown)
              .value_or(0);
      // Note: zero can mean both zero for the math constant and the fallback.
      if (!scriptScriptPercentScaleDown) {
        scriptScriptPercentScaleDown = defaultScaleDown * defaultScaleDown;
      }
      if (a <= 0 && b >= 2) {
        scaleFactor *= scriptScriptPercentScaleDown;
        exponent -= 2;
      } else if (a == 1) {
        scaleFactor *= scriptScriptPercentScaleDown / scriptPercentScaleDown;
        exponent--;
      } else if (b == 1) {
        scaleFactor *= scriptPercentScaleDown;
        exponent--;
      }
    }
  }
  scaleFactor *= pow(defaultScaleDown, exponent);
  return invertScaleFactor ? 1 / scaleFactor : scaleFactor;
}

static float ComputeFontSize(const CSSToLengthConversionData& conversion_data,
                             const CSSPrimitiveValue& primitive_value,
                             const FontDescription::Size& parent_size) {
  if (primitive_value.IsLength()) {
    return primitive_value.ComputeLength<float>(conversion_data);
  }
  if (primitive_value.IsCalculated()) {
    return To<CSSMathFunctionValue>(primitive_value)
        .ToCalcValue(conversion_data)
        ->Evaluate(parent_size.value);
  }
  NOTREACHED();
}

FontDescription::Size StyleBuilderConverterBase::ConvertFontSize(
    const CSSValue& value,
    const CSSToLengthConversionData& conversion_data,
    FontDescription::Size parent_size,
    const Document* document) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID value_id = identifier_value->GetValueID();
    if (FontSizeFunctions::IsValidValueID(value_id)) {
      return FontDescription::Size(FontSizeFunctions::KeywordSize(value_id),
                                   0.0f, false);
    }
    if (value_id == CSSValueID::kSmaller) {
      return FontDescription::SmallerSize(parent_size);
    }
    if (value_id == CSSValueID::kLarger) {
      return FontDescription::LargerSize(parent_size);
    }
    NOTREACHED();
  }

  if (const auto* system_font =
          DynamicTo<cssvalue::CSSPendingSystemFontValue>(value)) {
    return FontDescription::Size(0, system_font->ResolveFontSize(document),
                                 true);
  }

  const auto& primitive_value = To<CSSPrimitiveValue>(value);
  if (primitive_value.IsPercentage()) {
```