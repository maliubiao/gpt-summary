Response:
My thought process for analyzing the provided code snippet and generating the summary goes like this:

1. **Understand the Goal:** The request asks for the functionality of the `css_gradient_value.cc` file in Chromium's Blink rendering engine. It also asks for connections to web technologies, examples, error scenarios, and debugging clues. The specific instruction for this first part is to *summarize the functionality*.

2. **Initial Scan for Key Concepts:** I quickly skim the code, paying attention to includes, namespaces, class names, and function names. This gives me a high-level understanding of the file's purpose. I see includes related to:
    * CSS (`css_color.h`, `css_identifier_value.h`, etc.)
    * Graphics (`gradient.h`, `image.h`)
    * Core Blink infrastructure (`document.h`, `computed_style.h`)
    * Utility libraries (`algorithm`, `tuple`, `utility`, `string_builder.h`).
    The core class name `CSSGradientValue` immediately signals its primary function.

3. **Identify Core Functionality through Class and Method Names:** I focus on the `CSSGradientValue` class and its methods. Key methods that stand out are:
    * `GetImage()`:  This clearly indicates the file is involved in generating images, likely representing the gradient.
    * `AddDeprecatedStops()` and `AddComputedStops()`:  Suggests handling of gradient color stops, with different logic for deprecated and current syntax.
    * `AddStops()`:  The main logic for processing color stops.
    * `ComputeEndPoint()`: Indicates calculation of positions within the gradient.
    * `KnownToBeOpaque()`:  A check for optimization purposes related to rendering.
    * `ComputedCSSValue()`: Likely involved in the final computed style value for the gradient.

4. **Analyze Key Data Structures:**  I look at the data structures used within the class and the helper structs like `GradientDesc` and `GradientStop`. These reveal important information about how gradients are represented internally: color stops, offsets, positions, radii, angles, and spread methods.

5. **Look for Internal Logic and Algorithms:** I examine the functions' implementations to understand the steps involved in processing gradients. Key areas of interest are:
    * Color stop processing: Handling different units (percentages, lengths), default values, and the logic for resolving unspecified positions.
    * Color hints: The `ReplaceColorHintsWithColorStops()` function and the complex calculation involved in converting hints to regular stops.
    * Gradient normalization: The `NormalizeAndAddStops()` function and related functions like `AdjustedGradientDomainForOffsetRange` and `AdjustGradientRadiiForOffsetRange` suggest handling of edge cases and repeating gradients.

6. **Infer Connections to Web Technologies:** Based on the included headers and the functionality, I can infer the connections to:
    * **CSS:** This is the most obvious connection, as the file deals with CSS gradient values.
    * **HTML:**  Gradients are applied to HTML elements via CSS styles.
    * **JavaScript:** JavaScript can manipulate CSS styles, including those that define gradients.

7. **Synthesize a Summary:**  Based on the above analysis, I formulate a concise summary that captures the main responsibilities of the `css_gradient_value.cc` file. I focus on:
    * Representing CSS gradient values.
    * Parsing and interpreting gradient definitions.
    * Managing color stops and their positions.
    * Generating `Image` objects representing the gradient.
    * Handling different gradient types (linear, radial, conic).
    * Dealing with deprecated syntax and modern features like color hints.

8. **Review and Refine:** I read through the summary to ensure it's accurate, clear, and covers the most important aspects of the code. I also check if it directly addresses the "summarize the functionality" requirement of Part 1.

Essentially, I perform a top-down and bottom-up analysis of the code, starting with the overall purpose and drilling down into the details of the implementation, and then synthesizing the information back into a coherent summary. The specific requests in the prompt (examples, errors, debugging) will be addressed in the subsequent parts, building on this foundational understanding.
这是 `blink/renderer/core/css/css_gradient_value.cc` 文件的第一部分，主要功能是**处理和表示 CSS 渐变 (gradients) 的值**。它负责解析、计算和生成用于渲染的渐变图像数据。

以下是该文件主要功能的归纳：

**核心功能：**

* **表示 CSS 渐变值：** 定义了 `CSSGradientValue` 及其子类（如 `CSSLinearGradientValue`, `CSSRadialGradientValue`, `CSSConicGradientValue`, `CSSConstantGradientValue`）来表示不同类型的 CSS 渐变。
* **管理颜色停止点 (Color Stops)：**  处理渐变的颜色停止点，包括颜色、偏移量 (offset) 和颜色提示 (color hints)。它负责解析和规范化这些停止点，确保它们在渲染时能正确插值。
* **生成渐变图像 (Generating Gradient Images)：** 提供了 `GetImage()` 方法，根据提供的样式、容器尺寸和目标尺寸，生成一个表示渐变的 `Image` 对象。这涉及到将 CSS 定义的渐变转换为底层的图形表示 (如 Skia 的 `Gradient`)。
* **处理不同类型的渐变：** 针对线性渐变、径向渐变、锥形渐变和常量渐变，提供了特定的处理逻辑，包括计算起始点、结束点、半径、角度等参数。
* **处理颜色插值 (Color Interpolation)：**  虽然这部分代码没有直接实现插值算法，但它处理了颜色提示，这些提示会影响颜色如何在不同的颜色停止点之间过渡。`ReplaceColorHintsWithColorStops` 函数就负责将颜色提示转换为实际的颜色停止点，以便后续的渲染引擎进行插值。
* **处理 deprecated 的渐变语法：**  代码中包含了对 `kCSSDeprecatedLinearGradient` 和 `kCSSDeprecatedRadialGradient` 的处理，这意味着它仍然需要支持旧版本的渐变语法。
* **缓存 (Caching)：**  `GetImage()` 方法包含缓存逻辑，如果渐变值是可缓存的 (`is_cacheable_`)，它会尝试从缓存中获取图像，避免重复生成。
* **处理相对长度和百分比：** 代码能够处理颜色停止点偏移量中的长度和百分比单位，并将其转换为实际的偏移值。
* **处理 `currentColor` 等关键字：**  `ColorIsDerivedFromElement` 函数检查颜色是否来源于元素的属性，例如 `currentColor`。
* **与 Computed Style 交互：**  `GetImage()` 方法依赖 `ComputedStyle` 来获取元素的最终样式信息，并用于长度计算和颜色解析。`AddComputedStops` 函数用于计算颜色停止点的最终颜色值。
* **处理颜色方案 (Color Scheme)：**  代码中使用了 `style.UsedColorScheme()` 来获取当前使用的颜色方案，以便正确解析颜色。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS:** 这是最直接的关系。该文件处理的是 CSS 中 `linear-gradient`, `radial-gradient`, `conic-gradient`, `repeating-linear-gradient`, `repeating-radial-gradient`, `repeating-conic-gradient` 以及 deprecated 的 `-webkit-gradient` 等属性的值。例如，当浏览器解析到以下 CSS 时，该文件中的代码会被调用：

  ```css
  .element {
    background-image: linear-gradient(red, blue);
    background-image: radial-gradient(circle, yellow, green);
  }
  ```

* **HTML:** HTML 元素通过其 `style` 属性或外部 CSS 文件应用渐变样式。当浏览器渲染 HTML 页面时，会解析这些样式，最终调用到 `css_gradient_value.cc` 中的代码来生成渐变图像。

  ```html
  <div style="background-image: conic-gradient(from 90deg, red, yellow, green);"></div>
  ```

* **JavaScript:** JavaScript 可以通过 DOM API 修改元素的样式，包括渐变相关的属性。当 JavaScript 修改了元素的 `backgroundImage` 属性为一个新的渐变值时，浏览器会重新解析并使用 `css_gradient_value.cc` 来处理。

  ```javascript
  const element = document.querySelector('.element');
  element.style.backgroundImage = 'linear-gradient(to right, purple, orange)';
  ```

**逻辑推理的假设输入与输出（示例）：**

假设输入一个简单的线性渐变定义：

```css
background-image: linear-gradient(red, blue);
```

**假设输入：**

* `stops_`: 包含两个 `CSSGradientColorStop` 对象，一个颜色为 `red`，另一个颜色为 `blue`，都没有指定偏移量。
* `gradient_type_`: `kCSSLinearGradient`

**逻辑推理过程（简化）：**

1. `AddStops()` 方法会被调用。
2. 由于没有指定偏移量，第一个颜色停止点（`red`）的偏移量会被设置为 0，第二个颜色停止点（`blue`）的偏移量会被设置为 1。
3. 创建一个 `GradientDesc` 对象，用于描述渐变的参数。
4. 根据渐变类型（线性渐变），计算起始点和结束点（如果没有显式指定，通常是元素的边缘）。
5. 将颜色停止点信息添加到 `GradientDesc` 中。
6. `GetImage()` 方法会被调用，根据 `GradientDesc` 和目标尺寸生成 `Gradient` 对象。
7. `GradientGeneratedImage::Create()` 将 `Gradient` 对象转换为 `Image` 对象。

**假设输出：**

* 一个 `Image` 对象，表示从红色平滑过渡到蓝色的线性渐变。

**用户或编程常见的使用错误（示例）：**

* **颜色停止点顺序错误：** 用户可能错误地指定了颜色停止点的顺序，导致非预期的渐变效果。例如：

  ```css
  background-image: linear-gradient(blue 50%, red 20%); /* 错误：red 的偏移量小于 blue */
  ```

  在这种情况下，代码会调整颜色停止点的偏移量，使得后面的停止点的偏移量不小于前面的停止点。`AddStops` 方法中处理了这种情况。

* **拼写错误或使用了无效的颜色值：**  如果 CSS 中使用了错误的颜色名称或格式，解析器可能会报错，或者渐变可能无法正确渲染。

* **在不支持渐变的旧浏览器中使用：**  虽然现代浏览器都支持渐变，但在一些旧版本的浏览器中，渐变可能无法显示或显示效果不一致。

**用户操作如何一步步的到达这里作为调试线索：**

1. **用户在 HTML 文件中编写 CSS 样式，包含了渐变属性 (例如 `background-image: linear-gradient(...)`)。**
2. **用户使用支持 Chromium Blink 引擎的浏览器 (例如 Chrome) 打开该 HTML 文件。**
3. **Blink 引擎开始解析 HTML 和 CSS。**
4. **当 CSS 解析器遇到渐变相关的 CSS 属性时，会创建对应的 CSS 值对象，例如 `CSSLinearGradientValue`。**
5. **在布局和渲染阶段，当需要绘制带有渐变的元素背景时，会调用 `CSSGradientValue::GetImage()` 方法。**
6. **`GetImage()` 方法会调用其他方法，例如 `AddStops()`，来处理颜色停止点和计算渐变参数。**
7. **最终，`GradientGeneratedImage::Create()` 会被调用，使用底层的图形库 (Skia) 生成实际的图像数据。**

**调试线索：**

* 如果用户看到的渐变效果与预期不符，可以检查以下方面：
    * **CSS 语法是否正确：**  检查颜色值、偏移量、渐变类型等是否拼写正确，单位是否正确。
    * **浏览器开发者工具：** 使用浏览器的开发者工具 (例如 Chrome DevTools) 可以查看元素的计算样式，确认渐变属性是否被正确解析。还可以查看“渲染”标签下的图层信息，看是否生成了渐变图层。
    * **断点调试：**  可以在 `css_gradient_value.cc` 中的关键方法 (例如 `GetImage()`, `AddStops()`) 设置断点，逐步跟踪代码执行过程，查看颜色停止点、计算的偏移量等中间值，从而定位问题。

**总结：**

`blink/renderer/core/css/css_gradient_value.cc` 文件的第一部分主要负责定义和初步处理 CSS 渐变值，包括解析颜色停止点、处理不同类型的渐变，并为后续的图像生成过程提供必要的数据结构和计算。它是 Blink 引擎中处理 CSS 渐变的核心组件之一。

Prompt: 
```
这是目录为blink/renderer/core/css/css_gradient_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008 Apple Inc.  All rights reserved.
 * Copyright (C) 2015 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "third_party/blink/renderer/core/css/css_gradient_value.h"

#include <algorithm>
#include <tuple>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/text_link_colors.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/gradient.h"
#include "third_party/blink/renderer/platform/graphics/gradient_generated_image.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/size.h"

namespace blink::cssvalue {

namespace {

bool ColorIsDerivedFromElement(const CSSIdentifierValue& value) {
  CSSValueID value_id = value.GetValueID();
  switch (value_id) {
    case CSSValueID::kInternalQuirkInherit:
    case CSSValueID::kWebkitLink:
    case CSSValueID::kWebkitActivelink:
    case CSSValueID::kCurrentcolor:
      return true;
    default:
      return false;
  }
}

bool AppendPosition(StringBuilder& result,
                    const CSSValue* x,
                    const CSSValue* y,
                    bool wrote_something) {
  if (!x && !y) {
    return false;
  }

  if (IsA<CSSIdentifierValue>(x) &&
      To<CSSIdentifierValue>(x)->GetValueID() == CSSValueID::kCenter &&
      IsA<CSSIdentifierValue>(y) &&
      To<CSSIdentifierValue>(y)->GetValueID() == CSSValueID::kCenter) {
    return false;
  }

  if (wrote_something) {
    result.Append(' ');
  }
  result.Append("at ");

  if (x) {
    result.Append(x->CssText());
    if (y) {
      result.Append(' ');
    }
  }

  if (y) {
    result.Append(y->CssText());
  }

  return true;
}

}  // namespace

bool CSSGradientColorStop::IsCacheable() const {
  if (!IsHint()) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(color_.Get());
    if (identifier_value && ColorIsDerivedFromElement(*identifier_value)) {
      return false;
    }
  }

  // TODO(crbug.com/979895): This is the result of a refactoring, which might
  // have revealed an existing bug with calculated lengths. Investigate.
  return !offset_ || offset_->IsMathFunctionValue() ||
         !To<CSSNumericLiteralValue>(*offset_).IsFontRelativeLength();
}

void CSSGradientColorStop::Trace(Visitor* visitor) const {
  visitor->Trace(offset_);
  visitor->Trace(color_);
}

scoped_refptr<Image> CSSGradientValue::GetImage(
    const ImageResourceObserver& client,
    const Document& document,
    const ComputedStyle& style,
    const ContainerSizes& container_sizes,
    const gfx::SizeF& size) const {
  if (size.IsEmpty()) {
    return nullptr;
  }

  if (is_cacheable_) {
    if (!Clients().Contains(&client)) {
      return nullptr;
    }

    if (Image* result = CSSImageGeneratorValue::GetImage(&client, size)) {
      return result;
    }
  }

  // We need to create an image.
  const ComputedStyle* root_style =
      document.documentElement()->GetComputedStyle();

  // TODO(crbug.com/947377): Conversion is not supposed to happen here.
  CSSToLengthConversionData::Flags ignored_flags = 0;
  CSSToLengthConversionData conversion_data(
      style, &style, root_style,
      CSSToLengthConversionData::ViewportSize(document.GetLayoutView()),
      container_sizes, CSSToLengthConversionData::AnchorData(),
      style.EffectiveZoom(), ignored_flags, /*element=*/nullptr);

  scoped_refptr<Gradient> gradient;
  switch (GetClassType()) {
    case kLinearGradientClass:
      gradient = To<CSSLinearGradientValue>(this)->CreateGradient(
          conversion_data, size, document, style);
      break;
    case kRadialGradientClass:
      gradient = To<CSSRadialGradientValue>(this)->CreateGradient(
          conversion_data, size, document, style);
      break;
    case kConicGradientClass:
      gradient = To<CSSConicGradientValue>(this)->CreateGradient(
          conversion_data, size, document, style);
      break;
    case kConstantGradientClass:
      gradient = To<CSSConstantGradientValue>(this)->CreateGradient(
          conversion_data, size, document, style);
      break;
    default:
      NOTREACHED();
  }

  scoped_refptr<Image> new_image =
      GradientGeneratedImage::Create(gradient, size);
  if (is_cacheable_) {
    PutImage(size, new_image);
  }

  return new_image;
}

// Should only ever be called for deprecated gradients.
static inline bool CompareStops(
    const CSSGradientColorStop& a,
    const CSSGradientColorStop& b,
    const CSSToLengthConversionData& conversion_data) {
  double a_val = a.offset_->ComputeNumber(conversion_data);
  double b_val = b.offset_->ComputeNumber(conversion_data);

  return a_val < b_val;
}

struct GradientStop {
  Color color;
  float offset;
  bool specified;

  GradientStop() : offset(0), specified(false) {}
};

struct CSSGradientValue::GradientDesc {
  STACK_ALLOCATED();

 public:
  GradientDesc(const gfx::PointF& p0,
               const gfx::PointF& p1,
               GradientSpreadMethod spread_method)
      : p0(p0), p1(p1), spread_method(spread_method) {}
  GradientDesc(const gfx::PointF& p0,
               const gfx::PointF& p1,
               float r0,
               float r1,
               GradientSpreadMethod spread_method)
      : p0(p0), p1(p1), r0(r0), r1(r1), spread_method(spread_method) {}

  Vector<Gradient::ColorStop> stops;
  gfx::PointF p0, p1;
  float r0 = 0, r1 = 0;
  float start_angle = 0, end_angle = 360;
  GradientSpreadMethod spread_method;
};

static void ReplaceColorHintsWithColorStops(
    Vector<GradientStop>& stops,
    const HeapVector<CSSGradientColorStop, 2>& css_gradient_stops,
    Color::ColorSpace color_interpolation_space,
    Color::HueInterpolationMethod hue_interpolation_method) {
  // This algorithm will replace each color interpolation hint with 9 regular
  // color stops. The color values for the new color stops will be calculated
  // using the color weighting formula defined in the spec. The new color
  // stops will be positioned in such a way that all the pixels between the two
  // user defined color stops have color values close to the interpolation
  // curve.
  // If the hint is closer to the left color stop, add 2 stops to the left and
  // 6 to the right, else add 6 stops to the left and 2 to the right.
  // The color stops on the side with more space start midway because
  // the curve approximates a line in that region.
  // Using this aproximation, it is possible to discern the color steps when
  // the gradient is large. If this becomes an issue, we can consider improving
  // the algorithm, or adding support for color interpolation hints to skia
  // shaders.

  // Support legacy gradients with color hints when no interpolation space is
  // specified.
  if (color_interpolation_space == Color::ColorSpace::kNone) {
    color_interpolation_space = Color::ColorSpace::kSRGBLegacy;
  }

  int index_offset = 0;

  // The first and the last color stops cannot be color hints.
  for (wtf_size_t i = 1; i < css_gradient_stops.size() - 1; ++i) {
    if (!css_gradient_stops[i].IsHint()) {
      continue;
    }

    // The current index of the stops vector.
    wtf_size_t x = i + index_offset;
    DCHECK_GE(x, 1u);

    // offsetLeft          offset                            offsetRight
    //   |-------------------|---------------------------------|
    //          leftDist                 rightDist

    float offset_left = stops[x - 1].offset;
    float offset_right = stops[x + 1].offset;
    float offset = stops[x].offset;
    float left_dist = offset - offset_left;
    float right_dist = offset_right - offset;
    float total_dist = offset_right - offset_left;

    Color left_color = stops[x - 1].color;
    Color right_color = stops[x + 1].color;

    DCHECK_LE(offset_left, offset);
    DCHECK_LE(offset, offset_right);

    if (WebCoreFloatNearlyEqual(left_dist, right_dist)) {
      stops.EraseAt(x);
      --index_offset;
      continue;
    }

    if (WebCoreFloatNearlyEqual(left_dist, .0f)) {
      stops[x].color = right_color;
      continue;
    }

    if (WebCoreFloatNearlyEqual(right_dist, .0f)) {
      stops[x].color = left_color;
      continue;
    }

    std::array<GradientStop, 9> new_stops;
    // Position the new color stops. These must be in the range
    // [offset_left, offset_right], and in non-decreasing order, even in the
    // face of floating-point rounding.
    if (left_dist > right_dist) {
      for (size_t y = 0; y < 7; ++y) {
        new_stops[y].offset = offset_left + left_dist * ((7.0f + y) / 13.0f);
      }
      new_stops[7].offset = offset + right_dist * (1.0f / 3.0f);
      new_stops[8].offset = offset + right_dist * (2.0f / 3.0f);
    } else {
      new_stops[0].offset = offset_left + left_dist * (1.0f / 3.0f);
      new_stops[1].offset = offset_left + left_dist * (2.0f / 3.0f);
      for (size_t y = 0; y < 7; ++y) {
        new_stops[y + 2].offset = offset + right_dist * (y / 13.0f);
      }
    }

#if DCHECK_IS_ON()
    // Verify that offset_left <= x_0 <= x_1 <= ... <= x_8 <= offset_right.
    DCHECK_GE(new_stops[0].offset, offset_left);
    for (int j = 1; j < 8; ++j) {
      DCHECK_GE(new_stops[j].offset, new_stops[j - 1].offset);
    }
    DCHECK_GE(offset_right, new_stops[8].offset);
#endif  // DCHECK_IS_ON()

    // calculate colors for the new color hints.
    // The color weighting for the new color stops will be
    // pointRelativeOffset^(ln(0.5)/ln(hintRelativeOffset)).
    float hint_relative_offset = left_dist / total_dist;
    for (auto& new_stop : new_stops) {
      float point_relative_offset =
          (new_stop.offset - offset_left) / total_dist;
      float weighting =
          powf(point_relative_offset, logf(.5f) / logf(hint_relative_offset));
      // Prevent crashes from huge gradient stops. See:
      // wpt/css/css-images/radial-gradient-transition-hint-crash.html
      if (std::isinf(weighting) || std::isnan(weighting)) {
        continue;
      }
      // TODO(crbug.com/1416273): Testing that color hints are using the
      // correct interpolation space is challenging in CSS. Once Canvas2D
      // implements colorspaces for gradients we can use GetImageData() to
      // test this.
      new_stop.color = Color::InterpolateColors(
          color_interpolation_space, hue_interpolation_method, left_color,
          right_color, weighting);
    }

    // Replace the color hint with the new color stops.
    stops.EraseAt(x);
    stops.insert(x, new_stops.data(), 9);
    index_offset += 8;
  }
}

static Color ResolveStopColor(const CSSLengthResolver& length_resolver,
                              const CSSValue& stop_color,
                              const Document& document,
                              const ComputedStyle& style) {
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ResolveColorValueContext context{
      .length_resolver = length_resolver,
      .text_link_colors = document.GetTextLinkColors(),
      .used_color_scheme = color_scheme,
      .color_provider = document.GetColorProviderForPainting(color_scheme),
      .is_in_web_app_scope = document.IsInWebAppScope()};
  const StyleColor style_stop_color = ResolveColorValue(stop_color, context);
  return style_stop_color.Resolve(
      style.VisitedDependentColor(GetCSSPropertyColor()), color_scheme);
}

void CSSGradientValue::AddDeprecatedStops(
    GradientDesc& desc,
    const Document& document,
    const ComputedStyle& style,
    const CSSToLengthConversionData& conversion_data) const {
  DCHECK(gradient_type_ == kCSSDeprecatedLinearGradient ||
         gradient_type_ == kCSSDeprecatedRadialGradient);

  // Performance here is probably not important because this is for deprecated
  // gradients.
  auto stops_sorted = stops_;
  auto comparator = [&conversion_data](const CSSGradientColorStop& a,
                                       const CSSGradientColorStop& b) {
    return CompareStops(a, b, conversion_data);
  };
  std::stable_sort(stops_sorted.begin(), stops_sorted.end(), comparator);

  for (const auto& stop : stops_sorted) {
    float offset;
    if (stop.offset_->IsPercentage()) {
      offset = stop.offset_->ComputePercentage(conversion_data) / 100;
    } else {
      // Deprecated gradients are only parsed with either percentage or number.
      DCHECK(stop.offset_->IsNumber());
      offset = stop.offset_->ComputeNumber(conversion_data);
    }

    const Color color =
        ResolveStopColor(conversion_data, *stop.color_, document, style);
    desc.stops.emplace_back(offset, color);
  }
}

// NOTE: The difference between this and ResolveStopColor() is that
// ResolveStopColor() returns a Color, whereas this returns a CSSValue.
static const CSSValue* GetComputedStopColor(const CSSValue& color,
                                            const ComputedStyle& style,
                                            bool allow_visited_style,
                                            CSSValuePhase value_phase) {
  // TODO(crbug.com/40779801): Need to pass an appropriate color provider here.
  // TODO(crbug.com/40229450): Need to pass an appropriate boolean to say if it
  // is within webapp scope.
  const mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  // TODO(40946458): Don't use default length resolver here!
  const ResolveColorValueContext context{
      .length_resolver = CSSToLengthConversionData(/*element=*/nullptr),
      .text_link_colors = TextLinkColors(),
      .used_color_scheme = color_scheme};
  const StyleColor style_stop_color = ResolveColorValue(color, context);
  const Color current_color =
      style.VisitedDependentColor(GetCSSPropertyColor());
  return ComputedStyleUtils::ValueForColor(
      style_stop_color, style, allow_visited_style ? &current_color : nullptr,
      value_phase);
}

void CSSGradientValue::AddComputedStops(
    const ComputedStyle& style,
    bool allow_visited_style,
    const HeapVector<CSSGradientColorStop, 2>& stops,
    CSSValuePhase value_phase) {
  for (CSSGradientColorStop stop : stops) {
    if (!stop.IsHint()) {
      stop.color_ = GetComputedStopColor(*stop.color_, style,
                                         allow_visited_style, value_phase);
    }
    AddStop(stop);
  }
}

namespace {

bool RequiresStopsNormalization(const Vector<GradientStop>& stops,
                                CSSGradientValue::GradientDesc& desc) {
  // We need at least two stops to normalize
  if (stops.size() < 2) {
    return false;
  }

  // Repeating gradients are implemented using a normalized stop offset range
  // with the point/radius pairs aligned on the interval endpoints.
  if (desc.spread_method == kSpreadMethodRepeat) {
    return true;
  }

  // Degenerate stops
  if (stops.front().offset < 0 || stops.back().offset > 1) {
    return true;
  }

  return false;
}

// Redistribute the stops such that they fully cover [0 , 1] and add them to the
// gradient.
bool NormalizeAndAddStops(const Vector<GradientStop>& stops,
                          CSSGradientValue::GradientDesc& desc) {
  DCHECK_GT(stops.size(), 1u);

  const float first_offset = stops.front().offset;
  const float last_offset = stops.back().offset;
  const float span = std::min(std::max(last_offset - first_offset, 0.f),
                              std::numeric_limits<float>::max());

  if (fabs(span) < std::numeric_limits<float>::epsilon()) {
    // All stops are coincident -> use a single clamped offset value.
    const float clamped_offset = std::min(std::max(first_offset, 0.f), 1.f);

    // For repeating gradients, a coincident stop set defines a solid-color
    // image with the color of the last color-stop in the rule.
    // For non-repeating gradients, both the first color and the last color can
    // be significant (padding on both sides of the offset).
    if (desc.spread_method != kSpreadMethodRepeat) {
      desc.stops.emplace_back(clamped_offset, stops.front().color);
    }
    desc.stops.emplace_back(clamped_offset, stops.back().color);

    return false;
  }

  DCHECK_GT(span, 0);

  for (wtf_size_t i = 0; i < stops.size(); ++i) {
    const auto relative_offset = std::min(stops[i].offset - first_offset,
                                          std::numeric_limits<float>::max()),
               normalized_offset = relative_offset / span;

    // stop offsets should be monotonically increasing in [0 , 1]
    DCHECK_GE(normalized_offset, 0);
    DCHECK_LE(normalized_offset, 1);
    DCHECK(i == 0 || normalized_offset >= desc.stops.back().stop);

    desc.stops.emplace_back(normalized_offset, stops[i].color);
  }

  return true;
}

// Collapse all negative-offset stops to 0 and compute an interpolated color
// value for that point.
void ClampNegativeOffsets(
    Vector<GradientStop>& stops,
    Color::ColorSpace color_interpolation_space,
    Color::HueInterpolationMethod hue_interpolation_method) {
  // Support legacy gradients with color hints when no interpolation space is
  // specified.
  if (color_interpolation_space == Color::ColorSpace::kNone) {
    color_interpolation_space = Color::ColorSpace::kSRGBLegacy;
  }
  float last_negative_offset = 0;

  for (wtf_size_t i = 0; i < stops.size(); ++i) {
    const float current_offset = stops[i].offset;
    if (current_offset >= 0) {
      if (i > 0) {
        // We found the negative -> positive offset transition: compute an
        // interpolated color value for 0 and use it with the last clamped stop.
        DCHECK_LT(last_negative_offset, 0);
        float lerp_ratio =
            -last_negative_offset / (current_offset - last_negative_offset);
        stops[i - 1].color = Color::InterpolateColors(
            color_interpolation_space, hue_interpolation_method,
            stops[i - 1].color, stops[i].color, lerp_ratio);
      }

      break;
    }

    // Clamp all negative stops to 0.
    stops[i].offset = 0;
    last_negative_offset = current_offset;
  }
}

// Used in AdjustedGradientDomainForOffsetRange when the type of v1 - v0 is
// gfx::Vector2dF.
gfx::Vector2dF operator*(const gfx::Vector2dF& v, float scale) {
  return gfx::ScaleVector2d(v, scale);
}

template <typename T>
std::tuple<T, T> AdjustedGradientDomainForOffsetRange(const T& v0,
                                                      const T& v1,
                                                      float first_offset,
                                                      float last_offset) {
  DCHECK_LE(first_offset, last_offset);

  const auto d = v1 - v0;

  // The offsets are relative to the [v0 , v1] segment.
  return std::make_tuple(v0 + d * first_offset, v0 + d * last_offset);
}

// Update the radial gradient radii to align with the given offset range.
void AdjustGradientRadiiForOffsetRange(CSSGradientValue::GradientDesc& desc,
                                       float first_offset,
                                       float last_offset) {
  DCHECK_LE(first_offset, last_offset);

  // Radial offsets are relative to the [0 , endRadius] segment.
  float adjusted_r0 = ClampTo<float>(desc.r1 * first_offset);
  float adjusted_r1 = ClampTo<float>(desc.r1 * last_offset);
  DCHECK_LE(adjusted_r0, adjusted_r1);
  // Unlike linear gradients (where we can adjust the points arbitrarily),
  // we cannot let our radii turn negative here.
  if (adjusted_r0 < 0) {
    // For the non-repeat case, this can never happen: clampNegativeOffsets()
    // ensures we don't have to deal with negative offsets at this point.

    DCHECK_EQ(desc.spread_method, kSpreadMethodRepeat);

    // When in repeat mode, we deal with it by repositioning both radii in the
    // positive domain - shifting them by a multiple of the radius span (which
    // is the period of our repeating gradient -> hence no visible side
    // effects).
    const float radius_span = adjusted_r1 - adjusted_r0;
    const float shift_to_positive =
        radius_span * ceilf(-adjusted_r0 / radius_span);
    adjusted_r0 += shift_to_positive;
    adjusted_r1 += shift_to_positive;
  }
  DCHECK_GE(adjusted_r0, 0);
  DCHECK_GE(adjusted_r1, adjusted_r0);

  desc.r0 = adjusted_r0;
  desc.r1 = adjusted_r1;
}

}  // namespace

void CSSGradientValue::AddStops(
    CSSGradientValue::GradientDesc& desc,
    const CSSToLengthConversionData& conversion_data,
    const Document& document,
    const ComputedStyle& style) const {
  if (gradient_type_ == kCSSDeprecatedLinearGradient ||
      gradient_type_ == kCSSDeprecatedRadialGradient) {
    AddDeprecatedStops(desc, document, style, conversion_data);
    return;
  }

  wtf_size_t num_stops = stops_.size();

  Vector<GradientStop> stops(num_stops);

  float gradient_length;
  switch (GetClassType()) {
    case kLinearGradientClass:
      gradient_length = (desc.p1 - desc.p0).Length();
      break;
    case kRadialGradientClass:
      gradient_length = desc.r1;
      break;
    case kConicGradientClass:
      gradient_length = 1;
      break;
    default:
      NOTREACHED();
  }

  bool has_hints = false;
  for (wtf_size_t i = 0; i < num_stops; ++i) {
    const CSSGradientColorStop& stop = stops_[i];

    if (stop.IsHint()) {
      has_hints = true;
    } else {
      stops[i].color =
          ResolveStopColor(conversion_data, *stop.color_, document, style);
    }

    if (stop.offset_) {
      if (stop.offset_->IsPercentage()) {
        stops[i].offset =
            stop.offset_->ComputePercentage(conversion_data) / 100;
      } else if (stop.offset_->IsLength() ||
                 !stop.offset_->IsResolvableBeforeLayout()) {
        float length;
        if (stop.offset_->IsLength()) {
          length = stop.offset_->ComputeLength<float>(conversion_data);
        } else {
          length = To<CSSMathFunctionValue>(stop.offset_.Get())
                       ->ToCalcValue(conversion_data)
                       ->Evaluate(gradient_length);
        }
        stops[i].offset = (gradient_length > 0) ? length / gradient_length : 0;
      } else if (stop.offset_->IsAngle()) {
        stops[i].offset =
            stop.offset_->ComputeDegrees(conversion_data) / 360.0f;
      } else {
        NOTREACHED();
      }
      stops[i].specified = true;
    } else {
      // If the first color-stop does not have a position, its position defaults
      // to 0%. If the last color-stop does not have a position, its position
      // defaults to 100%.
      if (!i) {
        stops[i].offset = 0;
        stops[i].specified = true;
      } else if (num_stops > 1 && i == num_stops - 1) {
        stops[i].offset = 1;
        stops[i].specified = true;
      }
    }

    // If a color-stop has a position that is less than the specified position
    // of any color-stop before it in the list, its position is changed to be
    // equal to the largest specified position of any color-stop before it.
    if (stops[i].specified && i > 0) {
      wtf_size_t prev_specified_index;
      for (prev_specified_index = i - 1; prev_specified_index;
           --prev_specified_index) {
        if (stops[prev_specified_index].specified) {
          break;
        }
      }

      if (stops[i].offset < stops[prev_specified_index].offset) {
        stops[i].offset = stops[prev_specified_index].offset;
      }
    }
  }

  DCHECK(stops.front().specified);
  DCHECK(stops.back().specified);

  // If any color-stop still does not have a position, then, for each run of
  // adjacent color-stops without positions, set their positions so that they
  // are evenly spaced between the preceding and following color-stops with
  // positions.
  if (num_stops > 2) {
    wtf_size_t unspecified_run_start = 0;
    bool in_unspecified_run = false;

    for (wtf_size_t i = 0; i < num_stops; ++i) {
      if (!stops[i].specified && !in_unspecified_run) {
        unspecified_run_start = i;
        in_unspecified_run = true;
      } else if (stops[i].specified && in_unspecified_run) {
        wtf_size_t unspecified_run_end = i;

        if (unspecified_run_start < unspecified_run_end) {
          float last_specified_offset = stops[unspecified_run_start - 1].offset;
          float next_specified_offset = stops[unspecified_run_end].offset;
          float delta = (next_specified_offset - last_specified_offset) /
                        (unspecified_run_end - unspecified_run_start + 1);

          for (wtf_size_t j = unspecified_run_start; j < unspecified_run_end;
               ++j) {
            stops[j].offset =
                last_specified_offset + (j - unspecified_run_start + 1) * delta;
          }
        }

        in_unspecified_run = false;
      }
    }
  }

  DCHECK_EQ(stops.size(), stops_.size());
  if (has_hints) {
    ReplaceColorHintsWithColorStops(stops, stops_, color_interpolation_space_,
                                    hue_interpolation_method_);
  }

  // At this point we have a fully resolved set of stops. Time to perform
  // adjustments for repeat gradients and degenerate values if needed.
  if (!RequiresStopsNormalization(stops, desc)) {
    // No normalization required, just add the current stops.
    for (const auto& stop : stops) {
      desc.stops.emplace_back(stop.offset, stop.color);
    }
    return;
  }

  switch (GetClassType()) {
    case kLinearGradientClass:
      if (NormalizeAndAddStops(stops, desc)) {
        std::tie(desc.p0, desc.p1) = AdjustedGradientDomainForOffsetRange(
            desc.p0, desc.p1, stops.front().offset, stops.back().offset);
      }
      break;
    case kRadialGradientClass:
      // Negative offsets are only an issue for non-repeating radial gradients:
      // linear gradient points can be repositioned arbitrarily, and for
      // repeating radial gradients we shift the radii into equivalent positive
      // values.
      if (!repeating_) {
        ClampNegativeOffsets(stops, color_interpolation_space_,
                             hue_interpolation_method_);
      }

      // Always adjust the radii for non-repeating gradients, because they can
      // extend "outside" the [0, 1] range even if they are degenerate.
      if (NormalizeAndAddStops(stops, desc) || !repeating_) {
        AdjustGradientRadiiForOffsetRange(desc, stops.front().offset,
                                          stops.back().offset);
      }
      break;
    case kConicGradientClass:
      if (NormalizeAndAddStops(stops, desc)) {
        std::tie(desc.start_angle, desc.end_angle) =
            AdjustedGradientDomainForOffsetRange(
                desc.start_angle, desc.end_angle, stops.front().offset,
                stops.back().offset);
      }
      break;
    default:
      NOTREACHED();
  }
}

static float PositionFromValue(const CSSValue* value,
                               const CSSToLengthConversionData& conversion_data,
                               const gfx::SizeF& size,
                               bool is_horizontal) {
  float origin = 0;
  int sign = 1;
  float edge_distance = is_horizontal ? size.width() : size.height();

  // In this case the center of the gradient is given relative to an edge in the
  // form of: [ top | bottom | right | left ] [ <percentage> | <length> ].
  if (const auto* pair = DynamicTo<CSSValuePair>(*value)) {
    CSSValueID origin_id = To<CSSIdentifierValue>(pair->First()).GetValueID();
    value = &pair->Second();

    if (origin_id == CSSValueID::kRight || origin_id == CSSValueID::kBottom) {
      // For right/bottom, the offset is relative to the far edge.
      origin = edge_distance;
      sign = -1;
    }
  }

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kTop:
        DCHECK(!is_horizontal);
        return 0;
      case CSSValueID::kLeft:
        DCHECK(is_horizontal);
        return 0;
      case CSSValueID::kBottom:
        DCHECK(!is_horizontal);
        return size.height();
      case CSSValueID::kRight:
        DCHECK(is_horizontal);
        return size.width();
      case CSSValueID::kCenter:
        return origin + sign * .5f * edge_distance;
      default:
        NOTREACHED();
    }
  }

  const CSSPrimitiveValue* primitive_value = To<CSSPrimitiveValue>(value);

  if (primitive_value->IsNumber()) {
    return origin + sign * primitive_value->ComputeNumber(conversion_data) *
                        conversion_data.Zoom();
  }

  if (primitive_value->IsPercentage()) {
    return origin + sign * primitive_value->ComputePercentage(conversion_data) /
                        100.f * edge_distance;
  }

  if (!primitive_value->IsResolvableBeforeLayout()) {
    return origin + sign * To<CSSMathFunctionValue>(primitive_value)
                               ->ToCalcValue(conversion_data)
                               ->Evaluate(edge_distance);
  }

  return origin + sign * primitive_value->ComputeLength<float>(conversion_data);
}

// Resolve points/radii to front end values.
static gfx::PointF ComputeEndPoint(
    const CSSValue* horizontal,
    const CSSValue* vertical,
    const CSSToLengthConversionData& conversion_data,
    const gfx::SizeF& size) {
  gfx::PointF result;

  if (horizontal) {
    result.set_x(PositionFromValue(horizontal, conversion_data, size, true));
  }

  if (vertical) {
    result.set_y(PositionFromValue(vertical, conversion_data, size, false));
  }

  return result;
}

bool CSSGradientValue::KnownToBeOpaque(const Document& document,
                                       const ComputedStyle& style) const {
  for (auto& stop : stops_) {
    // TODO(40946458): Don't use default length resolver here!
    if (!stop.IsHint() &&
        !ResolveStopColor(CSSToLengthConversionData(/*element=*/nullptr),
                          *stop.color_, document, style)
             .IsOpaque()) {
      return false;
    }
  }
  return true;
}

CSSGradientValue* CSSGradientValue::ComputedCSSValue(
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (GetClassType()) {
    case kLinearGradientClass:
      return To<CSSLinearGradientValue>(this)->ComputedCSSValue(
          style, allow_visited_style, value_phase);
    case kRadialGradientClass:
      return To<CSSRadialGradientValue>(this)->ComputedCSSValue(
          style, allow_visited_style, value_phase);
    case kConicGradientClass:
      return To<CSSConicGradientValue>(this)->ComputedCSSValue(
          style, allow_visite
"""


```