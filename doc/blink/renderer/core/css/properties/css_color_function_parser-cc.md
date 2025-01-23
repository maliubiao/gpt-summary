Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a comprehensive analysis of the provided C++ file. This includes its purpose, relationships with web technologies (HTML, CSS, JavaScript), examples of its functionality, common errors, and debugging context.

2. **Initial Skim for Keywords and Structure:**  The first step is a quick scan of the code looking for recognizable keywords and structural elements. This gives an initial sense of what the code is doing.

    * **Headers:** `#include` statements indicate dependencies. `css_color.h`, `css_color_mix_value.h`, `css_relative_color_value.h`, and `css_parsing_utils.h` strongly suggest the file is involved in parsing and handling CSS color values. The `mojom/use_counter/metrics/web_feature.mojom-shared.h` hint at usage tracking.
    * **Namespace:** `namespace blink` confirms it's part of the Blink rendering engine.
    * **Functions:**  Functions like `IsValidColorFunction`, `ColorSpaceFrom...`, `Consume...`, `Resolve...`, and `ConsumeFunctionalSyntaxColor` provide clues about the parsing and processing flow. The "Consume" prefix often indicates parsing logic. "Resolve" points to converting parsed data into usable values.
    * **Data Structures:**  Variables like `unresolved_channels_`, `alpha_`, `color_space_`, `color_channel_map_`, and `unresolved_origin_color_` represent the state managed by the parser.
    * **Comments:**  The comments referencing W3C specifications (`https://www.w3.org/TR/css-color-4/#...`) are invaluable for understanding the standards being implemented.

3. **Identify Core Functionality:** Based on the initial skim, it's clear that the file is responsible for parsing CSS color functions (like `rgb()`, `hsl()`, `lab()`, `color()`, etc.). It needs to:
    * Identify valid color functions.
    * Extract color space information.
    * Parse the individual color channel values (red, green, blue, hue, saturation, lightness, etc.).
    * Handle alpha values (opacity).
    * Potentially deal with relative color syntax (`color(from ...)`) and color mixing (`color-mix()`).

4. **Trace the Parsing Process:** The `ConsumeFunctionalSyntaxColor` function seems to be the main entry point for parsing. Follow the logic within this function:
    * Check if the function ID is a valid color function.
    * Optionally consume the `from` keyword and the origin color (for relative colors).
    * Consume the color space information.
    * Consume the individual color channel values, handling different syntaxes (commas vs. slashes as separators).
    * Consume the alpha value, if present.
    * Error handling (returning `nullptr` on parse failure).

5. **Connect to Web Technologies:**  Now, think about how this C++ code relates to HTML, CSS, and JavaScript:
    * **CSS:** This is the most direct connection. The code *parses* CSS color values defined in stylesheets or inline styles. Provide examples of valid and invalid CSS color function syntax that this code would handle.
    * **HTML:**  HTML provides the structure to which CSS styles are applied. The color values parsed by this code ultimately affect the visual presentation of HTML elements.
    * **JavaScript:** JavaScript can manipulate CSS styles dynamically. When JavaScript changes a color-related CSS property, this parsing code might be invoked to interpret the new value.

6. **Focus on Specific Code Sections:**  Dive deeper into key functions:
    * `IsValidColorFunction`:  A simple check for allowed color function names.
    * `ColorSpaceFrom...`:  Mapping CSS function names and color space identifiers to internal `Color::ColorSpace` enums.
    * `ConsumeChannel` and `ConsumeAlpha`: Parsing individual channel and alpha values, handling different units (numbers, percentages, angles) and the `none` keyword.
    * `ResolveColorChannel` and `ResolveAlpha`: Converting the parsed values (which might be strings or abstract syntax tree nodes) into concrete numerical values. Pay attention to the handling of relative color channels.
    * `MakePerColorSpaceAdjustments`:  Applying color space-specific adjustments (like clamping values or converting percentages).

7. **Consider Edge Cases and Errors:** Think about what could go wrong:
    * **Invalid Syntax:** Incorrectly formatted color functions (e.g., missing commas, wrong order of arguments).
    * **Out-of-Range Values:**  Color channel values outside the valid range for a given color space.
    * **Mixing Syntaxes:** Incorrectly mixing legacy and modern syntax.
    * **Relative Color Issues:**  Trying to use relative colors when the feature is not enabled.

8. **Hypothesize Inputs and Outputs:** Create specific examples to illustrate the parsing logic. Provide both valid and invalid CSS color strings and explain what the parser would do with them. This helps solidify understanding and demonstrate the code's behavior.

9. **Debugging Context:** How would a developer end up looking at this file during debugging?
    * A bug report about incorrect color rendering.
    * Issues with relative color syntax not working as expected.
    * Performance problems related to CSS parsing.
    * Investigating newly implemented CSS color features. Describe the steps a developer might take to trace the execution flow leading to this file.

10. **Structure and Refine:** Organize the information logically. Use headings and bullet points to make it easier to read. Ensure the explanations are clear and concise. Review and refine the language for clarity and accuracy. For example, initially, I might just say "parses colors," but it's more accurate and informative to say "parses CSS color functions and their components."  Similarly, instead of just "handles errors," give specific examples of the errors it handles.

By following this structured approach, combining code examination with knowledge of web technologies and potential error scenarios, it's possible to generate a comprehensive and accurate analysis of the given C++ source file.
好的，让我们来详细分析一下 `blink/renderer/core/css/properties/css_color_function_parser.cc` 这个文件。

**文件功能概要**

这个 C++ 文件 `css_color_function_parser.cc` 的核心功能是**解析 CSS 颜色函数**。它负责将 CSS 样式中类似 `rgb()`, `rgba()`, `hsl()`, `hsla()`, `hwb()`, `lab()`, `lch()`, `oklab()`, `oklch()` 和 `color()` 这样的函数形式的颜色值解析成 Blink 引擎内部可以理解和使用的颜色表示。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接服务于 CSS 的解析，间接影响着 HTML 的渲染和 JavaScript 与 CSS 的交互。

* **CSS:**  这是最直接的关系。`css_color_function_parser.cc` 的主要任务就是解析 CSS 中定义的颜色值。
    * **举例：**  当浏览器解析到以下 CSS 规则时：
        ```css
        .my-element {
          background-color: rgba(255, 0, 0, 0.5); /* 解析 rgba() 函数 */
          color: hsl(120, 100%, 50%);           /* 解析 hsl() 函数 */
          border-color: color(display-p3 1 0 0); /* 解析 color() 函数 */
        }
        ```
        `css_color_function_parser.cc` 就会被调用来解析 `rgba(255, 0, 0, 0.5)`，`hsl(120, 100%, 50%)` 和 `color(display-p3 1 0 0)` 这些字符串，并将它们转换成内部的颜色对象，以便后续渲染引擎使用。

* **HTML:**  HTML 定义了网页的结构，而 CSS 则用来控制这些结构的样式，包括颜色。 `css_color_function_parser.cc` 解析出的颜色值最终会应用于 HTML 元素，影响其视觉呈现。
    * **举例：**  如果上述 CSS 规则应用到一个 `<div class="my-element"></div>` 元素上，解析器解析出的红色半透明背景色和绿色文字颜色就会被应用到这个 div 元素，最终用户在浏览器中看到的效果就是这个 div 有半透明的红色背景和绿色的文字。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 修改了颜色相关的 CSS 属性时，`css_color_function_parser.cc` 可能会被再次调用来解析新的颜色值。
    * **举例：**  JavaScript 代码如下：
        ```javascript
        const element = document.querySelector('.my-element');
        element.style.backgroundColor = 'lab(50% 100 50)'; // 设置新的背景色
        ```
        当执行这行代码时，浏览器需要解析新的背景色值 `lab(50% 100 50)`。`css_color_function_parser.cc` 会被调用来完成这个解析过程。

**逻辑推理（假设输入与输出）**

假设输入的是一个 CSS 颜色字符串和相关的解析上下文：

**假设输入 1:**

* **CSS 字符串:** `"rgb(100, 150, 200)"`
* **解析上下文:**  一个包含当前 CSS 解析状态的信息对象。

**逻辑推理:** `ConsumeFunctionalSyntaxColor` 函数会识别出 `rgb` 函数，然后调用 `ConsumeChannel` 三次来解析红色、绿色和蓝色通道的值（100, 150, 200）。由于没有 alpha 通道，最终会创建一个表示 RGB 颜色的 `CSSColor` 对象。

**假设输出 1:**

* 一个指向 `cssvalue::CSSColor` 对象的指针，该对象内部存储了 RGB 值 (100, 150, 200)，alpha 值为 1 (不透明)。

**假设输入 2:**

* **CSS 字符串:** `"hsla(30deg, 80%, 60%, 0.7)"`
* **解析上下文:**  一个包含当前 CSS 解析状态的信息对象。

**逻辑推理:** `ConsumeFunctionalSyntaxColor` 函数会识别出 `hsla` 函数，调用 `ConsumeChannel` 解析色相 (30deg)，饱和度 (80%) 和亮度 (60%)，然后调用 `ConsumeAlpha` 解析 alpha 值 (0.7)。最终会创建一个表示 HSLA 颜色的 `CSSColor` 对象。

**假设输出 2:**

* 一个指向 `cssvalue::CSSColor` 对象的指针，该对象内部存储了 HSLA 值 (30, 0.8, 0.6, 0.7)。

**假设输入 3 (错误输入):**

* **CSS 字符串:** `"rgb(100, 150)"`  // 缺少蓝色通道
* **解析上下文:**  一个包含当前 CSS 解析状态的信息对象。

**逻辑推理:** `ConsumeFunctionalSyntaxColor` 在解析 `rgb` 函数时，会期望解析到三个通道值。由于只找到了两个，`ConsumeChannel` 将会返回 `false`，导致 `ConsumeFunctionalSyntaxColor` 返回 `nullptr`。

**假设输出 3:**

* `nullptr`，表示解析失败。

**用户或编程常见的使用错误**

1. **拼写错误的颜色函数名:** 用户在 CSS 中可能会错误地拼写颜色函数名，例如写成 `rgab()` 而不是 `rgba()`。`IsValidColorFunction` 会检查函数名，如果不是有效的颜色函数，解析会失败。
    * **例子:** `background-color: rgab(255, 0, 0, 0.5);`  会导致解析错误。

2. **颜色通道值超出范围:**  不同的颜色函数对通道值的范围有不同的要求。例如，`rgb()` 的通道值通常是 0-255 的整数，或者 0%-100% 的百分比。如果提供超出范围的值，可能会导致解析错误或者得到非预期的颜色。
    * **例子:** `background-color: rgb(300, 0, 0);`  // 红色通道值超出 0-255 范围。
    * **例子:** `background-color: hsl(120, 150%, 50%);` // 饱和度超出 0%-100% 范围。

3. **缺少或多余的参数:** 颜色函数需要特定数量的参数。缺少或多余的参数都会导致解析失败。
    * **例子:** `background-color: rgba(255, 0, 0);` // 缺少 alpha 参数。
    * **例子:** `background-color: rgb(255, 0, 0, 0.5);` // `rgb` 函数不接受 alpha 参数。

4. **混合使用逗号和斜杠分隔符 (在现代语法中不应该混合):**  新的颜色函数语法使用斜杠 `/` 分隔颜色通道和 alpha 值，而旧的语法使用逗号 `,`。混合使用可能会导致解析错误。
    * **例子:** `background-color: rgb(255, 0, 0 / 0.5);` // `rgb` 函数的现代语法。
    * **例子:** `background-color: rgba(255, 0, 0, 0.5);` // `rgba` 函数的传统语法。
    * **错误例子:** `background-color: rgb(255, 0, 0, 0.5);` // `rgb` 函数不应该有逗号分隔的 alpha 值。

5. **在不支持的上下文中使用相对颜色语法:**  `color(from ...)` 是一种相对颜色语法，可能在某些旧版本的浏览器中不支持。尝试使用这种语法可能会导致解析失败。
    * **例子:** `background-color: color(from red srgb r g b);`

**用户操作如何一步步到达这里，作为调试线索**

假设用户发现网页上的某个元素的颜色显示不正确，他们可能会进行以下操作，最终可能需要查看 `css_color_function_parser.cc` 来进行调试：

1. **用户在浏览器中访问了某个网页。**
2. **网页的 CSS 样式中定义了某个元素的颜色值使用了颜色函数，例如 `background-color: hsl(30, 70%, 50%);`。**
3. **Blink 引擎在渲染这个网页时，需要解析这个 CSS 规则。**
4. **CSS 解析器遇到 `hsl(30, 70%, 50%)` 这个颜色值。**
5. **CSS 解析器将这个颜色字符串传递给 `css_color_function_parser.cc` 中的 `ConsumeFunctionalSyntaxColor` 函数进行解析。**
6. **如果解析过程中出现错误（例如，用户 CSS 中写成了 `hsl(30, 70)` 缺少了亮度值），`ConsumeFunctionalSyntaxColor` 可能会返回 `nullptr`。**
7. **渲染引擎根据解析结果（或者解析失败的信息），最终渲染出错误的颜色，或者根本不渲染样式。**

**调试线索:**

* **检查控制台错误信息:** 浏览器开发者工具的控制台可能会显示 CSS 解析错误，指出哪个 CSS 文件和哪一行出现了问题。
* **使用浏览器开发者工具检查元素样式:**  在 "Elements" 面板中，可以查看元素的 "Computed" 样式，看颜色属性是否被正确解析和应用。如果颜色值旁边有警告或错误图标，可能表示解析失败。
* **断点调试:**  开发人员可以在 `css_color_function_parser.cc` 中的关键函数（例如 `ConsumeFunctionalSyntaxColor`, `ConsumeChannel`, `ConsumeAlpha`) 设置断点，逐步跟踪代码执行，查看解析过程中的变量值，以确定解析失败的原因。例如，可以检查 `stream.Peek()` 来查看当前正在解析的 token，或者检查解析出的通道值是否符合预期。
* **查看 UseCounter 指标:** 文件中 `#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"` 表明 Blink 可能会跟踪某些 CSS 特性的使用情况。如果涉及到新的颜色函数或特性，可以查看相关的 UseCounter 指标，了解该特性是否被正确识别和处理。

总而言之，`css_color_function_parser.cc` 是 Blink 引擎中负责将 CSS 颜色函数的文本表示转换成内部数据结构的关键组件，它直接影响着网页的视觉呈现和与 JavaScript 的交互。理解它的工作原理对于调试 CSS 相关的渲染问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_color_function_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/properties/css_color_function_parser.h"

#include <cmath>

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_color_channel_keywords.h"
#include "third_party/blink/renderer/core/css/css_color_mix_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_relative_color_value.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"

namespace blink {

namespace {

// https://www.w3.org/TR/css-color-4/#typedef-color-function
bool IsValidColorFunction(CSSValueID id) {
  switch (id) {
    case CSSValueID::kRgb:
    case CSSValueID::kRgba:
    case CSSValueID::kHsl:
    case CSSValueID::kHsla:
    case CSSValueID::kHwb:
    case CSSValueID::kLab:
    case CSSValueID::kLch:
    case CSSValueID::kOklab:
    case CSSValueID::kOklch:
    case CSSValueID::kColor:
      return true;
    default:
      return false;
  }
}

Color::ColorSpace ColorSpaceFromFunctionName(CSSValueID id) {
  switch (id) {
    case CSSValueID::kRgb:
    case CSSValueID::kRgba:
      return Color::ColorSpace::kSRGBLegacy;
    case CSSValueID::kHsl:
    case CSSValueID::kHsla:
      return Color::ColorSpace::kHSL;
    case CSSValueID::kHwb:
      return Color::ColorSpace::kHWB;
    case CSSValueID::kLab:
      return Color::ColorSpace::kLab;
    case CSSValueID::kOklab:
      return Color::ColorSpace::kOklab;
    case CSSValueID::kLch:
      return Color::ColorSpace::kLch;
    case CSSValueID::kOklch:
      return Color::ColorSpace::kOklch;
    default:
      return Color::ColorSpace::kNone;
  }
}

// https://www.w3.org/TR/css-color-4/#color-function
Color::ColorSpace ColorSpaceFromColorSpaceArgument(CSSValueID id) {
  switch (id) {
    case CSSValueID::kSRGB:
      return Color::ColorSpace::kSRGB;
    case CSSValueID::kRec2020:
      return Color::ColorSpace::kRec2020;
    case CSSValueID::kSRGBLinear:
      return Color::ColorSpace::kSRGBLinear;
    case CSSValueID::kDisplayP3:
      return Color::ColorSpace::kDisplayP3;
    case CSSValueID::kA98Rgb:
      return Color::ColorSpace::kA98RGB;
    case CSSValueID::kProphotoRgb:
      return Color::ColorSpace::kProPhotoRGB;
    case CSSValueID::kXyzD50:
      return Color::ColorSpace::kXYZD50;
    case CSSValueID::kXyz:
    case CSSValueID::kXyzD65:
      return Color::ColorSpace::kXYZD65;
    default:
      return Color::ColorSpace::kNone;
  }
}

bool ColorChannelIsHue(Color::ColorSpace color_space, int channel) {
  if (color_space == Color::ColorSpace::kHSL ||
      color_space == Color::ColorSpace::kHWB) {
    if (channel == 0) {
      return true;
    }
  }
  if (color_space == Color::ColorSpace::kLch ||
      color_space == Color::ColorSpace::kOklch) {
    if (channel == 2) {
      return true;
    }
  }
  return false;
}

// If the CSSValue is an absolute color, return the corresponding Color.
std::optional<Color> TryResolveAtParseTime(const CSSValue& value) {
  if (auto* color_value = DynamicTo<cssvalue::CSSColor>(value)) {
    return color_value->Value();
  }
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    // We can resolve <named-color> and 'transparent' at parse-time.
    CSSValueID value_id = identifier_value->GetValueID();
    if ((value_id >= CSSValueID::kAqua && value_id <= CSSValueID::kYellow) ||
        (value_id >= CSSValueID::kAliceblue &&
         value_id <= CSSValueID::kYellowgreen) ||
        value_id == CSSValueID::kTransparent || value_id == CSSValueID::kGrey) {
      // We're passing 'light' as the color-scheme, but nothing above should
      // depend on that value (i.e it's a dummy argument). Ditto for the null
      // color provider.
      return StyleColor::ColorFromKeyword(
          value_id, mojom::blink::ColorScheme::kLight, nullptr,
          /*is_in_web_app_scope=*/false);
    }
    return std::nullopt;
  }
  if (auto* color_mix_value = DynamicTo<cssvalue::CSSColorMixValue>(value)) {
    auto color1 = TryResolveAtParseTime(color_mix_value->Color1());
    auto color2 = TryResolveAtParseTime(color_mix_value->Color2());
    if (!color1 || !color2) {
      return std::nullopt;
    }
    // We can only mix with percentages being numeric literals from here,
    // as we don't have a length conversion data to resolve against yet.
    if ((!color_mix_value->Percentage1() ||
         color_mix_value->Percentage1()->IsNumericLiteralValue()) &&
        (!color_mix_value->Percentage2() ||
         color_mix_value->Percentage2()->IsNumericLiteralValue())) {
      return color_mix_value->Mix(
          *color1, *color2, CSSToLengthConversionData(/*element=*/nullptr));
    }
  }
  if (auto* relative_color_value =
          DynamicTo<cssvalue::CSSRelativeColorValue>(value)) {
    auto origin_color =
        TryResolveAtParseTime(relative_color_value->OriginColor());
    if (!origin_color) {
      return std::nullopt;
    }
    StyleColor::UnresolvedRelativeColor* unresolved_relative_color =
        MakeGarbageCollected<StyleColor::UnresolvedRelativeColor>(
            StyleColor(origin_color.value()),
            relative_color_value->ColorInterpolationSpace(),
            relative_color_value->Channel0(), relative_color_value->Channel1(),
            relative_color_value->Channel2(), relative_color_value->Alpha());
    return unresolved_relative_color->Resolve(Color());
  }
  return std::nullopt;
}

CSSValue* ConsumeRelativeColorChannel(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSColorChannelMap& color_channel_map,
    CalculationResultCategorySet expected_categories,
    const double percentage_base = 0) {
  const CSSParserToken token = stream.Peek();
  // Relative color channels can be calc() functions with color channel
  // replacements. e.g. In "color(from magenta srgb calc(r / 2) 0 0)", the
  // "calc" should substitute "1" for "r" (magenta has a full red channel).
  if (token.GetType() == kFunctionToken) {
    using enum CSSMathExpressionNode::Flag;
    using Flags = CSSMathExpressionNode::Flags;

    // Don't consume the range if the parsing fails.
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    CSSMathFunctionValue* calc_value = CSSMathFunctionValue::Create(
        CSSMathExpressionNode::ParseMathFunction(
            token.FunctionId(), stream, context, Flags({AllowPercent}),
            kCSSAnchorQueryTypesNone, color_channel_map),
        CSSPrimitiveValue::ValueRange::kAll);
    if (calc_value) {
      const CalculationResultCategory category = calc_value->Category();
      if (!expected_categories.Has(category)) {
        return nullptr;
      }
      // Consume the range, since it has succeeded.
      guard.Release();
      stream.ConsumeWhitespace();
      return calc_value;
    }
  }

  // This is for just single variable swaps without calc(). e.g. The "l" in
  // "lab(from cyan l 0.5 0.5)".
  if (color_channel_map.Contains(token.Id())) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  return nullptr;
}

// Returns true if, when converted to Rec2020 space, all components of `color`
// are in the interval [-1/255, 256/255].
bool IsInGamutRec2020(Color color) {
  const float kEpsilon = 1 / 255.f;
  color.ConvertToColorSpace(Color::ColorSpace::kRec2020);
  return -kEpsilon <= color.Param0() && color.Param0() <= 1.f + kEpsilon &&
         -kEpsilon <= color.Param1() && color.Param1() <= 1.f + kEpsilon &&
         -kEpsilon <= color.Param2() && color.Param2() <= 1.f + kEpsilon;
}

}  // namespace

bool ColorFunctionParser::ConsumeColorSpaceAndOriginColor(
    CSSParserTokenStream& stream,
    CSSValueID function_id,
    const CSSParserContext& context) {
  // [from <color>]?
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kFrom>(stream)) {
    if (!RuntimeEnabledFeatures::CSSRelativeColorEnabled()) {
      return false;
    }
    unresolved_origin_color_ = css_parsing_utils::ConsumeColor(stream, context);
    if (!unresolved_origin_color_) {
      return false;
    }
  }

  // Get the color space. This will either be the name of the function, or it
  // will be the first argument of the "color" function.
  if (function_id == CSSValueID::kColor) {
    // <predefined-rgb> | <xyz-space>
    if (stream.Peek().GetType() != kIdentToken) {
      return false;
    }
    color_space_ = ColorSpaceFromColorSpaceArgument(
        stream.ConsumeIncludingWhitespace().Id());
    if (color_space_ == Color::ColorSpace::kNone) {
      return false;
    }
  } else {
    color_space_ = ColorSpaceFromFunctionName(function_id);
  }

  function_metadata_ = &ColorFunction::MetadataForColorSpace(color_space_);

  if (unresolved_origin_color_) {
    origin_color_ = TryResolveAtParseTime(*unresolved_origin_color_);
    if (origin_color_.has_value() &&
        !RuntimeEnabledFeatures::CSSRelativeColorLateResolveAlwaysEnabled()) {
      origin_color_->ConvertToColorSpace(color_space_);
      // Relative color syntax requires "channel keyword" substitutions for
      // color channels. Each color space has three "channel keywords", plus
      // "alpha", that correspond to the three parameters stored on the origin
      // color. This function generates a map between the channel keywords and
      // the stored values in order to make said substitutions. e.g. color(from
      // magenta srgb r g b) will need to generate srgb keyword values for the
      // origin color "magenta". This will produce a map like: {CSSValueID::kR:
      // 1, CSSValueID::kG: 0, CSSValueID::kB: 1, CSSValueID::kAlpha: 1}.
      std::array<double, 3> channel_values = {origin_color_->Param0(),
                                              origin_color_->Param1(),
                                              origin_color_->Param2()};

      // Convert from the [0 1] range to the [0 100] range for hsl() and
      // hwb(). This is the inverse of the transform in
      // MakePerColorSpaceAdjustments().
      if (color_space_ == Color::ColorSpace::kHSL ||
          color_space_ == Color::ColorSpace::kHWB) {
        channel_values[1] *= 100;
        channel_values[2] *= 100;
      }

      color_channel_map_ = {
          {function_metadata_->channel_name[0], channel_values[0]},
          {function_metadata_->channel_name[1], channel_values[1]},
          {function_metadata_->channel_name[2], channel_values[2]},
          {CSSValueID::kAlpha, origin_color_->Alpha()},
      };
    } else {
      if (!origin_color_.has_value() &&
          !RuntimeEnabledFeatures::
              CSSRelativeColorSupportsCurrentcolorEnabled()) {
        return false;
      }
      // If the origin color is not resolvable at parse time, fill out the map
      // with just the valid channel names. We still need that information to
      // parse the remainder of the color function.
      color_channel_map_ = {
          {function_metadata_->channel_name[0], std::nullopt},
          {function_metadata_->channel_name[1], std::nullopt},
          {function_metadata_->channel_name[2], std::nullopt},
          {CSSValueID::kAlpha, std::nullopt},
      };
    }
  }
  return true;
}

bool ColorFunctionParser::ConsumeChannel(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         int i) {
  if (css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    unresolved_channels_[i] = CSSIdentifierValue::Create(CSSValueID::kNone);
    channel_types_[i] = ChannelType::kNone;
    has_none_ = true;
    return true;
  }

  if (ColorChannelIsHue(color_space_, i)) {
    if ((unresolved_channels_[i] =
             css_parsing_utils::ConsumeAngle(stream, context, std::nullopt))) {
      channel_types_[i] = ChannelType::kNumber;
    } else if ((unresolved_channels_[i] = css_parsing_utils::ConsumeNumber(
                    stream, context, CSSPrimitiveValue::ValueRange::kAll))) {
      channel_types_[i] = ChannelType::kNumber;
    } else if (IsRelativeColor()) {
      if ((unresolved_channels_[i] =
               ConsumeRelativeColorChannel(stream, context, color_channel_map_,
                                           {kCalcNumber, kCalcAngle}))) {
        channel_types_[i] = ChannelType::kRelative;
      }
    }

    if (!unresolved_channels_[i]) {
      return false;
    }

    return true;
  }

  if ((unresolved_channels_[i] = css_parsing_utils::ConsumeNumber(
           stream, context, CSSPrimitiveValue::ValueRange::kAll))) {
    channel_types_[i] = ChannelType::kNumber;
    return true;
  }

  if ((unresolved_channels_[i] = css_parsing_utils::ConsumePercent(
           stream, context, CSSPrimitiveValue::ValueRange::kAll))) {
    channel_types_[i] = ChannelType::kPercentage;
    return true;
  }

  if (IsRelativeColor()) {
    channel_types_[i] = ChannelType::kRelative;
    if ((unresolved_channels_[i] = ConsumeRelativeColorChannel(
             stream, context, color_channel_map_, {kCalcNumber, kCalcPercent},
             function_metadata_->channel_percentage[i]))) {
      return true;
    }
  }

  // Missing components should not parse.
  return false;
}

bool ColorFunctionParser::ConsumeAlpha(CSSParserTokenStream& stream,
                                       const CSSParserContext& context) {
  if ((unresolved_alpha_ = css_parsing_utils::ConsumeNumber(
           stream, context, CSSPrimitiveValue::ValueRange::kAll))) {
    alpha_channel_type_ = ChannelType::kNumber;
    return true;
  }

  if ((unresolved_alpha_ = css_parsing_utils::ConsumePercent(
           stream, context, CSSPrimitiveValue::ValueRange::kAll))) {
    alpha_channel_type_ = ChannelType::kPercentage;
    return true;
  }

  if (css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    has_none_ = true;
    unresolved_alpha_ = CSSIdentifierValue::Create(CSSValueID::kNone);
    alpha_channel_type_ = ChannelType::kNone;
    return true;
  }

  if (IsRelativeColor() && (unresolved_alpha_ = ConsumeRelativeColorChannel(
                                stream, context, color_channel_map_,
                                {kCalcNumber, kCalcPercent}, 1.0))) {
    alpha_channel_type_ = ChannelType::kRelative;
    return true;
  }

  return false;
}

void ColorFunctionParser::MakePerColorSpaceAdjustments() {
  if (color_space_ == Color::ColorSpace::kSRGBLegacy) {
    for (int i = 0; i < 3; i++) {
      if (channel_types_[i] == ChannelType::kNone) {
        continue;
      }
      if (!isfinite(channels_[i].value())) {
        channels_[i].value() = channels_[i].value() > 0 ? 255.0 : 0;
      } else if (!IsRelativeColor()) {
        // Clamp to [0, 1] range, but allow out-of-gamut relative colors.
        channels_[i].value() =
            ClampTo<double>(channels_[i].value(), 0.0, 255.0);
      }
    }
    // TODO(crbug.com/1399566): There are many code paths that still compress
    // alpha to be an 8-bit integer. If it is not explicitly compressed here,
    // tests will fail due to some paths doing this compression and others not.
    // See compositing/background-color/background-color-alpha.html for example.
    // Ideally we would allow alpha to be any float value, but we have to clean
    // up all spots where this compression happens before this is possible.
    if (!IsRelativeColor() && alpha_.has_value()) {
      alpha_ = round(alpha_.value() * 255.0) / 255.0;
    }
  }

  if (color_space_ == Color::ColorSpace::kHSL ||
      color_space_ == Color::ColorSpace::kHWB) {
    for (int i : {1, 2}) {
      // Raw numbers are interpreted as percentages in these color spaces.
      if (channels_[i].has_value()) {
        channels_[i] = channels_[i].value() / 100.0;

        if (is_legacy_syntax_) {
          channels_[i] = ClampTo<double>(channels_[i].value(), 0.0, 1.0);
        }
      }
    }
  }
}

double ColorFunctionParser::ResolveColorChannel(
    const CSSValue* value,
    ChannelType channel_type,
    double percentage_base,
    const CSSColorChannelMap& color_channel_map) {
  if (const CSSPrimitiveValue* primitive_value =
          DynamicTo<CSSPrimitiveValue>(value)) {
    switch (channel_type) {
      case ChannelType::kNumber:
        if (primitive_value->IsAngle()) {
          return primitive_value->ComputeDegrees();
        } else {
          return primitive_value->GetDoubleValueWithoutClamping();
        }
      case ChannelType::kPercentage:
        return (primitive_value->GetDoubleValue() / 100.0) * percentage_base;
      case ChannelType::kRelative:
        // Proceed to relative channel value resolution below.
        break;
      default:
        NOTREACHED();
    }
  }

  return ResolveRelativeChannelValue(value, channel_type, percentage_base,
                                     color_channel_map);
}

double ColorFunctionParser::ResolveAlpha(
    const CSSValue* value,
    ChannelType channel_type,
    const CSSColorChannelMap& color_channel_map) {
  if (const CSSPrimitiveValue* primitive_value =
          DynamicTo<CSSPrimitiveValue>(value)) {
    switch (channel_type) {
      case ChannelType::kNumber:
        return ClampTo<double>(primitive_value->GetDoubleValue(), 0.0, 1.0);
      case ChannelType::kPercentage:
        return ClampTo<double>(primitive_value->GetDoubleValue() / 100.0, 0.0,
                               1.0);
      case ChannelType::kRelative:
        // Proceed to relative channel value resolution below.
        break;
      default:
        NOTREACHED();
    }
  }

  return ResolveRelativeChannelValue(
      value, channel_type, /*percentage_base=*/1.0, color_channel_map);
}

double ColorFunctionParser::ResolveRelativeChannelValue(
    const CSSValue* value,
    ChannelType channel_type,
    double percentage_base,
    const CSSColorChannelMap& color_channel_map) {
  if (const CSSIdentifierValue* identifier_value =
          DynamicTo<CSSIdentifierValue>(value)) {
    // This is for just single variable swaps without calc(). e.g. The "l" in
    // "lab(from cyan l 0.5 0.5)".
    if (auto it = color_channel_map.find(identifier_value->GetValueID());
        it != color_channel_map.end()) {
      return it->value.value();
    }
  }

  if (const CSSMathFunctionValue* calc_value =
          DynamicTo<CSSMathFunctionValue>(value)) {
    switch (calc_value->Category()) {
      case kCalcNumber:
        return calc_value->GetDoubleValueWithoutClamping();
      case kCalcPercent:
        return (calc_value->GetDoubleValue() / 100) * percentage_base;
      case kCalcAngle:
        return calc_value->ComputeDegrees();
      default:
        NOTREACHED();
    }
  }

  NOTREACHED();
}

bool ColorFunctionParser::IsRelativeColor() const {
  return !!unresolved_origin_color_;
}

CSSValue* ColorFunctionParser::ConsumeFunctionalSyntaxColor(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValueID function_id = stream.Peek().FunctionId();
  if (!IsValidColorFunction(function_id)) {
    return nullptr;
  }

  if (function_id == CSSValueID::kColor) {
    context.Count(WebFeature::kCSSColorFunction);
  }

  std::optional<Color> resolved_color;
  bool has_alpha = false;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (!ConsumeColorSpaceAndOriginColor(stream, function_id, context)) {
      return nullptr;
    }

    // Parse the three color channel params.
    for (int i = 0; i < 3; i++) {
      if (!ConsumeChannel(stream, context, i)) {
        return nullptr;
      }
      // Potentially expect a separator after the first and second channel. The
      // separator for a potential alpha channel is handled below.
      if (i < 2) {
        const bool matched_comma =
            css_parsing_utils::ConsumeCommaIncludingWhitespace(stream);
        if (is_legacy_syntax_) {
          // We've parsed one separating comma token, so we expect the second
          // separator to match.
          if (!matched_comma) {
            return nullptr;
          }
        } else if (matched_comma) {
          if (IsRelativeColor()) {
            return nullptr;
          }
          is_legacy_syntax_ = true;
        }
      }
    }

    // Parse alpha.
    if (is_legacy_syntax_) {
      if (!Color::IsLegacyColorSpace(color_space_)) {
        return nullptr;
      }
      // , <alpha-value>?
      if (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
        has_alpha = true;
      }
    } else {
      // / <alpha-value>?
      if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        has_alpha = true;
      }
    }
    if (has_alpha) {
      if (!ConsumeAlpha(stream, context)) {
        return nullptr;
      }
    }

    if (!stream.AtEnd()) {
      return nullptr;
    }

    if (is_legacy_syntax_) {
      // "None" is not a part of the legacy syntax.
      if (has_none_) {
        return nullptr;
      }
      // Legacy rgb needs percentage consistency. Percentages need to be mapped
      // from the range [0, 1] to the [0, 255] that the color space uses.
      // Percentages and bare numbers CAN be mixed in relative colors.
      if (color_space_ == Color::ColorSpace::kSRGBLegacy) {
        bool uses_percentage = false;
        bool uses_bare_numbers = false;
        for (int i = 0; i < 3; i++) {
          if (channel_types_[i] == ChannelType::kNone) {
            continue;
          }
          if (channel_types_[i] == ChannelType::kPercentage) {
            if (uses_bare_numbers) {
              return nullptr;
            }
            uses_percentage = true;
          } else if (channel_types_[i] == ChannelType::kNumber) {
            if (uses_percentage) {
              return nullptr;
            }
            uses_bare_numbers = true;
          }
        }
      }

      // Legacy syntax is not allowed for hwb().
      if (color_space_ == Color::ColorSpace::kHWB) {
        return nullptr;
      }

      if (color_space_ == Color::ColorSpace::kHSL ||
          color_space_ == Color::ColorSpace::kHWB) {
        for (int i : {1, 2}) {
          if (channel_types_[i] == ChannelType::kNumber) {
            // Legacy color syntax needs percentages.
            return nullptr;
          }
        }
      }
    }

    // The parsing was successful, so we need to consume the input.
    guard.Release();
  }
  stream.ConsumeWhitespace();

  // For non-relative colors, resolve channel values at parse time.
  // For relative colors:
  // - (Legacy behavior) Resolve channel values at parse time if the origin
  //   color is resolvable at parse time.
  // - (WPT-compliant behavior) Always defer resolution until used-value time.
  if (!IsRelativeColor() ||
      (origin_color_.has_value() &&
       !RuntimeEnabledFeatures::CSSRelativeColorLateResolveAlwaysEnabled())) {
    // Resolve channel values.
    for (int i = 0; i < 3; i++) {
      if (channel_types_[i] != ChannelType::kNone) {
        channels_[i] = ResolveColorChannel(
            unresolved_channels_[i], channel_types_[i],
            function_metadata_->channel_percentage[i], color_channel_map_);

        if (ColorChannelIsHue(color_space_, i)) {
          // Non-finite values should be clamped to the range [0, 360].
          // Since 0 = 360 in this case, they can all simply become zero.
          if (!isfinite(channels_[i].value())) {
            channels_[i] = 0.0;
          }

          // Wrap hue to be in the range [0, 360].
          channels_[i].value() =
              fmod(fmod(channels_[i].value(), 360.0) + 360.0, 360.0);
        }
      }
    }

    if (has_alpha) {
      if (alpha_channel_type_ != ChannelType::kNone) {
        alpha_ = ResolveAlpha(unresolved_alpha_, alpha_channel_type_,
                              color_channel_map_);
      } else {
        alpha_.reset();
      }
    } else if (IsRelativeColor()) {
      alpha_ = color_channel_map_.at(CSSValueID::kAlpha);
    }

    MakePerColorSpaceAdjustments();

    resolved_color = Color::FromColorSpace(color_space_, channels_[0],
                                           channels_[1], channels_[2], alpha_);
    if (IsRelativeColor() && Color::IsLegacyColorSpace(color_space_)) {
      resolved_color->ConvertToColorSpace(Color::ColorSpace::kSRGB);
    }
  }

  if (IsRelativeColor()) {
    context.Count(WebFeature::kCSSRelativeColor);
  } else {
    switch (color_space_) {
      case Color::ColorSpace::kSRGB:
      case Color::ColorSpace::kSRGBLinear:
      case Color::ColorSpace::kDisplayP3:
      case Color::ColorSpace::kA98RGB:
      case Color::ColorSpace::kProPhotoRGB:
      case Color::ColorSpace::kRec2020:
        context.Count(WebFeature::kCSSColor_SpaceRGB);
        if (resolved_color.has_value() && !IsInGamutRec2020(*resolved_color)) {
          context.Count(WebFeature::kCSSColor_SpaceRGB_outOfRec2020);
        }
        break;
      case Color::ColorSpace::kOklab:
      case Color::ColorSpace::kOklch:
        context.Count(WebFeature::kCSSColor_SpaceOkLxx);
        if (resolved_color.has_value() && !IsInGamutRec2020(*resolved_color)) {
          context.Count(WebFeature::kCSSColor_SpaceOkLxx_outOfRec2020);
        }
        break;
      case Color::ColorSpace::kLab:
      case Color::ColorSpace::kLch:
        context.Count(WebFeature::kCSSColor_SpaceLxx);
        break;
      case Color::ColorSpace::kHWB:
        context.Count(WebFeature::kCSSColor_SpaceHwb);
        break;
      case Color::ColorSpace::kXYZD50:
      case Color::ColorSpace::kXYZD65:
      case Color::ColorSpace::kSRGBLegacy:
      case Color::ColorSpace::kHSL:
      case Color::ColorSpace::kNone:
        break;
    }
  }

  if (resolved_color.has_value()) {
    return cssvalue::CSSColor::Create(*resolved_color);
  } else {
    return MakeGarbageCollected<cssvalue::CSSRelativeColorValue>(
        *unresolved_origin_color_, color_space_, *unresolved_channels_[0],
        *unresolved_channels_[1], *unresolved_channels_[2], unresolved_alpha_);
  }
}

}  // namespace blink
```