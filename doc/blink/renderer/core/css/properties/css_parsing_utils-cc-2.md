Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. They want to know what the code does, its relation to web technologies (JavaScript, HTML, CSS), examples of its usage, potential user errors, how a user action might lead to this code being executed, and a general summary of its purpose. This is part 3 of a 9-part series, which might provide additional context later.

**Breakdown of the Code:**

The code primarily focuses on parsing CSS color-related values and some associated concepts like positions and gradients. Here's a more granular breakdown:

1. **Color Interpolation:** Handles parsing keywords related to how color hues should be interpolated in color transitions or animations (`longer`, `shorter`, `increasing`, `decreasing`).
2. **`color-mix()` function:**  Parses the CSS `color-mix()` function, which blends two colors in a specified color space.
3. **Hex Color Parsing:**  Parses hexadecimal color codes (e.g., `#RRGGBB`, `#RGB`) and some quirky legacy variations.
4. **`color-contrast()` function:** Parses the CSS `color-contrast()` function, which selects a color from a list that has sufficient contrast with a background color.
5. **Color Keyword Parsing:** Handles parsing standard CSS color keywords (e.g., `red`, `blue`, `transparent`).
6. **Functional Color Notation Parsing:**  Uses a `ColorFunctionParser` to handle modern CSS color functions like `rgb()`, `rgba()`, `hsl()`, `hsla()`, `lab()`, `lch()`, `oklab()`, `oklch()`, and `color()`.
7. **`light-dark()` function:**  Handles parsing the CSS `light-dark()` color function.
8. **Line Width Parsing:** Parses values for properties like `border-width`, including keywords like `thin`, `medium`, and `thick`.
9. **Position Parsing:**  Parses values for properties like `background-position`, `object-position`, etc., handling keywords like `top`, `bottom`, `left`, `right`, and `center`, along with length and percentage values. It handles one, two, three, and four-value syntax variations.
10. **Border Shorthand Parsing:** Parses the `border` shorthand property.
11. **Deprecated Gradient Parsing:** Handles parsing the older `-webkit-gradient()` syntax.
12. **Modern Gradient Parsing:** Includes logic for parsing color stops in modern CSS gradients (`linear-gradient`, `radial-gradient`, `conic-gradient`).

**Planning the Response:**

I'll structure the response to address each of the user's requests:

*   **Functionality Summary:**  Provide a concise overview of the main tasks performed by the code.
*   **Relationship to Web Technologies:**  Explain how each major parsing function relates to CSS, HTML, and potentially JavaScript (though the interaction with JavaScript is more indirect through the rendering engine). Provide concrete examples.
*   **Logic Inference (Hypothetical Input/Output):**  For a few key functions (like `ConsumeColorMixFunction` and `ConsumeColorContrast`), provide hypothetical CSS input and the expected data structure output (though not the exact C++ object, but a representation of it).
*   **Common User/Programming Errors:**  List typical mistakes users or developers might make when writing CSS that would trigger parsing errors in this code.
*   **User Operation Leading to This Code:** Describe a realistic user interaction within a browser that would cause this CSS parsing code to be executed.
*   **Part 3 Summary:**  Synthesize the key functionalities described in this part.

**Self-Correction/Refinement:**

*   Initially, I might focus too much on the C++ implementation details. I need to keep the explanation geared towards the user's understanding of web technologies.
*   The "input/output" for C++ parsing is more about the token stream and the resulting data structures (like `CSSColorMixValue`) rather than simple string in/string out. I'll focus on representing these structures conceptually.
*   The user operation needs to be clear and directly linked to the parsing process. Simply saying "loading a webpage" isn't specific enough.
*   Given that this is part 3 of 9, I should avoid making assumptions about what was covered in previous parts. I'll focus solely on the provided code snippet.
这个代码片段是 Chromium Blink 引擎中 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第三部分，其主要功能是 **解析 CSS 中与颜色、位置和一些特殊效果相关的语法**。它包含了一系列用于从 CSS 词法单元流（`CSSParserTokenStream`）中提取并创建相应的 CSS 值的函数。

以下是代码片段中各个主要功能及其与 JavaScript、HTML、CSS 的关系的详细说明：

**1. 颜色插值空间解析 (`ConsumeColorInterpolationSpace`)**

*   **功能:**  解析 CSS 中用于颜色混合或颜色动画时指定的颜色插值空间，例如 `srgb`, `lab`, `lch`, `oklab`, `oklch`，以及色相插值方法 (`shorter`, `longer`, `increasing`, `decreasing`).
*   **与 CSS 的关系:**  直接关联到 CSS 颜色规范中的 `color-mix()` 函数和颜色动画/过渡中的颜色空间控制。
*   **示例:**
    *   **CSS:** `color-mix(in lch, blue 50%, red)` - 这里 `lch` 就是颜色插值空间。
    *   **CSS:** `@keyframes fade { from { color: blue; } to { color-mix(in oklab, blue, red); } }` -  这里 `oklab` 是在动画中使用的颜色插值空间。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (CSS 词法单元流):** `ident(in), whitespace, ident(lab)`
    *   **输出:** `color_space` 将被设置为 `Color::ColorSpace::kLab`，`hue_interpolation` 将被设置为默认值 `Color::HueInterpolationMethod::kShorter`。
    *   **假设输入 (CSS 词法单元流):** `ident(in), whitespace, ident(longer), whitespace, ident(hue), whitespace, ident(oklch)`
    *   **输出:** `color_space` 将被设置为 `Color::ColorSpace::kOKLCH`，`hue_interpolation` 将被设置为 `Color::HueInterpolationMethod::kLonger`。

**2. `color-mix()` 函数解析 (`ConsumeColorMixFunction`)**

*   **功能:** 解析 CSS `color-mix()` 函数的语法，提取参与混合的颜色、它们的比例、以及指定的颜色空间和色相插值方法。
*   **与 CSS 的关系:**  直接关联到 CSS 的 `color-mix()` 函数，允许在不同的颜色空间中混合两种颜色。
*   **示例:**
    *   **CSS:** `background-color: color-mix(in lch, blue 20%, red 80%);`
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (CSS 词法单元流):** `function(color-mix), whitespace, ident(in), whitespace, ident(srgb), comma, whitespace, ident(blue), whitespace, number(20), percentage, comma, whitespace, ident(red), number(80), percentage, close-paren`
    *   **输出 (简化的概念表示):**  一个表示 `CSSColorMixValue` 的对象，包含：
        *   `color1`: 代表 `blue` 的 `CSSValue`
        *   `color2`: 代表 `red` 的 `CSSValue`
        *   `p1`:  代表 `20%` 的 `CSSPrimitiveValue`
        *   `p2`:  代表 `80%` 的 `CSSPrimitiveValue`
        *   `color_space`: `Color::ColorSpace::kSRGB`
        *   `hue_interpolation_method`: `Color::HueInterpolationMethod::kShorter` (默认)

**3. 十六进制颜色解析 (`ParseHexColor`)**

*   **功能:** 解析 CSS 中的十六进制颜色代码，如 `#RRGGBB`, `#RGB`，以及一些非标准的数字或标识符表示的颜色值（在 Quirks 模式下）。
*   **与 CSS 和 HTML 的关系:**  HTML 和 CSS 中都广泛使用十六进制颜色代码。
*   **示例:**
    *   **CSS:** `color: #FF0000;`
    *   **HTML:** `<div style="background-color: #00F;"></div>`
*   **用户或编程常见的使用错误:**
    *   **错误的格式:**  输入了不符合十六进制格式的字符串，例如 `#GGG` 或 `#12345`。
    *   **Quirks 模式下的误用:**  依赖于 Quirks 模式下非标准的颜色表示，可能导致在标准模式下解析失败。
    *   **假设输入 (CSS 词法单元流):** `hash(#FF0000)`
    *   **输出:** `result` (一个 `Color` 对象) 将被设置为红色。
    *   **假设输入 (CSS 词法单元流):** `number(112233)` (在 Quirks 模式下)
    *   **输出:** `result` 将被设置为对应的颜色。

**4. `color-contrast()` 函数解析 (`ConsumeColorContrast`)**

*   **功能:** 解析 CSS `color-contrast()` 函数，它根据与背景颜色的对比度从提供的颜色列表中选择最佳的颜色。
*   **与 CSS 的关系:**  直接关联到 CSS 的 `color-contrast()` 函数，用于增强可访问性。
*   **示例:**
    *   **CSS:** `color: color-contrast(white vs black, blue, green);` -  选择 `black`, `blue`, `green` 中对比度最高的颜色与 `white` 进行对比。
    *   **CSS:** `color: color-contrast(#333 vs white, black to AA);` - 选择 `white` 或 `black` 中对比度达到 AA 级要求的颜色。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (CSS 词法单元流):** `function(color-contrast), whitespace, ident(white), whitespace, ident(vs), whitespace, ident(black), comma, whitespace, ident(blue), close-paren`
    *   **输出 (简化的概念表示):**  根据当前上下文（包括 `color_provider`，用于解析像 `currentColor` 这样的值）计算 `white` 与 `black` 以及 `white` 与 `blue` 的对比度，并返回对比度较高的颜色的 `CSSColor` 对象。

**5. 内部颜色解析 (`ConsumeColorInternal`)**

*   **功能:**  作为一个中心函数，协调各种颜色值的解析，包括颜色关键字、十六进制颜色、函数式颜色表示 (`rgb()`, `hsl()` 等) 以及 `color-mix()` 和 `color-contrast()` 函数。它还处理对 `system-accent-color` 的限制。
*   **与 CSS 的关系:**  所有 CSS 颜色属性的值都通过这个函数进行解析。

**6. 绝对颜色解析 (`ConsumeAbsoluteColor`)**

*   **功能:**  类似于 `ConsumeColorInternal`，但限制了可以接受的颜色类型，通常不允许使用 `currentColor` 或系统颜色等相对颜色。
*   **与 CSS 的关系:**  用于解析某些上下文中必须是明确颜色的属性值。

**7. 线宽解析 (`ConsumeLineWidth`)**

*   **功能:**  解析 CSS 中用于指定线宽的值，包括关键字 (`thin`, `medium`, `thick`) 和长度单位。
*   **与 CSS 的关系:**  用于解析 `border-width`, `outline-width` 等属性。
*   **示例:**
    *   **CSS:** `border-width: 2px;`
    *   **CSS:** `border-width: thick;`

**8. 位置组件解析 (`ConsumePositionComponent`) 和 位置解析 (`ConsumePosition`, `ConsumeOneOrTwoValuedPosition`)**

*   **功能:** 解析 CSS 中用于指定位置的值，例如 `background-position`, `object-position`。它可以处理关键字 (`top`, `bottom`, `left`, `right`, `center`) 和长度/百分比值，并处理单值、双值、三值和四值语法。
*   **与 CSS 的关系:**  广泛应用于定位相关的 CSS 属性。
*   **示例:**
    *   **CSS:** `background-position: top center;`
    *   **CSS:** `background-position: 10px 20%;`
    *   **CSS:** `background-position: bottom 10px right 20px;`
*   **用户或编程常见的使用错误:**
    *   **关键词顺序错误:**  例如，`center top` (虽然某些情况下可能被理解，但通常期望的是 `top center` 或 `center top` 根据规范的解析规则)。
    *   **三值或四值语法错误:**  例如，缺少必要的关键词或长度值。

**9. 边框简写属性解析 (`ConsumeBorderShorthand`)**

*   **功能:** 解析 CSS 的 `border` 简写属性，它可以同时指定边框的宽度、样式和颜色。
*   **与 CSS 的关系:**  直接关联到 CSS 的 `border` 属性。
*   **示例:**
    *   **CSS:** `border: 1px solid black;`

**10. 废弃的渐变解析 (`ConsumeDeprecatedGradient`, `ConsumeDeprecatedGradientPoint`, `ConsumeDeprecatedGradientStopColor`, `ConsumeDeprecatedGradientColorStop`)**

*   **功能:**  解析早期 WebKit 特有的 `-webkit-gradient()` 函数的语法，包括线性和径向渐变。
*   **与 CSS 的关系:**  虽然是废弃的语法，但浏览器仍然需要解析以保持向后兼容性。
*   **示例:**
    *   **CSS:** `background-image: -webkit-gradient(linear, left top, right bottom, from(red), to(blue));`

**11. 现代渐变颜色停止解析 (`ConsumeGradientColorStops`)**

*   **功能:** 解析现代 CSS 渐变（`linear-gradient`, `radial-gradient`, `conic-gradient`)中的颜色停止点，包括颜色和可选的位置。
*   **与 CSS 的关系:**  用于解析 `linear-gradient()`, `radial-gradient()`, `conic-gradient()` 等函数。
*   **示例:**
    *   **CSS:** `background-image: linear-gradient(red, yellow 50%, blue);`

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编辑 CSS:**  用户在一个网页的 CSS 文件或者 `<style>` 标签中编写了涉及颜色、位置或边框的 CSS 规则，例如设置了元素的 `background-color` 为 `color-mix(in lch, blue, red)`。
2. **浏览器加载页面或更新样式:**  当浏览器加载包含这些 CSS 规则的网页，或者用户通过开发者工具动态修改了样式时，Blink 渲染引擎会开始解析这些 CSS。
3. **CSS 词法分析:**  CSS 文本首先会被词法分析器分解成一系列的词法单元（tokens），例如 `ident("color-mix")`, `ident("in")`, `ident("lch")`, `comma`, 等等。
4. **CSS 语法解析:**  `css_parsing_utils.cc` 中的函数被调用，以根据 CSS 语法规则将这些词法单元组合成有意义的 CSS 值。
    *   当遇到 `color-mix` 标识符时，`ConsumeColorInternal` 会被调用，它会识别出这是一个函数，并调用 `ConsumeColorMixFunction` 来解析 `color-mix()` 的参数。
    *   类似地，当遇到 `#RRGGBB` 形式的词法单元时，`ParseHexColor` 会被调用。
    *   当解析 `border` 属性时，`ConsumeBorderShorthand` 会被调用，并进一步调用其他函数来解析宽度、样式和颜色部分。
5. **创建 CSS 值对象:**  解析函数会根据解析结果创建相应的 CSS 值对象，例如 `CSSColorMixValue`, `CSSColor`, `CSSValuePair` 等，这些对象会在后续的样式计算和渲染过程中使用。

**第3部分功能归纳:**

总而言之，`blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第三部分主要负责 **解析 CSS 中关于颜色（包括各种颜色表示法和颜色混合、对比度函数）、位置信息以及一些特殊的视觉效果（如边框和渐变）的语法**，并将这些语法转换为 Blink 引擎可以理解和使用的内部数据结构。它是 CSS 引擎处理视觉样式规则的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
(stream)) {
        read_hue = Color::HueInterpolationMethod::kLonger;
      } else if (ConsumeIdent<CSSValueID::kDecreasing>(stream)) {
        read_hue = Color::HueInterpolationMethod::kDecreasing;
      } else if (ConsumeIdent<CSSValueID::kIncreasing>(stream)) {
        read_hue = Color::HueInterpolationMethod::kIncreasing;
      }
      if (read_hue) {
        if (!ConsumeIdent<CSSValueID::kHue>(stream)) {
          return false;
        }
        hue_interpolation = read_hue.value();
      } else {
        // Shorter is the default method for hue interpolation.
        hue_interpolation = Color::HueInterpolationMethod::kShorter;
      }
    }
    return true;
  }

  return false;
}

namespace {

CSSValue* ConsumeColorInternal(CSSParserTokenStream&,
                               const CSSParserContext&,
                               bool accept_quirky_colors,
                               AllowedColors);

}  // namespace

// https://www.w3.org/TR/css-color-5/#color-mix
static CSSValue* ConsumeColorMixFunction(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         AllowedColors allowed_colors) {
  DCHECK(stream.Peek().FunctionId() == CSSValueID::kColorMix);
  context.Count(WebFeature::kCSSColorMixFunction);

  cssvalue::CSSColorMixValue* result;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    // First argument is the colorspace
    Color::ColorSpace color_space;
    Color::HueInterpolationMethod hue_interpolation_method =
        Color::HueInterpolationMethod::kShorter;
    if (!ConsumeColorInterpolationSpace(stream, color_space,
                                        hue_interpolation_method)) {
      return nullptr;
    }

    if (!ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }

    const bool no_quirky_colors = false;

    CSSValue* color1 =
        ConsumeColorInternal(stream, context, no_quirky_colors, allowed_colors);
    CSSPrimitiveValue* p1 =
        ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    // Color can come after the percentage
    if (!color1) {
      color1 = ConsumeColorInternal(stream, context, no_quirky_colors,
                                    allowed_colors);
      if (!color1) {
        return nullptr;
      }
    }
    // Reject negative values and values > 100%, but not calc() values.
    if (auto* p1_numeric = DynamicTo<CSSNumericLiteralValue>(p1);
        p1_numeric && (p1_numeric->ComputePercentage() < 0.0 ||
                       p1_numeric->ComputePercentage() > 100.0)) {
      return nullptr;
    }

    if (!ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }

    CSSValue* color2 =
        ConsumeColorInternal(stream, context, no_quirky_colors, allowed_colors);
    CSSPrimitiveValue* p2 =
        ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    // Color can come after the percentage
    if (!color2) {
      color2 = ConsumeColorInternal(stream, context, no_quirky_colors,
                                    allowed_colors);
      if (!color2) {
        return nullptr;
      }
    }
    // Reject negative values and values > 100%, but not calc() values.
    if (auto* p2_numeric = DynamicTo<CSSNumericLiteralValue>(p2);
        p2_numeric && (p2_numeric->ComputePercentage() < 0.0 ||
                       p2_numeric->ComputePercentage() > 100.0)) {
      return nullptr;
    }

    // If both values are literally zero (and not calc()) reject at parse time
    if (p1 && p2 && p1->IsNumericLiteralValue() &&
        To<CSSNumericLiteralValue>(p1)->ComputePercentage() == 0.0f &&
        p2->IsNumericLiteralValue() &&
        To<CSSNumericLiteralValue>(p2)->ComputePercentage() == 0.0) {
      return nullptr;
    }

    if (!stream.AtEnd()) {
      return nullptr;
    }

    guard.Release();
    result = MakeGarbageCollected<cssvalue::CSSColorMixValue>(
        color1, color2, p1, p2, color_space, hue_interpolation_method);
  }
  stream.ConsumeWhitespace();

  return result;
}

static bool ParseHexColor(CSSParserTokenStream& stream,
                          Color& result,
                          bool accept_quirky_colors) {
  const CSSParserToken& token = stream.Peek();
  if (token.GetType() == kHashToken) {
    if (!Color::ParseHexColor(token.Value(), result)) {
      return false;
    }
  } else if (accept_quirky_colors) {
    String color;
    if (token.GetType() == kNumberToken || token.GetType() == kDimensionToken) {
      if (token.GetNumericValueType() != kIntegerValueType ||
          token.NumericValue() < 0. || token.NumericValue() >= 1000000.) {
        return false;
      }
      if (token.GetType() == kNumberToken) {  // e.g. 112233
        color = String::Format("%d", static_cast<int>(token.NumericValue()));
      } else {  // e.g. 0001FF
        color = String::Number(static_cast<int>(token.NumericValue())) +
                token.Value().ToString();
      }
      while (color.length() < 6) {
        color = "0" + color;
      }
    } else if (token.GetType() == kIdentToken) {  // e.g. FF0000
      color = token.Value().ToString();
    }
    unsigned length = color.length();
    if (length != 3 && length != 6) {
      return false;
    }
    if (!Color::ParseHexColor(color, result)) {
      return false;
    }
  } else {
    return false;
  }
  stream.ConsumeIncludingWhitespace();
  return true;
}

namespace {

// TODO(crbug.com/1111385): Remove this when we move color-contrast()
// representation to ComputedStyle. This method does not handle currentColor
// correctly.
Color ResolveColor(CSSValue* value,
                   const ui::ColorProvider* color_provider,
                   bool is_in_web_app_scope) {
  if (auto* color = DynamicTo<cssvalue::CSSColor>(value)) {
    return color->Value();
  }

  if (auto* color = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID color_id = color->GetValueID();
    DCHECK(StyleColor::IsColorKeyword(color_id));
    return StyleColor::ColorFromKeyword(color_id,
                                        mojom::blink::ColorScheme::kLight,
                                        color_provider, is_in_web_app_scope);
  }

  NOTREACHED();
}

}  // namespace

CSSValue* ConsumeColorContrast(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               AllowedColors allowed_colors) {
  DCHECK_EQ(stream.Peek().FunctionId(), CSSValueID::kColorContrast);

  VectorOf<CSSValue> colors_to_compare_against;
  int highest_contrast_index = -1;
  SkColor4f resolved_background_color;
  const ui::ColorProvider* color_provider = nullptr;
  const auto* document = context.GetDocument();
  bool is_in_web_app_scope = document && document->IsInWebAppScope();
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    const bool no_quirky_colors = false;

    CSSValue* background_color =
        ConsumeColorInternal(stream, context, no_quirky_colors, allowed_colors);
    if (!background_color) {
      return nullptr;
    }

    if (!ConsumeIdent<CSSValueID::kVs>(stream)) {
      return nullptr;
    }

    do {
      CSSValue* color = ConsumeColorInternal(stream, context, no_quirky_colors,
                                             allowed_colors);
      if (!color) {
        return nullptr;
      }
      colors_to_compare_against.push_back(color);
    } while (ConsumeCommaIncludingWhitespace(stream));

    if (colors_to_compare_against.size() < 2) {
      return nullptr;
    }

    std::optional<double> target_contrast;
    if (ConsumeIdent<CSSValueID::kTo>(stream)) {
      double target_contrast_temp;
      if (ConsumeIdent<CSSValueID::kAA>(stream)) {
        target_contrast = 4.5;
      } else if (ConsumeIdent<CSSValueID::kAALarge>(stream)) {
        target_contrast = 3;
      } else if (ConsumeIdent<CSSValueID::kAAA>(stream)) {
        target_contrast = 7;
      } else if (ConsumeIdent<CSSValueID::kAAALarge>(stream)) {
        target_contrast = 4.5;
      } else if (ConsumeNumberRaw(stream, context, target_contrast_temp)) {
        target_contrast = target_contrast_temp;
      } else {
        return nullptr;
      }
    }

    // Bail out if there is any trailing stuff after we parse everything
    if (!stream.AtEnd()) {
      return nullptr;
    }
    if (document) {
      // TODO(crbug.com/929098) Need to pass an appropriate color scheme here.
      color_provider = document->GetColorProviderForPainting(
          mojom::blink::ColorScheme::kLight);
    }
    // TODO(crbug.com/1111385): Represent |background_color| and
    // |colors_to_compare_against| in ComputedStyle and evaluate with
    // currentColor and other variables at used-value time instead of doing it
    // at parse time below.
    resolved_background_color =
        ResolveColor(background_color, color_provider, is_in_web_app_scope)
            .toSkColor4f();
    float highest_contrast_ratio = 0;
    for (unsigned i = 0; i < colors_to_compare_against.size(); i++) {
      float contrast_ratio = color_utils::GetContrastRatio(
          resolved_background_color,
          ResolveColor(colors_to_compare_against[i], color_provider,
                       is_in_web_app_scope)
              .toSkColor4f());
      if (target_contrast.has_value()) {
        if (contrast_ratio >= target_contrast.value()) {
          highest_contrast_ratio = contrast_ratio;
          highest_contrast_index = i;
          break;
        }
      } else if (contrast_ratio > highest_contrast_ratio) {
        highest_contrast_ratio = contrast_ratio;
        highest_contrast_index = i;
      }
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();

  if (highest_contrast_index < 0) {
    // If an explicit target contrast was set and no provided colors have enough
    // contrast, then return white or black depending on which has the most
    // contrast.
    return color_utils::GetContrastRatio(resolved_background_color,
                                         SkColors::kWhite) >
                   color_utils::GetContrastRatio(resolved_background_color,
                                                 SkColors::kBlack)
               ? MakeGarbageCollected<cssvalue::CSSColor>(Color::kWhite)
               : MakeGarbageCollected<cssvalue::CSSColor>(Color::kBlack);
  }

  return MakeGarbageCollected<cssvalue::CSSColor>(
      ResolveColor(colors_to_compare_against[highest_contrast_index],
                   color_provider, is_in_web_app_scope));
}

namespace {

bool SystemAccentColorAllowed(const CSSParserContext& context) {
  if (!RuntimeEnabledFeatures::CSSAccentColorKeywordEnabled()) {
    return false;
  }

  // We should not allow the system accent color to be rendered in image
  // contexts because it could be read back by the page and used for
  // fingerprinting.
  if (const auto* document = context.GetDocument()) {
    if (document->GetPage()->GetChromeClient().IsIsolatedSVGChromeClient()) {
      return false;
    }
  }

  return true;
}

CSSValue* ConsumeColorInternal(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               bool accept_quirky_colors,
                               AllowedColors allowed_colors) {
  if (RuntimeEnabledFeatures::CSSColorContrastEnabled() &&
      stream.Peek().FunctionId() == CSSValueID::kColorContrast) {
    return ConsumeColorContrast(stream, context, allowed_colors);
  }

  if (stream.Peek().FunctionId() == CSSValueID::kColorMix) {
    CSSValue* color = ConsumeColorMixFunction(stream, context, allowed_colors);
    return color;
  }

  CSSValueID id = stream.Peek().Id();
  if ((id == CSSValueID::kAccentcolor || id == CSSValueID::kAccentcolortext) &&
      !SystemAccentColorAllowed(context)) {
    return nullptr;
  }
  if (StyleColor::IsColorKeyword(id)) {
    if (!IsValueAllowedInMode(id, context.Mode())) {
      return nullptr;
    }
    if (allowed_colors == AllowedColors::kAbsolute &&
        (id == CSSValueID::kCurrentcolor ||
         StyleColor::IsSystemColorIncludingDeprecated(id) ||
         StyleColor::IsSystemColor(id))) {
      return nullptr;
    }
    CSSIdentifierValue* color = ConsumeIdent(stream);
    return color;
  }

  Color color = Color::kTransparent;
  if (ParseHexColor(stream, color, accept_quirky_colors)) {
    return cssvalue::CSSColor::Create(color);
  }

  // Parses the color inputs rgb(), rgba(), hsl(), hsla(), hwb(), lab(),
  // oklab(), lch(), oklch() and color(). https://www.w3.org/TR/css-color-4/
  ColorFunctionParser parser;
  if (CSSValue* functional_syntax_color =
          parser.ConsumeFunctionalSyntaxColor(stream, context)) {
    return functional_syntax_color;
  }

  if (allowed_colors == AllowedColors::kAll) {
    return ConsumeLightDark(ConsumeColor, stream, context);
  }
  return nullptr;
}

}  // namespace

CSSValue* ConsumeColorMaybeQuirky(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  return ConsumeColorInternal(stream, context,
                              IsQuirksModeBehavior(context.Mode()),
                              AllowedColors::kAll);
}

CSSValue* ConsumeColor(CSSParserTokenStream& stream,
                       const CSSParserContext& context) {
  return ConsumeColorInternal(stream, context, false /* accept_quirky_colors */,
                              AllowedColors::kAll);
}

CSSValue* ConsumeAbsoluteColor(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  return ConsumeColorInternal(stream, context, false /* accept_quirky_colors */,
                              AllowedColors::kAbsolute);
}

CSSValue* ConsumeLineWidth(CSSParserTokenStream& stream,
                           const CSSParserContext& context,
                           UnitlessQuirk unitless) {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kThin || id == CSSValueID::kMedium ||
      id == CSSValueID::kThick) {
    return ConsumeIdent(stream);
  }
  return ConsumeLength(stream, context,
                       CSSPrimitiveValue::ValueRange::kNonNegative, unitless);
}

static CSSValue* ConsumePositionComponent(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          UnitlessQuirk unitless,
                                          bool& horizontal_edge,
                                          bool& vertical_edge) {
  if (stream.Peek().GetType() != kIdentToken) {
    return ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kAll, unitless);
  }

  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kLeft || id == CSSValueID::kRight) {
    if (horizontal_edge) {
      return nullptr;
    }
    horizontal_edge = true;
  } else if (id == CSSValueID::kTop || id == CSSValueID::kBottom) {
    if (vertical_edge) {
      return nullptr;
    }
    vertical_edge = true;
  } else if (id != CSSValueID::kCenter) {
    return nullptr;
  }
  return ConsumeIdent(stream);
}

static bool IsHorizontalPositionKeywordOnly(const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return false;
  }
  CSSValueID value_id = identifier_value->GetValueID();
  return value_id == CSSValueID::kLeft || value_id == CSSValueID::kRight;
}

static bool IsVerticalPositionKeywordOnly(const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (!identifier_value) {
    return false;
  }
  CSSValueID value_id = identifier_value->GetValueID();
  return value_id == CSSValueID::kTop || value_id == CSSValueID::kBottom;
}

static void PositionFromOneValue(CSSValue* value,
                                 CSSValue*& result_x,
                                 CSSValue*& result_y) {
  bool value_applies_to_y_axis_only = IsVerticalPositionKeywordOnly(*value);
  result_x = value;
  result_y = CSSIdentifierValue::Create(CSSValueID::kCenter);
  if (value_applies_to_y_axis_only) {
    std::swap(result_x, result_y);
  }
}

static void PositionFromTwoValues(CSSValue* value1,
                                  CSSValue* value2,
                                  CSSValue*& result_x,
                                  CSSValue*& result_y) {
  bool must_order_as_xy = IsHorizontalPositionKeywordOnly(*value1) ||
                          IsVerticalPositionKeywordOnly(*value2) ||
                          !value1->IsIdentifierValue() ||
                          !value2->IsIdentifierValue();
  bool must_order_as_yx = IsVerticalPositionKeywordOnly(*value1) ||
                          IsHorizontalPositionKeywordOnly(*value2);
  DCHECK(!must_order_as_xy || !must_order_as_yx);
  result_x = value1;
  result_y = value2;
  if (must_order_as_yx) {
    std::swap(result_x, result_y);
  }
}

static void PositionFromThreeOrFourValues(
    const std::array<CSSValue*, 5>& values,
    CSSValue*& result_x,
    CSSValue*& result_y) {
  CSSIdentifierValue* center = nullptr;
  for (int i = 0; values[i]; i++) {
    auto* current_value = To<CSSIdentifierValue>(values[i]);
    CSSValueID id = current_value->GetValueID();

    if (id == CSSValueID::kCenter) {
      DCHECK(!center);
      center = current_value;
      continue;
    }

    CSSValue* result = nullptr;
    if (values[i + 1] && !values[i + 1]->IsIdentifierValue()) {
      result = MakeGarbageCollected<CSSValuePair>(
          current_value, values[++i], CSSValuePair::kKeepIdenticalValues);
    } else {
      result = current_value;
    }

    if (id == CSSValueID::kLeft || id == CSSValueID::kRight) {
      DCHECK(!result_x);
      result_x = result;
    } else {
      DCHECK(id == CSSValueID::kTop || id == CSSValueID::kBottom);
      DCHECK(!result_y);
      result_y = result;
    }
  }

  if (center) {
    DCHECK(!!result_x != !!result_y);
    if (!result_x) {
      result_x = center;
    } else {
      result_y = center;
    }
  }

  DCHECK(result_x && result_y);
}

bool ConsumePosition(CSSParserTokenStream& stream,
                     const CSSParserContext& context,
                     UnitlessQuirk unitless,
                     std::optional<WebFeature> three_value_position,
                     CSSValue*& result_x,
                     CSSValue*& result_y) {
  bool horizontal_edge = false;
  bool vertical_edge = false;
  CSSValue* value1 = ConsumePositionComponent(stream, context, unitless,
                                              horizontal_edge, vertical_edge);
  if (!value1) {
    return false;
  }
  if (!value1->IsIdentifierValue()) {
    horizontal_edge = true;
  }

  CSSParserTokenStream::State savepoint_after_first_consume = stream.Save();
  CSSValue* value2 = ConsumePositionComponent(stream, context, unitless,
                                              horizontal_edge, vertical_edge);
  if (!value2) {
    PositionFromOneValue(value1, result_x, result_y);
    return true;
  }

  CSSParserTokenStream::State savepoint_after_second_consume = stream.Save();
  CSSValue* value3 = nullptr;
  auto* identifier_value1 = DynamicTo<CSSIdentifierValue>(value1);
  auto* identifier_value2 = DynamicTo<CSSIdentifierValue>(value2);
  // TODO(crbug.com/940442): Fix the strange comparison of a
  // CSSIdentifierValue instance against a specific "stream peek" type check.
  if (identifier_value1 &&
      !!identifier_value2 != (stream.Peek().GetType() == kIdentToken) &&
      (identifier_value2
           ? identifier_value2->GetValueID()
           : identifier_value1->GetValueID()) != CSSValueID::kCenter) {
    value3 = ConsumePositionComponent(stream, context, unitless,
                                      horizontal_edge, vertical_edge);
  }
  if (!value3) {
    if (vertical_edge && !value2->IsIdentifierValue()) {
      stream.Restore(savepoint_after_first_consume);
      PositionFromOneValue(value1, result_x, result_y);
      return true;
    }
    PositionFromTwoValues(value1, value2, result_x, result_y);
    return true;
  }

  CSSValue* value4 = nullptr;
  auto* identifier_value3 = DynamicTo<CSSIdentifierValue>(value3);
  if (identifier_value3 &&
      identifier_value3->GetValueID() != CSSValueID::kCenter &&
      stream.Peek().GetType() != kIdentToken) {
    value4 = ConsumePositionComponent(stream, context, unitless,
                                      horizontal_edge, vertical_edge);
  }

  if (!value4) {
    if (!three_value_position) {
      // [top | bottom] <length-percentage> is not permitted
      if (vertical_edge && !value2->IsIdentifierValue()) {
        stream.Restore(savepoint_after_first_consume);
        PositionFromOneValue(value1, result_x, result_y);
        return true;
      }
      stream.Restore(savepoint_after_second_consume);
      PositionFromTwoValues(value1, value2, result_x, result_y);
      return true;
    }
    DCHECK_EQ(*three_value_position,
              WebFeature::kThreeValuedPositionBackground);
    context.Count(*three_value_position);
  }

  std::array<CSSValue*, 5> values = {value1, value2, value3, value4, nullptr};
  PositionFromThreeOrFourValues(values, result_x, result_y);
  return true;
}

CSSValuePair* ConsumePosition(CSSParserTokenStream& stream,
                              const CSSParserContext& context,
                              UnitlessQuirk unitless,
                              std::optional<WebFeature> three_value_position) {
  CSSValue* result_x = nullptr;
  CSSValue* result_y = nullptr;
  if (ConsumePosition(stream, context, unitless, three_value_position, result_x,
                      result_y)) {
    return MakeGarbageCollected<CSSValuePair>(
        result_x, result_y, CSSValuePair::kKeepIdenticalValues);
  }
  return nullptr;
}

bool ConsumeOneOrTwoValuedPosition(CSSParserTokenStream& stream,
                                   const CSSParserContext& context,
                                   UnitlessQuirk unitless,
                                   CSSValue*& result_x,
                                   CSSValue*& result_y) {
  bool horizontal_edge = false;
  bool vertical_edge = false;
  CSSValue* value1 = ConsumePositionComponent(stream, context, unitless,
                                              horizontal_edge, vertical_edge);
  if (!value1) {
    return false;
  }
  if (!value1->IsIdentifierValue()) {
    horizontal_edge = true;
  }

  if (vertical_edge &&
      ConsumeLengthOrPercent(stream, context,
                             CSSPrimitiveValue::ValueRange::kAll, unitless)) {
    // <length-percentage> is not permitted after top | bottom.
    return false;
  }
  CSSValue* value2 = ConsumePositionComponent(stream, context, unitless,
                                              horizontal_edge, vertical_edge);
  if (!value2) {
    PositionFromOneValue(value1, result_x, result_y);
    return true;
  }
  PositionFromTwoValues(value1, value2, result_x, result_y);
  return true;
}

bool ConsumeBorderShorthand(CSSParserTokenStream& stream,
                            const CSSParserContext& context,
                            const CSSParserLocalContext& local_context,
                            const CSSValue*& result_width,
                            const CSSValue*& result_style,
                            const CSSValue*& result_color) {
  while (!result_width || !result_style || !result_color) {
    if (!result_width) {
      result_width = ParseBorderWidthSide(stream, context, local_context);
      if (result_width) {
        ConsumeCommaIncludingWhitespace(stream);
        continue;
      }
    }
    if (!result_style) {
      result_style = ParseBorderStyleSide(stream, context);
      if (result_style) {
        ConsumeCommaIncludingWhitespace(stream);
        continue;
      }
    }
    if (!result_color) {
      result_color = ConsumeBorderColorSide(stream, context, local_context);
      if (result_color) {
        ConsumeCommaIncludingWhitespace(stream);
        continue;
      }
    }
    break;
  }

  if (!result_width && !result_style && !result_color) {
    return false;
  }

  if (!result_width) {
    result_width = CSSInitialValue::Create();
  }
  if (!result_style) {
    result_style = CSSInitialValue::Create();
  }
  if (!result_color) {
    result_color = CSSInitialValue::Create();
  }
  return true;
}

// This should go away once we drop support for -webkit-gradient
static CSSPrimitiveValue* ConsumeDeprecatedGradientPoint(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    bool horizontal) {
  if (stream.Peek().GetType() == kIdentToken) {
    if ((horizontal && ConsumeIdent<CSSValueID::kLeft>(stream)) ||
        (!horizontal && ConsumeIdent<CSSValueID::kTop>(stream))) {
      return CSSNumericLiteralValue::Create(
          0., CSSPrimitiveValue::UnitType::kPercentage);
    }
    if ((horizontal && ConsumeIdent<CSSValueID::kRight>(stream)) ||
        (!horizontal && ConsumeIdent<CSSValueID::kBottom>(stream))) {
      return CSSNumericLiteralValue::Create(
          100., CSSPrimitiveValue::UnitType::kPercentage);
    }
    if (ConsumeIdent<CSSValueID::kCenter>(stream)) {
      return CSSNumericLiteralValue::Create(
          50., CSSPrimitiveValue::UnitType::kPercentage);
    }
    return nullptr;
  }
  CSSPrimitiveValue* result =
      ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!result) {
    result =
        ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  }
  return result;
}

// Used to parse colors for -webkit-gradient(...).
static CSSValue* ConsumeDeprecatedGradientStopColor(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kCurrentcolor) {
    return nullptr;
  }
  return ConsumeColor(stream, context);
}

static bool ConsumeDeprecatedGradientColorStop(
    CSSParserTokenStream& stream,
    cssvalue::CSSGradientColorStop& stop,
    const CSSParserContext& context) {
  CSSValueID id = stream.Peek().FunctionId();
  if (id != CSSValueID::kFrom && id != CSSValueID::kTo &&
      id != CSSValueID::kColorStop) {
    return false;
  }

  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (id == CSSValueID::kFrom || id == CSSValueID::kTo) {
      double position = (id == CSSValueID::kFrom) ? 0 : 1;
      stop.offset_ = CSSNumericLiteralValue::Create(
          position, CSSPrimitiveValue::UnitType::kNumber);
    } else {
      DCHECK(id == CSSValueID::kColorStop);
      stop.offset_ = ConsumeNumberOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kAll);
      if (!stop.offset_) {
        return false;
      }
      if (!ConsumeCommaIncludingWhitespace(stream)) {
        return false;
      }
    }

    stop.color_ = ConsumeDeprecatedGradientStopColor(stream, context);
    if (!stream.AtEnd()) {
      return false;
    }
  }
  stream.ConsumeWhitespace();
  return stop.color_;
}

static CSSValue* ConsumeDeprecatedGradient(CSSParserTokenStream& stream,
                                           const CSSParserContext& context) {
  CSSValueID id = stream.Peek().Id();
  if (id != CSSValueID::kRadial && id != CSSValueID::kLinear) {
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();  // id

  if (!ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  const CSSPrimitiveValue* first_x =
      ConsumeDeprecatedGradientPoint(stream, context, true);
  if (!first_x) {
    return nullptr;
  }
  const CSSPrimitiveValue* first_y =
      ConsumeDeprecatedGradientPoint(stream, context, false);
  if (!first_y) {
    return nullptr;
  }
  if (!ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  // For radial gradients only, we now expect a numeric radius.
  const CSSPrimitiveValue* first_radius = nullptr;
  if (id == CSSValueID::kRadial) {
    first_radius = ConsumeNumber(stream, context,
                                 CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!first_radius || !ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }
  }

  const CSSPrimitiveValue* second_x =
      ConsumeDeprecatedGradientPoint(stream, context, true);
  if (!second_x) {
    return nullptr;
  }
  const CSSPrimitiveValue* second_y =
      ConsumeDeprecatedGradientPoint(stream, context, false);
  if (!second_y) {
    return nullptr;
  }

  // For radial gradients only, we now expect the second radius.
  const CSSPrimitiveValue* second_radius = nullptr;
  if (id == CSSValueID::kRadial) {
    if (!ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }
    second_radius = ConsumeNumber(stream, context,
                                  CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!second_radius) {
      return nullptr;
    }
  }

  cssvalue::CSSGradientValue* result;
  if (id == CSSValueID::kRadial) {
    result = MakeGarbageCollected<cssvalue::CSSRadialGradientValue>(
        first_x, first_y, first_radius, second_x, second_y, second_radius,
        cssvalue::kNonRepeating, cssvalue::kCSSDeprecatedRadialGradient);
  } else {
    result = MakeGarbageCollected<cssvalue::CSSLinearGradientValue>(
        first_x, first_y, second_x, second_y, nullptr, cssvalue::kNonRepeating,
        cssvalue::kCSSDeprecatedLinearGradient);
  }
  cssvalue::CSSGradientColorStop stop;
  while (ConsumeCommaIncludingWhitespace(stream)) {
    if (!ConsumeDeprecatedGradientColorStop(stream, stop, context)) {
      return nullptr;
    }
    result->AddStop(stop);
  }

  return result;
}

static CSSPrimitiveValue* ConsumeGradientAngleOrPercent(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    CSSPrimitiveValue::ValueRange value_range,
    UnitlessQuirk) {
  const CSSParserToken& token = stream.Peek();
  if (token.GetType() == kDimensionToken || token.GetType() == kNumberToken) {
    return ConsumeAngle(stream, context,
                        WebFeature::kUnitlessZeroAngleGradient);
  }
  if (token.GetType() == kPercentageToken) {
    return ConsumePercent(stream, context, value_range);
  }
  MathFunctionParser math_parser(stream, context, value_range);
  if (const CSSMathFunctionValue* calculation = math_parser.Value()) {
    CalculationResultCategory category = calculation->Category();
    // TODO(fs): Add and support kCalcPercentAngle?
    if (category == kCalcAngle || category == kCalcPercent) {
      return math_parser.ConsumeValue();
    }
  }
  return nullptr;
}

using PositionFunctor = CSSPrimitiveValue* (*)(CSSParserTokenStream&,
                                               const CSSParserContext&,
                                               CSSPrimitiveValue::ValueRange,
                                               UnitlessQuirk);

static bool ConsumeGradientColorStops(CSSParserTokenStream& stream,
                                      const CSSParserContext& context,
                                      cssvalue::CSSGradientValue* gradient,
                                      PositionFunctor consume_position_func) {
  bool supports_color_hints =
      gradient->GradientType() == cssvalue::kCSSLinearGradient ||
      gradient->GradientType() == cssvalue::kCSSRadialGradient ||
      gradient->GradientType() == cssvalue::kCSSConicGradient;

  // The first color stop cannot be a color hint.
  bool previous_stop_was_color_hint = true;
  do {
    cssvalue::CSSGradientColorStop stop;
    stop.color_ = ConsumeColor(stream, context);
    // Two hints in a row are not allowed.
    if (!stop.color_ &&
        (!supports_color_hints || previous_stop_was_color_hint)) {
      return false;
    }
    previous_stop_was_color_hint = !stop.color_;
    stop.offset_ = consume_position_func(stream, context,
                                         CSSPrimitiveValue::ValueRange::kAll,
                                         UnitlessQuirk::kForbid);
    if (!stop.color_ && !stop.offset_) {
      return false;
    }
    gradient->AddStop(stop);

    if (!stop.color_ || !stop.offset_) {
      continue;
    }

    // Optional second position.
    stop.offset_ = consume_position_func(stream, context,
                                         CSSPrimitiveValue::ValueRange::kAll,
                                         UnitlessQuirk::kForbid);
    if (stop.offset_) {
      gradient->AddStop(stop);
    }
  } while (ConsumeCommaIncludingWhitespace(stream));

  // The last color stop cannot be a color hint.
  if (previous_stop_was_color_hint) {
    return false;
  }

  // Must have 2 or more stops to be valid.
  return gradient->StopCount() >= 2;
}

static CSSValue* ConsumeDeprecatedRadialGradient(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    cssvalue::C
```