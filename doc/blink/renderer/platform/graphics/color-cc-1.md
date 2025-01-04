Response:
The user wants me to summarize the functionality of the provided C++ code snippet from the Chromium Blink engine. This snippet is part of the `color.cc` file and deals with color representation and manipulation.

Here's a breakdown of the functions and their purposes:

1. **Getter functions:** `Blue()`, `Rgb()`: These retrieve color components.
2. **Hex Color Parsing:** `ParseHexColor()`:  Functions to parse hexadecimal color strings.
3. **Color Difference:** `DifferenceSquared()`: Calculates the squared difference between two colors.
4. **Setting Color from String:** `SetFromString()`: Sets the color based on a string, handling both named colors and hex codes.
5. **Color Space Conversion:** `ColorSpaceToString()`: Converts a `ColorSpace` enum to its string representation.
6. **Parameter to String:** `ColorParamToString()`: Converts a color parameter (float) to its string representation, handling special cases like `NaN` and `Infinity`.
7. **Serialization:**
    - `SerializeAsCanvasColor()`: Serializes the color for canvas usage (hex or CSS format).
    - `SerializeLegacyColorAsCSSColor()`: Serializes legacy color spaces (rgb, hsl, hwb) to CSS color strings.
    - `SerializeInternal()`: Internal serialization logic for non-legacy color spaces.
    - `SerializeAsCSSColor()`:  Main function to serialize the color to a CSS color string.
    - `NameForLayoutTreeAsText()`:  Provides a text representation of the color for layout tree debugging.
8. **Named Color Handling:** `SetNamedColor()`: Sets the color based on a named color string.
9. **Color Manipulation:**
    - `Light()`: Returns a lighter version of the color.
    - `Dark()`: Returns a darker version of the color.
    - `Blend()`: Blends two colors.
    - `BlendWithWhite()`: Blends the color with white.
10. **Getting RGBA values:** `GetRGBA()`: Retrieves the red, green, blue, and alpha components as floats or doubles.
11. **HSL and HWB Conversion:**
    - `GetHueMaxMin()`: Helper for calculating hue, max, and min color components.
    - `GetHSL()`: Converts the color to HSL (Hue, Saturation, Lightness).
    - `GetHWB()`: Converts the color to HWB (Hue, Whiteness, Blackness).
12. **Premultiplied Alpha Handling:**
    - `ColorFromPremultipliedARGB()`: Creates a `Color` from a premultiplied ARGB value.
    - `PremultipliedARGBFromColor()`: Converts a `Color` to a premultiplied ARGB value.
13. **Color Interpolation:**
    - `GetColorInterpolationSpace()`: Determines the default color space for interpolation.
    - `SerializeInterpolationSpace()`: Serializes the color space and hue interpolation method to a string.
14. **Handling Non-Finite Values:** `ResolveNonFiniteValues()`:  Handles `NaN` and `Infinity` values in color components.
15. **Output Stream Operator:** `operator<<`: Enables printing `Color` objects to an output stream.

Now, let's structure the answer according to the prompt's requirements.
这是 `blink/renderer/platform/graphics/color.cc` 文件的第二部分，延续了第一部分关于颜色处理的功能。它主要负责颜色的各种操作、转换和序列化。以下是该部分功能的归纳：

**功能归纳:**

1. **颜色调整和混合:**
   - 提供 `Light()` 和 `Dark()` 方法来获取颜色的亮色和暗色版本。
   - `Blend()` 方法用于将当前颜色与另一个颜色进行混合，考虑了透明度。
   - `BlendWithWhite()` 方法用于将当前颜色与白色混合，主要用于处理不透明颜色并尝试找到一个与白色混合后视觉效果相同的半透明颜色。

2. **颜色空间转换和获取:**
   - `GetRGBA()` 方法用于获取颜色的 RGBA 值，支持 `float` 和 `double` 精度。
   - `GetHueMaxMin()` 是一个辅助方法，用于计算 HSL 和 HWB 颜色空间转换所需的中间值（色相、最大值、最小值）。
   - `GetHSL()` 方法用于将颜色转换为 HSL（色相、饱和度、亮度）颜色空间。
   - `GetHWB()` 方法用于将颜色转换为 HWB（色相、白度、黑度）颜色空间。

3. **预乘 Alpha 处理:**
   - `ColorFromPremultipliedARGB()` 函数用于从预乘的 ARGB 值创建 `Color` 对象。
   - `PremultipliedARGBFromColor()` 函数用于将 `Color` 对象转换为预乘的 ARGB 值。

4. **颜色插值:**
   - `GetColorInterpolationSpace()` 方法用于获取颜色插值时默认使用的颜色空间（对于传统 sRGB 格式为 sRGB，否则为 Oklab）。
   - `SerializeInterpolationSpace()` 函数用于将颜色空间和色相插值方法序列化为字符串。

5. **处理非有限值:**
   - `ResolveNonFiniteValues()` 方法用于处理颜色通道中的 `NaN` (非数字) 和 `Infinity` 值，将其替换为合适的边界值或 0。

6. **输出流支持:**
   - 重载了 `operator<<`，允许将 `Color` 对象直接输出到 `std::ostream`，输出格式为 CSS 颜色字符串。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS 颜色表示:**  这个文件处理的颜色概念直接对应于 CSS 中定义的颜色，例如：
    * **假设输入:**  在 CSS 中设置元素的背景颜色为 `#FF0000` (红色)。
    * **逻辑推理:** `ParseHexColor()` 函数会被调用来解析这个十六进制颜色字符串，并创建一个 `Color` 对象。
    * **输出:**  `Color` 对象的内部表示会存储红色的 RGB 值 (255, 0, 0)。
* **JavaScript 颜色操作:** JavaScript 可以通过 DOM API 操作元素的样式，其中包括颜色属性。
    * **假设输入:** JavaScript 代码设置 `element.style.backgroundColor = 'blue';`
    * **逻辑推理:**  Blink 引擎会接收到这个颜色字符串 `'blue'`，并调用 `SetFromString()`，最终调用 `SetNamedColor()` 来查找并设置蓝色对应的 RGB 值。
    * **输出:**  `Color` 对象会被设置为蓝色的 RGB 值。
* **HTML Canvas 绘图:** HTML `<canvas>` 元素允许使用 JavaScript 进行像素级别的绘图，颜色是核心概念。
    * **假设输入:** JavaScript 代码使用 Canvas API 设置填充颜色 `ctx.fillStyle = 'rgba(0, 255, 0, 0.5)';` (半透明绿色)。
    * **逻辑推理:**  Blink 引擎会解析这个 `rgba()` 字符串，调用相应的解析逻辑（虽然这段代码中没有直接展示 `rgba` 解析，但在 `SerializeLegacyColorAsCSSColor` 中可以看到其序列化的逻辑），创建一个表示半透明绿色的 `Color` 对象。
    * **输出:**  `Color` 对象存储绿色的 RGB 值和 alpha 值。
* **CSS 颜色函数:**  CSS 提供了诸如 `hsl()`, `hwb()` 等颜色函数。
    * **假设输入:** CSS 样式为 `color: hsl(120, 100%, 50%);` (绿色)。
    * **逻辑推理:**  Blink 引擎在解析 CSS 时，会调用相应的逻辑（可能在其他文件中，但 `GetHSL()` 函数在这里定义）将 HSL 值转换为 RGB 值并存储在 `Color` 对象中。
    * **输出:**  `Color` 对象被设置为绿色的 RGB 值。

**用户或编程常见的使用错误举例说明:**

* **十六进制颜色格式错误:**
    * **假设输入:**  用户在 CSS 或 JavaScript 中输入了错误的十六进制颜色码，例如 `#GGG` 或 `#12345`。
    * **逻辑推理:**  `ParseHexColor()` 函数会返回 `false`，表明解析失败。
    * **输出:**  该元素的颜色可能不会被设置，或者会使用默认颜色。
* **颜色名称拼写错误:**
    * **假设输入:** 用户在 CSS 或 JavaScript 中使用了拼写错误的颜色名称，例如 `blu` 而不是 `blue`。
    * **逻辑推理:** `SetNamedColor()` 函数在 `FindNamedColor()` 中找不到匹配的颜色，会返回 `false`。
    * **输出:**  该元素的颜色可能不会被设置，或者会使用默认颜色。
* **`Blend()` 函数的透明度理解错误:**
    * **假设输入:** 开发者期望使用 `Blend()` 函数将一个不透明的红色和一个半透明的蓝色进行混合，但错误地认为结果会是纯粹的叠加。
    * **逻辑推理:** `Blend()` 函数的实现会根据两个颜色的 alpha 值进行加权混合。
    * **输出:** 混合后的颜色会是介于红色和蓝色之间的颜色，并具有一定的透明度，而不是简单地显示在顶部的蓝色。
* **颜色空间不一致时的插值问题:**
    * **假设输入:**  开发者尝试在两个不同颜色空间（例如 sRGB 和 Display P3）的颜色之间进行动画过渡。
    * **逻辑推理:**  `GetColorInterpolationSpace()` 会根据颜色的类型选择合适的插值空间。如果浏览器选择在 Oklab 中插值，结果可能与在 sRGB 中插值略有不同。
    * **输出:**  动画过渡的中间颜色可能会与开发者预期的有所差异，尤其是在处理广色域颜色时。

总而言之，这段代码是 Chromium Blink 引擎中处理颜色表示、转换和操作的核心部分，它直接服务于 CSS 样式解析、JavaScript 颜色操作以及 HTML Canvas 的绘图功能。它确保了颜色在不同场景下的一致性和正确处理。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/color.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
nt Color::Blue() const {
  return BlueChannel(Rgb());
}

RGBA32 Color::Rgb() const {
  return toSkColor4f().toSkColor();
}

bool Color::ParseHexColor(base::span<const LChar> name, Color& color) {
  return ParseHexColorInternal(name, color);
}

bool Color::ParseHexColor(base::span<const UChar> name, Color& color) {
  return ParseHexColorInternal(name, color);
}

bool Color::ParseHexColor(const StringView& name, Color& color) {
  if (name.empty())
    return false;
  return VisitCharacters(name, [&color](auto chars) {
    return ParseHexColorInternal(chars, color);
  });
}

int DifferenceSquared(const Color& c1, const Color& c2) {
  int d_r = c1.Red() - c2.Red();
  int d_g = c1.Green() - c2.Green();
  int d_b = c1.Blue() - c2.Blue();
  return d_r * d_r + d_g * d_g + d_b * d_b;
}

bool Color::SetFromString(const String& name) {
  // TODO(https://crbug.com/1434423): Implement CSS Color level 4 parsing.
  if (name[0] != '#')
    return SetNamedColor(name);
  return VisitCharacters(name, [this](auto chars) {
    return ParseHexColorInternal(chars.template subspan<1>(), *this);
  });
}

// static
String Color::ColorSpaceToString(Color::ColorSpace color_space) {
  switch (color_space) {
    case Color::ColorSpace::kSRGB:
      return "srgb";
    case Color::ColorSpace::kSRGBLinear:
      return "srgb-linear";
    case Color::ColorSpace::kDisplayP3:
      return "display-p3";
    case Color::ColorSpace::kA98RGB:
      return "a98-rgb";
    case Color::ColorSpace::kProPhotoRGB:
      return "prophoto-rgb";
    case Color::ColorSpace::kRec2020:
      return "rec2020";
    case Color::ColorSpace::kXYZD50:
      return "xyz-d50";
    case Color::ColorSpace::kXYZD65:
      return "xyz-d65";
    case Color::ColorSpace::kLab:
      return "lab";
    case Color::ColorSpace::kOklab:
      return "oklab";
    case Color::ColorSpace::kLch:
      return "lch";
    case Color::ColorSpace::kOklch:
      return "oklch";
    case Color::ColorSpace::kSRGBLegacy:
      return "rgb";
    case Color::ColorSpace::kHSL:
      return "hsl";
    case Color::ColorSpace::kHWB:
      return "hwb";
    case ColorSpace::kNone:
      NOTREACHED();
  }
}

static String ColorParamToString(float param, int precision = 6) {
  StringBuilder result;
  if (!isfinite(param)) {
    // https://www.w3.org/TR/css-values-4/#calc-serialize
    result.Append("calc(");
    if (isinf(param)) {
      // "Infinity" gets capitalized, so we can't use AppendNumber().
      (param < 0) ? result.Append("-infinity") : result.Append("infinity");
    } else {
      result.AppendNumber(param, precision);
    }
    result.Append(")");
    return result.ToString();
  }

  result.AppendNumber(param, precision);
  return result.ToString();
}

String Color::SerializeAsCanvasColor() const {
  if (IsOpaque() && IsLegacyColorSpace(color_space_)) {
    return String::Format("#%02x%02x%02x", Red(), Green(), Blue());
  }

  return SerializeAsCSSColor();
}

String Color::SerializeLegacyColorAsCSSColor() const {
  StringBuilder result;
  if (IsOpaque() && isfinite(alpha_)) {
    result.Append("rgb(");
  } else {
    result.Append("rgba(");
  }

  constexpr float kEpsilon = 1e-07;
  auto [r, g, b] = std::make_tuple(param0_, param1_, param2_);
  if (color_space_ == Color::ColorSpace::kHWB ||
      color_space_ == Color::ColorSpace::kHSL) {
    // hsl and hwb colors need to be serialized in srgb.
    if (color_space_ == Color::ColorSpace::kHSL) {
      std::tie(r, g, b) = gfx::HSLToSRGB(param0_, param1_, param2_);
    } else if (color_space_ == Color::ColorSpace::kHWB) {
      std::tie(r, g, b) = gfx::HWBToSRGB(param0_, param1_, param2_);
    }
    // Legacy color channels get serialized with integers in the range [0,255].
    // Channels that have a value of exactly 0.5 can get incorrectly rounded
    // down to 127 when being converted to an integer. Add a small epsilon to
    // avoid this. See crbug.com/1425856.
    std::tie(r, g, b) =
        gfx::SRGBToSRGBLegacy(r + kEpsilon, g + kEpsilon, b + kEpsilon);
  }

  result.AppendNumber(round(ClampTo(r, 0.0, 255.0)));
  result.Append(", ");
  result.AppendNumber(round(ClampTo(g, 0.0, 255.0)));
  result.Append(", ");
  result.AppendNumber(round(ClampTo(b, 0.0, 255.0)));

  if (!IsOpaque()) {
    result.Append(", ");

    // See <alphavalue> section in
    // https://www.w3.org/TR/cssom/#serializing-css-values
    // First we need an 8-bit integer alpha to begin the algorithm described in
    // the link above.
    int int_alpha = ClampTo(round((alpha_ + kEpsilon) * 255.0), 0.0, 255.0);

    // If there exists a two decimal float in [0,1] that is exactly equal to the
    // integer we calculated above, used that.
    float two_decimal_rounded_alpha = round(int_alpha * 100.0 / 255.0) / 100.0;
    if (round(two_decimal_rounded_alpha * 255) == int_alpha) {
      result.Append(ColorParamToString(two_decimal_rounded_alpha, 2));
    } else {
      // Otherwise, round to 3 decimals.
      float three_decimal_rounded_alpha =
          round(int_alpha * 1000.0 / 255.0) / 1000.0;
      result.Append(ColorParamToString(three_decimal_rounded_alpha, 3));
    }
  }

  result.Append(')');
  return result.ToString();
}

String Color::SerializeInternal() const {
  StringBuilder result;
  if (IsLightnessFirstComponent(color_space_)) {
    result.Append(ColorSpaceToString(color_space_));
    result.Append("(");
  } else {
    result.Append("color(");
    result.Append(ColorSpaceToString(color_space_));
    result.Append(" ");
  }

  param0_is_none_ ? result.Append("none")
                  : result.Append(ColorParamToString(param0_));
  result.Append(" ");
  param1_is_none_ ? result.Append("none")
                  : result.Append(ColorParamToString(param1_));
  result.Append(" ");
  param2_is_none_ ? result.Append("none")
                  : result.Append(ColorParamToString(param2_));

  if (alpha_ != 1.0 || alpha_is_none_) {
    result.Append(" / ");
    alpha_is_none_ ? result.Append("none") : result.AppendNumber(alpha_);
  }
  result.Append(")");
  return result.ToString();
}

String Color::SerializeAsCSSColor() const {
  if (IsLegacyColorSpace(color_space_)) {
    return SerializeLegacyColorAsCSSColor();
  }

  return SerializeInternal();
}

String Color::NameForLayoutTreeAsText() const {
  if (!IsLegacyColorSpace(color_space_)) {
    return SerializeAsCSSColor();
  }

  if (!IsOpaque()) {
    return String::Format("#%02X%02X%02X%02X", Red(), Green(), Blue(),
                          AlphaAsInteger());
  }

  return String::Format("#%02X%02X%02X", Red(), Green(), Blue());
}

bool Color::SetNamedColor(const String& name) {
  const NamedColor* found_color = FindNamedColor(name);
  *this =
      found_color ? Color::FromRGBA32(found_color->argb_value) : kTransparent;
  return found_color;
}

Color Color::Light() const {
  // Hardcode this common case for speed.
  if (*this == kBlack) {
    return Color(kLightenedBlack);
  }

  const float scale_factor = nextafterf(256.0f, 0.0f);

  float r, g, b, a;
  GetRGBA(r, g, b, a);

  float v = std::max(r, std::max(g, b));

  if (v == 0.0f) {
    // Lightened black with alpha.
    return Color(RedChannel(kLightenedBlack), GreenChannel(kLightenedBlack),
                 BlueChannel(kLightenedBlack), AlphaAsInteger());
  }

  float multiplier = std::min(1.0f, v + 0.33f) / v;

  return Color(static_cast<int>(multiplier * r * scale_factor),
               static_cast<int>(multiplier * g * scale_factor),
               static_cast<int>(multiplier * b * scale_factor),
               AlphaAsInteger());
}

Color Color::Dark() const {
  // Hardcode this common case for speed.
  if (*this == kWhite)
    return Color(kDarkenedWhite);

  const float scale_factor = nextafterf(256.0f, 0.0f);

  float r, g, b, a;
  GetRGBA(r, g, b, a);

  float v = std::max(r, std::max(g, b));
  float multiplier = (v == 0.0f) ? 0.0f : std::max(0.0f, (v - 0.33f) / v);

  return Color(static_cast<int>(multiplier * r * scale_factor),
               static_cast<int>(multiplier * g * scale_factor),
               static_cast<int>(multiplier * b * scale_factor),
               AlphaAsInteger());
}

Color Color::Blend(const Color& source) const {
  // TODO(https://crbug.com/1434423): CSS Color level 4 blending is implemented.
  // Remove this function.
  if (IsFullyTransparent() || source.IsOpaque()) {
    return source;
  }

  if (source.IsFullyTransparent()) {
    return *this;
  }

  int source_alpha = source.AlphaAsInteger();
  int alpha = AlphaAsInteger();

  int d = 255 * (alpha + source_alpha) - alpha * source_alpha;
  int a = d / 255;
  int r = (Red() * alpha * (255 - source_alpha) +
           255 * source_alpha * source.Red()) /
          d;
  int g = (Green() * alpha * (255 - source_alpha) +
           255 * source_alpha * source.Green()) /
          d;
  int b = (Blue() * alpha * (255 - source_alpha) +
           255 * source_alpha * source.Blue()) /
          d;
  return Color(r, g, b, a);
}

Color Color::BlendWithWhite() const {
  // If the color contains alpha already, we leave it alone.
  if (!IsOpaque()) {
    return *this;
  }

  Color new_color;
  for (int alpha = kCStartAlpha; alpha <= kCEndAlpha;
       alpha += kCAlphaIncrement) {
    // We have a solid color.  Convert to an equivalent color that looks the
    // same when blended with white at the current alpha.  Try using less
    // transparency if the numbers end up being negative.
    int r = BlendComponent(Red(), alpha);
    int g = BlendComponent(Green(), alpha);
    int b = BlendComponent(Blue(), alpha);

    new_color = Color(r, g, b, alpha);

    if (r >= 0 && g >= 0 && b >= 0)
      break;
  }
  return new_color;
}

void Color::GetRGBA(float& r, float& g, float& b, float& a) const {
  // TODO(crbug.com/1399566): Check for colorspace.
  r = Red() / 255.0f;
  g = Green() / 255.0f;
  b = Blue() / 255.0f;
  a = Alpha();
}

void Color::GetRGBA(double& r, double& g, double& b, double& a) const {
  // TODO(crbug.com/1399566): Check for colorspace.
  r = Red() / 255.0;
  g = Green() / 255.0;
  b = Blue() / 255.0;
  a = Alpha();
}

// Hue, max and min are returned in range of 0.0 to 1.0.
void Color::GetHueMaxMin(double& hue, double& max, double& min) const {
  // This is a helper function to calculate intermediate quantities needed
  // for conversion to HSL or HWB formats. The algorithm contained below
  // is a copy of http://en.wikipedia.org/wiki/HSL_color_space.
  double r = static_cast<double>(Red()) / 255.0;
  double g = static_cast<double>(Green()) / 255.0;
  double b = static_cast<double>(Blue()) / 255.0;
  max = std::max(std::max(r, g), b);
  min = std::min(std::min(r, g), b);

  if (max == min)
    hue = 0.0;
  else if (max == r)
    hue = (60.0 * ((g - b) / (max - min))) + 360.0;
  else if (max == g)
    hue = (60.0 * ((b - r) / (max - min))) + 120.0;
  else
    hue = (60.0 * ((r - g) / (max - min))) + 240.0;

  // Adjust for rounding errors and scale to interval 0.0 to 1.0.
  if (hue >= 360.0)
    hue -= 360.0;
  hue /= 360.0;
}

// Hue, saturation and lightness are returned in range of 0.0 to 1.0.
void Color::GetHSL(double& hue, double& saturation, double& lightness) const {
  double max, min;
  GetHueMaxMin(hue, max, min);

  lightness = 0.5 * (max + min);
  if (max == min)
    saturation = 0.0;
  else if (lightness <= 0.5)
    saturation = ((max - min) / (max + min));
  else
    saturation = ((max - min) / (2.0 - (max + min)));
}

// Output parameters hue, white and black are in the range 0.0 to 1.0.
void Color::GetHWB(double& hue, double& white, double& black) const {
  // https://www.w3.org/TR/css-color-4/#the-hwb-notation. This is an
  // implementation of the algorithm to transform sRGB to HWB.
  double max;
  GetHueMaxMin(hue, max, white);
  black = 1.0 - max;
}

Color ColorFromPremultipliedARGB(RGBA32 pixel_color) {
  int alpha = AlphaChannel(pixel_color);
  if (alpha && alpha < 255) {
    return Color::FromRGBA(RedChannel(pixel_color) * 255 / alpha,
                           GreenChannel(pixel_color) * 255 / alpha,
                           BlueChannel(pixel_color) * 255 / alpha, alpha);
  } else {
    return Color::FromRGBA32(pixel_color);
  }
}

RGBA32 PremultipliedARGBFromColor(const Color& color) {
  unsigned pixel_color;

  unsigned alpha = color.AlphaAsInteger();
  if (alpha < 255) {
    pixel_color = Color::FromRGBA((color.Red() * alpha + 254) / 255,
                                  (color.Green() * alpha + 254) / 255,
                                  (color.Blue() * alpha + 254) / 255, alpha)
                      .Rgb();
  } else {
    pixel_color = color.Rgb();
  }

  return pixel_color;
}

// From https://www.w3.org/TR/css-color-4/#interpolation
// If the host syntax does not define what color space interpolation should
// take place in, it defaults to Oklab.
// However, user agents may handle interpolation between legacy sRGB color
// formats (hex colors, named colors, rgb(), hsl() or hwb() and the equivalent
// alpha-including forms) in gamma-encoded sRGB space.
Color::ColorSpace Color::GetColorInterpolationSpace() const {
  if (IsLegacyColorSpace(color_space_)) {
    return ColorSpace::kSRGBLegacy;
  }

  return ColorSpace::kOklab;
}

// static
String Color::SerializeInterpolationSpace(
    Color::ColorSpace color_space,
    Color::HueInterpolationMethod hue_interpolation_method) {
  StringBuilder result;
  switch (color_space) {
    case Color::ColorSpace::kLab:
      result.Append("lab");
      break;
    case Color::ColorSpace::kOklab:
      result.Append("oklab");
      break;
    case Color::ColorSpace::kLch:
      result.Append("lch");
      break;
    case Color::ColorSpace::kOklch:
      result.Append("oklch");
      break;
    case Color::ColorSpace::kSRGBLinear:
      result.Append("srgb-linear");
      break;
    case Color::ColorSpace::kSRGB:
    case Color::ColorSpace::kSRGBLegacy:
      result.Append("srgb");
      break;
    case Color::ColorSpace::kXYZD65:
      result.Append("xyz-d65");
      break;
    case Color::ColorSpace::kXYZD50:
      result.Append("xyz-d50");
      break;
    case Color::ColorSpace::kHSL:
      result.Append("hsl");
      break;
    case Color::ColorSpace::kHWB:
      result.Append("hwb");
      break;
    case Color::ColorSpace::kNone:
      result.Append("none");
      break;
    case ColorSpace::kDisplayP3:
      result.Append("display-p3");
      break;
    case ColorSpace::kA98RGB:
      result.Append("a98-rgb");
      break;
    case ColorSpace::kProPhotoRGB:
      result.Append("prophoto-rgb");
      break;
    case ColorSpace::kRec2020:
      result.Append("rec2020");
      break;
  }

  if (ColorSpaceHasHue(color_space)) {
    switch (hue_interpolation_method) {
      case Color::HueInterpolationMethod::kDecreasing:
        result.Append(" decreasing hue");
        break;
      case Color::HueInterpolationMethod::kIncreasing:
        result.Append(" increasing hue");
        break;
      case Color::HueInterpolationMethod::kLonger:
        result.Append(" longer hue");
        break;
      // Shorter is the default value and does not get serialized
      case Color::HueInterpolationMethod::kShorter:
        break;
    }
  }

  return result.ReleaseString();
}

static float ResolveNonFiniteChannel(float value,
                                     float negative_infinity_substitution,
                                     float positive_infinity_substitution) {
  // Finite values should be unchanged, even if they are out-of-gamut.
  if (isfinite(value)) {
    return value;
  } else {
    if (isnan(value)) {
      return 0.0f;
    } else {
      if (value < 0) {
        return negative_infinity_substitution;
      }
      return positive_infinity_substitution;
    }
  }
}

void Color::ResolveNonFiniteValues() {
  // calc(NaN) and calc(Infinity) need to be serialized for colors at parse
  // time, but eventually their true values need to be computed. calc(NaN) will
  // always become zero and +/-infinity become the upper/lower bound of the
  // channel, respectively, if it exists.
  // Crucially, this function does not clamp channels that are finite, this is
  // to allow for things like blending out-of-gamut colors.
  // See: https://github.com/w3c/csswg-drafts/issues/8629

  // Lightness is clamped to [0, 100].
  if (IsLightnessFirstComponent(color_space_)) {
    param0_ = ResolveNonFiniteChannel(param0_, 0.0f, 100.0f);
  }

  // Chroma cannot be negative.
  if (IsChromaSecondComponent(color_space_) && isinf(param1_) &&
      param1_ < 0.0f) {
    param1_ = 0.0f;
  }

  // Legacy sRGB does not respresent out-of-gamut colors.
  if (color_space_ == Color::ColorSpace::kSRGBLegacy) {
    param0_ = ResolveNonFiniteChannel(param0_, 0.0f, 1.0f);
    param1_ = ResolveNonFiniteChannel(param1_, 0.0f, 1.0f);
    param2_ = ResolveNonFiniteChannel(param2_, 0.0f, 1.0f);
  }

  // Parsed values are `calc(NaN)` but computed values are 0 for NaN.
  param0_ = isnan(param0_) ? 0.0f : param0_;
  param1_ = isnan(param1_) ? 0.0f : param1_;
  param2_ = isnan(param2_) ? 0.0f : param2_;
  alpha_ = ResolveNonFiniteChannel(alpha_, 0.0f, 1.0f);
}

std::ostream& operator<<(std::ostream& os, const Color& color) {
  return os << color.SerializeAsCSSColor();
}

}  // namespace blink

"""


```