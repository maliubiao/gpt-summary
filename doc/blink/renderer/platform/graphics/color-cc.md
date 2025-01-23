Response:
The user wants to understand the functionality of the `color.cc` file in the Chromium Blink rendering engine. I need to:

1. **Identify the core purpose:** This file likely deals with color representation and manipulation within the rendering engine.
2. **Extract specific functionalities:** List the operations and data structures related to colors.
3. **Analyze relationships with web technologies:** Determine how the code interacts with JavaScript, HTML, and CSS color features.
4. **Provide illustrative examples:** Show how the code might work with hypothetical inputs and explain common usage errors.
5. **Summarize the key functions:** Condense the extracted information into a concise overview.

**Mental Sandbox:**

* **Color Representation:** The code defines a `Color` class. It likely stores color components (RGB, HSL, etc.) and potentially handles different color spaces. The constants `kBlack`, `kWhite`, etc., confirm basic color definitions.
* **Parsing:** The `ParseHexColorInternal` function suggests handling color values from strings, a common task in CSS parsing.
* **Conversion:** The numerous `From...` and `ConvertToColorSpace` methods indicate color space conversion functionalities. This is crucial for handling different color models supported by CSS.
* **Interpolation:** The `InterpolateColors` function hints at color blending and animation capabilities, relevant to CSS transitions and animations.
* **Skia Integration:** The inclusion of `skia/include/core/SkColor.h` and methods like `toSkColor4f()` shows interaction with the Skia graphics library, which Blink uses for rendering.
* **Relationship to Web:**  CSS color properties directly map to the functionalities in this file. JavaScript can manipulate styles, thus indirectly using this code. HTML defines elements that get styled with colors.

**Constraint Checklist & Confidence Score:**

1. List its functions? Yes.
2. Relationship with JS/HTML/CSS? Yes.
3. Examples for JS/HTML/CSS? Yes.
4. Logical inference with input/output? Yes.
5. Common usage errors? Yes.
6. Summarize its functionality? Yes.

Confidence Score: 5/5

**Potential Challenges:**

* **Deep Dive vs. High-Level Overview:** The request asks for a listing of *functions*, but also a higher-level understanding of the file's purpose. I need to balance these.
* **Inferring User Errors:** I'll need to think about common mistakes developers make when working with colors in web development (e.g., invalid hex codes, out-of-range values).

**Key Learnings from Sandboxing:**

* Focus on the key functionalities like parsing, conversion, interpolation, and representation.
* Clearly link these functionalities to specific aspects of CSS, HTML, and JavaScript.
* Use simple, illustrative examples for input/output and user errors.

Strategizing complete. I will now proceed with generating the response based on these insights.
## blink/renderer/platform/graphics/color.cc 文件功能分析 (第 1 部分)

此文件 `blink/renderer/platform/graphics/color.cc` 是 Chromium Blink 渲染引擎中负责颜色表示和操作的核心组件。 它定义了 `Color` 类，并提供了多种处理颜色的方法，包括颜色空间的转换、解析、混合以及与底层图形库 Skia 的集成。

**主要功能归纳:**

1. **颜色表示:** 定义了 `Color` 类，用于在 Blink 引擎中表示颜色。 这个类能够存储和操作不同颜色模型的数据，例如 RGB、HSL、HWB、Lab、Lch、Oklab、Oklch 以及各种 RGB 颜色空间（sRGB, Display P3 等）。
2. **预定义颜色常量:**  定义了一些常用的颜色常量，例如 `kBlack`, `kWhite`, `kTransparent` 等，方便代码中使用。
3. **颜色解析:**  提供了从不同格式的字符串解析颜色值的功能，例如：
    * **十六进制颜色码:**  `ParseHexColorInternal` 函数用于解析 `#RRGGBB`, `#RGBA`, `#RGB`, `#RRGGBBAA` 等格式的十六进制颜色码。
    * **命名颜色:**  `FindNamedColor` 函数用于查找并解析 CSS 预定义的颜色名称（例如 "red", "blue"）。
4. **颜色空间转换:** 提供了在不同颜色空间之间转换颜色的功能。例如，可以将 sRGB 颜色转换为 Lab 或 Lch 颜色空间，反之亦然。 这对于实现 CSS Color Module Level 4 中引入的现代颜色功能至关重要。
5. **颜色混合 (color-mix):**  实现了 `InterpolateColors` 函数，用于在不同的颜色空间中混合两个颜色，这对应于 CSS `color-mix()` 函数的功能。 它可以处理不同的色相插值方法 (`shorter`, `longer`, `increasing`, `decreasing`)。
6. **颜色参数处理:**  提供了处理颜色参数（例如 RGB 分量、HSL 分量等）的功能，包括 clamp 限制数值范围。 同时也处理了 `none` 值的特殊情况，在非插值场景下将其视为 0。
7. **与 Skia 的集成:**  提供了将 `Color` 对象转换为 Skia 图形库中 `SkColor4f` 对象的方法 (`toSkColor4f`, `ToGradientStopSkColor4f`)，以便在渲染过程中使用 Skia 进行实际的绘制。
8. **预乘和反预乘:**  提供了 `PremultiplyColor` 和 `UnpremultiplyColor` 方法，用于处理颜色分量的预乘，这在图形渲染中用于优化混合操作。
9. **哈希计算:** 提供了 `GetHash` 方法，用于计算 `Color` 对象的哈希值，方便在数据结构中进行比较和查找。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  `color.cc` 文件直接支持和实现了 CSS 中关于颜色的各种规范。
    * **颜色关键字:**  预定义的颜色常量（如 `kBlack`, `kWhite`）对应 CSS 中的颜色关键字。
    * **十六进制颜色码:** `ParseHexColorInternal` 用于解析 CSS 样式中使用的十六进制颜色码，例如 `background-color: #FF0000;`。
    * **RGB 和 RGBA:**  `Color::FromRGB` 和 `Color::FromRGBA` 等方法对应 CSS 中的 `rgb()` 和 `rgba()` 函数，例如 `color: rgb(255, 0, 0);` 或 `color: rgba(255, 0, 0, 0.5);`。
    * **HSL 和 HSLA:** `Color::FromHSLA` 对应 CSS 中的 `hsl()` 和 `hsla()` 函数，例如 `color: hsl(0, 100%, 50%);`。
    * **HWB:** `Color::FromHWBA` 对应 CSS 中的 `hwb()` 函数。
    * **颜色空间 (Color Spaces):**  `Color::FromColorSpace` 和 `ConvertToColorSpace` 支持 CSS Color Module Level 4 中引入的各种颜色空间，例如 `color(display-p3 1 0 0)` 或 `lab(50% 100 0)`。
    * **`color-mix()` 函数:** `InterpolateColors` 函数实现了 CSS 的 `color-mix()` 功能，例如 `background: color-mix(in lch, blue 40%, red);`。
* **HTML:** HTML 元素可以通过 CSS 样式属性来设置颜色，这些颜色值最终会通过 Blink 的 CSS 解析器传递到 `color.cc` 文件进行处理和表示。例如， `<div style="background-color: blue;"></div>` 中的 `blue` 会被解析并转换为 `Color` 对象。
* **JavaScript:** JavaScript 可以通过 DOM API 操作元素的样式，从而间接地使用到 `color.cc` 中的功能。
    * **修改样式:**  `element.style.backgroundColor = 'green';`  会触发 Blink 引擎解析 'green' 并创建相应的 `Color` 对象。
    * **获取计算样式:** `getComputedStyle(element).backgroundColor`  返回的颜色值，其内部表示形式就是 `Color` 对象，可能需要进行格式转换才能在 JavaScript 中使用。

**逻辑推理 (假设输入与输出):**

**假设输入 1 (十六进制颜色码解析):**
* **输入:** 字符串 `"#FF00AA"`
* **调用:** `ParseHexColorInternal(base::as_span("#FF00AA"), color)`
* **预期输出:**  `color` 对象被设置为红色分量为 255，绿色分量为 0，蓝色分量为 170，alpha 分量为 255 (不透明)。

**假设输入 2 (颜色混合):**
* **输入:**  `color1` 为红色 (sRGB: 1, 0, 0)， `color2` 为蓝色 (sRGB: 0, 0, 1)， `percentage` 为 0.5， `interpolation_space` 为 `ColorSpace::kSRGB`。
* **调用:** `Color::InterpolateColors(Color::ColorSpace::kSRGB, std::nullopt, color1, color2, 0.5f)`
* **预期输出:**  返回一个新的 `Color` 对象，其 sRGB 值为 (0.5, 0, 0.5)，表示紫色。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **无效的十六进制颜色码:**
   * **错误:**  传递给解析函数的字符串不是有效的十六进制颜色码，例如 `"#GGG"` 或 `"#12345"`。
   * **后果:** `ParseHexColorInternal` 返回 `false`，表示解析失败，可能导致样式没有被正确应用。
2. **颜色分量超出范围:**
   * **错误:**  尝试使用 `Color::FromRGB` 创建颜色时，传递超出 [0, 255] 范围的 RGB 分量值，例如 `Color::FromRGB(300, -10, 150)`。
   * **后果:**  `ClampInt255` 会将值限制在 [0, 255] 范围内，可能得到非预期的颜色。
3. **在不支持的上下文中使用了新的颜色空间语法:**
   * **错误:**  在旧版本的浏览器或不支持 CSS Color Module Level 4 的环境中使用了 `lab()` 或 `lch()` 等新的颜色函数。
   * **后果:**  浏览器可能无法解析这些颜色值，导致样式失效或使用默认颜色。
4. **颜色混合时使用了不合适的颜色空间:**
   * **错误:**  在感知均匀性很重要的场景下，例如创建平滑的颜色渐变，使用了非感知均匀的颜色空间（如 sRGB）进行混合。
   * **后果:**  可能导致渐变在视觉上不平滑，出现颜色跳跃。

**功能归纳 (第 1 部分):**

总而言之，`blink/renderer/platform/graphics/color.cc` 文件的主要功能是**提供 Blink 引擎中颜色的核心表示、解析、转换和操作能力**。 它负责处理来自 CSS 样式的各种颜色值，并将其转换为引擎内部可以理解和使用的格式，同时支持现代 CSS 颜色规范，并与 Skia 图形库集成以进行最终的渲染。

### 提示词
```
这是目录为blink/renderer/platform/graphics/color.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/graphics/color.h"

#include <math.h>

#include <array>
#include <optional>
#include <tuple>

#include "base/check_op.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/geometry/blend.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/color_conversions.h"

namespace blink {

const Color Color::kBlack = Color(0xFF000000);
const Color Color::kWhite = Color(0xFFFFFFFF);
const Color Color::kDarkGray = Color(0xFF808080);
const Color Color::kGray = Color(0xFFA0A0A0);
const Color Color::kLightGray = Color(0xFFC0C0C0);
const Color Color::kTransparent = Color(0x00000000);

namespace {

const RGBA32 kLightenedBlack = 0xFF545454;
const RGBA32 kDarkenedWhite = 0xFFABABAB;
// For lch/oklch colors, the value of chroma underneath which the color is
// considered to be "achromatic", relevant for color conversions.
// https://www.w3.org/TR/css-color-4/#lab-to-lch
const float kAchromaticChromaThreshold = 1e-6;

const int kCStartAlpha = 153;     // 60%
const int kCEndAlpha = 204;       // 80%;
const int kCAlphaIncrement = 17;  // Increments in between.

int BlendComponent(int c, int a) {
  // We use white.
  float alpha = a / 255.0f;
  int white_blend = 255 - a;
  c -= white_blend;
  return static_cast<int>(c / alpha);
}

// originally moved here from the CSS parser
template <typename CharacterType>
inline bool ParseHexColorInternal(base::span<const CharacterType> name,
                                  Color& color) {
  if (name.size() != 3 && name.size() != 4 && name.size() != 6 &&
      name.size() != 8) {
    return false;
  }
  if ((name.size() == 8 || name.size() == 4) &&
      !RuntimeEnabledFeatures::CSSHexAlphaColorEnabled()) {
    return false;
  }
  uint32_t value = 0;
  for (unsigned i = 0; i < name.size(); ++i) {
    if (!IsASCIIHexDigit(name[i]))
      return false;
    value <<= 4;
    value |= ToASCIIHexValue(name[i]);
  }
  if (name.size() == 6) {
    color = Color::FromRGBA32(0xFF000000 | value);
    return true;
  }
  if (name.size() == 8) {
    // We parsed the values into RGBA order, but the RGBA32 type
    // expects them to be in ARGB order, so we right rotate eight bits.
    color = Color::FromRGBA32(value << 24 | value >> 8);
    return true;
  }
  if (name.size() == 4) {
    // #abcd converts to ddaabbcc in RGBA32.
    color = Color::FromRGBA32((value & 0xF) << 28 | (value & 0xF) << 24 |
                              (value & 0xF000) << 8 | (value & 0xF000) << 4 |
                              (value & 0xF00) << 4 | (value & 0xF00) |
                              (value & 0xF0) | (value & 0xF0) >> 4);
    return true;
  }
  // #abc converts to #aabbcc
  color = Color::FromRGBA32(0xFF000000 | (value & 0xF00) << 12 |
                            (value & 0xF00) << 8 | (value & 0xF0) << 8 |
                            (value & 0xF0) << 4 | (value & 0xF) << 4 |
                            (value & 0xF));
  return true;
}

inline const NamedColor* FindNamedColor(const String& name) {
  std::array<char, 64> buffer;  // easily big enough for the longest color name
  wtf_size_t length = name.length();
  if (length > buffer.size() - 1) {
    return nullptr;
  }
  for (wtf_size_t i = 0; i < length; ++i) {
    const UChar c = name[i];
    if (!c || c > 0x7F)
      return nullptr;
    buffer[i] = ToASCIILower(static_cast<char>(c));
  }
  return FindColor(base::as_string_view(base::span(buffer).first(length)));
}

constexpr int RedChannel(RGBA32 color) {
  return (color >> 16) & 0xFF;
}

constexpr int GreenChannel(RGBA32 color) {
  return (color >> 8) & 0xFF;
}

constexpr int BlueChannel(RGBA32 color) {
  return color & 0xFF;
}

constexpr int AlphaChannel(RGBA32 color) {
  return (color >> 24) & 0xFF;
}

float AngleToUnitCircleDegrees(float angle) {
  return fmod(fmod(angle, 360.f) + 360.f, 360.f);
}
}  // namespace

// The color parameters will use 16 bytes (for 4 floats). Ensure that the
// remaining parameters fit into another 4 bytes (or 8 bytes, on Windows)
#if BUILDFLAG(IS_WIN)
static_assert(sizeof(Color) <= 24, "blink::Color should be <= 24 bytes.");
#else
static_assert(sizeof(Color) <= 20, "blink::Color should be <= 20 bytes.");
#endif

Color::Color(int r, int g, int b) {
  *this = FromRGB(r, g, b);
}

Color::Color(int r, int g, int b, int a) {
  *this = FromRGBA(r, g, b, a);
}

// static
Color Color::FromRGBALegacy(std::optional<int> r,
                            std::optional<int> g,
                            std::optional<int> b,
                            std::optional<int> a) {
  Color result = Color(
      ClampInt255(a.value_or(0.f)) << 24 | ClampInt255(r.value_or(0.f)) << 16 |
      ClampInt255(g.value_or(0.f)) << 8 | ClampInt255(b.value_or(0.f)));
  result.param0_is_none_ = !r;
  result.param1_is_none_ = !g;
  result.param2_is_none_ = !b;
  result.alpha_is_none_ = !a;
  result.color_space_ = ColorSpace::kSRGBLegacy;
  return result;
}

// static
Color Color::FromColorSpace(ColorSpace color_space,
                            std::optional<float> param0,
                            std::optional<float> param1,
                            std::optional<float> param2,
                            std::optional<float> alpha) {
  Color result;
  result.color_space_ = color_space;
  result.param0_is_none_ = !param0;
  result.param1_is_none_ = !param1;
  result.param2_is_none_ = !param2;
  result.alpha_is_none_ = !alpha;
  result.param0_ = param0.value_or(0.f);
  result.param1_ = param1.value_or(0.f);
  result.param2_ = param2.value_or(0.f);
  if (alpha) {
    // Alpha is clamped to the range [0,1], no matter what colorspace.
    result.alpha_ = ClampTo(alpha.value(), 0.f, 1.f);
  } else {
    result.alpha_ = 0.0f;
  }

  if (IsLightnessFirstComponent(color_space) && !isnan(result.param0_)) {
    // param0_ is lightness which cannot be negative or above 100%.
    // lab/lch have lightness in the range [0, 100].
    // oklab/okch have lightness in the range [0, 1].
    if (color_space == ColorSpace::kLab || color_space == ColorSpace::kLch) {
      result.param0_ = std::min(100.f, std::max(result.param0_, 0.f));
    } else {
      result.param0_ = std::min(1.f, std::max(result.param0_, 0.f));
    }
  }
  if (IsChromaSecondComponent(color_space)) {
    result.param1_ = std::max(result.param1_, 0.f);
  }

  return result;
}

// static
Color Color::FromHSLA(std::optional<float> h,
                      std::optional<float> s,
                      std::optional<float> l,
                      std::optional<float> a) {
  return FromColorSpace(ColorSpace::kHSL, h, s, l, a);
}

// static
Color Color::FromHWBA(std::optional<float> h,
                      std::optional<float> w,
                      std::optional<float> b,
                      std::optional<float> a) {
  return FromColorSpace(ColorSpace::kHWB, h, w, b, a);
}

// static
Color Color::FromColorMix(Color::ColorSpace interpolation_space,
                          std::optional<HueInterpolationMethod> hue_method,
                          Color color1,
                          Color color2,
                          float percentage,
                          float alpha_multiplier) {
  DCHECK(alpha_multiplier >= 0.0f && alpha_multiplier <= 1.0f);
  Color result = InterpolateColors(interpolation_space, hue_method, color1,
                                   color2, percentage);

  result.alpha_ *= alpha_multiplier;

  // Legacy colors that are the result of color-mix should serialize as
  // color(srgb ... ).
  // See: https://github.com/mozilla/wg-decisions/issues/1125
  if (result.IsLegacyColorSpace(result.color_space_)) {
    result.ConvertToColorSpace(Color::ColorSpace::kSRGB);
  }
  return result;
}

// static
float Color::HueInterpolation(float value1,
                              float value2,
                              float percentage,
                              Color::HueInterpolationMethod hue_method) {
  DCHECK(value1 >= 0.0f && value1 < 360.0f) << value1;
  DCHECK(value2 >= 0.0f && value2 < 360.0f) << value2;
  // Adapt values of angles if needed, depending on the hue_method.
  switch (hue_method) {
    case Color::HueInterpolationMethod::kShorter: {
      float diff = value2 - value1;
      if (diff > 180.0f) {
        value1 += 360.0f;
      } else if (diff < -180.0f) {
        value2 += 360.0f;
      }
      DCHECK(value2 - value1 >= -180.0f && value2 - value1 <= 180.0f);
    } break;
    case Color::HueInterpolationMethod::kLonger: {
      float diff = value2 - value1;
      if (diff > 0.0f && diff < 180.0f) {
        value1 += 360.0f;
      } else if (diff > -180.0f && diff <= 0.0f) {
        value2 += 360.0f;
      }
      DCHECK((value2 - value1 >= -360.0f && value2 - value1 <= -180.0f) ||
             (value2 - value1 >= 180.0f && value2 - value1 <= 360.0f))
          << value2 - value1;
    } break;
    case Color::HueInterpolationMethod::kIncreasing:
      if (value2 < value1)
        value2 += 360.0f;
      DCHECK(value2 - value1 >= 0.0f && value2 - value1 < 360.0f);
      break;
    case Color::HueInterpolationMethod::kDecreasing:
      if (value1 < value2)
        value1 += 360.0f;
      DCHECK(-360.0f < value2 - value1 && value2 - value1 <= 0.f);
      break;
  }
  return AngleToUnitCircleDegrees(blink::Blend(value1, value2, percentage));
}

namespace {}  // namespace

void Color::CarryForwardAnalogousMissingComponents(
    Color color,
    Color::ColorSpace prev_color_space) {
  auto HasRGBOrXYZComponents = [](Color::ColorSpace color_space) {
    return color_space == Color::ColorSpace::kSRGB ||
           color_space == Color::ColorSpace::kSRGBLinear ||
           color_space == Color::ColorSpace::kDisplayP3 ||
           color_space == Color::ColorSpace::kA98RGB ||
           color_space == Color::ColorSpace::kProPhotoRGB ||
           color_space == Color::ColorSpace::kRec2020 ||
           color_space == Color::ColorSpace::kXYZD50 ||
           color_space == Color::ColorSpace::kXYZD65 ||
           color_space == Color::ColorSpace::kSRGBLegacy;
  };

  const auto cur_color_space = color.GetColorSpace();
  if (cur_color_space == prev_color_space) {
    return;
  }
  if (HasRGBOrXYZComponents(cur_color_space) &&
      HasRGBOrXYZComponents(prev_color_space)) {
    return;
  }
  if (IsLightnessFirstComponent(cur_color_space) &&
      IsLightnessFirstComponent(prev_color_space)) {
    color.param1_is_none_ = false;
    color.param2_is_none_ = false;
    return;
  }
  if (IsLightnessFirstComponent(prev_color_space) &&
      cur_color_space == ColorSpace::kHSL) {
    color.param2_is_none_ = color.param0_is_none_;
    color.param0_is_none_ = false;
    if (prev_color_space != ColorSpace::kLch &&
        prev_color_space != ColorSpace::kOklch) {
      DCHECK(prev_color_space == ColorSpace::kLab ||
             prev_color_space == ColorSpace::kOklab);
      color.param1_is_none_ = false;
    }
    return;
  }
  // There are no analogous missing components.
  color.param0_is_none_ = false;
  color.param1_is_none_ = false;
  color.param2_is_none_ = false;
}

// static
bool Color::SubstituteMissingParameters(Color& color1, Color& color2) {
  if (color1.color_space_ != color2.color_space_) {
    return false;
  }

  if (color1.param0_is_none_ && !color2.param0_is_none_) {
    color1.param0_ = color2.param0_;
    color1.param0_is_none_ = false;
  } else if (color2.param0_is_none_ && !color1.param0_is_none_) {
    color2.param0_ = color1.param0_;
    color2.param0_is_none_ = false;
  }

  if (color1.param1_is_none_ && !color2.param1_is_none_) {
    color1.param1_ = color2.param1_;
    color1.param1_is_none_ = false;
  } else if (color2.param1_is_none_ && !color1.param1_is_none_) {
    color2.param1_ = color1.param1_;
    color2.param1_is_none_ = false;
  }

  if (color1.param2_is_none_ && !color2.param2_is_none_) {
    color1.param2_ = color2.param2_;
    color1.param2_is_none_ = false;
  } else if (color2.param2_is_none_ && !color1.param2_is_none_) {
    color2.param2_ = color1.param2_;
    color2.param2_is_none_ = false;
  }

  if (color1.alpha_is_none_ && !color2.alpha_is_none_) {
    color1.alpha_ = color2.alpha_;
    color1.alpha_is_none_ = false;
  } else if (color2.alpha_is_none_ && !color1.alpha_is_none_) {
    color2.alpha_ = color1.alpha_;
    color2.alpha_is_none_ = false;
  }

  return true;
}

// static
Color Color::InterpolateColors(Color::ColorSpace interpolation_space,
                               std::optional<HueInterpolationMethod> hue_method,
                               Color color1,
                               Color color2,
                               float percentage) {
  // https://www.w3.org/TR/css-color-4/#missing:
  // When interpolating colors, missing components do not behave as zero values
  // for color space conversions.
  const auto color1_prev_color_space = color1.GetColorSpace();
  color1.ConvertToColorSpace(interpolation_space,
                             false /* resolve_missing_components */);
  const auto color2_prev_color_space = color2.GetColorSpace();
  color2.ConvertToColorSpace(interpolation_space,
                             false /* resolve_missing_components */);

  CarryForwardAnalogousMissingComponents(color1, color1_prev_color_space);
  CarryForwardAnalogousMissingComponents(color2, color2_prev_color_space);

  if (!SubstituteMissingParameters(color1, color2)) {
    NOTREACHED();
  }

  float alpha1 = color1.PremultiplyColor();
  float alpha2 = color2.PremultiplyColor();

  if (!hue_method.has_value()) {
    // https://www.w3.org/TR/css-color-4/#hue-interpolation
    // Unless otherwise specified, if no specific hue interpolation algorithm
    // is selected by the host syntax, the default is shorter.
    hue_method = HueInterpolationMethod::kShorter;
  }

  std::optional<float> param0 =
      (color1.param0_is_none_ && color2.param0_is_none_)
          ? std::optional<float>(std::nullopt)
      : (interpolation_space == ColorSpace::kHSL ||
         interpolation_space == ColorSpace::kHWB)
          ? HueInterpolation(color1.param0_, color2.param0_, percentage,
                             hue_method.value())
          : blink::Blend(color1.param0_, color2.param0_, percentage);

  std::optional<float> param1 =
      (color1.param1_is_none_ && color2.param1_is_none_)
          ? std::optional<float>(std::nullopt)
          : blink::Blend(color1.param1_, color2.param1_, percentage);

  std::optional<float> param2 =
      (color1.param2_is_none_ && color2.param2_is_none_)
          ? std::optional<float>(std::nullopt)
      : (IsChromaSecondComponent(interpolation_space))
          ? HueInterpolation(color1.param2_, color2.param2_, percentage,
                             hue_method.value())
          : blink::Blend(color1.param2_, color2.param2_, percentage);

  std::optional<float> alpha = (color1.alpha_is_none_ && color2.alpha_is_none_)
                                   ? std::optional<float>(std::nullopt)
                                   : blink::Blend(alpha1, alpha2, percentage);

  Color result =
      FromColorSpace(interpolation_space, param0, param1, param2, alpha);

  result.UnpremultiplyColor();

  return result;
}

std::tuple<float, float, float> Color::ExportAsXYZD50Floats() const {
  switch (color_space_) {
    case ColorSpace::kSRGBLegacy: {
      auto [r, g, b] = gfx::SRGBLegacyToSRGB(param0_, param1_, param2_);
      return gfx::SRGBToXYZD50(r, g, b);
    }
    case ColorSpace::kSRGB:
      return gfx::SRGBToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kSRGBLinear:
      return gfx::SRGBLinearToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kDisplayP3:
      return gfx::DisplayP3ToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kA98RGB:
      return gfx::AdobeRGBToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kProPhotoRGB:
      return gfx::ProPhotoToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kRec2020:
      return gfx::Rec2020ToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kXYZD50:
      return {param0_, param1_, param2_};
    case ColorSpace::kXYZD65:
      return gfx::XYZD65ToD50(param0_, param1_, param2_);
    case ColorSpace::kLab:
      return gfx::LabToXYZD50(param0_, param1_, param2_);
    case ColorSpace::kOklab: {
      auto [x, y, z] = gfx::OklabToXYZD65(param0_, param1_, param2_);
      return gfx::XYZD65ToD50(x, y, z);
    }
    case ColorSpace::kLch: {
      auto [l, a, b] = gfx::LchToLab(param0_, param1_, param2_);
      return gfx::LabToXYZD50(l, a, b);
    }
    case ColorSpace::kOklch: {
      auto [l, a, b] = gfx::LchToLab(param0_, param1_, param2_);
      auto [x, y, z] = gfx::OklabToXYZD65(l, a, b);
      return gfx::XYZD65ToD50(x, y, z);
    }
    case ColorSpace::kHSL: {
      auto [r, g, b] = gfx::HSLToSRGB(param0_, param1_, param2_);
      return gfx::SRGBToXYZD50(r, g, b);
    }
    case ColorSpace::kHWB: {
      auto [r, g, b] = gfx::HWBToSRGB(param0_, param1_, param2_);
      return gfx::SRGBToXYZD50(r, g, b);
    }
    case ColorSpace::kNone:
      NOTREACHED();
  }
}

// https://www.w3.org/TR/css-color-4/#missing:
// "[Except for interpolations] a missing component behaves as a zero value, in
// the appropriate unit for that component: 0, 0%, or 0deg. This includes
// rendering the color directly, converting it to another color space,
// performing computations on the color component values, etc."
// So we simply turn "none"s into zeros here. Note that this does not happen for
// interpolations.
void Color::ResolveMissingComponents() {
  if (param0_is_none_) {
    param0_ = 0;
    param0_is_none_ = false;
  }
  if (param1_is_none_) {
    param1_ = 0;
    param1_is_none_ = false;
  }
  if (param2_is_none_) {
    param2_ = 0;
    param2_is_none_ = false;
  }
}

void Color::ConvertToColorSpace(ColorSpace destination_color_space,
                                bool resolve_missing_components) {
  if (color_space_ == destination_color_space) {
    return;
  }

  if (resolve_missing_components) {
    ResolveMissingComponents();
  }

  switch (destination_color_space) {
    case ColorSpace::kXYZD65: {
      if (color_space_ == ColorSpace::kOklab) {
        std::tie(param0_, param1_, param2_) =
            gfx::OklabToXYZD65(param0_, param1_, param2_);
      } else {
        auto [x, y, z] = ExportAsXYZD50Floats();
        std::tie(param0_, param1_, param2_) = gfx::XYZD50ToD65(x, y, z);
      }
      color_space_ = ColorSpace::kXYZD65;
      return;
    }
    case ColorSpace::kXYZD50: {
      std::tie(param0_, param1_, param2_) = ExportAsXYZD50Floats();
      color_space_ = ColorSpace::kXYZD50;
      return;
    }
    case ColorSpace::kSRGBLinear: {
      auto [x, y, z] = ExportAsXYZD50Floats();
      std::tie(param0_, param1_, param2_) = gfx::XYZD50TosRGBLinear(x, y, z);
      color_space_ = ColorSpace::kSRGBLinear;
      return;
    }
    case ColorSpace::kDisplayP3: {
      auto [x, y, z] = ExportAsXYZD50Floats();
      std::tie(param0_, param1_, param2_) = gfx::XYZD50ToDisplayP3(x, y, z);
      color_space_ = ColorSpace::kDisplayP3;
      return;
    }
    case ColorSpace::kA98RGB: {
      auto [x, y, z] = ExportAsXYZD50Floats();
      std::tie(param0_, param1_, param2_) = gfx::XYZD50ToAdobeRGB(x, y, z);
      color_space_ = ColorSpace::kA98RGB;
      return;
    }
    case ColorSpace::kProPhotoRGB: {
      auto [x, y, z] = ExportAsXYZD50Floats();
      std::tie(param0_, param1_, param2_) = gfx::XYZD50ToProPhoto(x, y, z);
      color_space_ = ColorSpace::kProPhotoRGB;
      return;
    }
    case ColorSpace::kRec2020: {
      auto [x, y, z] = ExportAsXYZD50Floats();
      std::tie(param0_, param1_, param2_) = gfx::XYZD50ToRec2020(x, y, z);
      color_space_ = ColorSpace::kRec2020;
      return;
    }
    case ColorSpace::kLab: {
      if (color_space_ == ColorSpace::kLch) {
        std::tie(param0_, param1_, param2_) =
            gfx::LchToLab(param0_, param1_, param2_);
      } else {
        auto [x, y, z] = ExportAsXYZD50Floats();
        std::tie(param0_, param1_, param2_) = gfx::XYZD50ToLab(x, y, z);
      }
      color_space_ = ColorSpace::kLab;
      return;
    }
    case ColorSpace::kOklab:
    // As per CSS Color 4 Spec, "If the host syntax does not define what color
    // space interpolation should take place in, it defaults to OKLab".
    // (https://www.w3.org/TR/css-color-4/#interpolation-space)
    case ColorSpace::kNone: {
      if (color_space_ == ColorSpace::kOklab) {
        return;
      }
      if (color_space_ == ColorSpace::kOklch) {
        std::tie(param0_, param1_, param2_) =
            gfx::LchToLab(param0_, param1_, param2_);
        color_space_ = ColorSpace::kOklab;
        return;
      }
      // Conversion to Oklab is done through XYZD65.
      auto [xd65, yd65, zd65] = [&]() {
        if (color_space_ == ColorSpace::kXYZD65) {
          return std::make_tuple(param0_, param1_, param2_);
        } else {
          auto [xd50, yd50, zd50] = ExportAsXYZD50Floats();
          return gfx::XYZD50ToD65(xd50, yd50, zd50);
        }
      }();

      std::tie(param0_, param1_, param2_) =
          gfx::XYZD65ToOklab(xd65, yd65, zd65);
      color_space_ = ColorSpace::kOklab;
      return;
    }
    case ColorSpace::kLch: {
      // Conversion to lch is done through lab.
      // https://www.w3.org/TR/css-color-4/#lab-to-lch
      auto [l, a, b] = [&]() {
        if (color_space_ == ColorSpace::kLab) {
          return std::make_tuple(param0_, param1_, param2_);
        } else {
          auto [xd50, yd50, zd50] = ExportAsXYZD50Floats();
          return gfx::XYZD50ToLab(xd50, yd50, zd50);
        }
      }();

      std::tie(param0_, param1_, param2_) = gfx::LabToLch(l, a, b);
      param2_ = AngleToUnitCircleDegrees(param2_);

      // Hue component is powerless for fully transparent or achromatic colors.
      if (IsFullyTransparent() || param1_ <= kAchromaticChromaThreshold) {
        param2_is_none_ = true;
      }

      color_space_ = ColorSpace::kLch;
      return;
    }
    case ColorSpace::kOklch: {
      if (color_space_ == ColorSpace::kOklab) {
        std::tie(param0_, param1_, param2_) =
            gfx::LabToLch(param0_, param1_, param2_);
      } else {
        // Conversion to Oklch is done through XYZD65.
        auto [xd65, yd65, zd65] = [&]() {
          if (color_space_ == ColorSpace::kXYZD65) {
            return std::make_tuple(param0_, param1_, param2_);
          } else {
            auto [xd50, yd50, zd50] = ExportAsXYZD50Floats();
            return gfx::XYZD50ToD65(xd50, yd50, zd50);
          }
        }();

        auto [l, a, b] = gfx::XYZD65ToOklab(xd65, yd65, zd65);
        std::tie(param0_, param1_, param2_) = gfx::LabToLch(l, a, b);
        param2_ = AngleToUnitCircleDegrees(param2_);
      }

      // Hue component is powerless for fully transparent or archromatic colors.
      if (IsFullyTransparent() || param1_ <= kAchromaticChromaThreshold) {
        param2_is_none_ = true;
      }

      color_space_ = ColorSpace::kOklch;
      return;
    }
    case ColorSpace::kSRGB:
    case ColorSpace::kSRGBLegacy: {
      if (color_space_ == ColorSpace::kHSL) {
        std::tie(param0_, param1_, param2_) =
            gfx::HSLToSRGB(param0_, param1_, param2_);
      } else if (color_space_ == ColorSpace::kHWB) {
        std::tie(param0_, param1_, param2_) =
            gfx::HWBToSRGB(param0_, param1_, param2_);
      } else if (color_space_ == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBLegacyToSRGB(param0_, param1_, param2_);
      } else if (color_space_ != ColorSpace::kSRGB) {
        // Don't go through the whole conversion to xyz for srgb to avoid
        // rounding issues.
        auto [x, y, z] = ExportAsXYZD50Floats();
        std::tie(param0_, param1_, param2_) = gfx::XYZD50TosRGB(x, y, z);
      }

      // All the above conversions result in non-legacy srgb.
      if (destination_color_space == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToSRGBLegacy(param0_, param1_, param2_);
      }

      color_space_ = destination_color_space;
      return;
    }
    case ColorSpace::kHSL: {
      if (color_space_ == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBLegacyToSRGB(param0_, param1_, param2_);
      }
      if (color_space_ == ColorSpace::kSRGB ||
          color_space_ == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHSL(param0_, param1_, param2_);
      } else if (color_space_ == ColorSpace::kHWB) {
        std::tie(param0_, param1_, param2_) =
            gfx::HWBToSRGB(param0_, param1_, param2_);
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHSL(param0_, param1_, param2_);
      } else {
        auto [x, y, z] = ExportAsXYZD50Floats();
        std::tie(param0_, param1_, param2_) = gfx::XYZD50TosRGB(x, y, z);
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHSL(param0_, param1_, param2_);
      }

      // Hue component is powerless for fully transparent or achromatic (s==0)
      // colors.
      if (IsFullyTransparent() || param1_ == 0) {
        param0_is_none_ = true;
      }

      color_space_ = ColorSpace::kHSL;
      return;
    }
    case ColorSpace::kHWB: {
      if (color_space_ == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBLegacyToSRGB(param0_, param1_, param2_);
      }
      if (color_space_ == ColorSpace::kSRGB ||
          color_space_ == ColorSpace::kSRGBLegacy) {
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHWB(param0_, param1_, param2_);
      } else if (color_space_ == ColorSpace::kHSL) {
        std::tie(param0_, param1_, param2_) =
            gfx::HSLToSRGB(param0_, param1_, param2_);
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHWB(param0_, param1_, param2_);
      } else {
        auto [x, y, z] = ExportAsXYZD50Floats();
        std::tie(param0_, param1_, param2_) = gfx::XYZD50TosRGB(x, y, z);
        std::tie(param0_, param1_, param2_) =
            gfx::SRGBToHWB(param0_, param1_, param2_);
      }

      // Hue component is powerless for fully transparent or achromatic colors.
      if (IsFullyTransparent() || param1_ + param2_ >= 1) {
        param0_is_none_ = true;
      }

      color_space_ = ColorSpace::kHWB;
      return;
    }
  }
}

SkColor4f Color::toSkColor4f() const {
  return ToSkColor4fInternal(IsBakedGamutMappingEnabled());
}

SkColor4f
Color::ToGradientStopSkColor4f(ColorSpace interpolation_space) const {
  // Do not apply gamut mapping to gradient stops. Skia will perform
  // gamut mapping on a per-pixel basis internally.
  return ToSkColor4fInternal(/*gamut_map_oklab_oklch=*/false);
}

// static
bool Color::IsBakedGamutMappingEnabled() {
  static bool enabled =
      base::FeatureList::IsEnabled(blink::features::kBakedGamutMapping);
  return enabled;
}

SkColor4f Color::ToSkColor4fInternal(bool gamut_map_oklab_oklch) const {
  switch (color_space_) {
    case ColorSpace::kSRGB:
      return SkColor4f{param0_, param1_, param2_, alpha_};
    case ColorSpace::kSRGBLegacy: {
      auto [r, g, b] = gfx::SRGBLegacyToSRGB(param0_, param1_, param2_);
      return SkColor4f{r, g, b, alpha_};
    }
    case ColorSpace::kSRGBLinear:
      return gfx::SRGBLinearToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kDisplayP3:
      return gfx::DisplayP3ToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kA98RGB:
      return gfx::AdobeRGBToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kProPhotoRGB:
      return gfx::ProPhotoToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kRec2020:
      return gfx::Rec2020ToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kXYZD50:
      return gfx::XYZD50ToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kXYZD65:
      return gfx::XYZD65ToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kLab:
      return gfx::LabToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kOklab:
      if (gamut_map_oklab_oklch) {
        return gfx::OklabGamutMapToSkColor4f(param0_, param1_, param2_, alpha_);
      } else {
        return gfx::OklabToSkColor4f(param0_, param1_, param2_, alpha_);
      }
    case ColorSpace::kLch:
      return gfx::LchToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kOklch:
      if (gamut_map_oklab_oklch) {
        return gfx::OklchGamutMapToSkColor4f(param0_, param1_, param2_, alpha_);
      } else {
        return gfx::OklchToSkColor4f(param0_, param1_, param2_, alpha_);
      }
    case ColorSpace::kHSL:
      return gfx::HSLToSkColor4f(param0_, param1_, param2_, alpha_);
    case ColorSpace::kHWB:
      return gfx::HWBToSkColor4f(param0_, param1_, param2_, alpha_);
    default:
      NOTIMPLEMENTED();
      return SkColor4f{0.f, 0.f, 0.f, 0.f};
  }
}

float Color::PremultiplyColor() {
  // By the spec (https://www.w3.org/TR/css-color-4/#interpolation) Hue values
  // are not premultiplied, and if alpha is none, the color premultiplied value
  // is the same as unpremultiplied.
  if (alpha_is_none_)
    return alpha_;
  float alpha = alpha_;
  if (color_space_ != ColorSpace::kHSL && color_space_ != ColorSpace::kHWB)
    param0_ = param0_ * alpha_;
  param1_ = param1_ * alpha_;
  if (!IsChromaSecondComponent(color_space_)) {
    param2_ = param2_ * alpha_;
  }
  alpha_ = 1.0f;
  return alpha;
}

void Color::UnpremultiplyColor() {
  // By the spec (https://www.w3.org/TR/css-color-4/#interpolation) Hue values
  // are not premultiplied, and if alpha is none, the color premultiplied value
  // is the same as unpremultiplied.
  if (alpha_is_none_ || alpha_ == 0.0f)
    return;

  if (color_space_ != ColorSpace::kHSL && color_space_ != ColorSpace::kHWB)
    param0_ = param0_ / alpha_;
  param1_ = param1_ / alpha_;
  if (!IsChromaSecondComponent(color_space_)) {
    param2_ = param2_ / alpha_;
  }
}

// This converts -0.0 to 0.0, so that they have the same hash value. This
// ensures that equal FontDescription have the same hash value.
float NormalizeSign(float number) {
  if (number == 0.0) [[unlikely]] {
    return 0.0;
  }
  return number;
}

unsigned Color::GetHash() const {
  unsigned result = WTF::HashInt(static_cast<uint8_t>(color_space_));
  WTF::AddFloatToHash(result, NormalizeSign(param0_));
  WTF::AddFloatToHash(result, NormalizeSign(param1_));
  WTF::AddFloatToHash(result, NormalizeSign(param2_));
  WTF::AddFloatToHash(result, NormalizeSign(alpha_));
  WTF::AddIntToHash(result, param0_is_none_);
  WTF::AddIntToHash(result, param1_is_none_);
  WTF::AddIntToHash(result, param2_is_none_);
  WTF::AddIntToHash(result, alpha_is_none_);
  return result;
}

int Color::Red() const {
  return RedChannel(Rgb());
}
int Color::Green() const {
  return GreenChannel(Rgb());
}
i
```