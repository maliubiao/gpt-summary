Response:
Let's break down the thought process for analyzing this `interpolable_color.cc` file. The request asks for functionalities, connections to web technologies, logic inference, and common usage errors. Here’s a possible thought progression:

1. **Understand the Core Purpose:** The filename and the presence of "interpolable" strongly suggest this code deals with color values that can be smoothly transitioned between, likely for animations or transitions in web pages. The inclusion of "animation" in the directory reinforces this.

2. **Identify Key Classes and Structures:**  The central class is clearly `InterpolableColor`. Other important elements are `Color`, `Color::ColorSpace`, `InlinedInterpolableDouble`, and constants like `ColorKeyword`. The namespace `blink` and inclusion of `third_party/blink` headers confirm this is part of the Chromium rendering engine.

3. **Analyze Key Methods:** Go through the public methods of `InterpolableColor` and understand their purpose:

    * **`Create(...)`:**  Multiple `Create` methods suggest different ways to instantiate an `InterpolableColor`. Notice the handling of both direct `Color` objects and color keywords like `currentcolor`. The `CSSValueID` overload connects it to CSS.

    * **`GetColor()`:** This is likely the method that returns the final `Color` object after interpolation. Pay attention to the pre-multiplication and unpremultiplication logic.

    * **`AssertCanInterpolateWith()`:** This method confirms the compatibility of two `InterpolableColor` objects for interpolation, checking the `color_space_`.

    * **`IsKeywordColor()`:** This function determines if the color is based on a keyword, which is important for the `Resolve()` method.

    * **`ConvertToColorSpace()`:**  Handles conversion between different color spaces (sRGB and Oklab are mentioned).

    * **`SetupColorInterpolationSpaces()`:**  Ensures that two colors being interpolated are in the same color space.

    * **`Scale()` and `Add()`:** These methods suggest vector-like operations on the color components, necessary for interpolation.

    * **`Resolve()`:** This is crucial. It takes keyword colors (`currentcolor`, etc.) into account and resolves the final color value based on context. It also handles the unpremultiplication.

    * **`Interpolate()`:** The heart of the interpolation logic. It takes a target color and a progress value (0 to 1) and calculates the intermediate color.

    * **`Composite()`:**  Likely used for layering or blending colors.

4. **Look for Connections to Web Technologies:**

    * **CSS:** The `CSSValueID` enum in the `Create` methods directly links to CSS color keywords. The mention of interpolation and transitions further reinforces this. Properties like `color`, `background-color`, `border-color`, and even SVG fill/stroke come to mind.
    * **JavaScript:** While not directly interacting in *this* file, JavaScript is the language that typically triggers style changes that lead to these interpolations. Think of JavaScript manipulating CSS properties using the DOM or through CSSOM.
    * **HTML:** HTML elements are styled with CSS, thus forming the context for these color interpolations.

5. **Infer Logical Flow and Data Handling:**

    * **Pre-multiplication:** The comments explain *why* colors are pre-multiplied during blending (efficiency) and unpremultiplied for the final `Color` object. This is a key optimization.
    * **Color Spaces:**  The limited set of supported color spaces (sRGB and Oklab) for interpolation is noted.
    * **Keyword Color Resolution:** The `Resolve()` method demonstrates the deferred resolution of keyword colors. The `InterpolableDouble` members (`current_color_`, etc.) store the *fraction* of the keyword color to be applied.

6. **Consider Potential Usage Errors:**

    * **Mismatched Color Spaces:** Although the code handles this with `SetupColorInterpolationSpaces()`, a developer might expect interpolation between arbitrary color spaces, which isn't the case here.
    * **Division by Zero:** The `GetColor()` method explicitly handles the case where alpha is zero. This hints at a potential pitfall if not handled.
    * **Unexpected Keyword Color Behavior:**  Developers might not fully grasp how `currentcolor` and other keyword colors are resolved during animation.

7. **Structure the Output:**  Organize the findings into the categories requested: Functionality, Web Technology Relationships, Logic Inference, and Common Errors. Use clear and concise language, providing code snippets or examples where helpful.

8. **Review and Refine:** Read through the analysis to ensure accuracy and completeness. Check for any jargon that needs explanation. Ensure the examples are relevant and easy to understand. For instance, initially, I might not have explicitly mentioned SVG, but upon reviewing, realized it's another important area where color interpolation applies. Similarly, thinking about how the browser *triggers* these animations led to the inclusion of JavaScript's role.
这个文件 `interpolable_color.cc` 是 Chromium Blink 引擎中负责处理**可插值的颜色值**的源代码。这意味着它定义了一种可以随着时间平滑过渡变化的颜色表示方式，主要用于 CSS 动画和过渡效果。

以下是它的主要功能：

**1. 表示和存储可插值的颜色：**

*   它定义了 `InterpolableColor` 类，用于存储颜色信息，包括颜色的各个分量（例如，红、绿、蓝、Alpha）以及颜色空间。
*   它支持存储传统的 RGBA 颜色以及像 `currentcolor`、`activeborder` 等 CSS 颜色关键字。
*   为了提高插值效率，颜色分量在内部以**预乘 alpha** 的形式存储。这意味着 RGB 值在存储时已经乘以了 alpha 值。在最终解析时，会进行反预乘。

**2. 创建 `InterpolableColor` 对象：**

*   提供了多个 `Create` 方法，用于从不同的来源创建 `InterpolableColor` 对象：
    *   从 `Color` 对象创建。
    *   从 `ColorKeyword` 枚举值创建（用于处理像 `currentcolor` 这样的关键字）。
    *   从 `CSSValueID` (CSS 属性值 ID) 创建，并能处理颜色方案 (color-scheme) 和颜色提供器 (ColorProvider)。

**3. 颜色空间的转换和处理：**

*   支持不同的颜色空间，目前主要关注 `srgb-legacy` 和 `oklab` 用于插值。
*   提供了 `ConvertToColorSpace` 方法，用于将 `InterpolableColor` 对象转换到指定的颜色空间。
*   `SetupColorInterpolationSpaces` 方法用于确保两个用于插值的 `InterpolableColor` 对象处于相同的颜色空间，如果不同，则会转换到 `oklab` 颜色空间。

**4. 插值操作：**

*   实现了 `Interpolate` 方法，用于在两个 `InterpolableColor` 对象之间进行插值。它接收一个进度值 (0 到 1)，并返回一个表示中间状态的新 `InterpolableColor` 对象。
*   插值是在预乘 alpha 的颜色分量上进行的。
*   对于颜色关键字，它会插值这些关键字的“权重”，以便在解析时根据上下文添加正确的颜色。

**5. 解析最终颜色值：**

*   `GetColor` 方法用于获取 `InterpolableColor` 对象所代表的最终 `Color` 对象。在这个过程中，会进行反预乘操作。
*   `Resolve` 方法是关键，它处理颜色关键字的解析。它会根据当前的上下文（例如，`currentcolor` 的值，链接颜色等）以及关键字的插值权重，计算出最终的颜色值。

**6. 其他操作：**

*   `RawClone` 和 `RawCloneAndZero` 用于创建对象的副本。
*   `Scale` 和 `Add` 方法提供了基本的数学运算，用于插值过程。
*   `Composite` 方法用于合成颜色。
*   `AssertCanInterpolateWith` 方法用于断言两个 `InterpolableColor` 对象是否可以进行插值（即颜色空间是否一致）。
*   `IsKeywordColor` 方法判断该可插值颜色是否包含颜色关键字。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Chromium 渲染引擎内部处理颜色动画和过渡的关键部分，它直接服务于 CSS 的 `transition` 和 `animation` 属性，以及一些需要颜色值平滑变化的场景。

*   **CSS:** 当 CSS 中定义了颜色属性的动画或过渡时（例如，`transition: background-color 1s;` 或 `@keyframes fade { from { background-color: red; } to { background-color: blue; } }`），Blink 引擎会使用 `InterpolableColor` 来表示起始和结束颜色，并执行插值计算以生成动画过程中的中间颜色。
    *   **示例:**  考虑以下 CSS：
        ```css
        .element {
          background-color: red;
          transition: background-color 1s;
        }
        .element:hover {
          background-color: blue;
        }
        ```
        当鼠标悬停在 `.element` 上时，`InterpolableColor` 会被用来在红色和蓝色之间平滑过渡背景颜色。

*   **JavaScript:** JavaScript 可以通过修改元素的 CSS 样式来触发颜色动画和过渡。例如：
    ```javascript
    const element = document.querySelector('.element');
    element.style.backgroundColor = 'blue'; // 如果有 transition，会触发颜色过渡
    ```
    在这种情况下，JavaScript 的操作会导致 Blink 引擎内部使用 `InterpolableColor` 来实现平滑的颜色变化。

*   **HTML:** HTML 定义了网页的结构，而 CSS 用于样式化这些结构。`InterpolableColor` 处理的是 CSS 样式中涉及的颜色值，所以它间接地与 HTML 元素相关联。

**逻辑推理的假设输入与输出：**

假设我们有两个 `InterpolableColor` 对象，分别表示红色和蓝色（在 sRGB 颜色空间）：

*   **输入 `color_from`:**  红色 (R: 255, G: 0, B: 0, A: 1)  ->  `InterpolableColor` 对象，`color_space_` 为 `kSRGBLegacy`，预乘后的 `param0_` 大约为 1.0, `param1_` 为 0, `param2_` 为 0, `alpha_` 为 1。
*   **输入 `color_to`:** 蓝色 (R: 0, G: 0, B: 255, A: 1) ->  `InterpolableColor` 对象，`color_space_` 为 `kSRGBLegacy`，预乘后的 `param0_` 为 0, `param1_` 为 0, `param2_` 大约为 1.0, `alpha_` 为 1。
*   **输入 `progress`:** 0.5 (表示动画进行到一半)

**调用 `Interpolate(color_to, progress, result)`：**

*   **输出 `result`:**  一个 `InterpolableColor` 对象，表示红色和蓝色之间的中间颜色（紫色）。预乘后的分量大约为 `param0_` 为 0.5, `param1_` 为 0, `param2_` 为 0.5, `alpha_` 为 1。
*   **调用 `result.GetColor()`:**  将会返回一个 `Color` 对象，其 RGB 值接近 (128, 0, 128)，Alpha 为 1。

**涉及用户或者编程常见的使用错误：**

1. **期望在不同的颜色空间之间直接插值，而没有进行转换:**
    *   **错误示例:**  假设一个动画从 sRGB 的红色过渡到 LAB 空间的蓝色。如果 Blink 没有先将这两个颜色转换到同一个插值颜色空间（如 `oklab`），直接在各自的颜色空间中插值可能会导致不期望的颜色变化路径。
    *   `InterpolableColor` 通过 `SetupColorInterpolationSpaces` 方法来避免这个问题，它会自动将颜色转换到 `oklab` (如果其中一个颜色是 `oklab`) 或者都保持在 `srgb-legacy`。

2. **在 alpha 值为 0 的情况下进行反预乘:**
    *   **错误场景:** 如果 `alpha_.Value()` 为 0，那么在 `GetColor` 方法中执行 `param0_.Value() / alpha_.Value()` 将会导致除零错误。
    *   **代码中的处理:**  `InterpolableColor::GetColor` 中有 `if (alpha_.Value() == 0)` 的检查，并返回 `Color::kTransparent` 来避免这种情况。

3. **不理解颜色关键字的解析时机:**
    *   **错误理解:**  开发者可能认为颜色关键字（如 `currentcolor`）在动画开始时就被其当前值替换了。
    *   **实际情况:**  `InterpolableColor` 会插值颜色关键字的“权重”，并在 `Resolve` 阶段才根据当时的上下文来确定最终颜色。这意味着在动画过程中，`currentcolor` 的值可能会动态变化，影响动画效果。

4. **手动修改 `InterpolableColor` 对象的内部状态而不考虑预乘:**
    *   **错误操作:**  直接设置 `param0_`、`param1_`、`param2_` 的值，而没有考虑它们是预乘 alpha 的，可能导致最终颜色不正确。
    *   **正确方式:**  应该通过 `Create` 方法创建对象，或者在修改内部状态时确保理解预乘的影响。

总而言之，`interpolable_color.cc` 是 Blink 引擎中一个核心的组件，它使得浏览器能够平滑地处理 CSS 颜色动画和过渡，为用户带来更流畅的视觉体验。它涉及到颜色表示、颜色空间转换、插值算法以及对 CSS 颜色关键字的处理等多个方面。

### 提示词
```
这是目录为blink/renderer/core/animation/interpolable_color.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/interpolable_color.h"

#include <cmath>
#include <memory>
#include "base/check_op.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/interpolable_value.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"

namespace blink {

namespace {
// InterpolableColors are stored premultiplied (scaled by alpha) during the
// blending process for efficiency and unpremultiplied during resolution. This
// works since restricted to rectangular color spaces. This optimization step
// would not work in polar color spaces. Fortunately, interpolation is currently
// restricted to srgb-legacy and oklab.

// Apply a color blend. The first color in the blend, expressed as doubles and a
// colorspace is expected to already be in premultiplied form (scaled by alpha).
// The result is left in premultiplied form for efficiency.
std::tuple<double, double, double, double> AddPremultipliedColor(
    double param0,
    double param1,
    double param2,
    double alpha,
    double fraction,
    Color color,
    Color::ColorSpace color_space) {
  DCHECK(color_space == Color::ColorSpace::kSRGBLegacy ||
         color_space == Color::ColorSpace::kOklab);
  color.ConvertToColorSpace(color_space);
  return std::make_tuple(param0 + fraction * color.Param0() * color.Alpha(),
                         param1 + fraction * color.Param1() * color.Alpha(),
                         param2 + fraction * color.Param2() * color.Alpha(),
                         alpha + fraction * color.Alpha());
}

// Convert color parameters back to unpremultiplied form (not scaled by alpha)
// suitable for the Color constructor.
std::tuple<double, double, double> UnpremultiplyColor(double param0,
                                                      double param1,
                                                      double param2,
                                                      double alpha) {
  return std::make_tuple(param0 / alpha, param1 / alpha, param2 / alpha);
}

}  // namespace

InterpolableColor* InterpolableColor::Create(Color color) {
  InterpolableColor* result = MakeGarbageCollected<InterpolableColor>();
  result->color_space_ = color.GetColorInterpolationSpace();

  // A color is not necessarily "in" it's desired interpolation space.
  color.ConvertToColorSpace(result->color_space_);

  // All params are stored pre-multiplied.
  // https://www.w3.org/TR/css-color-4/#interpolation-alpha
  result->param0_.Set(color.Param0() * color.Alpha());
  result->param1_.Set(color.Param1() * color.Alpha());
  result->param2_.Set(color.Param2() * color.Alpha());
  result->alpha_.Set(color.Alpha());

  return result;
}

InterpolableColor* InterpolableColor::Create(ColorKeyword color_keyword) {
  InterpolableColor* result = MakeGarbageCollected<InterpolableColor>();
  // color_keyword_fractions_ keeps track of keyword colors (like
  // "currentcolor") for interpolation. These keyword colors are not known at
  // specified value time, so we need to wait until we resolve them. Upon
  // creation the entry for the correct keyword is set to "1" and all others are
  // "0". These values are interpolated as normal. When the color is resolved
  // the proper fraction of the keyword color is added in.
  switch (color_keyword) {
    case ColorKeyword::kCurrentcolor:
      result->current_color_ = InlinedInterpolableDouble(1);
      break;
    case ColorKeyword::kWebkitActivelink:
      result->webkit_active_link_ = InlinedInterpolableDouble(1);
      break;
    case ColorKeyword::kWebkitLink:
      result->webkit_link_ = InlinedInterpolableDouble(1);
      break;
    case ColorKeyword::kQuirkInherit:
      result->quirk_inherit_ = InlinedInterpolableDouble(1);
      break;
  }
  // Keyword colors are functionally legacy colors for interpolation.
  result->color_space_ = Color::ColorSpace::kSRGBLegacy;

  return result;
}

InterpolableColor* InterpolableColor::Create(
    CSSValueID keyword,
    mojom::blink::ColorScheme color_scheme,
    const ui::ColorProvider* color_provider) {
  switch (keyword) {
    case CSSValueID::kCurrentcolor:
      return Create(ColorKeyword::kCurrentcolor);
    case CSSValueID::kWebkitActivelink:
      return Create(ColorKeyword::kWebkitActivelink);
    case CSSValueID::kWebkitLink:
      return Create(ColorKeyword::kWebkitLink);
    case CSSValueID::kInternalQuirkInherit:
      return Create(ColorKeyword::kQuirkInherit);
    case CSSValueID::kWebkitFocusRingColor:
      return Create(LayoutTheme::GetTheme().FocusRingColor(color_scheme));
    default:
      DCHECK(StyleColor::IsColorKeyword(keyword));
      // TODO(crbug.com/40229450): Pass down if within installed webapp scope
      // from Document.
      return Create(
          StyleColor::ColorFromKeyword(keyword, color_scheme, color_provider,
                                       /*is_in_web_app_scope=*/false));
  }
}

InterpolableColor::InterpolableColor(
    InlinedInterpolableDouble param0,
    InlinedInterpolableDouble param1,
    InlinedInterpolableDouble param2,
    InlinedInterpolableDouble alpha,
    InlinedInterpolableDouble current_color,
    InlinedInterpolableDouble webkit_active_link,
    InlinedInterpolableDouble webkit_link,
    InlinedInterpolableDouble quirk_inherit,
    Color::ColorSpace color_space)
    : param0_(std::move(param0)),
      param1_(std::move(param1)),
      param2_(std::move(param2)),
      alpha_(std::move(alpha)),
      current_color_(std::move(current_color)),
      webkit_active_link_(std::move(webkit_active_link)),
      webkit_link_(std::move(webkit_link)),
      quirk_inherit_(std::move(quirk_inherit)),
      color_space_(std::move(color_space)) {}

InterpolableColor* InterpolableColor::RawClone() const {
  return MakeGarbageCollected<InterpolableColor>(
      param0_, param1_, param2_, alpha_, current_color_, webkit_active_link_,
      webkit_link_, quirk_inherit_, color_space_);
}

InterpolableColor* InterpolableColor::RawCloneAndZero() const {
  return MakeGarbageCollected<InterpolableColor>(
      InlinedInterpolableDouble(0), InlinedInterpolableDouble(0),
      InlinedInterpolableDouble(0), InlinedInterpolableDouble(0),
      InlinedInterpolableDouble(0), InlinedInterpolableDouble(0),
      InlinedInterpolableDouble(0), InlinedInterpolableDouble(0), color_space_);
}

Color InterpolableColor::GetColor() const {
  // Prevent dividing by zero.
  if (alpha_.Value() == 0) {
    return Color::kTransparent;
  }

  // All params are stored pre-multiplied.
  float param0 = param0_.Value() / alpha_.Value();
  float param1 = param1_.Value() / alpha_.Value();
  float param2 = param2_.Value() / alpha_.Value();
  float alpha = ClampTo<double>(alpha_.Value(), 0, 1);

  switch (color_space_) {
    // There is no way for the user to specify which color spaces should be
    // used for interpolation, so sRGB (for legacy colors) and Oklab are the
    // only possibilities.
    case Color::ColorSpace::kSRGBLegacy:
    case Color::ColorSpace::kOklab:
      return Color::FromColorSpace(color_space_, param0, param1, param2, alpha);
    default:
      NOTREACHED();
  }
}

void InterpolableColor::AssertCanInterpolateWith(
    const InterpolableValue& other) const {
  const InterpolableColor& other_color = To<InterpolableColor>(other);
  DCHECK_EQ(color_space_, other_color.color_space_);
}

bool InterpolableColor::IsKeywordColor() const {
  // color_keyword_fractions_ indicate fractional blending amounts and are
  // important for resolving the color. If any of these store a non-zero value,
  // then the interpolated color is not the same as the color produced by simply
  // looking at the param values and color interpolation space.
  return current_color_.Value() || webkit_active_link_.Value() ||
         webkit_link_.Value() || quirk_inherit_.Value();
}

void InterpolableColor::ConvertToColorSpace(Color::ColorSpace color_space) {
  if (color_space_ == color_space) {
    return;
  }

  Color underlying_color = GetColor();
  underlying_color.ConvertToColorSpace(color_space);
  param0_.Set(underlying_color.Param0() * underlying_color.Alpha());
  param1_.Set(underlying_color.Param1() * underlying_color.Alpha());
  param2_.Set(underlying_color.Param2() * underlying_color.Alpha());
  alpha_.Set(underlying_color.Alpha());

  color_space_ = color_space;
}

// static
void InterpolableColor::SetupColorInterpolationSpaces(InterpolableColor& to,
                                                      InterpolableColor& from) {
  // In the event that the two colorspaces are the same, there's nothing to do.
  if (to.color_space_ == from.color_space_) {
    return;
  }

  // sRGB and Oklab are the only possible interpolation spaces, so one should be
  // in Oklab and we should convert the other.
  DCHECK(from.color_space_ == Color::ColorSpace::kOklab ||
         to.color_space_ == Color::ColorSpace::kOklab);

  to.ConvertToColorSpace(Color::ColorSpace::kOklab);
  from.ConvertToColorSpace(Color::ColorSpace::kOklab);
}

void InterpolableColor::Scale(double scale) {
// A guard to prevent overload with very large values.
#if DCHECK_IS_ON()
  bool param0_is_positive = param0_.Value() > 0.0;
  bool param1_is_positive = param1_.Value() > 0.0;
  bool param2_is_positive = param2_.Value() > 0.0;
  bool alpha_is_positive = alpha_.Value() > 0.0;
#endif

  param0_.Scale(scale);
  param1_.Scale(scale);
  param2_.Scale(scale);
  alpha_.Scale(scale);
  current_color_.Scale(scale);
  webkit_active_link_.Scale(scale);
  webkit_link_.Scale(scale);
  quirk_inherit_.Scale(scale);

#if DCHECK_IS_ON()
  DCHECK_EQ(param0_is_positive * (scale > 0), param0_.Value() > 0.0);
  DCHECK_EQ(param1_is_positive * (scale > 0), param1_.Value() > 0.0);
  DCHECK_EQ(param2_is_positive * (scale > 0), param2_.Value() > 0.0);
  DCHECK_EQ(alpha_is_positive * (scale > 0), alpha_.Value() > 0.0);
  DCHECK_GE(current_color_.Value(), 0.);
  DCHECK_LE(current_color_.Value(), 1.);
  DCHECK_GE(webkit_active_link_.Value(), 0.);
  DCHECK_LE(webkit_active_link_.Value(), 1.);
  DCHECK_GE(webkit_link_.Value(), 0.);
  DCHECK_LE(webkit_link_.Value(), 1.);
  DCHECK_GE(quirk_inherit_.Value(), 0.);
  DCHECK_LE(quirk_inherit_.Value(), 1.);
#endif
}

void InterpolableColor::Add(const InterpolableValue& other) {
  const InterpolableColor& other_color = To<InterpolableColor>(other);
  param0_.Add(other_color.param0_.Value());
  param1_.Add(other_color.param1_.Value());
  param2_.Add(other_color.param2_.Value());
  alpha_.Add(other_color.alpha_.Value());
  current_color_.Add(other_color.current_color_.Value());
  webkit_active_link_.Add(other_color.webkit_active_link_.Value());
  webkit_link_.Add(other_color.webkit_link_.Value());
  quirk_inherit_.Add(other_color.quirk_inherit_.Value());
}

Color InterpolableColor::Resolve(const Color& current_color,
                                 const Color& active_link_color,
                                 const Color& link_color,
                                 const Color& text_color,
                                 mojom::blink::ColorScheme color_scheme) const {
  double param0 = Param0();
  double param1 = Param1();
  double param2 = Param2();
  double alpha = Alpha();

  if (double currentcolor_fraction = current_color_.Value()) {
    std::tie(param0, param1, param2, alpha) = AddPremultipliedColor(
        param0, param1, param2, alpha, currentcolor_fraction, current_color,
        color_space_);
  }
  if (double webkit_activelink_fraction = webkit_active_link_.Value()) {
    std::tie(param0, param1, param2, alpha) = AddPremultipliedColor(
        param0, param1, param2, alpha, webkit_activelink_fraction,
        active_link_color, color_space_);
  }
  if (double webkit_link_fraction = webkit_link_.Value()) {
    std::tie(param0, param1, param2, alpha) =
        AddPremultipliedColor(param0, param1, param2, alpha,
                              webkit_link_fraction, link_color, color_space_);
  }
  if (double quirk_inherit_fraction = quirk_inherit_.Value()) {
    std::tie(param0, param1, param2, alpha) =
        AddPremultipliedColor(param0, param1, param2, alpha,
                              quirk_inherit_fraction, text_color, color_space_);
  }

  alpha = ClampTo<double>(alpha, 0, 1);
  if (alpha == 0) {
    return Color::FromColorSpace(color_space_, param0, param1, param2, 0);
  }

  std::tie(param0, param1, param2) =
      UnpremultiplyColor(param0, param1, param2, alpha);

  switch (color_space_) {
    case Color::ColorSpace::kSRGBLegacy:
    case Color::ColorSpace::kOklab:
      return Color::FromColorSpace(color_space_, param0, param1, param2, alpha);
    default:
      // There is no way for the user to specify which color spaces should be
      // used for interpolation, so sRGB (for legacy colors) and Oklab are
      // the only possibilities.
      // https://www.w3.org/TR/css-color-4/#interpolation-space
      NOTREACHED();
  }
}

void InterpolableColor::Interpolate(const InterpolableValue& to,
                                    const double progress,
                                    InterpolableValue& result) const {
  const InterpolableColor& to_color = To<InterpolableColor>(to);
  InterpolableColor& result_color = To<InterpolableColor>(result);

  DCHECK_EQ(to_color.color_space_, color_space_);
  DCHECK_EQ(result_color.color_space_, color_space_);

  result_color.param0_.Set(
      param0_.Interpolate(to_color.param0_.Value(), progress));
  result_color.param1_.Set(
      param1_.Interpolate(to_color.param1_.Value(), progress));
  result_color.param2_.Set(
      param2_.Interpolate(to_color.param2_.Value(), progress));
  result_color.alpha_.Set(
      alpha_.Interpolate(to_color.alpha_.Value(), progress));

  result_color.current_color_.Set(
      current_color_.Interpolate(to_color.current_color_.Value(), progress));
  result_color.webkit_active_link_.Set(webkit_active_link_.Interpolate(
      to_color.webkit_active_link_.Value(), progress));
  result_color.webkit_link_.Set(
      webkit_link_.Interpolate(to_color.webkit_link_.Value(), progress));
  result_color.quirk_inherit_.Set(
      quirk_inherit_.Interpolate(to_color.quirk_inherit_.Value(), progress));
}

void InterpolableColor::Composite(const BaseInterpolableColor& value,
                                  double fraction) {
  auto& other = To<InterpolableColor>(value);

  param0_.ScaleAndAdd(fraction, other.param0_.Value());
  param1_.ScaleAndAdd(fraction, other.param1_.Value());
  param2_.ScaleAndAdd(fraction, other.param2_.Value());
  // TODO(crbug.com/981326): Test coverage has historically been missing for
  // composition of transparent colors. We should aim for interop with Firefox
  // and Safari.
  if (alpha_.Value() != other.alpha_.Value()) {
    alpha_.ScaleAndAdd(fraction, other.alpha_.Value());
  }

  current_color_.ScaleAndAdd(fraction, other.current_color_.Value());
  webkit_active_link_.ScaleAndAdd(fraction, other.webkit_active_link_.Value());
  webkit_link_.ScaleAndAdd(fraction, other.webkit_link_.Value());
  quirk_inherit_.ScaleAndAdd(fraction, other.quirk_inherit_.Value());
}

}  // namespace blink
```