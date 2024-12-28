Response:
Let's break down the thought process for analyzing the `gradient.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `gradient.cc` file in the Chromium Blink rendering engine, its relationship to web technologies (HTML, CSS, JavaScript), provide examples, and identify potential usage errors.

2. **Initial Scan and Identification of Core Concepts:**  A quick skim reveals the presence of keywords like "Gradient", "ColorStop", "LinearGradient", "RadialGradient", "ConicGradient", "Skia", "Shader", and color-related terms. This immediately suggests the file deals with rendering color gradients. The copyright information points to Apple and Google, indicating its long history and importance.

3. **Deconstruct the Class Structure:**
    * **`Gradient` (Base Class):**  This is clearly the abstract base class. It manages common gradient properties like type, spread method, color interpolation, and color stops. Key methods include `AddColorStop`, `FillSkiaStops`, and `CreateShaderInternal`.
    * **Derived Classes (`LinearGradient`, `RadialGradient`, `ConicGradient`):**  These represent the specific types of gradients. They inherit from `Gradient` and implement the `CreateShader` method to generate the appropriate Skia shader.

4. **Analyze Key Methods within `Gradient`:**
    * **`AddColorStop`:**  This adds color stops to the gradient. The logic to maintain `stops_sorted_` is important for efficiency.
    * **`SortStopsIfNecessary`:** Sorts the color stops by their position. This is crucial for the correct rendering of the gradient.
    * **`FillSkiaStops`:**  This is a critical function. It takes the internal `stops_` and prepares the color and position data in the format Skia requires. The padding of 0 and 1 stops, and the handling of "none" color parameters, are significant details.
    * **`ResolveSkInterpolation`:** This function translates Blink's color interpolation settings into Skia's `SkGradientShader::Interpolation`. The logic here is complex and maps different color spaces. The handling of the default to Oklab is a noteworthy point.
    * **`CreateShaderInternal`:** This is the central method for generating the Skia shader. It orchestrates the sorting of stops, data preparation using `FillSkiaStops`, and the actual shader creation by calling the derived class's `CreateShader` method. It also handles dark mode.
    * **`ApplyToFlags`:** This method integrates the gradient shader into the `cc::PaintFlags` used for drawing. It manages caching of the shader and applying the color filter.
    * **`EnsureDarkModeFilter`:**  Handles the creation of the dark mode filter.

5. **Analyze Derived Class Implementations of `CreateShader`:**
    * **`LinearGradient::CreateShader`:** Creates a `SkGradientShader::MakeLinearGradient`. Handles the degenerate case where the start and end points are the same.
    * **`RadialGradient::CreateShader`:** Creates a `SkGradientShader::MakeTwoPointConicalGradient`. Deals with aspect ratio for elliptical gradients and handles degenerate cases.
    * **`ConicGradient::CreateShader`:** Creates a `SkGradientShader::MakeSweepGradient`. Adjusts rotation for Skia's coordinate system and handles degenerate angle cases.

6. **Identify Relationships with Web Technologies:**
    * **CSS:**  The most direct connection is to CSS gradient functions like `linear-gradient`, `radial-gradient`, and `conic-gradient`. The properties like `spread-method` (`repeat`, `reflect`, `pad`), color stops, and color interpolation are directly mapped from CSS.
    * **HTML:**  Gradients are used to style HTML elements.
    * **JavaScript:**  JavaScript can manipulate the style of HTML elements, indirectly triggering the creation and rendering of gradients. Canvas API also allows drawing gradients directly.

7. **Formulate Examples:** Based on the understanding of the code and its connection to CSS, create concrete examples of how these gradients are used in web development. Show the CSS syntax and explain how it maps to the C++ code.

8. **Identify Potential Usage Errors:** Think about common mistakes developers might make when using gradients:
    * Incorrect color stop order.
    * Missing color stops at 0% or 100%.
    * Using unsupported color spaces for interpolation.
    * Degenerate gradients (e.g., linear gradient with identical start and end points).
    * Issues with `none` color parameters.

9. **Infer Logic and Assumptions (Hypothetical Input/Output):**  Consider a simple case like a linear gradient with two color stops. Trace how the `AddColorStop`, `SortStopsIfNecessary`, and `FillSkiaStops` methods would process the data. Imagine the Skia calls that would be made.

10. **Consider Dark Mode:** The code explicitly handles dark mode. Explain how this integration works and its impact on the rendered colors.

11. **Structure the Answer:** Organize the findings logically with clear headings and explanations for each aspect: functionality, relationship to web technologies, examples, logic/assumptions, and common errors.

12. **Refine and Review:**  Read through the entire analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further explanation. For example, explicitly mention the Skia library's role.

This step-by-step approach, starting with a high-level understanding and then diving into the details of the code, combined with connecting the C++ implementation to web technologies and potential user errors, allows for a comprehensive and informative analysis of the `gradient.cc` file.
这个文件 `blink/renderer/platform/graphics/gradient.cc` 的主要功能是**在 Chromium Blink 渲染引擎中实现各种类型的颜色渐变效果**。它负责创建和管理用于绘制线性、径向和圆锥渐变的底层表示，并与 Skia 图形库进行交互以完成实际的渲染。

以下是更详细的功能列表：

**核心功能：**

1. **抽象渐变表示：** 定义了一个 `Gradient` 基类，作为所有渐变类型的抽象接口。它包含了所有渐变共有的属性，例如渐变类型、颜色混合方式、平铺模式等。
2. **支持多种渐变类型：**
    * **线性渐变 (`LinearGradient`):**  定义了沿直线方向颜色平滑过渡的渐变。
    * **径向渐变 (`RadialGradient`):**  定义了从一个点向外辐射状颜色过渡的渐变。可以支持圆形和椭圆形渐变。
    * **圆锥渐变 (`ConicGradient`):** 定义了绕着一个中心点旋转的颜色过渡的渐变。
3. **颜色停止点管理：**  允许添加和管理颜色停止点 (`ColorStop`)，每个停止点定义了渐变中特定位置的颜色。
4. **颜色混合模式：**  支持不同的颜色混合模式 (`ColorInterpolation`)，例如预乘 alpha 和非预乘 alpha。
5. **平铺模式：** 支持不同的平铺模式 (`GradientSpreadMethod`)，决定了渐变在超出其定义区域后的行为，包括：
    * `kSpreadMethodPad` (默认):  使用边缘颜色填充剩余区域。
    * `kSpreadMethodRepeat`:  重复渐变。
    * `kSpreadMethodReflect`:  镜像反射渐变。
6. **退化处理：**  允许指定如何处理退化的渐变情况 (`DegenerateHandling`)，例如线性渐变的起始点和结束点相同。
7. **与 Skia 集成：**  使用 Skia 图形库来创建实际的渐变着色器 (`SkShader`)。`CreateShaderInternal` 和派生类的 `CreateShader` 方法负责将 Blink 的渐变表示转换为 Skia 可以理解的对象。
8. **暗黑模式支持：**  集成了暗黑模式，可以在需要时调整渐变的颜色以适应暗黑主题。
9. **颜色空间处理：** 支持不同的颜色空间 (`ColorSpace`) 进行颜色插值，例如 sRGB、Lab、Oklab 等，以实现更精确的颜色过渡。
10. **颜色过滤：** 允许应用颜色过滤器 (`cc::ColorFilter`) 到渐变。

**与 JavaScript, HTML, CSS 的关系：**

`gradient.cc` 文件是 Blink 渲染引擎的一部分，负责解析和渲染由 CSS 定义的渐变。

* **CSS：**  这个文件直接对应于 CSS 的渐变功能，例如：
    * **`linear-gradient()`:**  对应 `LinearGradient` 类。
        ```css
        /* 假设输入 CSS */
        .element {
          background-image: linear-gradient(to right, red, blue);
        }
        ```
        **逻辑推理 (假设输入与输出):**  当 Blink 渲染引擎遇到这段 CSS 时，会解析出线性渐变的起始点（左侧中心），结束点（右侧中心），以及颜色停止点 (红色在 0%，蓝色在 100%)。 `LinearGradient` 类会根据这些信息创建相应的 Skia 线性渐变着色器。
    * **`radial-gradient()`:** 对应 `RadialGradient` 类。
        ```css
        /* 假设输入 CSS */
        .element {
          background-image: radial-gradient(circle at 50% 50%, yellow, green);
        }
        ```
        **逻辑推理 (假设输入与输出):**  Blink 会解析出中心点坐标 (50%, 50%)，形状 (circle)，以及颜色停止点 (黄色在 0%，绿色在 100%)。 `RadialGradient` 类会据此生成 Skia 的径向渐变着色器。
    * **`conic-gradient()`:** 对应 `ConicGradient` 类。
        ```css
        /* 假设输入 CSS */
        .element {
          background-image: conic-gradient(from 90deg, purple, orange);
        }
        ```
        **逻辑推理 (假设输入与输出):** Blink 会解析出中心点（默认为元素中心），起始角度 (90deg)，以及颜色停止点 (紫色在 0%，橙色在 100%)。 `ConicGradient` 类将负责创建 Skia 的圆锥渐变着色器。
    * **`background-repeat` 等属性：**  CSS 的 `background-repeat` 属性（`repeat`, `space`, `round`, `no-repeat`) 可以影响渐变的平铺方式，这与 `GradientSpreadMethod` 枚举中的值（`kSpreadMethodRepeat`, `kSpreadMethodReflect`, `kSpreadMethodPad`) 相关联。

* **HTML：**  HTML 元素可以通过 CSS 样式应用渐变背景。
    ```html
    <div style="background-image: linear-gradient(red, yellow);"></div>
    ```

* **JavaScript：**  JavaScript 可以通过操作元素的 `style` 属性来动态设置渐变，或者在 Canvas API 中使用渐变。
    ```javascript
    // 通过 JavaScript 设置渐变
    document.getElementById('myDiv').style.backgroundImage = 'radial-gradient(red, green)';

    // 在 Canvas 中使用渐
Prompt: 
```
这是目录为blink/renderer/platform/graphics/gradient.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/graphics/gradient.h"

#include <algorithm>
#include <optional>

#include "third_party/blink/renderer/platform/geometry/blend.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_settings_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_shader.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkMatrix.h"
#include "third_party/skia/include/core/SkShader.h"
#include "third_party/skia/include/effects/SkGradientShader.h"

namespace blink {

Gradient::Gradient(Type type,
                   GradientSpreadMethod spread_method,
                   ColorInterpolation interpolation,
                   DegenerateHandling degenerate_handling)
    : type_(type),
      spread_method_(spread_method),
      color_interpolation_(interpolation),
      degenerate_handling_(degenerate_handling),
      stops_sorted_(true) {}

Gradient::~Gradient() = default;

static inline bool CompareStops(const Gradient::ColorStop& a,
                                const Gradient::ColorStop& b) {
  return a.stop < b.stop;
}

void Gradient::AddColorStop(const Gradient::ColorStop& stop) {
  if (stops_.empty()) {
    stops_sorted_ = true;
  } else {
    stops_sorted_ = stops_sorted_ && CompareStops(stops_.back(), stop);
  }

  stops_.push_back(stop);
  cached_shader_.reset();
}

void Gradient::AddColorStops(const Vector<Gradient::ColorStop>& stops) {
  for (const auto& stop : stops) {
    AddColorStop(stop);
  }
}

void Gradient::SortStopsIfNecessary() const {
  if (stops_sorted_)
    return;

  stops_sorted_ = true;

  if (!stops_.size())
    return;

  std::stable_sort(stops_.begin(), stops_.end(), CompareStops);
}

static SkColor4f ResolveStopColorWithMissingParams(
    const Color& color,
    const Color& neighbor,
    Color::ColorSpace color_space,
    const cc::ColorFilter* color_filter) {
  std::optional<float> param0 =
      color.Param0IsNone() ? neighbor.Param0() : color.Param0();
  std::optional<float> param1 =
      color.Param1IsNone() ? neighbor.Param1() : color.Param1();
  std::optional<float> param2 =
      color.Param2IsNone() ? neighbor.Param2() : color.Param2();
  std::optional<float> alpha =
      color.AlphaIsNone() ? neighbor.Alpha() : color.Alpha();
  Color resolved_color =
      Color::FromColorSpace(color_space, param0, param1, param2, alpha);
  if (color_filter) {
    return color_filter->FilterColor(
        resolved_color.ToGradientStopSkColor4f(color_space));
  }
  return resolved_color.ToGradientStopSkColor4f(color_space);
}

// Collect sorted stop position and color information into the pos and colors
// buffers, ensuring stops at both 0.0 and 1.0.
// TODO(fmalita): theoretically Skia should provide the same 0.0/1.0 padding
// (making this logic redundant), but in practice there are rendering diffs;
// investigate.
void Gradient::FillSkiaStops(ColorBuffer& colors, OffsetBuffer& pos) const {
  if (stops_.empty()) {
    // A gradient with no stops must be transparent black.
    pos.push_back(WebCoreDoubleToSkScalar(0));
    colors.push_back(SkColors::kTransparent);
  } else if (stops_.front().stop > 0) {
    // Copy the first stop to 0.0. The first stop position may have a slight
    // rounding error, but we don't care in this float comparison, since
    // 0.0 comes through cleanly and people aren't likely to want a gradient
    // with a stop at (0 + epsilon).
    pos.push_back(WebCoreDoubleToSkScalar(0));
    if (color_filter_) {
      colors.push_back(color_filter_->FilterColor(
          stops_.front().color.ToGradientStopSkColor4f(
              color_space_interpolation_space_)));
    } else {
      colors.push_back(stops_.front().color.ToGradientStopSkColor4f(
          color_space_interpolation_space_));
    }
  }

  // Deal with none parameters.
  for (wtf_size_t i = 0; i < stops_.size(); i++) {
    Color color = stops_[i].color;
    color.ConvertToColorSpace(color_space_interpolation_space_);
    if (color.HasNoneParams()) {
      if (i != 0) {
        // Fill left
        pos.push_back(WebCoreDoubleToSkScalar(stops_[i].stop));
        colors.push_back(ResolveStopColorWithMissingParams(
            color, stops_[i - 1].color, color_space_interpolation_space_,
            color_filter_.get()));
      }

      if (i != stops_.size() - 1) {
        // Fill right
        pos.push_back(WebCoreDoubleToSkScalar(stops_[i].stop));
        colors.push_back(ResolveStopColorWithMissingParams(
            color, stops_[i + 1].color, color_space_interpolation_space_,
            color_filter_.get()));
      }
    } else {
      pos.push_back(WebCoreDoubleToSkScalar(stops_[i].stop));
      if (color_filter_) {
        colors.push_back(
            color_filter_->FilterColor(stops_[i].color.ToGradientStopSkColor4f(
                color_space_interpolation_space_)));
      } else {
        colors.push_back(stops_[i].color.ToGradientStopSkColor4f(
            color_space_interpolation_space_));
      }
    }
  }

  // Copy the last stop to 1.0 if needed. See comment above about this float
  // comparison.
  DCHECK(!pos.empty());
  if (pos.back() < 1) {
    pos.push_back(WebCoreDoubleToSkScalar(1));
    colors.push_back(colors.back());
  }
}

SkGradientShader::Interpolation Gradient::ResolveSkInterpolation() const {
  using sk_colorspace = SkGradientShader::Interpolation::ColorSpace;
  using sk_hue_method = SkGradientShader::Interpolation::HueMethod;
  SkGradientShader::Interpolation sk_interpolation;

  bool has_non_legacy_color = false;
  switch (color_space_interpolation_space_) {
    case Color::ColorSpace::kXYZD65:
    case Color::ColorSpace::kXYZD50:
    case Color::ColorSpace::kSRGBLinear:
      sk_interpolation.fColorSpace = sk_colorspace::kSRGBLinear;
      break;
    case Color::ColorSpace::kLab:
      sk_interpolation.fColorSpace = sk_colorspace::kLab;
      break;
    case Color::ColorSpace::kOklab:
      sk_interpolation.fColorSpace = Color::IsBakedGamutMappingEnabled()
                                         ? sk_colorspace::kOKLabGamutMap
                                         : sk_colorspace::kOKLab;
      break;
    case Color::ColorSpace::kLch:
      sk_interpolation.fColorSpace = sk_colorspace::kLCH;
      break;
    case Color::ColorSpace::kOklch:
      sk_interpolation.fColorSpace = Color::IsBakedGamutMappingEnabled()
                                         ? sk_colorspace::kOKLCHGamutMap
                                         : sk_colorspace::kOKLCH;
      break;
    case Color::ColorSpace::kSRGB:
    case Color::ColorSpace::kSRGBLegacy:
      sk_interpolation.fColorSpace = sk_colorspace::kSRGB;
      break;
    case Color::ColorSpace::kHSL:
      sk_interpolation.fColorSpace = sk_colorspace::kHSL;
      break;
    case Color::ColorSpace::kHWB:
      sk_interpolation.fColorSpace = sk_colorspace::kHWB;
      break;
    case Color::ColorSpace::kNone:
      for (const auto& stop : stops_) {
        if (!Color::IsLegacyColorSpace(stop.color.GetColorSpace())) {
          has_non_legacy_color = true;
        }
      }
      if (has_non_legacy_color) {
        // If no colorspace is provided and the gradient is not entirely
        // composed of legacy colors, Oklab is the default interpolation space.
        sk_interpolation.fColorSpace = Color::IsBakedGamutMappingEnabled()
                                           ? sk_colorspace::kOKLabGamutMap
                                           : sk_colorspace::kOKLab;
      } else {
        // TODO(crbug.com/1379462): This should be kSRGB.
        sk_interpolation.fColorSpace = sk_colorspace::kDestination;
      }
      break;
    // We do not yet support interpolation in these spaces.
    case Color::ColorSpace::kDisplayP3:
    case Color::ColorSpace::kA98RGB:
    case Color::ColorSpace::kProPhotoRGB:
    case Color::ColorSpace::kRec2020:
      NOTREACHED();
  }

  switch (hue_interpolation_method_) {
    case Color::HueInterpolationMethod::kLonger:
      sk_interpolation.fHueMethod = sk_hue_method::kLonger;
      break;
    case Color::HueInterpolationMethod::kIncreasing:
      sk_interpolation.fHueMethod = sk_hue_method::kIncreasing;
      break;
    case Color::HueInterpolationMethod::kDecreasing:
      sk_interpolation.fHueMethod = sk_hue_method::kDecreasing;
      break;
    default:
      sk_interpolation.fHueMethod = sk_hue_method::kShorter;
  }

  sk_interpolation.fInPremul =
      (color_interpolation_ == ColorInterpolation::kPremultiplied)
          ? SkGradientShader::Interpolation::InPremul::kYes
          : SkGradientShader::Interpolation::InPremul::kNo;

  return sk_interpolation;
}

sk_sp<PaintShader> Gradient::CreateShaderInternal(
    const SkMatrix& local_matrix) {
  SortStopsIfNecessary();
  DCHECK(stops_sorted_);

  ColorBuffer colors;
  colors.reserve(stops_.size());
  OffsetBuffer pos;
  pos.reserve(stops_.size());

  FillSkiaStops(colors, pos);
  DCHECK_GE(colors.size(), 2ul);
  DCHECK_EQ(pos.size(), colors.size());

  SkTileMode tile = SkTileMode::kClamp;
  switch (spread_method_) {
    case kSpreadMethodReflect:
      tile = SkTileMode::kMirror;
      break;
    case kSpreadMethodRepeat:
      tile = SkTileMode::kRepeat;
      break;
    case kSpreadMethodPad:
      tile = SkTileMode::kClamp;
      break;
  }

  if (is_dark_mode_enabled_) {
    for (auto& color : colors) {
      color = EnsureDarkModeFilter().InvertColorIfNeeded(
          color, DarkModeFilter::ElementRole::kBackground);
    }
  }
  sk_sp<PaintShader> shader = CreateShader(
      colors, pos, tile, ResolveSkInterpolation(), local_matrix, colors.back());
  DCHECK(shader);

  return shader;
}

void Gradient::ApplyToFlags(cc::PaintFlags& flags,
                            const SkMatrix& local_matrix,
                            const ImageDrawOptions& draw_options) {
  if (is_dark_mode_enabled_ != draw_options.apply_dark_mode) {
    is_dark_mode_enabled_ = draw_options.apply_dark_mode;
    cached_shader_.reset();
  }
  if (!cached_shader_ || local_matrix != cached_shader_->GetLocalMatrix() ||
      flags.getColorFilter().get() != color_filter_.get()) {
    color_filter_ = flags.getColorFilter();
    flags.setColorFilter(nullptr);
    cached_shader_ = CreateShaderInternal(local_matrix);
  }

  flags.setShader(cached_shader_);

  // Legacy behavior: gradients are always dithered.
  flags.setDither(true);
}

DarkModeFilter& Gradient::EnsureDarkModeFilter() {
  if (!dark_mode_filter_) {
    dark_mode_filter_ =
        std::make_unique<DarkModeFilter>(GetCurrentDarkModeSettings());
  }
  return *dark_mode_filter_;
}

namespace {

class LinearGradient final : public Gradient {
 public:
  LinearGradient(const gfx::PointF& p0,
                 const gfx::PointF& p1,
                 GradientSpreadMethod spread_method,
                 ColorInterpolation interpolation,
                 DegenerateHandling degenerate_handling)
      : Gradient(Type::kLinear,
                 spread_method,
                 interpolation,
                 degenerate_handling),
        p0_(p0),
        p1_(p1) {}

 protected:
  sk_sp<PaintShader> CreateShader(const ColorBuffer& colors,
                                  const OffsetBuffer& pos,
                                  SkTileMode tile_mode,
                                  SkGradientShader::Interpolation interpolation,
                                  const SkMatrix& local_matrix,
                                  SkColor4f fallback_color) const override {
    if (GetDegenerateHandling() == DegenerateHandling::kDisallow &&
        p0_ == p1_) {
      return PaintShader::MakeEmpty();
    }

    SkPoint pts[2] = {FloatPointToSkPoint(p0_), FloatPointToSkPoint(p1_)};
    return PaintShader::MakeLinearGradient(
        pts, colors.data(), pos.data(), static_cast<int>(colors.size()),
        tile_mode, interpolation, 0 /* flags */, &local_matrix, fallback_color);
  }

 private:
  const gfx::PointF p0_;
  const gfx::PointF p1_;
};

class RadialGradient final : public Gradient {
 public:
  RadialGradient(const gfx::PointF& p0,
                 float r0,
                 const gfx::PointF& p1,
                 float r1,
                 float aspect_ratio,
                 GradientSpreadMethod spread_method,
                 ColorInterpolation interpolation,
                 DegenerateHandling degenerate_handling)
      : Gradient(Type::kRadial,
                 spread_method,
                 interpolation,
                 degenerate_handling),
        p0_(p0),
        p1_(p1),
        r0_(r0),
        r1_(r1),
        aspect_ratio_(aspect_ratio) {}

 protected:
  sk_sp<PaintShader> CreateShader(const ColorBuffer& colors,
                                  const OffsetBuffer& pos,
                                  SkTileMode tile_mode,
                                  SkGradientShader::Interpolation interpolation,
                                  const SkMatrix& local_matrix,
                                  SkColor4f fallback_color) const override {
    const SkMatrix* matrix = &local_matrix;
    std::optional<SkMatrix> adjusted_local_matrix;
    if (aspect_ratio_ != 1) {
      // CSS3 elliptical gradients: apply the elliptical scaling at the
      // gradient center point.
      DCHECK(p0_ == p1_);
      adjusted_local_matrix.emplace(local_matrix);
      adjusted_local_matrix->preScale(1, 1 / aspect_ratio_, p0_.x(), p0_.y());
      matrix = &*adjusted_local_matrix;
    }

    // The radii we give to Skia must be positive. If we're given a
    // negative radius, ask for zero instead.
    const SkScalar radius0 = std::max(WebCoreFloatToSkScalar(r0_), 0.0f);
    const SkScalar radius1 = std::max(WebCoreFloatToSkScalar(r1_), 0.0f);

    if (GetDegenerateHandling() == DegenerateHandling::kDisallow &&
        p0_ == p1_ && radius0 == radius1) {
      return PaintShader::MakeEmpty();
    }

    return PaintShader::MakeTwoPointConicalGradient(
        FloatPointToSkPoint(p0_), radius0, FloatPointToSkPoint(p1_), radius1,
        colors.data(), pos.data(), static_cast<int>(colors.size()), tile_mode,
        interpolation, 0 /* flags */, matrix, fallback_color);
  }

 private:
  const gfx::PointF p0_;
  const gfx::PointF p1_;
  const float r0_;
  const float r1_;
  const float aspect_ratio_;  // For elliptical gradient, width / height.
};

class ConicGradient final : public Gradient {
 public:
  ConicGradient(const gfx::PointF& position,
                float rotation,
                float start_angle,
                float end_angle,
                GradientSpreadMethod spread_method,
                ColorInterpolation interpolation,
                DegenerateHandling degenerate_handling)
      : Gradient(Type::kConic,
                 spread_method,
                 interpolation,
                 degenerate_handling),
        position_(position),
        rotation_(rotation),
        start_angle_(start_angle),
        end_angle_(end_angle) {}

 protected:
  sk_sp<PaintShader> CreateShader(const ColorBuffer& colors,
                                  const OffsetBuffer& pos,
                                  SkTileMode tile_mode,
                                  SkGradientShader::Interpolation interpolation,
                                  const SkMatrix& local_matrix,
                                  SkColor4f fallback_color) const override {
    if (GetDegenerateHandling() == DegenerateHandling::kDisallow &&
        start_angle_ == end_angle_) {
      return PaintShader::MakeEmpty();
    }

    // Skia's sweep gradient angles are relative to the x-axis, not the y-axis.
    const float skia_rotation = rotation_ - 90;
    const SkMatrix* matrix = &local_matrix;
    std::optional<SkMatrix> adjusted_local_matrix;
    if (skia_rotation) {
      adjusted_local_matrix.emplace(local_matrix);
      adjusted_local_matrix->preRotate(skia_rotation, position_.x(),
                                       position_.y());
      matrix = &*adjusted_local_matrix;
    }

    return PaintShader::MakeSweepGradient(
        position_.x(), position_.y(), colors.data(), pos.data(),
        static_cast<int>(colors.size()), tile_mode, start_angle_, end_angle_,
        interpolation, 0 /* flags */, matrix, fallback_color);
  }

 private:
  const gfx::PointF position_;  // center point
  const float rotation_;       // global rotation (deg)
  const float start_angle_;    // angle (deg) corresponding to color position 0
  const float end_angle_;      // angle (deg) corresponding to color position 1
};

}  // namespace

scoped_refptr<Gradient> Gradient::CreateLinear(
    const gfx::PointF& p0,
    const gfx::PointF& p1,
    GradientSpreadMethod spread_method,
    ColorInterpolation interpolation,
    DegenerateHandling degenerate_handling) {
  return base::AdoptRef(new LinearGradient(p0, p1, spread_method, interpolation,
                                           degenerate_handling));
}

scoped_refptr<Gradient> Gradient::CreateRadial(
    const gfx::PointF& p0,
    float r0,
    const gfx::PointF& p1,
    float r1,
    float aspect_ratio,
    GradientSpreadMethod spread_method,
    ColorInterpolation interpolation,
    DegenerateHandling degenerate_handling) {
  return base::AdoptRef(new RadialGradient(p0, r0, p1, r1, aspect_ratio,
                                           spread_method, interpolation,
                                           degenerate_handling));
}

scoped_refptr<Gradient> Gradient::CreateConic(
    const gfx::PointF& position,
    float rotation,
    float start_angle,
    float end_angle,
    GradientSpreadMethod spread_method,
    ColorInterpolation interpolation,
    DegenerateHandling degenerate_handling) {
  return base::AdoptRef(new ConicGradient(position, rotation, start_angle,
                                          end_angle, spread_method,
                                          interpolation, degenerate_handling));
}

}  // namespace blink

"""

```