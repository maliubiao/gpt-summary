Response:
The user wants to understand the functionality of the provided C++ code snippet from `css_gradient_value.cc`. This is the second part of a three-part request, so I should focus on summarizing the functionality presented in this specific part.

Here's a breakdown of the code's functionality:

1. **`CSSLinearGradientValue`**: Deals with linear gradients.
    *   `CustomCSSText()`: Generates the CSS text representation of the linear gradient. It handles different syntax variations (prefixed, deprecated).
    *   `EndPointsFromAngle()`: Calculates the start and end points of a linear gradient based on an angle.
    *   `CreateGradient()`: Creates a `Gradient` object (likely for rendering) based on the linear gradient's properties. It handles different ways of defining the gradient line (angle, start/end points).
    *   `Equals()`: Checks if two `CSSLinearGradientValue` objects are equivalent.
    *   `ComputedCSSValue()`: Creates a computed value representation of the linear gradient.
    *   `IsUsingCurrentColor()` and `IsUsingContainerRelativeUnits()`: Checks if the gradient uses `currentColor` or container-relative units.
    *   `TraceAfterDispatch()`: Used for garbage collection.

2. **`CSSGradientValue` (Helper Methods)**:
    *   `AppendCSSTextForColorStops()`: Appends the CSS text for the color stops of a gradient.
    *   `AppendCSSTextForDeprecatedColorStops()`: Handles deprecated syntax for color stops.
    *   `Equals()`:  Base equality check for gradient properties.

3. **`CSSRadialGradientValue`**: Handles radial gradients.
    *   `CustomCSSText()`: Generates the CSS text for radial gradients, handling various syntax options (prefixed, deprecated, with/without explicit size/shape).
    *   `ResolveRadius()`: Calculates the radius value from CSS values.
    *   `RadiusToSide()` and `RadiusToCorner()`: Calculate radii based on keywords like `closest-side`, `farthest-corner`, etc.
    *   `EllipseRadius()`: Calculates the radii of an ellipse.
    *   `CreateGradient()`: Creates a `Gradient` object for radial gradients, handling different ways to define the size and position.
    *   `Equals()`: Checks if two `CSSRadialGradientValue` objects are equal.
    *   `ComputedCSSValue()`: Creates a computed value for radial gradients.
    *   `IsUsingCurrentColor()` and `IsUsingContainerRelativeUnits()`: Checks for `currentColor` and container units.
    *   `TraceAfterDispatch()`: For garbage collection.

4. **`CSSConicGradientValue`**: Deals with conic gradients.
    *   `CustomCSSText()`: Generates the CSS text for conic gradients.
    *   `CreateGradient()`: Creates a `Gradient` object for conic gradients.
    *   `Equals()`: Checks equality of conic gradients.
    *   `ComputedCSSValue()`: Creates a computed value for conic gradients.
    *   `IsUsingCurrentColor()` and `IsUsingContainerRelativeUnits()`: Checks for `currentColor` and container units.
    *   `TraceAfterDispatch()`: For garbage collection.

**Overall Functionality of this Snippet:**

This section of the code focuses on the **representation and manipulation of different types of CSS gradients (linear, radial, and conic)** within the Blink rendering engine. It provides methods for:

*   **Generating the CSS text representation** of gradient values.
*   **Creating internal `Gradient` objects** that are used for the actual rendering of the gradients. This involves calculating the necessary parameters like start/end points, radii, and angles.
*   **Comparing gradient values for equality**.
*   **Creating computed style values** for gradients.
*   **Checking if gradients use specific CSS features** like `currentColor` or container-relative units.
*   **Supporting both modern and deprecated syntax** for defining gradients.
这段代码主要负责 **`CSSLinearGradientValue`**, **`CSSRadialGradientValue`** 和 **`CSSConicGradientValue`** 这三种具体的 CSS 渐变类型的功能实现， 包括：

1. **CSS 文本生成:**  为这三种渐变类型生成对应的 CSS 文本表示形式 (`CustomCSSText()` 方法)。这包括处理不同的语法变体，例如旧的 `-webkit-gradient` 语法和新的标准语法，以及 `repeating-` 关键字。

2. **创建 `Gradient` 对象:**  负责将 `CSSLinearGradientValue`，`CSSRadialGradientValue` 和 `CSSConicGradientValue` 对象的信息转换为内部的 `Gradient` 对象 (`CreateGradient()` 方法)。这个 `Gradient` 对象很可能用于后续的渲染过程。这个过程涉及到：
    *   **计算渐变的端点和角度 (线性渐变):**  根据不同的属性 (例如 `angle`, `to top`, `to right`) 计算出线性渐变的起始和终止点。
    *   **计算渐变的中心点和半径 (径向渐变):** 根据不同的属性 (`circle`, `ellipse`, `closest-side`, `farthest-corner` 等) 计算出径向渐变的中心点和半径。
    *   **计算渐变的起始角度和中心点 (锥形渐变):** 根据 `from` 属性和位置属性计算锥形渐变的起始角度和中心点。
    *   **处理颜色停止点:**  将 `stops_` 中定义的颜色停止点添加到 `Gradient` 对象中。

3. **比较相等性:**  提供了 `Equals()` 方法来比较两个相同类型的渐变值对象是否相等，包括比较各种属性值和颜色停止点。

4. **创建 Computed CSS Value:** 提供了 `ComputedCSSValue()` 方法，用于在计算样式时创建新的、可能包含计算后值的渐变对象。

5. **检查 `currentColor` 和容器相对单位的使用:** 提供了 `IsUsingCurrentColor()` 和 `IsUsingContainerRelativeUnits()` 方法来检查渐变定义中是否使用了 `currentColor` 关键字或者容器相对长度单位。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **CSS:** 这段代码的核心功能是解析和处理 CSS 渐变相关的语法和属性。例如，`CustomCSSText()` 生成的字符串可以直接用于 CSS 样式表，`CreateGradient()` 解析的 CSS 属性值如 `linear-gradient(to right, red, blue)`， `radial-gradient(circle at center, green, yellow)` 等。
*   **HTML:** HTML 元素通过 CSS 样式来应用渐变效果。例如，一个 `<div>` 元素的 `background-image` 属性可以设置为一个渐变值，如 `background-image: linear-gradient(red, blue);`。Blink 引擎会解析这个 CSS 属性值，并最终调用这段代码来创建渲染所需的 `Gradient` 对象。
*   **JavaScript:** JavaScript 可以通过 DOM API 修改元素的 style 属性，从而动态地改变元素的背景渐变。例如，`element.style.backgroundImage = 'radial-gradient(green, yellow)';`。当 JavaScript 改变样式后，Blink 引擎会重新解析 CSS 并执行相应的代码，包括这段 `css_gradient_value.cc` 中的代码。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `CSSLinearGradientValue::CreateGradient`)**:

*   `angle_`: 一个表示角度的 `CSSValue` 对象，例如 `CSSPrimitiveValue::CreateIdentifier(CSSValueID::k45deg)`。
*   `size`: 一个 `gfx::SizeF` 对象，表示应用渐变的元素的尺寸，例如 `{100, 200}`。

**输出:**

*   一个指向 `Gradient` 对象的智能指针，该对象表示一个 45 度角的线性渐变，其起始和终止点已经根据元素尺寸计算出来。

**用户或编程常见的使用错误举例:**

*   **颜色停止点位置错误:** 用户在 CSS 中定义渐变时，颜色停止点的位置可能超出 0% 到 100% 的范围，或者定义顺序不正确。例如：`linear-gradient(red 120%, blue -10%);`。这段代码在处理颜色停止点时可能需要进行 clamping 或错误处理。
*   **径向渐变尺寸定义冲突:** 用户可能同时定义了 `shape` 和明确的 `size`，导致定义冲突。例如：`radial-gradient(circle 100px 200px, red, blue);`。这段代码需要处理这种不明确的定义。
*   **旧语法与新语法混用:** 用户可能在新的浏览器中使用旧的 `-webkit-gradient` 语法，或者在新语法中错误地使用了旧语法的概念。这段代码需要正确解析和处理这些不同的语法。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在 HTML 文件中编写 CSS 样式:** 例如，在 `<style>` 标签或外部 CSS 文件中定义了一个带有渐变背景的元素，如 `div { background-image: linear-gradient(red, blue); }`。
2. **用户在浏览器中打开该 HTML 文件:** 浏览器开始解析 HTML 和 CSS。
3. **Blink 引擎的 CSS 解析器解析到 `background-image` 属性:**  识别出 `linear-gradient(red, blue)` 是一个 `CSSLinearGradientValue`。
4. **Layout 阶段:**  当需要确定 `div` 元素的渲染方式时，Blink 引擎会请求该元素的 computed style。
5. **调用 `CSSLinearGradientValue::ComputedCSSValue()`:** 创建一个计算后的渐变值。
6. **渲染阶段:** 当需要绘制 `div` 元素的背景时，会调用 `CSSLinearGradientValue::CreateGradient()` 方法。
7. **`CreateGradient()` 方法内部的代码执行，包括 `EndPointsFromAngle()` 等:**  根据渐变的定义和元素的尺寸，计算出渐变的具体参数，并创建一个 `Gradient` 对象。
8. **`Gradient` 对象被用于实际的图形绘制。**

作为调试线索，如果渐变显示不正确，开发者可以通过浏览器的开发者工具查看元素的 computed style，检查生成的 `CSSLinearGradientValue` 或 `CSSRadialGradientValue` 对象是否符合预期。如果 computed style 中的值不正确，则可能是 CSS 解析或计算阶段出现了问题，需要回溯到 CSS 解析器的代码。如果 computed style 正确，但渲染结果不正确，则可能是 `CreateGradient()` 方法中的计算逻辑有问题，或者更底层的渲染代码出现了错误。

**归纳其功能:**

总而言之，这段 `css_gradient_value.cc` 代码的主要功能是 **实现了 CSS 线性渐变、径向渐变和锥形渐变的表示、解析、计算和转换成可用于渲染的内部数据结构 `Gradient`。** 它负责处理各种 CSS 渐变语法，并为后续的渲染过程提供必要的信息。

### 提示词
```
这是目录为blink/renderer/core/css/css_gradient_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
d_style, value_phase);
    case kConstantGradientClass:
      return To<CSSConstantGradientValue>(this)->ComputedCSSValue(
          style, allow_visited_style, value_phase);
    default:
      NOTREACHED();
  }
}

Vector<Color> CSSGradientValue::GetStopColors(
    const Document& document,
    const ComputedStyle& style) const {
  Vector<Color> stop_colors;
  for (const auto& stop : stops_) {
    if (!stop.IsHint()) {
      // TODO(40946458): Don't use default length resolver here!
      stop_colors.push_back(
          ResolveStopColor(CSSToLengthConversionData(/*element=*/nullptr),
                           *stop.color_, document, style));
    }
  }
  return stop_colors;
}

void CSSGradientValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(stops_);
  CSSImageGeneratorValue::TraceAfterDispatch(visitor);
}

bool CSSGradientValue::ShouldSerializeColorSpace() const {
  if (color_interpolation_space_ == Color::ColorSpace::kNone) {
    return false;
  }

  bool has_only_legacy_colors =
      base::ranges::all_of(stops_, [](const CSSGradientColorStop& stop) {
        const auto* color_value =
            DynamicTo<cssvalue::CSSColor>(stop.color_.Get());
        return !color_value ||
               Color::IsLegacyColorSpace(color_value->Value().GetColorSpace());
      });

  // OKLab is the default and should not be serialized unless all colors are
  // legacy colors.
  if (!has_only_legacy_colors &&
      color_interpolation_space_ == Color::ColorSpace::kOklab) {
    return false;
  }

  // sRGB is the default if all colors are legacy colors and should not be
  // serialized.
  if (has_only_legacy_colors &&
      color_interpolation_space_ == Color::ColorSpace::kSRGB) {
    return false;
  }

  return true;
}

String CSSLinearGradientValue::CustomCSSText() const {
  StringBuilder result;
  if (gradient_type_ == kCSSDeprecatedLinearGradient) {
    result.Append("-webkit-gradient(linear, ");
    result.Append(first_x_->CssText());
    result.Append(' ');
    result.Append(first_y_->CssText());
    result.Append(", ");
    result.Append(second_x_->CssText());
    result.Append(' ');
    result.Append(second_y_->CssText());
    AppendCSSTextForDeprecatedColorStops(result);
  } else if (gradient_type_ == kCSSPrefixedLinearGradient) {
    if (repeating_) {
      result.Append("-webkit-repeating-linear-gradient(");
    } else {
      result.Append("-webkit-linear-gradient(");
    }

    if (angle_) {
      result.Append(angle_->CssText());
    } else {
      if (first_x_ && first_y_) {
        result.Append(first_x_->CssText());
        result.Append(' ');
        result.Append(first_y_->CssText());
      } else if (first_x_ || first_y_) {
        if (first_x_) {
          result.Append(first_x_->CssText());
        }

        if (first_y_) {
          result.Append(first_y_->CssText());
        }
      }
    }

    constexpr bool kAppendSeparator = true;
    AppendCSSTextForColorStops(result, kAppendSeparator);
  } else {
    if (repeating_) {
      result.Append("repeating-linear-gradient(");
    } else {
      result.Append("linear-gradient(");
    }

    bool wrote_something = false;

    if (angle_ &&
        (angle_->IsMathFunctionValue() ||
         (angle_->IsNumericLiteralValue() &&
          To<CSSNumericLiteralValue>(*angle_).ComputeDegrees() != 180))) {
      result.Append(angle_->CssText());
      wrote_something = true;
    } else if ((first_x_ || first_y_) &&
               !(!first_x_ && first_y_ && first_y_->IsIdentifierValue() &&
                 To<CSSIdentifierValue>(first_y_.Get())->GetValueID() ==
                     CSSValueID::kBottom)) {
      result.Append("to ");
      if (first_x_ && first_y_) {
        result.Append(first_x_->CssText());
        result.Append(' ');
        result.Append(first_y_->CssText());
      } else if (first_x_) {
        result.Append(first_x_->CssText());
      } else {
        result.Append(first_y_->CssText());
      }
      wrote_something = true;
    }

    if (ShouldSerializeColorSpace()) {
      if (wrote_something) {
        result.Append(" ");
      }
      wrote_something = true;
      result.Append("in ");
      result.Append(Color::SerializeInterpolationSpace(
          color_interpolation_space_, hue_interpolation_method_));
    }

    AppendCSSTextForColorStops(result, wrote_something);
  }

  result.Append(')');
  return result.ReleaseString();
}

// Compute the endpoints so that a gradient of the given angle covers a box of
// the given size.
static void EndPointsFromAngle(float angle_deg,
                               const gfx::SizeF& size,
                               gfx::PointF& first_point,
                               gfx::PointF& second_point,
                               CSSGradientType type) {
  // Prefixed gradients use "polar coordinate" angles, rather than "bearing"
  // angles.
  if (type == kCSSPrefixedLinearGradient) {
    angle_deg = 90 - angle_deg;
  }

  angle_deg = fmodf(angle_deg, 360);
  if (angle_deg < 0) {
    angle_deg += 360;
  }

  if (!angle_deg) {
    first_point.SetPoint(0, size.height());
    second_point.SetPoint(0, 0);
    return;
  }

  if (angle_deg == 90) {
    first_point.SetPoint(0, 0);
    second_point.SetPoint(size.width(), 0);
    return;
  }

  if (angle_deg == 180) {
    first_point.SetPoint(0, 0);
    second_point.SetPoint(0, size.height());
    return;
  }

  if (angle_deg == 270) {
    first_point.SetPoint(size.width(), 0);
    second_point.SetPoint(0, 0);
    return;
  }

  // angleDeg is a "bearing angle" (0deg = N, 90deg = E),
  // but tan expects 0deg = E, 90deg = N.
  float slope = tan(Deg2rad(90 - angle_deg));

  // We find the endpoint by computing the intersection of the line formed by
  // the slope, and a line perpendicular to it that intersects the corner.
  float perpendicular_slope = -1 / slope;

  // Compute start corner relative to center, in Cartesian space (+y = up).
  float half_height = size.height() / 2;
  float half_width = size.width() / 2;
  gfx::PointF end_corner;
  if (angle_deg < 90) {
    end_corner.SetPoint(half_width, half_height);
  } else if (angle_deg < 180) {
    end_corner.SetPoint(half_width, -half_height);
  } else if (angle_deg < 270) {
    end_corner.SetPoint(-half_width, -half_height);
  } else {
    end_corner.SetPoint(-half_width, half_height);
  }

  // Compute c (of y = mx + c) using the corner point.
  float c = end_corner.y() - perpendicular_slope * end_corner.x();
  float end_x = c / (slope - perpendicular_slope);
  float end_y = perpendicular_slope * end_x + c;

  // We computed the end point, so set the second point, taking into account the
  // moved origin and the fact that we're in drawing space (+y = down).
  second_point.SetPoint(half_width + end_x, half_height - end_y);
  // Reflect around the center for the start point.
  first_point.SetPoint(half_width - end_x, half_height + end_y);
}

scoped_refptr<Gradient> CSSLinearGradientValue::CreateGradient(
    const CSSToLengthConversionData& conversion_data,
    const gfx::SizeF& size,
    const Document& document,
    const ComputedStyle& style) const {
  DCHECK(!size.IsEmpty());

  gfx::PointF first_point;
  gfx::PointF second_point;
  if (angle_) {
    float angle = angle_->ComputeDegrees(conversion_data);
    EndPointsFromAngle(angle, size, first_point, second_point, gradient_type_);
  } else {
    switch (gradient_type_) {
      case kCSSDeprecatedLinearGradient:
        first_point = ComputeEndPoint(first_x_.Get(), first_y_.Get(),
                                      conversion_data, size);
        if (second_x_ || second_y_) {
          second_point = ComputeEndPoint(second_x_.Get(), second_y_.Get(),
                                         conversion_data, size);
        } else {
          if (first_x_) {
            second_point.set_x(size.width() - first_point.x());
          }
          if (first_y_) {
            second_point.set_y(size.height() - first_point.y());
          }
        }
        break;
      case kCSSPrefixedLinearGradient:
        first_point = ComputeEndPoint(first_x_.Get(), first_y_.Get(),
                                      conversion_data, size);
        if (first_x_) {
          second_point.set_x(size.width() - first_point.x());
        }
        if (first_y_) {
          second_point.set_y(size.height() - first_point.y());
        }
        break;
      case kCSSLinearGradient:
        if (first_x_ && first_y_) {
          // "Magic" corners, so the 50% line touches two corners.
          float rise = size.width();
          float run = size.height();
          auto* first_x_identifier_value =
              DynamicTo<CSSIdentifierValue>(first_x_.Get());
          if (first_x_identifier_value &&
              first_x_identifier_value->GetValueID() == CSSValueID::kLeft) {
            run *= -1;
          }
          auto* first_y_identifier_value =
              DynamicTo<CSSIdentifierValue>(first_y_.Get());
          if (first_y_identifier_value &&
              first_y_identifier_value->GetValueID() == CSSValueID::kBottom) {
            rise *= -1;
          }
          // Compute angle, and flip it back to "bearing angle" degrees.
          float angle = 90 - Rad2deg(atan2(rise, run));
          EndPointsFromAngle(angle, size, first_point, second_point,
                             gradient_type_);
        } else if (first_x_ || first_y_) {
          second_point = ComputeEndPoint(first_x_.Get(), first_y_.Get(),
                                         conversion_data, size);
          if (first_x_) {
            first_point.set_x(size.width() - second_point.x());
          }
          if (first_y_) {
            first_point.set_y(size.height() - second_point.y());
          }
        } else {
          second_point.set_y(size.height());
        }
        break;
      default:
        NOTREACHED();
    }
  }

  GradientDesc desc(first_point, second_point,
                    repeating_ ? kSpreadMethodRepeat : kSpreadMethodPad);
  AddStops(desc, conversion_data, document, style);

  scoped_refptr<Gradient> gradient =
      Gradient::CreateLinear(desc.p0, desc.p1, desc.spread_method,
                             Gradient::ColorInterpolation::kPremultiplied);

  gradient->SetColorInterpolationSpace(color_interpolation_space_,
                                       hue_interpolation_method_);
  gradient->AddColorStops(desc.stops);

  return gradient;
}

bool CSSLinearGradientValue::Equals(const CSSLinearGradientValue& other) const {
  if (gradient_type_ != other.gradient_type_) {
    return false;
  }

  if (gradient_type_ == kCSSDeprecatedLinearGradient) {
    return base::ValuesEquivalent(first_x_, other.first_x_) &&
           base::ValuesEquivalent(first_y_, other.first_y_) &&
           base::ValuesEquivalent(second_x_, other.second_x_) &&
           base::ValuesEquivalent(second_y_, other.second_y_) &&
           stops_ == other.stops_;
  }

  if (!CSSGradientValue::Equals(other)) {
    return false;
  }

  if (angle_) {
    return base::ValuesEquivalent(angle_, other.angle_) &&
           stops_ == other.stops_;
  }

  if (other.angle_) {
    return false;
  }

  bool equal_xand_y = false;
  if (first_x_ && first_y_) {
    equal_xand_y = base::ValuesEquivalent(first_x_, other.first_x_) &&
                   base::ValuesEquivalent(first_y_, other.first_y_);
  } else if (first_x_) {
    equal_xand_y =
        base::ValuesEquivalent(first_x_, other.first_x_) && !other.first_y_;
  } else if (first_y_) {
    equal_xand_y =
        base::ValuesEquivalent(first_y_, other.first_y_) && !other.first_x_;
  } else {
    equal_xand_y = !other.first_x_ && !other.first_y_;
  }

  return equal_xand_y;
}

CSSLinearGradientValue* CSSLinearGradientValue::ComputedCSSValue(
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSLinearGradientValue* result = MakeGarbageCollected<CSSLinearGradientValue>(
      first_x_, first_y_, second_x_, second_y_, angle_,
      repeating_ ? kRepeating : kNonRepeating, GradientType());

  result->SetColorInterpolationSpace(color_interpolation_space_,
                                     hue_interpolation_method_);
  result->AddComputedStops(style, allow_visited_style, stops_, value_phase);
  return result;
}

static bool IsUsingCurrentColor(
    const HeapVector<CSSGradientColorStop, 2>& stops) {
  for (const CSSGradientColorStop& stop : stops) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(stop.color_.Get());
    if (identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kCurrentcolor) {
      return true;
    }
  }
  return false;
}

static bool IsUsingContainerRelativeUnits(const CSSValue* value) {
  const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  return primitive_value && primitive_value->HasContainerRelativeUnits();
}

static bool IsUsingContainerRelativeUnits(
    const HeapVector<CSSGradientColorStop, 2>& stops) {
  for (const CSSGradientColorStop& stop : stops) {
    if (IsUsingContainerRelativeUnits(stop.offset_.Get())) {
      return true;
    }
  }
  return false;
}

bool CSSLinearGradientValue::IsUsingCurrentColor() const {
  return blink::cssvalue::IsUsingCurrentColor(stops_);
}

bool CSSLinearGradientValue::IsUsingContainerRelativeUnits() const {
  return blink::cssvalue::IsUsingContainerRelativeUnits(stops_);
}

void CSSLinearGradientValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(first_x_);
  visitor->Trace(first_y_);
  visitor->Trace(second_x_);
  visitor->Trace(second_y_);
  visitor->Trace(angle_);
  CSSGradientValue::TraceAfterDispatch(visitor);
}

void CSSGradientValue::AppendCSSTextForColorStops(
    StringBuilder& result,
    bool requires_separator) const {
  for (const auto& stop : stops_) {
    if (requires_separator) {
      result.Append(", ");
    } else {
      requires_separator = true;
    }

    if (stop.color_) {
      result.Append(stop.color_->CssText());
    }
    if (stop.color_ && stop.offset_) {
      result.Append(' ');
    }
    if (stop.offset_) {
      result.Append(stop.offset_->CssText());
    }
  }
}

void CSSGradientValue::AppendCSSTextForDeprecatedColorStops(
    StringBuilder& result) const {
  for (unsigned i = 0; i < stops_.size(); i++) {
    const CSSGradientColorStop& stop = stops_[i];
    result.Append(", ");
    if (stop.offset_->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue) {
      result.Append("from(");
      result.Append(stop.color_->CssText());
      result.Append(')');
    } else if (stop.offset_->IsOne() == CSSPrimitiveValue::BoolStatus::kTrue) {
      result.Append("to(");
      result.Append(stop.color_->CssText());
      result.Append(')');
    } else {
      result.Append("color-stop(");
      result.Append(stop.offset_->CssText());
      result.Append(", ");
      result.Append(stop.color_->CssText());
      result.Append(')');
    }
  }
}

bool CSSGradientValue::Equals(const CSSGradientValue& other) const {
  return repeating_ == other.repeating_ &&
         color_interpolation_space_ == other.color_interpolation_space_ &&
         hue_interpolation_method_ == other.hue_interpolation_method_ &&
         stops_ == other.stops_;
}

String CSSRadialGradientValue::CustomCSSText() const {
  StringBuilder result;

  if (gradient_type_ == kCSSDeprecatedRadialGradient) {
    result.Append("-webkit-gradient(radial, ");
    result.Append(first_x_->CssText());
    result.Append(' ');
    result.Append(first_y_->CssText());
    result.Append(", ");
    result.Append(first_radius_->CssText());
    result.Append(", ");
    result.Append(second_x_->CssText());
    result.Append(' ');
    result.Append(second_y_->CssText());
    result.Append(", ");
    result.Append(second_radius_->CssText());
    AppendCSSTextForDeprecatedColorStops(result);
  } else if (gradient_type_ == kCSSPrefixedRadialGradient) {
    if (repeating_) {
      result.Append("-webkit-repeating-radial-gradient(");
    } else {
      result.Append("-webkit-radial-gradient(");
    }

    if (first_x_ && first_y_) {
      result.Append(first_x_->CssText());
      result.Append(' ');
      result.Append(first_y_->CssText());
    } else if (first_x_) {
      result.Append(first_x_->CssText());
    } else if (first_y_) {
      result.Append(first_y_->CssText());
    } else {
      result.Append("center");
    }

    if (shape_ || sizing_behavior_) {
      result.Append(", ");
      if (shape_) {
        result.Append(shape_->CssText());
        result.Append(' ');
      } else {
        result.Append("ellipse ");
      }

      if (sizing_behavior_) {
        result.Append(sizing_behavior_->CssText());
      } else {
        result.Append("cover");
      }

    } else if (end_horizontal_size_ && end_vertical_size_) {
      result.Append(", ");
      result.Append(end_horizontal_size_->CssText());
      result.Append(' ');
      result.Append(end_vertical_size_->CssText());
    }
    constexpr bool kAppendSeparator = true;

    if (ShouldSerializeColorSpace()) {
      result.Append(" in ");
      result.Append(Color::SerializeInterpolationSpace(
          color_interpolation_space_, hue_interpolation_method_));
    }

    AppendCSSTextForColorStops(result, kAppendSeparator);
  } else {
    if (repeating_) {
      result.Append("repeating-radial-gradient(");
    } else {
      result.Append("radial-gradient(");
    }

    bool wrote_something = false;

    // The only ambiguous case that needs an explicit shape to be provided
    // is when a sizing keyword is used (or all sizing is omitted).
    if (shape_ && shape_->GetValueID() != CSSValueID::kEllipse &&
        (sizing_behavior_ || (!sizing_behavior_ && !end_horizontal_size_))) {
      result.Append("circle");
      wrote_something = true;
    }

    if (sizing_behavior_ &&
        sizing_behavior_->GetValueID() != CSSValueID::kFarthestCorner) {
      if (wrote_something) {
        result.Append(' ');
      }
      result.Append(sizing_behavior_->CssText());
      wrote_something = true;
    } else if (end_horizontal_size_) {
      if (wrote_something) {
        result.Append(' ');
      }
      result.Append(end_horizontal_size_->CssText());
      if (end_vertical_size_) {
        result.Append(' ');
        result.Append(end_vertical_size_->CssText());
      }
      wrote_something = true;
    }

    wrote_something |=
        AppendPosition(result, first_x_, first_y_, wrote_something);

    if (ShouldSerializeColorSpace()) {
      if (wrote_something) {
        result.Append(" ");
      }
      result.Append("in ");
      wrote_something = true;
      result.Append(Color::SerializeInterpolationSpace(
          color_interpolation_space_, hue_interpolation_method_));
    }

    AppendCSSTextForColorStops(result, wrote_something);
  }

  result.Append(')');
  return result.ReleaseString();
}

namespace {

// Resolve points/radii to front end values.
float ResolveRadius(const CSSPrimitiveValue* radius,
                    const CSSToLengthConversionData& conversion_data,
                    float* width_or_height = nullptr) {
  float result = 0;
  if (radius->IsNumber()) {
    result = radius->ComputeNumber(conversion_data) * conversion_data.Zoom();
  } else if (width_or_height && radius->IsPercentage()) {
    result =
        *width_or_height * radius->ComputePercentage(conversion_data) / 100;
  } else {
    result = radius->ComputeLength<float>(conversion_data);
  }

  return ClampTo<float>(std::max(result, 0.0f));
}

enum EndShapeType { kCircleEndShape, kEllipseEndShape };

// Compute the radius to the closest/farthest side (depending on the compare
// functor).
gfx::SizeF RadiusToSide(const gfx::PointF& point,
                        const gfx::SizeF& size,
                        EndShapeType shape,
                        bool (*compare)(float, float)) {
  float dx1 = ClampTo<float>(fabs(point.x()));
  float dy1 = ClampTo<float>(fabs(point.y()));
  float dx2 = ClampTo<float>(fabs(point.x() - size.width()));
  float dy2 = ClampTo<float>(fabs(point.y() - size.height()));

  float dx = compare(dx1, dx2) ? dx1 : dx2;
  float dy = compare(dy1, dy2) ? dy1 : dy2;

  if (shape == kCircleEndShape) {
    return compare(dx, dy) ? gfx::SizeF(dx, dx) : gfx::SizeF(dy, dy);
  }

  DCHECK_EQ(shape, kEllipseEndShape);
  return gfx::SizeF(dx, dy);
}

// Compute the radius of an ellipse which passes through a point at
// |offset_from_center|, and has width/height given by aspectRatio.
inline gfx::SizeF EllipseRadius(const gfx::Vector2dF& offset_from_center,
                                float aspect_ratio) {
  // If the aspectRatio is 0 or infinite, the ellipse is completely flat.
  // (If it is NaN, the ellipse is 0x0, and should be handled as zero width.)
  // TODO(sashab): Implement Degenerate Radial Gradients, see crbug.com/635727.
  if (!std::isfinite(aspect_ratio) || aspect_ratio == 0) {
    return gfx::SizeF(0, 0);
  }

  // x^2/a^2 + y^2/b^2 = 1
  // a/b = aspectRatio, b = a/aspectRatio
  // a = sqrt(x^2 + y^2/(1/aspect_ratio^2))
  float a = sqrtf(offset_from_center.x() * offset_from_center.x() +
                  offset_from_center.y() * offset_from_center.y() *
                      aspect_ratio * aspect_ratio);
  return gfx::SizeF(ClampTo<float>(a), ClampTo<float>(a / aspect_ratio));
}

// Compute the radius to the closest/farthest corner (depending on the compare
// functor).
gfx::SizeF RadiusToCorner(const gfx::PointF& point,
                          const gfx::SizeF& size,
                          EndShapeType shape,
                          bool (*compare)(float, float)) {
  const gfx::RectF rect(size);
  const std::array<gfx::PointF, 4> corners = {
      rect.origin(), rect.top_right(), rect.bottom_right(), rect.bottom_left()};

  unsigned corner_index = 0;
  float distance = (point - corners[corner_index]).Length();
  for (unsigned i = 1; i < std::size(corners); ++i) {
    float new_distance = (point - corners[i]).Length();
    if (compare(new_distance, distance)) {
      corner_index = i;
      distance = new_distance;
    }
  }

  if (shape == kCircleEndShape) {
    distance = ClampTo<float>(distance);
    return gfx::SizeF(distance, distance);
  }

  DCHECK_EQ(shape, kEllipseEndShape);
  // If the end shape is an ellipse, the gradient-shape has the same ratio of
  // width to height that it would if closest-side or farthest-side were
  // specified, as appropriate.
  const gfx::SizeF side_radius =
      RadiusToSide(point, size, kEllipseEndShape, compare);

  return EllipseRadius(corners[corner_index] - point,
                       side_radius.AspectRatio());
}

}  // anonymous namespace

scoped_refptr<Gradient> CSSRadialGradientValue::CreateGradient(
    const CSSToLengthConversionData& conversion_data,
    const gfx::SizeF& size,
    const Document& document,
    const ComputedStyle& style) const {
  DCHECK(!size.IsEmpty());

  gfx::PointF first_point =
      ComputeEndPoint(first_x_.Get(), first_y_.Get(), conversion_data, size);
  if (!first_x_) {
    first_point.set_x(size.width() / 2);
  }
  if (!first_y_) {
    first_point.set_y(size.height() / 2);
  }

  gfx::PointF second_point =
      ComputeEndPoint(second_x_.Get(), second_y_.Get(), conversion_data, size);
  if (!second_x_) {
    second_point.set_x(size.width() / 2);
  }
  if (!second_y_) {
    second_point.set_y(size.height() / 2);
  }

  float first_radius = 0;
  if (first_radius_) {
    first_radius = ResolveRadius(first_radius_.Get(), conversion_data);
  }

  gfx::SizeF second_radius(0, 0);
  if (second_radius_) {
    second_radius.set_width(
        ResolveRadius(second_radius_.Get(), conversion_data));
    second_radius.set_height(second_radius.width());
  } else if (end_horizontal_size_) {
    float width = size.width();
    float height = size.height();
    second_radius.set_width(
        ResolveRadius(end_horizontal_size_.Get(), conversion_data, &width));
    second_radius.set_height(
        end_vertical_size_
            ? ResolveRadius(end_vertical_size_.Get(), conversion_data, &height)
            : second_radius.width());
  } else {
    EndShapeType shape =
        (shape_ && shape_->GetValueID() == CSSValueID::kCircle) ||
                (!shape_ && !sizing_behavior_ && end_horizontal_size_ &&
                 !end_vertical_size_)
            ? kCircleEndShape
            : kEllipseEndShape;

    switch (sizing_behavior_ ? sizing_behavior_->GetValueID()
                             : CSSValueID::kInvalid) {
      case CSSValueID::kContain:
      case CSSValueID::kClosestSide:
        second_radius = RadiusToSide(second_point, size, shape,
                                     [](float a, float b) { return a < b; });
        break;
      case CSSValueID::kFarthestSide:
        second_radius = RadiusToSide(second_point, size, shape,
                                     [](float a, float b) { return a > b; });
        break;
      case CSSValueID::kClosestCorner:
        second_radius = RadiusToCorner(second_point, size, shape,
                                       [](float a, float b) { return a < b; });
        break;
      default:
        second_radius = RadiusToCorner(second_point, size, shape,
                                       [](float a, float b) { return a > b; });
        break;
    }
  }

  DCHECK(std::isfinite(first_radius));
  DCHECK(std::isfinite(second_radius.width()));
  DCHECK(std::isfinite(second_radius.height()));

  bool is_degenerate = !second_radius.width() || !second_radius.height();
  GradientDesc desc(first_point, second_point, first_radius,
                    is_degenerate ? 0 : second_radius.width(),
                    repeating_ ? kSpreadMethodRepeat : kSpreadMethodPad);
  AddStops(desc, conversion_data, document, style);

  scoped_refptr<Gradient> gradient = Gradient::CreateRadial(
      desc.p0, desc.r0, desc.p1, desc.r1,
      is_degenerate ? 1 : second_radius.AspectRatio(), desc.spread_method,
      Gradient::ColorInterpolation::kPremultiplied);

  gradient->SetColorInterpolationSpace(color_interpolation_space_,
                                       hue_interpolation_method_);
  gradient->AddColorStops(desc.stops);

  return gradient;
}

namespace {

bool EqualIdentifiersWithDefault(const CSSIdentifierValue* id_a,
                                 const CSSIdentifierValue* id_b,
                                 CSSValueID default_id) {
  CSSValueID value_a = id_a ? id_a->GetValueID() : default_id;
  CSSValueID value_b = id_b ? id_b->GetValueID() : default_id;
  return value_a == value_b;
}

}  // namespace

bool CSSRadialGradientValue::Equals(const CSSRadialGradientValue& other) const {
  if (gradient_type_ == kCSSDeprecatedRadialGradient) {
    return other.gradient_type_ == gradient_type_ &&
           base::ValuesEquivalent(first_x_, other.first_x_) &&
           base::ValuesEquivalent(first_y_, other.first_y_) &&
           base::ValuesEquivalent(second_x_, other.second_x_) &&
           base::ValuesEquivalent(second_y_, other.second_y_) &&
           base::ValuesEquivalent(first_radius_, other.first_radius_) &&
           base::ValuesEquivalent(second_radius_, other.second_radius_) &&
           stops_ == other.stops_;
  }

  if (!CSSGradientValue::Equals(other)) {
    return false;
  }

  if (!base::ValuesEquivalent(first_x_, other.first_x_) ||
      !base::ValuesEquivalent(first_y_, other.first_y_)) {
    return false;
  }

  // There's either a size keyword or an explicit size specification.
  if (end_horizontal_size_) {
    // Explicit size specification. One <length> or two <length-percentage>.
    if (!base::ValuesEquivalent(end_horizontal_size_,
                                other.end_horizontal_size_)) {
      return false;
    }
    if (!base::ValuesEquivalent(end_vertical_size_, other.end_vertical_size_)) {
      return false;
    }
  } else {
    if (other.end_horizontal_size_) {
      return false;
    }
    // There's a size keyword.
    if (!EqualIdentifiersWithDefault(sizing_behavior_, other.sizing_behavior_,
                                     CSSValueID::kFarthestCorner)) {
      return false;
    }
    // Here the shape is 'ellipse' unless explicitly set to 'circle'.
    if (!EqualIdentifiersWithDefault(shape_, other.shape_,
                                     CSSValueID::kEllipse)) {
      return false;
    }
  }
  return true;
}

CSSRadialGradientValue* CSSRadialGradientValue::ComputedCSSValue(
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSRadialGradientValue* result = MakeGarbageCollected<CSSRadialGradientValue>(
      first_x_, first_y_, first_radius_, second_x_, second_y_, second_radius_,
      shape_, sizing_behavior_, end_horizontal_size_, end_vertical_size_,
      repeating_ ? kRepeating : kNonRepeating, GradientType());
  result->SetColorInterpolationSpace(color_interpolation_space_,
                                     hue_interpolation_method_);
  result->AddComputedStops(style, allow_visited_style, stops_, value_phase);
  return result;
}

bool CSSRadialGradientValue::IsUsingCurrentColor() const {
  return blink::cssvalue::IsUsingCurrentColor(stops_);
}

bool CSSRadialGradientValue::IsUsingContainerRelativeUnits() const {
  return blink::cssvalue::IsUsingContainerRelativeUnits(stops_);
}

void CSSRadialGradientValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(first_x_);
  visitor->Trace(first_y_);
  visitor->Trace(second_x_);
  visitor->Trace(second_y_);
  visitor->Trace(first_radius_);
  visitor->Trace(second_radius_);
  visitor->Trace(shape_);
  visitor->Trace(sizing_behavior_);
  visitor->Trace(end_horizontal_size_);
  visitor->Trace(end_vertical_size_);
  CSSGradientValue::TraceAfterDispatch(visitor);
}

String CSSConicGradientValue::CustomCSSText() const {
  StringBuilder result;

  if (repeating_) {
    result.Append("repeating-");
  }
  result.Append("conic-gradient(");

  bool wrote_something = false;

  if (from_angle_) {
    result.Append("from ");
    result.Append(from_angle_->CssText());
    wrote_something = true;
  }

  wrote_something |= AppendPosition(result, x_, y_, wrote_something);

  if (ShouldSerializeColorSpace()) {
    if (wrote_something) {
      result.Append(" ");
    }
    result.Append("in ");
    wrote_something = true;
    result.Append(Color::SerializeInterpolationSpace(
        color_interpolation_space_, hue_interpolation_method_));
  }

  AppendCSSTextForColorStops(result, wrote_something);

  result.Append(')');
  return result.ReleaseString();
}

scoped_refptr<Gradient> CSSConicGradientValue::CreateGradient(
    const CSSToLengthConversionData& conversion_data,
    const gfx::SizeF& size,
    const Document& document,
    const ComputedStyle& style) const {
  DCHECK(!size.IsEmpty());

  const float angle =
      from_angle_ ? from_angle_->ComputeDegrees(conversion_data) : 0;

  const gfx::PointF position(
      x_ ? PositionFromValue(x_, conversion_data, size, true)
         : size.width() / 2,
      y_ ? PositionFromValue(y_, conversion_data, size, false)
         : size.height() / 2);

  GradientDesc desc(position, position,
                    repeating_ ? kSpreadMethodRepeat : kSpreadMethodPad);
  AddStops(desc, conversion_data, document, style);

  scoped_refptr<Gradient> gradient = Gradient::CreateConic(
      position, angle, desc.start_angle, desc.end_angle, desc.spread_method,
      Gradient::ColorInterpolation::kPremultiplied);

  gradient->SetColorInterpolationSpace(color_interpolation_space_,
                                       hue_interpolation_method_);
  gradient->AddColorStops(desc.stops);

  return gradient;
}

bool CSSConicGradientValue::Equals(const CSSConicGradientValue& other) const {
  return CSSGradientValue::Equals(other) &&
         base::ValuesEquivalent(x_, other.x_) &&
         base::ValuesEquivalent(y_, other.y_) &&
         base::ValuesEquivalent(from_angle_, other.from_angle_);
}

CSSConicGradientValue* CSSConicGradientValue::ComputedCSSValue(
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  auto* result = MakeGarbageCollected<CSSConicGradientValue>(
      x_, y_, from_angle_, repeating_ ? kRepeating : kNonRepeating);
  result->SetColorInterpolationSpace(color_interpolation_space_,
                                     hue_interpolation_method_);
  result->AddComputedStops(style, allow_visited_style, stops_, value_phase);
  return result;
}

bool CSSConicGradientValue::IsUsingCurrentColor() const {
  return blink::cssvalue::IsUsingCurrentColor(stops_);
}

bool CSSConicGradientValue::IsUsingContainerRelativeUnits() const {
  return blink::cssvalue::IsUsingContainerRelativeUnits(stops_) ||
         blink::cssvalue::IsUsingContainerRelativeUnits(x_.Get()) ||
         blink::c
```