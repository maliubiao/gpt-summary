Response:
Let's break down the thought process for analyzing this C++ code and generating the summary.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality, its relation to web technologies (JS, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Initial Code Scan (Keywords and Structure):**  Read through the code, looking for important keywords and structural elements. Notice:
    * `#include` statements:  These indicate dependencies and areas of focus. `animation`, `css`, `style`, `Interpolable...`, `BasicShape...` are prominent. This immediately tells us the file is about CSS animations involving basic shapes.
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * Class `BasicShapeNonInterpolableValue`: This seems crucial for storing non-interpolatable aspects of shapes.
    * Several nested namespaces (`circle_functions`, `ellipse_functions`, `inset_functions`, `polygon_functions`): This suggests a modular approach, likely handling different basic shapes.
    * Functions like `ConvertCSSValue`, `ConvertBasicShape`, `CreateNeutralValue`, `CreateBasicShape`:  These clearly relate to converting between CSS values, internal shape representations, creating neutral values for interpolation, and constructing the final shape.
    * Use of `InterpolableValue`, `InterpolableList`, `InterpolableLength`, `InterpolableNumber`:  These are key types for representing values that can be interpolated.
    * Use of `CSSBasicShapeCircleValue`, `CSSBasicShapeEllipseValue`, etc.: These are CSS-specific value types.

3. **Identify Core Functionality:**  Based on the initial scan, the main purpose seems to be handling the *interpolation* of CSS basic shapes during animations and transitions. This involves:
    * **Conversion:**  Converting CSS basic shape values (like `circle(50px)`) and internal `BasicShape` objects into an interpolatable representation.
    * **Neutral Values:** Creating "zero" or "neutral" representations of shapes for cases where an animation starts or ends without a defined shape.
    * **Compatibility:** Determining if two shapes can be meaningfully interpolated between.
    * **Creation:** Reconstructing the `BasicShape` object from the interpolated values.
    * **Handling Different Shapes:**  Specific logic for circles, ellipses, insets, and polygons.

4. **Relate to Web Technologies (JS, HTML, CSS):**
    * **CSS:** The file directly deals with CSS basic shape values (`circle()`, `ellipse()`, `inset()`, `polygon()`). These are used in CSS properties like `clip-path` and `shape-outside`.
    * **JavaScript:** JavaScript is used to trigger CSS animations and transitions. When these animations involve basic shapes, this C++ code is what makes the smooth transitions possible. Example:  `element.style.clipPath = 'circle(0)'; animateTo('circle(50px)');`
    * **HTML:**  HTML provides the elements to which CSS styles (including those with basic shapes) are applied.

5. **Logical Reasoning Examples:**
    * **Interpolation:** The core idea is to break down complex shapes into simpler, interpolatable components (like center coordinates and radii).
    * **Neutral Values:**  For example, a neutral circle might have a radius of 0 and a center at 50% 50%. This acts as a starting or ending point when a shape isn't explicitly defined.
    * **Compatibility:**  Interpolating between a circle and an ellipse is generally possible. However, interpolating between a circle and a polygon with a different number of points wouldn't be straightforward. The code handles this by checking the shape types and, for polygons, the number of points and the winding rule.

6. **Common Usage Errors (Conceptual Level):** Since this is backend code, user errors aren't direct coding mistakes in this file. However, we can think about *how* improper CSS usage would interact with this code.
    * **Incompatible Shapes:** Trying to animate between fundamentally different shapes without proper fallback definitions could lead to jarring transitions or the animation not working as expected.
    * **Missing Units:**  While this code handles conversions, incorrect or missing units in CSS would be caught earlier in the parsing stage. However, it's a common source of CSS errors related to lengths.

7. **Structure the Output:** Organize the findings into clear sections:
    * **功能概要 (Summary of Functionality):**  Start with a concise overview.
    * **与 Javascript、HTML、CSS 的关系:** Explain the connections and provide examples.
    * **逻辑推理举例:** Illustrate the core logic with concrete inputs and outputs (even if simplified).
    * **用户或编程常见的使用错误:** Focus on how incorrect *usage* of the related web technologies might manifest, rather than errors within the C++ code itself.

8. **Refine and Elaborate:**  Review the generated output for clarity and completeness. Add more details or examples where needed. For instance, explicitly mention the `clip-path` and `shape-outside` CSS properties. Clarify the role of the `BasicShapeNonInterpolableValue` class.

By following these steps, we can systematically analyze the provided C++ code and generate a comprehensive and informative summary that addresses all aspects of the request. The key is to understand the *purpose* of the code within the broader context of a web browser's rendering engine.
这个文件 `blink/renderer/core/animation/basic_shape_interpolation_functions.cc` 的主要功能是**处理 CSS 基础图形（Basic Shapes）在动画和过渡期间的插值计算**。

更具体地说，它负责将 CSS 中定义的各种基础图形（如 `circle`, `ellipse`, `inset`, `polygon` 等）转换为可以在动画中平滑过渡的内部表示形式，并进行实际的插值运算。

以下是其功能的详细列举：

**核心功能:**

1. **CSS 值到插值类型的转换:**
   - 将 CSS 中定义的 `circle()`, `ellipse()`, `inset()`, `rect()`, `xywh()`, `polygon()` 等函数表示的基础图形值，转换为 `InterpolationValue` 对象。`InterpolationValue` 包含了可以进行插值的 `InterpolableValue` 和描述非插值属性的 `NonInterpolableValue`。
   - 例如，对于 `circle(50px at 20px 30px)`, 它会将其半径 `50px` 和中心点 `20px 30px` 转换为可以插值的长度值。

2. **内部 BasicShape 对象到插值类型的转换:**
   - 将 Blink 内部表示的 `BasicShape` 对象（如 `BasicShapeCircle`, `BasicShapeEllipse` 等）转换为 `InterpolationValue` 对象。这在内部动画逻辑中使用。

3. **创建中性插值值:**
   - 提供创建“中性”或“零”插值值的能力，用于在动画的开始或结束状态没有明确定义基础图形时作为占位符或初始值。
   - 例如，一个中性的圆可能半径为 0，中心点在 50% 50%。

4. **检查基础图形的兼容性:**
   - 判断两个基础图形是否可以进行有意义的插值。例如，一个圆形可以插值到另一个圆形或椭圆形，但直接插值到一个点数不同的多边形可能没有意义。
   - 对于 `polygon`，还会检查其 `wind-rule` (填充规则) 和顶点数量是否一致。

5. **从插值值创建 BasicShape 对象:**
   - 将插值计算后的 `InterpolableValue` 转换回 Blink 内部的 `BasicShape` 对象，以便渲染引擎可以使用它来绘制图形。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个文件是 Blink 渲染引擎的一部分，它直接支持 CSS 规范中定义的基础图形功能。当 JavaScript 触发 CSS 动画或过渡时，并且这些动画或过渡涉及到基础图形的改变，这个文件中的代码就会被调用来计算中间帧的图形形状。

* **CSS:**
    - **定义基础图形:** CSS 中使用 `clip-path` 和 `shape-outside` 等属性，以及 `circle()`, `ellipse()`, `inset()`, `polygon()` 等函数来定义元素的裁剪路径或形状。
    ```css
    .element {
      clip-path: circle(50px at 100px 100px); /* 定义一个圆形裁剪路径 */
      transition: clip-path 1s ease-in-out; /* 定义一个针对 clip-path 的过渡 */
    }

    .element:hover {
      clip-path: ellipse(80px 60px at 100px 100px); /* 鼠标悬停时变为椭圆 */
    }
    ```
    - 当鼠标悬停时，浏览器会调用 `basic_shape_interpolation_functions.cc` 中的代码来平滑地从圆形过渡到椭圆。

* **JavaScript:**
    - **触发动画和过渡:** JavaScript 可以通过修改元素的 CSS 属性来触发动画和过渡。
    ```javascript
    const element = document.querySelector('.element');
    element.style.clipPath = 'circle(20px)'; // 设置初始裁剪路径

    // 稍后触发过渡
    element.style.clipPath = 'polygon(50% 0%, 0% 100%, 100% 100%)';
    ```
    - 当 `clipPath` 的值发生变化时，如果定义了过渡，`basic_shape_interpolation_functions.cc` 会参与计算中间帧的多边形形状。

* **HTML:**
    - **承载元素:** HTML 元素是应用 CSS 样式（包括基础图形）的基础。

**逻辑推理举例 (假设输入与输出):**

假设我们有一个 CSS 过渡，将一个圆形动画过渡到一个内凹的矩形 (`inset`)：

**假设输入:**

* **起始值 (CSS):** `clip-path: circle(50px at 100px 100px);`
* **结束值 (CSS):** `clip-path: inset(20px 30px 40px 10px round 5px);`
* **插值进度 (t):** 0.5 (动画进行到一半)

**逻辑推理过程:**

1. **转换:** `MaybeConvertCSSValue` 函数会将起始和结束的 CSS 值转换为 `InterpolationValue` 对象。对于圆形，会提取半径和中心点；对于 `inset`，会提取各个方向的偏移量和圆角半径。
2. **兼容性检查:** `ShapesAreCompatible` 函数会判断圆形和 `inset` 是否可以插值。由于它们是不同的基础图形类型，可能需要特殊处理，例如转换为统一的表示形式或进行形状变形。在这个文件中，`rect` 和 `xywh` 会被转换成 `inset` 进行处理。
3. **插值计算:** 对于可以插值的属性（例如，圆的半径和 `inset` 的偏移量），会根据插值进度 `t` 进行线性插值。例如，如果圆的半径是 50px，`inset` 的 top 是 20px，那么在 `t=0.5` 时，可能会计算出一个中间值。由于形状类型不同，直接插值形状参数可能不是唯一的实现方式，也可能涉及到更复杂的形状变换。
4. **创建中间形状:** `CreateBasicShape` 函数会根据插值后的值创建一个新的 `BasicShape` 对象，表示动画中间帧的形状。

**可能的输出 (中间状态的 `BasicShape` 对象 - 简化表示):**

由于圆形和内凹矩形在结构上差异较大，直接线性插值其参数可能不会产生视觉上自然的效果。实际实现可能会采用更复杂的技术，例如将两者都近似为多边形，然后插值多边形的顶点。

如果简化地考虑参数插值，但不保证视觉合理性，可能的中间状态可能是：

* 一个中心点在 (100px, 100px) 附近，具有一定程度的圆角，并且四个边向内凹陷的形状。具体数值会根据插值算法而定。

**用户或编程常见的使用错误举例:**

1. **尝试在不兼容的基础图形之间进行平滑过渡，而没有提供足够的中间状态信息或回退机制。**
   - 例如，直接从 `circle()` 过渡到顶点数量相差很大的 `polygon()`，可能会导致动画过程中形状突变。
   - **解决方法:**  可以考虑使用关键帧动画来更精确地控制中间状态，或者使用 `path()` 函数定义更复杂的形状变换路径。

2. **在定义 `polygon()` 时，坐标点的数量在起始和结束状态不一致。**
   - `basic_shape_interpolation_functions.cc` 会检查 `polygon` 的顶点数量，如果数量不一致，将无法进行平滑的顶点插值。
   - **解决方法:**  确保动画开始和结束的 `polygon()` 函数具有相同数量的坐标点。

3. **在 JavaScript 中动态修改 `clip-path` 或 `shape-outside` 属性时，忘记添加过渡效果。**
   - 如果没有定义 `transition` 属性，形状的改变会是瞬间的，不会触发 `basic_shape_interpolation_functions.cc` 中的插值计算。
   - **解决方法:**  确保在需要平滑过渡的属性上定义了 `transition`。

4. **在定义 `polygon()` 时，使用了错误的 `wind-rule` (如 `nonzero` 或 `evenodd`)。**
   - 如果动画开始和结束状态的 `polygon()` 的 `wind-rule` 不同，`basic_shape_interpolation_functions.cc` 会认为它们不兼容，可能无法进行插值。
   - **解决方法:**  确保动画开始和结束的 `polygon()` 使用相同的 `wind-rule`。

总而言之，`basic_shape_interpolation_functions.cc` 是 Blink 渲染引擎中处理 CSS 基础图形动画和过渡的关键组件，它负责将 CSS 值转换为可插值的形式，进行实际的插值计算，并最终生成用于渲染的图形形状。理解其功能有助于开发者更好地利用 CSS 动画和过渡创建流畅的用户体验。

### 提示词
```
这是目录为blink/renderer/core/animation/basic_shape_interpolation_functions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/basic_shape_interpolation_functions.h"

#include <memory>
#include "third_party/blink/renderer/core/animation/css_position_axis_list_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/interpolable_length.h"
#include "third_party/blink/renderer/core/css/css_basic_shape_values.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/style/basic_shapes.h"

namespace blink {

class BasicShapeNonInterpolableValue : public NonInterpolableValue {
 public:
  static scoped_refptr<const NonInterpolableValue> Create(
      BasicShape::ShapeType type) {
    return base::AdoptRef(new BasicShapeNonInterpolableValue(type));
  }
  static scoped_refptr<const NonInterpolableValue> CreatePolygon(
      WindRule wind_rule,
      wtf_size_t size) {
    return base::AdoptRef(new BasicShapeNonInterpolableValue(wind_rule, size));
  }

  BasicShape::ShapeType GetShapeType() const { return type_; }

  WindRule GetWindRule() const {
    DCHECK_EQ(GetShapeType(), BasicShape::kBasicShapePolygonType);
    return wind_rule_;
  }
  wtf_size_t size() const {
    DCHECK_EQ(GetShapeType(), BasicShape::kBasicShapePolygonType);
    return size_;
  }

  bool IsCompatibleWith(const BasicShapeNonInterpolableValue& other) const {
    if (GetShapeType() != other.GetShapeType()) {
      return false;
    }
    switch (GetShapeType()) {
      case BasicShape::kBasicShapeCircleType:
      case BasicShape::kBasicShapeEllipseType:
      case BasicShape::kBasicShapeInsetType:
        return true;
      case BasicShape::kBasicShapePolygonType:
        return GetWindRule() == other.GetWindRule() && size() == other.size();
      default:
        NOTREACHED();
    }
  }

  DECLARE_NON_INTERPOLABLE_VALUE_TYPE();

 private:
  BasicShapeNonInterpolableValue(BasicShape::ShapeType type)
      : type_(type), wind_rule_(RULE_NONZERO), size_(0) {
    DCHECK_NE(type, BasicShape::kBasicShapePolygonType);
  }
  BasicShapeNonInterpolableValue(WindRule wind_rule, wtf_size_t size)
      : type_(BasicShape::kBasicShapePolygonType),
        wind_rule_(wind_rule),
        size_(size) {}

  const BasicShape::ShapeType type_;
  const WindRule wind_rule_;
  const wtf_size_t size_;
};

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(BasicShapeNonInterpolableValue);
template <>
struct DowncastTraits<BasicShapeNonInterpolableValue> {
  static bool AllowFrom(const NonInterpolableValue* value) {
    return value && AllowFrom(*value);
  }
  static bool AllowFrom(const NonInterpolableValue& value) {
    return value.GetType() == BasicShapeNonInterpolableValue::static_type_;
  }
};

namespace {

InterpolableValue* Unwrap(InterpolationValue&& value) {
  DCHECK(value.interpolable_value);
  return std::move(value.interpolable_value);
}

InterpolableValue* ConvertCSSCoordinate(const CSSValue* coordinate,
                                        const CSSProperty& property) {
  if (coordinate) {
    return Unwrap(
        CSSPositionAxisListInterpolationType::ConvertPositionAxisCSSValue(
            *coordinate));
  }
  return InterpolableLength::MaybeConvertLength(
      Length::Percent(50), property, 1, /*interpolate_size=*/std::nullopt);
}

InterpolableValue* ConvertCoordinate(
    const BasicShapeCenterCoordinate& coordinate,
    const CSSProperty& property,
    double zoom) {
  return InterpolableLength::MaybeConvertLength(
      coordinate.ComputedLength(), property, zoom,
      /*interpolate_size=*/std::nullopt);
}

InterpolableValue* CreateNeutralInterpolableCoordinate() {
  return InterpolableLength::CreateNeutral();
}

BasicShapeCenterCoordinate CreateCoordinate(
    const InterpolableValue& interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  return BasicShapeCenterCoordinate(
      BasicShapeCenterCoordinate::kTopLeft,
      To<InterpolableLength>(interpolable_value)
          .CreateLength(conversion_data, Length::ValueRange::kAll));
}

InterpolableValue* ConvertCSSRadius(const CSSValue* radius) {
  if (!radius || radius->IsIdentifierValue()) {
    return nullptr;
  }
  return InterpolableLength::MaybeConvertCSSValue(*radius);
}

InterpolableValue* ConvertRadius(const BasicShapeRadius& radius,
                                 const CSSProperty& property,
                                 double zoom) {
  if (radius.GetType() != BasicShapeRadius::kValue) {
    return nullptr;
  }
  return InterpolableLength::MaybeConvertLength(
      radius.Value(), property, zoom,
      /*interpolate_size=*/std::nullopt);
}

InterpolableValue* CreateNeutralInterpolableRadius() {
  return InterpolableLength::CreateNeutral();
}

BasicShapeRadius CreateRadius(
    const InterpolableValue& interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  return BasicShapeRadius(
      To<InterpolableLength>(interpolable_value)
          .CreateLength(conversion_data, Length::ValueRange::kNonNegative));
}

InterpolableLength* ConvertCSSLength(const CSSValue& length) {
  return InterpolableLength::MaybeConvertCSSValue(length);
}

InterpolableLength* ConvertCSSLength(const CSSValue* length) {
  if (!length) {
    return InterpolableLength::CreateNeutral();
  }
  return ConvertCSSLength(*length);
}

InterpolableLength* ConvertCSSLengthOrAuto(const CSSValue& length,
                                           double auto_percent) {
  auto* identifier = DynamicTo<CSSIdentifierValue>(length);
  if (identifier && identifier->GetValueID() == CSSValueID::kAuto) {
    return InterpolableLength::CreatePercent(auto_percent);
  }
  return InterpolableLength::MaybeConvertCSSValue(length);
}

const CSSMathExpressionNode* AsExpressionNode(const CSSPrimitiveValue& value) {
  if (const auto* numeric_literal = DynamicTo<CSSNumericLiteralValue>(value)) {
    return CSSMathExpressionNumericLiteral::Create(numeric_literal);
  }
  return To<CSSMathFunctionValue>(value).ExpressionNode();
}

// Generate the expression: calc(minuend - subtrahend).
const CSSMathExpressionNode* SubtractCSSLength(
    const CSSMathExpressionNode& minuend,
    const CSSPrimitiveValue& subtrahend) {
  return CSSMathExpressionOperation::CreateArithmeticOperationSimplified(
      &minuend, AsExpressionNode(subtrahend), CSSMathOperator::kSubtract);
}

// Produce a InterpolableLength from a CSSMathExpressionNode expression tree.
InterpolableLength* FinalizeExpression(
    const CSSMathExpressionNode& difference) {
  CSSLengthArray length_array;
  if (difference.AccumulateLengthArray(length_array, 1)) {
    return MakeGarbageCollected<InterpolableLength>(std::move(length_array));
  }
  return MakeGarbageCollected<InterpolableLength>(difference);
}

// Generate the expression: calc(100% - a - b).
InterpolableLength* ConvertCSSLengthsSubtractedFrom100Percent(
    const CSSPrimitiveValue& a,
    const CSSPrimitiveValue& b) {
  const auto* percent_100 = CSSMathExpressionNumericLiteral::Create(
      100, CSSPrimitiveValue::UnitType::kPercentage);
  return FinalizeExpression(
      *SubtractCSSLength(*SubtractCSSLength(*percent_100, a), b));
}

// Generate the expression: calc(100% - a).
InterpolableLength* ConvertCSSLengthSubtractedFrom100Percent(
    const CSSPrimitiveValue& a) {
  const auto* percent_100 = CSSMathExpressionNumericLiteral::Create(
      100, CSSPrimitiveValue::UnitType::kPercentage);
  return FinalizeExpression(*SubtractCSSLength(*percent_100, a));
}

InterpolableLength* ConvertCSSLengthOrAutoSubtractedFrom100Percent(
    const CSSValue& length,
    double auto_percent) {
  auto* identifier = DynamicTo<CSSIdentifierValue>(length);
  if (identifier && identifier->GetValueID() == CSSValueID::kAuto) {
    return InterpolableLength::CreatePercent(auto_percent);
  }
  return ConvertCSSLengthSubtractedFrom100Percent(
      To<CSSPrimitiveValue>(length));
}

InterpolableValue* ConvertLength(const Length& length,
                                 const CSSProperty& property,
                                 double zoom) {
  return InterpolableLength::MaybeConvertLength(
      length, property, zoom,
      /*interpolate_size=*/std::nullopt);
}

InterpolableValue* ConvertCSSBorderRadiusWidth(const CSSValuePair* pair) {
  return ConvertCSSLength(pair ? &pair->First() : nullptr);
}

InterpolableValue* ConvertCSSBorderRadiusHeight(const CSSValuePair* pair) {
  return ConvertCSSLength(pair ? &pair->Second() : nullptr);
}

LengthSize CreateBorderRadius(
    const InterpolableValue& width,
    const InterpolableValue& height,
    const CSSToLengthConversionData& conversion_data) {
  return LengthSize(To<InterpolableLength>(width).CreateLength(
                        conversion_data, Length::ValueRange::kNonNegative),
                    To<InterpolableLength>(height).CreateLength(
                        conversion_data, Length::ValueRange::kNonNegative));
}

namespace circle_functions {

enum CircleComponentIndex : unsigned {
  kCircleCenterXIndex,
  kCircleCenterYIndex,
  kCircleRadiusIndex,
  kCircleHasExplicitCenterIndex,
  kCircleComponentIndexCount,
};

InterpolationValue ConvertCSSValue(
    const cssvalue::CSSBasicShapeCircleValue& circle,
    const CSSProperty& property) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kCircleComponentIndexCount);
  list->Set(kCircleCenterXIndex,
            ConvertCSSCoordinate(circle.CenterX(), property));
  list->Set(kCircleCenterYIndex,
            ConvertCSSCoordinate(circle.CenterY(), property));
  list->Set(kCircleHasExplicitCenterIndex,
            MakeGarbageCollected<InterpolableNumber>(!!circle.CenterX()));

  InterpolableValue* radius = nullptr;
  if (!(radius = ConvertCSSRadius(circle.Radius()))) {
    return nullptr;
  }
  list->Set(kCircleRadiusIndex, radius);

  return InterpolationValue(std::move(list),
                            BasicShapeNonInterpolableValue::Create(
                                BasicShape::kBasicShapeCircleType));
}

InterpolationValue ConvertBasicShape(const BasicShapeCircle& circle,
                                     const CSSProperty& property,
                                     double zoom) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kCircleComponentIndexCount);
  list->Set(kCircleCenterXIndex,
            ConvertCoordinate(circle.CenterX(), property, zoom));
  list->Set(kCircleCenterYIndex,
            ConvertCoordinate(circle.CenterY(), property, zoom));
  list->Set(
      kCircleHasExplicitCenterIndex,
      MakeGarbageCollected<InterpolableNumber>(circle.HasExplicitCenter()));

  InterpolableValue* radius = nullptr;
  if (!(radius = ConvertRadius(circle.Radius(), property, zoom))) {
    return nullptr;
  }
  list->Set(kCircleRadiusIndex, radius);

  return InterpolationValue(std::move(list),
                            BasicShapeNonInterpolableValue::Create(
                                BasicShape::kBasicShapeCircleType));
}

InterpolableValue* CreateNeutralValue() {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kCircleComponentIndexCount);
  list->Set(kCircleCenterXIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kCircleCenterYIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kCircleRadiusIndex, CreateNeutralInterpolableRadius());
  list->Set(kCircleHasExplicitCenterIndex,
            MakeGarbageCollected<InterpolableNumber>(0));
  return list;
}

scoped_refptr<BasicShape> CreateBasicShape(
    const InterpolableValue& interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  scoped_refptr<BasicShapeCircle> circle = BasicShapeCircle::Create();
  const auto& list = To<InterpolableList>(interpolable_value);
  circle->SetCenterX(
      CreateCoordinate(*list.Get(kCircleCenterXIndex), conversion_data));
  circle->SetCenterY(
      CreateCoordinate(*list.Get(kCircleCenterYIndex), conversion_data));
  circle->SetRadius(
      CreateRadius(*list.Get(kCircleRadiusIndex), conversion_data));
  circle->SetHasExplicitCenter(
      To<InterpolableNumber>(list.Get(kCircleHasExplicitCenterIndex))
          ->Value(conversion_data));
  return circle;
}

}  // namespace circle_functions

namespace ellipse_functions {

enum EllipseComponentIndex : unsigned {
  kEllipseCenterXIndex,
  kEllipseCenterYIndex,
  kEllipseRadiusXIndex,
  kEllipseRadiusYIndex,
  kEllipseHasExplicitCenter,
  kEllipseComponentIndexCount,
};

InterpolationValue ConvertCSSValue(
    const cssvalue::CSSBasicShapeEllipseValue& ellipse,
    const CSSProperty& property) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kEllipseComponentIndexCount);
  list->Set(kEllipseCenterXIndex,
            ConvertCSSCoordinate(ellipse.CenterX(), property));
  list->Set(kEllipseCenterYIndex,
            ConvertCSSCoordinate(ellipse.CenterY(), property));
  list->Set(kEllipseHasExplicitCenter,
            MakeGarbageCollected<InterpolableNumber>(!!ellipse.CenterX()));

  InterpolableValue* radius = nullptr;
  if (!(radius = ConvertCSSRadius(ellipse.RadiusX()))) {
    return nullptr;
  }
  list->Set(kEllipseRadiusXIndex, radius);
  if (!(radius = ConvertCSSRadius(ellipse.RadiusY()))) {
    return nullptr;
  }
  list->Set(kEllipseRadiusYIndex, radius);

  return InterpolationValue(list, BasicShapeNonInterpolableValue::Create(
                                      BasicShape::kBasicShapeEllipseType));
}

InterpolationValue ConvertBasicShape(const BasicShapeEllipse& ellipse,
                                     const CSSProperty& property,
                                     double zoom) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kEllipseComponentIndexCount);
  list->Set(kEllipseCenterXIndex,
            ConvertCoordinate(ellipse.CenterX(), property, zoom));
  list->Set(kEllipseCenterYIndex,
            ConvertCoordinate(ellipse.CenterY(), property, zoom));
  list->Set(kEllipseHasExplicitCenter, MakeGarbageCollected<InterpolableNumber>(
                                           ellipse.HasExplicitCenter()));

  InterpolableValue* radius = nullptr;
  if (!(radius = ConvertRadius(ellipse.RadiusX(), property, zoom))) {
    return nullptr;
  }
  list->Set(kEllipseRadiusXIndex, radius);
  if (!(radius = ConvertRadius(ellipse.RadiusY(), property, zoom))) {
    return nullptr;
  }
  list->Set(kEllipseRadiusYIndex, radius);

  return InterpolationValue(list, BasicShapeNonInterpolableValue::Create(
                                      BasicShape::kBasicShapeEllipseType));
}

InterpolableValue* CreateNeutralValue() {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kEllipseComponentIndexCount);
  list->Set(kEllipseCenterXIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kEllipseCenterYIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kEllipseRadiusXIndex, CreateNeutralInterpolableRadius());
  list->Set(kEllipseRadiusYIndex, CreateNeutralInterpolableRadius());
  list->Set(kEllipseHasExplicitCenter,
            MakeGarbageCollected<InterpolableNumber>(0));
  return list;
}

scoped_refptr<BasicShape> CreateBasicShape(
    const InterpolableValue& interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  scoped_refptr<BasicShapeEllipse> ellipse = BasicShapeEllipse::Create();
  const auto& list = To<InterpolableList>(interpolable_value);
  ellipse->SetCenterX(
      CreateCoordinate(*list.Get(kEllipseCenterXIndex), conversion_data));
  ellipse->SetCenterY(
      CreateCoordinate(*list.Get(kEllipseCenterYIndex), conversion_data));
  ellipse->SetRadiusX(
      CreateRadius(*list.Get(kEllipseRadiusXIndex), conversion_data));
  ellipse->SetRadiusY(
      CreateRadius(*list.Get(kEllipseRadiusYIndex), conversion_data));
  ellipse->SetHasExplicitCenter(
      To<InterpolableNumber>(list.Get(kEllipseHasExplicitCenter))
          ->Value(conversion_data));
  return ellipse;
}

}  // namespace ellipse_functions

namespace inset_functions {

enum InsetComponentIndex : unsigned {
  kInsetTopIndex,
  kInsetRightIndex,
  kInsetBottomIndex,
  kInsetLeftIndex,
  kInsetBorderTopLeftWidthIndex,
  kInsetBorderTopLeftHeightIndex,
  kInsetBorderTopRightWidthIndex,
  kInsetBorderTopRightHeightIndex,
  kInsetBorderBottomRightWidthIndex,
  kInsetBorderBottomRightHeightIndex,
  kInsetBorderBottomLeftWidthIndex,
  kInsetBorderBottomLeftHeightIndex,
  kInsetComponentIndexCount,
};

InterpolationValue ConvertCSSValue(
    const cssvalue::CSSBasicShapeInsetValue& inset) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kInsetComponentIndexCount);
  list->Set(kInsetTopIndex, ConvertCSSLength(inset.Top()));
  list->Set(kInsetRightIndex, ConvertCSSLength(inset.Right()));
  list->Set(kInsetBottomIndex, ConvertCSSLength(inset.Bottom()));
  list->Set(kInsetLeftIndex, ConvertCSSLength(inset.Left()));

  list->Set(kInsetBorderTopLeftWidthIndex,
            ConvertCSSBorderRadiusWidth(inset.TopLeftRadius()));
  list->Set(kInsetBorderTopLeftHeightIndex,
            ConvertCSSBorderRadiusHeight(inset.TopLeftRadius()));
  list->Set(kInsetBorderTopRightWidthIndex,
            ConvertCSSBorderRadiusWidth(inset.TopRightRadius()));
  list->Set(kInsetBorderTopRightHeightIndex,
            ConvertCSSBorderRadiusHeight(inset.TopRightRadius()));
  list->Set(kInsetBorderBottomRightWidthIndex,
            ConvertCSSBorderRadiusWidth(inset.BottomRightRadius()));
  list->Set(kInsetBorderBottomRightHeightIndex,
            ConvertCSSBorderRadiusHeight(inset.BottomRightRadius()));
  list->Set(kInsetBorderBottomLeftWidthIndex,
            ConvertCSSBorderRadiusWidth(inset.BottomLeftRadius()));
  list->Set(kInsetBorderBottomLeftHeightIndex,
            ConvertCSSBorderRadiusHeight(inset.BottomLeftRadius()));
  return InterpolationValue(list, BasicShapeNonInterpolableValue::Create(
                                      BasicShape::kBasicShapeInsetType));
}

void FillCanonicalRect(InterpolableList* list,
                       const cssvalue::CSSBasicShapeRectValue& rect) {
  // rect(t r b l) => inset(t calc(100% - r) calc(100% - b) l).
  list->Set(kInsetTopIndex, ConvertCSSLengthOrAuto(*rect.Top(), 0));
  list->Set(kInsetRightIndex,
            ConvertCSSLengthOrAutoSubtractedFrom100Percent(*rect.Right(), 0));
  list->Set(kInsetBottomIndex,
            ConvertCSSLengthOrAutoSubtractedFrom100Percent(*rect.Bottom(), 0));
  list->Set(kInsetLeftIndex, ConvertCSSLengthOrAuto(*rect.Left(), 0));
}

void FillCanonicalRect(InterpolableList* list,
                       const cssvalue::CSSBasicShapeXYWHValue& xywh) {
  // xywh(x y w h) => inset(y calc(100% - (x + w)) calc(100% - (y + h)) x).
  const CSSPrimitiveValue& x = *xywh.X();
  const CSSPrimitiveValue& y = *xywh.Y();
  const CSSPrimitiveValue& w = *xywh.Width();
  const CSSPrimitiveValue& h = *xywh.Height();
  list->Set(kInsetTopIndex, ConvertCSSLength(y));
  // calc(100% - (x + w)) = calc(100% - x - w).
  list->Set(kInsetRightIndex, ConvertCSSLengthsSubtractedFrom100Percent(x, w));
  // calc(100% - (y + h)) = calc(100% - y - h).
  list->Set(kInsetBottomIndex, ConvertCSSLengthsSubtractedFrom100Percent(y, h));
  list->Set(kInsetLeftIndex, ConvertCSSLength(x));
}

template <typename BasicShapeCSSValueClass>
InterpolationValue ConvertCSSValueToInset(const BasicShapeCSSValueClass& rect) {
  // Spec: All <basic-shape-rect> functions compute to the equivalent
  // inset() function.

  // NOTE: Given `xywh(x y w h)`, the equivalent function is `inset(y
  // calc(100% - x - w) calc(100% - y - h) x)`.  See:
  // https://drafts.csswg.org/css-shapes/#basic-shape-computed-values and
  // https://github.com/w3c/csswg-drafts/issues/9053
  auto* list =
      MakeGarbageCollected<InterpolableList>(kInsetComponentIndexCount);
  FillCanonicalRect(list, rect);

  list->Set(kInsetBorderTopLeftWidthIndex,
            ConvertCSSBorderRadiusWidth(rect.TopLeftRadius()));
  list->Set(kInsetBorderTopLeftHeightIndex,
            ConvertCSSBorderRadiusHeight(rect.TopLeftRadius()));
  list->Set(kInsetBorderTopRightWidthIndex,
            ConvertCSSBorderRadiusWidth(rect.TopRightRadius()));
  list->Set(kInsetBorderTopRightHeightIndex,
            ConvertCSSBorderRadiusHeight(rect.TopRightRadius()));
  list->Set(kInsetBorderBottomRightWidthIndex,
            ConvertCSSBorderRadiusWidth(rect.BottomRightRadius()));
  list->Set(kInsetBorderBottomRightHeightIndex,
            ConvertCSSBorderRadiusHeight(rect.BottomRightRadius()));
  list->Set(kInsetBorderBottomLeftWidthIndex,
            ConvertCSSBorderRadiusWidth(rect.BottomLeftRadius()));
  list->Set(kInsetBorderBottomLeftHeightIndex,
            ConvertCSSBorderRadiusHeight(rect.BottomLeftRadius()));
  return InterpolationValue(list, BasicShapeNonInterpolableValue::Create(
                                      BasicShape::kBasicShapeInsetType));
}

InterpolationValue ConvertBasicShape(const BasicShapeInset& inset,
                                     const CSSProperty& property,
                                     double zoom) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kInsetComponentIndexCount);
  list->Set(kInsetTopIndex, ConvertLength(inset.Top(), property, zoom));
  list->Set(kInsetRightIndex, ConvertLength(inset.Right(), property, zoom));
  list->Set(kInsetBottomIndex, ConvertLength(inset.Bottom(), property, zoom));
  list->Set(kInsetLeftIndex, ConvertLength(inset.Left(), property, zoom));

  list->Set(kInsetBorderTopLeftWidthIndex,
            ConvertLength(inset.TopLeftRadius().Width(), property, zoom));
  list->Set(kInsetBorderTopLeftHeightIndex,
            ConvertLength(inset.TopLeftRadius().Height(), property, zoom));
  list->Set(kInsetBorderTopRightWidthIndex,
            ConvertLength(inset.TopRightRadius().Width(), property, zoom));
  list->Set(kInsetBorderTopRightHeightIndex,
            ConvertLength(inset.TopRightRadius().Height(), property, zoom));
  list->Set(kInsetBorderBottomRightWidthIndex,
            ConvertLength(inset.BottomRightRadius().Width(), property, zoom));
  list->Set(kInsetBorderBottomRightHeightIndex,
            ConvertLength(inset.BottomRightRadius().Height(), property, zoom));
  list->Set(kInsetBorderBottomLeftWidthIndex,
            ConvertLength(inset.BottomLeftRadius().Width(), property, zoom));
  list->Set(kInsetBorderBottomLeftHeightIndex,
            ConvertLength(inset.BottomLeftRadius().Height(), property, zoom));
  return InterpolationValue(list, BasicShapeNonInterpolableValue::Create(
                                      BasicShape::kBasicShapeInsetType));
}

InterpolableValue* CreateNeutralValue() {
  auto* list =
      MakeGarbageCollected<InterpolableList>(kInsetComponentIndexCount);
  list->Set(kInsetTopIndex, InterpolableLength::CreateNeutral());
  list->Set(kInsetRightIndex, InterpolableLength::CreateNeutral());
  list->Set(kInsetBottomIndex, InterpolableLength::CreateNeutral());
  list->Set(kInsetLeftIndex, InterpolableLength::CreateNeutral());

  list->Set(kInsetBorderTopLeftWidthIndex, InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderTopLeftHeightIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderTopRightWidthIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderTopRightHeightIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderBottomRightWidthIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderBottomRightHeightIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderBottomLeftWidthIndex,
            InterpolableLength::CreateNeutral());
  list->Set(kInsetBorderBottomLeftHeightIndex,
            InterpolableLength::CreateNeutral());
  return list;
}

scoped_refptr<BasicShape> CreateBasicShape(
    const InterpolableValue& interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  const auto& list = To<InterpolableList>(interpolable_value);

  scoped_refptr<BasicShapeInset> inset = BasicShapeInset::Create();
  inset->SetTop(To<InterpolableLength>(*list.Get(kInsetTopIndex))
                    .CreateLength(conversion_data, Length::ValueRange::kAll));
  inset->SetRight(To<InterpolableLength>(*list.Get(kInsetRightIndex))
                      .CreateLength(conversion_data, Length::ValueRange::kAll));
  inset->SetBottom(
      To<InterpolableLength>(*list.Get(kInsetBottomIndex))
          .CreateLength(conversion_data, Length::ValueRange::kAll));
  inset->SetLeft(To<InterpolableLength>(*list.Get(kInsetLeftIndex))
                     .CreateLength(conversion_data, Length::ValueRange::kAll));

  inset->SetTopLeftRadius(CreateBorderRadius(
      *list.Get(kInsetBorderTopLeftWidthIndex),
      *list.Get(kInsetBorderTopLeftHeightIndex), conversion_data));
  inset->SetTopRightRadius(CreateBorderRadius(
      *list.Get(kInsetBorderTopRightWidthIndex),
      *list.Get(kInsetBorderTopRightHeightIndex), conversion_data));
  inset->SetBottomRightRadius(CreateBorderRadius(
      *list.Get(kInsetBorderBottomRightWidthIndex),
      *list.Get(kInsetBorderBottomRightHeightIndex), conversion_data));
  inset->SetBottomLeftRadius(CreateBorderRadius(
      *list.Get(kInsetBorderBottomLeftWidthIndex),
      *list.Get(kInsetBorderBottomLeftHeightIndex), conversion_data));
  return inset;
}

}  // namespace inset_functions

namespace polygon_functions {

InterpolationValue ConvertCSSValue(
    const cssvalue::CSSBasicShapePolygonValue& polygon) {
  wtf_size_t size = polygon.Values().size();
  auto* list = MakeGarbageCollected<InterpolableList>(size);
  for (wtf_size_t i = 0; i < size; i++) {
    list->Set(i, ConvertCSSLength(polygon.Values()[i].Get()));
  }
  return InterpolationValue(list, BasicShapeNonInterpolableValue::CreatePolygon(
                                      polygon.GetWindRule(), size));
}

InterpolationValue ConvertBasicShape(const BasicShapePolygon& polygon,
                                     const CSSProperty& property,
                                     double zoom) {
  wtf_size_t size = polygon.Values().size();
  auto* list = MakeGarbageCollected<InterpolableList>(size);
  for (wtf_size_t i = 0; i < size; i++) {
    list->Set(i, ConvertLength(polygon.Values()[i], property, zoom));
  }
  return InterpolationValue(list, BasicShapeNonInterpolableValue::CreatePolygon(
                                      polygon.GetWindRule(), size));
}

InterpolableValue* CreateNeutralValue(
    const BasicShapeNonInterpolableValue& non_interpolable_value) {
  auto* list =
      MakeGarbageCollected<InterpolableList>(non_interpolable_value.size());
  for (wtf_size_t i = 0; i < non_interpolable_value.size(); i++) {
    list->Set(i, InterpolableLength::CreateNeutral());
  }
  return list;
}

scoped_refptr<BasicShape> CreateBasicShape(
    const InterpolableValue& interpolable_value,
    const BasicShapeNonInterpolableValue& non_interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  scoped_refptr<BasicShapePolygon> polygon = BasicShapePolygon::Create();
  polygon->SetWindRule(non_interpolable_value.GetWindRule());
  const auto& list = To<InterpolableList>(interpolable_value);
  wtf_size_t size = non_interpolable_value.size();
  DCHECK_EQ(list.length(), size);
  DCHECK_EQ(size % 2, 0U);
  for (wtf_size_t i = 0; i < size; i += 2) {
    polygon->AppendPoint(
        To<InterpolableLength>(*list.Get(i))
            .CreateLength(conversion_data, Length::ValueRange::kAll),
        To<InterpolableLength>(*list.Get(i + 1))
            .CreateLength(conversion_data, Length::ValueRange::kAll));
  }
  return polygon;
}

}  // namespace polygon_functions

}  // namespace

InterpolationValue basic_shape_interpolation_functions::MaybeConvertCSSValue(
    const CSSValue& value,
    const CSSProperty& property) {
  if (auto* circle_value =
          DynamicTo<cssvalue::CSSBasicShapeCircleValue>(value)) {
    return circle_functions::ConvertCSSValue(*circle_value, property);
  }

  if (auto* ellipse_value =
          DynamicTo<cssvalue::CSSBasicShapeEllipseValue>(value)) {
    return ellipse_functions::ConvertCSSValue(*ellipse_value, property);
  }
  if (auto* inset_value = DynamicTo<cssvalue::CSSBasicShapeInsetValue>(value)) {
    return inset_functions::ConvertCSSValue(*inset_value);
  }
  if (auto* rect_value = DynamicTo<cssvalue::CSSBasicShapeRectValue>(value)) {
    return inset_functions::ConvertCSSValueToInset(*rect_value);
  }
  if (auto* xywh_value = DynamicTo<cssvalue::CSSBasicShapeXYWHValue>(value)) {
    return inset_functions::ConvertCSSValueToInset(*xywh_value);
  }
  if (auto* polygon_value =
          DynamicTo<cssvalue::CSSBasicShapePolygonValue>(value)) {
    return polygon_functions::ConvertCSSValue(*polygon_value);
  }
  return nullptr;
}

InterpolationValue basic_shape_interpolation_functions::MaybeConvertBasicShape(
    const BasicShape* shape,
    const CSSProperty& property,
    double zoom) {
  if (!shape) {
    return nullptr;
  }
  switch (shape->GetType()) {
    case BasicShape::kBasicShapeCircleType:
      return circle_functions::ConvertBasicShape(To<BasicShapeCircle>(*shape),
                                                 property, zoom);
    case BasicShape::kBasicShapeEllipseType:
      return ellipse_functions::ConvertBasicShape(To<BasicShapeEllipse>(*shape),
                                                  property, zoom);
    case BasicShape::kBasicShapeInsetType:
      return inset_functions::ConvertBasicShape(To<BasicShapeInset>(*shape),
                                                property, zoom);
    case BasicShape::kBasicShapePolygonType:
      return polygon_functions::ConvertBasicShape(To<BasicShapePolygon>(*shape),
                                                  property, zoom);
    // Handled by PathInterpolationFunction.
    case BasicShape::kStylePathType:
      return nullptr;
    default:
      NOTREACHED();
  }
}

InterpolableValue* basic_shape_interpolation_functions::CreateNeutralValue(
    const NonInterpolableValue& untyped_non_interpolable_value) {
  const auto& non_interpolable_value =
      To<BasicShapeNonInterpolableValue>(untyped_non_interpolable_value);
  switch (non_interpolable_value.GetShapeType()) {
    case BasicShape::kBasicShapeCircleType:
      return circle_functions::CreateNeutralValue();
    case BasicShape::kBasicShapeEllipseType:
      return ellipse_functions::CreateNeutralValue();
    case BasicShape::kBasicShapeInsetType:
      return inset_functions::CreateNeutralValue();
    case BasicShape::kBasicShapePolygonType:
      return polygon_functions::CreateNeutralValue(non_interpolable_value);
    default:
      NOTREACHED();
  }
}

bool basic_shape_interpolation_functions::ShapesAreCompatible(
    const NonInterpolableValue& a,
    const NonInterpolableValue& b) {
  return To<BasicShapeNonInterpolableValue>(a).IsCompatibleWith(
      To<BasicShapeNonInterpolableValue>(b));
}

scoped_refptr<BasicShape> basic_shape_interpolation_functions::CreateBasicShape(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue& untyped_non_interpolable_value,
    const CSSToLengthConversionData& conversion_data) {
  const auto& non_interpolable_value =
      To<BasicShapeNonInterpolableValue>(untyped_non_interpolable_value);
  switch (non_interpolable_value.GetShapeType()) {
    case BasicShape::kBasicShapeCircleType:
      return circle_functions::CreateBasicShape(interpolable_value,
                                                conversion_data);
    case BasicShape::kBasicShapeEllipseType:
      return ellipse_functions::CreateBasicShape(interpolable_value,
                                                 conversion_data);
    case BasicShape::kBasicShapeInsetType:
      return inset_functions::CreateBasicShape(interpolable_value,
                                               conversion_data);
    case BasicShape::kBasicShapePolygonType:
      return polygon_functions::CreateBasicShape(
          interpolable_value, non_interpolable_value, conversion_data);
    default:
      NOTREACHED();
  }
}

}  // namespace blink
```