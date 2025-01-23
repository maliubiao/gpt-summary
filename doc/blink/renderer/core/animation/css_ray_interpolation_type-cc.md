Response:
Let's break down the thought process for analyzing this code.

1. **Understand the Goal:** The request asks for the functionality of the `css_ray_interpolation_type.cc` file in the Blink rendering engine. It also asks for connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), and common usage errors.

2. **High-Level Overview:** The filename itself, "css_ray_interpolation_type.cc," strongly suggests this file is responsible for *animating* or *transitioning* CSS `ray()` values. The word "interpolation" is the key here. CSS animations and transitions involve calculating intermediate values between a starting and ending state.

3. **Identify Key Classes and Structures:**  The code uses several custom classes and structures. The most prominent are:
    * `CSSRayInterpolationType`: This is the central class, likely registered with the animation system.
    * `StyleRay`: Represents the parsed `ray()` CSS function. It holds information like angle, size, and center.
    * `CSSRayNonInterpolableValue`: A wrapper to store non-interpolatable parts of the `ray()` function (like the `contain` keyword or the coordinate box). This is important because not *everything* in a `ray()` can be smoothly interpolated.
    * `RayMode`: A helper class to group the non-interpolatable aspects of a `ray()`. This is used for checking compatibility during transitions.
    * `InterpolableList`: A generic way to store a list of interpolatable values. In this case, it's used to represent the different components of the `ray()` that *can* be interpolated (angle, center coordinates).
    * `InterpolableNumber`, `InterpolableLength`:  Represent numeric and length values that can be interpolated.

4. **Trace the Core Functionality (Interpolation Process):**  The primary purpose is to interpolate between two `ray()` values. Let's look for methods that hint at this process:
    * `MaybeConvertValue()`: This likely handles converting a raw CSS `ray()` value into an internal representation suitable for interpolation. It parses the CSS and extracts relevant data.
    * `CreateValue()`:  This method seems to package the interpolatable parts (angle, center) into an `InterpolableList` and the non-interpolatable parts into a `CSSRayNonInterpolableValue`.
    * `ApplyStandardPropertyValue()`:  This is the reverse of `MaybeConvertValue()`. It takes the *interpolated* values and applies them back to the element's style. It reconstructs the `StyleRay` and sets the `offset-path` property.
    * `Composite()`: This method is central to the interpolation. It determines how to combine the "underlying" (current) value with the target value at a specific point in the animation. The check for `underlying_mode == ray_mode` is crucial – it ensures that only compatible `ray()` values are smoothly interpolated. If they aren't compatible (different `contain` or coordinate box), it jumps directly to the target value.
    * `MaybeConvertNeutral()`:  This likely creates a "neutral" or starting point for interpolation if one isn't explicitly defined.
    * `MaybeMergeSingles()`: This method checks if two individual `InterpolationValue` objects can be merged for a smooth transition. The mode check is present here as well.

5. **Identify Relationships to Web Technologies:**
    * **CSS:** The entire file revolves around the CSS `ray()` function, specifically used with the `offset-path` property.
    * **JavaScript:**  JavaScript is used to trigger and control CSS animations and transitions. The code here enables these animations for `ray()`. When a JavaScript animation or transition modifies an element's `offset-path` using a `ray()`, this code comes into play.
    * **HTML:**  HTML elements are styled using CSS. The `offset-path` property, and thus the `ray()` function, is applied to HTML elements.

6. **Construct Examples and Scenarios:** Now, let's create concrete examples to illustrate the concepts:
    * **Simple Interpolation:**  Animate the angle of a `ray()`.
    * **Non-Interpolatable Change:** Transition between `ray()` functions with different `contain` values.
    * **Usage Errors:**  Try to animate between incompatible `ray()` values.

7. **Logical Reasoning (Input/Output):**  Focus on the `Composite()` function. If the `RayMode` is the same, the angle and center coordinates will be interpolated. If the `RayMode` is different, the output jumps to the end value.

8. **Common Usage Errors:** Think about what a developer might do incorrectly when trying to animate `ray()` functions. Mismatched `contain` values are a prime example.

9. **Refine and Organize:**  Review the generated information, organize it logically, and ensure clarity and accuracy. Use headings and bullet points to improve readability. Ensure the explanation flows naturally and addresses all parts of the original request. For instance, explicitly mention the role of `offset-path`.

Self-Correction/Refinement during the process:

* **Initial thought:** "This is just about parsing the `ray()` function."  **Correction:** The "interpolation" part is crucial. It's not just about parsing but about *animating* the values.
* **Focusing too much on syntax:**  Shift focus from the exact syntax of the C++ to the *conceptual* role of each part. What does `RayMode` *represent*? Why is it important?
* **Not enough connection to web technologies:**  Initially, the connection might be implicit. Make it explicit by mentioning `offset-path`, CSS animations/transitions, and JavaScript's role in triggering these.
* **Vague examples:**  Make the examples concrete and illustrate the "before" and "after" states.

By following these steps, we can systematically analyze the code and generate a comprehensive explanation like the example provided.
这个文件 `css_ray_interpolation_type.cc` 是 Chromium Blink 渲染引擎中的一部分，专门负责处理 CSS `ray()` 函数的动画和过渡效果的插值（interpolation）。更具体地说，它定义了如何在两个不同的 `ray()` 值之间进行平滑过渡。

以下是它的主要功能：

**1. 定义 `ray()` 函数的插值方式:**

   - 该文件定义了 `CSSRayInterpolationType` 类，这个类实现了 `CSSInterpolationType` 接口。这个接口是 Blink 中用于处理各种 CSS 属性动画和过渡的核心机制。
   - 它指定了如何对 `ray()` 函数的不同组成部分进行插值，例如射线的角度、中心点的 X 和 Y 坐标。

**2. 处理 `ray()` 函数的非插值部分:**

   - CSS `ray()` 函数有一些属性在动画或过渡中不能直接插值，例如 `contain` 关键字（`contain` 或 `cover`）和坐标盒模型（例如 `border-box`）。
   - 文件中定义了 `CSSRayNonInterpolableValue` 类来存储这些非插值部分。在插值过程中，会保持这些值不变。

**3. 类型转换和创建插值值:**

   - 提供了 `MaybeConvertValue` 函数，用于将 CSS `ray()` 值转换为可以用于插值的内部表示 `InterpolationValue`。
   - `CreateValue` 函数用于创建一个 `InterpolationValue` 对象，其中包含了可插值的数值部分（例如角度和中心坐标，存储在 `InterpolableList` 中）以及非插值部分（存储在 `CSSRayNonInterpolableValue` 中）。
   - `CreateNeutralValue` 函数用于创建一个“中性”的插值值，这在某些动画场景下作为起始或结束值使用。

**4. 应用插值后的值:**

   - `ApplyStandardPropertyValue` 函数将插值计算后的值应用到元素的样式上。它根据插值得到的角度和中心坐标等信息，重新构建 `StyleRay` 对象，并将其设置为元素的 `offset-path` 属性。

**5. 合成（Compositing）插值值:**

   - `Composite` 函数负责在动画的每一帧，根据插值进度计算出最终的 `ray()` 值。它会检查两个 `ray()` 值的非插值部分是否相同，如果相同，则对可插值部分进行线性插值；如果不同，则直接切换到目标值。

**6. 处理继承、初始值和中性值:**

   - `MaybeConvertInitial` 和 `MaybeConvertInherit` 函数分别处理 `ray()` 属性的初始值和继承值。
   - `MaybeConvertNeutral` 函数用于创建一个中性的插值值，以便在没有明确起始或结束值时进行插值。

**7. 合并单个插值值对:**

   - `MaybeMergeSingles` 函数用于尝试合并两个单独的 `InterpolationValue` 对象，以便进行更高效的插值。它会检查两个值的非插值部分是否一致。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个文件直接关系到 CSS 的 `ray()` 函数和 `offset-path` 属性的动画和过渡。

* **CSS:**
    - `ray()` 函数是 CSS 形状函数，用于定义一个从指定中心点向外发射的射线。
    - `offset-path` 属性允许将元素沿着一个路径进行动画或定位，`ray()` 可以作为 `offset-path` 的值之一。
    - **举例:** 你可以使用 CSS 过渡或动画来改变一个元素的 `offset-path` 属性的 `ray()` 值，例如改变射线的角度，使其看起来像在旋转。

      ```css
      .element {
        offset-path: ray(0deg);
        transition: offset-path 1s ease-in-out;
      }

      .element:hover {
        offset-path: ray(180deg);
      }
      ```

* **JavaScript:**
    - JavaScript 可以动态地修改元素的 CSS 属性，包括 `offset-path`，从而触发 `ray()` 函数的动画或过渡。
    - **举例:** 你可以使用 JavaScript 来动态改变 `ray()` 函数的角度：

      ```javascript
      const element = document.querySelector('.element');
      element.style.offsetPath = 'ray(90deg)';
      ```
    - JavaScript 的 `animate()` API 也可以用于创建 `offset-path` 属性的动画，Blink 引擎会使用 `CSSRayInterpolationType` 来处理 `ray()` 值的插值。

      ```javascript
      element.animate([
        { offsetPath: 'ray(0deg)' },
        { offsetPath: 'ray(180deg)' }
      ], {
        duration: 1000,
        easing: 'ease-in-out'
      });
      ```

* **HTML:**
    - HTML 元素是应用这些 CSS 样式和 JavaScript 动画的目标。
    - **举例:**

      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          .element {
            width: 50px;
            height: 50px;
            background-color: red;
            position: absolute; /* offset-path 需要配合绝对或固定定位 */
            offset-path: ray(45deg);
            transition: offset-path 1s ease-in-out;
          }

          .element:hover {
            offset-path: ray(135deg);
          }
        </style>
      </head>
      <body>
        <div class="element"></div>
      </body>
      </html>
      ```

**逻辑推理 (假设输入与输出):**

假设我们有一个元素，其 `offset-path` 属性正在从 `ray(45deg)` 过渡到 `ray(135deg)`。

**假设输入:**

* **起始值:** `ray(45deg)`
* **结束值:** `ray(135deg)`
* **插值进度:** 0.5 (表示过渡进行到一半)

**输出 (推断):**

由于 `ray()` 函数的角度是可插值的数值，`CSSRayInterpolationType` 会计算出中间值。线性插值计算如下：

`中间角度 = 起始角度 + (结束角度 - 起始角度) * 插值进度`
`中间角度 = 45deg + (135deg - 45deg) * 0.5`
`中间角度 = 45deg + 90deg * 0.5`
`中间角度 = 45deg + 45deg`
`中间角度 = 90deg`

因此，在插值进度为 0.5 时，元素的 `offset-path` 属性的 `ray()` 值会被计算为 `ray(90deg)`。

**涉及用户或者编程常见的使用错误:**

1. **尝试在非数值属性上进行插值:** 用户可能会尝试在 `ray()` 函数的非数值部分（如 `contain` 值）之间进行平滑过渡。例如，从 `ray(45deg contain)` 过渡到 `ray(45deg cover)`。`CSSRayInterpolationType` 会检测到这些非插值部分的差异，并可能直接切换到目标值，而不是平滑过渡。

   **举例:**

   ```css
   .element {
     offset-path: ray(45deg contain);
     transition: offset-path 1s ease-in-out;
   }

   .element:hover {
     offset-path: ray(45deg cover);
   }
   ```

   在这个例子中，hover 时元素的 `offset-path` 可能会瞬间从 `contain` 变为 `cover`，而不是平滑过渡。

2. **忘记配合 `position: absolute` 或 `position: fixed` 使用 `offset-path`:**  `offset-path` 属性通常需要与绝对定位或固定定位配合使用才能生效。如果用户忘记设置这些定位方式，`ray()` 函数的动画可能不会产生预期的视觉效果。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <style>
       .element {
         width: 50px;
         height: 50px;
         background-color: red;
         /* 缺少 position: absolute; */
         offset-path: ray(45deg);
         transition: offset-path 1s ease-in-out;
       }

       .element:hover {
         offset-path: ray(135deg);
       }
     </style>
   </head>
   <body>
     <div class="element"></div>
   </body>
   </html>
   ```

   在这个例子中，即使 `offset-path` 的值发生了变化，由于元素没有被绝对或固定定位，它可能不会沿着射线路径移动。

3. **假设所有 `ray()` 函数的值都可以平滑过渡:**  用户可能没有意识到 `ray()` 函数的某些部分是不可插值的。因此，他们可能会期望所有从一个 `ray()` 值到另一个 `ray()` 值的过渡都是平滑的，但实际上，非插值部分的改变会导致跳跃。

总而言之，`css_ray_interpolation_type.cc` 是 Blink 引擎中处理 CSS `ray()` 函数动画和过渡的关键部分，它负责定义如何对 `ray()` 函数的值进行插值，并确保在 Web 页面上能够实现平滑的动画效果。理解这个文件的功能有助于开发者更好地利用 CSS `ray()` 函数创建复杂的动画和布局效果。

### 提示词
```
这是目录为blink/renderer/core/animation/css_ray_interpolation_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/css_ray_interpolation_type.h"

#include <memory>
#include <utility>

#include "third_party/blink/renderer/core/animation/interpolable_length.h"
#include "third_party/blink/renderer/core/css/basic_shape_functions.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_ray_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/shape_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/style_ray.h"

namespace blink {

namespace {

class RayMode {
 public:
  RayMode(StyleRay::RaySize size, bool contain, CoordBox coord_box)
      : size_(size), contain_(contain), coord_box_(coord_box) {}

  RayMode(const StyleRay& style_ray, CoordBox coord_box)
      : size_(style_ray.Size()),
        contain_(style_ray.Contain()),
        coord_box_(coord_box) {}

  StyleRay::RaySize Size() const { return size_; }
  bool Contain() const { return contain_; }
  CoordBox GetCoordBox() const { return coord_box_; }

  bool operator==(const RayMode& other) const {
    return size_ == other.size_ && contain_ == other.contain_ &&
           coord_box_ == other.coord_box_;
  }
  bool operator!=(const RayMode& other) const { return !(*this == other); }

 private:
  StyleRay::RaySize size_;
  bool contain_;
  CoordBox coord_box_;
};

}  // namespace

class CSSRayNonInterpolableValue : public NonInterpolableValue {
 public:
  static scoped_refptr<CSSRayNonInterpolableValue> Create(const RayMode& mode) {
    return base::AdoptRef(new CSSRayNonInterpolableValue(mode));
  }

  const RayMode& Mode() const { return mode_; }

  DECLARE_NON_INTERPOLABLE_VALUE_TYPE();

 private:
  explicit CSSRayNonInterpolableValue(const RayMode& mode) : mode_(mode) {}

  const RayMode mode_;
};

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(CSSRayNonInterpolableValue);
template <>
struct DowncastTraits<CSSRayNonInterpolableValue> {
  static bool AllowFrom(const NonInterpolableValue* value) {
    return value && AllowFrom(*value);
  }
  static bool AllowFrom(const NonInterpolableValue& value) {
    return value.GetType() == CSSRayNonInterpolableValue::static_type_;
  }
};

namespace {

struct StyleRayAndCoordBox {
  const StyleRay* ray;
  const CoordBox coord_box;
};

// Returns the offset-path ray() value.
// If the offset-path is not a ray(), returns nullptr.
StyleRayAndCoordBox GetRay(const ComputedStyle& style) {
  const auto* offset_shape =
      DynamicTo<ShapeOffsetPathOperation>(style.OffsetPath());
  if (!offset_shape) {
    return {nullptr, CoordBox::kBorderBox};
  }
  const BasicShape& shape = offset_shape->GetBasicShape();
  const CoordBox coord_box = offset_shape->GetCoordBox();
  return {DynamicTo<StyleRay>(shape), coord_box};
}

class UnderlyingRayModeChecker
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  explicit UnderlyingRayModeChecker(const RayMode& mode) : mode_(mode) {}

  bool IsValid(const StyleResolverState&,
               const InterpolationValue& underlying) const final {
    return mode_ ==
           To<CSSRayNonInterpolableValue>(*underlying.non_interpolable_value)
               .Mode();
  }

 private:
  const RayMode mode_;
};

class InheritedRayChecker : public CSSInterpolationType::CSSConversionChecker {
 public:
  InheritedRayChecker(scoped_refptr<const StyleRay> style_ray,
                      CoordBox coord_box)
      : style_ray_(std::move(style_ray)), coord_box_(coord_box) {
    DCHECK(style_ray_);
  }

 private:
  bool IsValid(const StyleResolverState& state,
               const InterpolationValue&) const final {
    const auto& [ray, coord_box] = GetRay(*state.ParentStyle());
    return ray == style_ray_.get() && coord_box_ == coord_box;
  }

  scoped_refptr<const StyleRay> style_ray_;
  CoordBox coord_box_;
};

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

enum RayComponentIndex : unsigned {
  kRayAngleIndex,
  kRayCenterXIndex,
  kRayCenterYIndex,
  kRayHasExplicitCenterIndex,
  kRayComponentIndexCount,
};

InterpolationValue CreateValue(const StyleRay& ray,
                               CoordBox coord_box,
                               const CSSProperty& property,
                               double zoom) {
  auto* list = MakeGarbageCollected<InterpolableList>(kRayComponentIndexCount);
  list->Set(kRayAngleIndex,
            MakeGarbageCollected<InterpolableNumber>(
                ray.Angle(), CSSPrimitiveValue::UnitType::kDegrees));
  list->Set(kRayCenterXIndex, ConvertCoordinate(ray.CenterX(), property, zoom));
  list->Set(kRayCenterYIndex, ConvertCoordinate(ray.CenterY(), property, zoom));
  list->Set(kRayHasExplicitCenterIndex,
            MakeGarbageCollected<InterpolableNumber>(ray.HasExplicitCenter()));
  return InterpolationValue(
      list, CSSRayNonInterpolableValue::Create(RayMode(ray, coord_box)));
}

InterpolationValue CreateNeutralValue(const RayMode& mode) {
  auto* list = MakeGarbageCollected<InterpolableList>(kRayComponentIndexCount);
  list->Set(kRayAngleIndex, MakeGarbageCollected<InterpolableNumber>(
                                0, CSSPrimitiveValue::UnitType::kDegrees));
  list->Set(kRayCenterXIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kRayCenterYIndex, CreateNeutralInterpolableCoordinate());
  list->Set(kRayHasExplicitCenterIndex,
            MakeGarbageCollected<InterpolableNumber>(0));
  return InterpolationValue(list, CSSRayNonInterpolableValue::Create(mode));
}

InterpolationValue CreateValue(const CSSValue& angle,
                               const StyleRay& ray,
                               CoordBox coord_box,
                               const CSSProperty& property,
                               double zoom) {
  auto* list = MakeGarbageCollected<InterpolableList>(kRayComponentIndexCount);
  if (auto* numeric_value = DynamicTo<CSSNumericLiteralValue>(angle)) {
    list->Set(kRayAngleIndex, MakeGarbageCollected<InterpolableNumber>(
                                  numeric_value->ComputeDegrees(),
                                  CSSPrimitiveValue::UnitType::kDegrees));
  } else {
    CHECK(angle.IsMathFunctionValue());
    const auto& function_value = To<CSSMathFunctionValue>(angle);
    list->Set(kRayAngleIndex, MakeGarbageCollected<InterpolableNumber>(
                                  *function_value.ExpressionNode()));
  }
  list->Set(kRayCenterXIndex, ConvertCoordinate(ray.CenterX(), property, zoom));
  list->Set(kRayCenterYIndex, ConvertCoordinate(ray.CenterY(), property, zoom));
  list->Set(kRayHasExplicitCenterIndex,
            MakeGarbageCollected<InterpolableNumber>(ray.HasExplicitCenter()));
  return InterpolationValue(
      list, CSSRayNonInterpolableValue::Create(RayMode(ray, coord_box)));
}

}  // namespace

void CSSRayInterpolationType::ApplyStandardPropertyValue(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue* non_interpolable_value,
    StyleResolverState& state) const {
  const auto& ray_non_interpolable_value =
      To<CSSRayNonInterpolableValue>(*non_interpolable_value);
  const auto& list = To<InterpolableList>(interpolable_value);
  scoped_refptr<StyleRay> style_ray = StyleRay::Create(
      To<InterpolableNumber>(list.Get(kRayAngleIndex))
          ->Value(state.CssToLengthConversionData()),
      ray_non_interpolable_value.Mode().Size(),
      ray_non_interpolable_value.Mode().Contain(),
      CreateCoordinate(*list.Get(kRayCenterXIndex),
                       state.CssToLengthConversionData()),
      CreateCoordinate(*list.Get(kRayCenterYIndex),
                       state.CssToLengthConversionData()),
      To<InterpolableNumber>(list.Get(kRayHasExplicitCenterIndex))
          ->Value(state.CssToLengthConversionData()));
  state.StyleBuilder().SetOffsetPath(
      MakeGarbageCollected<ShapeOffsetPathOperation>(
          style_ray, ray_non_interpolable_value.Mode().GetCoordBox()));
}

void CSSRayInterpolationType::Composite(
    UnderlyingValueOwner& underlying_value_owner,
    double underlying_fraction,
    const InterpolationValue& value,
    double interpolation_fraction) const {
  const RayMode& underlying_mode =
      To<CSSRayNonInterpolableValue>(
          *underlying_value_owner.Value().non_interpolable_value)
          .Mode();
  const RayMode& ray_mode =
      To<CSSRayNonInterpolableValue>(*value.non_interpolable_value).Mode();
  if (underlying_mode == ray_mode) {
    underlying_value_owner.MutableValue().interpolable_value->ScaleAndAdd(
        underlying_fraction, *value.interpolable_value);
  } else {
    underlying_value_owner.Set(*this, value);
  }
}

InterpolationValue CSSRayInterpolationType::MaybeConvertNeutral(
    const InterpolationValue& underlying,
    ConversionCheckers& conversion_checkers) const {
  const RayMode& underlying_mode =
      To<CSSRayNonInterpolableValue>(*underlying.non_interpolable_value).Mode();
  conversion_checkers.push_back(
      MakeGarbageCollected<UnderlyingRayModeChecker>(underlying_mode));
  return CreateNeutralValue(underlying_mode);
}

InterpolationValue CSSRayInterpolationType::MaybeConvertInitial(
    const StyleResolverState&,
    ConversionCheckers&) const {
  // 'none' is not a ray().
  return nullptr;
}

InterpolationValue CSSRayInterpolationType::MaybeConvertInherit(
    const StyleResolverState& state,
    ConversionCheckers& conversion_checkers) const {
  if (!state.ParentStyle())
    return nullptr;

  const auto& [inherited_ray, coord_box] = GetRay(*state.ParentStyle());
  if (!inherited_ray)
    return nullptr;

  conversion_checkers.push_back(
      MakeGarbageCollected<InheritedRayChecker>(inherited_ray, coord_box));
  return CreateValue(*inherited_ray, coord_box, CssProperty(),
                     state.ParentStyle()->EffectiveZoom());
}

PairwiseInterpolationValue CSSRayInterpolationType::MaybeMergeSingles(
    InterpolationValue&& start,
    InterpolationValue&& end) const {
  const RayMode& start_mode =
      To<CSSRayNonInterpolableValue>(*start.non_interpolable_value).Mode();
  const RayMode& end_mode =
      To<CSSRayNonInterpolableValue>(*end.non_interpolable_value).Mode();
  if (start_mode != end_mode)
    return nullptr;
  return PairwiseInterpolationValue(std::move(start.interpolable_value),
                                    std::move(end.interpolable_value),
                                    std::move(start.non_interpolable_value));
}

InterpolationValue
CSSRayInterpolationType::MaybeConvertStandardPropertyUnderlyingValue(
    const ComputedStyle& style) const {
  const auto& [underlying_ray, coord_box] = GetRay(style);
  if (!underlying_ray)
    return nullptr;

  return CreateValue(*underlying_ray, coord_box, CssProperty(),
                     style.EffectiveZoom());
}

InterpolationValue CSSRayInterpolationType::MaybeConvertValue(
    const CSSValue& value,
    const StyleResolverState* state,
    ConversionCheckers&) const {
  DCHECK(state);
  scoped_refptr<BasicShape> shape = nullptr;
  CoordBox coord_box = CoordBox::kBorderBox;
  const CSSPrimitiveValue* angle = nullptr;
  // TODO(crbug.com/326260768): Don't use the resolved center coordinates.
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    if (list->First().IsRayValue()) {
      angle = &To<cssvalue::CSSRayValue>(list->First()).Angle();
      shape = BasicShapeForValue(*state, list->First());
      if (list->length() == 2) {
        coord_box = To<CSSIdentifierValue>(list->Last()).ConvertTo<CoordBox>();
      }
    }
  } else if (value.IsRayValue()) {
    angle = &To<cssvalue::CSSRayValue>(value).Angle();
    shape = BasicShapeForValue(*state, value);
  }
  if (!shape) {
    return nullptr;
  }
  return CreateValue(*angle, To<StyleRay>(*shape), coord_box, CssProperty(),
                     state->ParentStyle()->EffectiveZoom());
}

}  // namespace blink
```