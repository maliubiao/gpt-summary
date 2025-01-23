Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Identify the Core Purpose:** The filename `css_image_slice_interpolation_type.cc` and the namespace `blink::animation` immediately suggest this code deals with animating the `image-slice` CSS property within the Blink rendering engine. The keyword "interpolation" is a strong indicator that it's about smoothly transitioning between different values of this property.

2. **Deconstruct the Code - Top Down:** Start by looking at the overall structure and key classes.

    * **Includes:**  Note the included headers. They provide clues about dependencies and related functionality. `css_length_interpolation_type.h`, `image_slice_property_functions.h`, `css_border_image_slice_value.h` are all directly related to the `image-slice` property and CSS concepts.

    * **Namespaces:**  The `blink` namespace is expected. The anonymous namespace `namespace {}` is used for internal implementation details.

    * **`SliceTypes` struct:** This struct is crucial. It holds information about whether each side of the slice is a number (pixels) or a percentage, and whether the `fill` keyword is present. This immediately points to the two possible ways to define `image-slice` values in CSS. The overloaded constructor for `ImageSlice` and `CSSBorderImageSliceValue` reinforces this. The equality operators are for comparing these type configurations.

    * **`CSSImageSliceNonInterpolableValue` class:**  This derives from `NonInterpolableValue`. The name suggests this class stores information that *doesn't* get interpolated directly. Given the `SliceTypes` it holds, this likely means the *type* of the slice (number or percentage, presence of `fill`) remains constant during an animation. Only the *numeric values* are interpolated.

    * **Checker Classes (`UnderlyingSliceTypesChecker`, `InheritedSliceTypesChecker`):** These are used for validation during the interpolation process. They ensure that the types of the slices are consistent when transitioning between different values or inheriting values.

    * **`ConvertImageSlice` function:** This function takes an `ImageSlice` and converts it into an `InterpolationValue`. This is a key step in preparing the value for animation. It creates an `InterpolableList` (likely representing the top, right, bottom, left values) and the `CSSImageSliceNonInterpolableValue` (storing the types).

    * **`CSSImageSliceInterpolationType` class:** This is the main class. It inherits from `CSSInterpolationType`, indicating it's responsible for handling the interpolation of `image-slice` properties. Its methods implement the core logic of conversion, merging, compositing, and applying the interpolated values.

3. **Analyze Key Methods:** Focus on the methods within `CSSImageSliceInterpolationType` as they define the interpolation behavior.

    * **`MaybeConvertNeutral`:**  Handles the "neutral" value in animations (often the initial state). It creates a zero-valued slice with the same type configuration as the underlying value.

    * **`MaybeConvertInitial`:** Handles the "initial" value of the property. It fetches the initial `image-slice` value from the style system.

    * **`MaybeConvertInherit`:** Handles the "inherit" value. It retrieves the inherited `image-slice` value from the parent element's style.

    * **`MaybeConvertValue`:** This is crucial. It takes a `CSSValue` (specifically a `CSSBorderImageSliceValue`) and converts it into an `InterpolationValue`. It parses the different ways `image-slice` can be specified (numbers, percentages, `fill`). Notice the handling of `CSSNumericLiteralValue` and `CSSMathFunctionValue`.

    * **`MaybeConvertStandardPropertyUnderlyingValue`:** Gets the current `image-slice` value from a `ComputedStyle`.

    * **`MaybeMergeSingles`:**  Determines if two single `InterpolationValue`s can be merged for pairwise interpolation. It checks if the `SliceTypes` are the same.

    * **`Composite`:** This is where the actual interpolation happens. It blends the underlying value with the target value based on the interpolation fraction. It only interpolates if the types are the same; otherwise, it directly sets the value.

    * **`ApplyStandardPropertyValue`:**  This method takes the *interpolated* value and applies it to the element's style. It converts the `InterpolableList` back into `Length` values (pixels or percentages) based on the stored `SliceTypes`.

4. **Connect to Web Technologies (HTML, CSS, JavaScript):**

    * **CSS:** The entire file revolves around the `border-image-slice` CSS property (implicitly). The `SliceTypes` struct directly maps to the syntax of this property. The handling of numbers, percentages, and the `fill` keyword are all core to CSS.

    * **HTML:** While not directly manipulated in this *specific* file, the results of this code affect how elements styled with `border-image-slice` are rendered.

    * **JavaScript:**  JavaScript animations using the Web Animations API or CSS Transitions/Animations can trigger this interpolation logic. When a JavaScript animation changes the `border-image-slice` property, this code is responsible for the smooth transition.

5. **Infer Logic and Examples:** Based on the code, construct scenarios. Think about what happens when animating between different `border-image-slice` values.

    * **Scenario 1 (Same Types):** Animating from `border-image-slice: 10px 20px 30px 40px fill;` to `border-image-slice: 50px 60px 70px 80px fill;`. Here, `SliceTypes` will be the same, so the numeric values will be interpolated.

    * **Scenario 2 (Different Types):** Animating from `border-image-slice: 10px 20px 30px 40px;` to `border-image-slice: 10% 20% 30% 40%;`. The `SliceTypes` will be different. The `Composite` method will detect this and likely perform a discrete jump instead of a smooth interpolation.

    * **Scenario 3 (Missing `fill`):** Animating between values with and without the `fill` keyword. This will also result in different `SliceTypes` and a discrete jump.

6. **Identify Potential Errors:** Think about how developers might misuse the `border-image-slice` property or animations involving it.

    * **Mismatched Units:** Trying to smoothly animate between pixel and percentage values would be problematic. The code handles this by storing the type information.

    * **Inconsistent `fill` keyword:**  Animating between states with and without `fill` would lead to abrupt changes.

7. **Refine and Organize:** Structure the analysis logically, starting with a high-level overview and then diving into specifics. Use clear examples and connect the code to web development concepts. Use bullet points or numbered lists for clarity. Explain technical terms.

This systematic approach allows for a comprehensive understanding of the code's functionality and its relationship to web technologies. It combines code analysis with knowledge of CSS and animation concepts.
这个文件 `css_image_slice_interpolation_type.cc` 是 Chromium Blink 引擎中的一部分，专门负责处理 CSS `border-image-slice` 属性的动画插值。简单来说，它的功能是 **在 CSS 动画或过渡中，平滑地从一个 `border-image-slice` 值过渡到另一个值。**

让我们详细列举一下它的功能，并解释它与 JavaScript、HTML 和 CSS 的关系：

**核心功能:**

1. **类型检查和存储 (`SliceTypes`, `CSSImageSliceNonInterpolableValue`):**
   - 它定义了一个 `SliceTypes` 结构体，用于存储 `border-image-slice` 值的类型信息，例如每个边的 slice 是像素值还是百分比值，以及是否使用了 `fill` 关键字。
   - 它定义了一个 `CSSImageSliceNonInterpolableValue` 类，用于存储在插值过程中不会被直接插值的部分信息，也就是 `SliceTypes`。这意味着动画过程中，slice 值的类型（像素/百分比）和 `fill` 属性是否启用是不会改变的，只有数值会平滑过渡。

2. **值转换 (`ConvertImageSlice`, `MaybeConvertValue`):**
   - 提供了将 `ImageSlice` 对象（Blink 内部表示 slice 的类）转换为 `InterpolationValue` 的方法。`InterpolationValue` 是 Blink 动画系统中用于表示可插值值的通用结构。
   - 提供了 `MaybeConvertValue` 方法，用于将 CSS `border-image-slice` 值（`CSSBorderImageSliceValue`）转换为 `InterpolationValue`，以便进行动画处理。这个过程中会提取出数值部分和类型信息。

3. **初始值、继承值和中性值的处理 (`MaybeConvertInitial`, `MaybeConvertInherit`, `MaybeConvertNeutral`):**
   - 实现了获取属性的初始值、继承值，以及在没有明确起始或结束值时创建“中性”值的逻辑，这些都是动画系统正常工作所必需的。

4. **插值合并 (`MaybeMergeSingles`):**
   - 实现了 `MaybeMergeSingles` 方法，用于判断两个独立的 `InterpolationValue` 是否可以合并成一个可以进行两两插值的 `PairwiseInterpolationValue`。关键在于两个值的 `SliceTypes` 必须相同才能合并。

5. **复合插值 (`Composite`):**
   - 实现了 `Composite` 方法，这是实际进行插值的核心逻辑。它根据插值进度（`interpolation_fraction`）将目标值与当前值（`underlying_value`）进行混合。**重要的一点是，只有当起始值和结束值的 `SliceTypes` 相同时才会进行数值插值，否则会直接使用目标值，实现一个突变的效果。**

6. **应用插值结果 (`ApplyStandardPropertyValue`):**
   - 实现了 `ApplyStandardPropertyValue` 方法，将插值计算得到的值应用到元素的样式上。它将 `InterpolableValue` 转换回 Blink 内部的 `ImageSlice` 对象，并设置到 `ComputedStyleBuilder` 中。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接关联到 CSS 的 `border-image-slice` 属性，并且是 Blink 引擎处理 CSS 动画和过渡的关键部分。

* **CSS:**
    - 这个文件的主要目的是处理 `border-image-slice` 属性的动画。
    - 它解析和理解 `border-image-slice` 属性的语法，包括像素值、百分比值和 `fill` 关键字。
    - **例子:** 当 CSS 中定义了 `transition: border-image-slice 1s;` 或使用了 CSS Animations 来改变 `border-image-slice` 的值时，这个文件中的代码就会被调用来计算动画的每一帧的 `border-image-slice` 值。

* **HTML:**
    - HTML 元素可以通过 CSS 样式规则应用 `border-image-slice` 属性。
    - **例子:** `<div style="border-image-source: url(border.png); border-image-slice: 10 20 30 40;">...</div>`。当这个元素的 `border-image-slice` 值通过动画或过渡改变时，这个文件中的代码负责平滑过渡。

* **JavaScript:**
    - JavaScript 可以通过修改元素的 style 属性或使用 Web Animations API 来触发 `border-image-slice` 属性的动画。
    - **例子:**
        ```javascript
        const element = document.querySelector('div');
        element.style.transition = 'border-image-slice 1s';
        element.style.borderImageSlice = '50 60 70 80'; // 触发过渡
        ```
        或者使用 Web Animations API:
        ```javascript
        element.animate([
          { borderImageSlice: '10 20 30 40' },
          { borderImageSlice: '50 60 70 80' }
        ], { duration: 1000 });
        ```
    - 在这些 JavaScript 操作触发动画时，Blink 引擎会调用 `css_image_slice_interpolation_type.cc` 中的代码来计算中间帧的 `border-image-slice` 值。

**逻辑推理 (假设输入与输出):**

假设我们有以下 CSS 过渡:

```css
.element {
  border-image-source: url(image.png);
  border-image-slice: 10px 20px 30px 40px;
  transition: border-image-slice 1s;
}

.element:hover {
  border-image-slice: 50px 60px 70px 80px fill;
}
```

**假设输入:**

* **起始值 (鼠标移开时):** `border-image-slice: 10px 20px 30px 40px;`
* **结束值 (鼠标悬停时):** `border-image-slice: 50px 60px 70px 80px fill;`
* **插值进度 (例如 0.5，表示动画进行到一半):** 0.5

**逻辑推理和输出:**

1. **类型检查:**  `SliceTypes` 会比较起始值和结束值的类型。起始值的所有边都是像素，且没有 `fill`；结束值的所有边都是像素，且有 `fill`。由于 `fill` 属性不同，`SliceTypes` 会认为类型不同。
2. **复合插值 (`Composite`):** 由于类型不同，`Composite` 方法不会进行数值插值，而是会直接使用目标值。
3. **输出 (插值进度 0.5 时):** `border-image-slice: 50px 60px 70px 80px fill;`  **动画会发生突变，而不是平滑过渡数值。**

**另一个例子 (类型相同):**

```css
.element {
  border-image-source: url(image.png);
  border-image-slice: 10px 20px 30px 40px;
  transition: border-image-slice 1s;
}

.element:hover {
  border-image-slice: 50px 60px 70px 80px;
}
```

**假设输入:**

* **起始值:** `border-image-slice: 10px 20px 30px 40px;`
* **结束值:** `border-image-slice: 50px 60px 70px 80px;`
* **插值进度:** 0.5

**逻辑推理和输出:**

1. **类型检查:** `SliceTypes` 会认为类型相同 (所有边都是像素，且都没有 `fill`)。
2. **复合插值:** `Composite` 方法会进行数值插值。对于每个边，计算 `(结束值 - 起始值) * 插值进度 + 起始值`。
   - Top: `(50 - 10) * 0.5 + 10 = 30px`
   - Right: `(60 - 20) * 0.5 + 20 = 40px`
   - Bottom: `(70 - 30) * 0.5 + 30 = 50px`
   - Left: `(80 - 40) * 0.5 + 40 = 60px`
3. **输出 (插值进度 0.5 时):** `border-image-slice: 30px 40px 50px 60px;` **动画会平滑过渡数值。**

**用户或编程常见的使用错误:**

1. **尝试在不同类型之间进行平滑过渡:**  用户可能会期望在像素值和百分比值之间平滑过渡 `border-image-slice`，或者在包含 `fill` 和不包含 `fill` 的值之间平滑过渡。然而，如上面的例子所示，由于 `SliceTypes` 的检查，Blink 引擎在这种情况下不会进行数值插值，而是会直接跳到目标值，导致动画效果不符合预期。
   - **例子:**  CSS 中定义了从 `border-image-slice: 10px;` 过渡到 `border-
### 提示词
```
这是目录为blink/renderer/core/animation/css_image_slice_interpolation_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/css_image_slice_interpolation_type.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/animation/css_length_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/image_slice_property_functions.h"
#include "third_party/blink/renderer/core/animation/side_index.h"
#include "third_party/blink/renderer/core/css/css_border_image_slice_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"

namespace blink {

namespace {

struct SliceTypes {
  explicit SliceTypes(const ImageSlice& slice) {
    is_number[kSideTop] = slice.slices.Top().IsFixed();
    is_number[kSideRight] = slice.slices.Right().IsFixed();
    is_number[kSideBottom] = slice.slices.Bottom().IsFixed();
    is_number[kSideLeft] = slice.slices.Left().IsFixed();
    fill = slice.fill;
  }
  explicit SliceTypes(const cssvalue::CSSBorderImageSliceValue& slice) {
    auto* top_primitive_value =
        DynamicTo<CSSPrimitiveValue>(slice.Slices().Top());
    is_number[kSideTop] =
        top_primitive_value && top_primitive_value->IsNumber();

    auto* right_primitive_value =
        DynamicTo<CSSPrimitiveValue>(slice.Slices().Right());
    is_number[kSideRight] =
        right_primitive_value && right_primitive_value->IsNumber();

    auto* bottom_primitive_value =
        DynamicTo<CSSPrimitiveValue>(slice.Slices().Bottom());
    is_number[kSideBottom] =
        bottom_primitive_value && bottom_primitive_value->IsNumber();

    auto* left_primitive_value =
        DynamicTo<CSSPrimitiveValue>(slice.Slices().Left());
    is_number[kSideLeft] =
        left_primitive_value && left_primitive_value->IsNumber();

    fill = slice.Fill();
  }

  bool operator==(const SliceTypes& other) const {
    for (size_t i = 0; i < kSideIndexCount; i++) {
      if (is_number[i] != other.is_number[i])
        return false;
    }
    return fill == other.fill;
  }
  bool operator!=(const SliceTypes& other) const { return !(*this == other); }

  // If a side is not a number then it is a percentage.
  std::array<bool, kSideIndexCount> is_number;
  bool fill;
};

}  // namespace

class CSSImageSliceNonInterpolableValue : public NonInterpolableValue {
 public:
  static scoped_refptr<CSSImageSliceNonInterpolableValue> Create(
      const SliceTypes& types) {
    return base::AdoptRef(new CSSImageSliceNonInterpolableValue(types));
  }

  const SliceTypes& Types() const { return types_; }

  DECLARE_NON_INTERPOLABLE_VALUE_TYPE();

 private:
  CSSImageSliceNonInterpolableValue(const SliceTypes& types) : types_(types) {}

  const SliceTypes types_;
};

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(CSSImageSliceNonInterpolableValue);
template <>
struct DowncastTraits<CSSImageSliceNonInterpolableValue> {
  static bool AllowFrom(const NonInterpolableValue* value) {
    return value && AllowFrom(*value);
  }
  static bool AllowFrom(const NonInterpolableValue& value) {
    return value.GetType() == CSSImageSliceNonInterpolableValue::static_type_;
  }
};

namespace {

class UnderlyingSliceTypesChecker
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  explicit UnderlyingSliceTypesChecker(const SliceTypes& underlying_types)
      : underlying_types_(underlying_types) {}

  static SliceTypes GetUnderlyingSliceTypes(
      const InterpolationValue& underlying) {
    return To<CSSImageSliceNonInterpolableValue>(
               *underlying.non_interpolable_value)
        .Types();
  }

 private:
  bool IsValid(const StyleResolverState&,
               const InterpolationValue& underlying) const final {
    return underlying_types_ == GetUnderlyingSliceTypes(underlying);
  }

  const SliceTypes underlying_types_;
};

class InheritedSliceTypesChecker
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  InheritedSliceTypesChecker(const CSSProperty& property,
                             const SliceTypes& inherited_types)
      : property_(property), inherited_types_(inherited_types) {}

 private:
  bool IsValid(const StyleResolverState& state,
               const InterpolationValue& underlying) const final {
    return inherited_types_ ==
           SliceTypes(ImageSlicePropertyFunctions::GetImageSlice(
               property_, *state.ParentStyle()));
  }

  const CSSProperty& property_;
  const SliceTypes inherited_types_;
};

InterpolationValue ConvertImageSlice(const ImageSlice& slice, double zoom) {
  auto* list = MakeGarbageCollected<InterpolableList>(kSideIndexCount);
  std::array<const Length*, kSideIndexCount> sides{};
  sides[kSideTop] = &slice.slices.Top();
  sides[kSideRight] = &slice.slices.Right();
  sides[kSideBottom] = &slice.slices.Bottom();
  sides[kSideLeft] = &slice.slices.Left();

  for (wtf_size_t i = 0; i < kSideIndexCount; i++) {
    const Length& side = *sides[i];
    list->Set(i,
              MakeGarbageCollected<InterpolableNumber>(
                  side.IsFixed() ? side.Pixels() / zoom : side.Percent(),
                  side.IsFixed() ? CSSPrimitiveValue::UnitType::kNumber
                                 : CSSPrimitiveValue::UnitType::kPercentage));
  }

  return InterpolationValue(
      std::move(list),
      CSSImageSliceNonInterpolableValue::Create(SliceTypes(slice)));
}

}  // namespace

InterpolationValue CSSImageSliceInterpolationType::MaybeConvertNeutral(
    const InterpolationValue& underlying,
    ConversionCheckers& conversion_checkers) const {
  SliceTypes underlying_types =
      UnderlyingSliceTypesChecker::GetUnderlyingSliceTypes(underlying);
  conversion_checkers.push_back(
      MakeGarbageCollected<UnderlyingSliceTypesChecker>(underlying_types));
  LengthBox zero_box(
      underlying_types.is_number[kSideTop] ? Length::Fixed(0)
                                           : Length::Percent(0),
      underlying_types.is_number[kSideRight] ? Length::Fixed(0)
                                             : Length::Percent(0),
      underlying_types.is_number[kSideBottom] ? Length::Fixed(0)
                                              : Length::Percent(0),
      underlying_types.is_number[kSideLeft] ? Length::Fixed(0)
                                            : Length::Percent(0));
  return ConvertImageSlice(ImageSlice(zero_box, underlying_types.fill), 1);
}

InterpolationValue CSSImageSliceInterpolationType::MaybeConvertInitial(
    const StyleResolverState& state,
    ConversionCheckers& conversion_checkers) const {
  return ConvertImageSlice(
      ImageSlicePropertyFunctions::GetInitialImageSlice(
          CssProperty(), state.GetDocument().GetStyleResolver().InitialStyle()),
      1);
}

InterpolationValue CSSImageSliceInterpolationType::MaybeConvertInherit(
    const StyleResolverState& state,
    ConversionCheckers& conversion_checkers) const {
  const ImageSlice& inherited_image_slice =
      ImageSlicePropertyFunctions::GetImageSlice(CssProperty(),
                                                 *state.ParentStyle());
  conversion_checkers.push_back(
      MakeGarbageCollected<InheritedSliceTypesChecker>(
          CssProperty(), SliceTypes(inherited_image_slice)));
  return ConvertImageSlice(inherited_image_slice,
                           state.ParentStyle()->EffectiveZoom());
}

InterpolationValue CSSImageSliceInterpolationType::MaybeConvertValue(
    const CSSValue& value,
    const StyleResolverState*,
    ConversionCheckers&) const {
  if (!IsA<cssvalue::CSSBorderImageSliceValue>(value))
    return nullptr;

  const cssvalue::CSSBorderImageSliceValue& slice =
      To<cssvalue::CSSBorderImageSliceValue>(value);
  auto* list = MakeGarbageCollected<InterpolableList>(kSideIndexCount);
  std::array<const CSSValue*, kSideIndexCount> sides;
  sides[kSideTop] = slice.Slices().Top();
  sides[kSideRight] = slice.Slices().Right();
  sides[kSideBottom] = slice.Slices().Bottom();
  sides[kSideLeft] = slice.Slices().Left();

  for (wtf_size_t i = 0; i < kSideIndexCount; i++) {
    const auto& side = *To<CSSPrimitiveValue>(sides[i]);
    DCHECK(side.IsNumber() || side.IsPercentage());
    if (auto* numeric_value = DynamicTo<CSSNumericLiteralValue>(side)) {
      CSSPrimitiveValue::UnitType unit_type =
          numeric_value->IsNumber() ? CSSPrimitiveValue::UnitType::kNumber
                                    : CSSPrimitiveValue::UnitType::kPercentage;
      list->Set(
          i, MakeGarbageCollected<InterpolableNumber>(
                 numeric_value->IsNumber() ? numeric_value->ComputeNumber()
                                           : numeric_value->ComputePercentage(),
                 unit_type));
      continue;
    }
    CHECK(side.IsMathFunctionValue());
    list->Set(i, MakeGarbageCollected<InterpolableNumber>(
                     *To<CSSMathFunctionValue>(side).ExpressionNode()));
  }

  return InterpolationValue(
      list, CSSImageSliceNonInterpolableValue::Create(SliceTypes(slice)));
}

InterpolationValue
CSSImageSliceInterpolationType::MaybeConvertStandardPropertyUnderlyingValue(
    const ComputedStyle& style) const {
  return ConvertImageSlice(
      ImageSlicePropertyFunctions::GetImageSlice(CssProperty(), style),
      style.EffectiveZoom());
}

PairwiseInterpolationValue CSSImageSliceInterpolationType::MaybeMergeSingles(
    InterpolationValue&& start,
    InterpolationValue&& end) const {
  const auto& start_slice_types =
      To<CSSImageSliceNonInterpolableValue>(*start.non_interpolable_value)
          .Types();
  const auto& end_slice_types =
      To<CSSImageSliceNonInterpolableValue>(*end.non_interpolable_value)
          .Types();

  if (start_slice_types != end_slice_types)
    return nullptr;

  return PairwiseInterpolationValue(std::move(start.interpolable_value),
                                    std::move(end.interpolable_value),
                                    std::move(start.non_interpolable_value));
}

void CSSImageSliceInterpolationType::Composite(
    UnderlyingValueOwner& underlying_value_owner,
    double underlying_fraction,
    const InterpolationValue& value,
    double interpolation_fraction) const {
  const auto& underlying_types =
      To<CSSImageSliceNonInterpolableValue>(
          *underlying_value_owner.Value().non_interpolable_value)
          .Types();
  const auto& types =
      To<CSSImageSliceNonInterpolableValue>(*value.non_interpolable_value)
          .Types();

  if (underlying_types == types)
    underlying_value_owner.MutableValue().interpolable_value->ScaleAndAdd(
        underlying_fraction, *value.interpolable_value);
  else
    underlying_value_owner.Set(*this, value);
}

void CSSImageSliceInterpolationType::ApplyStandardPropertyValue(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue* non_interpolable_value,
    StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  const auto& list = To<InterpolableList>(interpolable_value);
  const auto& types =
      To<CSSImageSliceNonInterpolableValue>(non_interpolable_value)->Types();
  const auto& convert_side = [&types, &list, &builder,
                              &state](wtf_size_t index) {
    float value = ClampTo<float>(To<InterpolableNumber>(list.Get(index))
                                     ->Value(state.CssToLengthConversionData()),
                                 0);
    return types.is_number[index]
               ? Length::Fixed(value * builder.EffectiveZoom())
               : Length::Percent(value);
  };
  LengthBox box(convert_side(kSideTop), convert_side(kSideRight),
                convert_side(kSideBottom), convert_side(kSideLeft));
  ImageSlicePropertyFunctions::SetImageSlice(CssProperty(), builder,
                                             ImageSlice(box, types.fill));
}

}  // namespace blink
```