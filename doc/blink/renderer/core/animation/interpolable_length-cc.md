Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request is to analyze the `interpolable_length.cc` file, explain its functionality, its relation to web technologies (HTML, CSS, JS), provide logical reasoning examples, and highlight potential user/developer errors.

2. **High-Level Overview of the File:** The filename `interpolable_length.cc` and the directory `blink/renderer/core/animation` strongly suggest that this file is responsible for handling length values within CSS animations in the Blink rendering engine. The "interpolable" part indicates it deals with how these lengths change smoothly over time during an animation.

3. **Core Data Structure: `InterpolableLength`:**  The central class in this file is `InterpolableLength`. The first step is to understand its internal representation. Looking at the constructor and member variables reveals three main ways a length can be stored:
    * `length_array_`:  A `CSSLengthArray` which appears to hold explicit pixel and percentage values.
    * `expression_`: A pointer to a `CSSMathExpressionNode`, used for representing `calc()` expressions and potentially keywords.
    * `keyword_`: A `CSSValueID` to represent CSS keyword values like `auto`, `min-content`, etc.
    * `type_`: An enum indicating the current representation.

4. **Key Functionality - What Does It *Do*?:** Now, go through the functions and categorize their purpose:

    * **Creation:** `CreatePixels`, `CreatePercent`, `CreateNeutral`, `MaybeConvertCSSValue`, `MaybeConvertLength`. These functions are responsible for creating `InterpolableLength` objects from different types of CSS values and lengths. Pay attention to how different input types (pixels, percentages, keywords, `calc()`) are handled and stored.

    * **Conversion to/from CSS:** `CreateLength`, `CreateCSSValue`. These handle the conversion between the internal `InterpolableLength` representation and the more general `Length` and `CSSPrimitiveValue` types used in other parts of the rendering engine. This is crucial for applying the animated values.

    * **Animation Logic:** `CanMergeValues`, `MaybeMergeSingles`, `Interpolate`, `Scale`, `Add`, `ScaleAndAdd`, `SubtractFromOneHundredPercent`. These functions implement the core logic for how `InterpolableLength` values are combined and modified during animations. Notice the special handling for `calc()` expressions and keywords in `CanMergeValues`.

    * **Helper Functions:** `LengthTypeToCSSValueID`, `CSSValueIDToLengthType`, `IsCalcSize`, `ExtractCalcSizeBasis`, `HasPercentage`, `SetHasPercentage`, `IsNeutralValue`. These are utility functions used by the main logic.

5. **Connecting to Web Technologies (HTML, CSS, JS):** This is where you relate the internal workings to the developer-facing aspects:

    * **CSS:**  Focus on how `InterpolableLength` handles different CSS length units (pixels, percentages), keywords (`auto`, `min-content`), and `calc()` expressions. Give concrete CSS examples that would utilize this code.

    * **JavaScript:** Explain that JS interacts with CSS animations via the CSSOM and Web Animations API. When a JS animation targets a CSS property with a length value, this code is likely involved in interpolating those values.

    * **HTML:**  While not directly involved, HTML provides the structure where CSS styles are applied, and these styles can include length values that are then animated.

6. **Logical Reasoning (Input/Output Examples):** Create simple scenarios to illustrate how the code transforms inputs to outputs. Choose easy-to-understand examples, like interpolating between `10px` and `20px`, or between `50%` and `75%`. For `calc()`, demonstrate a basic interpolation.

7. **Common User/Developer Errors:**  Think about how developers might misuse CSS animations or write CSS that could lead to unexpected behavior handled by this code. Focus on:

    * **Incompatible Units:** Animating between values with incompatible units without using `calc()`.
    * **Incorrect `calc()` Syntax:** Errors in writing `calc()` expressions.
    * **Animating Keywords Incorrectly:**  Trying to smoothly animate between keywords without understanding the limitations.

8. **Refine and Organize:** Structure the explanation logically with clear headings and subheadings. Use concise language and avoid overly technical jargon where possible. Provide code snippets (both C++ and web technologies) to illustrate the concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the low-level details of `CSSLengthArray`.
* **Correction:**  Realize the explanation should be higher-level, focusing on the *purpose* of the code and its connection to web technologies. Details of `CSSLengthArray` are less important than understanding its role in storing length values.
* **Initial thought:** Provide very complex `calc()` examples.
* **Correction:** Simplify the `calc()` examples to the most basic interpolation to make the concept clearer.
* **Initial thought:**  Only focus on explicit CSS animations.
* **Correction:**  Remember that CSS transitions also use this code, and JS animations interact with CSS properties.

By following this structured approach and iteratively refining the explanation, you can arrive at a comprehensive and understandable analysis of the `interpolable_length.cc` file.
这个文件 `blink/renderer/core/animation/interpolable_length.cc` 的主要功能是**实现 CSS 长度值的插值 (interpolation)**，使其能够平滑地在动画或过渡中改变。它定义了 `InterpolableLength` 类，该类负责处理各种 CSS 长度单位、百分比以及 `calc()` 表达式的插值逻辑。

以下是该文件的详细功能列表：

**核心功能：**

1. **表示可插值的 CSS 长度：** 定义了 `InterpolableLength` 类，用于存储和操作可用于插值的 CSS 长度值。它可以表示以下几种类型的长度：
    * 像素值 (pixels)
    * 百分比值 (percentages)
    * 包含像素和百分比的混合值
    * CSS 关键字 (例如 `auto`, `min-content`)
    * `calc()` 表达式

2. **创建 `InterpolableLength` 对象：** 提供了静态方法来创建 `InterpolableLength` 对象：
    * `CreatePixels(double pixels)`: 从像素值创建。
    * `CreatePercent(double percent)`: 从百分比值创建。
    * `CreateNeutral()`: 创建一个中性的、未初始化的长度值。
    * `MaybeConvertCSSValue(const CSSValue& value)`: 尝试将 `CSSValue` 转换为 `InterpolableLength`，支持像素、百分比和可解析的关键字。
    * `MaybeConvertLength(const Length& length, ...)`: 尝试将 `Length` 对象转换为 `InterpolableLength`，处理各种长度类型，包括 `calc()` 表达式和关键字。

3. **长度类型转换：** 提供了在 `Length::Type` 和 `CSSValueID` 之间进行转换的方法，用于处理 CSS 关键字：
    * `LengthTypeToCSSValueID(Length::Type lt)`
    * `CSSValueIDToLengthType(CSSValueID id)`

4. **判断和提取信息：** 提供方法来判断 `InterpolableLength` 对象的类型和提取相关信息：
    * `IsCalcSize()`: 判断是否是 `calc-size()` 表达式。
    * `ExtractCalcSizeBasis(const CSSMathExpressionNode* node)`: 从 `calc-size()` 表达式中提取基础值。
    * `HasPercentage()`: 判断是否包含百分比。
    * `IsNeutralValue()`: 判断是否是中性值。

5. **插值逻辑的核心实现：** 提供了用于插值的关键方法：
    * `CanMergeValues(const InterpolableValue* start, const InterpolableValue* end)`: 判断两个 `InterpolableLength` 值是否可以合并进行插值，特别是处理 `calc()` 表达式和关键字的兼容性。
    * `MaybeMergeSingles(InterpolableValue* start, InterpolableValue* end)`: 尝试合并两个单独的 `InterpolableLength` 对象，以便进行更高效的插值。
    * `Interpolate(const InterpolableValue& to, double progress, InterpolableValue& result)`: 执行实际的插值计算，根据进度值 `progress` 在起始值和目标值之间计算中间值。对于不同的长度类型（像素、百分比、`calc()` 表达式），采用不同的插值策略。

6. **数学运算：** 提供了对 `InterpolableLength` 对象进行基本数学运算的方法：
    * `Scale(double scale)`: 将长度值缩放指定的倍数。
    * `Add(const InterpolableValue& other)`: 将另一个 `InterpolableLength` 值加到当前值上。
    * `ScaleAndAdd(double scale, const InterpolableValue& other)`: 将当前值缩放后加上另一个值。
    * `SubtractFromOneHundredPercent()`: 从 100% 中减去当前值，常用于一些布局计算。

7. **转换为其他 CSS 值类型：** 提供了将 `InterpolableLength` 转换回标准 CSS 值类型的方法：
    * `CreateLength(const CSSToLengthConversionData& conversion_data, Length::ValueRange range) const`: 创建 `Length` 对象，考虑缩放和值范围限制。
    * `CreateCSSValue(Length::ValueRange range) const`: 创建 `CSSPrimitiveValue` 或 `CSSMathFunctionValue` 对象。
    * `AsExpression() const`: 将 `InterpolableLength` 转换为 `CSSMathExpressionNode`，方便处理 `calc()` 表达式。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接参与了浏览器如何实现 CSS 动画和过渡效果，这些效果可以通过 JavaScript 或 CSS 来触发。

* **CSS 动画和过渡：** 当 CSS 属性（如 `width`, `height`, `margin`, `padding` 等）的值是长度类型，并且该属性参与动画或过渡时，`InterpolableLength` 就发挥作用。浏览器会使用这个类来计算动画过程中属性的中间值，从而实现平滑的过渡效果。

    **示例 (CSS)：**
    ```css
    .box {
      width: 100px;
      transition: width 1s ease-in-out;
    }
    .box:hover {
      width: 200px;
    }
    ```
    当鼠标悬停在 `.box` 上时，`width` 属性会从 `100px` 平滑过渡到 `200px`。`InterpolableLength` 会负责计算中间的宽度值，例如在 0.5 秒时可能是 `150px`。

* **JavaScript Web Animations API：** JavaScript 可以使用 Web Animations API 更精细地控制动画。当使用该 API 操作 CSS 长度属性时，`InterpolableLength` 同样会被用于计算动画帧之间的值。

    **示例 (JavaScript)：**
    ```javascript
    const box = document.querySelector('.box');
    box.animate([
      { width: '100px' },
      { width: '200px' }
    ], {
      duration: 1000,
      easing: 'ease-in-out'
    });
    ```
    这段 JavaScript 代码创建了一个 `width` 属性从 `100px` 到 `200px` 的动画，持续 1 秒。`InterpolableLength` 会在每一帧计算 `width` 的中间值。

* **CSS `calc()` 函数：** `InterpolableLength` 能够处理包含 `calc()` 函数的长度值，这使得动画和过渡可以应用于更复杂的长度计算。

    **示例 (CSS)：**
    ```css
    .element {
      width: calc(50% - 20px);
      transition: width 0.5s;
    }
    .element:hover {
      width: calc(75% + 10px);
    }
    ```
    `InterpolableLength` 会解析和插值 `calc()` 表达式中的数值和单位。

* **CSS 关键字：** 某些 CSS 关键字（如 `auto`, `min-content`, `max-content`）也可以参与动画，尽管其插值逻辑可能更复杂。`InterpolableLength` 提供了处理这些关键字插值的能力。

**逻辑推理示例：**

**假设输入：**

* **起始值：** `InterpolableLength::CreatePixels(100)` (表示 100px)
* **目标值：** `InterpolableLength::CreatePercent(50)` (表示 50%)
* **进度：** `0.5` (动画进行到一半)
* **上下文：** 假设在特定的布局上下文中，50% 相当于 200px。

**输出：**

由于单位不同，直接在像素和百分比之间插值是不可行的。`InterpolableLength` 的 `Interpolate` 方法会尝试找到一种合理的插值方式，通常会将百分比转换为像素，或者将像素转换为百分比，或者使用 `calc()` 表达式来表示中间值。

在这种情况下，一种可能的输出是创建一个表示中间状态的 `InterpolableLength` 对象，其内部可能表示为 `calc(50px + 25%)`，其中 25% 是从 0% 到 50% 的一半。在实际渲染时，这个 `calc()` 表达式会被解析并计算出最终的像素值（可能是 50px + 100px = 150px）。

**用户或编程常见的使用错误：**

1. **尝试在不兼容的长度单位之间进行平滑过渡，但没有使用 `calc()`：**

   **错误示例 (CSS)：**
   ```css
   .element {
     width: 100px;
     transition: width 1s;
   }
   .element:hover {
     width: 50%; /* 容器大小变化时，最终像素值会变化 */
   }
   ```
   如果容器的大小在过渡期间发生变化，那么从 `100px` 到 `50%` 的过渡可能不会如预期那样平滑，因为百分比的含义会随着容器大小而改变。为了更精确地控制，可以使用 `calc()`。

2. **在 JavaScript 中直接操作样式时，假设了简单的数值插值：**

   **错误示例 (JavaScript)：**
   ```javascript
   const element = document.querySelector('.element');
   let progress = 0;
   setInterval(() => {
     progress += 0.01;
     element.style.width = `${100 + (200 - 100) * progress}px`; // 假设线性插值
   }, 10);
   ```
   这种方式只适用于像素值。如果涉及百分比或 `calc()`，则需要更复杂的逻辑，而浏览器内部的 `InterpolableLength` 已经处理了这些复杂性。直接操作样式字符串可能会忽略浏览器的优化和处理。

3. **错误地认为所有 CSS 属性和值都可以平滑过渡：**

   并非所有的 CSS 属性都支持平滑过渡。即使对于支持过渡的属性，某些值的组合也可能无法进行平滑插值。例如，尝试在不同的 `background-image` 之间进行平滑过渡可能需要特定的技术（如 `cross-fade()`）。

4. **忽略了 `interpolate-size` 属性对关键字插值的影响：**

   对于像 `auto` 这样的关键字，其插值行为受到 `interpolate-size` 属性的影响。如果开发者没有考虑到这一点，可能会对动画效果感到困惑。

**总结：**

`blink/renderer/core/animation/interpolable_length.cc` 是 Chromium Blink 引擎中一个至关重要的文件，它负责实现 CSS 长度值的平滑插值，是实现 CSS 动画和过渡效果的基础。它处理了各种长度单位、百分比、`calc()` 表达式以及关键字的插值逻辑，并与 JavaScript 和 HTML 紧密协作，为用户提供了丰富的视觉效果。理解这个文件的功能有助于开发者更好地理解浏览器如何处理动画和过渡，并避免一些常见的使用错误。

Prompt: 
```
这是目录为blink/renderer/core/animation/interpolable_length.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/interpolable_length.h"

#include "third_party/blink/renderer/core/animation/length_property_functions.h"
#include "third_party/blink/renderer/core/animation/underlying_value.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_math_operator.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_clamping_utils.h"
#include "third_party/blink/renderer/platform/geometry/blend.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"

namespace blink {

using UnitType = CSSPrimitiveValue::UnitType;

namespace {

CSSMathExpressionNode* NumberNode(double number) {
  return CSSMathExpressionNumericLiteral::Create(
      CSSNumericLiteralValue::Create(number, UnitType::kNumber));
}

CSSMathExpressionNode* PercentageNode(double number) {
  return CSSMathExpressionNumericLiteral::Create(
      CSSNumericLiteralValue::Create(number, UnitType::kPercentage));
}

}  // namespace

// static
InterpolableLength* InterpolableLength::CreatePixels(double pixels) {
  CSSLengthArray length_array;
  length_array.values[CSSPrimitiveValue::kUnitTypePixels] = pixels;
  length_array.type_flags.set(CSSPrimitiveValue::kUnitTypePixels);
  return MakeGarbageCollected<InterpolableLength>(std::move(length_array));
}

// static
InterpolableLength* InterpolableLength::CreatePercent(double percent) {
  CSSLengthArray length_array;
  length_array.values[CSSPrimitiveValue::kUnitTypePercentage] = percent;
  length_array.type_flags.set(CSSPrimitiveValue::kUnitTypePercentage);
  return MakeGarbageCollected<InterpolableLength>(std::move(length_array));
}

// static
InterpolableLength* InterpolableLength::CreateNeutral() {
  return MakeGarbageCollected<InterpolableLength>(CSSLengthArray());
}

// static
InterpolableLength* InterpolableLength::MaybeConvertCSSValue(
    const CSSValue& value) {
  const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  if (!primitive_value)
    return nullptr;

  if (!primitive_value->IsLength() && !primitive_value->IsPercentage() &&
      primitive_value->IsResolvableBeforeLayout()) {
    return nullptr;
  }

  CSSLengthArray length_array;
  if (primitive_value->AccumulateLengthArray(length_array))
    return MakeGarbageCollected<InterpolableLength>(std::move(length_array));

  const CSSMathExpressionNode* expression_node = nullptr;

  if (const auto* numeric_literal =
          DynamicTo<CSSNumericLiteralValue>(primitive_value)) {
    expression_node = CSSMathExpressionNumericLiteral::Create(numeric_literal);
  } else {
    DCHECK(primitive_value->IsMathFunctionValue());
    expression_node =
        To<CSSMathFunctionValue>(primitive_value)->ExpressionNode();
  }

  return MakeGarbageCollected<InterpolableLength>(*expression_node);
}

CSSValueID InterpolableLength::LengthTypeToCSSValueID(Length::Type lt) {
  switch (lt) {
    case Length::Type::kAuto:
      return CSSValueID::kAuto;
    case Length::Type::kMinContent:
      return CSSValueID::kMinContent;
    case Length::Type::kMaxContent:
      return CSSValueID::kMaxContent;
    case Length::Type::kFitContent:
      return CSSValueID::kFitContent;
    case Length::Type::kStretch:
      return RuntimeEnabledFeatures::LayoutStretchEnabled()
                 ? CSSValueID::kStretch
                 : CSSValueID::kWebkitFillAvailable;
    case Length::Type::kContent:  // only valid for flex-basis.
      return CSSValueID::kContent;
    default:
      return CSSValueID::kInvalid;
  }
}

Length::Type InterpolableLength::CSSValueIDToLengthType(CSSValueID id) {
  switch (id) {
    case CSSValueID::kAuto:
      return Length::Type::kAuto;
    case CSSValueID::kMinContent:
    case CSSValueID::kWebkitMinContent:
      return Length::Type::kMinContent;
    case CSSValueID::kMaxContent:
    case CSSValueID::kWebkitMaxContent:
      return Length::Type::kMaxContent;
    case CSSValueID::kFitContent:
    case CSSValueID::kWebkitFitContent:
      return Length::Type::kFitContent;
    case CSSValueID::kStretch:
    case CSSValueID::kWebkitFillAvailable:
      return Length::Type::kStretch;
    case CSSValueID::kContent:  // only valid for flex-basis.
      return Length::Type::kContent;
    default:
      NOTREACHED();
  }
}

// static
InterpolableLength* InterpolableLength::MaybeConvertLength(
    const Length& length,
    const CSSProperty& property,
    float zoom,
    std::optional<EInterpolateSize> interpolate_size) {
  if (!length.IsSpecified()) {
    if (!RuntimeEnabledFeatures::CSSCalcSizeFunctionEnabled()) {
      return nullptr;
    }
    CSSValueID keyword = LengthTypeToCSSValueID(length.GetType());
    if (keyword == CSSValueID::kInvalid ||
        !LengthPropertyFunctions::CanAnimateKeyword(property, keyword)) {
      return nullptr;
    }
    return MakeGarbageCollected<InterpolableLength>(keyword, interpolate_size);
  }

  if (length.IsCalculated() && length.GetCalculationValue().IsExpression()) {
    auto unzoomed_calc = length.GetCalculationValue().Zoom(1.0 / zoom);
    return MakeGarbageCollected<InterpolableLength>(
        *CSSMathExpressionNode::Create(*unzoomed_calc));
  }

  PixelsAndPercent pixels_and_percent = length.GetPixelsAndPercent();
  CSSLengthArray length_array;

  length_array.values[CSSPrimitiveValue::kUnitTypePixels] =
      pixels_and_percent.pixels / zoom;
  length_array.type_flags[CSSPrimitiveValue::kUnitTypePixels] =
      pixels_and_percent.has_explicit_pixels;

  length_array.values[CSSPrimitiveValue::kUnitTypePercentage] =
      pixels_and_percent.percent;
  length_array.type_flags[CSSPrimitiveValue::kUnitTypePercentage] =
      pixels_and_percent.has_explicit_percent;
  return MakeGarbageCollected<InterpolableLength>(std::move(length_array));
}

bool InterpolableLength::IsCalcSize() const {
  if (!IsExpression()) {
    return false;
  }
  const auto* operation =
      DynamicTo<CSSMathExpressionOperation>(expression_.Get());
  return operation && operation->IsCalcSize();
}

namespace {

const CSSMathExpressionNode& ExtractCalcSizeBasis(
    const CSSMathExpressionNode* node) {
  const auto* operation = DynamicTo<CSSMathExpressionOperation>(node);
  if (!operation || !operation->IsCalcSize()) {
    return *node;
  }

  return ExtractCalcSizeBasis(operation->GetOperands()[0]);
}

}  // namespace

// static
bool InterpolableLength::CanMergeValues(const InterpolableValue* start,
                                        const InterpolableValue* end) {
  const auto& start_length = To<InterpolableLength>(*start);
  const auto& end_length = To<InterpolableLength>(*end);

  // Implement the rules in
  // https://drafts.csswg.org/css-values-5/#interp-calc-size, but
  // without actually writing the implicit conversion of the "other"
  // value to a calc-size().  This means that if one value is a
  // calc-size(), the other value converts to:
  // * for intrinsic size keywords, a calc-size(value, size)
  // * for other values, a calc-size(any, value)

  // Only animate to or from width keywords if the other endpoint of the
  // animation is a calc-size() expression.  And only animate between
  // calc-size() expressions or between a keyword and a calc-size() expression
  // if they have compatible basis.

  const bool start_is_keyword = start_length.IsKeyword();
  const bool end_is_keyword = end_length.IsKeyword();
  if (start_is_keyword || end_is_keyword) {
    // Only animate to or from width keywords if the other endpoint of the
    // animation is a calc-size() expression.
    const InterpolableLength* keyword;
    const InterpolableLength* non_keyword;
    if (start_is_keyword) {
      if (end_is_keyword) {
        return false;
      }
      keyword = &start_length;
      non_keyword = &end_length;
    } else {
      non_keyword = &start_length;
      keyword = &end_length;
    }

    if (!non_keyword->IsCalcSize()) {
      // Check the 'interpolate-size' value stored with the keyword.
      return keyword->IsKeywordFullyInterpolable();
    }
    const CSSMathExpressionNode& basis =
        ExtractCalcSizeBasis(non_keyword->expression_);

    if (const auto* basis_literal =
            DynamicTo<CSSMathExpressionKeywordLiteral>(basis)) {
      return basis_literal->GetValue() == keyword->keyword_ ||
             basis_literal->GetValue() == CSSValueID::kAny;
    }

    return false;
  }

  // Only animate between calc-size() expressions if they have compatible
  // basis.  This includes checking the type of the keyword, but it also
  // includes broad compatibility for 'any', and for animating between
  // different <calc-sum> values.  There are also some cases where we
  // need to check that we don't exceed the expansion limit for
  // substituting to handle nested calc-size() expressions.
  //
  // CreateArithmeticOperationAndSimplifyCalcSize knows how to determine
  // this.
  if (start_length.IsCalcSize() && end_length.IsCalcSize()) {
    return CSSMathExpressionOperation::
               CreateArithmeticOperationAndSimplifyCalcSize(
                   start_length.expression_, end_length.expression_,
                   CSSMathOperator::kAdd) != nullptr;
  }

  return true;
}

// static
PairwiseInterpolationValue InterpolableLength::MaybeMergeSingles(
    InterpolableValue* start,
    InterpolableValue* end) {
  // TODO(crbug.com/991672): We currently have a lot of "fast paths" that do not
  // go through here, and hence, do not merge the percentage info of two
  // lengths. We should stop doing that.
  auto& start_length = To<InterpolableLength>(*start);
  auto& end_length = To<InterpolableLength>(*end);

  if (!CanMergeValues(start, end)) {
    return nullptr;
  }

  if (start_length.HasPercentage() || end_length.HasPercentage()) {
    start_length.SetHasPercentage();
    end_length.SetHasPercentage();
  }
  if (start_length.IsExpression() || end_length.IsExpression()) {
    start_length.SetExpression(start_length.AsExpression());
    end_length.SetExpression(end_length.AsExpression());
  }
  return PairwiseInterpolationValue(start, end);
}

InterpolableLength::InterpolableLength(CSSLengthArray&& length_array) {
  SetLengthArray(std::move(length_array));
}

void InterpolableLength::SetLengthArray(CSSLengthArray&& length_array) {
  type_ = Type::kLengthArray;
  length_array_ = std::move(length_array);
  expression_.Clear();
}

InterpolableLength::InterpolableLength(
    const CSSMathExpressionNode& expression) {
  SetExpression(expression);
}

void InterpolableLength::SetExpression(
    const CSSMathExpressionNode& expression) {
  type_ = Type::kExpression;
  expression_ = &expression;
}

InterpolableLength::InterpolableLength(
    CSSValueID keyword,
    std::optional<EInterpolateSize> interpolate_size) {
  SetKeyword(keyword, interpolate_size);
}

void InterpolableLength::SetKeyword(
    CSSValueID keyword,
    std::optional<EInterpolateSize> interpolate_size) {
  if (interpolate_size) {
    switch (*interpolate_size) {
      case EInterpolateSize::kNumericOnly:
        type_ = Type::kRestrictedKeyword;
        break;
      case EInterpolateSize::kAllowKeywords:
        type_ = Type::kFullyInterpolableKeyword;
        break;
      default:
        NOTREACHED();
    }
  } else {
    type_ = Type::kUnknownKeyword;
  }
  keyword_ = keyword;
  expression_.Clear();
}

void InterpolableLength::SetInterpolateSize(EInterpolateSize interpolate_size) {
  if (!IsKeyword()) {
    return;
  }

  // We can't make useful assertions about this not changing an
  // already-set type because, for CSS transitions, we do exactly that,
  // for the length that comes from the before-change style (in the case
  // where it comes from an underlying value), so that it uses the
  // interpolate-size value from the after-change style.

  switch (interpolate_size) {
    case EInterpolateSize::kNumericOnly:
      type_ = Type::kRestrictedKeyword;
      break;
    case EInterpolateSize::kAllowKeywords:
      type_ = Type::kFullyInterpolableKeyword;
      break;
    default:
      NOTREACHED();
  }
}

InterpolableLength* InterpolableLength::RawClone() const {
  return MakeGarbageCollected<InterpolableLength>(*this);
}

bool InterpolableLength::HasPercentage() const {
  switch (type_) {
    case Type::kRestrictedKeyword:
    case Type::kFullyInterpolableKeyword:
    case Type::kUnknownKeyword:
      return false;
    case Type::kLengthArray:
      return length_array_.type_flags.test(
          CSSPrimitiveValue::kUnitTypePercentage);
    case Type::kExpression:
      return expression_->HasPercentage();
  }
  NOTREACHED();
}

void InterpolableLength::SetHasPercentage() {
  if (HasPercentage())
    return;

  if (IsLengthArray()) {
    length_array_.type_flags.set(CSSPrimitiveValue::kUnitTypePercentage);
    return;
  }

  if (IsKeyword()) {
    SetExpression(AsExpression());
  }

  DEFINE_STATIC_LOCAL(Persistent<CSSMathExpressionNode>, zero_percent,
                      {PercentageNode(0)});
  SetExpression(
      *CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          expression_, zero_percent, CSSMathOperator::kAdd));
}

void InterpolableLength::SubtractFromOneHundredPercent() {
  if (IsLengthArray()) {
    for (double& value : length_array_.values)
      value *= -1;
    length_array_.values[CSSPrimitiveValue::kUnitTypePercentage] += 100;
    length_array_.type_flags.set(CSSPrimitiveValue::kUnitTypePercentage);
    return;
  }

  if (IsKeyword()) {
    SetExpression(AsExpression());
  }

  DEFINE_STATIC_LOCAL(Persistent<CSSMathExpressionNode>, hundred_percent,
                      {PercentageNode(100)});
  SetExpression(
      *CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          hundred_percent, expression_, CSSMathOperator::kSubtract));
}

bool InterpolableLength::IsNeutralValue() const {
  return IsLengthArray() && length_array_.type_flags.none();
}

static double ClampToRange(double x, Length::ValueRange range) {
  return (range == Length::ValueRange::kNonNegative && x < 0) ? 0 : x;
}

static const CSSNumericLiteralValue& ClampNumericLiteralValueToRange(
    const CSSNumericLiteralValue& value,
    CSSPrimitiveValue::ValueRange range) {
  if (range == CSSPrimitiveValue::ValueRange::kAll || value.DoubleValue() >= 0)
    return value;
  return *CSSNumericLiteralValue::Create(0, value.GetType());
}

static UnitType IndexToUnitType(wtf_size_t index) {
  return CSSPrimitiveValue::LengthUnitTypeToUnitType(
      static_cast<CSSPrimitiveValue::LengthUnitType>(index));
}

Length InterpolableLength::CreateLength(
    const CSSToLengthConversionData& conversion_data,
    Length::ValueRange range) const {
  if (IsExpression()) {
    if (expression_->Category() == kCalcLength) {
      double pixels = expression_->ComputeLengthPx(conversion_data);
      return Length::Fixed(CSSPrimitiveValue::ClampToCSSLengthRange(
          ClampToRange(pixels, range)));
    }
    // Passing true for ToCalcValue is a dirty hack to ensure that we don't
    // create a degenerate value when animating 'background-position', while we
    // know it may cause some minor animation glitches for the other properties.
    return Length(expression_->ToCalcValue(conversion_data, range, true));
  }

  if (IsKeyword()) {
    return Length(CSSValueIDToLengthType(keyword_));
  }

  DCHECK(IsLengthArray());
  bool has_percentage = HasPercentage();
  double pixels = 0;
  double percentage = 0;
  for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
    double value = CSSValueClampingUtils::ClampLength(length_array_.values[i]);
    if (value == 0)
      continue;
    if (i == CSSPrimitiveValue::kUnitTypePercentage) {
      percentage = value;
    } else {
      pixels += conversion_data.ZoomedComputedPixels(value, IndexToUnitType(i));
    }
  }
  pixels = CSSValueClampingUtils::ClampLength(pixels);

  if (percentage != 0)
    has_percentage = true;
  if (pixels != 0 && has_percentage) {
    pixels = ClampTo<float>(pixels);
    if (percentage == 0) {
      // Match the clamping behavior in the StyleBuilder code path,
      // which goes through CSSPrimitiveValue::CreateFromLength and then
      // CSSPrimitiveValue::ConvertToLength.
      pixels = CSSPrimitiveValue::ClampToCSSLengthRange(pixels);
    }
    return Length(CalculationValue::Create(
        PixelsAndPercent(pixels, ClampTo<float>(percentage),
                         /*has_explicit_pixels=*/true,
                         /*has_explicit_percent=*/true),
        range));
  }
  if (has_percentage)
    return Length::Percent(ClampToRange(percentage, range));
  return Length::Fixed(
      CSSPrimitiveValue::ClampToCSSLengthRange(ClampToRange(pixels, range)));
}

const CSSPrimitiveValue* InterpolableLength::CreateCSSValue(
    Length::ValueRange range) const {
  if (!IsLengthArray()) {
    return CSSMathFunctionValue::Create(
        &AsExpression(),
        CSSPrimitiveValue::ValueRangeForLengthValueRange(range));
  }

  DCHECK(IsLengthArray());
  if (length_array_.type_flags.count() > 1u) {
    const CSSMathExpressionNode& expression = AsExpression();
    if (!expression.IsNumericLiteral()) {
      return CSSMathFunctionValue::Create(
          &expression, CSSPrimitiveValue::ValueRangeForLengthValueRange(range));
    }

    // This creates a temporary CSSMathExpressionNode. Eliminate it if this
    // results in significant performance regression.
    return &ClampNumericLiteralValueToRange(
        To<CSSMathExpressionNumericLiteral>(expression).GetValue(),
        CSSPrimitiveValue::ValueRangeForLengthValueRange(range));
  }

  for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
    if (length_array_.type_flags.test(i)) {
      double value = ClampToRange(length_array_.values[i], range);
      UnitType unit_type = IndexToUnitType(i);
      return CSSNumericLiteralValue::Create(value, unit_type);
    }
  }

  return CSSNumericLiteralValue::Create(0, UnitType::kPixels);
}

const CSSMathExpressionNode& InterpolableLength::AsExpression() const {
  if (IsExpression())
    return *expression_;

  if (IsKeyword()) {
    const auto* basis = CSSMathExpressionKeywordLiteral::Create(
        keyword_, CSSMathExpressionKeywordLiteral::Context::kCalcSize);
    const auto* calculation = CSSMathExpressionKeywordLiteral::Create(
        CSSValueID::kSize, CSSMathExpressionKeywordLiteral::Context::kCalcSize);
    return *CSSMathExpressionOperation::CreateCalcSizeOperation(basis,
                                                                calculation);
  }

  DCHECK(IsLengthArray());
  bool has_percentage = HasPercentage();

  CSSMathExpressionNode* root_node = nullptr;
  for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
    double value = length_array_.values[i];
    if (value == 0 &&
        (i != CSSPrimitiveValue::kUnitTypePercentage || !has_percentage)) {
      continue;
    }
    CSSNumericLiteralValue* current_value =
        CSSNumericLiteralValue::Create(value, IndexToUnitType(i));
    CSSMathExpressionNode* current_node =
        CSSMathExpressionNumericLiteral::Create(current_value);
    if (!root_node) {
      root_node = current_node;
    } else {
      root_node = CSSMathExpressionOperation::CreateArithmeticOperation(
          root_node, current_node, CSSMathOperator::kAdd);
    }
  }

  if (root_node)
    return *root_node;
  return *CSSMathExpressionNumericLiteral::Create(
      CSSNumericLiteralValue::Create(0, UnitType::kPixels));
}

void InterpolableLength::Scale(double scale) {
  if (IsLengthArray()) {
    for (auto& value : length_array_.values)
      value *= scale;
    return;
  }

  if (IsKeyword()) {
    SetExpression(AsExpression());
  }

  DCHECK(IsExpression());
  SetExpression(
      *CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          expression_, NumberNode(scale), CSSMathOperator::kMultiply));
}

void InterpolableLength::Add(const InterpolableValue& other) {
  const InterpolableLength& other_length = To<InterpolableLength>(other);
  if (IsLengthArray() && other_length.IsLengthArray()) {
    for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
      length_array_.values[i] =
          length_array_.values[i] + other_length.length_array_.values[i];
    }
    length_array_.type_flags |= other_length.length_array_.type_flags;
    return;
  }

  CSSMathExpressionNode* result =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          &AsExpression(), &other_length.AsExpression(), CSSMathOperator::kAdd);
  CHECK(result)
      << "should not attempt to interpolate when result would be IACVT";
  SetExpression(*result);
}

void InterpolableLength::ScaleAndAdd(double scale,
                                     const InterpolableValue& other) {
  const InterpolableLength& other_length = To<InterpolableLength>(other);
  if (IsLengthArray() && other_length.IsLengthArray()) {
    for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
      length_array_.values[i] = length_array_.values[i] * scale +
                                other_length.length_array_.values[i];
    }
    length_array_.type_flags |= other_length.length_array_.type_flags;
    return;
  }

  CSSMathExpressionNode* scaled =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          &AsExpression(), NumberNode(scale), CSSMathOperator::kMultiply);
  CSSMathExpressionNode* result =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          scaled, &other_length.AsExpression(), CSSMathOperator::kAdd);
  CHECK(result)
      << "should not attempt to interpolate when result would be IACVT";
  SetExpression(*result);
}

void InterpolableLength::AssertCanInterpolateWith(
    const InterpolableValue& other) const {
  DCHECK(other.IsLength());
  // TODO(crbug.com/991672): Ensure that all |MergeSingles| variants that merge
  // two |InterpolableLength| objects should also assign them the same shape
  // (i.e. type flags) after merging into a |PairwiseInterpolationValue|. We
  // currently fail to do that, and hit the following DCHECK:
  // DCHECK_EQ(HasPercentage(),
  //           To<InterpolableLength>(other).HasPercentage());
}

void InterpolableLength::Interpolate(const InterpolableValue& to,
                                     const double progress,
                                     InterpolableValue& result) const {
  const auto& to_length = To<InterpolableLength>(to);
  auto& result_length = To<InterpolableLength>(result);
  if (IsLengthArray() && to_length.IsLengthArray()) {
    if (!result_length.IsLengthArray())
      result_length.SetLengthArray(CSSLengthArray());
    const CSSLengthArray& to_length_array = to_length.length_array_;
    CSSLengthArray& result_length_array =
        To<InterpolableLength>(result).length_array_;
    for (wtf_size_t i = 0; i < length_array_.values.size(); ++i) {
      result_length_array.values[i] =
          Blend(length_array_.values[i], to_length_array.values[i], progress);
    }
    result_length_array.type_flags =
        length_array_.type_flags | to_length_array.type_flags;
    return;
  }

  CSSMathExpressionNode* blended_from =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          &AsExpression(), NumberNode(1 - progress),
          CSSMathOperator::kMultiply);
  CSSMathExpressionNode* blended_to =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          &to_length.AsExpression(), NumberNode(progress),
          CSSMathOperator::kMultiply);
  CSSMathExpressionNode* result_expression =
      CSSMathExpressionOperation::CreateArithmeticOperationAndSimplifyCalcSize(
          blended_from, blended_to, CSSMathOperator::kAdd);
  CHECK(result_expression)
      << "should not attempt to interpolate when result would be IACVT";
  result_length.SetExpression(*result_expression);
}

void InterpolableLength::Trace(Visitor* v) const {
  InterpolableValue::Trace(v);
  v->Trace(expression_);
}

}  // namespace blink

"""

```