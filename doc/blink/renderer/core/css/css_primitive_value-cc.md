Response:
My thinking process to answer the request about `CSSPrimitiveValue.cc` went through these stages:

1. **Understanding the Core Request:** The request asks for a summary of the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of its behavior, potential errors, debugging hints, and a final concise summary. The "part 1 of 2" suggests focusing on the content within the provided snippet.

2. **Initial Code Scan and Keyword Identification:** I started by quickly scanning the code for prominent keywords and structures:
    * Includes:  `css_primitive_value.h`, various CSS-related headers (`css_length_resolver.h`, `css_markup.h`, `css_math_expression_node.h`, etc.), `LayoutUnit.h`, `GarbageCollected.h`, and `wtf` utilities. This immediately signals that the file deals with the fundamental representation of CSS values within the Blink rendering engine.
    * Class Definition: The core is the `CSSPrimitiveValue` class.
    * Methods:  A large number of methods, many starting with `Compute`, `Is`, `ConvertTo`, `Accumulate`, `Has`. This indicates the file provides functionalities for:
        * Determining the type and nature of CSS values (e.g., `IsLength`, `IsPercentage`).
        * Converting and computing CSS values to different units (e.g., `ComputeLength`, `ComputeDegrees`).
        * Managing different CSS unit categories (length, time, angle, etc.).
        * Handling calculations within CSS (references to `CSSMathFunctionValue`).
        * Clamping values to valid CSS ranges.
    * Namespaces: The code is within the `blink` namespace, confirming it's part of the Chromium/Blink project.
    * Assertions and `NOTREACHED()`: These are used for internal consistency checks and indicate points that should ideally not be reached during normal execution, suggesting potential error conditions.

3. **Categorizing Functionality:**  Based on the keywords and methods, I started grouping the functionalities:
    * **Value Representation:**  How CSS primitive values are stored and represented internally. The `CSSPrimitiveValue` class itself is the key here. The `UnitType` enum is also crucial.
    * **Type Checking:**  Methods like `IsLength()`, `IsPercentage()`, `IsCalculated()` are used to determine the type of the value.
    * **Unit Conversion and Computation:** A significant portion of the code focuses on converting between different CSS units (pixels, ems, percentages, degrees, seconds, etc.) and computing their actual values in a given context. This involves `CSSLengthResolver` for context-dependent calculations.
    * **Mathematical Operations:** The integration with `CSSMathFunctionValue` indicates support for CSS `calc()` and other mathematical expressions.
    * **Range Clamping:** The `ClampToCSSLengthRange` function ensures values stay within valid CSS limits.
    * **Unit Categorization:**  Mapping `UnitType` to broader `UnitCategory` (length, time, angle, etc.).
    * **Layout Dependency:**  Methods like `InvolvesLayout()` and `IsResolvableBeforeLayout()` indicate whether the value's resolution depends on the layout process.

4. **Relating to Web Technologies:**  This is where I connect the internal implementation to the user-facing web technologies:
    * **CSS:** The file is fundamentally about representing and manipulating CSS values. Every CSS property that accepts numeric or dimension values likely interacts with this code.
    * **HTML:**  HTML provides the structure that CSS styles are applied to. The styles defined in CSS (and processed by this code) determine how HTML elements are rendered.
    * **JavaScript:** JavaScript can interact with CSS through the DOM (Document Object Model). Scripts can read and modify CSS properties, which will eventually involve the processing done in this file.

5. **Developing Examples and Scenarios:** I started thinking about how these functionalities manifest in practical web development scenarios:
    * **Simple Length:** Setting `width: 100px;` in CSS.
    * **Percentages:** Using `width: 50%;`.
    * **Calculations:**  Using `calc(100% - 20px);`.
    * **Unit Conversions:** The browser automatically converting `1in` to pixels.
    * **Viewport Units:** Using `vw` and `vh`.
    * **Potential Errors:**  Invalid `calc()` syntax, extremely large or small values.

6. **Considering Debugging:** I thought about how a developer might end up examining this code:
    * Investigating rendering issues related to incorrect sizing or positioning.
    * Debugging complex `calc()` expressions.
    * Stepping through the browser's rendering engine to understand how CSS values are being resolved.

7. **Structuring the Answer:** I organized the information into logical sections based on the prompt's requirements: Functionality, Relationship to Web Technologies, Examples, Logical Reasoning (though less prominent in this snippet), User Errors, Debugging, and Summary.

8. **Refining and Elaborating:** I reviewed my initial thoughts and expanded on them, providing more specific examples and explanations. For instance, when discussing the relationship with JavaScript, I mentioned `element.style.width`.

9. **Focusing on Part 1:**  I made sure to restrict my analysis to the code snippet provided. I noted that the snippet primarily deals with the representation and basic manipulation of CSS primitive values and hints at more complex calculation logic handled by other classes (like `CSSMathFunctionValue`). I avoided speculating too much about what might be in "part 2."

This iterative process of scanning, categorizing, connecting to broader concepts, generating examples, and structuring the information allowed me to produce a comprehensive answer that addressed all aspects of the request.
这是 `blink/renderer/core/css/css_primitive_value.cc` 文件的第一部分，其主要功能是**定义和实现了 `CSSPrimitiveValue` 类，这个类是 Blink 渲染引擎中表示 CSS 原始值的核心类。**  CSS 原始值是 CSS 属性值的基本组成部分，例如长度、数字、百分比、颜色等。

**以下是该文件功能的详细归纳：**

1. **表示和存储 CSS 原始值:**
   - `CSSPrimitiveValue` 类是用来表示各种不同类型的 CSS 原始值的基类。
   - 虽然这个文件中没有直接定义 `CSSPrimitiveValue` 的数据成员，但它定义了许多用于操作和查询这些值的接口。
   - 子类（未在此文件中完全展示，但从 `#include` 可以看出）如 `CSSNumericLiteralValue` (表示数字和单位) 和 `CSSMathFunctionValue` (表示 `calc()` 等数学函数) 继承自它并存储具体的数值和类型信息。

2. **提供类型判断和转换方法:**
   - 提供了大量的 `Is...()` 方法来判断一个 `CSSPrimitiveValue` 对象是否属于特定的类型（例如 `IsLength()`, `IsPercentage()`, `IsNumber()`, `IsCalculated()` 等）。
   - 提供了将 `CSSPrimitiveValue` 转换为特定类型的数值的方法，例如 `ComputeLength()`, `ComputeDegrees()`, `ComputeSeconds()` 等。这些方法会考虑单位转换和上下文。
   - 定义了单位类型枚举 `UnitType` 和单位类别枚举 `UnitCategory`，以及它们之间的转换函数 (`UnitTypeToUnitCategory`, `CanonicalUnitTypeForCategory`)。

3. **处理 CSS 单位:**
   - 包含了对各种 CSS 单位（如 `px`, `em`, `%`, `deg`, `s` 等）的支持和转换逻辑。
   - `UnitTypeToUnitCategory` 函数将具体的单位类型映射到更高级别的类别（例如，`px`, `cm`, `in` 都属于 `kULength` 类别）。
   - `ConversionToCanonicalUnitsScaleFactor` 函数提供将不同单位转换为其类别中的标准单位的比例因子。

4. **处理 CSS 数学表达式:**
   - 通过与 `CSSMathFunctionValue` 类的交互，支持 CSS `calc()` 函数和其他数学表达式。
   - `IsCalculated()` 方法用于判断值是否是计算值。
   - 许多 `Compute...()` 方法会根据值的类型（是否是计算值）调用不同的实现。

5. **处理长度值:**
   - 提供了与 `Length` 类（Blink 中表示长度的类）之间的转换 (`CreateFromLength`, `ConvertToLength`)。
   - 包含了处理不同类型的长度单位（绝对单位、相对单位、视口单位、容器查询单位等）的逻辑。
   - `InvolvesLayout()` 方法判断长度值是否依赖于布局计算（例如百分比单位）。
   - `IsResolvableBeforeLayout()` 方法判断长度值是否可以在布局前解析。

6. **值的范围限制:**
   - `ClampToCSSLengthRange` 函数用于将 CSS 长度值限制在允许的范围内，防止溢出。

7. **与其他 CSS 相关的类的交互:**
   - 依赖于 `CSSLengthResolver` 类来解决依赖上下文的长度值（例如 `em`, `rem`, 视口单位等）。
   - 使用 `CSSValuePool` (虽然此部分未直接展示) 来管理 `CSSPrimitiveValue` 对象的生命周期，提高内存效率。

**它与 JavaScript, HTML, CSS 的功能关系：**

* **CSS:** `CSSPrimitiveValue` 直接对应于 CSS 属性值中的基本单元。当浏览器解析 CSS 样式时，会将属性值解析成一系列的 `CSSPrimitiveValue` 对象或其他更复杂的 CSS 值对象。例如，对于 CSS 规则 `width: 100px; color: red;`，`100px` 和 `red` 都可能被表示为 `CSSPrimitiveValue` 或其子类的实例。
    * **例子:** CSS 样式 `font-size: 16px;` 中的 `16px` 会被解析成一个 `CSSNumericLiteralValue` 对象，它是 `CSSPrimitiveValue` 的子类，表示数值 `16` 和单位 `px`。
    * **例子:** CSS 样式 `width: calc(100% - 20px);` 中的 `calc(100% - 20px)` 会被解析成一个 `CSSMathFunctionValue` 对象，它也继承自 `CSSPrimitiveValue`。

* **HTML:** HTML 提供了结构，CSS 样式被应用到这些结构上。`CSSPrimitiveValue` 对象最终会影响 HTML 元素的渲染。例如，一个 `div` 元素的 `width` 属性值（通过 `CSSPrimitiveValue` 表示）决定了该元素在页面上的宽度。
    * **例子:**  HTML 中有一个 `<div style="margin-left: 10px;"></div>`，其中 `margin-left: 10px;`  会被解析，`10px` 会被表示为一个 `CSSPrimitiveValue`，最终影响 `div` 元素的左边距。

* **JavaScript:** JavaScript 可以通过 DOM API 与 CSS 交互。当 JavaScript 获取或设置元素的样式时，会涉及到 `CSSPrimitiveValue` 对象。例如，`element.style.width = '200px';` 或 `getComputedStyle(element).width` 的操作背后，Blink 引擎会创建或读取相应的 `CSSPrimitiveValue` 对象。
    * **例子:** JavaScript 代码 `element.style.fontSize = '1.2em';` 会导致 Blink 创建一个表示 `1.2em` 的 `CSSPrimitiveValue` 对象，并将其赋值给元素的 `fontSize` 属性。
    * **例子:** JavaScript 代码 `let width = getComputedStyle(element).width;` 获取到的 `width` 值（例如 "100px"）是浏览器计算后的结果，这个计算过程涉及到 `CSSPrimitiveValue` 及其相关的计算方法。

**逻辑推理的假设输入与输出 (此处主要是类型判断和单位转换相关):**

* **假设输入:** 一个 `CSSPrimitiveValue` 对象，表示 CSS 值 `100px`。
* **输出:**
    * `IsLength()` 方法返回 `true`。
    * `IsPercentage()` 方法返回 `false`。
    * `ComputeLength()` 方法 (在提供 `CSSLengthResolver` 的情况下) 返回一个数值，表示 `100px` 对应的像素值。
    * `UnitTypeToUnitCategory()` 方法传入 `UnitType::kPixels`，返回 `CSSPrimitiveValue::kULength`。

* **假设输入:** 一个 `CSSPrimitiveValue` 对象，表示 CSS 值 `50%`。
* **输出:**
    * `IsLength()` 方法返回 `true` (通常百分比也作为长度处理)。
    * `IsPercentage()` 方法返回 `true`。
    * `ComputePercentage()` 方法 返回 `50.0`。
    * `ConvertToLength()` 方法 (在提供 `CSSLengthResolver` 的情况下) 返回一个 `Length` 对象，其类型为百分比，值为 `50.0`。

**用户或编程常见的使用错误举例说明:**

* **类型假设错误:**  开发者可能错误地假设一个 CSS 属性值总是某种特定类型，例如总是像素值。如果 CSS 中使用了其他单位（如 `em`, `%`），直接将其当作像素值处理会导致计算错误。
    * **例子:** JavaScript 代码 `element.style.paddingLeft = '10%'; let padding = parseInt(element.style.paddingLeft);`  这里直接使用 `parseInt` 假设 `paddingLeft` 是像素值是错误的。应该使用 `getComputedStyle` 获取计算后的像素值。

* **单位转换错误:**  在进行自定义计算时，没有正确处理单位转换，导致结果不准确。
    * **例子:**  在 JavaScript 中尝试将 `em` 值直接加到 `px` 值上，而没有考虑当前的字体大小。

* **在需要具体数值时使用了无法立即解析的值:**  例如，在某些 JavaScript 动画或计算中，直接使用了包含百分比或视口单位的 CSS 值，而没有在正确的上下文中进行计算。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中加载一个网页。**
2. **浏览器开始解析 HTML 和 CSS。**
3. **当解析器遇到 CSS 样式规则时，例如 `width: 200px;`，它会创建表示这些值的 `CSSPrimitiveValue` 对象。**  这个过程中，`CSSPrimitiveValue::Create` 或其子类的构造函数会被调用。
4. **布局引擎开始计算元素的布局。** 在计算 `width` 属性时，`CSSPrimitiveValue` 对象（表示 `200px`) 的 `ComputeLength()` 方法会被调用，以获取实际的像素值。
5. **如果 CSS 中包含 `calc()` 函数，例如 `width: calc(100% - 50px);`，则会创建 `CSSMathFunctionValue` 对象。** 在布局时，会调用 `CSSMathFunctionValue` 的计算方法，这些方法可能会递归调用其他 `CSSPrimitiveValue` 的方法。
6. **如果开发者使用浏览器的开发者工具查看元素的样式，或者使用 JavaScript 获取元素的计算样式 (`getComputedStyle`)，浏览器内部会访问和处理 `CSSPrimitiveValue` 对象。**
7. **如果开发者遇到了与 CSS 值相关的渲染问题或计算错误，他们可能会尝试调试，并可能需要深入到 Blink 的渲染引擎代码中，这时就可能接触到 `CSSPrimitiveValue.cc` 这样的文件。**
8. **在调试器中设置断点，例如在 `CSSPrimitiveValue::ComputeLength` 或 `CSSPrimitiveValue::IsLength` 等方法中，可以观察到这些方法的调用，以及 `CSSPrimitiveValue` 对象的状态。**  通过堆栈跟踪，可以了解用户操作是如何触发这些代码的执行的。例如，一个 JavaScript 动画修改了元素的宽度，导致样式重新计算，最终调用到 `CSSPrimitiveValue` 的相关方法。

**归纳一下 `CSSPrimitiveValue.cc` 的功能:**

总而言之，`blink/renderer/core/css/css_primitive_value.cc` (第一部分) 的核心功能是定义了在 Blink 渲染引擎中表示和操作 CSS 原始值的基本框架。它提供了类型判断、单位转换、数学表达式处理以及与其他 CSS 相关类的交互机制，是浏览器理解和应用 CSS 样式的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/core/css/css_primitive_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2012 Apple Inc. All rights
 * reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/css_primitive_value.h"

#include <cmath>

#include "build/build_config.h"
#include "third_party/blink/renderer/core/css/css_length_resolver.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/css/css_value_clamping_utils.h"
#include "third_party/blink/renderer/core/css/css_value_pool.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// Max/min values for CSS, needs to slightly smaller/larger than the true
// max/min values to allow for rounding without overflowing.
// Subtract two (rather than one) to allow for values to be converted to float
// and back without exceeding the LayoutUnit::Max.
const int kMaxValueForCssLength =
    INT_MAX / LayoutUnit::kFixedPointDenominator - 2;
const int kMinValueForCssLength =
    INT_MIN / LayoutUnit::kFixedPointDenominator + 2;

}  // namespace

struct SameSizeAsCSSPrimitiveValue : CSSValue {};
ASSERT_SIZE(CSSPrimitiveValue, SameSizeAsCSSPrimitiveValue);

float CSSPrimitiveValue::ClampToCSSLengthRange(double value) {
  // TODO(crbug.com/1133390): ClampTo function could occur the DECHECK failure
  // for NaN value. Therefore, infinity and NaN values should not be clamped
  // here.
  return ClampTo<float>(CSSValueClampingUtils::ClampLength(value),
                        kMinValueForCssLength, kMaxValueForCssLength);
}

Length::ValueRange CSSPrimitiveValue::ConversionToLengthValueRange(
    ValueRange range) {
  switch (range) {
    case ValueRange::kNonNegative:
      return Length::ValueRange::kNonNegative;
    case ValueRange::kAll:
      return Length::ValueRange::kAll;
    default:
      NOTREACHED();
  }
}

CSSPrimitiveValue::ValueRange CSSPrimitiveValue::ValueRangeForLengthValueRange(
    Length::ValueRange range) {
  switch (range) {
    case Length::ValueRange::kNonNegative:
      return ValueRange::kNonNegative;
    case Length::ValueRange::kAll:
      return ValueRange::kAll;
  }
}

CSSPrimitiveValue::UnitCategory CSSPrimitiveValue::UnitTypeToUnitCategory(
    UnitType type) {
  switch (type) {
    case UnitType::kNumber:
    case UnitType::kInteger:
      return CSSPrimitiveValue::kUNumber;
    case UnitType::kPercentage:
      return CSSPrimitiveValue::kUPercent;
    case UnitType::kPixels:
    case UnitType::kCentimeters:
    case UnitType::kMillimeters:
    case UnitType::kQuarterMillimeters:
    case UnitType::kInches:
    case UnitType::kPoints:
    case UnitType::kPicas:
    case UnitType::kUserUnits:
      return CSSPrimitiveValue::kULength;
    case UnitType::kMilliseconds:
    case UnitType::kSeconds:
      return CSSPrimitiveValue::kUTime;
    case UnitType::kDegrees:
    case UnitType::kRadians:
    case UnitType::kGradians:
    case UnitType::kTurns:
      return CSSPrimitiveValue::kUAngle;
    case UnitType::kHertz:
    case UnitType::kKilohertz:
      return CSSPrimitiveValue::kUFrequency;
    case UnitType::kDotsPerPixel:
    case UnitType::kX:
    case UnitType::kDotsPerInch:
    case UnitType::kDotsPerCentimeter:
      return CSSPrimitiveValue::kUResolution;
    default:
      return CSSPrimitiveValue::kUOther;
  }
}

bool CSSPrimitiveValue::IsResolvableBeforeLayout() const {
  // TODO(crbug.com/979895): Move this function to |CSSMathFunctionValue|.
  if (!IsCalculated()) {
    return true;
  }
  CalculationResultCategory category =
      To<CSSMathFunctionValue>(this)->Category();
  return category != kCalcLengthFunction && category != kCalcIntrinsicSize;
}

bool CSSPrimitiveValue::IsResolution() const {
  return (IsNumericLiteralValue() &&
          To<CSSNumericLiteralValue>(this)->IsResolution()) ||
         (IsMathFunctionValue() &&
          To<CSSMathFunctionValue>(this)->IsResolution());
}

bool CSSPrimitiveValue::IsFlex() const {
  // TODO(crbug.com/993136): Either support math functions on flexible lengths;
  // or provide a justification for not supporting it, and move this function to
  // |CSSNumericLiteralValue|.
  return IsNumericLiteralValue() && To<CSSNumericLiteralValue>(this)->IsFlex();
}

bool CSSPrimitiveValue::IsAngle() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsAngle();
  }
  return To<CSSMathFunctionValue>(this)->IsAngle();
}

bool CSSPrimitiveValue::IsLength() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsLength();
  }
  return To<CSSMathFunctionValue>(this)->IsLength();
}

bool CSSPrimitiveValue::IsPx() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsPx();
  }
  return To<CSSMathFunctionValue>(this)->IsPx();
}

bool CSSPrimitiveValue::IsNumber() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsNumber();
  }
  return To<CSSMathFunctionValue>(this)->IsNumber();
}

bool CSSPrimitiveValue::IsInteger() const {
  // Integer target context can take calc() function
  // which resolves to number type.
  // So we don't have to track whether cals type is integer,
  // and we can answer to IsInteger() question asked from a context
  // in which requires integer type
  // (e.g. CSSPrimitiveValue::IsInteger() check in MediaQueryExp::Create)
  // here.
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsInteger();
  }
  return To<CSSMathFunctionValue>(this)->IsNumber();
}

bool CSSPrimitiveValue::IsPercentage() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsPercentage();
  }
  return To<CSSMathFunctionValue>(this)->IsPercentage();
}

bool CSSPrimitiveValue::IsResolvableLength() const {
  return IsLength() && !InvolvesLayout();
}

bool CSSPrimitiveValue::HasPercentage() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsPercentage();
  }
  return To<CSSMathFunctionValue>(this)->ExpressionNode()->HasPercentage();
}

bool CSSPrimitiveValue::InvolvesLayout() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsPercentage();
  }
  return To<CSSMathFunctionValue>(this)->ExpressionNode()->InvolvesLayout();
}

bool CSSPrimitiveValue::IsTime() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsTime();
  }
  return To<CSSMathFunctionValue>(this)->IsTime();
}

bool CSSPrimitiveValue::IsComputationallyIndependent() const {
  if (IsNumericLiteralValue()) {
    return To<CSSNumericLiteralValue>(this)->IsComputationallyIndependent();
  }
  return To<CSSMathFunctionValue>(this)->IsComputationallyIndependent();
}

bool CSSPrimitiveValue::HasContainerRelativeUnits() const {
  CSSPrimitiveValue::LengthTypeFlags units;
  AccumulateLengthUnitTypes(units);
  const CSSPrimitiveValue::LengthTypeFlags container_units(
      (1ull << CSSPrimitiveValue::kUnitTypeContainerWidth) |
      (1ull << CSSPrimitiveValue::kUnitTypeContainerHeight) |
      (1ull << CSSPrimitiveValue::kUnitTypeContainerInlineSize) |
      (1ull << CSSPrimitiveValue::kUnitTypeContainerBlockSize) |
      (1ull << CSSPrimitiveValue::kUnitTypeContainerMin) |
      (1ull << CSSPrimitiveValue::kUnitTypeContainerMax));
  return (units & container_units).any();
}

// static
CSSPrimitiveValue* CSSPrimitiveValue::CreateFromLength(const Length& length,
                                                       float zoom) {
  switch (length.GetType()) {
    case Length::kPercent:
      return CSSNumericLiteralValue::Create(length.Percent(),
                                            UnitType::kPercentage);
    case Length::kFixed:
      return CSSNumericLiteralValue::Create(length.Value() / zoom,
                                            UnitType::kPixels);
    case Length::kCalculated: {
      const CalculationValue& calc = length.GetCalculationValue();
      if (calc.IsExpression() || calc.Pixels()) {
        return CSSMathFunctionValue::Create(length, zoom);
      }
      double num = calc.Percent();
      if (num < 0 && calc.IsNonNegative()) {
        num = 0;
      }
      return CSSNumericLiteralValue::Create(num, UnitType::kPercentage);
    }
    case Length::kFlex:
      return CSSNumericLiteralValue::Create(length.GetFloatValue(),
                                            UnitType::kFlex);
    default:
      break;
  }
  NOTREACHED();
}

// TODO(crbug.com/1133390): When we support <frequency>, we must clamp like
// <time>.
double CSSPrimitiveValue::ComputeSeconds() const {
  double result = IsCalculated()
                      ? To<CSSMathFunctionValue>(this)->ComputeSeconds()
                      : To<CSSNumericLiteralValue>(this)->ComputeSeconds();
  return CSSValueClampingUtils::ClampTime(result);
}

double CSSPrimitiveValue::ComputeDegrees() const {
  double result = IsCalculated()
                      ? To<CSSMathFunctionValue>(this)->ComputeDegrees()
                      : To<CSSNumericLiteralValue>(this)->ComputeDegrees();
  return CSSValueClampingUtils::ClampAngle(result);
}

double CSSPrimitiveValue::ComputeDotsPerPixel() const {
  DCHECK(IsResolution());

  if (IsCalculated()) {
    return To<CSSMathFunctionValue>(this)->ComputeDotsPerPixel();
  }

  return To<CSSNumericLiteralValue>(this)->ComputeDotsPerPixel();
}

double CSSPrimitiveValue::ComputeDegrees(
    const CSSLengthResolver& length_resolver) const {
  double result =
      IsCalculated()
          ? To<CSSMathFunctionValue>(this)->ComputeDegrees(length_resolver)
          : To<CSSNumericLiteralValue>(this)->ComputeDegrees();
  return CSSValueClampingUtils::ClampAngle(result);
}

double CSSPrimitiveValue::ComputeSeconds(
    const CSSLengthResolver& length_resolver) const {
  double result =
      IsCalculated()
          ? To<CSSMathFunctionValue>(this)->ComputeSeconds(length_resolver)
          : To<CSSNumericLiteralValue>(this)->ComputeSeconds();
  return CSSValueClampingUtils::ClampTime(result);
}

double CSSPrimitiveValue::ComputeDotsPerPixel(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsResolution());
  double result =
      IsCalculated()
          ? To<CSSMathFunctionValue>(this)->ComputeDotsPerPixel(length_resolver)
          : To<CSSNumericLiteralValue>(this)->ComputeDotsPerPixel();
  return CSSValueClampingUtils::ClampDouble(result);
}

template <>
int CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return RoundForImpreciseConversion<int>(ComputeLengthDouble(length_resolver));
}

template <>
unsigned CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return RoundForImpreciseConversion<unsigned>(
      ComputeLengthDouble(length_resolver));
}

template <>
Length CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return Length::Fixed(
      ClampToCSSLengthRange(ComputeLengthDouble(length_resolver)));
}

template <>
int16_t CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return RoundForImpreciseConversion<int16_t>(
      ComputeLengthDouble(length_resolver));
}

template <>
uint16_t CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return RoundForImpreciseConversion<uint16_t>(
      ComputeLengthDouble(length_resolver));
}

template <>
uint8_t CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return RoundForImpreciseConversion<uint8_t>(
      ComputeLengthDouble(length_resolver));
}

template <>
float CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return ClampTo<float>(
      CSSValueClampingUtils::ClampLength(ComputeLengthDouble(length_resolver)));
}

template <>
double CSSPrimitiveValue::ComputeLength(
    const CSSLengthResolver& length_resolver) const {
  return CSSValueClampingUtils::ClampLength(
      ComputeLengthDouble(length_resolver));
}

int CSSPrimitiveValue::ComputeInteger(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsNumber());
  return IsCalculated()
             ? To<CSSMathFunctionValue>(this)->ComputeInteger(length_resolver)
             : To<CSSNumericLiteralValue>(this)->ComputeInteger();
}

double CSSPrimitiveValue::ComputeNumber(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsNumber());
  return IsCalculated()
             ? To<CSSMathFunctionValue>(this)->ComputeNumber(length_resolver)
             : To<CSSNumericLiteralValue>(this)->ComputeNumber();
}

double CSSPrimitiveValue::ComputePercentage(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsPercentage());
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->ComputePercentage(
                              length_resolver)
                        : To<CSSNumericLiteralValue>(this)->ComputePercentage();
}

double CSSPrimitiveValue::ComputeValueInCanonicalUnit(
    const CSSLengthResolver& length_resolver) const {
  // Don't use it for mix of length and percentage or similar,
  // as it would compute 10px + 10% to 20.
  DCHECK(IsResolvableBeforeLayout());
  return IsCalculated()
             ? To<CSSMathFunctionValue>(this)->ComputeValueInCanonicalUnit(
                   length_resolver)
             : To<CSSNumericLiteralValue>(this)->ComputeInCanonicalUnit(
                   length_resolver);
}

double CSSPrimitiveValue::ComputeLengthDouble(
    const CSSLengthResolver& length_resolver) const {
  if (IsCalculated()) {
    return To<CSSMathFunctionValue>(this)->ComputeLengthPx(length_resolver);
  }
  return To<CSSNumericLiteralValue>(this)->ComputeLengthPx(length_resolver);
}

bool CSSPrimitiveValue::AccumulateLengthArray(CSSLengthArray& length_array,
                                              double multiplier) const {
  DCHECK_EQ(length_array.values.size(), CSSLengthArray::kSize);
  if (IsCalculated()) {
    return To<CSSMathFunctionValue>(this)->AccumulateLengthArray(length_array,
                                                                 multiplier);
  }
  return To<CSSNumericLiteralValue>(this)->AccumulateLengthArray(length_array,
                                                                 multiplier);
}

void CSSPrimitiveValue::AccumulateLengthUnitTypes(
    LengthTypeFlags& types) const {
  if (IsCalculated()) {
    return To<CSSMathFunctionValue>(this)->AccumulateLengthUnitTypes(types);
  }
  To<CSSNumericLiteralValue>(this)->AccumulateLengthUnitTypes(types);
}

bool CSSPrimitiveValue::HasStaticViewportUnits(
    const LengthTypeFlags& length_type_flags) {
  return length_type_flags.test(CSSPrimitiveValue::kUnitTypeViewportWidth) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeViewportHeight) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeViewportInlineSize) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeViewportBlockSize) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeViewportMin) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeViewportMax) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeSmallViewportWidth) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeSmallViewportHeight) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeSmallViewportInlineSize) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeSmallViewportBlockSize) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeSmallViewportMin) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeSmallViewportMax) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeLargeViewportWidth) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeLargeViewportHeight) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeLargeViewportInlineSize) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeLargeViewportBlockSize) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeLargeViewportMin) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeLargeViewportMax);
}

bool CSSPrimitiveValue::HasDynamicViewportUnits(
    const LengthTypeFlags& length_type_flags) {
  return length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeDynamicViewportWidth) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeDynamicViewportHeight) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeDynamicViewportInlineSize) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeDynamicViewportBlockSize) ||
         length_type_flags.test(
             CSSPrimitiveValue::kUnitTypeDynamicViewportMin) ||
         length_type_flags.test(CSSPrimitiveValue::kUnitTypeDynamicViewportMax);
}

double CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
    UnitType unit_type) {
  double factor = 1.0;
  // FIXME: the switch can be replaced by an array of scale factors.
  switch (unit_type) {
    // These are "canonical" units in their respective categories.
    case UnitType::kPixels:
    case UnitType::kUserUnits:
    case UnitType::kDegrees:
    case UnitType::kSeconds:
    case UnitType::kHertz:
      break;
    case UnitType::kMilliseconds:
      factor = 0.001;
      break;
    case UnitType::kCentimeters:
      factor = kCssPixelsPerCentimeter;
      break;
    case UnitType::kDotsPerCentimeter:
      factor = 1 / kCssPixelsPerCentimeter;
      break;
    case UnitType::kMillimeters:
      factor = kCssPixelsPerMillimeter;
      break;
    case UnitType::kQuarterMillimeters:
      factor = kCssPixelsPerQuarterMillimeter;
      break;
    case UnitType::kInches:
      factor = kCssPixelsPerInch;
      break;
    case UnitType::kDotsPerInch:
      factor = 1 / kCssPixelsPerInch;
      break;
    case UnitType::kPoints:
      factor = kCssPixelsPerPoint;
      break;
    case UnitType::kPicas:
      factor = kCssPixelsPerPica;
      break;
    case UnitType::kRadians:
      factor = 180 / kPiDouble;
      break;
    case UnitType::kGradians:
      factor = 0.9;
      break;
    case UnitType::kTurns:
      factor = 360;
      break;
    case UnitType::kKilohertz:
      factor = 1000;
      break;
    default:
      break;
  }

  return factor;
}

Length CSSPrimitiveValue::ConvertToLength(
    const CSSLengthResolver& length_resolver) const {
  if (IsResolvableLength()) {
    return ComputeLength<Length>(length_resolver);
  }
  if (IsPercentage()) {
    if (IsNumericLiteralValue() ||
        !To<CSSMathFunctionValue>(this)->AllowsNegativePercentageReference()) {
      return Length::Percent(
          CSSValueClampingUtils::ClampLength(GetDoubleValueWithoutClamping()));
    }
  }
  DCHECK(IsCalculated());
  return To<CSSMathFunctionValue>(this)->ConvertToLength(length_resolver);
}

double CSSPrimitiveValue::GetDoubleValue() const {
  return CSSValueClampingUtils::ClampDouble(GetDoubleValueWithoutClamping());
}

double CSSPrimitiveValue::GetDoubleValueWithoutClamping() const {
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->DoubleValue()
                        : To<CSSNumericLiteralValue>(this)->DoubleValue();
}

CSSPrimitiveValue::BoolStatus CSSPrimitiveValue::IsZero() const {
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->IsZero()
                        : To<CSSNumericLiteralValue>(this)->IsZero();
}

CSSPrimitiveValue::BoolStatus CSSPrimitiveValue::IsOne() const {
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->IsOne()
                        : To<CSSNumericLiteralValue>(this)->IsOne();
}

CSSPrimitiveValue::BoolStatus CSSPrimitiveValue::IsHundred() const {
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->IsHundred()
                        : To<CSSNumericLiteralValue>(this)->IsHundred();
}

CSSPrimitiveValue::BoolStatus CSSPrimitiveValue::IsNegative() const {
  return IsCalculated() ? To<CSSMathFunctionValue>(this)->IsNegative()
                        : To<CSSNumericLiteralValue>(this)->IsNegative();
}

CSSPrimitiveValue::UnitType CSSPrimitiveValue::CanonicalUnitTypeForCategory(
    UnitCategory category) {
  // The canonical unit type is chosen according to the way
  // CSSPropertyParser::ValidUnit() chooses the default unit in each category
  // (based on unitflags).
  switch (category) {
    case kUNumber:
      return UnitType::kNumber;
    case kULength:
      return UnitType::kPixels;
    case kUPercent:
      return UnitType::kUnknown;  // Cannot convert between numbers and percent.
    case kUTime:
      return UnitType::kSeconds;
    case kUAngle:
      return UnitType::kDegrees;
    case kUFrequency:
      return UnitType::kHertz;
    case kUResolution:
      return UnitType::kDotsPerPixel;
    default:
      return UnitType::kUnknown;
  }
}

// static
CSSPrimitiveValue::UnitType CSSPrimitiveValue::CanonicalUnit(
    CSSPrimitiveValue::UnitType unit_type) {
  return CanonicalUnitTypeForCategory(UnitTypeToUnitCategory(unit_type));
}

bool CSSPrimitiveValue::UnitTypeToLengthUnitType(UnitType unit_type,
                                                 LengthUnitType& length_type) {
  switch (unit_type) {
    case CSSPrimitiveValue::UnitType::kPixels:
    case CSSPrimitiveValue::UnitType::kCentimeters:
    case CSSPrimitiveValue::UnitType::kMillimeters:
    case CSSPrimitiveValue::UnitType::kQuarterMillimeters:
    case CSSPrimitiveValue::UnitType::kInches:
    case CSSPrimitiveValue::UnitType::kPoints:
    case CSSPrimitiveValue::UnitType::kPicas:
    case CSSPrimitiveValue::UnitType::kUserUnits:
      length_type = kUnitTypePixels;
      return true;
    case CSSPrimitiveValue::UnitType::kEms:
    case CSSPrimitiveValue::UnitType::kQuirkyEms:
      length_type = kUnitTypeFontSize;
      return true;
    case CSSPrimitiveValue::UnitType::kExs:
      length_type = kUnitTypeFontXSize;
      return true;
    case CSSPrimitiveValue::UnitType::kRems:
      length_type = kUnitTypeRootFontSize;
      return true;
    case CSSPrimitiveValue::UnitType::kRexs:
      length_type = kUnitTypeRootFontXSize;
      return true;
    case CSSPrimitiveValue::UnitType::kRchs:
      length_type = kUnitTypeRootFontZeroCharacterWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kRics:
      length_type = kUnitTypeRootFontIdeographicFullWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kChs:
      length_type = kUnitTypeZeroCharacterWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kIcs:
      length_type = kUnitTypeIdeographicFullWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kCaps:
      length_type = kUnitTypeFontCapitalHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kRcaps:
      length_type = kUnitTypeRootFontCapitalHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kLhs:
      length_type = kUnitTypeLineHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kRlhs:
      length_type = kUnitTypeRootLineHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kPercentage:
      length_type = kUnitTypePercentage;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportWidth:
      length_type = kUnitTypeViewportWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportHeight:
      length_type = kUnitTypeViewportHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportInlineSize:
      length_type = kUnitTypeViewportInlineSize;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportBlockSize:
      length_type = kUnitTypeViewportBlockSize;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportMin:
      length_type = kUnitTypeViewportMin;
      return true;
    case CSSPrimitiveValue::UnitType::kViewportMax:
      length_type = kUnitTypeViewportMax;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportWidth:
      length_type = kUnitTypeSmallViewportWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportHeight:
      length_type = kUnitTypeSmallViewportHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportInlineSize:
      length_type = kUnitTypeSmallViewportInlineSize;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportBlockSize:
      length_type = kUnitTypeSmallViewportBlockSize;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportMin:
      length_type = kUnitTypeSmallViewportMin;
      return true;
    case CSSPrimitiveValue::UnitType::kSmallViewportMax:
      length_type = kUnitTypeSmallViewportMax;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportWidth:
      length_type = kUnitTypeLargeViewportWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportHeight:
      length_type = kUnitTypeLargeViewportHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportInlineSize:
      length_type = kUnitTypeLargeViewportInlineSize;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportBlockSize:
      length_type = kUnitTypeLargeViewportBlockSize;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportMin:
      length_type = kUnitTypeLargeViewportMin;
      return true;
    case CSSPrimitiveValue::UnitType::kLargeViewportMax:
      length_type = kUnitTypeLargeViewportMax;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportWidth:
      length_type = kUnitTypeDynamicViewportWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportHeight:
      length_type = kUnitTypeDynamicViewportHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportInlineSize:
      length_type = kUnitTypeDynamicViewportInlineSize;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportBlockSize:
      length_type = kUnitTypeDynamicViewportBlockSize;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportMin:
      length_type = kUnitTypeDynamicViewportMin;
      return true;
    case CSSPrimitiveValue::UnitType::kDynamicViewportMax:
      length_type = kUnitTypeDynamicViewportMax;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerWidth:
      length_type = kUnitTypeContainerWidth;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerHeight:
      length_type = kUnitTypeContainerHeight;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerInlineSize:
      length_type = kUnitTypeContainerInlineSize;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerBlockSize:
      length_type = kUnitTypeContainerBlockSize;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerMin:
      length_type = kUnitTypeContainerMin;
      return true;
    case CSSPrimitiveValue::UnitType::kContainerMax:
      length_type = kUnitTypeContainerMax;
      return true;
    default:
      return false;
  }
}

CSSPrimitiveValue::UnitType CSSPrimitiveValue::LengthUnitTypeToUnitType(
    LengthUnitType type) {
  switch (type) {
    case kUnitTypePixels:
      return CSSPrimitiveValue::UnitType::kPixels;
    case kUnitTypeFontSize:
      return CSSPrimitiveValue::UnitType::kEms;
    case kUnitTypeFontXSize:
      return CSSPrimitiveValue::UnitType::kExs;
    case kUnitTypeRootFontSize:
      return CSSPrimitiveValue::UnitType::kRems;
    case kUnitTypeRootFontXSize:
      return CSSPrimitiveValue::UnitType::kRexs;
    case kUnitTypeRootFontZeroCharacterWidth:
      return CSSPrimitiveValue::UnitType::kRchs;
    case kUnitTypeRootFontIdeographicFullWidth:
      return CSSPrimitiveValue::UnitType::kRics;
    case kUnitTypeZeroCharacterWidth:
      return CSSPrimitiveValue::UnitType::kChs;
    case kUnitTypeIdeographicFullWidth:
      return CSSPrimitiveValue::UnitType::kIcs;
    case kUnitTypeFontCapitalHeight:
      return CSSPrimitiveValue::UnitType::kCaps;
    case kUnitTypeRootFontCapitalHeight:
      return CSSPrimitiveValue::UnitType::kRcaps;
    case kUnitTypeLineHeight:
      return CSSPrimitiveValue::UnitType::kLhs;
    case kUnitTypeRootLineHeight:
      return CSSPrimitiveValue::UnitType::kRlhs;
    case kUnitTypePercentage:
      return CSSPrimitiveValue::UnitType::kPercentage;
    case kUnitTypeViewportWidth:
      return CSSPrimitiveValue::UnitType::kViewportWidth;
    case kUnitTypeViewportHeight:
      return CSSPrimitiveValue::UnitType::kViewportHeight;
    case kUnitTypeViewportInlineSize:
      return CSSPrimitiveValue::UnitType::kViewportInlineSize;
    case kUnitTypeViewportBlockSize:
      return CSSPrimitiveValue::UnitType::kViewportBlockSize;
    case kUnitTypeViewportMin:
      return CSSPrimitiveValue::UnitType::kViewportMin;
    case kUnitTypeViewportMax:
      return CSSPrimitiveValue::UnitType::kViewportMax;
    case kUnitTypeSmallViewportWidth:
      return CSSPrimitiveValue::UnitType::kSmallViewportWidth;
    case kUnitTypeSmallViewportHeight:
      return CSSPrimitiveValue::UnitType::kSmallViewportHeight;
    case kUnitTypeSmallViewportInlineSize:
      return CSSPrimitiveValue::UnitType::kSmallViewportInlineSize;
    case kUnitTypeSmallViewportBlockSize:
      return CSSPrimitiveValue::UnitType::kSmallViewportBlockSize;
    case kUnitTypeSmallViewportMin:
      return CSSPrimitiveValue::UnitType::kSmallViewportMin;
    case kUnitTypeSmallViewportMax:
      return CSSPrimitiveValue::UnitType::kSmallViewportMax;
    case kUnitTypeLargeViewportWidth:
      return CSSPrimitiveValue::UnitType::kLargeViewportWidth;
    case kUnitTypeLargeViewportHeight:
      return CSSPrimitiveValue::UnitType::kLargeViewportHeight;
    case kUnitTypeLargeViewportInlineSize:
      return CSSPrimitiveValue::UnitType::kLargeViewportInlineSize;
    case kUnitTypeLargeViewportBlockSize:
      return CSSPrimitiveValue::UnitType::kLargeViewportBlockSize;
    case kUnitTypeLargeViewportMin:
      return CSSPrimitiveValue::UnitType::kLargeViewportMin;
    case kUnitTypeLargeViewportMax:
      return CSSPrimitiveValue::UnitType::kLargeViewportMax;
    case kUnitTypeDynamicViewportWidth:
      return CSSPrimitiveValue::UnitType::kDynamicViewportWidth;
    case kUnitTypeDynamicViewportHeight:
      return CSSPrimitiveValue::UnitType::kDynamicViewportHeight;
    case kUnitTypeDynamicViewportInlineSize:
      return CSSPrimitiveValue::UnitType::kDynamicViewportInlineSize;
    case kUnitTypeDynamicViewportBlockSize:
      return CSSPrimitiveValue::UnitType::kDynamicViewportBlockSize;
    case kUnitTypeDynamicViewportMin:
      return CSSPrimitiveValue::UnitType::kDynamicViewportMin;
    case kUnitTypeDynamicViewportMax:
      return CSSPrimitiveValue::UnitType::kDynamicViewportMax;
    case kUnitTypeContainerWidth:
      return CSSPrimitiveValue::UnitType::kContainerWidth;
    case kUnitTypeContainerHeight:
      return CSSPrimitiveValue::UnitType::kContainerHeight;
    case kUnitTypeContainerInlineSize:
      return CSSPrimitiveValue::UnitType::kContainerInlineSize;
    case kUnitTypeContainerBlockSize:
      return CSSPrimitiveValue::UnitType::kContainerBlockSize;
    case kUnitTypeContainerMin:
      return CSSPrimitiveValue::UnitType::kContainerMin;
    case kUnitTypeContainerMax:
      return CSSPrimitiveValue::UnitType::kContainerMax;
    case kLengthUnitTypeCount:
      break;
  }
  NOTRE
"""


```