Response:
Let's break down the thought process for analyzing this C++ file.

**1. Understanding the Goal:**

The core request is to analyze the `CSSUnitValue.cc` file, focusing on its functionality, relationships with web technologies (JavaScript, HTML, CSS), example scenarios, potential user errors, and debugging hints.

**2. Initial Reading and Keyword Identification:**

First, I'd quickly skim the code, looking for recognizable keywords and structures. Things that jump out are:

* `#include`:  Indicates dependencies on other files (`.h` headers). This hints at how this class interacts with the larger Blink engine.
* `namespace blink`: Shows this code belongs to the Blink rendering engine.
* `class CSSUnitValue`:  The central class being analyzed.
* `Create(...)`:  Static factory methods, crucial for how `CSSUnitValue` objects are instantiated.
* `unit()`, `GetType()`, `ConvertTo(...)`, `SumValue()`, `Equals(...)`, `ToCSSValue(...)`, `ToCalcExpressionNode()`, `Negate()`, `Invert()`, `BuildCSSText(...)`: These are methods defining the behavior of `CSSUnitValue`.
* `CSSPrimitiveValue::UnitType`: An enum representing different CSS units (px, em, %, etc.).
* `ExceptionState`: Used for error handling.
* `DCHECK`: A debug assertion, indicating a condition that should always be true.
*  Mentions of `CSSPropertyID` and specific CSS properties (e.g., `kOrder`, `kZIndex`, `kFontSize`).
*  References to `CSSNumericLiteralValue`, `CSSMathExpressionNode`, `CSSMathFunctionValue`, and other related CSSOM classes.

**3. Deconstructing Functionality (Method by Method):**

Next, I'd go through each important method and try to understand its purpose:

* **`Create(...)` (multiple overloads):** How do you make a `CSSUnitValue`?  It takes a numeric `value` and a `unit`. One version takes a string for the unit, the other an enum. The version taking a `CSSNumericLiteralValue` is interesting – it shows how it can be constructed from existing CSS values.
* **`unit()`:**  Returns the unit as a string. Note the special handling for "number" and "percent". This is about providing a user-friendly representation.
* **`GetType()`:**  Identifies the type of this CSS value (it's a unit). This is for type checking and polymorphism.
* **`ConvertTo(...)`:**  This is a key method! It handles unit conversions. The comments about "canonical units" are important – they reveal an internal optimization strategy. If conversion isn't possible, it returns `nullptr`.
* **`SumValue()`:**  Represents the value as a sum, potentially involving different units (though in this case, it's mostly for internal consistency with how more complex CSS values are represented). The "canonical unit" concept reappears.
* **`Equals(...)`:**  Checks for value and unit equality. Important for comparisons.
* **`ToCSSValue()`:** Converts the `CSSUnitValue` back to a simpler `CSSNumericLiteralValue`. This is about interoperability with the broader CSS value system.
* **`ToCSSValueWithProperty(...)`:**  This is more complex. It considers the CSS property being applied and checks if the value is within valid ranges. If it's out of range, it wraps the value in a `calc()` function. This is a crucial piece of logic for CSS validity.
* **`ToCalcExpressionNode()`:**  Represents the value as a node in a CSS `calc()` expression tree. This shows how simple units can be part of more complex calculations.
* **`Negate()`:**  Simple negation of the value.
* **`Invert()`:** Handles the inversion (1/value). Special handling for `unit_ == kNumber` and zero values. For other units, it uses `CSSMathInvert`, indicating a more general approach for inverting other unit types.
* **`BuildCSSText(...)`:**  Generates the CSS text representation (e.g., "10px", "50%").

**4. Identifying Connections to Web Technologies:**

Now, the focus shifts to the relationships with JavaScript, HTML, and CSS:

* **CSS:** The primary connection is obvious. This class *represents* CSS unit values. The methods directly relate to how CSS units are used and manipulated (conversion, calculations, etc.). The `ToCSSValueWithProperty` method highlights the connection to specific CSS properties and their constraints.
* **JavaScript:** JavaScript interacts with CSS through the CSSOM (CSS Object Model). JavaScript can get and set CSS property values, and `CSSUnitValue` is likely the underlying representation for many length, size, and other unit-based CSS properties accessed via JavaScript. The `unit()` method is directly accessible in JavaScript. Methods like `convertTo()` have corresponding JavaScript API counterparts.
* **HTML:** While not directly manipulating `CSSUnitValue`, HTML provides the structure to which CSS styles are applied. The values parsed from CSS applied to HTML elements are eventually represented by classes like `CSSUnitValue`.

**5. Developing Examples and Scenarios:**

With a good understanding of the methods, I can now construct concrete examples:

* **Basic Usage:** Setting a simple CSS property like `width: 100px;`.
* **Unit Conversion:**  Demonstrating `convertTo()`.
* **`calc()`:**  Showing how out-of-range values trigger `calc()`.
* **JavaScript Interaction:** Accessing `unit` and using `convertTo` in JavaScript.
* **Error Scenarios:** Providing an invalid unit name.

**6. Considering User/Programmer Errors:**

Think about common mistakes developers make when working with CSS units:

* **Incorrect Unit Strings:** Typos in unit names.
* **Invalid Values:**  Providing negative lengths when not allowed.
* **Mixing Incompatible Units:** Trying to add pixels and percentages directly without conversion.

**7. Constructing Debugging Scenarios:**

How might a developer end up looking at this code?

* **Debugging Layout Issues:**  Investigating why an element isn't sizing correctly.
* **Inspecting Computed Styles:**  Seeing how the browser represents computed CSS values.
* **Tracing Unit Conversions:**  Understanding why a conversion isn't happening as expected.
* **Investigating `calc()` Issues:**  Seeing how `calc()` expressions are built.

**8. Structuring the Output:**

Finally, organize the information logically, using headings and bullet points for clarity. Start with a general overview of the file's purpose, then delve into specific functionalities, relationships, examples, errors, and debugging hints.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just creates and manipulates CSS units."
* **Correction:**  "It does more than just basic manipulation. The `ToCSSValueWithProperty` method shows it's aware of CSS property constraints and integrates with the `calc()` mechanism."
* **Initial thought:** "The JavaScript connection is just about getting/setting styles."
* **Correction:** "The CSSOM provides a more structured way to interact with these objects, including methods that mirror some of the C++ functionality."

By following this detailed, step-by-step process,  I can effectively analyze the given C++ source code and provide a comprehensive explanation.
好的，让我们来分析一下 `blink/renderer/core/css/cssom/css_unit_value.cc` 这个文件。

**功能概述**

`CSSUnitValue.cc` 文件定义了 `CSSUnitValue` 类，这个类在 Chromium 的 Blink 渲染引擎中，专门用来表示带有单位的 CSS 数值，例如 `10px`，`50%`，`2em` 等。它的主要功能包括：

1. **存储和表示带单位的数值:**  `CSSUnitValue` 对象会存储数值部分 (例如 `10`，`50`) 和单位类型 (例如 `px`, `%`, `em`)。
2. **单位转换:**  提供了将一个单位的值转换为另一个单位的值的能力（如果可能）。例如，将 `em` 转换为 `px`。
3. **与 CSS 值的交互:**  能够与其他 CSS 值对象（如 `CSSNumericLiteralValue`，`CSSMathFunctionValue`）进行转换和交互。
4. **参与 CSS 计算:**  可以作为 CSS `calc()` 函数的组成部分。
5. **提供 CSS 文本表示:**  能够生成该值的 CSS 文本形式，例如将 `CSSUnitValue` 对象转换为字符串 `"10px"`。
6. **处理数值范围限制:**  根据不同的 CSS 属性，检查数值是否超出允许的范围，如果超出，则可能将其包装在 `calc()` 函数中。
7. **基本的数学运算:**  支持取负、取倒数等基本数学运算。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`CSSUnitValue` 在 Blink 引擎中扮演着桥梁的角色，连接着 CSS 的解析结果和 JavaScript 的可操作对象，最终影响着 HTML 的渲染。

**1. 与 CSS 的关系:**

* **解析 CSS:** 当 Blink 引擎解析 CSS 样式时，如果遇到带单位的数值，例如 `width: 100px;`，解析器会创建一个 `CSSUnitValue` 对象来表示这个值，其中数值为 `100`，单位为 `px`。
* **计算样式:** 在布局和渲染过程中，浏览器需要计算元素的最终样式。`CSSUnitValue` 参与各种计算，例如百分比长度的解析需要基于父元素的尺寸，`em` 单位的解析需要基于元素的字体大小。
* **`calc()` 函数:**  `CSSUnitValue` 可以作为 `calc()` 函数的输入。例如，对于 `width: calc(50px + 2em);`，`50px` 和 `2em` 会被表示为 `CSSUnitValue` 对象，参与 `calc()` 函数的运算。

**举例:**

假设有以下 CSS 代码：

```css
.element {
  width: 50%;
  font-size: 16px;
  padding: 1em;
}
```

当浏览器解析这段 CSS 时：

* `width: 50%;` 会创建一个 `CSSUnitValue` 对象，数值为 `50`，单位为 `%`。
* `font-size: 16px;` 会创建一个 `CSSUnitValue` 对象，数值为 `16`，单位为 `px`。
* `padding: 1em;` 会创建一个 `CSSUnitValue` 对象，数值为 `1`，单位为 `em`。

在计算 `padding` 时，浏览器会基于元素的 `font-size` (16px) 将 `1em` 转换为 `16px`。这个转换过程可能会用到 `CSSUnitValue::ConvertTo` 方法。

**2. 与 JavaScript 的关系:**

* **CSSOM (CSS Object Model):** JavaScript 可以通过 CSSOM 来操作元素的样式。例如，可以使用 `element.style.width` 来获取或设置元素的宽度。当获取样式时，如果宽度是以带单位的数值表示，JavaScript 可能会接收到一个表示 `CSSUnitValue` 的 JavaScript 对象（在 Blink 中，这通常会映射到 `CSSStyleValue` 的子类）。
* **`CSSStyleValue` 接口:**  `CSSUnitValue` 继承自 `CSSStyleValue`。在 JavaScript 中，通过 CSSOM 获取的样式值可能会是 `CSSUnitValue` 的实例。
* **`CSSNumericValue` 接口:** `CSSUnitValue` 也实现了 `CSSNumericValue` 接口，这使得 JavaScript 可以对这些数值进行更抽象的操作，例如进行单位转换或执行数学运算。

**举例:**

假设有以下 HTML 和 JavaScript 代码：

```html
<div id="myDiv" style="width: 200px;"></div>
<script>
  const div = document.getElementById('myDiv');
  console.log(div.style.width); // 输出 "200px"

  const widthValue = div.computedStyleMap().get('width');
  console.log(widthValue.unit); // 如果 widthValue 是 CSSUnitValue 的映射，可能输出 "px"
  console.log(widthValue.value); // 可能输出 200

  const newWidth = widthValue.convertTo('em'); // JavaScript 中可能存在类似的单位转换方法
  if (newWidth) {
    console.log(newWidth.value);
    console.log(newWidth.unit);
  }
</script>
```

在这个例子中，JavaScript 通过 CSSOM 获取了元素的宽度，并可能以某种方式访问到与 `CSSUnitValue` 相关的属性和方法，进行单位转换。

**3. 与 HTML 的关系:**

* **CSS 应用于 HTML:** HTML 结构通过 CSS 样式进行渲染。`CSSUnitValue` 存储的数值和单位直接影响着 HTML 元素的尺寸、位置等属性。

**举例:**

HTML 结构：

```html
<div style="width: 75vw;">Content</div>
```

浏览器在渲染这个 `div` 元素时，会使用 `CSSUnitValue` 对象 (数值 `75`，单位 `vw`) 来计算 `div` 的宽度，其中 `vw` (viewport width) 是相对于浏览器窗口宽度的单位。

**逻辑推理、假设输入与输出**

**假设输入:**

一个 `CSSUnitValue` 对象，表示 `100px`。

**方法调用与输出:**

* `unit()`: 输出字符串 `"px"`
* `value()` (假设存在这样的访问器): 输出浮点数 `100.0`
* `ConvertTo(CSSPrimitiveValue::UnitType::kEm)`:  输出一个新的 `CSSUnitValue` 对象，表示 `100px` 转换为 `em` 后的值。转换结果依赖于当前元素的字体大小。 假设字体大小是 `16px`，则输出的 `CSSUnitValue` 的数值大约是 `6.25`，单位是 `em`。如果无法转换（例如尝试将时间单位转换为长度单位），则可能返回空指针或一个表示失败的特殊值。
* `ToCSSValue()`: 输出一个 `CSSNumericLiteralValue` 对象，数值为 `100.0`，单位为 `CSSPrimitiveValue::UnitType::kPixels`。
* `ToCalcExpressionNode()`: 输出一个 `CSSMathExpressionNumericLiteral` 对象，包含一个表示 `100px` 的 `CSSNumericLiteralValue`。

**用户或编程常见的使用错误及举例说明**

1. **尝试创建无效单位的 `CSSUnitValue`:**

   ```c++
   ExceptionState exception_state;
   CSSUnitValue::Create(10, "invalid-unit", exception_state);
   // 假设 UnitFromName("invalid-unit") 返回 kUnknown 或类似的值
   // exception_state 会包含一个类型错误，指示单位无效
   ```

   **用户操作如何到达这里：**  开发者在 JavaScript 中使用了 `CSSUnitValue.parse()` 或类似的 API 来解析一个包含错误单位的 CSS 值字符串，或者在 C++ 代码中手动创建了带有错误单位的 `CSSUnitValue`。

2. **尝试进行不兼容的单位转换:**

   ```c++
   CSSUnitValue* length_value = CSSUnitValue::Create(100, CSSPrimitiveValue::UnitType::kPixels);
   CSSUnitValue* angle_value = length_value->ConvertTo(CSSPrimitiveValue::UnitType::kDegrees);
   // angle_value 将为 nullptr，因为像素是长度单位，无法直接转换为角度单位
   ```

   **用户操作如何到达这里：** 开发者在 JavaScript 中尝试使用 `convertTo()` 方法将长度值转换为角度值，或者在 C++ 代码中进行了类似的错误转换操作。

3. **为不支持负值的属性设置负的 `CSSUnitValue`:**

   ```c++
   CSSUnitValue* negative_width = CSSUnitValue::Create(-10, CSSPrimitiveValue::UnitType::kPixels);
   // 假设 CSSPropertyID::kWidth 属性不支持负值
   const CSSPrimitiveValue* css_value = negative_width->ToCSSValueWithProperty(CSSPropertyID::kWidth);
   // css_value 可能会是一个 CSSMathFunctionValue 对象，表示 `calc(-10px)`
   ```

   **用户操作如何到达这里：** 开发者在 CSS 中为 `width` 属性设置了负值（例如 `width: -10px;`），或者在 JavaScript 中通过 CSSOM 设置了负值。浏览器在解析或应用这些样式时会遇到这种情况。

**用户操作如何一步步的到达这里，作为调试线索**

假设开发者在调试一个网页布局问题，发现一个元素的宽度没有按照预期显示。以下是可能的调试步骤，最终可能涉及到 `CSSUnitValue.cc`：

1. **检查 HTML 结构:** 开发者首先会查看 HTML 代码，确认元素的结构是否正确。
2. **检查 CSS 样式:** 开发者会检查应用于该元素的 CSS 样式，包括内联样式、外部样式表等，查看 `width` 属性的值。
3. **使用浏览器开发者工具:**
   * **Elements 面板:** 开发者可以使用浏览器的开发者工具的 Elements 面板，查看元素的 Computed 样式，这会显示浏览器最终计算出的 `width` 值及其单位。
   * **Styles 面板:** 开发者可以查看应用于元素的 CSS 规则，并可能发现 `width` 的值是一个复杂的 `calc()` 表达式，或者使用了不熟悉的单位。
4. **JavaScript 调试:** 如果样式是通过 JavaScript 动态修改的，开发者可能会使用 `console.log()` 或断点来检查 JavaScript 代码中与宽度相关的变量和操作。他们可能会看到通过 CSSOM 获取的宽度值对象，并尝试理解其结构和属性。
5. **Blink 渲染引擎代码调试 (高级):** 如果开发者需要深入了解浏览器如何处理 CSS 单位和计算，他们可能会尝试调试 Blink 渲染引擎的代码。
   * **设置断点:** 开发者可能会在 `CSSUnitValue::Create`，`CSSUnitValue::ConvertTo`，`CSSUnitValue::ToCSSValueWithProperty` 等关键方法设置断点。
   * **追踪代码执行:** 当浏览器解析 CSS 或计算样式时，如果遇到了与该元素宽度相关的带单位的值，代码执行可能会命中这些断点，允许开发者查看 `CSSUnitValue` 对象的创建、转换和使用过程。
   * **查看调用堆栈:**  开发者可以查看调用堆栈，了解 `CSSUnitValue` 的创建和操作是如何被上层代码调用的，例如从 CSS 解析器或样式计算模块。

通过以上步骤，特别是当开发者需要深入理解浏览器内部如何处理 CSS 单位时，他们可能会逐步进入 `CSSUnitValue.cc` 文件的代码中，分析其逻辑和行为，以便找出布局问题的根源。例如，他们可能想知道为什么一个负的 `width` 值会被包装在 `calc()` 函数中，或者为什么一个单位转换失败了。

希望以上分析能够帮助你理解 `CSSUnitValue.cc` 文件的功能及其在 Chromium Blink 引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/css/cssom/css_unit_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"

#include "third_party/blink/renderer/core/animation/length_property_functions.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_invert.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_max.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_min.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_product.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_sum.h"
#include "third_party/blink/renderer/core/css/cssom/css_numeric_sum_value.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

CSSPrimitiveValue::UnitType ToCanonicalUnit(CSSPrimitiveValue::UnitType unit) {
  return CSSPrimitiveValue::CanonicalUnitTypeForCategory(
      CSSPrimitiveValue::UnitTypeToUnitCategory(unit));
}

CSSPrimitiveValue::UnitType ToCanonicalUnitIfPossible(
    CSSPrimitiveValue::UnitType unit) {
  const auto canonical_unit = ToCanonicalUnit(unit);
  if (canonical_unit == CSSPrimitiveValue::UnitType::kUnknown) {
    return unit;
  }
  return canonical_unit;
}

bool IsValueOutOfRangeForProperty(CSSPropertyID property_id,
                                  double value,
                                  CSSPrimitiveValue::UnitType unit) {
  // FIXME: Avoid this CSSProperty::Get call as it can be costly.
  // The caller often has a CSSProperty already, so we can just pass it here.
  if (LengthPropertyFunctions::GetValueRange(CSSProperty::Get(property_id)) ==
          Length::ValueRange::kNonNegative &&
      value < 0) {
    return true;
  }

  // For non-length properties and special cases.
  switch (property_id) {
    case CSSPropertyID::kOrder:
    case CSSPropertyID::kZIndex:
    case CSSPropertyID::kMathDepth:
      return round(value) != value;
    case CSSPropertyID::kTabSize:
      return value < 0 || (unit == CSSPrimitiveValue::UnitType::kNumber &&
                           round(value) != value);
    case CSSPropertyID::kOrphans:
    case CSSPropertyID::kWidows:
    case CSSPropertyID::kColumnCount:
      return round(value) != value || value < 1;
    case CSSPropertyID::kBlockSize:
    case CSSPropertyID::kColumnRuleWidth:
    case CSSPropertyID::kFlexGrow:
    case CSSPropertyID::kFlexShrink:
    case CSSPropertyID::kFontSize:
    case CSSPropertyID::kFontSizeAdjust:
    case CSSPropertyID::kFontStretch:
    case CSSPropertyID::kInlineSize:
    case CSSPropertyID::kMaxBlockSize:
    case CSSPropertyID::kMaxInlineSize:
    case CSSPropertyID::kMinBlockSize:
    case CSSPropertyID::kMinInlineSize:
    case CSSPropertyID::kR:
    case CSSPropertyID::kRx:
    case CSSPropertyID::kRy:
      return value < 0;
    case CSSPropertyID::kFontWeight:
      return value < 0 || value > 1000;
    default:
      return false;
  }
}

}  // namespace

CSSUnitValue* CSSUnitValue::Create(double value,
                                   const String& unit_name,
                                   ExceptionState& exception_state) {
  CSSPrimitiveValue::UnitType unit = UnitFromName(unit_name);
  if (!IsValidUnit(unit)) {
    exception_state.ThrowTypeError("Invalid unit: " + unit_name);
    return nullptr;
  }
  return MakeGarbageCollected<CSSUnitValue>(value, unit);
}

CSSUnitValue* CSSUnitValue::Create(double value,
                                   CSSPrimitiveValue::UnitType unit) {
  DCHECK(IsValidUnit(unit));
  return MakeGarbageCollected<CSSUnitValue>(value, unit);
}

CSSUnitValue* CSSUnitValue::FromCSSValue(const CSSNumericLiteralValue& value) {
  CSSPrimitiveValue::UnitType unit = value.GetType();
  if (unit == CSSPrimitiveValue::UnitType::kInteger) {
    unit = CSSPrimitiveValue::UnitType::kNumber;
  }

  if (!IsValidUnit(unit)) {
    return nullptr;
  }
  return MakeGarbageCollected<CSSUnitValue>(value.GetDoubleValue(), unit);
}

String CSSUnitValue::unit() const {
  if (unit_ == CSSPrimitiveValue::UnitType::kNumber) {
    return "number";
  }
  if (unit_ == CSSPrimitiveValue::UnitType::kPercentage) {
    return "percent";
  }
  return CSSPrimitiveValue::UnitTypeToString(unit_);
}

CSSStyleValue::StyleValueType CSSUnitValue::GetType() const {
  return StyleValueType::kUnitType;
}

CSSUnitValue* CSSUnitValue::ConvertTo(
    CSSPrimitiveValue::UnitType target_unit) const {
  if (unit_ == target_unit) {
    return Create(value_, unit_);
  }

  // Instead of defining the scale factors for every unit to every other unit,
  // we simply convert to the canonical unit and back since we already have
  // the scale factors for canonical units.
  const auto canonical_unit = ToCanonicalUnit(unit_);
  if (canonical_unit != ToCanonicalUnit(target_unit) ||
      canonical_unit == CSSPrimitiveValue::UnitType::kUnknown) {
    return nullptr;
  }

  const double scale_factor =
      CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(unit_) /
      CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(target_unit);

  return CSSUnitValue::Create(value_ * scale_factor, target_unit);
}

std::optional<CSSNumericSumValue> CSSUnitValue::SumValue() const {
  CSSNumericSumValue sum;
  CSSNumericSumValue::UnitMap unit_map;
  if (unit_ != CSSPrimitiveValue::UnitType::kNumber) {
    unit_map.insert(ToCanonicalUnitIfPossible(unit_), 1);
  }

  sum.terms.emplace_back(
      value_ * CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(unit_),
      std::move(unit_map));
  return sum;
}

bool CSSUnitValue::Equals(const CSSNumericValue& other) const {
  auto* other_unit_value = DynamicTo<CSSUnitValue>(other);
  if (!other_unit_value) {
    return false;
  }

  return value_ == other_unit_value->value_ && unit_ == other_unit_value->unit_;
}

const CSSNumericLiteralValue* CSSUnitValue::ToCSSValue() const {
  return CSSNumericLiteralValue::Create(value_, unit_);
}

const CSSPrimitiveValue* CSSUnitValue::ToCSSValueWithProperty(
    CSSPropertyID property_id) const {
  if (IsValueOutOfRangeForProperty(property_id, value_, unit_)) {
    // Wrap out of range values with a calc.
    CSSMathExpressionNode* node = ToCalcExpressionNode();
    node->SetIsNestedCalc();
    return CSSMathFunctionValue::Create(node);
  }

  return CSSNumericLiteralValue::Create(value_, unit_);
}

CSSMathExpressionNode* CSSUnitValue::ToCalcExpressionNode() const {
  return CSSMathExpressionNumericLiteral::Create(
      CSSNumericLiteralValue::Create(value_, unit_));
}

CSSNumericValue* CSSUnitValue::Negate() {
  return CSSUnitValue::Create(-value_, unit_);
}

CSSNumericValue* CSSUnitValue::Invert() {
  if (unit_ == CSSPrimitiveValue::UnitType::kNumber) {
    if (value_ == 0) {
      return nullptr;
    }
    return CSSUnitValue::Create(1.0 / value_, unit_);
  }
  return CSSMathInvert::Create(this);
}

void CSSUnitValue::BuildCSSText(Nested,
                                ParenLess,
                                StringBuilder& result) const {
  result.Append(ToCSSValue()->CssText());
}

}  // namespace blink
```