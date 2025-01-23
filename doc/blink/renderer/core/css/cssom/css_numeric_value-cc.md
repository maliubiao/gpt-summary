Response:
Let's break down the request and the thought process to arrive at the explanation of `css_numeric_value.cc`.

**1. Understanding the Core Request:**

The request asks for an analysis of a specific Chromium Blink source file, `css_numeric_value.cc`. The core of the request is to identify its purpose and relationships to web technologies (JavaScript, HTML, CSS). It also includes requests for specific examples, debugging hints, and common usage errors.

**2. Initial Code Examination (Skimming and Keyword Spotting):**

The first step is to quickly read through the code, paying attention to:

* **Includes:**  These reveal dependencies and related functionalities. We see headers related to CSS (like `css_math_expression_node.h`, `css_primitive_value.h`), JavaScript bindings (`v8_css_numeric_type.h`), and general utilities (`<numeric>`, `base/ranges/algorithm.h`). This immediately suggests the file is crucial for handling numerical values within CSS and how they interact with JavaScript.
* **Namespace:** The `blink` namespace confirms this is part of the Blink rendering engine.
* **Class Name:** `CSSNumericValue` is the central class. This strongly implies it's responsible for representing and manipulating numeric CSS values.
* **Key Function Names/Patterns:**  Functions like `parse`, `to`, `add`, `sub`, `mul`, `div`, `min`, `max`, `equals`, `toString` are strong indicators of the file's core responsibilities: parsing, conversion, arithmetic, comparison, and string representation of numeric CSS values.
* **Mentions of "calc":** The presence of `kCalc`, `CSSMathExpressionNode`, `CSSMathSum`, `CSSMathProduct`, etc., signifies the file's involvement in handling CSS `calc()` expressions and its related mathematical functions.
* **Error Handling:** The use of `ExceptionState` points to the integration with JavaScript's error handling mechanism.

**3. Formulating the Core Functionality:**

Based on the initial examination, the central functionality seems to be:

* **Representation:**  Providing a C++ representation (`CSSNumericValue`) for CSS numeric values.
* **Parsing:**  Converting CSS text into `CSSNumericValue` objects (`parse` function).
* **Conversion:**  Converting between different units and types (`to`, `toSum`).
* **Mathematical Operations:** Implementing arithmetic and comparison operations (`add`, `sub`, `mul`, `div`, `min`, `max`, `equals`).
* **Interaction with `calc()`:**  Handling `calc()` expressions and related functions (`min()`, `max()`, `clamp()`).
* **JavaScript Integration:**  Providing an interface for JavaScript to interact with these values (through the bindings mentioned in the includes).

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, we need to make the connections explicit:

* **CSS:** The file directly deals with CSS concepts like units (pixels, percentages, etc.), `calc()` expressions, and mathematical functions (`min`, `max`, `clamp`).
* **JavaScript:**  The "bindings" headers (`v8_...`) clearly indicate this code is exposed to JavaScript. The functions like `parse`, `to`, `add`, etc., are likely accessible through the CSS Typed Object Model (Typed OM).
* **HTML:**  While the file itself doesn't directly manipulate HTML, it plays a role in how CSS styles applied to HTML elements are interpreted and calculated. For instance, when a CSS property value involves a calculation or a specific unit, this code is involved.

**5. Developing Examples:**

Concrete examples are crucial for understanding. I thought about scenarios where these functionalities would be used:

* **Parsing:** A simple CSS value like `10px` or a `calc()` expression like `calc(100% - 20px)`.
* **Conversion:** Converting `1em` to `px`.
* **Mathematical Operations:**  JavaScript manipulating CSS numeric values, like `element.style.width = CSS.px(100).add(CSS.percent(50));`.
* **`calc()`:**  Illustrating how `calc()`, `min()`, and `max()` expressions in CSS are handled.

**6. Considering Logical Reasoning (Hypothetical Input/Output):**

This involves imagining how the functions would behave with specific inputs:

* **`parse()`:**  Valid and invalid CSS strings.
* **`to()`:**  Conversion between compatible and incompatible units.
* **Arithmetic operations:**  Operations with different units and how they are handled (or potentially result in errors).

**7. Identifying Common User/Programming Errors:**

This requires thinking about common mistakes developers might make:

* **Invalid Units:**  Using non-existent or incompatible units in `to()`.
* **Type Mismatches:** Trying to perform operations on incompatible types (though the Typed OM helps prevent this).
* **Divide by Zero:** A classic error when dealing with division.
* **Invalid `calc()` syntax:**  Writing incorrect `calc()` expressions in CSS.

**8. Tracing User Operations (Debugging Clues):**

This involves thinking about the sequence of events that would lead to this code being executed:

* **Writing CSS:**  The most direct way to involve this code.
* **Using JavaScript (Typed OM):**  Manipulating CSS styles via JavaScript.
* **Browser DevTools:** How a developer could inspect the computed styles and potentially step through the code.

**9. Structuring the Explanation:**

Finally, the information needs to be presented in a clear and organized manner, addressing all parts of the request:

* Start with a high-level summary of the file's purpose.
* Detail the functionalities with explanations and examples.
* Explicitly connect to JavaScript, HTML, and CSS.
* Provide hypothetical inputs and outputs for key functions.
* Illustrate common errors and how they might arise.
* Offer debugging hints based on user actions.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the low-level C++ details.
* **Correction:** Shifting the focus to the *functional* aspects and its relation to web technologies, as requested.
* **Initial thought:**  Providing very technical code examples.
* **Correction:**  Simplifying examples to be more illustrative and less about the internal implementation.
* **Ensuring all parts of the prompt are addressed:**  Double-checking that each specific request (functionality, examples, errors, debugging) has been covered.

By following this systematic approach, combining code analysis with an understanding of web development concepts, and thinking from the perspective of a developer using these technologies, I could construct a comprehensive and helpful explanation of the `css_numeric_value.cc` file.
好的，让我们来分析一下 `blink/renderer/core/css/cssom/css_numeric_value.cc` 这个文件。

**文件功能概述**

`css_numeric_value.cc` 文件的核心功能是定义和实现 `CSSNumericValue` 类及其相关功能。`CSSNumericValue` 类是 Blink 渲染引擎中用于表示 CSS 数字类型值的抽象基类。它旨在提供一种统一的方式来处理各种 CSS 数字值，包括：

* **基本单位值 (CSSUnitValue):**  例如 `10px`, `50%`, `2em` 等带有单位的数值。
* **数学表达式结果 (CSSMathSum, CSSMathProduct 等):**  例如 `calc(100px + 50%)`, `min(10px, 20px)` 等计算结果。

该文件负责：

1. **创建和解析 `CSSNumericValue` 对象:**  提供静态方法 `parse()` 从 CSS 字符串解析成 `CSSNumericValue` 对象，以及 `FromCSSValue()` 从 `CSSPrimitiveValue` 对象创建。
2. **类型转换:**  提供方法 `to()` 将 `CSSNumericValue` 转换为特定单位的 `CSSUnitValue`，以及 `toSum()` 将其转换为 `CSSMathSum`。
3. **数学运算:**  实现了加 (`add`)、减 (`sub`)、乘 (`mul`)、除 (`div`)、最小值 (`min`)、最大值 (`max`) 等数学运算，这些运算返回新的 `CSSNumericValue` 对象。
4. **类型查询:**  提供 `type()` 方法返回 `CSSNumericType` 对象，描述数值的维度（长度、角度、时间等）。
5. **相等性比较:**  提供 `equals()` 方法比较多个数值是否相等。
6. **字符串表示:**  提供 `toString()` 方法将 `CSSNumericValue` 转换回 CSS 字符串。
7. **辅助函数:**  包含一些辅助函数，例如单位名称到单位类型的转换 (`UnitFromName`)，以及将 JavaScript 的 `Numberish` 类型转换为 `CSSNumericValue` (`FromNumberish`, `FromPercentish`, `CSSNumberishesToNumericValues`).
8. **`calc()` 表达式处理:** 负责将 CSS `calc()`, `min()`, `max()`, `clamp()` 等数学函数解析成的表达式树 (`CSSMathExpressionNode`) 转换为 `CSSNumericValue` 体系中的对象 (如 `CSSMathSum`, `CSSMathMin`, `CSSMathMax`, `CSSMathClamp`)。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件在 Blink 引擎中扮演着连接 CSS 解析和 JavaScript 操作的关键角色。它使得 JavaScript 能够以结构化的方式处理 CSS 中的数值，并进行各种操作。

* **CSS:**
    * **解析 CSS 值:** 当浏览器解析 CSS 样式时，如果遇到数值类型的属性值（例如 `width: 100px;` 或 `margin: calc(10px + 5%);`），`CSSNumericValue::parse()` 或 `CSSNumericValue::FromCSSValue()` 会被调用来创建对应的 `CSSNumericValue` 对象。
    * **`calc()` 等数学函数:**  该文件负责将 CSS `calc()`, `min()`, `max()`, `clamp()` 函数的表达式解析并转换为 `CSSMathSum`、`CSSMathMin` 等对象，以便后续计算和使用。
        * **例子:** CSS 代码 `width: calc(100% - 20px);` 会被解析成一个 `CSSMathSum` 对象，表示百分比值减去像素值。

* **JavaScript (通过 CSS Typed Object Model):**
    * **访问和操作 CSS 数值:**  通过 CSS Typed Object Model API，JavaScript 可以获取和操作 CSS 属性的数值，这些数值会以 `CSSNumericValue` 或其子类的实例呈现。
        * **例子:**  JavaScript 代码 `element.attributeStyleMap.get('width')` 如果 `width` 属性是 `100px`，则返回一个 `CSSUnitValue` 对象。如果 `width` 是 `calc(50px + 10%)`，则返回一个 `CSSMathSum` 对象。
    * **创建和修改 CSS 数值:** JavaScript 可以使用 `CSSUnitValue.of()` 或 `CSS.px(10)` 等方法创建 `CSSNumericValue` 对象，并将其赋值给 CSS 属性。
        * **例子:** JavaScript 代码 `element.attributeStyleMap.set('width', CSS.px(100).add(CSS.percent(50)));` 会将元素的 `width` 设置为计算后的值。这里 `add()` 方法就是 `CSSNumericValue` 中定义的。
    * **单位转换:** JavaScript 可以调用 `to()` 方法进行单位转换。
        * **例子:** JavaScript 代码 `let width = element.attributeStyleMap.get('width'); let widthInEm = width.to('em');` 可以将 `width` 的值转换为 `em` 单位。

* **HTML:**
    * **样式应用:**  最终，`CSSNumericValue` 对象参与到 HTML 元素的样式计算和布局过程中。例如，元素的宽度、高度、边距等属性的值由 `CSSNumericValue` 表示和计算。

**逻辑推理、假设输入与输出**

假设我们调用 `CSSNumericValue::parse()` 函数：

* **假设输入:**  CSS 字符串 `"150px"`
* **逻辑推理:**  `parse()` 函数会识别出数字 `150` 和单位 `px`，创建一个 `CSSUnitValue` 对象。
* **输出:**  返回一个 `CSSUnitValue` 对象，其 `value()` 为 `150.0`，`unit()` 为 `CSSPrimitiveValue::UnitType::kPixels`。

* **假设输入:** CSS 字符串 `"calc(100% / 2 + 20px)"`
* **逻辑推理:** `parse()` 函数会识别这是一个 `calc()` 表达式，并调用 `CSSMathExpressionNode::ParseMathFunction()` 解析成表达式树。然后 `CalcToNumericValue()` 函数会将该表达式树转换为 `CSSMathSum` 对象，其中包含一个 `CSSMathProduct` (表示 `100% / 2`) 和一个 `CSSUnitValue` (表示 `20px`)。
* **输出:** 返回一个 `CSSMathSum` 对象，内部结构表示该计算表达式。

假设我们对一个 `CSSUnitValue` 对象调用 `to()` 方法：

* **假设输入:** 一个 `CSSUnitValue` 对象，表示 `"2em"` (假设当前字体大小为 16px)。
* **调用:** `value->to("px")`
* **逻辑推理:** `to()` 函数会根据当前的上下文（例如字体大小）将 `2em` 转换为像素值。
* **输出:** 返回一个新的 `CSSUnitValue` 对象，其 `value()` 为 `32.0`，`unit()` 为 `CSSPrimitiveValue::UnitType::kPixels`。

**用户或编程常见的使用错误**

1. **在 `to()` 方法中使用无效的单位:**
   * **例子:**  一个表示角度的 `CSSUnitValue` 对象 (如 `90deg`) 调用 `to("px")` 会导致 `ThrowTypeError("Cannot convert to px")`，因为角度不能直接转换为像素。
   * **说明:** 用户尝试进行不兼容的单位转换。

2. **在数学运算中操作不兼容的单位:**
   * **例子:** 尝试将一个长度值与一个角度值相加，例如 `CSS.px(10).add(CSS.deg(45))`。虽然该文件本身会创建 `CSSMathSum` 对象，但在后续的布局计算中可能会导致问题，或者在 JavaScript 中使用时可能会抛出异常（取决于具体的后续处理逻辑）。
   * **说明:**  虽然 `CSSNumericValue` 允许创建包含不同类型单位的数学表达式，但在实际应用中需要注意单位的兼容性。

3. **除零错误:**
   * **例子:** 在 CSS 中使用 `calc(100px / 0)` 或在 JavaScript 中调用 `numericValue.div(CSS.number(0))` 会导致错误。在 `CSSNumericValue::div()` 中，如果除数为零，会调用 `exception_state.ThrowRangeError("Can't divide-by-zero")`。
   * **说明:** 这是一个经典的数学错误，需要在编程时避免。

4. **解析无效的 CSS 数值字符串:**
   * **例子:**  使用 `CSSNumericValue::parse("invalid-value")` 会导致 `exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError, "Invalid math expression")`。
   * **说明:**  传递给 `parse()` 的字符串必须是有效的 CSS 数值表示。

**用户操作如何一步步到达这里 (调试线索)**

作为调试线索，以下是一些用户操作可能导致代码执行到 `css_numeric_value.cc` 的场景：

1. **用户在 HTML 文件中编写 CSS 样式:**
   * 用户编辑 HTML 文件，在 `<style>` 标签或通过 `style` 属性添加 CSS 样式，例如 `width: 150px;` 或 `margin: calc(10px + 5%);`。
   * 当浏览器加载和解析这些 CSS 时，Blink 的 CSS 解析器会工作，并调用 `CSSNumericValue::parse()` 来创建表示这些数值的 `CSSNumericValue` 对象。

2. **用户通过 JavaScript 操作 CSS 样式 (使用 CSS Typed OM):**
   * 用户编写 JavaScript 代码来获取或设置元素的样式。
   * **获取样式:** 当 JavaScript 代码调用 `element.attributeStyleMap.get('width')` 时，如果 `width` 属性的值是一个数值，Blink 会返回一个 `CSSNumericValue` 对象。这个对象的创建可能发生在 CSS 解析阶段，或者在计算样式时动态创建。
   * **设置样式:** 当 JavaScript 代码调用 `element.attributeStyleMap.set('width', CSS.px(100))` 或 `element.attributeStyleMap.set('margin', CSS.calc('10px + 5%'))` 时，`CSS.px()` 或 `CSS.calc()` 等方法会创建 `CSSNumericValue` 对象，然后 Blink 的样式系统会使用这些对象来更新元素的样式。

3. **浏览器渲染网页布局:**
   * 当浏览器进行布局计算时，需要知道元素的尺寸、边距等信息。这些信息通常以 `CSSNumericValue` 的形式存在。
   * 例如，计算一个设置了 `width: calc(100% - 20px)` 的元素的实际宽度时，会涉及到 `CSSMathSum` 对象的计算。

**调试示例:**

假设开发者想调试一个 `calc()` 表达式的计算问题：

1. **设置断点:** 开发者可以在 `css_numeric_value.cc` 中 `CalcToNumericValue()` 函数的入口处设置断点。
2. **用户操作:** 用户在浏览器中加载包含该 `calc()` 表达式的网页，或者通过 JavaScript 修改元素的样式触发计算。
3. **断点命中:** 当 CSS 解析器或样式计算引擎处理到该 `calc()` 表达式时，断点会被命中。
4. **单步调试:** 开发者可以单步执行代码，查看 `CSSMathExpressionNode` 的结构，以及 `CalcToNumericValue()` 如何将其转换为 `CSSMathSum` 或其他 `CSSNumericValue` 子类的对象。
5. **检查变量:** 开发者可以检查局部变量的值，例如 `root` 指向的 `CSSMathExpressionNode` 的类型和内容，以及创建的 `CSSNumericValueVector` 中的元素。

总而言之，`css_numeric_value.cc` 是 Blink 渲染引擎中处理 CSS 数字值的核心组件，它连接了 CSS 解析、JavaScript 操作和最终的页面渲染，使得对 CSS 数值的处理更加结构化和可编程。理解这个文件的功能对于理解 Blink 如何处理 CSS 中的数值至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/cssom/css_numeric_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/css/cssom/css_numeric_value.h"

#include <numeric>

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_css_numeric_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_clamp.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_invert.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_max.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_min.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_negate.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_product.h"
#include "third_party/blink/renderer/core/css/cssom/css_math_sum.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

template <CSSStyleValue::StyleValueType type>
void PrependValueForArithmetic(CSSNumericValueVector& vector,
                               CSSNumericValue* value) {
  DCHECK(value);
  if (value->GetType() == type) {
    vector.PrependVector(static_cast<CSSMathVariadic*>(value)->NumericValues());
  } else {
    vector.push_front(value);
  }
}

template <class BinaryOperation>
CSSUnitValue* MaybeSimplifyAsUnitValue(const CSSNumericValueVector& values,
                                       const BinaryOperation& op) {
  DCHECK(!values.empty());

  auto* first_unit_value = DynamicTo<CSSUnitValue>(values[0].Get());
  if (!first_unit_value) {
    return nullptr;
  }

  double final_value = first_unit_value->value();
  for (wtf_size_t i = 1; i < values.size(); i++) {
    auto* unit_value = DynamicTo<CSSUnitValue>(values[i].Get());
    if (!unit_value ||
        unit_value->GetInternalUnit() != first_unit_value->GetInternalUnit()) {
      return nullptr;
    }

    final_value = op(final_value, unit_value->value());
  }

  return CSSUnitValue::Create(final_value, first_unit_value->GetInternalUnit());
}

CSSUnitValue* MaybeMultiplyAsUnitValue(const CSSNumericValueVector& values) {
  DCHECK(!values.empty());

  // We are allowed one unit value with type other than kNumber.
  auto unit_other_than_number = CSSPrimitiveValue::UnitType::kNumber;

  double final_value = 1.0;
  for (wtf_size_t i = 0; i < values.size(); i++) {
    auto* unit_value = DynamicTo<CSSUnitValue>(values[i].Get());
    if (!unit_value) {
      return nullptr;
    }

    if (unit_value->GetInternalUnit() != CSSPrimitiveValue::UnitType::kNumber) {
      if (unit_other_than_number != CSSPrimitiveValue::UnitType::kNumber) {
        return nullptr;
      }
      unit_other_than_number = unit_value->GetInternalUnit();
    }

    final_value *= unit_value->value();
  }

  return CSSUnitValue::Create(final_value, unit_other_than_number);
}

CSSMathOperator CanonicalOperator(CSSMathOperator op) {
  switch (op) {
    case CSSMathOperator::kAdd:
    case CSSMathOperator::kSubtract:
      return CSSMathOperator::kAdd;
    case CSSMathOperator::kMultiply:
    case CSSMathOperator::kDivide:
      return CSSMathOperator::kMultiply;
    default:
      NOTREACHED();
  }
}

bool CanCombineNodes(const CSSMathExpressionNode& root,
                     const CSSMathExpressionNode& node) {
  DCHECK(root.IsOperation());
  if (!node.IsOperation()) {
    return false;
  }
  if (node.IsNestedCalc()) {
    return false;
  }
  const auto& node_exp = To<CSSMathExpressionOperation>(node);
  if (node_exp.IsMathFunction()) {
    return false;
  }
  return CanonicalOperator(
             To<CSSMathExpressionOperation>(root).OperatorType()) ==
         CanonicalOperator(node_exp.OperatorType());
}

CSSNumericValue* NegateOrInvertIfRequired(CSSMathOperator parent_op,
                                          CSSNumericValue* value) {
  DCHECK(value);
  if (parent_op == CSSMathOperator::kSubtract) {
    return CSSMathNegate::Create(value);
  }
  if (parent_op == CSSMathOperator::kDivide) {
    return CSSMathInvert::Create(value);
  }
  return value;
}

CSSNumericValue* CalcToNumericValue(const CSSMathExpressionNode& root) {
  if (root.IsNumericLiteral()) {
    const CSSPrimitiveValue::UnitType unit = root.ResolvedUnitType();
    auto* value = CSSUnitValue::Create(
        root.DoubleValue(), unit == CSSPrimitiveValue::UnitType::kInteger
                                ? CSSPrimitiveValue::UnitType::kNumber
                                : unit);
    DCHECK(value);

    // For cases like calc(1), we need to wrap the value in a CSSMathSum
    if (!root.IsNestedCalc()) {
      return value;
    }

    CSSNumericValueVector values;
    values.push_back(value);
    return CSSMathSum::Create(std::move(values));
  }

  // TODO(crbug.com/1376521): Implement Typed OM API for `anchor()`, and turn
  // the CHECK below back into a DCHECK.

  CHECK(root.IsOperation());

  CSSNumericValueVector values;

  // When the node is a variadic operation, we return either a CSSMathMin or a
  // CSSMathMax.
  if (const auto& node = To<CSSMathExpressionOperation>(root);
      node.IsMathFunction()) {
    for (const auto& operand : node.GetOperands()) {
      values.push_back(CalcToNumericValue(*operand));
    }
    if (node.OperatorType() == CSSMathOperator::kMin) {
      return CSSMathMin::Create(std::move(values));
    }
    if (node.OperatorType() == CSSMathOperator::kMax) {
      return CSSMathMax::Create(std::move(values));
    }
    DCHECK_EQ(CSSMathOperator::kClamp, node.OperatorType());
    auto& min = values[0];
    auto& val = values[1];
    auto& max = values[2];
    return CSSMathClamp::Create(std::move(min), std::move(val), std::move(max));
  }

  DCHECK_EQ(To<CSSMathExpressionOperation>(root).GetOperands().size(), 2u);
  // When the node is a binary operator, we return either a CSSMathSum or a
  // CSSMathProduct.
  // For cases like calc(1 + 2 + 3), the calc expression tree looks like:
  //       +     //
  //      / \    //
  //     +   3   //
  //    / \      //
  //   1   2     //
  //
  // But we want to produce a CSSMathValue tree that looks like:
  //       +     //
  //      /|\    //
  //     1 2 3   //
  //
  // So when the left child has the same operator as its parent, we can combine
  // the two nodes. We keep moving down the left side of the tree as long as the
  // current node and the root can be combined, collecting the right child of
  // the nodes that we encounter.
  const CSSMathExpressionNode* cur_node = &root;
  do {
    DCHECK(cur_node->IsOperation());
    const CSSMathExpressionOperation* binary_op =
        To<CSSMathExpressionOperation>(cur_node);
    CSSMathExpressionOperation::Operands operands = binary_op->GetOperands();
    DCHECK_EQ(operands.size(), 2u);
    const auto* left_node = operands[0].Get();
    const auto* right_node = operands[1].Get();
    DCHECK(left_node);
    DCHECK(right_node);

    auto* const value = CalcToNumericValue(*right_node);

    // If the current node is a '-' or '/', it's really just a '+' or '*' with
    // the right child negated or inverted, respectively.
    values.push_back(
        NegateOrInvertIfRequired(binary_op->OperatorType(), value));
    cur_node = left_node;
  } while (CanCombineNodes(root, *cur_node));

  DCHECK(cur_node);
  values.push_back(CalcToNumericValue(*cur_node));

  // Our algorithm collects the children in reverse order, so we have to reverse
  // the values.
  std::reverse(values.begin(), values.end());
  CSSMathOperator operator_type =
      To<CSSMathExpressionOperation>(root).OperatorType();
  if (operator_type == CSSMathOperator::kAdd ||
      operator_type == CSSMathOperator::kSubtract) {
    return CSSMathSum::Create(std::move(values));
  }
  return CSSMathProduct::Create(std::move(values));
}

CSSUnitValue* CSSNumericSumValueEntryToUnitValue(
    const CSSNumericSumValue::Term& term) {
  if (term.units.size() == 0) {
    return CSSUnitValue::Create(term.value);
  }
  if (term.units.size() == 1 && term.units.begin()->value == 1) {
    return CSSUnitValue::Create(term.value, term.units.begin()->key);
  }
  return nullptr;
}

}  // namespace

bool CSSNumericValue::IsValidUnit(CSSPrimitiveValue::UnitType unit) {
  // UserUnits returns true for CSSPrimitiveValue::IsLength below.
  if (unit == CSSPrimitiveValue::UnitType::kUserUnits) {
    return false;
  }
  if (unit == CSSPrimitiveValue::UnitType::kNumber ||
      unit == CSSPrimitiveValue::UnitType::kPercentage ||
      CSSPrimitiveValue::IsLength(unit) || CSSPrimitiveValue::IsAngle(unit) ||
      CSSPrimitiveValue::IsTime(unit) || CSSPrimitiveValue::IsFrequency(unit) ||
      CSSPrimitiveValue::IsResolution(unit) ||
      CSSPrimitiveValue::IsFlex(unit)) {
    return true;
  }
  return false;
}

CSSPrimitiveValue::UnitType CSSNumericValue::UnitFromName(const String& name) {
  if (name.empty()) {
    return CSSPrimitiveValue::UnitType::kUnknown;
  }
  if (EqualIgnoringASCIICase(name, "number")) {
    return CSSPrimitiveValue::UnitType::kNumber;
  }
  if (EqualIgnoringASCIICase(name, "percent") || name == "%") {
    return CSSPrimitiveValue::UnitType::kPercentage;
  }
  return CSSPrimitiveValue::StringToUnitType(name);
}

// static
CSSNumericValue* CSSNumericValue::parse(
    const ExecutionContext* execution_context,
    const String& css_text,
    ExceptionState& exception_state) {
  CSSParserTokenStream stream(css_text);
  stream.ConsumeWhitespace();

  switch (stream.Peek().GetType()) {
    case kNumberToken:
    case kPercentageToken:
    case kDimensionToken: {
      const auto token = stream.ConsumeIncludingWhitespace();
      if (!stream.AtEnd() || !IsValidUnit(token.GetUnitType())) {
        break;
      }
      return CSSUnitValue::Create(token.NumericValue(), token.GetUnitType());
    }
    case kFunctionToken:
      if (stream.Peek().FunctionId() == CSSValueID::kCalc ||
          stream.Peek().FunctionId() == CSSValueID::kWebkitCalc ||
          stream.Peek().FunctionId() == CSSValueID::kMin ||
          stream.Peek().FunctionId() == CSSValueID::kMax ||
          stream.Peek().FunctionId() == CSSValueID::kClamp) {
        using enum CSSMathExpressionNode::Flag;
        using Flags = CSSMathExpressionNode::Flags;

        // TODO(crbug.com/1309178): Decide how to handle anchor queries here.
        CSSMathExpressionNode* expression =
            CSSMathExpressionNode::ParseMathFunction(
                CSSValueID::kCalc, stream,
                *MakeGarbageCollected<CSSParserContext>(*execution_context),
                Flags({AllowPercent}), kCSSAnchorQueryTypesNone);
        if (expression) {
          return CalcToNumericValue(*expression);
        }
      }
      break;
    default:
      break;
  }

  exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                    "Invalid math expression");
  return nullptr;
}

// static
CSSNumericValue* CSSNumericValue::FromCSSValue(const CSSPrimitiveValue& value) {
  if (value.IsCalculated()) {
    const auto& math_function = To<CSSMathFunctionValue>(value);
    // We don't currently have a spec or implementation for a typed OM
    // representation of anchor functions or sizing keywords (in calc-size()).
    // So we should not attempt to produce such a representation.  Do this
    // exactly for anchor functions, but handle sizing keywords by rejecting
    // any calc-size() function (even if it doesn't have sizing keywords),
    // since the use of sizing keywords is the main use of such functions.
    auto is_calc_size = [](const CSSMathExpressionNode* expression) {
      const auto* operation = DynamicTo<CSSMathExpressionOperation>(expression);
      return operation && operation->IsCalcSize();
    };
    const CSSMathExpressionNode* expression = math_function.ExpressionNode();
    if (math_function.HasAnchorFunctions() || is_calc_size(expression)) {
      return nullptr;
    }
    return CalcToNumericValue(*expression);
  }
  return CSSUnitValue::FromCSSValue(To<CSSNumericLiteralValue>(value));
}

// static
CSSNumericValue* CSSNumericValue::FromNumberish(const V8CSSNumberish* value) {
  if (value->IsDouble()) {
    return CSSUnitValue::Create(value->GetAsDouble(),
                                CSSPrimitiveValue::UnitType::kNumber);
  }
  return value->GetAsCSSNumericValue();
}

// static
CSSNumericValue* CSSNumericValue::FromPercentish(const V8CSSNumberish* value) {
  if (value->IsDouble()) {
    return CSSUnitValue::Create(value->GetAsDouble() * 100,
                                CSSPrimitiveValue::UnitType::kPercentage);
  }
  return value->GetAsCSSNumericValue();
}

CSSUnitValue* CSSNumericValue::to(const String& unit_string,
                                  ExceptionState& exception_state) {
  CSSPrimitiveValue::UnitType target_unit = UnitFromName(unit_string);
  if (!IsValidUnit(target_unit)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Invalid unit for conversion");
    return nullptr;
  }

  CSSUnitValue* result = to(target_unit);
  if (!result) {
    exception_state.ThrowTypeError("Cannot convert to " + unit_string);
    return nullptr;
  }

  return result;
}

CSSUnitValue* CSSNumericValue::to(CSSPrimitiveValue::UnitType unit) const {
  const auto sum = SumValue();
  if (!sum.has_value() || sum->terms.size() != 1) {
    return nullptr;
  }

  CSSUnitValue* value = CSSNumericSumValueEntryToUnitValue(sum->terms[0]);
  if (!value) {
    return nullptr;
  }
  return value->ConvertTo(unit);
}

CSSMathSum* CSSNumericValue::toSum(const Vector<String>& unit_strings,
                                   ExceptionState& exception_state) {
  for (const auto& unit_string : unit_strings) {
    if (!IsValidUnit(UnitFromName(unit_string))) {
      exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                        "Invalid unit for conversion");
      return nullptr;
    }
  }

  const std::optional<CSSNumericSumValue> sum = SumValue();
  if (!sum.has_value()) {
    exception_state.ThrowTypeError("Invalid value for conversion");
    return nullptr;
  }

  CSSNumericValueVector values;
  for (const auto& term : sum->terms) {
    CSSUnitValue* value = CSSNumericSumValueEntryToUnitValue(term);
    if (!value) {
      exception_state.ThrowTypeError("Invalid value for conversion");
      return nullptr;
    }
    values.push_back(value);
  }

  if (unit_strings.size() == 0) {
    std::sort(values.begin(), values.end(), [](const auto& a, const auto& b) {
      return WTF::CodeUnitCompareLessThan(To<CSSUnitValue>(a.Get())->unit(),
                                          To<CSSUnitValue>(b.Get())->unit());
    });

    // We got 'values' from a sum value, so it must be a valid CSSMathSum.
    CSSMathSum* result = CSSMathSum::Create(values);
    DCHECK(result);
    return result;
  }

  CSSNumericValueVector result;
  for (const auto& unit_string : unit_strings) {
    CSSPrimitiveValue::UnitType target_unit = UnitFromName(unit_string);
    DCHECK(IsValidUnit(target_unit));

    // Collect all the terms that are compatible with this unit.
    // We mark used terms as null so we don't use them again.
    double total_value =
        std::accumulate(values.begin(), values.end(), 0.0,
                        [target_unit](double cur_sum, auto& value) {
                          if (value) {
                            auto& unit_value = To<CSSUnitValue>(*value);
                            if (const auto* converted_value =
                                    unit_value.ConvertTo(target_unit)) {
                              cur_sum += converted_value->value();
                              value = nullptr;
                            }
                          }
                          return cur_sum;
                        });

    result.push_back(CSSUnitValue::Create(total_value, target_unit));
  }

  if (base::ranges::any_of(values, [](const auto& v) { return v; })) {
    exception_state.ThrowTypeError(
        "There were leftover terms that were not converted");
    return nullptr;
  }

  return CSSMathSum::Create(result, exception_state);
}

CSSNumericType* CSSNumericValue::type() const {
  CSSNumericType* type = CSSNumericType::Create();
  using BaseType = CSSNumericValueType::BaseType;

  if (int exponent = type_.Exponent(BaseType::kLength)) {
    type->setLength(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kAngle)) {
    type->setAngle(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kTime)) {
    type->setTime(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kFrequency)) {
    type->setFrequency(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kResolution)) {
    type->setResolution(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kFlex)) {
    type->setFlex(exponent);
  }
  if (int exponent = type_.Exponent(BaseType::kPercent)) {
    type->setPercent(exponent);
  }
  if (type_.HasPercentHint()) {
    type->setPercentHint(
        CSSNumericValueType::BaseTypeToString(type_.PercentHint()));
  }
  return type;
}

CSSNumericValue* CSSNumericValue::add(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  PrependValueForArithmetic<kSumType>(values, this);

  if (CSSUnitValue* unit_value =
          MaybeSimplifyAsUnitValue(values, std::plus<double>())) {
    return unit_value;
  }
  return CSSMathSum::Create(std::move(values), exception_state);
}

CSSNumericValue* CSSNumericValue::sub(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  base::ranges::transform(values, values.begin(), &CSSNumericValue::Negate);
  PrependValueForArithmetic<kSumType>(values, this);

  if (CSSUnitValue* unit_value =
          MaybeSimplifyAsUnitValue(values, std::plus<double>())) {
    return unit_value;
  }
  return CSSMathSum::Create(std::move(values), exception_state);
}

CSSNumericValue* CSSNumericValue::mul(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  PrependValueForArithmetic<kProductType>(values, this);

  if (CSSUnitValue* unit_value = MaybeMultiplyAsUnitValue(values)) {
    return unit_value;
  }
  return CSSMathProduct::Create(std::move(values));
}

CSSNumericValue* CSSNumericValue::div(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  for (auto& v : values) {
    auto* invert_value = v->Invert();
    if (!invert_value) {
      exception_state.ThrowRangeError("Can't divide-by-zero");
      return nullptr;
    }
    v = invert_value;
  }

  PrependValueForArithmetic<kProductType>(values, this);

  if (CSSUnitValue* unit_value = MaybeMultiplyAsUnitValue(values)) {
    return unit_value;
  }
  return CSSMathProduct::Create(std::move(values));
}

CSSNumericValue* CSSNumericValue::min(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  PrependValueForArithmetic<kMinType>(values, this);

  if (CSSUnitValue *unit_value = MaybeSimplifyAsUnitValue(
          values, [](double a, double b) { return std::min(a, b); })) {
    return unit_value;
  }
  return CSSMathMin::Create(std::move(values));
}

CSSNumericValue* CSSNumericValue::max(
    const HeapVector<Member<V8CSSNumberish>>& numberishes,
    ExceptionState& exception_state) {
  auto values = CSSNumberishesToNumericValues(numberishes);
  PrependValueForArithmetic<kMaxType>(values, this);

  if (CSSUnitValue *unit_value = MaybeSimplifyAsUnitValue(
          values, [](double a, double b) { return std::max(a, b); })) {
    return unit_value;
  }
  return CSSMathMax::Create(std::move(values));
}

bool CSSNumericValue::equals(
    const HeapVector<Member<V8CSSNumberish>>& numberishes) {
  CSSNumericValueVector values = CSSNumberishesToNumericValues(numberishes);
  return base::ranges::all_of(
      values, [this](const auto& v) { return this->Equals(*v); });
}

String CSSNumericValue::toString() const {
  StringBuilder result;
  BuildCSSText(Nested::kNo, ParenLess::kNo, result);
  return result.ReleaseString();
}

CSSNumericValue* CSSNumericValue::Negate() {
  return CSSMathNegate::Create(this);
}

CSSNumericValue* CSSNumericValue::Invert() {
  return CSSMathInvert::Create(this);
}

CSSNumericValueVector CSSNumberishesToNumericValues(
    const HeapVector<Member<V8CSSNumberish>>& values) {
  CSSNumericValueVector result;
  for (const V8CSSNumberish* value : values) {
    result.push_back(CSSNumericValue::FromNumberish(value));
  }
  return result;
}

}  // namespace blink
```