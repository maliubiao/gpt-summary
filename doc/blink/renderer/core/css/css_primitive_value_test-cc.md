Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Subject:** The file name `css_primitive_value_test.cc` and the `#include "third_party/blink/renderer/core/css/css_primitive_value.h"` clearly indicate that this file contains tests for the `CSSPrimitiveValue` class in the Blink rendering engine.

2. **Understand the Purpose of Unit Tests:**  Unit tests verify the behavior of individual components or units of code in isolation. The goal is to ensure that each part of the system works as expected. In this case, the "unit" is the `CSSPrimitiveValue` class and its related functionalities.

3. **Scan for Key Test Areas:** Look for `TEST_F` macros. Each `TEST_F` defines a specific test case. By reading the names of these tests, we can get a high-level overview of what aspects of `CSSPrimitiveValue` are being tested. Initial scan reveals tests for:
    * `IsTime` and `IsTimeCalc`: Time unit handling.
    * `ClampTimeToNonNegative`: Clamping values.
    * `IsResolution`: Resolution unit handling.
    * `Zooming`: Interaction with zooming.
    * `PositiveInfinityLengthClamp`, `NegativeInfinityLengthClamp`, `NaNLengthClamp`: Handling of special numeric values in length calculations.
    * `PositiveInfinityPercentLengthClamp`, etc.: Similar tests for percentages.
    * `GetDoubleValueWithoutClampingAllowNaN`, etc.: Different ways to retrieve double values, with and without clamping.
    * `TestCanonicalizingNumberUnitCategory`: Unit type conversion.
    * `HasContainerRelativeUnits`, `HasStaticViewportUnits`, `HasDynamicViewportUnits`: Checking for the presence of specific unit types.
    * `ComputeMethodsWithLengthResolver`: Calculations involving length resolution.
    * `ContainerProgressTreeScope`:  Testing scoping for a specific CSS function.
    * `CSSPrimitiveValueOperations`: Testing arithmetic and other operations on `CSSPrimitiveValue` objects.
    * `ComputeValueToCanonicalUnit`:  Converting to a canonical unit.

4. **Analyze Individual Test Cases (Example):** Take one or two examples to understand the testing pattern. Let's look at `TEST_F(CSSPrimitiveValueTest, IsTime)`:
    * It creates `CSSPrimitiveValue` objects with different `UnitType`s.
    * It uses `EXPECT_FALSE` and `EXPECT_TRUE` to assert whether the `IsTime()` method returns the correct boolean value for time-related and non-time-related units. This tells us that `IsTime()` is a method of `CSSPrimitiveValue` that checks if the value represents a time unit.

5. **Identify Relationships with Web Technologies:** Consider how `CSSPrimitiveValue` and the tested functionalities relate to HTML, CSS, and JavaScript:
    * **CSS:**  `CSSPrimitiveValue` directly represents values used in CSS properties (like length, time, angles, etc.). The tests for different unit types (pixels, ems, seconds, degrees, viewport units, etc.) are direct demonstrations of how CSS values are handled internally. The `calc()` function is also explicitly tested.
    * **HTML:**  CSS styles are applied to HTML elements. The tests implicitly involve HTML because the CSS values will eventually style HTML content. The test setup uses `GetDocument()`, indicating interaction with a Document object, which is part of the HTML DOM.
    * **JavaScript:** JavaScript can interact with CSS through the DOM (e.g., `element.style.width = '100px'`). While this test file doesn't directly involve JavaScript code, the underlying mechanisms being tested are crucial for JavaScript's ability to manipulate styles.

6. **Look for Logic and Assumptions:** Examine tests involving calculations or conversions. For example, the `Zooming` test shows a conversion process where zooming affects length values. The `ClampTimeToNonNegative` test demonstrates clamping logic. Note the use of `CSSToLengthConversionData`, suggesting a context-dependent conversion.

7. **Identify Potential User/Programming Errors:** Think about how developers might misuse CSS or encounter issues. The tests involving `NaN` and infinity highlight potential errors in calculations or data input that the rendering engine needs to handle gracefully. Incorrect unit usage (e.g., adding incompatible units without `calc()`) is another area implicitly covered.

8. **Trace User Actions (Debugging Clues):** Consider how a user action in the browser could lead to this code being executed. When a web page is loaded:
    * The HTML is parsed.
    * The CSS is parsed.
    * The CSS values are represented internally by objects like `CSSPrimitiveValue`.
    * When layout or painting occurs, these values are used to determine the size, position, and appearance of elements.
    * Interactions like zooming trigger recalculations involving these values.
    * JavaScript manipulation of styles also relies on the correct handling of these values.

9. **Synthesize and Organize:**  Structure the findings logically, covering the core functionality, relationships to web technologies, logic/assumptions, potential errors, and debugging clues. Use clear and concise language. Provide specific examples from the code to support your explanations.

10. **Refine and Review:** Read through the analysis to ensure accuracy and completeness. Check for any missing connections or areas that need further clarification. For example, explicitly mentioning the role of the layout engine would strengthen the explanation of how these values are used. Double-checking the interpretation of specific test cases is important.

By following this systematic approach, we can effectively analyze the provided C++ test file and understand its role within the Blink rendering engine.
这个C++文件 `css_primitive_value_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `CSSPrimitiveValue` 类的功能。 `CSSPrimitiveValue` 类是 Blink 引擎中表示 CSS 原始值的核心类，例如长度、颜色、数字等。

**文件功能列表:**

1. **测试 `CSSPrimitiveValue` 的基本属性和方法:**
   - 测试判断值是否属于特定类型的方法，例如 `IsTime()`, `IsResolution()`。
   - 测试获取和转换值的方法，例如 `ComputeSeconds()`, `ComputeDegrees()`, `ConvertToLength()`, `GetDoubleValue()`, `GetDoubleValueWithoutClamping()`。
   - 测试处理特殊数值的方法，例如正负无穷大和 NaN (Not a Number) 的处理。
   - 测试值的运算操作，例如加法 `Add()`, 减法 `Subtract()`, 乘法 `Multiply()`, 除法 `Divide()`, `SubtractFrom()`。
   - 测试值的规范化表示，例如将不同单位转换为规范单位。
   - 测试获取 CSS 文本表示的方法 `CustomCSSText()`。

2. **测试 `CSSPrimitiveValue` 对不同 CSS 单位的支持:**
   - 时间单位: `seconds`, `milliseconds`。
   - 角度单位: `degrees`, `gradians`, `turns`。
   - 分辨率单位: `dpi`, `dpcm`, `dppx` (别名 `x`)。
   - 长度单位: `px`, `em`, `rem`, `vw`, `vh`, `vmin`, `vmax`, `cqw`, `cqh`, `cqi`, `cqb`, `cqmin`, `cqmax`, `svw`, `svh`, `lvw`, `lvh`, `dvw`, `dvh` 等。
   - 百分比单位 `%`。
   - 数字单位 `number` 和 `integer`。

3. **测试涉及计算的 `CSSPrimitiveValue`:**
   - 测试 `calc()` 函数表达式的解析和计算。
   - 测试包含不同单位的计算，以及单位转换。
   - 测试计算结果的 clamp 行为（例如，确保时间或角度值非负）。

4. **测试与视口单位和容器查询相关的 `CSSPrimitiveValue`:**
   - 测试判断值是否包含容器相对单位 (如 `cqw`, `cqh`) 的方法 `HasContainerRelativeUnits()`。
   - 测试判断值是否包含静态视口单位 (如 `vw`, `vh`, `svw`, `svh`, `lvw`, `lvh`) 的方法 `HasStaticViewportUnits()`。
   - 测试判断值是否包含动态视口单位 (如 `dvw`, `dvh`) 的方法 `HasDynamicViewportUnits()`。

5. **测试在特定上下文中的 `CSSPrimitiveValue` 计算:**
   - 使用 `CSSToLengthConversionData` 来模拟长度转换所需的上下文信息，例如字体大小和缩放级别。

6. **测试 `CSSPrimitiveValue` 的作用域:**
   - 测试 `EnsureScopedValue()` 方法，可能涉及到自定义属性或容器查询的上下文。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

- **CSS:**  该测试文件直接测试了 CSS 值的表示和处理。`CSSPrimitiveValue` 类是 CSS 属性值的内部表示。
    - **例子:** 当浏览器解析 CSS 规则 `width: 100px;` 时，`100px` 这个值会被表示为一个 `CSSPrimitiveValue` 对象，其值为 100，单位为像素 (`UnitType::kPixels`)。测试文件中的 `Create({100, UnitType::kPixels})` 就模拟了这种创建过程。
    - **例子:** CSS 中的 `calc(10px + 2em)` 函数会被解析为一个包含 `CSSMathFunctionValue` 的 `CSSPrimitiveValue` 对象，其中包含加法操作和两个操作数（分别表示 10px 和 2em）。测试文件中的 `CreateAddition(a, b)` 就模拟了创建这种计算值。

- **HTML:** CSS 样式应用于 HTML 元素。`CSSPrimitiveValue` 对象最终会影响 HTML 元素的渲染结果。
    - **例子:** 当 HTML 元素的 `style` 属性或外部 CSS 文件中定义了 `font-size: 16px;` 时，浏览器会创建一个 `CSSPrimitiveValue` 对象来表示这个字体大小，并将其应用于相应的 HTML 元素。测试文件中的 `CSSToLengthConversionData` 涉及到字体信息，表明 `CSSPrimitiveValue` 的计算会受到 HTML 元素上下文的影响。

- **JavaScript:** JavaScript 可以通过 DOM API 操作 CSS 样式。JavaScript 设置或获取的 CSS 属性值，在 Blink 引擎内部会转换为 `CSSPrimitiveValue` 对象。
    - **例子:**  JavaScript 代码 `element.style.width = '50vw';` 会导致浏览器创建一个 `CSSPrimitiveValue` 对象来表示 `50vw`。测试文件中的 `HasStaticViewportUnits("50vw")` 测试了对这种视口单位的处理。
    - **例子:** JavaScript 代码 `getComputedStyle(element).width` 获取到的宽度值，其底层表示也涉及到 `CSSPrimitiveValue`。

**逻辑推理的假设输入与输出:**

- **假设输入:**  一个表示 CSS 值的字符串，例如 `"10px"`, `"calc(50% - 20px)"`, `"1s"`.
- **输出:**  通过 `ParseValue()` 函数解析后得到的 `CSSPrimitiveValue` 对象，或者通过测试方法（如 `IsTime()`, `ComputeLength()`）得到的布尔值或数值。

**示例:**

- **假设输入:** `"100ms"`
- **测试方法:** `IsTime()`
- **输出:** `true` (因为 100ms 是一个时间值)

- **假设输入:** `"calc(10px + 1em)"`
- **测试方法:** `CustomCSSText()`
- **输出:** `"calc(1em + 10px)"` (或者类似的标准化的 CSS 文本表示，顺序可能不同)

- **假设输入:** `"2turns"`
- **测试方法:** `ComputeDegrees(nullptr)` (假设没有元素上下文)
- **输出:** `720.0` (因为 2 圈等于 720 度)

**用户或编程常见的使用错误:**

1. **单位不匹配的计算:**
   - **错误示例 (CSS):** `width: calc(10px + 2s);`  尝试将长度和时间相加，这是无效的 CSS。
   - **测试体现:** 测试文件中会验证 `IsTimeCalc()` 在单位不匹配时返回 `false`。

2. **超出范围的值:**
   - **错误示例 (CSS):** 某些属性可能对值的范围有约束。例如，`opacity` 的值应该在 0 到 1 之间。虽然 `CSSPrimitiveValue` 本身不直接强制这些约束，但其计算和转换过程会处理这些情况。
   - **测试体现:** `ClampTimeToNonNegative` 和 `ClampAngleToNonNegative` 测试了将计算结果 clamp 到非负值的逻辑，这模拟了某些 CSS 属性的行为。

3. **使用未定义的单位:**
   - **错误示例 (CSS):**  `width: 10foo;`  使用了不存在的单位 `foo`。
   - **测试体现:** 虽然测试文件没有直接测试解析错误，但它通过测试已知单位的功能来确保对合法单位的支持。解析器在遇到未知单位时会产生错误，但这通常在更上层的解析器测试中进行。

4. **数值溢出或 NaN:**
   - **错误示例 (JavaScript 或 CSS 计算):**  进行可能导致无限大或 NaN 的计算。
   - **测试体现:** `PositiveInfinityLengthClamp`, `NegativeInfinityLengthClamp`, `NaNLengthClamp` 等测试专门处理了这些特殊数值的情况，确保 `CSSPrimitiveValue` 在这些情况下能返回合理的 clamped 值或 NaN (在允许的情况下)。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 HTML 和 CSS 代码:** 用户在编写网页时，会使用各种 CSS 属性和值，包括长度、颜色、时间等。例如，用户可能设置一个元素的宽度为 `100px`，动画的持续时间为 `2s`。

2. **浏览器加载和解析网页:** 当用户访问包含这些 HTML 和 CSS 代码的网页时，浏览器 (Chromium) 的渲染引擎 (Blink) 会开始解析这些代码。

3. **CSS 解析器创建 `CSSPrimitiveValue` 对象:**  CSS 解析器会识别 CSS 属性的值，并将这些值转换为 Blink 引擎内部的数据结构。对于像 `100px` 这样的原始值，会创建一个 `CSSPrimitiveValue` 对象，存储数值 `100` 和单位 `px`。对于像 `calc(50% - 20px)` 这样的计算值，会创建包含 `CSSMathFunctionValue` 的 `CSSPrimitiveValue` 对象。

4. **布局和渲染过程使用 `CSSPrimitiveValue`:**  在布局 (Layout) 阶段，渲染引擎会计算每个元素的大小和位置。`CSSPrimitiveValue` 对象会被用来确定元素的具体尺寸（例如，将 `100px` 直接用于像素值，或者根据父元素的字体大小计算 `em` 单位）。在渲染 (Paint) 阶段，这些值也会影响元素的绘制。

5. **JavaScript 操作 CSS 样式:** 用户与网页交互时，JavaScript 代码可能会动态地修改元素的 CSS 样式。例如，点击按钮后改变元素的宽度。这些操作也会导致创建或修改 `CSSPrimitiveValue` 对象。

6. **调试线索:** 当开发者需要调试与 CSS 值相关的问题时（例如，元素的宽度不正确，动画没有按预期运行），他们可能会：
   - **使用开发者工具检查元素:**  在 Chrome 开发者工具的 "Elements" 面板中，可以查看元素的 "Computed" 样式，这些样式的值在 Blink 引擎内部就是由 `CSSPrimitiveValue` 对象表示的。
   - **断点调试 Blink 引擎代码:** 如果问题很复杂，开发者可能会下载 Chromium 源代码，并在 Blink 引擎的相关代码中设置断点，例如在 `CSSPrimitiveValue` 的计算或转换方法中。`css_primitive_value_test.cc` 这个文件中的测试用例可以帮助开发者理解 `CSSPrimitiveValue` 的行为，并作为调试的参考。如果某个测试用例失败了，可能就意味着 `CSSPrimitiveValue` 在特定情况下的行为不符合预期。

总而言之，`css_primitive_value_test.cc` 是 Blink 引擎中用于确保 `CSSPrimitiveValue` 类功能正确性的关键测试文件。它涵盖了各种 CSS 值的表示、计算和转换，对于理解 Blink 引擎如何处理 CSS 样式至关重要，并且可以作为调试 CSS 相关问题的线索。

### 提示词
```
这是目录为blink/renderer/core/css/css_primitive_value_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/css_primitive_value.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace {

class CSSPrimitiveValueTest : public PageTestBase {
 public:
  const CSSPrimitiveValue* ParseValue(const char* text) {
    const CSSPrimitiveValue* value = To<CSSPrimitiveValue>(
        css_test_helpers::ParseValue(GetDocument(), "<length>", text));
    DCHECK(value);
    return value;
  }

  bool HasContainerRelativeUnits(const char* text) {
    return ParseValue(text)->HasContainerRelativeUnits();
  }

  bool HasStaticViewportUnits(const char* text) {
    const CSSPrimitiveValue* value = ParseValue(text);
    CSSPrimitiveValue::LengthTypeFlags length_type_flags;
    value->AccumulateLengthUnitTypes(length_type_flags);
    return CSSPrimitiveValue::HasStaticViewportUnits(length_type_flags);
  }

  bool HasDynamicViewportUnits(const char* text) {
    const CSSPrimitiveValue* value = ParseValue(text);
    CSSPrimitiveValue::LengthTypeFlags length_type_flags;
    value->AccumulateLengthUnitTypes(length_type_flags);
    return CSSPrimitiveValue::HasDynamicViewportUnits(length_type_flags);
  }

  CSSPrimitiveValueTest() = default;
};

using UnitType = CSSPrimitiveValue::UnitType;

struct UnitValue {
  double value;
  UnitType unit_type;
};

CSSNumericLiteralValue* Create(UnitValue v) {
  return CSSNumericLiteralValue::Create(v.value, v.unit_type);
}

CSSPrimitiveValue* CreateAddition(UnitValue a, UnitValue b) {
  return CSSMathFunctionValue::Create(
      CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionNumericLiteral::Create(Create(a)),
          CSSMathExpressionNumericLiteral::Create(Create(b)),
          CSSMathOperator::kAdd));
}

CSSPrimitiveValue* CreateNonNegativeSubtraction(UnitValue a, UnitValue b) {
  return CSSMathFunctionValue::Create(
      CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionNumericLiteral::Create(Create(a)),
          CSSMathExpressionNumericLiteral::Create(Create(b)),
          CSSMathOperator::kSubtract),
      CSSPrimitiveValue::ValueRange::kNonNegative);
}

UnitType ToCanonicalUnit(CSSPrimitiveValue::UnitType unit) {
  return CSSPrimitiveValue::CanonicalUnitTypeForCategory(
      CSSPrimitiveValue::UnitTypeToUnitCategory(unit));
}

TEST_F(CSSPrimitiveValueTest, IsTime) {
  EXPECT_FALSE(Create({5.0, UnitType::kNumber})->IsTime());
  EXPECT_FALSE(Create({5.0, UnitType::kDegrees})->IsTime());
  EXPECT_TRUE(Create({5.0, UnitType::kSeconds})->IsTime());
  EXPECT_TRUE(Create({5.0, UnitType::kMilliseconds})->IsTime());
}

TEST_F(CSSPrimitiveValueTest, IsTimeCalc) {
  {
    UnitValue a = {1.0, UnitType::kSeconds};
    UnitValue b = {1000.0, UnitType::kMilliseconds};
    EXPECT_TRUE(CreateAddition(a, b)->IsTime());
  }
  {
    UnitValue a = {1.0, UnitType::kDegrees};
    UnitValue b = {1000.0, UnitType::kGradians};
    EXPECT_FALSE(CreateAddition(a, b)->IsTime());
  }
}

TEST_F(CSSPrimitiveValueTest, ClampTimeToNonNegative) {
  UnitValue a = {4926, UnitType::kMilliseconds};
  UnitValue b = {5, UnitType::kSeconds};
  EXPECT_EQ(0.0, CreateNonNegativeSubtraction(a, b)->ComputeSeconds());
}

TEST_F(CSSPrimitiveValueTest, ClampAngleToNonNegative) {
  UnitValue a = {89, UnitType::kDegrees};
  UnitValue b = {0.25, UnitType::kTurns};
  EXPECT_EQ(0.0, CreateNonNegativeSubtraction(a, b)->ComputeDegrees(
                     CSSToLengthConversionData(/*element=*/nullptr)));
}

TEST_F(CSSPrimitiveValueTest, IsResolution) {
  EXPECT_FALSE(Create({5.0, UnitType::kNumber})->IsResolution());
  EXPECT_FALSE(Create({5.0, UnitType::kDegrees})->IsResolution());
  EXPECT_TRUE(Create({5.0, UnitType::kDotsPerPixel})->IsResolution());
  EXPECT_TRUE(Create({5.0, UnitType::kX})->IsResolution());
  EXPECT_TRUE(Create({5.0, UnitType::kDotsPerInch})->IsResolution());
  EXPECT_TRUE(Create({5.0, UnitType::kDotsPerCentimeter})->IsResolution());
}

// https://crbug.com/999875
TEST_F(CSSPrimitiveValueTest, Zooming) {
  // Tests that the conversion CSSPrimitiveValue -> Length -> CSSPrimitiveValue
  // yields the same value under zooming.

  UnitValue a = {100, UnitType::kPixels};
  UnitValue b = {10, UnitType::kPercentage};
  CSSPrimitiveValue* original = CreateAddition(a, b);

  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  conversion_data.SetZoom(0.5);

  Length length = original->ConvertToLength(conversion_data);
  EXPECT_TRUE(length.IsCalculated());
  EXPECT_EQ(50.0, length.GetPixelsAndPercent().pixels);
  EXPECT_EQ(10.0, length.GetPixelsAndPercent().percent);

  CSSPrimitiveValue* converted =
      CSSPrimitiveValue::CreateFromLength(length, conversion_data.Zoom());
  EXPECT_TRUE(converted->IsMathFunctionValue());
  EXPECT_EQ("calc(10% + 100px)", converted->CustomCSSText());
}

TEST_F(CSSPrimitiveValueTest, PositiveInfinityLengthClamp) {
  UnitValue a = {std::numeric_limits<double>::infinity(), UnitType::kPixels};
  UnitValue b = {1, UnitType::kPixels};
  CSSPrimitiveValue* value = CreateAddition(a, b);
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  EXPECT_EQ(std::numeric_limits<double>::max(),
            value->ComputeLength<double>(conversion_data));
}

TEST_F(CSSPrimitiveValueTest, NegativeInfinityLengthClamp) {
  UnitValue a = {-std::numeric_limits<double>::infinity(), UnitType::kPixels};
  UnitValue b = {1, UnitType::kPixels};
  CSSPrimitiveValue* value = CreateAddition(a, b);
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  EXPECT_EQ(std::numeric_limits<double>::lowest(),
            value->ComputeLength<double>(conversion_data));
}

TEST_F(CSSPrimitiveValueTest, NaNLengthClamp) {
  UnitValue a = {-std::numeric_limits<double>::quiet_NaN(), UnitType::kPixels};
  UnitValue b = {1, UnitType::kPixels};
  CSSPrimitiveValue* value = CreateAddition(a, b);
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  EXPECT_EQ(0.0, value->ComputeLength<double>(conversion_data));
}

TEST_F(CSSPrimitiveValueTest, PositiveInfinityPercentLengthClamp) {
  CSSPrimitiveValue* value =
      Create({std::numeric_limits<double>::infinity(), UnitType::kPercentage});
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  Length length = value->ConvertToLength(conversion_data);
  EXPECT_EQ(std::numeric_limits<float>::max(), length.Percent());
}

TEST_F(CSSPrimitiveValueTest, NegativeInfinityPercentLengthClamp) {
  CSSPrimitiveValue* value =
      Create({-std::numeric_limits<double>::infinity(), UnitType::kPercentage});
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  Length length = value->ConvertToLength(conversion_data);
  EXPECT_EQ(std::numeric_limits<float>::lowest(), length.Percent());
}

TEST_F(CSSPrimitiveValueTest, NaNPercentLengthClamp) {
  CSSPrimitiveValue* value = Create(
      {-std::numeric_limits<double>::quiet_NaN(), UnitType::kPercentage});
  CSSToLengthConversionData conversion_data(/*element=*/nullptr);
  Length length = value->ConvertToLength(conversion_data);
  EXPECT_EQ(0.0, length.Percent());
}

TEST_F(CSSPrimitiveValueTest, GetDoubleValueWithoutClampingAllowNaN) {
  CSSPrimitiveValue* value =
      Create({std::numeric_limits<double>::quiet_NaN(), UnitType::kPixels});
  EXPECT_TRUE(std::isnan(value->GetDoubleValueWithoutClamping()));
}

TEST_F(CSSPrimitiveValueTest,
       GetDoubleValueWithoutClampingAllowPositveInfinity) {
  CSSPrimitiveValue* value =
      Create({std::numeric_limits<double>::infinity(), UnitType::kPixels});
  EXPECT_TRUE(std::isinf(value->GetDoubleValueWithoutClamping()) &&
              value->GetDoubleValueWithoutClamping() > 0);
}

TEST_F(CSSPrimitiveValueTest,
       GetDoubleValueWithoutClampingAllowNegativeInfinity) {
  CSSPrimitiveValue* value =
      Create({-std::numeric_limits<double>::infinity(), UnitType::kPixels});

  EXPECT_TRUE(std::isinf(value->GetDoubleValueWithoutClamping()) &&
              value->GetDoubleValueWithoutClamping() < 0);
}

TEST_F(CSSPrimitiveValueTest, GetDoubleValueClampNaN) {
  CSSPrimitiveValue* value =
      Create({std::numeric_limits<double>::quiet_NaN(), UnitType::kPixels});
  EXPECT_EQ(0.0, value->GetDoubleValue());
}

TEST_F(CSSPrimitiveValueTest, GetDoubleValueClampPositiveInfinity) {
  CSSPrimitiveValue* value =
      Create({std::numeric_limits<double>::infinity(), UnitType::kPixels});
  EXPECT_EQ(std::numeric_limits<double>::max(), value->GetDoubleValue());
}

TEST_F(CSSPrimitiveValueTest, GetDoubleValueClampNegativeInfinity) {
  CSSPrimitiveValue* value =
      Create({-std::numeric_limits<double>::infinity(), UnitType::kPixels});
  EXPECT_EQ(std::numeric_limits<double>::lowest(), value->GetDoubleValue());
}

TEST_F(CSSPrimitiveValueTest, TestCanonicalizingNumberUnitCategory) {
  UnitType canonicalized_from_num = ToCanonicalUnit(UnitType::kNumber);
  EXPECT_EQ(canonicalized_from_num, UnitType::kNumber);

  UnitType canonicalized_from_int = ToCanonicalUnit(UnitType::kInteger);
  EXPECT_EQ(canonicalized_from_int, UnitType::kNumber);
}

TEST_F(CSSPrimitiveValueTest, HasContainerRelativeUnits) {
  EXPECT_TRUE(HasContainerRelativeUnits("1cqw"));
  EXPECT_TRUE(HasContainerRelativeUnits("1cqh"));
  EXPECT_TRUE(HasContainerRelativeUnits("1cqi"));
  EXPECT_TRUE(HasContainerRelativeUnits("1cqb"));
  EXPECT_TRUE(HasContainerRelativeUnits("1cqmin"));
  EXPECT_TRUE(HasContainerRelativeUnits("1cqmax"));
  EXPECT_TRUE(HasContainerRelativeUnits("calc(1px + 1cqw)"));
  EXPECT_TRUE(HasContainerRelativeUnits("min(1px, 1cqw)"));

  EXPECT_FALSE(HasContainerRelativeUnits("1px"));
  EXPECT_FALSE(HasContainerRelativeUnits("1em"));
  EXPECT_FALSE(HasContainerRelativeUnits("1vh"));
  EXPECT_FALSE(HasContainerRelativeUnits("1svh"));
  EXPECT_FALSE(HasContainerRelativeUnits("calc(1px + 1px)"));
  EXPECT_FALSE(HasContainerRelativeUnits("calc(1px + 1em)"));
  EXPECT_FALSE(HasContainerRelativeUnits("calc(1px + 1svh)"));
}

TEST_F(CSSPrimitiveValueTest, HasStaticViewportUnits) {
  // v*
  EXPECT_TRUE(HasStaticViewportUnits("1vw"));
  EXPECT_TRUE(HasStaticViewportUnits("1vh"));
  EXPECT_TRUE(HasStaticViewportUnits("1vi"));
  EXPECT_TRUE(HasStaticViewportUnits("1vb"));
  EXPECT_TRUE(HasStaticViewportUnits("1vmin"));
  EXPECT_TRUE(HasStaticViewportUnits("1vmax"));
  EXPECT_TRUE(HasStaticViewportUnits("calc(1px + 1vw)"));
  EXPECT_TRUE(HasStaticViewportUnits("min(1px, 1vw)"));
  EXPECT_FALSE(HasStaticViewportUnits("1px"));
  EXPECT_FALSE(HasStaticViewportUnits("1em"));
  EXPECT_FALSE(HasStaticViewportUnits("1dvh"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1px)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1em)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1dvh)"));

  // sv*
  EXPECT_TRUE(HasStaticViewportUnits("1svw"));
  EXPECT_TRUE(HasStaticViewportUnits("1svh"));
  EXPECT_TRUE(HasStaticViewportUnits("1svi"));
  EXPECT_TRUE(HasStaticViewportUnits("1svb"));
  EXPECT_TRUE(HasStaticViewportUnits("1svmin"));
  EXPECT_TRUE(HasStaticViewportUnits("1svmax"));
  EXPECT_TRUE(HasStaticViewportUnits("calc(1px + 1svw)"));
  EXPECT_TRUE(HasStaticViewportUnits("min(1px, 1svw)"));
  EXPECT_FALSE(HasStaticViewportUnits("1px"));
  EXPECT_FALSE(HasStaticViewportUnits("1em"));
  EXPECT_FALSE(HasStaticViewportUnits("1dvh"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1px)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1em)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1dvh)"));

  // lv*
  EXPECT_TRUE(HasStaticViewportUnits("1lvw"));
  EXPECT_TRUE(HasStaticViewportUnits("1lvh"));
  EXPECT_TRUE(HasStaticViewportUnits("1lvi"));
  EXPECT_TRUE(HasStaticViewportUnits("1lvb"));
  EXPECT_TRUE(HasStaticViewportUnits("1lvmin"));
  EXPECT_TRUE(HasStaticViewportUnits("1lvmax"));
  EXPECT_TRUE(HasStaticViewportUnits("calc(1px + 1lvw)"));
  EXPECT_TRUE(HasStaticViewportUnits("min(1px, 1lvw)"));
  EXPECT_FALSE(HasStaticViewportUnits("1px"));
  EXPECT_FALSE(HasStaticViewportUnits("1em"));
  EXPECT_FALSE(HasStaticViewportUnits("1dvh"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1px)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1em)"));
  EXPECT_FALSE(HasStaticViewportUnits("calc(1px + 1dvh)"));
}

TEST_F(CSSPrimitiveValueTest, HasDynamicViewportUnits) {
  // dv*
  EXPECT_TRUE(HasDynamicViewportUnits("1dvw"));
  EXPECT_TRUE(HasDynamicViewportUnits("1dvh"));
  EXPECT_TRUE(HasDynamicViewportUnits("1dvi"));
  EXPECT_TRUE(HasDynamicViewportUnits("1dvb"));
  EXPECT_TRUE(HasDynamicViewportUnits("1dvmin"));
  EXPECT_TRUE(HasDynamicViewportUnits("1dvmax"));
  EXPECT_TRUE(HasDynamicViewportUnits("calc(1px + 1dvw)"));
  EXPECT_TRUE(HasDynamicViewportUnits("min(1px, 1dvw)"));
  EXPECT_FALSE(HasDynamicViewportUnits("1px"));
  EXPECT_FALSE(HasDynamicViewportUnits("1em"));
  EXPECT_FALSE(HasDynamicViewportUnits("1svh"));
  EXPECT_FALSE(HasDynamicViewportUnits("calc(1px + 1px)"));
  EXPECT_FALSE(HasDynamicViewportUnits("calc(1px + 1em)"));
  EXPECT_FALSE(HasDynamicViewportUnits("calc(1px + 1svh)"));
}

TEST_F(CSSPrimitiveValueTest, ComputeMethodsWithLengthResolver) {
  {
    auto* pxs = CSSMathExpressionNumericLiteral::Create(
        12.0, CSSPrimitiveValue::UnitType::kPixels);
    auto* ems = CSSMathExpressionNumericLiteral::Create(
        1.0, CSSPrimitiveValue::UnitType::kEms);
    auto* subtraction = CSSMathExpressionOperation::CreateArithmeticOperation(
        pxs, ems, CSSMathOperator::kSubtract);
    auto* sign = CSSMathExpressionOperation::CreateSignRelatedFunction(
        {subtraction}, CSSValueID::kSign);
    auto* degs = CSSMathExpressionNumericLiteral::Create(
        10.0, CSSPrimitiveValue::UnitType::kDegrees);
    auto* expression = CSSMathExpressionOperation::CreateArithmeticOperation(
        sign, degs, CSSMathOperator::kMultiply);
    CSSPrimitiveValue* value = CSSMathFunctionValue::Create(expression);

    Font font;
    CSSToLengthConversionData length_resolver =
        CSSToLengthConversionData(/*element=*/nullptr);
    length_resolver.SetFontSizes(
        CSSToLengthConversionData::FontSizes(10.0f, 10.0f, &font, 1.0f));
    EXPECT_EQ(10.0, value->ComputeDegrees(length_resolver));
    EXPECT_EQ("calc(sign(-1em + 12px) * 10deg)", value->CustomCSSText());
  }
}

TEST_F(CSSPrimitiveValueTest, ContainerProgressTreeScope) {
  ScopedCSSProgressNotationForTest scoped_feature(true);
  const CSSValue* value = css_test_helpers::ParseValue(
      GetDocument(), "<number>",
      "container-progress(width of my-container from 0px to 1px)");
  ASSERT_TRUE(value);

  const CSSValue& scoped_value = value->EnsureScopedValue(&GetDocument());
  EXPECT_NE(value, &scoped_value);
  EXPECT_TRUE(scoped_value.IsScopedValue());
  // Don't crash:
  const CSSValue& scoped_value2 =
      scoped_value.EnsureScopedValue(&GetDocument());
  EXPECT_TRUE(scoped_value2.IsScopedValue());
  EXPECT_EQ(&scoped_value, &scoped_value2);
}

TEST_F(CSSPrimitiveValueTest, CSSPrimitiveValueOperations) {
  auto* numeric_percentage = CSSNumericLiteralValue::Create(
      10, CSSPrimitiveValue::UnitType::kPercentage);
  auto* numeric_number =
      CSSNumericLiteralValue::Create(10, CSSPrimitiveValue::UnitType::kNumber);
  auto* node_10_px = CSSMathExpressionNumericLiteral::Create(
      10, CSSPrimitiveValue::UnitType::kPixels);
  auto* node_20_em = CSSMathExpressionNumericLiteral::Create(
      20, CSSPrimitiveValue::UnitType::kEms);
  auto* node_subtract = CSSMathExpressionOperation::CreateArithmeticOperation(
      node_10_px, node_20_em, CSSMathOperator::kSubtract);
  auto* node_sign = CSSMathExpressionOperation::CreateSignRelatedFunction(
      {node_subtract}, CSSValueID::kSign);
  auto* function = CSSMathFunctionValue::Create(node_sign);
  EXPECT_EQ(function->Multiply(1, CSSPrimitiveValue::UnitType::kPixels)
                ->Add(10, CSSPrimitiveValue::UnitType::kPixels)
                ->CustomCSSText(),
            "calc(10px + sign(-20em + 10px) * 1px)");
  EXPECT_EQ(function->MultiplyBy(10, CSSPrimitiveValue::UnitType::kNumber)
                ->CustomCSSText(),
            "calc(10 * sign(-20em + 10px))");
  EXPECT_EQ(function->MultiplyBy(1, CSSPrimitiveValue::UnitType::kPixels)
                ->Subtract(*numeric_percentage)
                ->CustomCSSText(),
            "calc(-10% + 1px * sign(-20em + 10px))");
  EXPECT_EQ(function->Divide(20, CSSPrimitiveValue::UnitType::kNumber)
                ->CustomCSSText(),
            "calc(sign(-20em + 10px) / 20)");
  EXPECT_EQ(function->Subtract(*function)->CustomCSSText(),
            "calc(sign(-20em + 10px) - sign(-20em + 10px))");
  EXPECT_EQ(
      numeric_percentage->SubtractFrom(10, CSSPrimitiveValue::UnitType::kPixels)
          ->CustomCSSText(),
      "calc(-10% + 10px)");
  EXPECT_EQ(numeric_number->Subtract(10, CSSPrimitiveValue::UnitType::kNumber)
                ->CustomCSSText(),
            "0");
}

TEST_F(CSSPrimitiveValueTest, ComputeValueToCanonicalUnit) {
  CSSNumericLiteralValue* numeric_percentage = CSSNumericLiteralValue::Create(
      10, CSSPrimitiveValue::UnitType::kPercentage);
  CSSMathExpressionNode* node_20_px = CSSMathExpressionNumericLiteral::Create(
      20, CSSPrimitiveValue::UnitType::kPixels);
  CSSMathExpressionNode* node_2_em = CSSMathExpressionNumericLiteral::Create(
      2, CSSPrimitiveValue::UnitType::kEms);
  CSSMathExpressionNode* node_sub =
      CSSMathExpressionOperation::CreateArithmeticOperation(
          node_20_px, node_2_em, CSSMathOperator::kSubtract);
  auto* function = CSSMathFunctionValue::Create(node_sub);

  Font font;
  CSSToLengthConversionData length_resolver(/*element=*/nullptr);
  length_resolver.SetFontSizes(
      CSSToLengthConversionData::FontSizes(10.0f, 10.0f, &font, 1.0f));

  EXPECT_EQ(function->ComputeValueInCanonicalUnit(length_resolver), 0);
  EXPECT_EQ(numeric_percentage->ComputeValueInCanonicalUnit(length_resolver),
            10);
}

}  // namespace
}  // namespace blink
```