Response:
Let's break down the thought process to analyze the given C++ test file.

**1. Understanding the Goal:**

The core request is to understand the functionality of `css_math_expression_node_test.cc`. This immediately suggests it's a test file for something related to CSS math expressions within the Blink rendering engine.

**2. Initial Code Scan (Keywords and Structure):**

I'll quickly scan the code for important keywords and structural elements:

* **`#include` directives:** These tell us the dependencies. Key includes are:
    * `"third_party/blink/renderer/core/css/css_math_expression_node.h"`: This is the primary header being tested. So, the file is about testing the `CSSMathExpressionNode` class.
    * `"testing/gtest/include/gtest/gtest.h"`:  This confirms it's using Google Test for unit testing.
    * Other CSS-related headers (`css_length_resolver.h`, `css_math_operator.h`, etc.): These indicate the context of `CSSMathExpressionNode` – it deals with CSS values, lengths, and operators.
    * `"third_party/blink/renderer/platform/geometry/calculation_expression_node.h"`: This suggests a related concept of `CalculationExpressionNode`, likely a more abstract representation of the math expression.

* **`namespace blink { ... }`:** This confirms it's part of the Blink rendering engine.

* **`TEST(...)` macros:**  These are the actual test cases. Scanning the names of these tests provides a high-level overview of what's being tested:
    * `AccumulatePixelsAndPercent`
    * `RefCount`
    * `AddToLengthUnitValues`
    * `CSSLengthArrayUnits`
    * `TestParseDeeplyNestedExpression`
    * `TestSteppedValueFunctions`
    * `TestSteppedValueFunctionsToCalculationExpression`
    * `TestSteppedValueFunctionsSerialization`
    * `TestExponentialFunctions`
    * `TestExponentialFunctionsSerialization`
    * `TestExponentialFunctionsToCalculationExpression`
    * `IdentifierLiteralConversion`
    * `ColorChannelKeywordConversion`
    * `TestProgressNotation`
    * `TestProgressNotationComplex`
    * `TestInvalidProgressNotation`
    * `TestFunctionsWithNumberReturn`
    * `TestColorChannelExpressionWithSubstitution`
    * `TestColorChannelExpressionWithInvalidChannelName`
    * `TestColorChannelExpressionWithoutSubstitution`

**3. Deeper Dive into Test Cases (Connecting to CSS/JS/HTML):**

Now, I'll look at specific test cases and connect them to web technologies:

* **`AccumulatePixelsAndPercent`:** This test seems to focus on converting CSS math expressions into a representation of pixels and percentages. This is directly relevant to CSS layout and sizing, where values can be specified in these units. *Example:*  `calc(10px + 20%)` in CSS.

* **`RefCount`:**  This is about memory management, specifically reference counting, a common technique in C++. It ensures that the `CalculationValue` object is properly deallocated. While not directly visible in HTML/CSS/JS, it's crucial for performance and stability.

* **`AddToLengthUnitValues` and `CSSLengthArrayUnits`:** These tests deal with parsing and accumulating different CSS length units (px, %, em, etc.) within a math expression. This directly relates to how CSS properties like `width`, `margin`, `padding` can use `calc()` with different units. *Example:* `width: calc(10px + 2em);`

* **`TestParseDeeplyNestedExpression`:** This test checks how the parser handles complex, nested `calc()`, `min()`, `max()`, and `clamp()` functions. This is important because CSS allows for such nesting. *Example:* `width: calc(10px + calc(20px - 5px));`

* **`TestSteppedValueFunctions` (round, mod, rem):** These tests focus on the specific CSS math functions that perform rounding or modulo operations. These are used for more advanced styling calculations. *Example:* `width: round(up, 105px, 10px);`

* **`TestExponentialFunctions` (hypot, log, sqrt, exp, pow):**  These tests cover more advanced mathematical functions available in CSS `calc()`. *Example:* `font-size: calc(sqrt(16) * 1px);`

* **`IdentifierLiteralConversion` and `ColorChannelKeywordConversion`:** These relate to more specialized aspects of CSS math expressions, such as using identifiers or color channel keywords within calculations (e.g., in upcoming CSS color functions).

* **`TestProgressNotation`:** This tests a specific function, likely for animation or gradient purposes, where you can calculate a value based on its position between two points.

* **`TestFunctionsWithNumberReturn`:** This checks functions like `sign()` that return a unitless number, which can be used in more complex calculations.

* **`TestColorChannelExpression...`:** These tests deal with using color channel keywords (like `h`, `s`, `l`, `alpha`) directly in math expressions, a feature related to CSS Color Level 5. *Example:*  `color: hsl(calc(h + 30), s, l);`

**4. Logic Inference and Examples:**

For each test group, I try to infer the underlying logic being tested. For example, in `AccumulatePixelsAndPercent`, the assumption is that the `ToCalculationExpression` method should correctly extract pixel and percentage components. I then create simple CSS examples to illustrate how this functionality is used.

**5. User/Programming Errors:**

I consider common mistakes users or developers might make when using these CSS features. For instance, mixing incompatible units without `calc()` or deeply nesting expressions beyond the allowed limit.

**6. Debugging Clues (User Operations):**

I think about how a user's actions in a web browser could lead to this code being executed. This involves tracing back from the rendered output to the CSS parsing and style calculation stages. For example, a user setting a complex `calc()` value in their CSS will trigger the parsing logic tested here.

**7. Structuring the Output:**

Finally, I organize the information into the requested categories: functionality, relationship to web technologies, logic inference, usage errors, and debugging clues. This makes the analysis clear and easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe some tests are purely internal. **Correction:** While some details are internal (like ref-counting), the *purpose* of almost all these tests ultimately ties back to correctly processing CSS as defined by web standards.

* **Realization:** The `CalculationExpressionNode` seems like an intermediate representation. **Refinement:**  Explain its role in the conversion process.

* **Overly focused on individual tests:** **Correction:**  Group related tests thematically to provide a more coherent overview of the file's purpose.

By following this kind of systematic approach, combining code analysis with knowledge of web technologies, I can effectively break down the functionality of a complex source code file like this one.
这个文件 `css_math_expression_node_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `CSSMathExpressionNode` 类的功能。 `CSSMathExpressionNode` 用于表示 CSS 数学表达式（例如 `calc()`, `min()`, `max()` 等）的语法树节点。

以下是该文件的功能列表：

**核心功能：测试 `CSSMathExpressionNode` 及其相关类的各种能力**

1. **解析和创建 CSS 数学表达式节点:**
   - 测试能否正确解析各种 CSS 数学表达式字符串，并创建相应的 `CSSMathExpressionNode` 对象。
   - 测试不同类型的数学函数（`calc`, `min`, `max`, `clamp`, `round`, `mod`, `rem`, `hypot`, `log`, `sqrt`, `exp`, `pow`, `progress` 等）的解析。
   - 测试嵌套的数学表达式的解析深度限制。
   - 测试带有单位的数值的解析（例如 `10px`, `20%`, `1em`）。
   - 测试标识符和颜色通道关键字在数学表达式中的解析。

2. **转换为 `CalculationExpressionNode`:**
   - 测试 `CSSMathExpressionNode` 对象能否正确转换为 `CalculationExpressionNode` 对象。 `CalculationExpressionNode` 是一个更通用的、用于实际计算的表达式节点。
   - 测试转换过程中像素和百分比的累积和处理。

3. **计算和求值:**
   - 测试 `CSSMathExpressionNode` 或其转换后的 `CalculationExpressionNode` 能否正确地求值。
   - 测试在有缩放因子 (zoom) 的情况下，像素值的正确计算。
   - 测试 `progress()` 函数的计算逻辑。

4. **序列化:**
   - 测试 `CSSMathExpressionNode` 对象能否正确地序列化回 CSS 文本表示。

5. **引用计数:**
   - 测试 `CalculationValue` 对象的引用计数机制，确保内存管理的正确性。

6. **单位处理:**
   - 测试 `CSSMathExpressionNode` 能否正确处理各种 CSS 长度单位，以及单位的累积。
   - 测试支持和不支持的 CSS 单位。

7. **颜色通道表达式:**
   - 测试在数学表达式中使用颜色通道关键字（例如 `h`, `s`, `l`, `alpha`）。
   - 测试在有和没有颜色通道值替换的情况下，颜色通道表达式的解析和求值。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 **CSS** 的功能，特别是 CSS 数学表达式。 这些表达式在 CSS 中用于动态计算属性值。

* **CSS `calc()` 函数:**  这是最核心的关联。 `calc()` 允许在 CSS 中执行简单的数学运算。 例如：
   ```css
   .element {
     width: calc(100% - 20px);
     font-size: calc(1em + 2px);
   }
   ```
   该测试文件会测试 Blink 引擎是否能正确解析和计算这些 `calc()` 表达式。

* **CSS `min()`, `max()`, `clamp()` 函数:** 这些函数允许选择一组值中的最小值、最大值或将值限制在一个范围内。 例如：
   ```css
   .element {
     width: min(50%, 300px);
     font-size: clamp(16px, 2vw, 24px);
   }
   ```
   测试文件会验证这些函数的解析和计算。

* **CSS `round()`, `mod()`, `rem()` 函数:** 这些是 CSS Math Functions Level 4 中引入的步进值函数，用于对数值进行舍入或取模运算。 例如：
   ```css
   .element {
     width: round(up, 105px, 10px); /* 向上舍入到最接近 10px 的倍数 */
   }
   ```
   测试文件会测试这些函数的解析和求值。

* **CSS `hypot()`, `log()`, `sqrt()`, `exp()`, `pow()` 函数:**  这些是 CSS Math Functions Level 4 中引入的指数函数。 例如：
   ```css
   .element {
     font-size: calc(sqrt(25) * 1px);
   }
   ```
   测试文件会测试这些函数的解析和求值。

* **CSS 自定义属性（CSS Variables）和 `env()`:** 虽然这个测试文件本身没有直接测试自定义属性或 `env()`，但 `CSSMathExpressionNode` 也负责处理包含这些特性的表达式。例如： `calc(var(--my-width) + 10px)`.

* **CSS 颜色函数和颜色通道:**  较新的 CSS 颜色函数允许访问和操作颜色的各个通道。例如： `hsl(calc(h + 30), s, l)`. 该测试文件包含了对在 `calc()` 中使用颜色通道关键字的测试。

**与 JavaScript 的关系：**

JavaScript 可以通过 DOM API 获取和修改元素的样式，这些样式可能包含 CSS 数学表达式。 浏览器需要正确地将 CSS 解析并应用到渲染过程中。 例如，如果 JavaScript 设置了元素的 `width` 属性为 `calc(100% - 50px)`，Blink 引擎会使用到 `CSSMathExpressionNode` 来处理这个值。

**与 HTML 的关系：**

HTML 结构定义了文档的内容，而 CSS 负责样式。 CSS 数学表达式用于设置 HTML 元素的样式属性。 例如，一个 `<div>` 元素的宽度可以通过 CSS 中的 `calc()` 来动态计算。

**逻辑推理和假设输入与输出：**

**假设输入:**  CSS 属性值字符串 `"calc(10px + 20px)"`

**逻辑推理:**  `CSSMathExpressionNode` 的解析器会将这个字符串解析成一个加法运算节点，包含两个子节点，分别表示 `10px` 和 `20px`。  然后，转换器会将这个节点树转换为 `CalculationExpressionNode` 树。  求值器会计算这个表达式，得到 `30px`。

**预期输出:**  测试会断言解析过程成功，创建了正确的节点类型，并且求值结果为 `30`（在转换为特定单位后）。

**假设输入:**  CSS 属性值字符串 `"min(100px, 50%)"`，并且在特定的上下文（例如父元素的宽度）下，`50%` 相当于 `200px`。

**逻辑推理:**  `CSSMathExpressionNode` 会解析 `min()` 函数及其参数。求值器会比较 `100px` 和 `200px`（`50%` 的计算结果），并选择最小值。

**预期输出:**  测试会断言求值结果为 `100px` (或其数值表示)。

**用户或编程常见的使用错误及举例说明：**

1. **单位不兼容:** 在 `calc()` 中混合不兼容的单位而没有进行单位转换。
   ```css
   .element {
     width: calc(100px + 50%); /* 这种写法可能需要上下文信息才能正确计算 */
   }
   ```
   `CSSMathExpressionNode` 的相关逻辑会处理这种情况，可能需要依赖于上下文信息（例如父元素的尺寸）。

2. **语法错误:**  `calc()` 表达式中存在语法错误。
   ```css
   .element {
     width: calc(100px +  50); /* 缺少单位 */
   }
   ```
   解析器会检测到错误，并可能导致解析失败或得到错误的结果。 测试会验证这些错误处理情况。

3. **除零错误:** 在 `calc()` 中进行除零运算。
   ```css
   .element {
     width: calc(100px / 0);
   }
   ```
   `CSSMathExpressionNode` 的求值逻辑需要处理这种异常情况，通常会返回 `infinity` 或特定的错误值。

4. **嵌套深度过深:**  `calc()` 或其他数学函数嵌套层级过深，超出浏览器的限制。
   ```css
   .element {
     width: calc(1px + calc(1px + calc(1px + ...))); // 嵌套很多层
   }
   ```
   测试文件中的 `TestParseDeeplyNestedExpression` 会模拟这种情况，并验证解析器是否能正确处理嵌套深度限制。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 HTML, CSS 或 JavaScript 代码:** 用户在他们的网页代码中使用了 CSS 数学表达式，例如在 CSS 样式表中设置了 `width: calc(100% - 20px);` 或者通过 JavaScript 修改了元素的 style 属性。

2. **浏览器加载和解析 HTML:** 当浏览器加载 HTML 页面时，会解析 HTML 结构。

3. **浏览器解析 CSS:** 浏览器会解析 CSS 样式表（包括外部 CSS 文件、`<style>` 标签内的 CSS 和行内样式）。  在解析过程中，如果遇到包含数学表达式的 CSS 属性值，CSS 解析器会识别出来。

4. **创建 `CSSMathExpressionNode`:**  Blink 引擎的 CSS 解析器会调用相关的代码来将数学表达式字符串转换成 `CSSMathExpressionNode` 对象。 这个过程中会使用到 `css_math_expression_node_test.cc` 所测试的解析逻辑。

5. **样式计算 (Style Calculation):**  接下来，浏览器会进行样式计算，确定每个元素最终的样式属性值。 对于包含数学表达式的属性，会调用 `CSSMathExpressionNode` 的求值方法，或者将其转换为 `CalculationExpressionNode` 进行求值。

6. **布局 (Layout):**  计算出的样式信息会被用于布局阶段，确定元素在页面上的位置和尺寸。 例如，`width: calc(100% - 20px)` 的计算结果会影响元素的最终宽度。

7. **渲染 (Rendering):**  最后，浏览器会根据布局信息将页面渲染到屏幕上。

**作为调试线索:**

如果开发者在使用 CSS 数学表达式时遇到问题（例如，计算结果不符合预期，或者出现解析错误），可以按照以下步骤进行调试，而 `css_math_expression_node_test.cc` 的测试用例可以作为参考：

* **检查 CSS 语法:**  确保 `calc()`, `min()`, `max()` 等函数的语法正确，单位使用兼容。
* **查看开发者工具:**  浏览器的开发者工具（例如 Chrome DevTools）可以查看元素的计算样式 (Computed Style)，这会显示数学表达式的最终计算结果。
* **逐步简化表达式:**  如果表达式很复杂，可以尝试逐步简化，找到导致问题的部分。
* **参考测试用例:**  如果怀疑是 Blink 引擎的解析或计算错误，可以查看 `css_math_expression_node_test.cc` 中是否有类似的测试用例，了解 Blink 引擎是如何处理特定情况的。  如果发现测试用例覆盖了预期的情况但实际结果不符，可能就是一个 Bug 的线索。
* **断点调试 Blink 源码:**  对于更深入的调试，可以下载 Blink 引擎的源码，并在 CSS 解析和样式计算相关的代码中设置断点，跟踪代码的执行流程，查看 `CSSMathExpressionNode` 的创建和求值过程。

总而言之，`css_math_expression_node_test.cc` 是确保 Blink 引擎能够正确解析、表示和计算 CSS 数学表达式的关键组成部分，直接影响着网页的最终渲染效果。理解这个文件的功能有助于开发者理解 CSS 数学表达式的工作原理，并为调试相关问题提供有价值的线索。

Prompt: 
```
这是目录为blink/renderer/core/css/css_math_expression_node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/css_math_expression_node.h"

#include <algorithm>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_length_resolver.h"
#include "third_party/blink/renderer/core/css/css_math_operator.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/geometry/calculation_expression_node.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

void PrintTo(const CSSLengthArray& length_array, ::std::ostream* os) {
  for (double x : length_array.values) {
    *os << x << ' ';
  }
}

namespace {

void TestAccumulatePixelsAndPercent(
    const CSSToLengthConversionData& conversion_data,
    CSSMathExpressionNode* expression,
    float expected_pixels,
    float expected_percent) {
  scoped_refptr<const CalculationExpressionNode> value =
      expression->ToCalculationExpression(conversion_data);
  EXPECT_TRUE(value->IsPixelsAndPercent());
  EXPECT_EQ(expected_pixels,
            To<CalculationExpressionPixelsAndPercentNode>(*value).Pixels());
  EXPECT_EQ(expected_percent,
            To<CalculationExpressionPixelsAndPercentNode>(*value).Percent());

  std::optional<PixelsAndPercent> pixels_and_percent =
      expression->ToPixelsAndPercent(conversion_data);
  EXPECT_TRUE(pixels_and_percent.has_value());
  EXPECT_EQ(expected_pixels, pixels_and_percent->pixels);
  EXPECT_EQ(expected_percent, pixels_and_percent->percent);
}

bool AccumulateLengthArray(String text, CSSLengthArray& length_array) {
  auto* property_set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  property_set->ParseAndSetProperty(CSSPropertyID::kLeft, text,
                                    /* important */ false,
                                    SecureContextMode::kInsecureContext);
  return To<CSSPrimitiveValue>(
             property_set->GetPropertyCSSValue(CSSPropertyID::kLeft))
      ->AccumulateLengthArray(length_array);
}

CSSLengthArray& SetLengthArray(String text, CSSLengthArray& length_array) {
  std::fill(length_array.values.begin(), length_array.values.end(), 0);
  AccumulateLengthArray(text, length_array);
  return length_array;
}

TEST(CSSCalculationValue, AccumulatePixelsAndPercent) {
  ComputedStyleBuilder builder(*ComputedStyle::GetInitialStyleSingleton());
  builder.SetEffectiveZoom(5);
  const ComputedStyle* style = builder.TakeStyle();
  CSSToLengthConversionData::Flags ignored_flags = 0;
  CSSToLengthConversionData conversion_data(
      *style, style, style, CSSToLengthConversionData::ViewportSize(nullptr),
      CSSToLengthConversionData::ContainerSizes(),
      CSSToLengthConversionData::AnchorData(), style->EffectiveZoom(),
      ignored_flags, /*element=*/nullptr);

  TestAccumulatePixelsAndPercent(
      conversion_data,
      CSSMathExpressionNumericLiteral::Create(CSSNumericLiteralValue::Create(
          10, CSSPrimitiveValue::UnitType::kPixels)),
      50, 0);

  TestAccumulatePixelsAndPercent(
      conversion_data,
      CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionNumericLiteral::Create(
              CSSNumericLiteralValue::Create(
                  10, CSSPrimitiveValue::UnitType::kPixels)),
          CSSMathExpressionNumericLiteral::Create(
              CSSNumericLiteralValue::Create(
                  20, CSSPrimitiveValue::UnitType::kPixels)),
          CSSMathOperator::kAdd),
      150, 0);

  TestAccumulatePixelsAndPercent(
      conversion_data,
      CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionNumericLiteral::Create(
              CSSNumericLiteralValue::Create(
                  1, CSSPrimitiveValue::UnitType::kInches)),
          CSSMathExpressionNumericLiteral::Create(
              CSSNumericLiteralValue::Create(
                  2, CSSPrimitiveValue::UnitType::kNumber)),
          CSSMathOperator::kMultiply),
      960, 0);

  TestAccumulatePixelsAndPercent(
      conversion_data,
      CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionOperation::CreateArithmeticOperation(
              CSSMathExpressionNumericLiteral::Create(
                  CSSNumericLiteralValue::Create(
                      50, CSSPrimitiveValue::UnitType::kPixels)),
              CSSMathExpressionNumericLiteral::Create(
                  CSSNumericLiteralValue::Create(
                      0.25, CSSPrimitiveValue::UnitType::kNumber)),
              CSSMathOperator::kMultiply),
          CSSMathExpressionOperation::CreateArithmeticOperation(
              CSSMathExpressionNumericLiteral::Create(
                  CSSNumericLiteralValue::Create(
                      20, CSSPrimitiveValue::UnitType::kPixels)),
              CSSMathExpressionNumericLiteral::Create(
                  CSSNumericLiteralValue::Create(
                      40, CSSPrimitiveValue::UnitType::kPercentage)),
              CSSMathOperator::kSubtract),
          CSSMathOperator::kSubtract),
      -37.5, 40);
}

TEST(CSSCalculationValue, RefCount) {
  scoped_refptr<const CalculationValue> calc = CalculationValue::Create(
      PixelsAndPercent(1, 2, /*has_explicit_pixels=*/true,
                       /*has_explicit_percent=*/true),
      Length::ValueRange::kAll);

  // FIXME: Test the Length construction without using the ref count value.

  EXPECT_TRUE(calc->HasOneRef());
  {
    Length length_a(calc);
    EXPECT_FALSE(calc->HasOneRef());

    Length length_b;
    length_b = length_a;

    Length length_c(calc);
    length_c = length_a;

    Length length_d(CalculationValue::Create(
        PixelsAndPercent(1, 2, /*has_explicit_pixels=*/true,
                         /*has_explicit_percent=*/true),
        Length::ValueRange::kAll));
    length_d = length_a;
  }
  EXPECT_TRUE(calc->HasOneRef());
}

TEST(CSSCalculationValue, AddToLengthUnitValues) {
  CSSLengthArray expectation, actual;
  EXPECT_EQ(expectation.values, SetLengthArray("0", actual).values);

  expectation.values.at(CSSPrimitiveValue::kUnitTypePixels) = 10;
  EXPECT_EQ(expectation.values, SetLengthArray("10px", actual).values);

  expectation.values.at(CSSPrimitiveValue::kUnitTypePixels) = 0;
  expectation.values.at(CSSPrimitiveValue::kUnitTypePercentage) = 20;
  EXPECT_EQ(expectation.values, SetLengthArray("20%", actual).values);

  expectation.values.at(CSSPrimitiveValue::kUnitTypePixels) = 30;
  expectation.values.at(CSSPrimitiveValue::kUnitTypePercentage) = -40;
  EXPECT_EQ(expectation.values,
            SetLengthArray("calc(30px - 40%)", actual).values);

  expectation.values.at(CSSPrimitiveValue::kUnitTypePixels) = 90;
  expectation.values.at(CSSPrimitiveValue::kUnitTypePercentage) = 10;
  EXPECT_EQ(expectation.values,
            SetLengthArray("calc(1in + 10% - 6px)", actual).values);

  expectation.values.at(CSSPrimitiveValue::kUnitTypePixels) = 15;
  expectation.values.at(CSSPrimitiveValue::kUnitTypeFontSize) = 20;
  expectation.values.at(CSSPrimitiveValue::kUnitTypePercentage) = -40;
  EXPECT_EQ(
      expectation.values,
      SetLengthArray("calc((1 * 2) * (5px + 20em / 2) - 80% / (3 - 1) + 5px)",
                     actual)
          .values);
}

TEST(CSSCalculationValue, CSSLengthArrayUnits) {
  CSSLengthArray unused;

  // Supported units:
  EXPECT_TRUE(AccumulateLengthArray("1px", unused));
  EXPECT_TRUE(AccumulateLengthArray("1%", unused));
  EXPECT_TRUE(AccumulateLengthArray("1em", unused));
  EXPECT_TRUE(AccumulateLengthArray("1ex", unused));
  EXPECT_TRUE(AccumulateLengthArray("1rem", unused));
  EXPECT_TRUE(AccumulateLengthArray("1ch", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vw", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vh", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vi", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vb", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vmin", unused));
  EXPECT_TRUE(AccumulateLengthArray("1vmax", unused));

  // Unsupported units:
  EXPECT_FALSE(AccumulateLengthArray("1svw", unused));
  EXPECT_FALSE(AccumulateLengthArray("1svh", unused));
  EXPECT_FALSE(AccumulateLengthArray("1svi", unused));
  EXPECT_FALSE(AccumulateLengthArray("1svb", unused));
  EXPECT_FALSE(AccumulateLengthArray("1svmin", unused));
  EXPECT_FALSE(AccumulateLengthArray("1svmax", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvw", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvh", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvi", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvb", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvmin", unused));
  EXPECT_FALSE(AccumulateLengthArray("1lvmax", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvw", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvh", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvi", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvb", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvmin", unused));
  EXPECT_FALSE(AccumulateLengthArray("1dvmax", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqw", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqh", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqi", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqb", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqmin", unused));
  EXPECT_FALSE(AccumulateLengthArray("1cqmax", unused));

  EXPECT_TRUE(AccumulateLengthArray("calc(1em + calc(1ex + 1px))", unused));
  EXPECT_FALSE(AccumulateLengthArray("calc(1dvh + calc(1ex + 1px))", unused));
  EXPECT_FALSE(AccumulateLengthArray("calc(1em + calc(1dvh + 1px))", unused));
  EXPECT_FALSE(AccumulateLengthArray("calc(1em + calc(1ex + 1dvh))", unused));
}

using Flag = CSSMathExpressionNode::Flag;
using Flags = CSSMathExpressionNode::Flags;

TEST(CSSMathExpressionNode, TestParseDeeplyNestedExpression) {
  enum Kind {
    kCalc,
    kMin,
    kMax,
    kClamp,
  };

  // Ref: https://bugs.chromium.org/p/chromium/issues/detail?id=1211283
  const struct TestCase {
    const Kind kind;
    const int nest_num;
    const bool expected;
  } test_cases[] = {
      {kCalc, 1, true},
      {kCalc, 10, true},
      {kCalc, kMaxExpressionDepth - 1, true},
      {kCalc, kMaxExpressionDepth, false},
      {kCalc, kMaxExpressionDepth + 1, false},
      {kMin, 1, true},
      {kMin, 10, true},
      {kMin, kMaxExpressionDepth - 1, true},
      {kMin, kMaxExpressionDepth, false},
      {kMin, kMaxExpressionDepth + 1, false},
      {kMax, 1, true},
      {kMax, 10, true},
      {kMax, kMaxExpressionDepth - 1, true},
      {kMax, kMaxExpressionDepth, false},
      {kMax, kMaxExpressionDepth + 1, false},
      {kClamp, 1, true},
      {kClamp, 10, true},
      {kClamp, kMaxExpressionDepth - 1, true},
      {kClamp, kMaxExpressionDepth, false},
      {kClamp, kMaxExpressionDepth + 1, false},
  };

  for (const auto& test_case : test_cases) {
    std::stringstream ss;

    // Make nested expression as follows:
    // calc(1px + calc(1px + calc(1px)))
    // min(1px, 1px + min(1px, 1px + min(1px, 1px)))
    // max(1px, 1px + max(1px, 1px + max(1px, 1px)))
    // clamp(1px, 1px, 1px + clamp(1px, 1px, 1px + clamp(1px, 1px, 1px)))
    for (int i = 0; i < test_case.nest_num; i++) {
      if (i) {
        ss << " + ";
      }
      switch (test_case.kind) {
        case kCalc:
          ss << "calc(1px";
          break;
        case kMin:
          ss << "min(1px, 1px";
          break;
        case kMax:
          ss << "max(1px, 1px";
          break;
        case kClamp:
          ss << "clamp(1px, 1px, 1px";
          break;
      }
    }
    for (int i = 0; i < test_case.nest_num; i++) {
      ss << ")";
    }

    std::string str = ss.str();
    CSSParserTokenStream stream(str.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);

    if (test_case.expected) {
      ASSERT_TRUE(res);
      EXPECT_TRUE(!res->HasPercentage());
    } else {
      EXPECT_FALSE(res);
    }
  }
}

TEST(CSSMathExpressionNode, TestSteppedValueFunctions) {
  const struct TestCase {
    const std::string input;
    const double output;
  } test_cases[] = {
      {"round(10, 10)", 10.0f},
      {"calc(round(up, 101, 10))", 110.0f},
      {"calc(round(down, 106, 10))", 100.0f},
      {"mod(18,5)", 3.0f},
      {"rem(18,5)", 3.0f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_EQ(res->DoubleValue(), test_case.output);
    CSSToLengthConversionData resolver{/*element=*/nullptr};
    scoped_refptr<const CalculationExpressionNode> node =
        res->ToCalculationExpression(resolver);
    EXPECT_EQ(node->Evaluate(FLT_MAX, {}), test_case.output);
    EXPECT_TRUE(!res->HasPercentage());
  }
}

TEST(CSSMathExpressionNode, TestSteppedValueFunctionsToCalculationExpression) {
  const struct TestCase {
    const CSSMathOperator op;
    const double output;
  } test_cases[] = {
      {CSSMathOperator::kRoundNearest, 10}, {CSSMathOperator::kRoundUp, 10},
      {CSSMathOperator::kRoundDown, 10},    {CSSMathOperator::kRoundToZero, 10},
      {CSSMathOperator::kMod, 0},           {CSSMathOperator::kRem, 0}};

  for (const auto& test_case : test_cases) {
    CSSMathExpressionOperation::Operands operands{
        CSSMathExpressionNumericLiteral::Create(
            10, CSSPrimitiveValue::UnitType::kNumber),
        CSSMathExpressionNumericLiteral::Create(
            10, CSSPrimitiveValue::UnitType::kNumber)};
    const auto* operation = MakeGarbageCollected<CSSMathExpressionOperation>(
        kCalcNumber, std::move(operands), test_case.op);
    CSSToLengthConversionData resolver{/*element=*/nullptr};
    scoped_refptr<const CalculationExpressionNode> node =
        operation->ToCalculationExpression(resolver);
    EXPECT_EQ(node->Evaluate(FLT_MAX, {}), test_case.output);
    const CSSMathExpressionNode* css_node =
        CSSMathExpressionOperation::Create(*node);
    EXPECT_NE(css_node, nullptr);
  }
}

TEST(CSSMathExpressionNode, TestSteppedValueFunctionsSerialization) {
  const struct TestCase {
    const String input;
  } test_cases[] = {
      {"round(10%, 10%)"},       {"round(up, 10%, 10%)"},
      {"round(down, 10%, 10%)"}, {"round(to-zero, 10%, 10%)"},
      {"mod(10%, 10%)"},         {"rem(10%, 10%)"},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input);
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_EQ(res->CustomCSSText(), test_case.input);
  }
}

TEST(CSSMathExpressionNode, TestExponentialFunctions) {
  const struct TestCase {
    const std::string input;
    const double output;
  } test_cases[] = {
      {"hypot(3, 4)", 5.0f}, {"log(100, 10)", 2.0f}, {"sqrt(144)", 12.0f},
      {"exp(0)", 1.0f},      {"pow(2, 2)", 4.0f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_EQ(res->DoubleValue(), test_case.output);
    CSSToLengthConversionData resolver{/*element=*/nullptr};
    scoped_refptr<const CalculationExpressionNode> node =
        res->ToCalculationExpression(resolver);
    EXPECT_EQ(node->Evaluate(FLT_MAX, {}), test_case.output);
    EXPECT_TRUE(!res->HasPercentage());
  }
}

TEST(CSSMathExpressionNode, TestExponentialFunctionsSerialization) {
  const struct TestCase {
    const String input;
    const bool can_be_simplified_with_conversion_data;
  } test_cases[] = {
      {"hypot(3em, 4rem)", true},
      {"hypot(3%, 4%)", false},
      {"hypot(hypot(3%, 4%), 5em)", false},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input);
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_EQ(res->CustomCSSText(), test_case.input);
    EXPECT_EQ(!res->HasPercentage(),
              test_case.can_be_simplified_with_conversion_data);
  }
}

TEST(CSSMathExpressionNode, TestExponentialFunctionsToCalculationExpression) {
  const struct TestCase {
    const CSSMathOperator op;
    const double output;
  } test_cases[] = {{CSSMathOperator::kHypot, 5.0f}};

  for (const auto& test_case : test_cases) {
    CSSMathExpressionOperation::Operands operands{
        CSSMathExpressionNumericLiteral::Create(
            3.0f, CSSPrimitiveValue::UnitType::kNumber),
        CSSMathExpressionNumericLiteral::Create(
            4.0f, CSSPrimitiveValue::UnitType::kNumber)};
    const auto* operation = MakeGarbageCollected<CSSMathExpressionOperation>(
        kCalcNumber, std::move(operands), test_case.op);
    CSSToLengthConversionData resolver{/*element=*/nullptr};
    scoped_refptr<const CalculationExpressionNode> node =
        operation->ToCalculationExpression(resolver);
    EXPECT_EQ(node->Evaluate(FLT_MAX, {}), test_case.output);
    const CSSMathExpressionNode* css_node =
        CSSMathExpressionOperation::Create(*node);
    EXPECT_NE(css_node, nullptr);
  }
}

TEST(CSSMathExpressionNode, IdentifierLiteralConversion) {
  const CSSMathExpressionIdentifierLiteral* css_node =
      CSSMathExpressionIdentifierLiteral::Create(AtomicString("test"));
  EXPECT_TRUE(css_node->IsIdentifierLiteral());
  EXPECT_EQ(css_node->Category(), kCalcIdent);
  EXPECT_EQ(css_node->GetValue(), AtomicString("test"));
  scoped_refptr<const CalculationExpressionNode> calc_node =
      css_node->ToCalculationExpression(
          CSSToLengthConversionData(/*element=*/nullptr));
  EXPECT_TRUE(calc_node->IsIdentifier());
  EXPECT_EQ(To<CalculationExpressionIdentifierNode>(*calc_node).Value(),
            AtomicString("test"));
  auto* node = CSSMathExpressionNode::Create(*calc_node);
  EXPECT_TRUE(node->IsIdentifierLiteral());
  EXPECT_EQ(To<CSSMathExpressionIdentifierLiteral>(node)->GetValue(),
            AtomicString("test"));
}

TEST(CSSMathExpressionNode, ColorChannelKeywordConversion) {
  const CSSMathExpressionKeywordLiteral* css_node =
      CSSMathExpressionKeywordLiteral::Create(
          CSSValueID::kAlpha,
          CSSMathExpressionKeywordLiteral::Context::kColorChannel);
  EXPECT_TRUE(css_node->IsKeywordLiteral());
  EXPECT_EQ(css_node->Category(), kCalcNumber);
  EXPECT_EQ(css_node->GetValue(), CSSValueID::kAlpha);
  scoped_refptr<const CalculationExpressionNode> calc_node =
      css_node->ToCalculationExpression(
          CSSToLengthConversionData(/*element=*/nullptr));
  EXPECT_TRUE(calc_node->IsColorChannelKeyword());
  EXPECT_EQ(
      To<CalculationExpressionColorChannelKeywordNode>(*calc_node).Value(),
      ColorChannelKeyword::kAlpha);
  auto* node = CSSMathExpressionNode::Create(*calc_node);
  EXPECT_TRUE(node->IsKeywordLiteral());
  EXPECT_EQ(To<CSSMathExpressionKeywordLiteral>(node)->GetValue(),
            CSSValueID::kAlpha);
}

TEST(CSSMathExpressionNode, TestProgressNotation) {
  const struct TestCase {
    const std::string input;
    const double output;
  } test_cases[] = {
      {"progress(1px from 0px to 4px)", 0.25f},
      {"progress(10deg from 0deg to 10deg)", 1.0f},
      {"progress(progress(10% from 0% to 40%) * 1px from 0.5px to 1px)", -0.5f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_EQ(res->DoubleValue(), test_case.output);
    CSSToLengthConversionData resolver(/*element=*/nullptr);
    scoped_refptr<const CalculationExpressionNode> node =
        res->ToCalculationExpression(resolver);
    EXPECT_EQ(node->Evaluate(FLT_MAX, {}), test_case.output);
  }
}

TEST(CSSMathExpressionNode, TestProgressNotationComplex) {
  const struct TestCase {
    const std::string input;
    const double output;
  } test_cases[] = {
      {"progress(abs(5%) from hypot(3%, 4%) to 10%)", 0.0f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_TRUE(res);
    EXPECT_TRUE(res->IsOperation());
    CSSToLengthConversionData resolver(/*element=*/nullptr);
    scoped_refptr<const CalculationExpressionNode> node =
        res->ToCalculationExpression(resolver);
    // Very close to 0.0f, but not exactly 0.0f for unknown reason.
    EXPECT_NEAR(node->Evaluate(FLT_MAX, {}), test_case.output, 0.001);
  }
}

TEST(CSSMathExpressionNode, TestInvalidProgressNotation) {
  const std::string test_cases[] = {
      "progress(1% from 0px to 4px)",
      "progress(1px, 0px, 4px)",
      "progress(10deg from 0 to 10deg)",
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.c_str());
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* res = CSSMathExpressionNode::ParseMathFunction(
        CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
        kCSSAnchorQueryTypesNone);
    EXPECT_FALSE(res);
  }
}

TEST(CSSMathExpressionNode, TestFunctionsWithNumberReturn) {
  const struct TestCase {
    const String input;
    const CalculationResultCategory category;
    const double output;
  } test_cases[] = {
      {"10 * sign(10%)", CalculationResultCategory::kCalcNumber, 10.0},
      {"10px * sign(10%)", CalculationResultCategory::kCalcLength, 10.0},
      {"10 + 2 * (1 + sign(10%))", CalculationResultCategory::kCalcNumber,
       14.0},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input);
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* css_node =
        CSSMathExpressionNode::ParseMathFunction(
            CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
            kCSSAnchorQueryTypesNone);
    EXPECT_EQ(css_node->CustomCSSText(), test_case.input);
    EXPECT_EQ(css_node->Category(), test_case.category);
    EXPECT_TRUE(css_node->IsOperation());
    scoped_refptr<const CalculationExpressionNode> calc_node =
        css_node->ToCalculationExpression(
            CSSToLengthConversionData(/*element=*/nullptr));
    EXPECT_TRUE(calc_node->IsOperation());
    EXPECT_EQ(calc_node->Evaluate(100.0, {}), test_case.output);
    css_node = CSSMathExpressionNode::Create(*calc_node);
    EXPECT_EQ(css_node->CustomCSSText(), test_case.input);
  }
}

TEST(CSSMathExpressionNode, TestColorChannelExpressionWithSubstitution) {
  const struct TestCase {
    const String input;
    const CalculationResultCategory category;
    const double output;
  } test_cases[] = {
      {"h / 2", CalculationResultCategory::kCalcNumber, 120.0f},
  };

  const CSSColorChannelMap color_channel_map = {
      {CSSValueID::kH, 240.0f},
      {CSSValueID::kS, 50.0f},
      {CSSValueID::kL, 75.0f},
      {CSSValueID::kAlpha, 1.0f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case.input);
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* css_node =
        CSSMathExpressionNode::ParseMathFunction(
            CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
            kCSSAnchorQueryTypesNone, color_channel_map);
    EXPECT_EQ(css_node->Category(), test_case.category);
    EXPECT_TRUE(css_node->IsNumericLiteral());
    scoped_refptr<const CalculationExpressionNode> calc_node =
        css_node->ToCalculationExpression(
            CSSToLengthConversionData(/*element=*/nullptr));
    EXPECT_TRUE(calc_node->IsNumber());
    EXPECT_EQ(calc_node->Evaluate(FLT_MAX, {}), test_case.output);
  }
}

TEST(CSSMathExpressionNode, TestColorChannelExpressionWithInvalidChannelName) {
  const String test_cases[] = {
      "r / 2",
  };

  const CSSColorChannelMap color_channel_map = {
      {CSSValueID::kH, 240.0f},
      {CSSValueID::kS, 50.0f},
      {CSSValueID::kL, 75.0f},
      {CSSValueID::kAlpha, 1.0f},
  };

  for (const auto& test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
    const CSSMathExpressionNode* css_node =
        CSSMathExpressionNode::ParseMathFunction(
            CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
            kCSSAnchorQueryTypesNone, color_channel_map);
    EXPECT_EQ(css_node, nullptr);
  }
}

TEST(CSSMathExpressionNode, TestColorChannelExpressionWithoutSubstitution) {
  const String input = "(h / 360) * 360deg";

  const CSSColorChannelMap color_channel_map = {
      {CSSValueID::kH, std::nullopt},
      {CSSValueID::kS, std::nullopt},
      {CSSValueID::kL, std::nullopt},
      {CSSValueID::kAlpha, std::nullopt},
  };

  CSSParserTokenStream stream(input);
  const CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  const CSSMathExpressionNode* css_node =
      CSSMathExpressionNode::ParseMathFunction(
          CSSValueID::kCalc, stream, *context, Flags({Flag::AllowPercent}),
          kCSSAnchorQueryTypesNone, color_channel_map);
  EXPECT_EQ(css_node->Category(), CalculationResultCategory::kCalcAngle);
  EXPECT_TRUE(css_node->IsOperation());
  const CSSMathExpressionOperation* css_op =
      To<CSSMathExpressionOperation>(css_node);
  const CSSMathExpressionNode* operand = css_op->GetOperands()[0];
  EXPECT_TRUE(operand->IsOperation());
  const CSSMathExpressionOperation* inner_css_op =
      To<CSSMathExpressionOperation>(operand);
  const CSSMathExpressionNode* inner_operand = inner_css_op->GetOperands()[0];
  EXPECT_TRUE(inner_operand->IsKeywordLiteral());
  const CSSMathExpressionKeywordLiteral* keyword =
      To<CSSMathExpressionKeywordLiteral>(inner_operand);
  EXPECT_EQ(keyword->GetValue(), CSSValueID::kH);
  EXPECT_EQ(keyword->GetContext(),
            CSSMathExpressionKeywordLiteral::Context::kColorChannel);

  CSSToLengthConversionData resolver{/*element=*/nullptr};
  scoped_refptr<const CalculationExpressionNode> node =
      css_node->ToCalculationExpression(resolver);
  EXPECT_TRUE(node->IsOperation());
  const CalculationExpressionOperationNode* operation_node =
      To<CalculationExpressionOperationNode>(node.get());
  EXPECT_EQ(operation_node->GetOperator(), CalculationOperator::kMultiply);
  const CalculationExpressionOperationNode::Children& operands =
      operation_node->GetChildren();
  EXPECT_EQ(operands.size(), 2u);
  EXPECT_TRUE(operands[0]->IsOperation());

  const CalculationExpressionOperationNode* inner_operation_node =
      To<CalculationExpressionOperationNode>(operands[0].get());
  const CalculationExpressionOperationNode::Children& inner_operands =
      inner_operation_node->GetChildren();
  EXPECT_EQ(inner_operation_node->GetOperator(),
            CalculationOperator::kMultiply);
  EXPECT_EQ(inner_operands.size(), 2u);
  EXPECT_TRUE(inner_operands[0]->IsColorChannelKeyword());
  EXPECT_EQ(
      To<CalculationExpressionColorChannelKeywordNode>(inner_operands[0].get())
          ->Value(),
      ColorChannelKeyword::kH);
  EXPECT_TRUE(inner_operands[1]->IsNumber());
  EXPECT_EQ(
      To<CalculationExpressionNumberNode>(inner_operands[1].get())->Value(),
      (1.f / 360.f));

  EXPECT_TRUE(operands[1]->IsPixelsAndPercent());
  EXPECT_EQ(To<CalculationExpressionPixelsAndPercentNode>(operands[1].get())
                ->Pixels(),
            360.f);
}

}  // anonymous namespace

}  // namespace blink

"""

```