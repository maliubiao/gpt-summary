Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to understand the *functionality* of `decimal_test.cc`. This means figuring out what the code tests and, by extension, what the `Decimal` class itself is meant to do. We also need to explore connections to web technologies (JavaScript, HTML, CSS), common usage errors, and logical inferences with examples.

2. **Initial Code Scan (High-Level):**  Quickly look at the includes and the main namespace (`blink`). We see standard testing includes (`gtest`), math utilities (`math_extras`), and the crucial `decimal.h`. The `blink` namespace suggests this is part of the Chromium rendering engine.

3. **Identify the Core Class Under Test:** The presence of `DecimalTest` and the inclusion of `decimal.h` immediately point to the `Decimal` class being the focus.

4. **Recognize the Testing Framework:** The use of `TEST_F(DecimalTest, ...)` indicates Google Test is being used. This structure helps organize the tests by functionality.

5. **Categorize the Tests:**  Start reading through the `TEST_F` blocks. Notice patterns:
    * Tests for basic arithmetic operations (`Add`, `Subtract`, `Multiply`, `Divide`).
    * Tests for comparison operators (`Compare`).
    * Tests for unary operations (`Abs`, `Negate`).
    * Tests related to rounding and truncation (`Ceil`, `Floor`, `Round`).
    * Tests for conversion to/from other types (`FromDouble`, `FromString`, `ToDouble`, `ToString`).
    * Tests for special values (infinity, NaN).
    * Tests for predicates (checking properties like `IsFinite`, `IsNaN`, `IsZero`).
    * A simulated `DecimalStepRange` class and related tests (`StepUp`, `StepDown`, and "RealWorldExample" tests).

6. **Infer Functionality from Test Names and Code:**  Based on the categorized tests, start listing the functionalities of the `Decimal` class. For example:
    * `Abs`: Calculates the absolute value.
    * `Add`: Performs addition.
    * `Ceil`: Rounds up to the nearest integer.
    * `FromString`: Parses a decimal number from a string.
    * ... and so on.

7. **Look for Connections to Web Technologies:** This is where understanding the purpose of Blink is key. `Decimal` is likely used to represent numbers precisely in web-related contexts. Think about where numbers are important:
    * **JavaScript:**  JavaScript's `Number` type has limitations with floating-point precision. A `Decimal` class could be used internally for more accurate calculations in certain scenarios or potentially exposed (though not directly in this file).
    * **HTML:** Input elements of type `number` have attributes like `min`, `max`, and `step`. The `DecimalStepRange` class strongly suggests a connection to handling the `step` attribute.
    * **CSS:** While less direct, CSS properties can involve numerical values (e.g., `width`, `margin`, `font-size`). Precision might be less critical here, but the underlying rendering engine needs accurate calculations.

8. **Develop Examples for Web Technology Connections:**  Once the potential connections are identified, create specific examples:
    * **JavaScript:**  Illustrate the floating-point issue and how a `Decimal` type could solve it.
    * **HTML:** Show how `min`, `max`, and `step` interact, and how `DecimalStepRange` simulates this. The `StepUp` and `StepDown` tests are direct evidence of this.
    * **CSS:** Briefly mention that while less direct, the rendering engine uses precise calculations.

9. **Identify Logical Inferences and Provide Examples:** Look for tests that demonstrate specific logic. The `StepUp` and `StepDown` tests with `ClampValue` are prime examples. Create scenarios with input values and predicted outputs based on the clamping and stepping logic.

10. **Consider Common Usage Errors:** Think about how developers might misuse numerical representations:
    * **Floating-point inaccuracies:** This is a classic issue that `Decimal` likely aims to address.
    * **String parsing errors:** Incorrectly formatted strings passed to `FromString`.
    * **Division by zero:**  How does `Decimal` handle this? The tests for `DivisionSpecialValues` provide clues.
    * **Overflow/underflow:**  While `Decimal` might handle larger ranges, consider potential limits or edge cases.

11. **Refine and Organize:** Review the collected information. Structure it logically with clear headings and bullet points. Ensure the examples are easy to understand and directly relate to the points being made. Use code snippets where appropriate.

12. **Self-Correction/Review:**  Read through the explanation. Does it make sense? Is it accurate? Have all parts of the prompt been addressed?  For instance, initially, I might focus too much on the arithmetic tests. Then, realizing the `DecimalStepRange` class, I'd shift focus to the HTML input type connection. Similarly, I'd ensure the explanations about JavaScript's floating-point limitations are clear and concise.

By following these steps, we can systematically analyze the C++ test file and extract meaningful information about the `Decimal` class's functionality, its relationship to web technologies, and potential usage considerations.
这个文件 `decimal_test.cc` 是 Chromium Blink 引擎中 `wtf` 库的一部分，专门用于测试 `Decimal` 类。`Decimal` 类旨在提供一种高精度的十进制数值表示，避免了使用标准浮点数（如 `float` 或 `double`）时可能出现的精度问题。

以下是 `decimal_test.cc` 文件的功能列表：

1. **单元测试框架**: 使用 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`) 来组织和执行对 `Decimal` 类的各项功能的测试。

2. **`Decimal` 类的功能测试**:  该文件包含了大量的测试用例，覆盖了 `Decimal` 类的各种方法和操作符，确保其行为符合预期。测试范围包括：
    * **基本算术运算**: 加法 (`Add`)、减法 (`Subtract`)、乘法 (`Multiplication`)、除法 (`Division`)、取余 (`Remainder`)。
    * **比较操作**:  相等 (`==`)、不等 (`!=`)、小于 (`<`)、小于等于 (`<=`)、大于 (`>`)、大于等于 (`>=`)。
    * **取绝对值**: `Abs()`。
    * **取反**:  负号运算符 (`-`)。
    * **舍入**: 向上取整 (`Ceil`)、向下取整 (`Floor`)、四舍五入 (`Round`)。
    * **构造函数**: 测试不同的构造方式。
    * **类型转换**:  从 `double` (`FromDouble`)、从字符串 (`FromString`)、转换为 `double` (`ToDouble`)、转换为字符串 (`ToString`)。
    * **特殊值处理**:  正负零、正负无穷大 (`Infinity`)、非数字 (`NaN`)。
    * **谓词函数**:  判断数值的特性，如 `IsFinite`、`IsInfinity`、`IsNaN`、`IsPositive`、`IsNegative`、`IsZero`、`IsSpecial`。
    * **模拟步进范围**:  通过 `DecimalStepRange` 类模拟 HTML 表单中数字输入的步进逻辑 (`StepUp`, `StepDown`, `ClampValue`)。

3. **辅助函数**:  提供了一些辅助函数来简化测试用例的编写：
    * `Encode`:  根据系数、指数和符号创建一个 `Decimal` 对象。
    * `FromString`:  调用 `Decimal::FromString` 从字符串创建 `Decimal` 对象。
    * `StepDown`, `StepUp`:  模拟在指定范围内，按照步长值递减或递增 `Decimal` 值。

**与 JavaScript, HTML, CSS 的功能关系：**

`Decimal` 类在 Blink 引擎中主要用于处理需要高精度数值的场景，特别是在与 Web 技术交互时，避免浮点数精度问题。

* **JavaScript**:
    * **数值表示**: JavaScript 的 `Number` 类型是基于 IEEE 754 标准的双精度浮点数，存在精度问题，例如 `0.1 + 0.2 !== 0.3`。`Decimal` 类可以在 Blink 引擎内部用于处理需要更高精度的数值计算，例如在执行 JavaScript 代码时，如果涉及到金融计算或其他对精度要求极高的场景。
    * **假设输入与输出**: 假设 JavaScript 中有需要进行高精度计算的需求，Blink 引擎内部可能会使用 `Decimal` 类进行运算。例如，如果 JavaScript 代码尝试计算 `0.1 + 0.2`，在内部可以使用 `Decimal::FromString("0.1") + Decimal::FromString("0.2")`，其输出将会是精确的 `Decimal::FromString("0.3")`。最终转换回 JavaScript 的 `Number` 类型时，可能会有精度损失，但中间的计算过程是精确的。

* **HTML**:
    * **`<input type="number">` 元素的 `step`, `min`, `max` 属性**:  `DecimalStepRange` 类的存在直接表明了 `Decimal` 类与 HTML 数字输入框的处理有关。HTML 的 `<input type="number">` 元素允许设置 `min`（最小值）、`max`（最大值）和 `step`（步长）属性。浏览器需要根据这些属性来限制用户输入，并处理通过键盘箭头或鼠标滚轮进行的数值增减。
    * **举例说明**: `DecimalStepRange` 类的 `ClampValue` 方法模拟了当输入值超出 `min` 和 `max` 范围时，如何将其调整到最接近有效步长的值。`StepUp` 和 `StepDown` 方法模拟了按照 `step` 值递增或递减数值的过程。
        * **假设输入与输出**: 假设 HTML 中有 `<input type="number" min="0" max="10" step="2" value="5">`。当用户尝试将值减小一步时，`StepDown("0", "10", "2", "5", 1)` 会被调用，内部逻辑会计算出 `5 - 2 = 3`，并且 `3` 在 `[0, 10]` 范围内，所以输出是 `3`。如果当前值为 `1`，减小一步时，`1 - 2 = -1`，超出最小值 `0`，`ClampValue` 方法会将其调整为 `0 + round(((-1) - 0) / 2) * 2 = 0 + round(-0.5) * 2 = 0 + (-1) * 2 = -2`，但由于结果小于最小值，最终会返回 `0` (最小值)。
    * **用户或编程常见的使用错误**:
        * **`step` 属性导致的意外舍入**: 用户可能认为 `step="0.1"` 就能精确地按 0.1 增减，但由于浮点数精度问题，累加可能会产生误差。Blink 使用 `Decimal` 类可以更精确地处理 `step` 值。例如，如果 `step="0.1"`，多次点击增加按钮，使用浮点数可能会出现 `0.1 + 0.1 + 0.1 = 0.30000000000000004` 的情况，而使用 `Decimal` 则能保证 `Decimal::FromString("0.1") + Decimal::FromString("0.1") + Decimal::FromString("0.1")` 精确等于 `Decimal::FromString("0.3")`。

* **CSS**:
    * **数值属性**: CSS 中也存在大量的数值属性，例如 `width`, `height`, `margin`, `padding`, `font-size` 等。虽然这些属性的值通常不需要极高的精度，但渲染引擎在计算布局和渲染时仍然需要处理这些数值。`Decimal` 类可能在某些内部计算中使用，以确保布局的准确性，尤其是在涉及到百分比、缩放等复杂计算时。
    * **举例说明**: 假设 CSS 中设置了元素的宽度为父元素宽度的 33.3%。如果父元素宽度是 10px，那么子元素的宽度应该是 `10 * 0.333 = 3.33px`。在内部计算时，可以使用 `Decimal::FromString("10") * Decimal::FromString("0.333")` 来获得更精确的结果，虽然最终像素值可能需要进行舍入。

**逻辑推理的假设输入与输出：**

* **假设输入**: 调用 `Decimal::FromString("1.23")`
* **输出**: 创建一个 `Decimal` 对象，其内部表示的系数 (coefficient) 为 `123`，指数 (exponent) 为 `-2`，符号 (sign) 为正 (`kPositive`)。  测试用例 `TEST_F(DecimalTest, FromString)` 中有大量的此类测试。

* **假设输入**:  计算 `Decimal::FromString("0.1") + Decimal::FromString("0.2")`
* **输出**:  返回一个新的 `Decimal` 对象，其值为 `0.3`。具体的内部表示可能是系数 `3`，指数 `-1`，符号 `kPositive`。测试用例 `TEST_F(DecimalTest, Add)` 中包含了类似的加法测试。

**涉及用户或编程常见的使用错误：**

* **依赖浮点数进行精确计算**: 程序员可能会错误地使用 `float` 或 `double` 来处理需要精确计算的数值，例如货币金额。这会导致精度丢失。`Decimal` 类的存在就是为了解决这个问题。
    * **举例说明**:  在处理金融数据时，如果使用 `double` 计算 `1.00 - 0.10 - 0.10 - 0.10 - 0.10 - 0.10 - 0.10 - 0.10 - 0.10 - 0.10`，结果可能不是精确的 `0.00`。而使用 `Decimal` 类进行相同的计算，则能保证结果的精确性。

* **字符串到数值转换错误**:  用户或程序员可能会提供格式错误的字符串给 `Decimal::FromString`。
    * **举例说明**:  如果调用 `Decimal::FromString("1,234")`（使用了逗号作为千位分隔符），或者 `Decimal::FromString("abc")`，这些都不能被正确解析为十进制数，`FromString` 方法会返回 `NaN` (Not a Number)。测试用例 `TEST_F(DecimalTest, FromStringLikeNumber)` 和 `TEST_F(DecimalTest, fromStringTruncated)` 覆盖了这些情况。

* **除零错误**:  进行除法运算时，除数为零会导致错误。
    * **举例说明**:  计算 `Decimal(1) / Decimal(0)` 会得到无穷大 (`Infinity`)。计算 `Decimal(0) / Decimal(0)` 会得到 `NaN`。测试用例 `TEST_F(DecimalTest, DivisionSpecialValues)` 验证了这些行为。

总而言之，`decimal_test.cc` 文件全面测试了 `Decimal` 类在 Blink 引擎中提供的精确十进制数值处理能力，这对于确保 Web 内容的准确渲染和交互至关重要，尤其是在处理与数值相关的 HTML 元素和潜在的 JavaScript 计算时。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/decimal_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/wtf/decimal.h"

#include <cfloat>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

// Simulate core/html/forms/StepRange
class DecimalStepRange {
  STACK_ALLOCATED();

 public:
  Decimal maximum;
  Decimal minimum;
  Decimal step;

  DecimalStepRange(const Decimal& minimum,
                   const Decimal& maximum,
                   const Decimal& step)
      : maximum(maximum), minimum(minimum), step(step) {}

  Decimal ClampValue(Decimal value) const {
    const Decimal result = minimum + ((value - minimum) / step).Round() * step;
    DCHECK(result.IsFinite());
    return result > maximum ? result - step : result;
  }
};

class DecimalTest : public testing::Test {
 protected:
  using Sign = Decimal::Sign;
  static const Sign kPositive = Decimal::kPositive;
  static const Sign kNegative = Decimal::kNegative;

  Decimal Encode(uint64_t coefficient, int exponent, Sign sign) {
    return Decimal(sign, exponent, coefficient);
  }

  Decimal FromString(const String& string) {
    return Decimal::FromString(string);
  }

  Decimal StepDown(const String& minimum,
                   const String& maximum,
                   const String& step,
                   const String& value_string,
                   int number_of_step_times) {
    DecimalStepRange step_range(FromString(minimum), FromString(maximum),
                                FromString(step));
    Decimal value = FromString(value_string);
    for (int i = 0; i < number_of_step_times; ++i) {
      value -= step_range.step;
      value = step_range.ClampValue(value);
    }
    return value;
  }

  Decimal StepUp(const String& minimum,
                 const String& maximum,
                 const String& step,
                 const String& value_string,
                 int number_of_step_times) {
    DecimalStepRange step_range(FromString(minimum), FromString(maximum),
                                FromString(step));
    Decimal value = FromString(value_string);
    for (int i = 0; i < number_of_step_times; ++i) {
      value += step_range.step;
      value = step_range.ClampValue(value);
    }
    return value;
  }
};

// FIXME: We should use expectedSign without "Decimal::", however, g++ causes
// undefined references for DecimalTest::Positive and Negative.
#define EXPECT_DECIMAL_ENCODED_DATA_EQ(expectedCoefficient, expectedExponent, \
                                       expectedSign, decimal)                 \
  EXPECT_EQ((expectedCoefficient), (decimal).Value().Coefficient());          \
  EXPECT_EQ((expectedExponent), (decimal).Value().Exponent());                \
  EXPECT_EQ(Decimal::expectedSign, (decimal).Value().GetSign());

TEST_F(DecimalTest, Abs) {
  EXPECT_EQ(Encode(0, 0, kPositive), Encode(0, 0, kPositive).Abs());
  EXPECT_EQ(Encode(0, 0, kPositive), Encode(0, 0, kNegative).Abs());

  EXPECT_EQ(Encode(0, 10, kPositive), Encode(0, 10, kPositive).Abs());
  EXPECT_EQ(Encode(0, 10, kPositive), Encode(0, 10, kNegative).Abs());

  EXPECT_EQ(Encode(0, -10, kPositive), Encode(0, -10, kPositive).Abs());
  EXPECT_EQ(Encode(0, -10, kPositive), Encode(0, -10, kNegative).Abs());

  EXPECT_EQ(Encode(1, 0, kPositive), Encode(1, 0, kPositive).Abs());
  EXPECT_EQ(Encode(1, 0, kPositive), Encode(1, 0, kNegative).Abs());

  EXPECT_EQ(Encode(1, 10, kPositive), Encode(1, 10, kPositive).Abs());
  EXPECT_EQ(Encode(1, 10, kPositive), Encode(1, 10, kNegative).Abs());

  EXPECT_EQ(Encode(1, -10, kPositive), Encode(1, -10, kPositive).Abs());
  EXPECT_EQ(Encode(1, -10, kPositive), Encode(1, -10, kNegative).Abs());
}

TEST_F(DecimalTest, AbsBigExponent) {
  EXPECT_EQ(Encode(1, 1000, kPositive), Encode(1, 1000, kPositive).Abs());
  EXPECT_EQ(Encode(1, 1000, kPositive), Encode(1, 1000, kNegative).Abs());
}

TEST_F(DecimalTest, AbsSmallExponent) {
  EXPECT_EQ(Encode(1, -1000, kPositive), Encode(1, -1000, kPositive).Abs());
  EXPECT_EQ(Encode(1, -1000, kPositive), Encode(1, -1000, kNegative).Abs());
}

TEST_F(DecimalTest, AbsSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kPositive), Decimal::Infinity(kPositive).Abs());
  EXPECT_EQ(Decimal::Infinity(kPositive), Decimal::Infinity(kNegative).Abs());
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Abs());
}

TEST_F(DecimalTest, Add) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(0) + Decimal(0));
  EXPECT_EQ(Decimal(1), Decimal(2) + Decimal(-1));
  EXPECT_EQ(Decimal(1), Decimal(-1) + Decimal(2));
  EXPECT_EQ(Encode(100, 0, kPositive), Decimal(99) + Decimal(1));
  EXPECT_EQ(Encode(100, 0, kNegative), Decimal(-50) + Decimal(-50));
  EXPECT_EQ(Encode(UINT64_C(1000000000000000), 35, kPositive),
            Encode(1, 50, kPositive) + Decimal(1));
  EXPECT_EQ(Encode(UINT64_C(1000000000000000), 35, kPositive),
            Decimal(1) + Encode(1, 50, kPositive));
  EXPECT_EQ(Encode(UINT64_C(10000000001), 0, kPositive),
            Encode(1, 10, kPositive) + Decimal(1));
  EXPECT_EQ(Encode(UINT64_C(10000000001), 0, kPositive),
            Decimal(1) + Encode(1, 10, kPositive));
  EXPECT_EQ(Encode(1, 0, kPositive),
            Encode(1, -1022, kPositive) + Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(2, -1022, kPositive),
            Encode(1, -1022, kPositive) + Encode(1, -1022, kPositive));
}

TEST_F(DecimalTest, AddBigExponent) {
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) + Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(2, 1022, kPositive),
            Encode(1, 1022, kPositive) + Encode(1, 1022, kPositive));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Encode(std::numeric_limits<uint64_t>::max(), 1022, kPositive) +
                Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) + Encode(1, -1000, kPositive));
}

TEST_F(DecimalTest, AddSmallExponent) {
  EXPECT_EQ(Encode(1, 0, kPositive),
            Encode(1, -1022, kPositive) + Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(2, -1022, kPositive),
            Encode(1, -1022, kPositive) + Encode(1, -1022, kPositive));
}

TEST_F(DecimalTest, AddSpecialValues) {
  const Decimal infinity(Decimal::Infinity(kPositive));
  const Decimal minus_infinity(Decimal::Infinity(kNegative));
  const Decimal na_n(Decimal::Nan());
  const Decimal ten(10);

  EXPECT_EQ(infinity, infinity + infinity);
  EXPECT_EQ(na_n, infinity + minus_infinity);
  EXPECT_EQ(na_n, minus_infinity + infinity);
  EXPECT_EQ(minus_infinity, minus_infinity + minus_infinity);

  EXPECT_EQ(infinity, infinity + ten);
  EXPECT_EQ(infinity, ten + infinity);
  EXPECT_EQ(minus_infinity, minus_infinity + ten);
  EXPECT_EQ(minus_infinity, ten + minus_infinity);

  EXPECT_EQ(na_n, na_n + na_n);
  EXPECT_EQ(na_n, na_n + ten);
  EXPECT_EQ(na_n, ten + na_n);

  EXPECT_EQ(na_n, na_n - infinity);
  EXPECT_EQ(na_n, na_n - minus_infinity);
  EXPECT_EQ(na_n, infinity - na_n);
  EXPECT_EQ(na_n, minus_infinity - na_n);
}

TEST_F(DecimalTest, Ceil) {
  EXPECT_EQ(Decimal(1), Decimal(1).Ceil());
  EXPECT_EQ(Decimal(1), Encode(1, -10, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(11, -1, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(13, -1, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(15, -1, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(19, -1, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(151, -2, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(101, -2, kPositive).Ceil());
  EXPECT_EQ(Decimal(1), Encode(199, -3, kPositive).Ceil());
  EXPECT_EQ(Decimal(2), Encode(199, -2, kPositive).Ceil());
  EXPECT_EQ(Decimal(3), Encode(209, -2, kPositive).Ceil());

  EXPECT_EQ(Decimal(-1), Decimal(-1).Ceil());
  EXPECT_EQ(Decimal(0), Encode(1, -10, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(11, -1, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(13, -1, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(15, -1, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(19, -1, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(151, -2, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(101, -2, kNegative).Ceil());
  EXPECT_EQ(Decimal(0), Encode(199, -3, kNegative).Ceil());
  EXPECT_EQ(Decimal(-1), Encode(199, -2, kNegative).Ceil());
  EXPECT_EQ(Decimal(-2), Encode(209, -2, kNegative).Ceil());
  EXPECT_EQ(Decimal(1),
            Encode(UINT64_C(123456789012345678), -18, kPositive).Ceil());
}

TEST_F(DecimalTest, CeilingBigExponent) {
  EXPECT_EQ(Encode(1, 1000, kPositive), Encode(1, 1000, kPositive).Ceil());
  EXPECT_EQ(Encode(1, 1000, kNegative), Encode(1, 1000, kNegative).Ceil());
}

TEST_F(DecimalTest, CeilingSmallExponent) {
  EXPECT_EQ(Encode(1, 0, kPositive), Encode(1, -1000, kPositive).Ceil());
  EXPECT_EQ(Encode(0, 0, kNegative), Encode(1, -1000, kNegative).Ceil());
}

TEST_F(DecimalTest, CeilingSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kPositive), Decimal::Infinity(kPositive).Ceil());
  EXPECT_EQ(Decimal::Infinity(kNegative), Decimal::Infinity(kNegative).Ceil());
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Ceil());
}

TEST_F(DecimalTest, Compare) {
  EXPECT_TRUE(Decimal(0) == Decimal(0));
  EXPECT_TRUE(Decimal(0) != Decimal(1));
  EXPECT_TRUE(Decimal(0) < Decimal(1));
  EXPECT_TRUE(Decimal(0) <= Decimal(0));
  EXPECT_TRUE(Decimal(0) > Decimal(-1));
  EXPECT_TRUE(Decimal(0) >= Decimal(0));

  EXPECT_FALSE(Decimal(1) == Decimal(2));
  EXPECT_FALSE(Decimal(1) != Decimal(1));
  EXPECT_FALSE(Decimal(1) < Decimal(0));
  EXPECT_FALSE(Decimal(1) <= Decimal(0));
  EXPECT_FALSE(Decimal(1) > Decimal(2));
  EXPECT_FALSE(Decimal(1) >= Decimal(2));
}

TEST_F(DecimalTest, CompareBigExponent) {
  EXPECT_TRUE(Encode(1, 1000, kPositive) == Encode(1, 1000, kPositive));
  EXPECT_FALSE(Encode(1, 1000, kPositive) != Encode(1, 1000, kPositive));
  EXPECT_FALSE(Encode(1, 1000, kPositive) < Encode(1, 1000, kPositive));
  EXPECT_TRUE(Encode(1, 1000, kPositive) <= Encode(1, 1000, kPositive));
  EXPECT_FALSE(Encode(1, 1000, kPositive) > Encode(1, 1000, kPositive));
  EXPECT_TRUE(Encode(1, 1000, kPositive) >= Encode(1, 1000, kPositive));

  EXPECT_TRUE(Encode(1, 1000, kNegative) == Encode(1, 1000, kNegative));
  EXPECT_FALSE(Encode(1, 1000, kNegative) != Encode(1, 1000, kNegative));
  EXPECT_FALSE(Encode(1, 1000, kNegative) < Encode(1, 1000, kNegative));
  EXPECT_TRUE(Encode(1, 1000, kNegative) <= Encode(1, 1000, kNegative));
  EXPECT_FALSE(Encode(1, 1000, kNegative) > Encode(1, 1000, kNegative));
  EXPECT_TRUE(Encode(1, 1000, kNegative) >= Encode(1, 1000, kNegative));

  EXPECT_FALSE(Encode(2, 1000, kPositive) == Encode(1, 1000, kPositive));
  EXPECT_TRUE(Encode(2, 1000, kPositive) != Encode(1, 1000, kPositive));
  EXPECT_FALSE(Encode(2, 1000, kPositive) < Encode(1, 1000, kPositive));
  EXPECT_FALSE(Encode(2, 1000, kPositive) <= Encode(1, 1000, kPositive));
  EXPECT_TRUE(Encode(2, 1000, kPositive) > Encode(1, 1000, kPositive));
  EXPECT_TRUE(Encode(2, 1000, kPositive) >= Encode(1, 1000, kPositive));

  EXPECT_FALSE(Encode(2, 1000, kNegative) == Encode(1, 1000, kNegative));
  EXPECT_TRUE(Encode(2, 1000, kNegative) != Encode(1, 1000, kNegative));
  EXPECT_TRUE(Encode(2, 1000, kNegative) < Encode(1, 1000, kNegative));
  EXPECT_TRUE(Encode(2, 1000, kNegative) <= Encode(1, 1000, kNegative));
  EXPECT_FALSE(Encode(2, 1000, kNegative) > Encode(1, 1000, kNegative));
  EXPECT_FALSE(Encode(2, 1000, kNegative) >= Encode(1, 1000, kNegative));
}

TEST_F(DecimalTest, CompareSmallExponent) {
  EXPECT_TRUE(Encode(1, -1000, kPositive) == Encode(1, -1000, kPositive));
  EXPECT_FALSE(Encode(1, -1000, kPositive) != Encode(1, -1000, kPositive));
  EXPECT_FALSE(Encode(1, -1000, kPositive) < Encode(1, -1000, kPositive));
  EXPECT_TRUE(Encode(1, -1000, kPositive) <= Encode(1, -1000, kPositive));
  EXPECT_FALSE(Encode(1, -1000, kPositive) > Encode(1, -1000, kPositive));
  EXPECT_TRUE(Encode(1, -1000, kPositive) >= Encode(1, -1000, kPositive));

  EXPECT_TRUE(Encode(1, -1000, kNegative) == Encode(1, -1000, kNegative));
  EXPECT_FALSE(Encode(1, -1000, kNegative) != Encode(1, -1000, kNegative));
  EXPECT_FALSE(Encode(1, -1000, kNegative) < Encode(1, -1000, kNegative));
  EXPECT_TRUE(Encode(1, -1000, kNegative) <= Encode(1, -1000, kNegative));
  EXPECT_FALSE(Encode(1, -1000, kNegative) > Encode(1, -1000, kNegative));
  EXPECT_TRUE(Encode(1, -1000, kNegative) >= Encode(1, -1000, kNegative));

  EXPECT_FALSE(Encode(2, -1000, kPositive) == Encode(1, -1000, kPositive));
  EXPECT_TRUE(Encode(2, -1000, kPositive) != Encode(1, -1000, kPositive));
  EXPECT_FALSE(Encode(2, -1000, kPositive) < Encode(1, -1000, kPositive));
  EXPECT_FALSE(Encode(2, -1000, kPositive) <= Encode(1, -1000, kPositive));
  EXPECT_TRUE(Encode(2, -1000, kPositive) > Encode(1, -1000, kPositive));
  EXPECT_TRUE(Encode(2, -1000, kPositive) >= Encode(1, -1000, kPositive));

  EXPECT_FALSE(Encode(2, -1000, kNegative) == Encode(1, -1000, kNegative));
  EXPECT_TRUE(Encode(2, -1000, kNegative) != Encode(1, -1000, kNegative));
  EXPECT_TRUE(Encode(2, -1000, kNegative) < Encode(1, -1000, kNegative));
  EXPECT_TRUE(Encode(2, -1000, kNegative) <= Encode(1, -1000, kNegative));
  EXPECT_FALSE(Encode(2, -1000, kNegative) > Encode(1, -1000, kNegative));
  EXPECT_FALSE(Encode(2, -1000, kNegative) >= Encode(1, -1000, kNegative));
}

TEST_F(DecimalTest, CompareSpecialValues) {
  const Decimal infinity(Decimal::Infinity(kPositive));
  const Decimal minus_infinity(Decimal::Infinity(kNegative));
  const Decimal na_n(Decimal::Nan());
  const Decimal zero(Decimal::Zero(kPositive));
  const Decimal minus_zero(Decimal::Zero(kNegative));
  const Decimal ten(10);

  EXPECT_TRUE(zero == zero);
  EXPECT_FALSE(zero != zero);
  EXPECT_FALSE(zero < zero);
  EXPECT_TRUE(zero <= zero);
  EXPECT_FALSE(zero > zero);
  EXPECT_TRUE(zero >= zero);

  EXPECT_TRUE(zero == minus_zero);
  EXPECT_FALSE(zero != minus_zero);
  EXPECT_FALSE(zero < minus_zero);
  EXPECT_TRUE(zero <= minus_zero);
  EXPECT_FALSE(zero > minus_zero);
  EXPECT_TRUE(zero >= minus_zero);

  EXPECT_TRUE(minus_zero == zero);
  EXPECT_FALSE(minus_zero != zero);
  EXPECT_FALSE(minus_zero < zero);
  EXPECT_TRUE(minus_zero <= zero);
  EXPECT_FALSE(minus_zero > zero);
  EXPECT_TRUE(minus_zero >= zero);

  EXPECT_TRUE(minus_zero == minus_zero);
  EXPECT_FALSE(minus_zero != minus_zero);
  EXPECT_FALSE(minus_zero < minus_zero);
  EXPECT_TRUE(minus_zero <= minus_zero);
  EXPECT_FALSE(minus_zero > minus_zero);
  EXPECT_TRUE(minus_zero >= minus_zero);

  EXPECT_TRUE(infinity == infinity);
  EXPECT_FALSE(infinity != infinity);
  EXPECT_FALSE(infinity < infinity);
  EXPECT_TRUE(infinity <= infinity);
  EXPECT_FALSE(infinity > infinity);
  EXPECT_TRUE(infinity >= infinity);

  EXPECT_FALSE(infinity == ten);
  EXPECT_TRUE(infinity != ten);
  EXPECT_FALSE(infinity < ten);
  EXPECT_FALSE(infinity <= ten);
  EXPECT_TRUE(infinity > ten);
  EXPECT_TRUE(infinity >= ten);

  EXPECT_FALSE(infinity == minus_infinity);
  EXPECT_TRUE(infinity != minus_infinity);
  EXPECT_FALSE(infinity < minus_infinity);
  EXPECT_FALSE(infinity <= minus_infinity);
  EXPECT_TRUE(infinity > minus_infinity);
  EXPECT_TRUE(infinity >= minus_infinity);

  EXPECT_FALSE(infinity == na_n);
  EXPECT_FALSE(infinity != na_n);
  EXPECT_FALSE(infinity < na_n);
  EXPECT_FALSE(infinity <= na_n);
  EXPECT_FALSE(infinity > na_n);
  EXPECT_FALSE(infinity >= na_n);

  EXPECT_FALSE(minus_infinity == infinity);
  EXPECT_TRUE(minus_infinity != infinity);
  EXPECT_TRUE(minus_infinity < infinity);
  EXPECT_TRUE(minus_infinity <= infinity);
  EXPECT_FALSE(minus_infinity > infinity);
  EXPECT_FALSE(minus_infinity >= infinity);

  EXPECT_FALSE(minus_infinity == ten);
  EXPECT_TRUE(minus_infinity != ten);
  EXPECT_TRUE(minus_infinity < ten);
  EXPECT_TRUE(minus_infinity <= ten);
  EXPECT_FALSE(minus_infinity > ten);
  EXPECT_FALSE(minus_infinity >= ten);

  EXPECT_TRUE(minus_infinity == minus_infinity);
  EXPECT_FALSE(minus_infinity != minus_infinity);
  EXPECT_FALSE(minus_infinity < minus_infinity);
  EXPECT_TRUE(minus_infinity <= minus_infinity);
  EXPECT_FALSE(minus_infinity > minus_infinity);
  EXPECT_TRUE(minus_infinity >= minus_infinity);

  EXPECT_FALSE(minus_infinity == na_n);
  EXPECT_FALSE(minus_infinity != na_n);
  EXPECT_FALSE(minus_infinity < na_n);
  EXPECT_FALSE(minus_infinity <= na_n);
  EXPECT_FALSE(minus_infinity > na_n);
  EXPECT_FALSE(minus_infinity >= na_n);

  EXPECT_FALSE(na_n == infinity);
  EXPECT_FALSE(na_n != infinity);
  EXPECT_FALSE(na_n < infinity);
  EXPECT_FALSE(na_n <= infinity);
  EXPECT_FALSE(na_n > infinity);
  EXPECT_FALSE(na_n >= infinity);

  EXPECT_FALSE(na_n == ten);
  EXPECT_FALSE(na_n != ten);
  EXPECT_FALSE(na_n < ten);
  EXPECT_FALSE(na_n <= ten);
  EXPECT_FALSE(na_n > ten);
  EXPECT_FALSE(na_n >= ten);

  EXPECT_FALSE(na_n == minus_infinity);
  EXPECT_FALSE(na_n != minus_infinity);
  EXPECT_FALSE(na_n < minus_infinity);
  EXPECT_FALSE(na_n <= minus_infinity);
  EXPECT_FALSE(na_n > minus_infinity);
  EXPECT_FALSE(na_n >= minus_infinity);

  EXPECT_TRUE(na_n == na_n);
  EXPECT_FALSE(na_n != na_n);
  EXPECT_FALSE(na_n < na_n);
  EXPECT_TRUE(na_n <= na_n);
  EXPECT_FALSE(na_n > na_n);
  EXPECT_TRUE(na_n >= na_n);
}

TEST_F(DecimalTest, Constructor) {
  EXPECT_DECIMAL_ENCODED_DATA_EQ(0u, 0, kPositive, Encode(0, 0, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(0u, 0, kNegative, Encode(0, 0, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 0, kPositive, Encode(1, 0, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 0, kNegative, Encode(1, 0, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 1022, kPositive,
                                 Encode(1, 1022, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 1022, kNegative,
                                 Encode(1, 1022, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 1023, kPositive,
                                 Encode(1, 1023, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(1u, 1023, kNegative,
                                 Encode(1, 1023, kNegative));
  EXPECT_TRUE(Encode(1, 2000, kPositive).IsInfinity());
  EXPECT_TRUE(Encode(1, 2000, kNegative).IsInfinity());
  EXPECT_DECIMAL_ENCODED_DATA_EQ(0u, 0, kPositive, Encode(1, -2000, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(0u, 0, kNegative, Encode(1, -2000, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(99999999999999998), 0, kPositive,
      Encode(UINT64_C(99999999999999998), 0, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(99999999999999998), 0, kNegative,
      Encode(UINT64_C(99999999999999998), 0, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(99999999999999999), 0, kPositive,
      Encode(UINT64_C(99999999999999999), 0, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(99999999999999999), 0, kNegative,
      Encode(UINT64_C(99999999999999999), 0, kNegative));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(100000000000000000), 0, kPositive,
      Encode(UINT64_C(100000000000000000), 0, kPositive));
  EXPECT_DECIMAL_ENCODED_DATA_EQ(
      UINT64_C(100000000000000000), 0, kNegative,
      Encode(UINT64_C(100000000000000000), 0, kNegative));
}

TEST_F(DecimalTest, Division) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(0) / Decimal(1));
  EXPECT_EQ(Encode(2, 0, kNegative), Decimal(2) / Decimal(-1));
  EXPECT_EQ(Encode(5, -1, kNegative), Decimal(-1) / Decimal(2));
  EXPECT_EQ(Encode(99, 0, kPositive), Decimal(99) / Decimal(1));
  EXPECT_EQ(Decimal(1), Decimal(-50) / Decimal(-50));
  EXPECT_EQ(Encode(UINT64_C(333333333333333333), -18, kPositive),
            Decimal(1) / Decimal(3));
  EXPECT_EQ(Encode(UINT64_C(12345678901234), -1, kPositive),
            Encode(UINT64_C(12345678901234), 0, kPositive) / Decimal(10));
  EXPECT_EQ(Encode(UINT64_C(500005000050000500), -18, kPositive),
            Decimal(50000) / Decimal(99999));
}

TEST_F(DecimalTest, DivisionBigExponent) {
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) / Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(1, 0, kPositive),
            Encode(1, 1022, kPositive) / Encode(1, 1022, kPositive));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Encode(1, 1022, kPositive) / Encode(1, -1000, kPositive));
}

TEST_F(DecimalTest, DivisionSmallExponent) {
  EXPECT_EQ(Encode(1, -1022, kPositive),
            Encode(1, -1022, kPositive) / Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(1, 0, kPositive),
            Encode(1, -1022, kPositive) / Encode(1, -1022, kPositive));
}

TEST_F(DecimalTest, DivisionSpecialValues) {
  const Decimal infinity(Decimal::Infinity(kPositive));
  const Decimal minus_infinity(Decimal::Infinity(kNegative));
  const Decimal na_n(Decimal::Nan());
  const Decimal zero(Decimal::Zero(kPositive));
  const Decimal minus_zero(Decimal::Zero(kNegative));
  const Decimal ten(10);
  const Decimal minus_ten(-10);

  EXPECT_EQ(na_n, zero / zero);
  EXPECT_EQ(na_n, zero / minus_zero);
  EXPECT_EQ(na_n, minus_zero / zero);
  EXPECT_EQ(na_n, minus_zero / minus_zero);

  EXPECT_EQ(infinity, ten / zero);
  EXPECT_EQ(minus_infinity, ten / minus_zero);
  EXPECT_EQ(minus_infinity, minus_ten / zero);
  EXPECT_EQ(infinity, minus_ten / minus_zero);

  EXPECT_EQ(infinity, infinity / zero);
  EXPECT_EQ(minus_infinity, infinity / minus_zero);
  EXPECT_EQ(minus_infinity, minus_infinity / zero);
  EXPECT_EQ(infinity, minus_infinity / minus_zero);

  EXPECT_EQ(na_n, infinity / infinity);
  EXPECT_EQ(na_n, infinity / minus_infinity);
  EXPECT_EQ(na_n, minus_infinity / infinity);
  EXPECT_EQ(na_n, minus_infinity / minus_infinity);

  EXPECT_EQ(zero, ten / infinity);
  EXPECT_EQ(minus_zero, ten / minus_infinity);
  EXPECT_EQ(minus_zero, minus_ten / infinity);
  EXPECT_EQ(zero, minus_ten / minus_infinity);

  EXPECT_EQ(na_n, na_n / na_n);
  EXPECT_EQ(na_n, na_n / ten);
  EXPECT_EQ(na_n, ten / na_n);

  EXPECT_EQ(na_n, na_n / infinity);
  EXPECT_EQ(na_n, na_n / minus_infinity);
  EXPECT_EQ(na_n, infinity / na_n);
  EXPECT_EQ(na_n, minus_infinity / na_n);
}

TEST_F(DecimalTest, EncodedData) {
  EXPECT_EQ(Encode(0, 0, kPositive), Encode(0, 0, kPositive));
  EXPECT_EQ(Encode(0, 0, kNegative), Encode(0, 0, kNegative));
  EXPECT_EQ(Decimal(1), Decimal(1));
  EXPECT_EQ(Encode(1, 0, kNegative), Encode(1, 0, kNegative));
  EXPECT_EQ(Decimal::Infinity(kPositive), Encode(1, 2000, kPositive));
  EXPECT_EQ(Decimal::Zero(kPositive), Encode(1, -2000, kPositive));
}

TEST_F(DecimalTest, Floor) {
  EXPECT_EQ(Decimal(1), Decimal(1).Floor());
  EXPECT_EQ(Decimal(0), Encode(1, -10, kPositive).Floor());
  EXPECT_EQ(Decimal(1), Encode(11, -1, kPositive).Floor());
  EXPECT_EQ(Decimal(1), Encode(13, -1, kPositive).Floor());
  EXPECT_EQ(Decimal(1), Encode(15, -1, kPositive).Floor());
  EXPECT_EQ(Decimal(1), Encode(19, -1, kPositive).Floor());
  EXPECT_EQ(Decimal(1), Encode(193332, -5, kPositive).Floor());
  EXPECT_EQ(Decimal(12), Encode(12002, -3, kPositive).Floor());

  EXPECT_EQ(Decimal(-1), Decimal(-1).Floor());
  EXPECT_EQ(Decimal(-1), Encode(1, -10, kNegative).Floor());
  EXPECT_EQ(Decimal(-2), Encode(11, -1, kNegative).Floor());
  EXPECT_EQ(Decimal(-2), Encode(13, -1, kNegative).Floor());
  EXPECT_EQ(Decimal(-2), Encode(15, -1, kNegative).Floor());
  EXPECT_EQ(Decimal(-2), Encode(19, -1, kNegative).Floor());
  EXPECT_EQ(Decimal(-2), Encode(193332, -5, kNegative).Floor());
  EXPECT_EQ(Decimal(-13), Encode(12002, -3, kNegative).Floor());

  // crbug.com/572769
  EXPECT_EQ(Decimal(-1), Encode(992971299197409433, -18, kNegative).Floor());
}

TEST_F(DecimalTest, FloorBigExponent) {
  EXPECT_EQ(Encode(1, 1000, kPositive), Encode(1, 1000, kPositive).Floor());
  EXPECT_EQ(Encode(1, 1000, kNegative), Encode(1, 1000, kNegative).Floor());
}

TEST_F(DecimalTest, FloorSmallExponent) {
  EXPECT_EQ(Encode(0, 0, kPositive), Encode(1, -1000, kPositive).Floor());
  EXPECT_EQ(Encode(1, 0, kNegative), Encode(1, -1000, kNegative).Floor());
}

TEST_F(DecimalTest, FloorSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kPositive), Decimal::Infinity(kPositive).Floor());
  EXPECT_EQ(Decimal::Infinity(kNegative), Decimal::Infinity(kNegative).Floor());
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Floor());
}

TEST_F(DecimalTest, FromDouble) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal::FromDouble(0.0));
  EXPECT_EQ(Encode(0, 0, kNegative), Decimal::FromDouble(-0.0));
  EXPECT_EQ(Encode(1, 0, kPositive), Decimal::FromDouble(1));
  EXPECT_EQ(Encode(1, 0, kNegative), Decimal::FromDouble(-1));
  EXPECT_EQ(Encode(123, 0, kPositive), Decimal::FromDouble(123));
  EXPECT_EQ(Encode(123, 0, kNegative), Decimal::FromDouble(-123));
  EXPECT_EQ(Encode(1, -1, kPositive), Decimal::FromDouble(0.1));
  EXPECT_EQ(Encode(1, -1, kNegative), Decimal::FromDouble(-0.1));
}

TEST_F(DecimalTest, FromDoubleLimits) {
  EXPECT_EQ(Encode(UINT64_C(2220446049250313), -31, kPositive),
            Decimal::FromDouble(std::numeric_limits<double>::epsilon()));
  EXPECT_EQ(Encode(UINT64_C(2220446049250313), -31, kNegative),
            Decimal::FromDouble(-std::numeric_limits<double>::epsilon()));
  EXPECT_EQ(Encode(UINT64_C(17976931348623157), 292, kPositive),
            Decimal::FromDouble(std::numeric_limits<double>::max()));
  EXPECT_EQ(Encode(UINT64_C(17976931348623157), 292, kNegative),
            Decimal::FromDouble(-std::numeric_limits<double>::max()));
  EXPECT_EQ(Encode(UINT64_C(22250738585072014), -324, kPositive),
            Decimal::FromDouble(std::numeric_limits<double>::min()));
  EXPECT_EQ(Encode(UINT64_C(22250738585072014), -324, kNegative),
            Decimal::FromDouble(-std::numeric_limits<double>::min()));
  EXPECT_TRUE(Decimal::FromDouble(std::numeric_limits<double>::infinity())
                  .IsInfinity());
  EXPECT_TRUE(Decimal::FromDouble(-std::numeric_limits<double>::infinity())
                  .IsInfinity());
  EXPECT_TRUE(
      Decimal::FromDouble(std::numeric_limits<double>::quiet_NaN()).IsNaN());
  EXPECT_TRUE(
      Decimal::FromDouble(-std::numeric_limits<double>::quiet_NaN()).IsNaN());
}

TEST_F(DecimalTest, FromInt32) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(0));
  EXPECT_EQ(Encode(1, 0, kPositive), Decimal(1));
  EXPECT_EQ(Encode(1, 0, kNegative), Decimal(-1));
  EXPECT_EQ(Encode(100, 0, kPositive), Decimal(100));
  EXPECT_EQ(Encode(100, 0, kNegative), Decimal(-100));
  EXPECT_EQ(Encode(0x7FFFFFFF, 0, kPositive),
            Decimal(std::numeric_limits<int32_t>::max()));
  EXPECT_EQ(Encode(0x80000000u, 0, kNegative),
            Decimal(std::numeric_limits<int32_t>::min()));
}

TEST_F(DecimalTest, FromString) {
  EXPECT_EQ(Encode(0, 0, kPositive), FromString("0"));
  EXPECT_EQ(Encode(0, 0, kNegative), FromString("-0"));
  EXPECT_EQ(Decimal(1), FromString("1"));
  EXPECT_EQ(Encode(1, 0, kNegative), FromString("-1"));
  EXPECT_EQ(Decimal(1), FromString("01"));
  EXPECT_EQ(Encode(3, 0, kPositive), FromString("+3"));
  EXPECT_EQ(Encode(0, 3, kPositive), FromString("0E3"));
  EXPECT_EQ(Encode(5, -1, kPositive), FromString(".5"));
  EXPECT_EQ(Encode(5, -1, kPositive), FromString("+.5"));
  EXPECT_EQ(Encode(5, -1, kNegative), FromString("-.5"));
  EXPECT_EQ(Encode(100, 0, kPositive), FromString("100"));
  EXPECT_EQ(Encode(100, 0, kNegative), FromString("-100"));
  EXPECT_EQ(Encode(123, -2, kPositive), FromString("1.23"));
  EXPECT_EQ(Encode(123, -2, kNegative), FromString("-1.23"));
  EXPECT_EQ(Encode(123, 8, kPositive), FromString("1.23E10"));
  EXPECT_EQ(Encode(123, 8, kNegative), FromString("-1.23E10"));
  EXPECT_EQ(Encode(123, 8, kPositive), FromString("1.23E+10"));
  EXPECT_EQ(Encode(123, 8, kNegative), FromString("-1.23E+10"));
  EXPECT_EQ(Encode(123, -12, kPositive), FromString("1.23E-10"));
  EXPECT_EQ(Encode(123, -12, kNegative), FromString("-1.23E-10"));
  EXPECT_EQ(Encode(5, -7, kPositive), FromString("0.0000005"));
  EXPECT_EQ(Encode(0, 0, kPositive), FromString("0e9999"));
  EXPECT_EQ(Encode(123, -3, kPositive), FromString("0.123"));
  EXPECT_EQ(Encode(0, -2, kPositive), FromString("00.00"));
  EXPECT_EQ(Encode(1, 2, kPositive), FromString("1E2"));
  EXPECT_EQ(Decimal::Infinity(kPositive), FromString("1E20000"));
  EXPECT_EQ(Decimal::Zero(kPositive), FromString("1E-20000"));
  EXPECT_EQ(Encode(1000, 1023, kPositive), FromString("1E1026"));
  EXPECT_EQ(Decimal::Zero(kPositive), FromString("1E-1026"));
  EXPECT_EQ(Decimal::Infinity(kPositive), FromString("1234567890E1036"));

  // 2^1024
  const uint64_t kLeadingDigitsOf2PowerOf1024 = UINT64_C(17976931348623159);
  EXPECT_EQ(Encode(kLeadingDigitsOf2PowerOf1024, 292, kPositive),
            FromString("1797693134862315907729305190789024733617976978942306572"
                       "7343008115773267580550096313270847732240753602112011387"
                       "9871393357658789768814416622492847430639474124377767893"
                       "4248654852763022196012460941194530829520850057688381506"
                       "8234246288147391311054082723716335051068458629823994724"
                       "5938479716304835356329624224137216"));
}

// These strings are look like proper number, but we don't accept them.
TEST_F(DecimalTest, FromStringLikeNumber) {
  EXPECT_EQ(Decimal::Nan(), FromString(" 123 "));
  EXPECT_EQ(Decimal::Nan(), FromString("1,234"));
}

// fromString doesn't support infinity and NaN.
TEST_F(DecimalTest, FromStringSpecialValues) {
  EXPECT_EQ(Decimal::Nan(), FromString("INF"));
  EXPECT_EQ(Decimal::Nan(), FromString("Infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("+Infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("+infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("-Infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("-infinity"));
  EXPECT_EQ(Decimal::Nan(), FromString("NaN"));
  EXPECT_EQ(Decimal::Nan(), FromString("nan"));
  EXPECT_EQ(Decimal::Nan(), FromString("+NaN"));
  EXPECT_EQ(Decimal::Nan(), FromString("+nan"));
  EXPECT_EQ(Decimal::Nan(), FromString("-NaN"));
  EXPECT_EQ(Decimal::Nan(), FromString("-nan"));
}

TEST_F(DecimalTest, fromStringTruncated) {
  EXPECT_EQ(Decimal::Nan(), FromString("x"));
  EXPECT_EQ(Decimal::Nan(), FromString("0."));
  EXPECT_EQ(Decimal::Nan(), FromString("1x"));

  EXPECT_EQ(Decimal::Nan(), FromString("1Ex"));
  EXPECT_EQ(Decimal::Nan(), FromString("1E2x"));
  EXPECT_EQ(Decimal::Nan(), FromString("1E+x"));
}

TEST_F(DecimalTest, Multiplication) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(0) * Decimal(0));
  EXPECT_EQ(Encode(2, 0, kNegative), Decimal(2) * Decimal(-1));
  EXPECT_EQ(Encode(2, 0, kNegative), Decimal(-1) * Decimal(2));
  EXPECT_EQ(Encode(99, 0, kPositive), Decimal(99) * Decimal(1));
  EXPECT_EQ(Encode(2500, 0, kPositive), Decimal(-50) * Decimal(-50));
  EXPECT_EQ(Encode(1, 21, kPositive),
            Encode(UINT64_C(10000000000), 0, kPositive) *
                Encode(UINT64_C(100000000000), 0, kPositive));
}

TEST_F(DecimalTest, MultiplicationBigExponent) {
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) * Encode(1, 0, kPositive));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Encode(1, 1022, kPositive) * Encode(1, 1022, kPositive));
  EXPECT_EQ(Encode(1, 22, kPositive),
            Encode(1, 1022, kPositive) * Encode(1, -1000, kPositive));
}

TEST_F(DecimalTest, MultiplicationSmallExponent) {
  EXPECT_EQ(Encode(1, -1022, kPositive),
            Encode(1, -1022, kPositive) * Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(0, 0, kPositive),
            Encode(1, -1022, kPositive) * Encode(1, -1022, kPositive));
}

TEST_F(DecimalTest, MultiplicationSpecialValues) {
  const Decimal infinity(Decimal::Infinity(kPositive));
  const Decimal minus_infinity(Decimal::Infinity(kNegative));
  const Decimal na_n(Decimal::Nan());
  const Decimal ten(10);
  const Decimal minus_ten(-10);
  const Decimal zero(Decimal::Zero(kPositive));
  const Decimal minus_zero(Decimal::Zero(kNegative));

  EXPECT_EQ(infinity, infinity * infinity);
  EXPECT_EQ(minus_infinity, infinity * minus_infinity);
  EXPECT_EQ(minus_infinity, minus_infinity * infinity);
  EXPECT_EQ(infinity, minus_infinity * minus_infinity);

  EXPECT_EQ(na_n, infinity * zero);
  EXPECT_EQ(na_n, zero * minus_infinity);
  EXPECT_EQ(na_n, minus_infinity * zero);
  EXPECT_EQ(na_n, minus_infinity * zero);

  EXPECT_EQ(na_n, infinity * minus_zero);
  EXPECT_EQ(na_n, minus_zero * minus_infinity);
  EXPECT_EQ(na_n, minus_infinity * minus_zero);
  EXPECT_EQ(na_n, minus_infinity * minus_zero);

  EXPECT_EQ(infinity, infinity * ten);
  EXPECT_EQ(infinity, ten * infinity);
  EXPECT_EQ(minus_infinity, minus_infinity * ten);
  EXPECT_EQ(minus_infinity, ten * minus_infinity);

  EXPECT_EQ(minus_infinity, infinity * minus_ten);
  EXPECT_EQ(minus_infinity, minus_ten * infinity);
  EXPECT_EQ(infinity, minus_infinity * minus_ten);
  EXPECT_EQ(infinity, minus_ten * minus_infinity);

  EXPECT_EQ(na_n, na_n * na_n);
  EXPECT_EQ(na_n, na_n * ten);
  EXPECT_EQ(na_n, ten * na_n);

  EXPECT_EQ(na_n, na_n * infinity);
  EXPECT_EQ(na_n, na_n * minus_infinity);
  EXPECT_EQ(na_n, infinity * na_n);
  EXPECT_EQ(na_n, minus_infinity * na_n);
}

TEST_F(DecimalTest, Negate) {
  EXPECT_EQ(Encode(0, 0, kNegative), -Encode(0, 0, kPositive));
  EXPECT_EQ(Encode(0, 0, kPositive), -Encode(0, 0, kNegative));

  EXPECT_EQ(Encode(0, 10, kNegative), -Encode(0, 10, kPositive));
  EXPECT_EQ(Encode(0, 10, kPositive), -Encode(0, 10, kNegative));

  EXPECT_EQ(Encode(0, -10, kNegative), -Encode(0, -10, kPositive));
  EXPECT_EQ(Encode(0, -10, kPositive), -Encode(0, -10, kNegative));

  EXPECT_EQ(Encode(1, 0, kNegative), -Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(1, 0, kPositive), -Encode(1, 0, kNegative));

  EXPECT_EQ(Encode(1, 10, kNegative), -Encode(1, 10, kPositive));
  EXPECT_EQ(Encode(1, 10, kPositive), -Encode(1, 10, kNegative));

  EXPECT_EQ(Encode(1, -10, kNegative), -Encode(1, -10, kPositive));
  EXPECT_EQ(Encode(1, -10, kPositive), -Encode(1, -10, kNegative));
}

TEST_F(DecimalTest, NegateBigExponent) {
  EXPECT_EQ(Encode(1, 1000, kNegative), -Encode(1, 1000, kPositive));
  EXPECT_EQ(Encode(1, 1000, kPositive), -Encode(1, 1000, kNegative));
}

TEST_F(DecimalTest, NegateSmallExponent) {
  EXPECT_EQ(Encode(1, -1000, kNegative), -Encode(1, -1000, kPositive));
  EXPECT_EQ(Encode(1, -1000, kPositive), -Encode(1, -1000, kNegative));
}

TEST_F(DecimalTest, NegateSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kNegative), -Decimal::Infinity(kPositive));
  EXPECT_EQ(Decimal::Infinity(kPositive), -Decimal::Infinity(kNegative));
  EXPECT_EQ(Decimal::Nan(), -Decimal::Nan());
}

TEST_F(DecimalTest, Predicates) {
  EXPECT_TRUE(Decimal::Zero(kPositive).IsFinite());
  EXPECT_FALSE(Decimal::Zero(kPositive).IsInfinity());
  EXPECT_FALSE(Decimal::Zero(kPositive).IsNaN());
  EXPECT_TRUE(Decimal::Zero(kPositive).IsPositive());
  EXPECT_FALSE(Decimal::Zero(kPositive).IsNegative());
  EXPECT_FALSE(Decimal::Zero(kPositive).IsSpecial());
  EXPECT_TRUE(Decimal::Zero(kPositive).IsZero());

  EXPECT_TRUE(Decimal::Zero(kNegative).IsFinite());
  EXPECT_FALSE(Decimal::Zero(kNegative).IsInfinity());
  EXPECT_FALSE(Decimal::Zero(kNegative).IsNaN());
  EXPECT_FALSE(Decimal::Zero(kNegative).IsPositive());
  EXPECT_TRUE(Decimal::Zero(kNegative).IsNegative());
  EXPECT_FALSE(Decimal::Zero(kNegative).IsSpecial());
  EXPECT_TRUE(Decimal::Zero(kNegative).IsZero());

  EXPECT_TRUE(Decimal(123).IsFinite());
  EXPECT_FALSE(Decimal(123).IsInfinity());
  EXPECT_FALSE(Decimal(123).IsNaN());
  EXPECT_TRUE(Decimal(123).IsPositive());
  EXPECT_FALSE(Decimal(123).IsNegative());
  EXPECT_FALSE(Decimal(123).IsSpecial());
  EXPECT_FALSE(Decimal(123).IsZero());

  EXPECT_TRUE(Decimal(-123).IsFinite());
  EXPECT_FALSE(Decimal(-123).IsInfinity());
  EXPECT_FALSE(Decimal(-123).IsNaN());
  EXPECT_FALSE(Decimal(-123).IsPositive());
  EXPECT_TRUE(Decimal(-123).IsNegative());
  EXPECT_FALSE(Decimal(-123).IsSpecial());
  EXPECT_FALSE(Decimal(-123).IsZero());
}

TEST_F(DecimalTest, PredicatesSpecialValues) {
  EXPECT_FALSE(Decimal::Infinity(kPositive).IsFinite());
  EXPECT_TRUE(Decimal::Infinity(kPositive).IsInfinity());
  EXPECT_FALSE(Decimal::Infinity(kPositive).IsNaN());
  EXPECT_TRUE(Decimal::Infinity(kPositive).IsPositive());
  EXPECT_FALSE(Decimal::Infinity(kPositive).IsNegative());
  EXPECT_TRUE(Decimal::Infinity(kPositive).IsSpecial());
  EXPECT_FALSE(Decimal::Infinity(kPositive).IsZero());

  EXPECT_FALSE(Decimal::Infinity(kNegative).IsFinite());
  EXPECT_TRUE(Decimal::Infinity(kNegative).IsInfinity());
  EXPECT_FALSE(Decimal::Infinity(kNegative).IsNaN());
  EXPECT_FALSE(Decimal::Infinity(kNegative).IsPositive());
  EXPECT_TRUE(Decimal::Infinity(kNegative).IsNegative());
  EXPECT_TRUE(Decimal::Infinity(kNegative).IsSpecial());
  EXPECT_FALSE(Decimal::Infinity(kNegative).IsZero());

  EXPECT_FALSE(Decimal::Nan().IsFinite());
  EXPECT_FALSE(Decimal::Nan().IsInfinity());
  EXPECT_TRUE(Decimal::Nan().IsNaN());
  EXPECT_TRUE(Decimal::Nan().IsSpecial());
  EXPECT_FALSE(Decimal::Nan().IsZero());
}

// web_tests/fast/forms/number/number-stepup-stepdown-from-renderer
TEST_F(DecimalTest, RealWorldExampleNumberStepUpStepDownFromRenderer) {
  EXPECT_EQ("10", StepDown("0", "100", "10", "19", 1).ToString());
  EXPECT_EQ("90", StepUp("0", "99", "10", "89", 1).ToString());
  EXPECT_EQ(
      "1",
      StepUp("0", "1", "0.33333333333333333", "0", 3).ToString());  // step=1/3
  EXPECT_EQ("0.01", StepUp("0", "0.01", "0.0033333333333333333", "0",
                           3)
                        .ToString());  // step=1/300
  EXPECT_EQ("1", StepUp("0", "1", "0.003921568627450980", "0", 255)
                     .ToString());  // step=1/255
  EXPECT_EQ("1", StepUp("0", "1", "0.1", "0", 10).ToString());
}

TEST_F(DecimalTest, RealWorldExampleNumberStepUpStepDownFromRendererRounding) {
  EXPECT_EQ("5.015", StepUp("0", "100", "0.005", "5.005", 2).ToString());
  EXPECT_EQ("5.06", StepUp("0", "100", "0.005", "5.005", 11).ToString());
  EXPECT_EQ("5.065", StepUp("0", "100", "0.005", "5.005", 12).ToString());

  EXPECT_EQ("5.015", StepUp("4", "9", "0.005", "5.005", 2).ToString());
  EXPECT_EQ("5.06", StepUp("4", "9", "0.005", "5.005", 11).ToString());
  EXPECT_EQ("5.065", StepUp("4", "9", "0.005", "5.005", 12).ToString());
}

TEST_F(DecimalTest, RealWorldExampleRangeStepUpStepDown) {
  EXPECT_EQ("1e+38", StepUp("0", "1E38", "1", "1E38", 9).ToString());
  EXPECT_EQ("1e+38", StepDown("0", "1E38", "1", "1E38", 9).ToString());
}

TEST_F(DecimalTest, Remainder) {
  EXPECT_EQ(Encode(21, -1, kPositive), Encode(21, -1, kPositive).Remainder(3));
  EXPECT_EQ(Decimal(1), Decimal(10).Remainder(3));
  EXPECT_EQ(Decimal(1), Decimal(10).Remainder(-3));
  EXPECT_EQ(Encode(1, 0, kNegative), Decimal(-10).Remainder(3));
  EXPECT_EQ(Decimal(-1), Decimal(-10).Remainder(-3));
  EXPECT_EQ(Encode(2, -1, kPositive), Encode(102, -1, kPositive).Remainder(1));
  EXPECT_EQ(Encode(1, -1, kPositive),
            Decimal(10).Remainder(Encode(3, -1, kPositive)));
  EXPECT_EQ(Decimal(1),
            Encode(36, -1, kPositive).Remainder(Encode(13, -1, kPositive)));
  EXPECT_EQ(Encode(1, 86, kPositive),
            (Encode(1234, 100, kPositive).Remainder(Decimal(3))));
  EXPECT_EQ(Decimal(500), (Decimal(500).Remainder(1000)));
  EXPECT_EQ(Decimal(-500), (Decimal(-500).Remainder(1000)));
}

TEST_F(DecimalTest, RemainderBigExponent) {
  EXPECT_EQ(Encode(0, 1022, kPositive),
            Encode(1, 1022, kPositive).Remainder(Encode(1, 0, kPositive)));
  EXPECT_EQ(Encode(0, 1022, kPositive),
            Encode(1, 1022, kPositive).Remainder(Encode(1, 1022, kPositive)));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Encode(1, 1022, kPositive).Remainder(Encode(1, -1000, kPositive)));
}

TEST_F(DecimalTest, RemainderSmallExponent) {
  EXPECT_EQ(Encode(1, -1022, kPositive),
            Encode(1, -1022, kPositive).Remainder(Encode(1, 0, kPositive)));
  EXPECT_EQ(Encode(0, -1022, kPositive),
            Encode(1, -1022, kPositive).Remainder(Encode(1, -1022, kPositive)));
}

TEST_F(DecimalTest, RemainderSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Decimal::Infinity(kPositive).Remainder(1));
  EXPECT_EQ(Decimal::Infinity(kNegative),
            Decimal::Infinity(kNegative).Remainder(1));
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Remainder(1));

  EXPECT_EQ(Decimal::Infinity(kNegative),
            Decimal::Infinity(kPositive).Remainder(-1));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Decimal::Infinity(kNegative).Remainder(-1));
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Remainder(-1));

  EXPECT_EQ(Decimal::Infinity(kPositive),
            Decimal::Infinity(kPositive).Remainder(3));
  EXPECT_EQ(Decimal::Infinity(kNegative),
            Decimal::Infinity(kNegative).Remainder(3));
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Remainder(3));

  EXPECT_EQ(Decimal::Infinity(kNegative),
            Decimal::Infinity(kPositive).Remainder(-1));
  EXPECT_EQ(Decimal::Infinity(kPositive),
            Decimal::Infinity(kNegative).Remainder(-1));
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Remainder(-1));

  EXPECT_EQ(Decimal::Nan(), Decimal(1).Remainder(Decimal::Infinity(kPositive)));
  EXPECT_EQ(Decimal::Nan(), Decimal(1).Remainder(Decimal::Infinity(kNegative)));
  EXPECT_EQ(Decimal::Nan(), Decimal(1).Remainder(Decimal::Nan()));
}

TEST_F(DecimalTest, Round) {
  EXPECT_EQ(Decimal(1), (Decimal(9) / Decimal(10)).Round());
  EXPECT_EQ(Decimal(25), (Decimal(5) / FromString("0.200")).Round());
  EXPECT_EQ(Decimal(3), (Decimal(5) / Decimal(2)).Round());
  EXPECT_EQ(Decimal(1), (Decimal(2) / Decimal(3)).Round());
  EXPECT_EQ(Decimal(3), (Decimal(10) / Decimal(3)).Round());
  EXPECT_EQ(Decimal(3), (Decimal(1) / FromString("0.3")).Round());
  EXPECT_EQ(Decimal(10), (Decimal(1) / FromString("0.1")).Round());
  EXPECT_EQ(Decimal(5), (Decimal(1) / FromString("0.2")).Round());
  EXPECT_EQ(Decimal(10), (FromString("10.2") / 1).Round());
  EXPECT_EQ(Encode(1234, 100, kPositive), Encode(1234, 100, kPositive).Round());

  EXPECT_EQ(Decimal(2), Encode(190002, -5, kPositive).Round());
  EXPECT_EQ(Decimal(2), Encode(150002, -5, kPositive).Round());
  EXPECT_EQ(Decimal(2), Encode(150000, -5, kPositive).Round());
  EXPECT_EQ(Decimal(12), Encode(12492, -3, kPositive).Round());
  EXPECT_EQ(Decimal(13), Encode(12502, -3, kPositive).Round());

  EXPECT_EQ(Decimal(-2), Encode(190002, -5, kNegative).Round());
  EXPECT_EQ(Decimal(-2), Encode(150002, -5, kNegative).Round());
  EXPECT_EQ(Decimal(-2), Encode(150000, -5, kNegative).Round());
  EXPECT_EQ(Decimal(-12), Encode(12492, -3, kNegative).Round());
  EXPECT_EQ(Decimal(-13), Encode(12502, -3, kNegative).Round());
}

TEST_F(DecimalTest, RoundSpecialValues) {
  EXPECT_EQ(Decimal::Infinity(kPositive), Decimal::Infinity(kPositive).Round());
  EXPECT_EQ(Decimal::Infinity(kNegative), Decimal::Infinity(kNegative).Round());
  EXPECT_EQ(Decimal::Nan(), Decimal::Nan().Round());
}

TEST_F(DecimalTest, Subtract) {
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(0) - Decimal(0));
  EXPECT_EQ(Encode(3, 0, kPositive), Decimal(2) - Decimal(-1));
  EXPECT_EQ(Encode(3, 0, kNegative), Decimal(-1) - Decimal(2));
  EXPECT_EQ(Encode(98, 0, kPositive), Decimal(99) - Decimal(1));
  EXPECT_EQ(Encode(0, 0, kPositive), Decimal(-50) - Decimal(-50));
  EXPECT_EQ(Encode(UINT64_C(1000000000000000), 35, kPositive),
            Encode(1, 50, kPositive) - Decimal(1));
  EXPECT_EQ(Encode(UINT64_C(1000000000000000), 35, kNegative),
            Decimal(1) - Encode(1, 50, kPositive));
}

TEST_F(DecimalTest, SubtractBigExponent) {
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) - Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(0, 0, kPositive),
            Encode(1, 1022, kPositive) - Encode(1, 1022, kPositive));
  EXPECT_EQ(Encode(1, 1022, kPositive),
            Encode(1, 1022, kPositive) + Encode(1, -1000, kPositive));
}

TEST_F(DecimalTest, SubtractSmallExponent) {
  EXPECT_EQ(Encode(UINT64_C(10000000000000000), -16, kNegative),
            Encode(1, -1022, kPositive) - Encode(1, 0, kPositive));
  EXPECT_EQ(Encode(0, 0, kPositive),
            Encode(1, -1022, kPositive) - Encode(1, -1022, kPositive));
}

TEST_F(DecimalTest, SubtractSpecialValues) {
  const Decimal infinity(Decimal::Infinity(kPositive));
  const Decimal minus_infinity(Decimal::Infinity(kNegative));
  const Decimal na_n(Decimal::Nan());
  const Decimal ten(10);

  EXPECT_EQ(na_n, infinity - infinity);
  EXPECT_EQ(infinity, infinity - minus_infinity);
  EXPECT_EQ(minus_infinity, minus_infinity - infinity);
  EXPECT_EQ(na_n, minus_infinity - minus_infinity);

  EXPECT_EQ(infinity, infinity - ten);
  EXPECT_EQ(minus_infinity, ten - infinity);
  EXPECT_EQ(minus_infinity, minus_infinity - ten);
  EXPECT_EQ(infinity, ten - minus_infinity);

  EXPECT_EQ(na_n, na_n - na_n);
  EXPECT_EQ(na_n, na_n - ten);
  EXPECT_EQ(na_n, ten - na_n);

  EXPECT_EQ(na_n, na_n - infinity);
  EXPECT_EQ(na_n, na_n - minus_infinity);
  EXPECT_EQ(na_n, infinity - na_n);
  EXPECT_EQ(na_n, minus_infinity - na_n);
}

TEST_F(DecimalTest, ToDouble) {
  EXPECT_EQ(0.0, Encode(0, 0, kPositive).ToDouble());
  EXPECT_EQ(-0.0, Encode(0, 0, kNegative).ToDouble());

  EXPECT_EQ(1.0, Encode(1, 0, kPositive).ToDouble());
  EXPECT_EQ(-1.0, Encode(1, 0, kNegative).ToDouble());

  EXPECT_EQ(0.1, Encode(1, -1, kPositive).ToDouble());
  EXPECT_EQ(-0.1, Encode(1, -1, kNegative).ToDouble());
  EXPECT_EQ(0.3, Encode(3, -1, kPositive).ToDouble());
  EXPECT_EQ(-0.3, Encode(3, -1, kNegative).ToDouble());
  EXPECT_EQ(0.6, Encode(6, -1, kPositive).ToDouble());
  EXPECT_EQ(-0.6, Encode(6, -1, kNegative).ToDouble());
  EXPECT_EQ(0.7, Encode(7, -1, kPositive).ToDouble());
  EXPECT_EQ(-0.7, Encode(7, -1, kNegative).ToDouble());

  EXPECT_EQ(0.01, Encode(1, -2, kPositive).ToDouble());
  EXPECT_EQ(0.001, Encode(1, -3, kPositive).ToDouble());
  EXPECT_EQ(0.0001, Encode(1, -4, kPositive).ToDouble());
  EXPECT_EQ(0.00001, Encode(1, -5, kPositive).ToDouble());

  EXPECT_EQ(1e+308, Encode(1, 308, kPositive).ToDouble());
  EXPECT_EQ(1e-307, Encode(1, -307, kPositive).ToDouble());

  EXPECT_TRUE(std::isinf(Encode(1, 1000, kPositive).ToDouble()));
  EXPECT_EQ(0.0, Encode(1, -1000, kPositive).ToDouble());
}

TEST_F(DecimalTest, ToDoubleSpecialValues) {
  EXPECT_TRUE(std::isinf(Decimal::Infinity(Decimal::kPositive).ToDouble()));
  EXPECT_TRUE(std::isinf(Decimal::Infinity(Decimal::kNegative).ToDouble()));
  EXPECT_TRUE(std::isnan(Decimal::Nan().ToDouble()));
}

TEST_F(DecimalTest, ToString) {
  EXPECT_EQ("0", Decimal::Zero(kPositive).ToString());
  EXPECT_EQ("-0", Decimal::Zero(kNegative).ToString());
  EXPECT_EQ("1", Decimal(1).ToString());
  EXPECT_EQ("-1", Decimal(-1).ToString());
  EXPECT_EQ("1234567", Decimal(1234567).ToString());
  EXPECT_EQ("-1234567", Decimal(-1234567).ToString());
  EXPECT_EQ("0.5", Encode(5, -1, kPositive).ToString());
  EXPECT_EQ("-0.5", Encode(5, -1, kNegative).ToString());
  EXPECT_EQ("12.345", Encode(12345, -3, kPositive).ToString());
  EXPECT_EQ("-12.345", Encode(12345, -3, kNegative).ToString());
  EXPECT_EQ("0.12345", Encode(12345, -5, kPositive).ToString());
  EXPECT_EQ("-0.12345", Encode(12345, -5, kNegative).ToString());
  EXPECT_EQ("50", Encode(50, 0, kPositive).ToString());
  EXPECT_EQ("-50", Encode(50, 0, kNegative).ToString());
  EXPECT_EQ("5e+1", Encode(5, 1, kPositive).ToString());
  EXPECT_EQ("-5e+1", Encode(5, 1, kNegative).ToString());
  EXPECT_EQ("5.678e+103", Encode(5678, 100, kPositive).ToString());
  EXPECT_EQ("-5.678e+103", Encode(5678, 100, kNegative).ToString());
  EXPECT_EQ("5.678e-97", Encode(5678, -100, kPositive).ToString());
  EXPECT_EQ("-5.678e-97", Encode(5678, -100, kNegative).ToString());
  EXPECT_EQ("8639999913600001",
            Encode(UINT64_C(8639999913600001), 0, kPositive).ToString());
  EXPECT_EQ("9007199254740991",
            Encode((static_cast<uint64_t>(1) << DBL_MANT_DIG) - 1, 0, kPositive)
                .ToString());
  EXPECT_EQ("99999999999999999",
            Encode(UINT64_C(99999999999999999), 0, kPositive).ToString());
  EXPECT_EQ("9.9999999999999999e+17",
            Encode(UINT64_C(99999999999999999), 1, kPositive).ToString());
  EXPECT_EQ("9.9999999999999999e+18",
            Encode(UINT64_C(99999999999999999), 2, kPositive).ToString());
  EXPECT_EQ("1e+16",
            Encode(UINT64_C(99999999999999999), -1, kPositive).ToString());
  EXPECT_EQ("1000000000000000",
            Encode(UINT64_C(99999999999999999), -2, kPositive).ToString());
  EXPECT_EQ("1",
            Encode(UINT64_C(99999999999999999), -17, kPositive).ToString());
  EXPECT_EQ("0.001",
            Encode(UINT64_C(99999999999999999), -20, kPositive).ToString());
  EXPECT_EQ("1e-83",
            Encode(UINT64_C(99999999999999999), -100, kPositive).ToString());
}

TEST_F(DecimalTest, ToStringSpecialValues) {
  EXPECT_EQ("Infinity", Decimal::Infinity(kPositive).ToString());
  EXPECT_EQ("-Infinity", Decimal::Infinity(kNegative).ToString());
  EXPECT_EQ("NaN", Decimal::Nan().ToString());
}

}  // namespace blink

"""

```