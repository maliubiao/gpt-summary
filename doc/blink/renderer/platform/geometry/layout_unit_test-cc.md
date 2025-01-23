Response:
My thinking process to analyze the C++ test file and provide the requested information goes through these stages:

1. **Understand the Core Purpose:**  The file name `layout_unit_test.cc` immediately suggests this is a unit test file. The directory `blink/renderer/platform/geometry/` indicates it's testing code related to layout and geometry within the Blink rendering engine. The `LayoutUnit` part likely refers to a specific class or concept being tested.

2. **Identify Key Classes Under Test:**  The `#include` directives confirm that `LayoutUnit` is the primary class. The `template <class T> class LayoutUnitTypedTest : public testing::Test {};` and `using LayoutUnitTypes = ::testing::Types<LayoutUnit, TextRunLayoutUnit, InlineLayoutUnit>;` tell me that `TextRunLayoutUnit` and `InlineLayoutUnit` are also related and being tested, potentially through inheritance or composition.

3. **Analyze Individual Test Cases (Mental Walkthrough):** I go through each `TEST()` or `TYPED_TEST()` block and try to understand what aspect of the classes it's verifying. I look for:
    * **Function names:**  Like `ToInt()`, `ToFloat()`, `FromFloatCeil()`, `Round()`, `SnapSizeToPixel()`, operators (+, -, *, /), `Ceil()`, `Floor()`, etc. These directly indicate the methods being tested.
    * **Assertions:** `EXPECT_EQ()`, `EXPECT_FLOAT_EQ()`, `EXPECT_NEAR()`. These show the expected outcomes of the tested methods.
    * **Test data:** The numerical values used as input to the methods. I pay attention to edge cases like `INT_MIN`, `INT_MAX`, floating-point numbers, and specific fractional values.
    * **Test setup:** How are the objects of `LayoutUnit`, `TextRunLayoutUnit`, and `InlineLayoutUnit` created and manipulated before the assertions.

4. **Group Functionality:** Based on the individual tests, I categorize the functionality being tested:
    * **Integer Conversion:** Testing conversion to `int` and handling of overflow/underflow.
    * **Float Conversion:** Testing conversion to `float` with precision considerations.
    * **Construction:** Testing various constructor forms (from `int`, `float`, raw values).
    * **Rounding:** Testing `Ceil()`, `Floor()`, `Round()`, and `FromFloat*()` methods.
    * **Pixel Snapping:** Testing the `SnapSizeToPixel()` function.
    * **Arithmetic Operations:** Testing operators like `+`, `-`, `*`, `/`.
    * **Comparison (Implicit):** Although not explicit tests, the arithmetic tests implicitly verify the correct behavior of comparison operators.
    * **Fixed-Point Representation:** Observing the tests related to `kFractionalBits` and raw values.
    * **Type Conversions:** Testing conversions between `LayoutUnit`, `TextRunLayoutUnit`, and `InlineLayoutUnit`.
    * **Edge Cases:** Tests involving `NaN`, infinity, and min/max values.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):** This requires understanding how layout units are used in web rendering.
    * **HTML:**  HTML elements have dimensions (width, height, margins, padding) that are ultimately represented in layout units.
    * **CSS:** CSS properties like `width`, `height`, `margin`, `padding`, `font-size`, `line-height`, etc., often take values that are translated into layout units for internal calculations. Pixel values in CSS are a common example.
    * **JavaScript:** JavaScript can manipulate the styles of HTML elements, which involves changing the underlying layout units. Methods like `element.offsetWidth`, `element.offsetHeight`, `element.getBoundingClientRect()` return values based on layout calculations.

6. **Provide Concrete Examples:**  To illustrate the relationship with web technologies, I create simple HTML/CSS/JS snippets demonstrating how the concepts tested in the C++ code manifest in the browser. For instance, showing how a CSS `width: 10.5px;` might involve the kind of rounding or fixed-point arithmetic being tested.

7. **Address Logic and Assumptions:**  When a test performs logical operations (like checking for saturation or overflow), I try to extract the underlying assumptions and the expected inputs and outputs. For example, the tests around `LayoutUnit::kIntMax` and `LayoutUnit::kIntMin` are about handling boundary conditions.

8. **Identify Potential User/Programming Errors:**  Based on the tests, I deduce common mistakes a developer might make:
    * **Assuming exact floating-point representation:** The tests around `kTolerance` highlight that floating-point to fixed-point conversions involve precision loss.
    * **Integer overflow/underflow:** The tests with `INT_MAX` and `INT_MIN` show the importance of handling these limits.
    * **Incorrect rounding:** The various rounding tests demonstrate how different rounding methods can yield different results.

9. **Structure the Output:**  I organize the information clearly with headings and bullet points to make it easy to read and understand. I follow the specific instructions in the prompt (listing functionalities, relating to web technologies, providing examples, etc.).

10. **Refine and Review:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure I've addressed all parts of the prompt. I check for any logical inconsistencies or areas where I could provide more detail or better examples.
这个C++源代码文件 `layout_unit_test.cc` 是 Chromium Blink 渲染引擎的一部分，它的主要功能是**测试 `LayoutUnit` 类及其相关类型 (`TextRunLayoutUnit`, `InlineLayoutUnit`) 的各种功能和边界情况。** 这些类在 Blink 引擎中用于表示布局计算中的长度和尺寸，是进行网页排版和渲染的基础。

以下是该文件功能的详细列举，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及可能的逻辑推理和常见使用错误：

**文件功能列举：**

1. **测试 `LayoutUnit` 的基本属性和构造：**
   - 测试从 `int` 类型创建 `LayoutUnit` 对象，并验证 `ToInt()` 方法的正确性，包括对 `INT_MIN` 和 `INT_MAX` 等边界值的处理。
   - 测试从 `unsigned int` 类型创建 `LayoutUnit` 对象。
   - 测试从 `int64_t` 和 `uint64_t` 类型创建 `LayoutUnit` 对象，并验证是否正确处理超出 `int` 范围的值。
   - 测试从 `float` 类型创建 `LayoutUnit` 对象，并验证 `ToFloat()` 方法的精度和对极大/极小浮点数的处理，以及 `NaN` 值的处理。
   - 测试 `constexpr` 构造函数是否为常量表达式。
   - 测试 `Min()` 和 `Max()` 静态方法的正确性。

2. **测试 `LayoutUnit` 的舍入功能：**
   - 测试 `FromFloatCeil()`：从浮点数创建 `LayoutUnit` 并向上取整。
   - 测试 `FromFloatFloor()`：从浮点数创建 `LayoutUnit` 并向下取整。
   - 测试 `FromFloatRound()`：从浮点数创建 `LayoutUnit` 并四舍五入。
   - 测试 `Round()`：对 `LayoutUnit` 对象进行四舍五入到最接近的整数。

3. **测试像素对齐功能：**
   - 测试 `SnapSizeToPixel()` 函数，该函数用于将布局尺寸对齐到像素边界，考虑了亚像素偏移。

4. **测试算术运算：**
   - 测试 `LayoutUnit` 之间的乘法运算 (`*`)，包括正数、负数和浮点数的乘法，以及与 `size_t` 类型的乘法。同时测试了乘法溢出的处理。
   - 测试 `LayoutUnit` 与整数之间的乘法运算。
   - 测试 `LayoutUnit` 之间的除法运算 (`/`)，包括正数、负数和浮点数的除法，以及与 `size_t` 类型的除法。
   - 测试 `LayoutUnit` 与整数之间的除法运算。
   - 测试 `MulDiv()` 函数，该函数执行 `(a * b) / c` 的操作，并能更精确地处理中间结果，避免过早的溢出或精度损失。

5. **测试取整函数：**
   - 测试 `Ceil()`：向上取整到最接近的整数。
   - 测试 `Floor()`：向下取整到最接近的整数。

6. **测试浮点数溢出到 `LayoutUnit` 的处理：**
   - 验证当浮点数超出 `LayoutUnit` 的表示范围时，是否正确地饱和到 `kIntMax` 或 `kIntMin`。

7. **测试一元负号运算符 (`-`)：**
   - 测试对 `LayoutUnit` 对象取负号的正确性，包括对 `Min()` 和 `Max()` 值的处理。

8. **测试自增运算符 (`++`)：**
   - 测试 `LayoutUnit` 对象的自增操作。

9. **测试取模运算 (`IntMod`)：**
   - 测试 `IntMod()` 函数，该函数执行整数取模运算，并处理正负数和浮点数的情况。

10. **测试是否包含小数部分 (`HasFraction`)：**
    - 验证 `HasFraction()` 方法能否正确判断 `LayoutUnit` 是否包含小数部分。

11. **测试固定点表示的常量：**
    - 验证 `kFractionalBits` 和 `kIntegralBits` 等常量的值，这些常量定义了 `LayoutUnit` 的固定点精度。

12. **测试不同精度固定点类型之间的转换：**
    - 测试 `LayoutUnit`、`TextRunLayoutUnit` 和 `InlineLayoutUnit` 之间的相互转换，以及精度损失和饱和处理。

**与 JavaScript, HTML, CSS 的关系举例说明：**

- **CSS 中的长度单位 (例如 `px`, `em`, `rem`)：** 当浏览器解析 CSS 样式时，像 `width: 100px;` 这样的声明，`100px` 这个值会被转换成 `LayoutUnit` 对象进行内部的布局计算。`LayoutUnit` 负责存储和操作这些布局尺寸。
    - **假设输入 (CSS):** `width: 10.5px;`
    - **内部处理 (C++):**  `LayoutUnit::FromFloatRound(10.5f)` 可能会被调用来创建一个表示该宽度的 `LayoutUnit` 对象。测试用例中关于 `FromFloatRound` 的测试就验证了这种转换的正确性。

- **HTML 元素的尺寸和位置：** JavaScript 可以通过 DOM API 获取和设置 HTML 元素的尺寸和位置，例如 `element.offsetWidth` 和 `element.style.width`。这些属性的值最终都与 `LayoutUnit` 相关。
    - **假设输入 (JavaScript):**  `element.style.width = '50.7px';`
    - **内部处理 (C++):**  Blink 引擎会将字符串 `'50.7px'` 解析并转换为一个 `LayoutUnit` 对象。测试用例中对浮点数到 `LayoutUnit` 的转换测试确保了这种转换的准确性。

- **JavaScript 获取元素的布局信息：**  `element.getBoundingClientRect()` 方法返回一个对象，包含了元素的尺寸和相对于视口的位置。这些尺寸信息在 Blink 内部是用 `LayoutUnit` 进行计算和存储的。
    - **假设场景:** 一个元素的 CSS `width` 设置为 `100.3px`。
    - **内部计算:** Blink 使用 `LayoutUnit(100.3f)` 来表示这个宽度。
    - **输出 (JavaScript):** 当 JavaScript 调用 `element.getBoundingClientRect().width` 时，Blink 会将内部的 `LayoutUnit` 值转换回浮点数并返回 (可能需要考虑精度问题，这正是测试用例中 `ToFloat()` 测试的目的)。

**逻辑推理的假设输入与输出举例：**

- **测试像素对齐 (`SnapSizeToPixel`)：**
    - **假设输入:**  `SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0.49))`
    - **逻辑推理:**  原始尺寸是 1.5 个布局单元，亚像素偏移是 0.49。由于偏移小于 0.5，因此尺寸会向下舍入到最近的整数像素。
    - **预期输出:** `1`

- **测试乘法溢出：**
    - **假设输入:** `LayoutUnit(LayoutUnit::kIntMax / 4) * LayoutUnit(5)`
    - **逻辑推理:**  四分之一的 `kIntMax` 乘以 5 会超过 `kIntMax` 的表示范围，应该饱和到 `kIntMax`。
    - **预期输出:** `LayoutUnit::kIntMax`

**涉及用户或者编程常见的使用错误举例说明：**

1. **精度丢失：** 当在 JavaScript 中操作浮点数样式的像素值，并期望它能完全精确地反映到 Blink 的内部 `LayoutUnit` 时，可能会遇到精度丢失的问题。`LayoutUnit` 使用固定点数表示，从浮点数转换到固定点数会有舍入。
   - **用户错误示例 (JavaScript):**
     ```javascript
     element.style.width = '10.3px';
     console.log(element.offsetWidth); // 可能输出 10 而不是期望的 10.3
     ```
   - **原因:**  `10.3px` 在转换为 `LayoutUnit` 时可能被舍入为 `10`。

2. **假设浮点数运算的精确性：** 开发者可能会在 JavaScript 中进行一些浮点数计算，然后将其赋值给 CSS 属性，并期望 Blink 能完全按照这些浮点数进行布局。但由于内部使用固定点数，直接传递浮点数可能不会得到期望的精确结果。
   - **用户错误示例 (JavaScript):**
     ```javascript
     let width = 10.1 + 0.2; // width 的浮点数表示可能不是精确的 10.3
     element.style.width = width + 'px';
     ```
   - **原因:** 浮点数加法可能存在精度问题，最终传递给 Blink 的值可能略有偏差。

3. **忽略像素对齐的影响：** 在某些情况下，开发者可能没有考虑到浏览器的像素对齐机制，导致元素尺寸或位置出现细微的偏差。`SnapSizeToPixel` 测试的就是 Blink 如何处理这种情况。
   - **用户错误示例 (CSS/JavaScript):**  通过 JavaScript 精确地设置一个带有浮点数像素值的元素的 `left` 属性，但没有意识到浏览器可能会将其对齐到最近的物理像素。

4. **整数溢出：** 虽然 `LayoutUnit` 内部会处理溢出，但在进行涉及 `LayoutUnit` 的计算时，开发者仍然可能在 JavaScript 或 C++ 代码中遇到整数溢出的问题，尤其是在进行大量的乘法或加法运算时。`LayoutUnit` 的测试用例中对溢出的测试提醒了开发者注意这些边界情况。

总结来说，`layout_unit_test.cc` 文件是 Blink 引擎中至关重要的一个测试文件，它确保了用于网页布局计算的核心数据类型 `LayoutUnit` 及其相关类型的功能正确性和鲁棒性。这直接关系到网页在浏览器中的最终渲染效果和用户体验。通过详尽的测试用例，开发者可以避免因数值表示和运算错误而导致的各种布局问题。

### 提示词
```
这是目录为blink/renderer/platform/geometry/layout_unit_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2012, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/geometry/layout_unit.h"

#include <limits.h>
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {

template <class T>
class LayoutUnitTypedTest : public testing::Test {};
using LayoutUnitTypes =
    ::testing::Types<LayoutUnit, TextRunLayoutUnit, InlineLayoutUnit>;
TYPED_TEST_SUITE(LayoutUnitTypedTest, LayoutUnitTypes);

TEST(LayoutUnitTest, LayoutUnitInt) {
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(INT_MIN).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(INT_MIN / 2).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(LayoutUnit::kIntMin - 1).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(LayoutUnit::kIntMin).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin + 1,
            LayoutUnit(LayoutUnit::kIntMin + 1).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin / 2,
            LayoutUnit(LayoutUnit::kIntMin / 2).ToInt());
  EXPECT_EQ(-10000, LayoutUnit(-10000).ToInt());
  EXPECT_EQ(-1000, LayoutUnit(-1000).ToInt());
  EXPECT_EQ(-100, LayoutUnit(-100).ToInt());
  EXPECT_EQ(-10, LayoutUnit(-10).ToInt());
  EXPECT_EQ(-1, LayoutUnit(-1).ToInt());
  EXPECT_EQ(0, LayoutUnit(0).ToInt());
  EXPECT_EQ(1, LayoutUnit(1).ToInt());
  EXPECT_EQ(100, LayoutUnit(100).ToInt());
  EXPECT_EQ(1000, LayoutUnit(1000).ToInt());
  EXPECT_EQ(10000, LayoutUnit(10000).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax / 2,
            LayoutUnit(LayoutUnit::kIntMax / 2).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax - 1,
            LayoutUnit(LayoutUnit::kIntMax - 1).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(LayoutUnit::kIntMax).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(LayoutUnit::kIntMax + 1).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(INT_MAX / 2).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(INT_MAX).ToInt());

  // Test the raw unsaturated value
  EXPECT_EQ(0, LayoutUnit(0).RawValue());
  // Internally the max number we can represent (without saturating)
  // is all the (non-sign) bits set except for the bottom n fraction bits
  const int max_internal_representation =
      std::numeric_limits<int>::max() ^
      ((1 << LayoutUnit::kFractionalBits) - 1);
  EXPECT_EQ(max_internal_representation,
            LayoutUnit(LayoutUnit::kIntMax).RawValue());
  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(),
            LayoutUnit(LayoutUnit::kIntMax + 100).RawValue());
  EXPECT_EQ((LayoutUnit::kIntMax - 100) << LayoutUnit::kFractionalBits,
            LayoutUnit(LayoutUnit::kIntMax - 100).RawValue());
  EXPECT_EQ(GetMinSaturatedSetResultForTesting(),
            LayoutUnit(LayoutUnit::kIntMin).RawValue());
  EXPECT_EQ(GetMinSaturatedSetResultForTesting(),
            LayoutUnit(LayoutUnit::kIntMin - 100).RawValue());
  // Shifting negative numbers left has undefined behavior, so use
  // multiplication instead of direct shifting here.
  EXPECT_EQ((LayoutUnit::kIntMin + 100) * (1 << LayoutUnit::kFractionalBits),
            LayoutUnit(LayoutUnit::kIntMin + 100).RawValue());
}

TEST(LayoutUnitTest, LayoutUnitUnsigned) {
  // Test the raw unsaturated value
  EXPECT_EQ(0, LayoutUnit((unsigned)0).RawValue());
  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(),
            LayoutUnit((unsigned)LayoutUnit::kIntMax).RawValue());
  const unsigned kOverflowed = LayoutUnit::kIntMax + 100;
  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(),
            LayoutUnit(kOverflowed).RawValue());
  const unsigned kNotOverflowed = LayoutUnit::kIntMax - 100;
  EXPECT_EQ((LayoutUnit::kIntMax - 100) << LayoutUnit::kFractionalBits,
            LayoutUnit(kNotOverflowed).RawValue());
}

TEST(LayoutUnitTest, Int64) {
  constexpr int raw_min = std::numeric_limits<int>::min();
  EXPECT_EQ(LayoutUnit(static_cast<int64_t>(raw_min) - 100), LayoutUnit::Min());

  constexpr int raw_max = std::numeric_limits<int>::max();
  EXPECT_EQ(LayoutUnit(static_cast<int64_t>(raw_max) + 100), LayoutUnit::Max());
  EXPECT_EQ(LayoutUnit(static_cast<uint64_t>(raw_max) + 100),
            LayoutUnit::Max());
}

TEST(LayoutUnitTest, LayoutUnitFloat) {
  const float kTolerance = 1.0f / LayoutUnit::kFixedPointDenominator;
  EXPECT_FLOAT_EQ(1.0f, LayoutUnit(1.0f).ToFloat());
  EXPECT_FLOAT_EQ(1.25f, LayoutUnit(1.25f).ToFloat());
  EXPECT_EQ(LayoutUnit(1.25f), LayoutUnit(1.25f + kTolerance / 2));
  EXPECT_EQ(LayoutUnit(-2.0f), LayoutUnit(-2.0f - kTolerance / 2));
  EXPECT_NEAR(LayoutUnit(1.1f).ToFloat(), 1.1f, kTolerance);
  EXPECT_NEAR(LayoutUnit(1.33f).ToFloat(), 1.33f, kTolerance);
  EXPECT_NEAR(LayoutUnit(1.3333f).ToFloat(), 1.3333f, kTolerance);
  EXPECT_NEAR(LayoutUnit(1.53434f).ToFloat(), 1.53434f, kTolerance);
  EXPECT_NEAR(LayoutUnit(345634).ToFloat(), 345634.0f, kTolerance);
  EXPECT_NEAR(LayoutUnit(345634.12335f).ToFloat(), 345634.12335f, kTolerance);
  EXPECT_NEAR(LayoutUnit(-345634.12335f).ToFloat(), -345634.12335f, kTolerance);
  EXPECT_NEAR(LayoutUnit(-345634).ToFloat(), -345634.0f, kTolerance);

  using Limits = std::numeric_limits<float>;
  // Larger than Max()
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit(Limits::max()));
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit(Limits::infinity()));
  // Smaller than Min()
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit(Limits::lowest()));
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit(-Limits::infinity()));

  EXPECT_EQ(LayoutUnit(), LayoutUnit::Clamp(Limits::quiet_NaN()));
}

// Test that `constexpr` constructors are constant expressions.
TEST(LayoutUnitTest, ConstExprCtor) {
  [[maybe_unused]] constexpr LayoutUnit from_int(1);
  [[maybe_unused]] constexpr LayoutUnit from_float(1.0f);
  [[maybe_unused]] constexpr LayoutUnit from_raw = LayoutUnit::FromRawValue(1);
  [[maybe_unused]] constexpr LayoutUnit from_raw_with_clamp =
      LayoutUnit::FromRawValueWithClamp(1);
}

TEST(LayoutUnitTest, FromFloatCeil) {
  const float kTolerance = 1.0f / LayoutUnit::kFixedPointDenominator;
  EXPECT_EQ(LayoutUnit(1.25f), LayoutUnit::FromFloatCeil(1.25f));
  EXPECT_EQ(LayoutUnit(1.25f + kTolerance),
            LayoutUnit::FromFloatCeil(1.25f + kTolerance / 2));
  EXPECT_EQ(LayoutUnit(), LayoutUnit::FromFloatCeil(-kTolerance / 2));

  using Limits = std::numeric_limits<float>;
  // Larger than Max()
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatCeil(Limits::max()));
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatCeil(Limits::infinity()));
  // Smaller than Min()
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatCeil(Limits::lowest()));
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatCeil(-Limits::infinity()));

  EXPECT_EQ(LayoutUnit(), LayoutUnit::FromFloatCeil(Limits::quiet_NaN()));
}

TEST(LayoutUnitTest, FromFloatFloor) {
  const float kTolerance = 1.0f / LayoutUnit::kFixedPointDenominator;
  EXPECT_EQ(LayoutUnit(1.25f), LayoutUnit::FromFloatFloor(1.25f));
  EXPECT_EQ(LayoutUnit(1.25f),
            LayoutUnit::FromFloatFloor(1.25f + kTolerance / 2));
  EXPECT_EQ(LayoutUnit(-kTolerance),
            LayoutUnit::FromFloatFloor(-kTolerance / 2));

  using Limits = std::numeric_limits<float>;
  // Larger than Max()
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatFloor(Limits::max()));
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatFloor(Limits::infinity()));
  // Smaller than Min()
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatFloor(Limits::lowest()));
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatFloor(-Limits::infinity()));

  EXPECT_EQ(LayoutUnit(), LayoutUnit::FromFloatFloor(Limits::quiet_NaN()));
}

TEST(LayoutUnitTest, FromFloatRound) {
  const float kTolerance = 1.0f / LayoutUnit::kFixedPointDenominator;
  EXPECT_EQ(LayoutUnit(1.25f), LayoutUnit::FromFloatRound(1.25f));
  EXPECT_EQ(LayoutUnit(1.25f),
            LayoutUnit::FromFloatRound(1.25f + kTolerance / 4));
  EXPECT_EQ(LayoutUnit(1.25f + kTolerance),
            LayoutUnit::FromFloatRound(1.25f + kTolerance * 3 / 4));
  EXPECT_EQ(LayoutUnit(-kTolerance),
            LayoutUnit::FromFloatRound(-kTolerance * 3 / 4));

  using Limits = std::numeric_limits<float>;
  // Larger than Max()
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatRound(Limits::max()));
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit::FromFloatRound(Limits::infinity()));
  // Smaller than Min()
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatRound(Limits::lowest()));
  EXPECT_EQ(LayoutUnit::Min(), LayoutUnit::FromFloatRound(-Limits::infinity()));

  EXPECT_EQ(LayoutUnit(), LayoutUnit::FromFloatRound(Limits::quiet_NaN()));
}

TEST(LayoutUnitTest, LayoutUnitRounding) {
  EXPECT_EQ(-2, LayoutUnit(-1.9f).Round());
  EXPECT_EQ(-2, LayoutUnit(-1.6f).Round());
  EXPECT_EQ(-2, LayoutUnit::FromFloatRound(-1.51f).Round());
  EXPECT_EQ(-1, LayoutUnit::FromFloatRound(-1.5f).Round());
  EXPECT_EQ(-1, LayoutUnit::FromFloatRound(-1.49f).Round());
  EXPECT_EQ(-1, LayoutUnit(-1.0f).Round());
  EXPECT_EQ(-1, LayoutUnit::FromFloatRound(-0.99f).Round());
  EXPECT_EQ(-1, LayoutUnit::FromFloatRound(-0.51f).Round());
  EXPECT_EQ(0, LayoutUnit::FromFloatRound(-0.50f).Round());
  EXPECT_EQ(0, LayoutUnit::FromFloatRound(-0.49f).Round());
  EXPECT_EQ(0, LayoutUnit(-0.1f).Round());
  EXPECT_EQ(0, LayoutUnit(0.0f).Round());
  EXPECT_EQ(0, LayoutUnit(0.1f).Round());
  EXPECT_EQ(0, LayoutUnit::FromFloatRound(0.49f).Round());
  EXPECT_EQ(1, LayoutUnit::FromFloatRound(0.50f).Round());
  EXPECT_EQ(1, LayoutUnit::FromFloatRound(0.51f).Round());
  EXPECT_EQ(1, LayoutUnit(0.99f).Round());
  EXPECT_EQ(1, LayoutUnit(1.0f).Round());
  EXPECT_EQ(1, LayoutUnit::FromFloatRound(1.49f).Round());
  EXPECT_EQ(2, LayoutUnit::FromFloatRound(1.5f).Round());
  EXPECT_EQ(2, LayoutUnit::FromFloatRound(1.51f).Round());
  // The fractional part of LayoutUnit::Max() is 0x3f, so it should round up.
  EXPECT_EQ(
      ((std::numeric_limits<int>::max() / LayoutUnit::kFixedPointDenominator) +
       1),
      LayoutUnit::Max().Round());
  // The fractional part of LayoutUnit::Min() is 0, so the next bigger possible
  // value should round down.
  LayoutUnit epsilon;
  epsilon.SetRawValue(1);
  EXPECT_EQ(
      ((std::numeric_limits<int>::min() / LayoutUnit::kFixedPointDenominator)),
      (LayoutUnit::Min() + epsilon).Round());
}

TEST(LayoutUnitTest, LayoutUnitSnapSizeToPixel) {
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1), LayoutUnit(0)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1), LayoutUnit(0.5)));
  EXPECT_EQ(2, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0)));
  EXPECT_EQ(2, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0.49)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0.5)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0.75)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(0.99)));
  EXPECT_EQ(2, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(1)));

  // 0.046875 is 3/64, lower than 4 * LayoutUnit::Epsilon()
  EXPECT_EQ(0, SnapSizeToPixel(LayoutUnit(0.046875), LayoutUnit(0)));
  // 0.078125 is 5/64, higher than 4 * LayoutUnit::Epsilon()
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(0.078125), LayoutUnit(0)));

  // Negative versions
  EXPECT_EQ(0, SnapSizeToPixel(LayoutUnit(-0.046875), LayoutUnit(0)));
  EXPECT_EQ(-1, SnapSizeToPixel(LayoutUnit(-0.078125), LayoutUnit(0)));

  // The next 2 would snap to zero but for the requirement that we not snap
  // sizes greater than 4 * LayoutUnit::Epsilon() to 0.
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(0.5), LayoutUnit(1.5)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(0.99), LayoutUnit(1.5)));

  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.0), LayoutUnit(1.5)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.49), LayoutUnit(1.5)));
  EXPECT_EQ(1, SnapSizeToPixel(LayoutUnit(1.5), LayoutUnit(1.5)));

  EXPECT_EQ(101, SnapSizeToPixel(LayoutUnit(100.5), LayoutUnit(100)));
  EXPECT_EQ(LayoutUnit::kIntMax,
            SnapSizeToPixel(LayoutUnit(LayoutUnit::kIntMax), LayoutUnit(0.3)));
  EXPECT_EQ(LayoutUnit::kIntMin,
            SnapSizeToPixel(LayoutUnit(LayoutUnit::kIntMin), LayoutUnit(-0.3)));
}

TEST(LayoutUnitTest, LayoutUnitMultiplication) {
  EXPECT_EQ(1, (LayoutUnit(1) * LayoutUnit(1)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(1) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(2) * LayoutUnit(1)).ToInt());
  EXPECT_EQ(1, (LayoutUnit(2) * LayoutUnit(0.5)).ToInt());
  EXPECT_EQ(1, (LayoutUnit(0.5) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(100, (LayoutUnit(100) * LayoutUnit(1)).ToInt());

  EXPECT_EQ(-1, (LayoutUnit(-1) * LayoutUnit(1)).ToInt());
  EXPECT_EQ(-2, (LayoutUnit(-1) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(-2, (LayoutUnit(-2) * LayoutUnit(1)).ToInt());
  EXPECT_EQ(-1, (LayoutUnit(-2) * LayoutUnit(0.5)).ToInt());
  EXPECT_EQ(-1, (LayoutUnit(-0.5) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(-100, (LayoutUnit(-100) * LayoutUnit(1)).ToInt());

  EXPECT_EQ(1, (LayoutUnit(-1) * LayoutUnit(-1)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(-1) * LayoutUnit(-2)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(-2) * LayoutUnit(-1)).ToInt());
  EXPECT_EQ(1, (LayoutUnit(-2) * LayoutUnit(-0.5)).ToInt());
  EXPECT_EQ(1, (LayoutUnit(-0.5) * LayoutUnit(-2)).ToInt());
  EXPECT_EQ(100, (LayoutUnit(-100) * LayoutUnit(-1)).ToInt());

  EXPECT_EQ(333, (LayoutUnit(100) * LayoutUnit(3.33)).Round());
  EXPECT_EQ(-333, (LayoutUnit(-100) * LayoutUnit(3.33)).Round());
  EXPECT_EQ(333, (LayoutUnit(-100) * LayoutUnit(-3.33)).Round());

  size_t a_hundred_size_t = 100;
  EXPECT_EQ(100, (LayoutUnit(a_hundred_size_t) * LayoutUnit(1)).ToInt());
  EXPECT_EQ(400, (a_hundred_size_t * LayoutUnit(4)).ToInt());
  EXPECT_EQ(400, (LayoutUnit(4) * a_hundred_size_t).ToInt());

  int quarter_max = LayoutUnit::kIntMax / 4;
  EXPECT_EQ(quarter_max * 2, (LayoutUnit(quarter_max) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(quarter_max * 3, (LayoutUnit(quarter_max) * LayoutUnit(3)).ToInt());
  EXPECT_EQ(quarter_max * 4, (LayoutUnit(quarter_max) * LayoutUnit(4)).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax,
            (LayoutUnit(quarter_max) * LayoutUnit(5)).ToInt());

  size_t overflow_int_size_t = LayoutUnit::kIntMax * 4;
  EXPECT_EQ(LayoutUnit::kIntMax,
            (LayoutUnit(overflow_int_size_t) * LayoutUnit(2)).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, (overflow_int_size_t * LayoutUnit(4)).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, (LayoutUnit(4) * overflow_int_size_t).ToInt());

  {
    // Multiple by float 1.0 can produce a different value.
    LayoutUnit source = LayoutUnit::FromRawValue(2147483009);
    EXPECT_NE(source, LayoutUnit(source * 1.0f));
    LayoutUnit updated = source;
    updated *= 1.0f;
    EXPECT_NE(source, updated);
  }
}

TYPED_TEST(LayoutUnitTypedTest, MultiplicationByInt) {
  const auto quarter_max = TypeParam::kIntMax / 4;
  EXPECT_EQ(TypeParam(quarter_max * 2), TypeParam(quarter_max) * 2);
  EXPECT_EQ(TypeParam(quarter_max * 3), TypeParam(quarter_max) * 3);
  EXPECT_EQ(TypeParam(quarter_max * 4), TypeParam(quarter_max) * 4);
  EXPECT_EQ(TypeParam::Max(), TypeParam(quarter_max) * 5);
}

TEST(LayoutUnitTest, LayoutUnitDivision) {
  EXPECT_EQ(1, (LayoutUnit(1) / LayoutUnit(1)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(1) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(2) / LayoutUnit(1)).ToInt());
  EXPECT_EQ(4, (LayoutUnit(2) / LayoutUnit(0.5)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(0.5) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(10, (LayoutUnit(100) / LayoutUnit(10)).ToInt());
  EXPECT_FLOAT_EQ(0.5f, (LayoutUnit(1) / LayoutUnit(2)).ToFloat());
  EXPECT_FLOAT_EQ(0.25f, (LayoutUnit(0.5) / LayoutUnit(2)).ToFloat());

  EXPECT_EQ(-1, (LayoutUnit(-1) / LayoutUnit(1)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(-1) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(-2, (LayoutUnit(-2) / LayoutUnit(1)).ToInt());
  EXPECT_EQ(-4, (LayoutUnit(-2) / LayoutUnit(0.5)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(-0.5) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(-10, (LayoutUnit(-100) / LayoutUnit(10)).ToInt());
  EXPECT_FLOAT_EQ(-0.5f, (LayoutUnit(-1) / LayoutUnit(2)).ToFloat());
  EXPECT_FLOAT_EQ(-0.25f, (LayoutUnit(-0.5) / LayoutUnit(2)).ToFloat());

  EXPECT_EQ(1, (LayoutUnit(-1) / LayoutUnit(-1)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(-1) / LayoutUnit(-2)).ToInt());
  EXPECT_EQ(2, (LayoutUnit(-2) / LayoutUnit(-1)).ToInt());
  EXPECT_EQ(4, (LayoutUnit(-2) / LayoutUnit(-0.5)).ToInt());
  EXPECT_EQ(0, (LayoutUnit(-0.5) / LayoutUnit(-2)).ToInt());
  EXPECT_EQ(10, (LayoutUnit(-100) / LayoutUnit(-10)).ToInt());
  EXPECT_FLOAT_EQ(0.5f, (LayoutUnit(-1) / LayoutUnit(-2)).ToFloat());
  EXPECT_FLOAT_EQ(0.25f, (LayoutUnit(-0.5) / LayoutUnit(-2)).ToFloat());

  size_t a_hundred_size_t = 100;
  EXPECT_EQ(50, (LayoutUnit(a_hundred_size_t) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(25, (a_hundred_size_t / LayoutUnit(4)).ToInt());
  EXPECT_EQ(4, (LayoutUnit(400) / a_hundred_size_t).ToInt());

  EXPECT_EQ(LayoutUnit::kIntMax / 2,
            (LayoutUnit(LayoutUnit::kIntMax) / LayoutUnit(2)).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax,
            (LayoutUnit(LayoutUnit::kIntMax) / LayoutUnit(0.5)).ToInt());
}

TEST(LayoutUnitTest, LayoutUnitDivisionByInt) {
  EXPECT_EQ(LayoutUnit(1), LayoutUnit(1) / 1);
  EXPECT_EQ(LayoutUnit(0.5), LayoutUnit(1) / 2);
  EXPECT_EQ(LayoutUnit(-0.5), LayoutUnit(1) / -2);
  EXPECT_EQ(LayoutUnit(-0.5), LayoutUnit(-1) / 2);
  EXPECT_EQ(LayoutUnit(0.5), LayoutUnit(-1) / -2);

  EXPECT_DOUBLE_EQ(LayoutUnit::kIntMax / 2.0,
                   (LayoutUnit(LayoutUnit::kIntMax) / 2).ToDouble());
  EXPECT_DOUBLE_EQ(
      InlineLayoutUnit::kIntMax / 2.0,
      (InlineLayoutUnit(InlineLayoutUnit::kIntMax) / 2).ToDouble());
}

TEST(LayoutUnitTest, LayoutUnitMulDiv) {
  const LayoutUnit kMaxValue = LayoutUnit::Max();
  const LayoutUnit kMinValue = LayoutUnit::Min();
  const LayoutUnit kEpsilon = LayoutUnit().AddEpsilon();
  EXPECT_EQ(kMaxValue, kMaxValue.MulDiv(kMaxValue, kMaxValue));
  EXPECT_EQ(kMinValue, kMinValue.MulDiv(kMinValue, kMinValue));
  EXPECT_EQ(kMinValue, kMaxValue.MulDiv(kMinValue, kMaxValue));
  EXPECT_EQ(kMaxValue, kMinValue.MulDiv(kMinValue, kMaxValue));
  EXPECT_EQ(kMinValue + kEpsilon * 2, kMaxValue.MulDiv(kMaxValue, kMinValue));

  EXPECT_EQ(kMaxValue, kMaxValue.MulDiv(LayoutUnit(2), kEpsilon));
  EXPECT_EQ(kMinValue, kMinValue.MulDiv(LayoutUnit(2), kEpsilon));

  const LayoutUnit kLargerInt(16384);
  const LayoutUnit kLargerInt2(32768);
  EXPECT_EQ(LayoutUnit(8192), kLargerInt.MulDiv(kLargerInt, kLargerInt2));
}

TEST(LayoutUnitTest, LayoutUnitCeil) {
  EXPECT_EQ(0, LayoutUnit(0).Ceil());
  EXPECT_EQ(1, LayoutUnit(0.1).Ceil());
  EXPECT_EQ(1, LayoutUnit(0.5).Ceil());
  EXPECT_EQ(1, LayoutUnit(0.9).Ceil());
  EXPECT_EQ(1, LayoutUnit(1.0).Ceil());
  EXPECT_EQ(2, LayoutUnit(1.1).Ceil());

  EXPECT_EQ(0, LayoutUnit(-0.1).Ceil());
  EXPECT_EQ(0, LayoutUnit(-0.5).Ceil());
  EXPECT_EQ(0, LayoutUnit(-0.9).Ceil());
  EXPECT_EQ(-1, LayoutUnit(-1.0).Ceil());

  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(LayoutUnit::kIntMax).Ceil());
  EXPECT_EQ(LayoutUnit::kIntMax,
            (LayoutUnit(LayoutUnit::kIntMax) - LayoutUnit(0.5)).Ceil());
  EXPECT_EQ(LayoutUnit::kIntMax - 1,
            (LayoutUnit(LayoutUnit::kIntMax) - LayoutUnit(1)).Ceil());

  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(LayoutUnit::kIntMin).Ceil());
}

TEST(LayoutUnitTest, LayoutUnitFloor) {
  EXPECT_EQ(0, LayoutUnit(0).Floor());
  EXPECT_EQ(0, LayoutUnit(0.1).Floor());
  EXPECT_EQ(0, LayoutUnit(0.5).Floor());
  EXPECT_EQ(0, LayoutUnit(0.9).Floor());
  EXPECT_EQ(1, LayoutUnit(1.0).Floor());
  EXPECT_EQ(1, LayoutUnit(1.1).Floor());

  EXPECT_EQ(-1, LayoutUnit(-0.1).Floor());
  EXPECT_EQ(-1, LayoutUnit(-0.5).Floor());
  EXPECT_EQ(-1, LayoutUnit(-0.9).Floor());
  EXPECT_EQ(-1, LayoutUnit(-1.0).Floor());

  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(LayoutUnit::kIntMax).Floor());

  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(LayoutUnit::kIntMin).Floor());
  EXPECT_EQ(LayoutUnit::kIntMin,
            (LayoutUnit(LayoutUnit::kIntMin) + LayoutUnit(0.5)).Floor());
  EXPECT_EQ(LayoutUnit::kIntMin + 1,
            (LayoutUnit(LayoutUnit::kIntMin) + LayoutUnit(1)).Floor());
}

TEST(LayoutUnitTest, LayoutUnitFloatOverflow) {
  // These should overflow to the max/min according to their sign.
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(176972000.0f).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(-176972000.0f).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMax, LayoutUnit(176972000.0).ToInt());
  EXPECT_EQ(LayoutUnit::kIntMin, LayoutUnit(-176972000.0).ToInt());
}

TEST(LayoutUnitTest, UnaryMinus) {
  EXPECT_EQ(LayoutUnit(), -LayoutUnit());
  EXPECT_EQ(LayoutUnit(999), -LayoutUnit(-999));
  EXPECT_EQ(LayoutUnit(-999), -LayoutUnit(999));

  LayoutUnit negative_max;
  negative_max.SetRawValue(LayoutUnit::Min().RawValue() + 1);
  EXPECT_EQ(negative_max, -LayoutUnit::Max());
  EXPECT_EQ(LayoutUnit::Max(), -negative_max);

  // -LayoutUnit::min() is saturated to LayoutUnit::max()
  EXPECT_EQ(LayoutUnit::Max(), -LayoutUnit::Min());
}

TEST(LayoutUnitTest, LayoutUnitPlusPlus) {
  EXPECT_EQ(LayoutUnit(-1), LayoutUnit(-2)++);
  EXPECT_EQ(LayoutUnit(0), LayoutUnit(-1)++);
  EXPECT_EQ(LayoutUnit(1), LayoutUnit(0)++);
  EXPECT_EQ(LayoutUnit(2), LayoutUnit(1)++);
  EXPECT_EQ(LayoutUnit::Max(), LayoutUnit(LayoutUnit::Max())++);
}

TEST(LayoutUnitTest, IntMod) {
  EXPECT_EQ(LayoutUnit(5), IntMod(LayoutUnit(55), LayoutUnit(10)));
  EXPECT_EQ(LayoutUnit(5), IntMod(LayoutUnit(55), LayoutUnit(-10)));
  EXPECT_EQ(LayoutUnit(-5), IntMod(LayoutUnit(-55), LayoutUnit(10)));
  EXPECT_EQ(LayoutUnit(-5), IntMod(LayoutUnit(-55), LayoutUnit(-10)));
  EXPECT_EQ(LayoutUnit(1.5), IntMod(LayoutUnit(7.5), LayoutUnit(3)));
  EXPECT_EQ(LayoutUnit(1.25), IntMod(LayoutUnit(7.5), LayoutUnit(3.125)));
  EXPECT_EQ(LayoutUnit(), IntMod(LayoutUnit(7.5), LayoutUnit(2.5)));
  EXPECT_EQ(LayoutUnit(), IntMod(LayoutUnit(), LayoutUnit(123)));
}

TEST(LayoutUnitTest, Fraction) {
  EXPECT_TRUE(LayoutUnit(-1.9f).HasFraction());
  EXPECT_TRUE(LayoutUnit(-1.6f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-1.51f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-1.5f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-1.49f).HasFraction());
  EXPECT_FALSE(LayoutUnit(-1.0f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-0.95f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-0.51f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-0.50f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(-0.49f).HasFraction());
  EXPECT_TRUE(LayoutUnit(-0.1f).HasFraction());
  EXPECT_FALSE(LayoutUnit(-1.0f).HasFraction());
  EXPECT_FALSE(LayoutUnit(0.0f).HasFraction());
  EXPECT_TRUE(LayoutUnit(0.1f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(0.49f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(0.50f).HasFraction());
  EXPECT_TRUE(LayoutUnit::FromFloatRound(0.51f).HasFraction());
  EXPECT_TRUE(LayoutUnit(0.95f).HasFraction());
  EXPECT_FALSE(LayoutUnit(1.0f).HasFraction());
}

TEST(LayoutUnitTest, FixedConsts) {
  EXPECT_EQ(LayoutUnit::kFractionalBits, 6u);
  EXPECT_EQ(LayoutUnit::kIntegralBits, 26u);
  EXPECT_EQ(TextRunLayoutUnit::kFractionalBits, 16u);
  EXPECT_EQ(TextRunLayoutUnit::kIntegralBits, 16u);
  EXPECT_EQ(InlineLayoutUnit::kFractionalBits, 16u);
  EXPECT_EQ(InlineLayoutUnit::kIntegralBits, 48u);
}

TEST(LayoutUnitTest, Fixed) {
  constexpr int raw_value16 = 0x12345678;
  constexpr int raw_value6 = raw_value16 >> 10;
  const auto value16 = TextRunLayoutUnit::FromRawValue(raw_value16);
  const auto value6 = LayoutUnit::FromRawValue(raw_value6);
  EXPECT_EQ(value16.To<LayoutUnit>(), value6);
}

TEST(LayoutUnitTest, Raw64FromInt32) {
  constexpr int32_t int32_max_plus = LayoutUnit::kIntMax + 10;
  LayoutUnit int32_max_plus_32(int32_max_plus);
  EXPECT_NE(int32_max_plus_32.ToInt(), int32_max_plus);
  InlineLayoutUnit int32_max_plus_64(int32_max_plus);
  EXPECT_EQ(int32_max_plus_64.ToInt(), int32_max_plus);

  constexpr int32_t int32_min_minus = LayoutUnit::kIntMin - 10;
  LayoutUnit int32_min_minus_32(int32_min_minus);
  EXPECT_NE(int32_min_minus_32.ToInt(), int32_min_minus);
  InlineLayoutUnit int32_min_minus_64(int32_min_minus);
  EXPECT_EQ(int32_min_minus_64.ToInt(), int32_min_minus);

  constexpr int64_t raw32_max_plus =
      static_cast<int64_t>(LayoutUnit::kRawValueMax) + 10;
  LayoutUnit raw32_max_plus_32(raw32_max_plus);
  EXPECT_NE(raw32_max_plus_32.ToInt(), raw32_max_plus);
  InlineLayoutUnit raw32_max_plus_64(raw32_max_plus);
  EXPECT_EQ(raw32_max_plus_64.ToInt(), raw32_max_plus);

  constexpr int64_t raw32_min_minus =
      static_cast<int64_t>(LayoutUnit::kRawValueMin) - 10;
  LayoutUnit raw32_min_minus_32(raw32_min_minus);
  EXPECT_NE(raw32_min_minus_32.ToInt(), raw32_min_minus);
  InlineLayoutUnit raw32_min_minus_64(raw32_min_minus);
  EXPECT_EQ(raw32_min_minus_64.ToInt(), raw32_min_minus);
}

TEST(LayoutUnitTest, Raw64FromRaw32) {
  constexpr float value = 1.f + LayoutUnit::Epsilon() * 234;
  LayoutUnit value32_6(value);
  EXPECT_EQ(InlineLayoutUnit(value32_6), InlineLayoutUnit(value));
  TextRunLayoutUnit value32_16(value);
  EXPECT_EQ(InlineLayoutUnit(value32_16), InlineLayoutUnit(value));

  // The following code should fail to compile.
  // TextRunLayoutUnit back_to_32{InlineLayoutUnit(value)};
}

TEST(LayoutUnitTest, To) {
#define TEST_ROUND_TRIP(T1, T2)                      \
  EXPECT_EQ(T1(value), T2(value).To<T1>()) << value; \
  EXPECT_EQ(T2(value), T1(value).To<T2>()) << value;

  for (const float value : {1.0f, 1.5f, -1.0f}) {
    TEST_ROUND_TRIP(LayoutUnit, TextRunLayoutUnit);
    TEST_ROUND_TRIP(LayoutUnit, InlineLayoutUnit);
    TEST_ROUND_TRIP(TextRunLayoutUnit, InlineLayoutUnit);
  }
#undef TEST_ROUND_TRIP
}

TEST(LayoutUnitTest, ToClampSameFractional64To32) {
  EXPECT_EQ(
      TextRunLayoutUnit::Max(),
      InlineLayoutUnit(TextRunLayoutUnit::kIntMax + 1).To<TextRunLayoutUnit>());
  EXPECT_EQ(
      TextRunLayoutUnit::Min(),
      InlineLayoutUnit(TextRunLayoutUnit::kIntMin - 1).To<TextRunLayoutUnit>());
}

TEST(LayoutUnitTest, ToClampLessFractional64To32) {
  EXPECT_EQ(LayoutUnit::Max(),
            InlineLayoutUnit(LayoutUnit::kIntMax + 1).To<LayoutUnit>());
  EXPECT_EQ(LayoutUnit::Min(),
            InlineLayoutUnit(LayoutUnit::kIntMin - 1).To<LayoutUnit>());
}

TEST(LayoutUnitTest, ToClampMoreFractional) {
  EXPECT_EQ(TextRunLayoutUnit::Max(),
            LayoutUnit(TextRunLayoutUnit::kIntMax + 1).To<TextRunLayoutUnit>());
  EXPECT_EQ(TextRunLayoutUnit::Min(),
            LayoutUnit(TextRunLayoutUnit::kIntMin - 1).To<TextRunLayoutUnit>());
}

TEST(LayoutUnitTest, Raw64Ceil) {
  LayoutUnit layout(1.234);
  InlineLayoutUnit inline_value(layout);
  EXPECT_EQ(layout, inline_value.ToCeil<LayoutUnit>());

  inline_value = inline_value.AddEpsilon();
  EXPECT_NE(layout, inline_value.ToCeil<LayoutUnit>());
  EXPECT_EQ(layout.AddEpsilon(), inline_value.ToCeil<LayoutUnit>());
}

}  // namespace blink
```