Response:
The user wants a summary of the functionality of the provided C++ code.
The code is a test suite for a `Decimal` class within the Chromium Blink rendering engine.
I need to identify the functionalities being tested and whether they relate to Javascript, HTML, or CSS.

**Plan:**
1. Analyze each `TEST_F` block to determine the functionality being tested.
2. Check if the tested functionality has any relevance to Javascript, HTML, or CSS. If so, provide examples.
3. Summarize the overall functionality of the test suite.
这个C++代码文件 `decimal_test.cc` 是 Chromium Blink 引擎中 `Decimal` 类的单元测试。它详细测试了 `Decimal` 类的各种算术运算、比较操作、特殊值处理以及与其他数据类型的转换。

以下是该测试文件涵盖的功能点的归纳：

**核心功能测试:**

* **构造和编码 (Construction and Encoding):**
    * 测试使用不同的参数（尾数、指数、符号）构造 `Decimal` 对象。
    * 测试内部表示的编码和解码机制。
* **加法 (Addition):**
    * 测试正数、负数、零之间的加法。
    * 测试大指数和小指数情况下的加法。
    * 测试与特殊值（无穷大、NaN）的加法。
* **比较 (Comparison):**
    * 测试相等、不等、小于、大于、小于等于、大于等于的比较操作。
    * 测试与特殊值的比较。
* **除法 (Division):**
    * 测试正数、负数、零之间的除法。
    * 测试大指数和小指数情况下的除法。
    * 测试与特殊值的除法。
* **乘法 (Multiplication):**
    * 测试正数、负数之间的乘法。
    * 测试大指数和小指数情况下的乘法。
    * 测试与特殊值（无穷大、NaN、零）的乘法，包括正零和负零。
* **取反 (Negation):**
    * 测试正数、负数、零的取反操作。
    * 测试大指数和小指数情况下的取反。
    * 测试特殊值的取反。
* **谓词 (Predicates):**
    * 测试判断 `Decimal` 对象是否是有限数 (`IsFinite`)。
    * 测试判断是否是无穷大 (`IsInfinity`)。
    * 测试判断是否是 NaN (`IsNaN`)。
    * 测试判断是否是正数 (`IsPositive`)。
    * 测试判断是否是负数 (`IsNegative`)。
    * 测试判断是否是特殊值 (`IsSpecial`)。
    * 测试判断是否是零 (`IsZero`)。
* **步进/步退 (Step Up/Step Down):**
    * 测试 `StepUp` 和 `StepDown` 函数，模拟数值输入框的步进和步退功能。
* **取余 (Remainder):**
    * 测试计算两个 `Decimal` 对象相除的余数。
    * 测试大指数和小指数情况下的取余。
    * 测试与特殊值的取余。
* **四舍五入 (Round):**
    * 测试将 `Decimal` 对象四舍五入到最接近的整数。
    * 测试不同尾数和指数的四舍五入。
    * 测试特殊值的四舍五入。
* **减法 (Subtraction):**
    * 测试正数、负数、零之间的减法。
    * 测试大指数和小指数情况下的减法。
    * 测试与特殊值的减法。
* **转换为双精度浮点数 (ToDouble):**
    * 测试将 `Decimal` 对象转换为 `double` 类型。
    * 测试各种数值和特殊值的转换。
* **转换为字符串 (ToString):**
    * 测试将 `Decimal` 对象转换为字符串表示。
    * 测试各种数值，包括整数、小数、科学计数法以及特殊值的转换。

**与 Javascript, HTML, CSS 的关系：**

`Decimal` 类在 Blink 引擎中主要用于处理 **Javascript** 中数字类型的精确计算，特别是在涉及浮点数运算时，避免精度丢失问题。 虽然直接与 HTML 或 CSS 没有直接关系，但它支撑了 Javascript 的数值运算，而 Javascript 经常被用来操作 HTML 结构和 CSS 样式。

* **Javascript 数值运算:**  Javascript 的 `Number` 类型在处理大数字或需要高精度的小数时可能会出现精度问题。`Decimal` 类提供了一种更精确的表示和计算方式，尤其是在处理用户输入、货币计算、或者需要精确数值的场景下。

**举例说明:**

* **假设输入 (Javascript):** 在 Javascript 中进行 `0.1 + 0.2` 的运算，结果可能不是精确的 `0.3`。
* **内部处理 (Decimal):** Blink 引擎内部可以使用 `Decimal` 类来精确表示 `0.1` 和 `0.2`，并进行精确的加法运算，得到精确的 `0.3`。
* **输出 (Javascript):** 最终将精确的结果返回给 Javascript。

* **HTML 数字输入框 (假设):**  HTML 的 `<input type="number">` 元素允许用户输入数字。
* **步进/步退 (Decimal):**  当用户点击输入框的步进或步退按钮时，浏览器内部可能使用类似 `Decimal` 类的 `StepUp` 和 `StepDown` 功能来计算新的数值，确保按照指定的步长进行精确增减。
* **显示 (HTML):**  最终更新输入框中显示的数值。

**逻辑推理与假设输入输出:**

* **测试 `Addition` 中的大指数情况:**
    * **假设输入:** 两个 `Decimal` 对象，例如 `Encode(1, 1022, kPositive)` 和 `Encode(1, 0, kPositive)`，分别表示一个非常大的数和一个较小的数。
    * **预期输出:**  由于第一个数远大于第二个数，它们的和应该接近于第一个数，即 `Encode(1, 1022, kPositive)`。

* **测试 `Multiplication` 中的特殊值:**
    * **假设输入:** 一个 `Decimal` 的无穷大值 (`Decimal::Infinity(kPositive)`) 乘以一个 `Decimal` 的零值 (`Decimal::Zero(kPositive)`).
    * **预期输出:** 根据 IEEE 754 标准，无穷大乘以零的结果是 NaN (`Decimal::Nan()`)。

**用户或编程常见的使用错误:**

* **不注意浮点数精度问题:**  程序员可能会直接使用 Javascript 的 `Number` 类型进行浮点数运算，而忽略潜在的精度丢失问题。例如，在需要精确计算货币金额时，直接使用 `Number` 可能导致误差。
* **错误地比较浮点数:** 由于浮点数的精度问题，直接使用 `==` 比较两个浮点数是否相等可能会失败。应该使用一个小的误差范围进行比较。`Decimal` 类提供的精确比较操作可以避免这类错误。
* **未正确处理特殊值:**  在进行数值运算时，需要考虑特殊值（如无穷大和 NaN）的情况，并进行相应的处理。例如，不检查除数为零的情况会导致程序错误。 `Decimal` 类的测试覆盖了这些特殊情况的处理。

**归纳其功能 (第 2 部分):**

总而言之，`blink/renderer/platform/wtf/decimal_test.cc` 文件的主要功能是 **全面细致地测试 `Decimal` 类的各种功能，确保其在各种场景下都能正确、可靠地工作**。这包括基本的算术运算、比较操作、类型转换以及对特殊值的处理。 这些测试对于保证 Blink 引擎在处理 Javascript 数值运算时的精度和正确性至关重要。

### 提示词
```
这是目录为blink/renderer/platform/wtf/decimal_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
kPositive) * Encode(1, 0, kPositive));
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
```