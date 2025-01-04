Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The first step is to recognize that this is a *test file*. Test files exist to verify the correctness of other code. The file path `blink/renderer/platform/wtf/text/string_to_number_test.cc` gives us a strong hint: it's testing the functionality of converting strings to numbers within the Blink rendering engine (part of Chromium).

2. **Identify the Core Functionality Under Test:**  The `#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"` line is the most important clue. It tells us this test file is specifically designed to test the functions declared in `string_to_number.h`. Scanning the test file confirms this:  we see calls to functions like `CharactersToInt`, `CharactersToUInt`, `HexCharactersToUInt`, `CharactersToDouble`, and `CharactersToFloat`.

3. **Analyze the Test Structure:**  The file uses the Google Test framework (indicated by `#include "testing/gtest/include/gtest/gtest.h"`). This means tests are organized using `TEST(TestSuiteName, TestName) { ... }` blocks. This structure provides a clear way to examine individual test cases.

4. **Examine Individual Test Cases:** Now, dive into the details of each test.

   * **`StringToNumberTest, CharactersToInt`:** This tests the `CharactersToInt` function. The macros `EXPECT_VALID` and `EXPECT_INVALID` simplify the test setup. Observe the different input strings and the expected outcomes (valid integer or invalid conversion). Notice the use of `NumberParsingOptions::Strict()` and `NumberParsingOptions()` to test different parsing behaviors. Pay attention to edge cases like leading zeros, signs, and out-of-range values.

   * **`StringToNumberTest, CharactersToUInt`:** Similar to the `CharactersToInt` test, but for unsigned integers. Note the handling of negative numbers (they are generally invalid for unsigned integers unless `SetAcceptMinusZeroForUnsigned()` is used).

   * **`StringToNumberTest, HexCharactersToUInt`:**  This focuses on parsing hexadecimal strings into unsigned integers. Observe the handling of uppercase and lowercase 'a' through 'f', and the validation of the hex format.

   * **`StringToNumberTest, NumberParsingState`:** This test examines the return type of a parsing function (`ParseUInt`) which provides more information than just a boolean success/failure. It checks for overflow and other error conditions.

   * **`StringToNumberTest, CharactersToDouble`:**  Tests the conversion of strings to double-precision floating-point numbers. Examine the handling of decimal points, exponents, special values like "NaN" and "Infinity", and whitespace. The `FailToParseDouble` helper function makes the tests cleaner.

   * **`StringToNumberTest, CharactersToDoubleParsedLength`:**  This test focuses on *how much* of the string was successfully parsed. This is important when you might have extra characters after the number.

   * **`StringToNumberTest, CharactersToFloat`:**  Similar to the double test, but for single-precision floating-point numbers. Note the slight differences in range and precision.

   * **`StringToNumberTest, CharactersToFloatParsedLength`:**  Again, testing the parsed length for float conversions.

5. **Infer Functionality:** Based on the test cases, we can infer the core functionalities of the `string_to_number.h` file:

   * Converting strings to integers (signed and unsigned).
   * Converting strings to hexadecimal unsigned integers.
   * Converting strings to floating-point numbers (single and double precision).
   * Handling different parsing options (strict vs. loose, allowing trailing garbage, etc.).
   * Identifying valid and invalid number strings.
   * Handling edge cases (leading zeros, signs, whitespace, overflow, underflow, special values like NaN and Infinity).
   * Reporting the success or failure of the conversion.
   * Reporting the length of the successfully parsed portion of the string.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Now, consider how these functionalities relate to web technologies:

   * **JavaScript:** JavaScript heavily relies on converting strings to numbers for various operations. Think of user input in forms, calculations, and parsing data. The `parseInt()`, `parseFloat()`, and `Number()` functions in JavaScript have direct parallels to the C++ functions being tested.

   * **HTML:** While HTML itself doesn't do string-to-number conversion, it *represents* data that often needs to be converted. For instance, the `value` of an `<input type="number">` element is a string that JavaScript will need to convert. Also, data attributes (`data-*`) are strings that might need numeric interpretation.

   * **CSS:** CSS properties like `width`, `height`, `margin`, `padding`, etc., often take numeric values with units (like "10px", "2.5em"). The parsing logic tested in this file is crucial for correctly interpreting these CSS values. The "loose" parsing options likely relate to handling these unit suffixes.

7. **Provide Examples and Scenarios:**  Illustrate the connections with concrete examples for each technology. Think about typical use cases where string-to-number conversion is necessary.

8. **Consider User/Programming Errors:**  Reflect on common mistakes developers or users might make that would be caught by these tests. This involves thinking about invalid input formats, out-of-range values, and incorrect assumptions about parsing behavior.

9. **Review and Refine:** Finally, review the entire analysis to ensure clarity, accuracy, and completeness. Check for logical flow and make sure the examples are relevant and easy to understand. For example, ensure that the assumptions about input and output are clearly stated when explaining logical inferences.

This systematic approach, starting with understanding the purpose of the file and progressively delving into the details of the tests, allows for a comprehensive analysis and a clear explanation of the functionality and its relevance.
这个文件 `string_to_number_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，它的主要功能是**测试 `string_to_number.h` 头文件中定义的字符串到数字的转换函数是否正确工作**。

更具体地说，它测试了以下功能：

1. **将字符串转换为有符号整数 (`CharactersToInt`)**:
   - 测试各种合法的整数格式，包括正数、负数、零、带有正负号的数、带有前导零的数。
   - 测试不同的解析选项 (`NumberParsingOptions`)，例如严格模式 (`Strict`) 和允许尾部垃圾字符的模式 (`AcceptTrailingGarbage`)。
   - 测试整数的边界情况，例如 `INT_MAX` 和 `INT_MIN`。
   - 测试各种非法的整数格式。

2. **将字符串转换为无符号整数 (`CharactersToUInt`)**:
   - 测试各种合法的无符号整数格式，包括正数、零、带有正号的数、带有前导零的数。
   - 测试不同的解析选项，包括允许 `-0` 的情况。
   - 测试无符号整数的边界情况，例如 `UINT_MAX`。
   - 测试各种非法的无符号整数格式，包括负数。

3. **将十六进制字符串转换为无符号整数 (`HexCharactersToUInt`)**:
   - 测试各种合法的十六进制格式，包括大小写字母。
   - 测试十六进制数的边界情况。
   - 测试各种非法的十六进制格式，包括负号。

4. **获取字符串解析为无符号整数的结果状态 (`ParseUInt` 和 `NumberParsingState` 测试)**:
   - 测试解析结果的状态，例如成功、溢出、错误。

5. **将字符串转换为双精度浮点数 (`CharactersToDouble`)**:
   - 测试各种合法的浮点数格式，包括整数部分、小数部分、指数部分、正负号、特殊值（如 `NaN` 和 `Infinity`）。
   - 测试空白字符的处理。
   - 测试各种非法的浮点数格式。

6. **获取字符串解析为双精度浮点数的长度 (`CharactersToDoubleParsedLength`)**:
   - 测试成功解析的字符串的长度。

7. **将字符串转换为单精度浮点数 (`CharactersToFloat`)**:
   - 测试各种合法的浮点数格式，类似于双精度浮点数。
   - 测试各种非法的浮点数格式。

8. **获取字符串解析为单精度浮点数的长度 (`CharactersToFloatParsedLength`)**:
   - 测试成功解析的字符串的长度。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些字符串到数字的转换功能在 Web 浏览器中至关重要，因为 JavaScript, HTML, 和 CSS 都涉及到字符串和数字之间的交互。

**1. JavaScript:**

- **功能关系:** JavaScript 提供了 `parseInt()`, `parseFloat()`, 和 `Number()` 等函数用于将字符串转换为数字。`string_to_number.h` 中测试的函数很可能就是 Blink 引擎在实现这些 JavaScript 函数时所使用的底层 C++ 代码。
- **举例说明:**
  ```javascript
  let strInt = "123";
  let numInt = parseInt(strInt); // JavaScript 调用底层 C++ 代码将 "123" 转换为整数 123

  let strFloat = "3.14";
  let numFloat = parseFloat(strFloat); // JavaScript 调用底层 C++ 代码将 "3.14" 转换为浮点数 3.14

  let strHex = "0xff";
  let numHex = parseInt(strHex); // JavaScript 调用底层 C++ 代码将 "0xff" 转换为整数 255
  ```
  **假设输入与输出 (逻辑推理):**
  - **假设输入:** JavaScript 代码调用 `parseInt("42")`。
  - **预期输出:** 底层的 `CharactersToInt` 函数 (或类似实现) 应该返回整数 `42`，并且 `ok` 参数为 `true`。

**2. HTML:**

- **功能关系:** HTML 元素属性的值通常是字符串，当需要将其作为数字处理时，浏览器需要进行转换。例如，`<input type="number">` 元素的 `value` 属性是一个字符串，但 JavaScript 代码通常会将其转换为数字进行计算。
- **举例说明:**
  ```html
  <input type="number" id="myNumber" value="100">
  <script>
    let inputElement = document.getElementById("myNumber");
    let numberValue = parseInt(inputElement.value); // 浏览器底层 C++ 代码将 "100" 转换为整数 100
    console.log(numberValue + 5); // 输出 105
  </script>
  ```
  **假设输入与输出 (逻辑推理):**
  - **假设输入:** HTML 中 `<input type="number" value=" -5 ">`，JavaScript 调用 `parseInt(inputElement.value)`。
  - **预期输出:** 底层的 `CharactersToInt` 函数在处理带有前导空格的字符串时，应该返回整数 `-5` (取决于解析选项，严格模式可能不允许前导空格，宽松模式允许)。

**3. CSS:**

- **功能关系:** CSS 属性的值很多是带有单位的数字字符串（例如 `"10px"`, `"2.5em"`）。浏览器需要解析这些字符串，提取数字部分，并根据单位进行计算。`string_to_number.h` 中测试的允许尾部垃圾字符的解析选项，很可能就是为了处理这种情况。
- **举例说明:**
  ```css
  .my-element {
    width: 200px; /* 浏览器底层 C++ 代码需要解析 "200px" 提取数字 200 */
    margin-left: 10.5em; /* 浏览器底层 C++ 代码需要解析 "10.5em" 提取数字 10.5 */
  }
  ```
  **假设输入与输出 (逻辑推理):**
  - **假设输入:** CSS 属性 `padding: 5.2pt;`。
  - **预期输出:** 底层的 `CharactersToDouble` 函数 (或类似实现) 在使用允许尾部垃圾字符的解析选项时，应该返回浮点数 `5.2`。

**用户或编程常见的使用错误及举例说明:**

1. **类型不匹配:**  用户或程序员期望一个数字，但提供了一个无法转换为数字的字符串。
   ```javascript
   let input = "hello";
   let num = parseInt(input); // 结果为 NaN (Not a Number)，表明转换失败
   ```
   - **底层 C++ 行为:** `CharactersToInt` 函数在接收到 `"hello"` 时，会因为无法解析为整数而设置 `ok` 参数为 `false`。

2. **超出范围的值:**  提供的字符串表示的数字超出了目标类型的范围。
   ```javascript
   let largeNumberString = "999999999999999999999";
   let num = parseInt(largeNumberString); // JavaScript 中 parseInt 可能截断或返回 Infinity
   ```
   - **底层 C++ 行为:**  `CharactersToInt` 在解析超出 `INT_MAX` 或 `INT_MIN` 范围的字符串时，会设置 `ok` 为 `false` (在严格模式下) 或根据实现返回边界值并设置相应的错误状态 (例如 `NumberParsingResult::kOverflowMax`)。

3. **非法的数字格式:**  字符串包含无效的字符或格式。
   ```javascript
   let invalidNumber = "12a3";
   let num = parseInt(invalidNumber); // 结果为 12，只解析了开头的数字部分
   ```
   - **底层 C++ 行为:** `CharactersToInt` 在严格模式下解析 `"12a3"` 会失败，设置 `ok` 为 `false`。但在某些非严格模式下，可能会解析到第一个非数字字符为止。

4. **忘记处理解析失败的情况:** 程序员没有检查字符串到数字转换是否成功，导致后续代码使用了 `NaN` 或不正确的值。
   ```javascript
   let inputStr = getUserInput(); // 假设用户输入了 "abc"
   let num = parseInt(inputStr);
   let result = num * 2; // 如果 num 是 NaN，result 也是 NaN，可能会导致程序错误
   ```
   - **底层 C++ 启示:** 测试用例中 `EXPECT_FALSE(ok)` 的存在，强调了在实际编程中需要检查转换函数的 `ok` 返回值，以确保转换成功。

总结来说，`string_to_number_test.cc` 文件通过大量的测试用例，确保了 Blink 引擎能够正确地将各种格式的字符串转换为数字，这对于浏览器正确渲染网页、执行 JavaScript 代码至关重要。它覆盖了各种边界情况和错误情况，有助于提高代码的健壮性和可靠性。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/string_to_number_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"

#include <cstring>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace WTF {

TEST(StringToNumberTest, CharactersToInt) {
#define EXPECT_VALID(string, options, expectedValue)                   \
  do {                                                                 \
    bool ok;                                                           \
    int value = CharactersToInt(String(string).Span8(), options, &ok); \
    EXPECT_TRUE(ok);                                                   \
    EXPECT_EQ(value, expectedValue);                                   \
  } while (false)

#define EXPECT_INVALID(string, options)                    \
  do {                                                     \
    bool ok;                                               \
    CharactersToInt(String(string).Span8(), options, &ok); \
    EXPECT_FALSE(ok);                                      \
  } while (false)

  constexpr auto kStrict = NumberParsingOptions::Strict();
  EXPECT_VALID("1", kStrict, 1);
  EXPECT_VALID("2", kStrict, 2);
  EXPECT_VALID("9", kStrict, 9);
  EXPECT_VALID("10", kStrict, 10);
  EXPECT_VALID("0", kStrict, 0);
  EXPECT_VALID("-0", kStrict, 0);
  EXPECT_VALID("-1", kStrict, -1);
  EXPECT_VALID("-2", kStrict, -2);
  EXPECT_VALID("-9", kStrict, -9);
  EXPECT_VALID("-10", kStrict, -10);
  EXPECT_VALID("+0", kStrict, 0);
  EXPECT_VALID("+1", kStrict, 1);
  EXPECT_INVALID("+1", NumberParsingOptions());
  EXPECT_VALID("+2", kStrict, 2);
  EXPECT_VALID("+9", kStrict, 9);
  EXPECT_VALID("+10", kStrict, 10);
  EXPECT_VALID("00", kStrict, 0);
  EXPECT_VALID("+00", kStrict, 0);
  EXPECT_VALID("-00", kStrict, 0);
  EXPECT_VALID("01", kStrict, 1);
  EXPECT_VALID("-01", kStrict, -1);
  EXPECT_VALID("00000000000000000000", kStrict, 0);
  EXPECT_VALID(" 3 ", kStrict, 3);
  EXPECT_INVALID(" 3 ", NumberParsingOptions());
  EXPECT_VALID(" 3 pt", NumberParsingOptions::Loose(), 3);
  EXPECT_INVALID(" 3 pt", kStrict);
  EXPECT_VALID("3px", NumberParsingOptions().SetAcceptTrailingGarbage(), 3);
  EXPECT_INVALID("a", kStrict);
  EXPECT_INVALID("1a", kStrict);
  EXPECT_INVALID("a1", kStrict);
  EXPECT_INVALID("-a", kStrict);
  EXPECT_INVALID("", kStrict);
  EXPECT_INVALID("-", kStrict);
  EXPECT_INVALID("--1", kStrict);
  EXPECT_INVALID("++1", kStrict);
  EXPECT_INVALID("+-1", kStrict);
  EXPECT_INVALID("-+1", kStrict);
  EXPECT_INVALID("0-", kStrict);
  EXPECT_INVALID("0+", kStrict);

  EXPECT_VALID("2147483647", kStrict, 2147483647);
  EXPECT_VALID("02147483647", kStrict, 2147483647);
  EXPECT_INVALID("2147483648", kStrict);
  EXPECT_INVALID("2147483649", kStrict);
  EXPECT_INVALID("2147483650", kStrict);
  EXPECT_INVALID("2147483700", kStrict);
  EXPECT_INVALID("2147484000", kStrict);
  EXPECT_INVALID("2200000000", kStrict);
  EXPECT_INVALID("3000000000", kStrict);
  EXPECT_INVALID("10000000000", kStrict);
  EXPECT_VALID("-2147483647", kStrict, -2147483647);
  EXPECT_VALID("-2147483648", kStrict, -2147483647 - 1);
  EXPECT_INVALID("-2147483649", kStrict);
  EXPECT_INVALID("-2147483650", kStrict);
  EXPECT_INVALID("-2147483700", kStrict);
  EXPECT_INVALID("-2147484000", kStrict);
  EXPECT_INVALID("-2200000000", kStrict);
  EXPECT_INVALID("-3000000000", kStrict);
  EXPECT_INVALID("-10000000000", kStrict);

#undef EXPECT_VALID
#undef EXPECT_INVALID
}

TEST(StringToNumberTest, CharactersToUInt) {
#define EXPECT_VALID(string, options, expectedValue)                         \
  do {                                                                       \
    bool ok;                                                                 \
    unsigned value = CharactersToUInt(String(string).Span8(), options, &ok); \
    EXPECT_TRUE(ok);                                                         \
    EXPECT_EQ(value, expectedValue);                                         \
  } while (false)

#define EXPECT_INVALID(string, options)                     \
  do {                                                      \
    bool ok;                                                \
    CharactersToUInt(String(string).Span8(), options, &ok); \
    EXPECT_FALSE(ok);                                       \
  } while (false)

  constexpr auto kStrict = NumberParsingOptions::Strict();
  constexpr auto kAcceptMinusZeroForUnsigned =
      NumberParsingOptions().SetAcceptMinusZeroForUnsigned();
  EXPECT_VALID("1", kStrict, 1u);
  EXPECT_VALID("2", kStrict, 2u);
  EXPECT_VALID("9", kStrict, 9u);
  EXPECT_VALID("10", kStrict, 10u);
  EXPECT_VALID("0", kStrict, 0u);
  EXPECT_VALID("+0", kStrict, 0u);
  EXPECT_VALID("+1", kStrict, 1u);
  EXPECT_VALID("+2", kStrict, 2u);
  EXPECT_VALID("+9", kStrict, 9u);
  EXPECT_VALID("+10", kStrict, 10u);
  EXPECT_INVALID("+10", NumberParsingOptions());
  EXPECT_VALID("00", kStrict, 0u);
  EXPECT_VALID("+00", kStrict, 0u);
  EXPECT_VALID("01", kStrict, 1u);
  EXPECT_VALID("00000000000000000000", kStrict, 0u);
  EXPECT_INVALID("a", kStrict);
  EXPECT_INVALID("1a", kStrict);
  EXPECT_INVALID("a1", kStrict);
  EXPECT_INVALID("-a", kStrict);
  EXPECT_INVALID("", kStrict);
  EXPECT_INVALID("-", kStrict);
  EXPECT_INVALID("-0", kStrict);
  EXPECT_VALID("-0", kAcceptMinusZeroForUnsigned, 0u);
  EXPECT_INVALID("-1", kStrict);
  EXPECT_INVALID("-1", kAcceptMinusZeroForUnsigned);
  EXPECT_INVALID("-2", kStrict);
  EXPECT_INVALID("-9", kStrict);
  EXPECT_INVALID("-10", kStrict);
  EXPECT_INVALID("-00", kStrict);
  EXPECT_VALID("-00", kAcceptMinusZeroForUnsigned, 0u);
  EXPECT_INVALID("-01", kStrict);
  EXPECT_INVALID("--1", kStrict);
  EXPECT_INVALID("++1", kStrict);
  EXPECT_INVALID("+-1", kStrict);
  EXPECT_INVALID("-+1", kStrict);
  EXPECT_INVALID("0-", kStrict);
  EXPECT_INVALID("0+", kStrict);

  EXPECT_VALID("2147483647", kStrict, 2147483647u);
  EXPECT_VALID("02147483647", kStrict, 2147483647u);
  EXPECT_VALID("2147483648", kStrict, 2147483648u);
  EXPECT_VALID("4294967295", kStrict, 4294967295u);
  EXPECT_VALID("0004294967295", kStrict, 4294967295u);
  EXPECT_INVALID("4294967296", kStrict);
  EXPECT_INVALID("4294967300", kStrict);
  EXPECT_INVALID("4300000000", kStrict);
  EXPECT_INVALID("5000000000", kStrict);
  EXPECT_INVALID("10000000000", kStrict);
  EXPECT_INVALID("-2147483647", kStrict);
  EXPECT_INVALID("-2147483648", kStrict);
  EXPECT_INVALID("-2147483649", kStrict);
  EXPECT_INVALID("-2147483650", kStrict);
  EXPECT_INVALID("-2147483700", kStrict);
  EXPECT_INVALID("-2147484000", kStrict);
  EXPECT_INVALID("-2200000000", kStrict);
  EXPECT_INVALID("-3000000000", kStrict);
  EXPECT_INVALID("-10000000000", kStrict);

#undef EXPECT_VALID
#undef EXPECT_INVALID
}

TEST(StringToNumberTest, HexCharactersToUInt) {
#define EXPECT_VALID(string, expectedValue)                                    \
  do {                                                                         \
    bool ok;                                                                   \
    unsigned value = HexCharactersToUInt(String(string).Span8(),               \
                                         NumberParsingOptions::Strict(), &ok); \
    EXPECT_TRUE(ok);                                                           \
    EXPECT_EQ(value, expectedValue);                                           \
  } while (false)

#define EXPECT_INVALID(string)                                \
  do {                                                        \
    bool ok;                                                  \
    HexCharactersToUInt(String(string).Span8(),               \
                        NumberParsingOptions::Strict(), &ok); \
    EXPECT_FALSE(ok);                                         \
  } while (false)

  EXPECT_VALID("1", 1u);
  EXPECT_VALID("a", 0xAu);
  EXPECT_VALID("A", 0xAu);
  EXPECT_VALID("+a", 0xAu);
  EXPECT_VALID("+A", 0xAu);
  EXPECT_INVALID("-a");
  EXPECT_INVALID("-A");

  EXPECT_VALID("7fffffff", 0x7FFFFFFFu);
  EXPECT_VALID("80000000", 0x80000000u);
  EXPECT_VALID("fffffff0", 0xFFFFFFF0u);
  EXPECT_VALID("ffffffff", 0xFFFFFFFFu);
  EXPECT_VALID("00ffffffff", 0xFFFFFFFFu);
  EXPECT_INVALID("100000000");
  EXPECT_INVALID("7fffffff0");
  EXPECT_INVALID("-7fffffff");
  EXPECT_INVALID("-80000000");
  EXPECT_INVALID("-80000001");
  EXPECT_INVALID("-8000000a");
  EXPECT_INVALID("-8000000f");
  EXPECT_INVALID("-80000010");
  EXPECT_INVALID("-90000000");
  EXPECT_INVALID("-f0000000");
  EXPECT_INVALID("-fffffff0");
  EXPECT_INVALID("-ffffffff");

#undef EXPECT_VALID
#undef EXPECT_INVALID
}

NumberParsingResult ParseUInt(const String str, unsigned* value) {
  NumberParsingResult result;
  *value =
      CharactersToUInt(str.Span8(), NumberParsingOptions::Strict(), &result);
  return result;
}

TEST(StringToNumberTest, NumberParsingState) {
  unsigned value;
  EXPECT_EQ(NumberParsingResult::kOverflowMax,
            ParseUInt("10000000000", &value));
  EXPECT_EQ(NumberParsingResult::kError, ParseUInt("10000000000abc", &value));
  EXPECT_EQ(NumberParsingResult::kError, ParseUInt("-10000000000", &value));
  EXPECT_EQ(NumberParsingResult::kError, ParseUInt("-0", &value));
  EXPECT_EQ(NumberParsingResult::kSuccess, ParseUInt("10", &value));
}

void ParseDouble(const String& str, double expected_value) {
  bool ok;
  double value = CharactersToDouble(str.Span8(), &ok);
  EXPECT_TRUE(ok) << "\"" << str << "\"";
  EXPECT_EQ(expected_value, value);
}

void FailToParseDouble(const String& str) {
  bool ok;
  CharactersToDouble(str.Span8(), &ok);
  EXPECT_FALSE(ok) << "\"" << str << "\"";
}

TEST(StringToNumberTest, CharactersToDouble) {
  FailToParseDouble("");
  ParseDouble("0", 0.0);
  ParseDouble("-0", 0.0);
  ParseDouble("1.5", 1.5);
  ParseDouble("+1.5", 1.5);
  FailToParseDouble("+");
  FailToParseDouble("-");
  ParseDouble(".5", 0.5);
  ParseDouble("1.", 1);
  FailToParseDouble(".");
  ParseDouble("1e-100", 1e-100);
  ParseDouble("1e100", 1e+100);
  ParseDouble("    1.5", 1.5);
  FailToParseDouble("1.5   ");
  FailToParseDouble("1.5px");
  FailToParseDouble("NaN");
  FailToParseDouble("nan");
  FailToParseDouble("Infinity");
  FailToParseDouble("infinity");
  FailToParseDouble("Inf");
  FailToParseDouble("inf");
  ParseDouble("1e+4000", std::numeric_limits<double>::infinity());
  ParseDouble("-1e+4000", -std::numeric_limits<double>::infinity());
  ParseDouble("1e-4000", 0);
  FailToParseDouble("1e");
  FailToParseDouble("1e-");
  FailToParseDouble("1e+");
  FailToParseDouble("1e3.");
  FailToParseDouble("1e3.5");
  FailToParseDouble("1e.3");
}

size_t ParseDouble(const String& str) {
  size_t parsed;
  CharactersToDouble(str.Span8(), parsed);
  return parsed;
}

TEST(StringToNumberTest, CharactersToDoubleParsedLength) {
  EXPECT_EQ(0u, ParseDouble(""));
  EXPECT_EQ(0u, ParseDouble("  "));
  EXPECT_EQ(0u, ParseDouble("+"));
  EXPECT_EQ(0u, ParseDouble("-"));
  EXPECT_EQ(0u, ParseDouble("."));
  EXPECT_EQ(0u, ParseDouble("  "));
  EXPECT_EQ(4u, ParseDouble(" 123"));
  EXPECT_EQ(4u, ParseDouble(" 123 "));
  EXPECT_EQ(4u, ParseDouble(" 123px"));
  EXPECT_EQ(5u, ParseDouble("1.234"));
  EXPECT_EQ(5u, ParseDouble("1.234e"));
  EXPECT_EQ(7u, ParseDouble("1.234e1"));
}

void ParseFloat(const String& str, float expected_value) {
  bool ok;
  float value = CharactersToFloat(str.Span8(), &ok);
  EXPECT_TRUE(ok) << "\"" << str << "\"";
  EXPECT_EQ(expected_value, value);
}

void FailToParseFloat(const String& str) {
  bool ok;
  CharactersToFloat(str.Span8(), &ok);
  EXPECT_FALSE(ok) << "\"" << str << "\"";
}

TEST(StringToNumberTest, CharactersToFloat) {
  FailToParseFloat("");
  ParseFloat("0", 0.0f);
  ParseFloat("-0", 0.0f);
  ParseFloat("1.5", 1.5f);
  ParseFloat("+1.5", 1.5f);
  FailToParseFloat("+");
  FailToParseFloat("-");
  ParseFloat(".5", 0.5f);
  ParseFloat("1.", 1.0f);
  FailToParseFloat(".");
  ParseFloat("1e-40", 1e-40f);
  ParseFloat("1e30", 1e+30f);
  ParseFloat("    1.5", 1.5f);
  FailToParseFloat("1.5   ");
  FailToParseFloat("1.5px");
  FailToParseFloat("NaN");
  FailToParseFloat("nan");
  FailToParseFloat("Infinity");
  FailToParseFloat("infinity");
  FailToParseFloat("Inf");
  FailToParseFloat("inf");
  ParseFloat("1e+4000", std::numeric_limits<float>::infinity());
  ParseFloat("-1e+4000", -std::numeric_limits<float>::infinity());
  ParseFloat("1e+100", std::numeric_limits<float>::infinity());
  ParseFloat("-1e+100", -std::numeric_limits<float>::infinity());
  ParseFloat("1e-4000", 0);
  FailToParseFloat("1e");
  FailToParseFloat("1e-");
  FailToParseFloat("1e+");
  FailToParseFloat("1e3.");
  FailToParseFloat("1e3.5");
  FailToParseFloat("1e.3");
}

size_t ParseFloat(const String& str) {
  size_t parsed;
  CharactersToFloat(str.Span8(), parsed);
  return parsed;
}

TEST(StringToNumberTest, CharactersToFloatParsedLength) {
  EXPECT_EQ(0u, ParseFloat(""));
  EXPECT_EQ(0u, ParseFloat("  "));
  EXPECT_EQ(0u, ParseFloat("+"));
  EXPECT_EQ(0u, ParseFloat("-"));
  EXPECT_EQ(0u, ParseFloat("."));
  EXPECT_EQ(0u, ParseFloat("  "));
  EXPECT_EQ(4u, ParseFloat(" 123"));
  EXPECT_EQ(4u, ParseFloat(" 123 "));
  EXPECT_EQ(4u, ParseFloat(" 123px"));
  EXPECT_EQ(5u, ParseFloat("1.234"));
  EXPECT_EQ(5u, ParseFloat("1.234e"));
  EXPECT_EQ(7u, ParseFloat("1.234e1"));
}

}  // namespace WTF

"""

```