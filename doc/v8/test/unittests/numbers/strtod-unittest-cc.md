Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Identify the Core Functionality:** The filename `strtod-unittest.cc` and the inclusion of `src/base/numbers/strtod.h` strongly suggest that this code is testing the `Strtod` function. The `unittest` suffix confirms this. The comment mentioning "conversion of strings to doubles" reinforces this.

2. **Understand the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test. The `TEST_F(StrtodTest, ...)` macro is the standard way to define test cases in GTest. This means each `TEST_F` block is an individual test of the `Strtod` function.

3. **Analyze Individual Test Cases:**

   * **`Strtod` Test:** This is the main test case. It systematically checks `Strtod` with various string inputs ("0", "1", "2", "9", "12345", longer digit strings) and different exponent values (positive, negative, zero, large). The `CHECK_EQ` calls verify the expected output against the actual output of `Strtod`. The test cases cover:
      * Basic single-digit numbers.
      * Multi-digit numbers.
      * The impact of different exponents.
      * Edge cases like "0", "", "000000000".
      * Values near the limits of representable doubles (subnormal numbers, infinity).
      * Specific "problematic" cases that caused issues in other languages.

   * **`RandomStrtod` Test:**  This test aims for broader coverage by generating random digit strings of varying lengths and random exponents. It uses the `CheckDouble` function to validate the result.

4. **Deconstruct Helper Functions:**

   * **`StrtodChar`:** This is a simple helper function that converts a C-style string literal to a `Vector<const char>` for easier use with the `Strtod` function being tested. It's a convenience for the tests.

   * **`CompareBignumToDiyFp`:** This function is crucial for the `CheckDouble` function. It compares a large integer representation of the input number (using `Bignum`) with the internal representation of a double (using `DiyFp`). This is a rigorous way to check if the converted double is within the correct range defined by its boundaries. The steps involve:
      * Creating `Bignum` objects from the input string and the `DiyFp` significand.
      * Applying the exponent from the input string to the `Bignum`.
      * Applying the exponent from the `DiyFp` to the other `Bignum`.
      * Comparing the two `Bignum` representations.

   * **`CheckDouble`:** This function determines if the result of `Strtod` is accurate. It does this by:
      * Calculating the correct boundaries for the expected double value using `Double::NormalizedBoundaries`.
      * For zero, it checks against the smallest positive double.
      * For infinity, it checks against the largest representable double.
      * For regular numbers, it checks if the input number (represented as a `Bignum`) falls within the calculated boundaries of the `Strtod` result. The even/odd significand check is related to how ties are handled in floating-point rounding.

   * **`DeterministicRandom`:**  This function generates pseudo-random numbers in a deterministic way. This is important for unit tests to be reproducible. The specific algorithm isn't critical to understanding the test's *purpose*, but knowing it's deterministic is key.

5. **Relate to JavaScript:** The `Strtod` function being tested is directly related to JavaScript's `parseFloat()` function. Both are responsible for parsing strings and converting them into floating-point numbers.

6. **Identify Potential Errors:**  Based on the test cases, common errors when using `parseFloat` (or the underlying `strtod` functionality) include:
    * Incorrectly assuming integer division when working with string representations of numbers.
    * Not handling very large or very small numbers correctly, potentially leading to infinity or zero.
    * Misunderstanding how exponents affect the value.
    * Not considering the limitations of floating-point representation (precision).

7. **Consider `.tq` Extension:**  The prompt specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for implementing built-in functions is important here. While this specific file isn't `.tq`, the fact that it's testing `strtod` suggests that the *implementation* of `parseFloat` in JavaScript *might* involve Torque.

8. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt (functionality, `.tq` extension, JavaScript relationship, code logic, common errors). Use clear and concise language. Provide specific examples for the JavaScript and error sections.

By following these steps, a comprehensive understanding of the `strtod-unittest.cc` code and its purpose can be achieved, leading to a well-structured and informative answer.
好的，让我们来分析一下 `v8/test/unittests/numbers/strtod-unittest.cc` 这个 V8 源代码文件。

**功能列举:**

这个 C++ 文件是 V8 JavaScript 引擎的一部分，它的主要功能是：

1. **单元测试 (Unit Testing):**  这个文件包含了针对 V8 内部用于将字符串转换为双精度浮点数的函数 `Strtod` 的单元测试。单元测试是软件开发中一种常见的实践，用于验证代码的特定部分（这里是 `Strtod` 函数）是否按照预期工作。

2. **测试 `Strtod` 函数的各种输入:**  文件中包含了大量的测试用例，覆盖了 `Strtod` 函数可能接收的各种输入，包括：
   - **正数和零:** "0", "1", "2", "9", "12345" 等。
   - **带不同指数的数字:**  通过 `Strtod(vector, exponent)` 的第二个参数 `exponent` 来模拟乘以 10 的不同幂次，测试正负指数。例如，`Strtod("1", 2)` 相当于 1 * 10^2 = 100。
   - **边界情况:**  测试了接近零的极小值、接近无穷大的极大值以及 IEEE 754 双精度浮点数的边界值。
   - **随机生成的数字:**  使用随机数生成器创建一些测试用例，以增加测试的覆盖范围。
   - **特定问题用例:**  包含了之前在其他语言（如 Java 和 PHP）中导致无限循环的特定字符串输入，用于确保 V8 的实现能够正确处理这些情况。

3. **验证 `Strtod` 函数的正确性:**  每个测试用例都使用 `CHECK_EQ` 宏来断言 `Strtod` 函数的输出与预期的正确结果是否一致。如果断言失败，则表明 `Strtod` 函数在特定输入下存在问题。

4. **使用 `DiyFp` 和 `Bignum` 进行精确比较:**  为了更精确地验证浮点数转换的正确性，测试代码使用了 `DiyFp` (Do-It-Yourself Floating Point) 和 `Bignum` (大数) 类。这允许在不依赖标准 `double` 类型的精度限制下进行比较，特别是对于接近浮点数边界的情况。

**关于 .tq 结尾:**

如果 `v8/test/unittests/numbers/strtod-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是 V8 内部使用的一种领域特定语言，用于实现 JavaScript 的内置函数和运行时库。由于这里是 `.cc` 结尾，它是一个标准的 C++ 源文件。

**与 JavaScript 功能的关系:**

`Strtod` 函数在 V8 中是实现 JavaScript 中 `parseFloat()` 函数的核心部分。 `parseFloat()` 函数用于将字符串解析为浮点数。

**JavaScript 示例:**

```javascript
console.log(parseFloat("0"));      // 输出: 0
console.log(parseFloat("1"));      // 输出: 1
console.log(parseFloat("1e2"));    // 输出: 100
console.log(parseFloat("1e-2"));   // 输出: 0.01
console.log(parseFloat("123.45")); // 输出: 123.45
```

在 JavaScript 引擎的内部实现中，当执行 `parseFloat("1e2")` 时，V8 可能会调用类似 `Strtod("1", 2)` 的操作（内部表示可能略有不同，但概念相似）来完成字符串到数字的转换。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下测试用例：

```c++
TEST_F(StrtodTest, ExampleInference) {
  Vector<const char> vector;

  vector = CStrVector("123");
  CHECK_EQ(123.0, Strtod(vector, 0));  // 假设输入 "123"，指数为 0，输出应为 123.0
  CHECK_EQ(1230.0, Strtod(vector, 1)); // 假设输入 "123"，指数为 1，输出应为 1230.0 (123 * 10^1)
  CHECK_EQ(1.23, Strtod(vector, -2));  // 假设输入 "123"，指数为 -2，输出应为 1.23 (123 * 10^-2)
}
```

**假设输入与输出:**

| 输入字符串 | 指数 | 预期输出 |
|---|---|---|
| "123" | 0 | 123.0 |
| "123" | 1 | 1230.0 |
| "123" | -2 | 1.23 |

**涉及用户常见的编程错误:**

使用 JavaScript 的 `parseFloat()` (以及底层 C++ 的 `Strtod`) 时，用户可能会遇到以下常见的编程错误：

1. **未考虑非数字字符:** `parseFloat()` 会尝试从字符串的开头解析数字，直到遇到非数字字符。如果字符串开头不是数字，则返回 `NaN` (Not a Number)。

   **JavaScript 示例:**
   ```javascript
   console.log(parseFloat("abc123")); // 输出: NaN
   console.log(parseFloat("123abc")); // 输出: 123
   ```

2. **精度问题:** 浮点数在计算机中以二进制形式存储，可能无法精确表示某些十进制小数。这可能导致一些意想不到的结果。

   **JavaScript 示例:**
   ```javascript
   console.log(0.1 + 0.2);          // 输出: 0.30000000000000004 (而不是精确的 0.3)
   console.log(parseFloat("0.1") + parseFloat("0.2")); // 也会有类似的精度问题
   ```

3. **误解指数表示:**  用户可能不熟悉或错误地使用科学计数法的字符串表示。

   **JavaScript 示例:**
   ```javascript
   console.log(parseFloat("10e2"));  // 输出: 1000
   console.log(parseFloat("10e-2")); // 输出: 0.1
   console.log(parseFloat("e10"));   // 输出: NaN (开头不是数字)
   ```

4. **依赖本地化设置:**  `parseFloat()`  的行为在某些旧版本的浏览器中可能受到本地化设置的影响，例如小数点分隔符是逗号还是点。不过，现代 JavaScript 实现通常使用点作为小数点分隔符。

5. **parseInt() 与 parseFloat() 的混淆:** 用户可能错误地使用了 `parseInt()`，它只解析整数部分，会截断小数部分。

   **JavaScript 示例:**
   ```javascript
   console.log(parseInt("123.45")); // 输出: 123
   console.log(parseFloat("123.45")); // 输出: 123.45
   ```

总结来说，`v8/test/unittests/numbers/strtod-unittest.cc` 是一个关键的测试文件，用于确保 V8 引擎中字符串到浮点数转换功能的正确性和健壮性，这直接关系到 JavaScript 中 `parseFloat()` 函数的可靠性。

### 提示词
```
这是目录为v8/test/unittests/numbers/strtod-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/numbers/strtod-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2006-2008 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "src/base/numbers/strtod.h"

#include <stdlib.h>

#include "src/base/numbers/bignum.h"
#include "src/base/numbers/diy-fp.h"
#include "src/base/numbers/double.h"
#include "src/base/utils/random-number-generator.h"
#include "src/init/v8.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace base {

using StrtodTest = ::testing::Test;

static double StrtodChar(const char* str, int exponent) {
  return Strtod(CStrVector(str), exponent);
}

TEST_F(StrtodTest, Strtod) {
  Vector<const char> vector;

  vector = CStrVector("0");
  CHECK_EQ(0.0, Strtod(vector, 1));
  CHECK_EQ(0.0, Strtod(vector, 2));
  CHECK_EQ(0.0, Strtod(vector, -2));
  CHECK_EQ(0.0, Strtod(vector, -999));
  CHECK_EQ(0.0, Strtod(vector, +999));

  vector = CStrVector("1");
  CHECK_EQ(1.0, Strtod(vector, 0));
  CHECK_EQ(10.0, Strtod(vector, 1));
  CHECK_EQ(100.0, Strtod(vector, 2));
  CHECK_EQ(1e20, Strtod(vector, 20));
  CHECK_EQ(1e22, Strtod(vector, 22));
  CHECK_EQ(1e23, Strtod(vector, 23));
  CHECK_EQ(1e35, Strtod(vector, 35));
  CHECK_EQ(1e36, Strtod(vector, 36));
  CHECK_EQ(1e37, Strtod(vector, 37));
  CHECK_EQ(1e-1, Strtod(vector, -1));
  CHECK_EQ(1e-2, Strtod(vector, -2));
  CHECK_EQ(1e-5, Strtod(vector, -5));
  CHECK_EQ(1e-20, Strtod(vector, -20));
  CHECK_EQ(1e-22, Strtod(vector, -22));
  CHECK_EQ(1e-23, Strtod(vector, -23));
  CHECK_EQ(1e-25, Strtod(vector, -25));
  CHECK_EQ(1e-39, Strtod(vector, -39));

  vector = CStrVector("2");
  CHECK_EQ(2.0, Strtod(vector, 0));
  CHECK_EQ(20.0, Strtod(vector, 1));
  CHECK_EQ(200.0, Strtod(vector, 2));
  CHECK_EQ(2e20, Strtod(vector, 20));
  CHECK_EQ(2e22, Strtod(vector, 22));
  CHECK_EQ(2e23, Strtod(vector, 23));
  CHECK_EQ(2e35, Strtod(vector, 35));
  CHECK_EQ(2e36, Strtod(vector, 36));
  CHECK_EQ(2e37, Strtod(vector, 37));
  CHECK_EQ(2e-1, Strtod(vector, -1));
  CHECK_EQ(2e-2, Strtod(vector, -2));
  CHECK_EQ(2e-5, Strtod(vector, -5));
  CHECK_EQ(2e-20, Strtod(vector, -20));
  CHECK_EQ(2e-22, Strtod(vector, -22));
  CHECK_EQ(2e-23, Strtod(vector, -23));
  CHECK_EQ(2e-25, Strtod(vector, -25));
  CHECK_EQ(2e-39, Strtod(vector, -39));

  vector = CStrVector("9");
  CHECK_EQ(9.0, Strtod(vector, 0));
  CHECK_EQ(90.0, Strtod(vector, 1));
  CHECK_EQ(900.0, Strtod(vector, 2));
  CHECK_EQ(9e20, Strtod(vector, 20));
  CHECK_EQ(9e22, Strtod(vector, 22));
  CHECK_EQ(9e23, Strtod(vector, 23));
  CHECK_EQ(9e35, Strtod(vector, 35));
  CHECK_EQ(9e36, Strtod(vector, 36));
  CHECK_EQ(9e37, Strtod(vector, 37));
  CHECK_EQ(9e-1, Strtod(vector, -1));
  CHECK_EQ(9e-2, Strtod(vector, -2));
  CHECK_EQ(9e-5, Strtod(vector, -5));
  CHECK_EQ(9e-20, Strtod(vector, -20));
  CHECK_EQ(9e-22, Strtod(vector, -22));
  CHECK_EQ(9e-23, Strtod(vector, -23));
  CHECK_EQ(9e-25, Strtod(vector, -25));
  CHECK_EQ(9e-39, Strtod(vector, -39));

  vector = CStrVector("12345");
  CHECK_EQ(12345.0, Strtod(vector, 0));
  CHECK_EQ(123450.0, Strtod(vector, 1));
  CHECK_EQ(1234500.0, Strtod(vector, 2));
  CHECK_EQ(12345e20, Strtod(vector, 20));
  CHECK_EQ(12345e22, Strtod(vector, 22));
  CHECK_EQ(12345e23, Strtod(vector, 23));
  CHECK_EQ(12345e30, Strtod(vector, 30));
  CHECK_EQ(12345e31, Strtod(vector, 31));
  CHECK_EQ(12345e32, Strtod(vector, 32));
  CHECK_EQ(12345e35, Strtod(vector, 35));
  CHECK_EQ(12345e36, Strtod(vector, 36));
  CHECK_EQ(12345e37, Strtod(vector, 37));
  CHECK_EQ(12345e-1, Strtod(vector, -1));
  CHECK_EQ(12345e-2, Strtod(vector, -2));
  CHECK_EQ(12345e-5, Strtod(vector, -5));
  CHECK_EQ(12345e-20, Strtod(vector, -20));
  CHECK_EQ(12345e-22, Strtod(vector, -22));
  CHECK_EQ(12345e-23, Strtod(vector, -23));
  CHECK_EQ(12345e-25, Strtod(vector, -25));
  CHECK_EQ(12345e-39, Strtod(vector, -39));

  vector = CStrVector("12345678901234");
  CHECK_EQ(12345678901234.0, Strtod(vector, 0));
  CHECK_EQ(123456789012340.0, Strtod(vector, 1));
  CHECK_EQ(1234567890123400.0, Strtod(vector, 2));
  CHECK_EQ(12345678901234e20, Strtod(vector, 20));
  CHECK_EQ(12345678901234e22, Strtod(vector, 22));
  CHECK_EQ(12345678901234e23, Strtod(vector, 23));
  CHECK_EQ(12345678901234e30, Strtod(vector, 30));
  CHECK_EQ(12345678901234e31, Strtod(vector, 31));
  CHECK_EQ(12345678901234e32, Strtod(vector, 32));
  CHECK_EQ(12345678901234e35, Strtod(vector, 35));
  CHECK_EQ(12345678901234e36, Strtod(vector, 36));
  CHECK_EQ(12345678901234e37, Strtod(vector, 37));
  CHECK_EQ(12345678901234e-1, Strtod(vector, -1));
  CHECK_EQ(12345678901234e-2, Strtod(vector, -2));
  CHECK_EQ(12345678901234e-5, Strtod(vector, -5));
  CHECK_EQ(12345678901234e-20, Strtod(vector, -20));
  CHECK_EQ(12345678901234e-22, Strtod(vector, -22));
  CHECK_EQ(12345678901234e-23, Strtod(vector, -23));
  CHECK_EQ(12345678901234e-25, Strtod(vector, -25));
  CHECK_EQ(12345678901234e-39, Strtod(vector, -39));

  vector = CStrVector("123456789012345");
  CHECK_EQ(123456789012345.0, Strtod(vector, 0));
  CHECK_EQ(1234567890123450.0, Strtod(vector, 1));
  CHECK_EQ(12345678901234500.0, Strtod(vector, 2));
  CHECK_EQ(123456789012345e20, Strtod(vector, 20));
  CHECK_EQ(123456789012345e22, Strtod(vector, 22));
  CHECK_EQ(123456789012345e23, Strtod(vector, 23));
  CHECK_EQ(123456789012345e35, Strtod(vector, 35));
  CHECK_EQ(123456789012345e36, Strtod(vector, 36));
  CHECK_EQ(123456789012345e37, Strtod(vector, 37));
  CHECK_EQ(123456789012345e39, Strtod(vector, 39));
  CHECK_EQ(123456789012345e-1, Strtod(vector, -1));
  CHECK_EQ(123456789012345e-2, Strtod(vector, -2));
  CHECK_EQ(123456789012345e-5, Strtod(vector, -5));
  CHECK_EQ(123456789012345e-20, Strtod(vector, -20));
  CHECK_EQ(123456789012345e-22, Strtod(vector, -22));
  CHECK_EQ(123456789012345e-23, Strtod(vector, -23));
  CHECK_EQ(123456789012345e-25, Strtod(vector, -25));
  CHECK_EQ(123456789012345e-39, Strtod(vector, -39));

  CHECK_EQ(0.0, StrtodChar("0", 12345));
  CHECK_EQ(0.0, StrtodChar("", 1324));
  CHECK_EQ(0.0, StrtodChar("000000000", 123));
  CHECK_EQ(0.0, StrtodChar("2", -324));
  CHECK_EQ(4e-324, StrtodChar("3", -324));
  // It would be more readable to put non-zero literals on the left side (i.e.
  //   CHECK_EQ(1e-325, StrtodChar("1", -325))), but then Gcc complains that
  // they are truncated to zero.
  CHECK_EQ(0.0, StrtodChar("1", -325));
  CHECK_EQ(0.0, StrtodChar("1", -325));
  CHECK_EQ(0.0, StrtodChar("20000", -328));
  CHECK_EQ(40000e-328, StrtodChar("30000", -328));
  CHECK_EQ(0.0, StrtodChar("10000", -329));
  CHECK_EQ(0.0, StrtodChar("90000", -329));
  CHECK_EQ(0.0, StrtodChar("000000001", -325));
  CHECK_EQ(0.0, StrtodChar("000000001", -325));
  CHECK_EQ(0.0, StrtodChar("0000000020000", -328));
  CHECK_EQ(40000e-328, StrtodChar("00000030000", -328));
  CHECK_EQ(0.0, StrtodChar("0000000010000", -329));
  CHECK_EQ(0.0, StrtodChar("0000000090000", -329));

  // It would be more readable to put the literals (and not V8_INFINITY) on the
  // left side (i.e. CHECK_EQ(1e309, StrtodChar("1", 309))), but then Gcc
  // complains that the floating constant exceeds range of 'double'.
  CHECK_EQ(V8_INFINITY, StrtodChar("1", 309));
  CHECK_EQ(1e308, StrtodChar("1", 308));
  CHECK_EQ(1234e305, StrtodChar("1234", 305));
  CHECK_EQ(1234e304, StrtodChar("1234", 304));
  CHECK_EQ(V8_INFINITY, StrtodChar("18", 307));
  CHECK_EQ(17e307, StrtodChar("17", 307));
  CHECK_EQ(V8_INFINITY, StrtodChar("0000001", 309));
  CHECK_EQ(1e308, StrtodChar("00000001", 308));
  CHECK_EQ(1234e305, StrtodChar("00000001234", 305));
  CHECK_EQ(1234e304, StrtodChar("000000001234", 304));
  CHECK_EQ(V8_INFINITY, StrtodChar("0000000018", 307));
  CHECK_EQ(17e307, StrtodChar("0000000017", 307));
  CHECK_EQ(V8_INFINITY, StrtodChar("1000000", 303));
  CHECK_EQ(1e308, StrtodChar("100000", 303));
  CHECK_EQ(1234e305, StrtodChar("123400000", 300));
  CHECK_EQ(1234e304, StrtodChar("123400000", 299));
  CHECK_EQ(V8_INFINITY, StrtodChar("180000000", 300));
  CHECK_EQ(17e307, StrtodChar("170000000", 300));
  CHECK_EQ(V8_INFINITY, StrtodChar("00000001000000", 303));
  CHECK_EQ(1e308, StrtodChar("000000000000100000", 303));
  CHECK_EQ(1234e305, StrtodChar("00000000123400000", 300));
  CHECK_EQ(1234e304, StrtodChar("0000000123400000", 299));
  CHECK_EQ(V8_INFINITY, StrtodChar("00000000180000000", 300));
  CHECK_EQ(17e307, StrtodChar("00000000170000000", 300));
  CHECK_EQ(1.7976931348623157E+308, StrtodChar("17976931348623157", 292));
  CHECK_EQ(1.7976931348623158E+308, StrtodChar("17976931348623158", 292));
  CHECK_EQ(V8_INFINITY, StrtodChar("17976931348623159", 292));

  // The following number is the result of 89255.0/1e22. Both floating-point
  // numbers can be accurately represented with doubles. However on Linux,x86
  // the floating-point stack is set to 80bits and the double-rounding
  // introduces an error.
  CHECK_EQ(89255e-22, StrtodChar("89255", -22));

  // Some random values.
  CHECK_EQ(358416272e-33, StrtodChar("358416272", -33));
  CHECK_EQ(104110013277974872254e-225,
           StrtodChar("104110013277974872254", -225));

  CHECK_EQ(123456789e108, StrtodChar("123456789", 108));
  CHECK_EQ(123456789e109, StrtodChar("123456789", 109));
  CHECK_EQ(123456789e110, StrtodChar("123456789", 110));
  CHECK_EQ(123456789e111, StrtodChar("123456789", 111));
  CHECK_EQ(123456789e112, StrtodChar("123456789", 112));
  CHECK_EQ(123456789e113, StrtodChar("123456789", 113));
  CHECK_EQ(123456789e114, StrtodChar("123456789", 114));
  CHECK_EQ(123456789e115, StrtodChar("123456789", 115));

  CHECK_EQ(1234567890123456789012345e108,
           StrtodChar("1234567890123456789012345", 108));
  CHECK_EQ(1234567890123456789012345e109,
           StrtodChar("1234567890123456789012345", 109));
  CHECK_EQ(1234567890123456789012345e110,
           StrtodChar("1234567890123456789012345", 110));
  CHECK_EQ(1234567890123456789012345e111,
           StrtodChar("1234567890123456789012345", 111));
  CHECK_EQ(1234567890123456789012345e112,
           StrtodChar("1234567890123456789012345", 112));
  CHECK_EQ(1234567890123456789012345e113,
           StrtodChar("1234567890123456789012345", 113));
  CHECK_EQ(1234567890123456789012345e114,
           StrtodChar("1234567890123456789012345", 114));
  CHECK_EQ(1234567890123456789012345e115,
           StrtodChar("1234567890123456789012345", 115));

  CHECK_EQ(1234567890123456789052345e108,
           StrtodChar("1234567890123456789052345", 108));
  CHECK_EQ(1234567890123456789052345e109,
           StrtodChar("1234567890123456789052345", 109));
  CHECK_EQ(1234567890123456789052345e110,
           StrtodChar("1234567890123456789052345", 110));
  CHECK_EQ(1234567890123456789052345e111,
           StrtodChar("1234567890123456789052345", 111));
  CHECK_EQ(1234567890123456789052345e112,
           StrtodChar("1234567890123456789052345", 112));
  CHECK_EQ(1234567890123456789052345e113,
           StrtodChar("1234567890123456789052345", 113));
  CHECK_EQ(1234567890123456789052345e114,
           StrtodChar("1234567890123456789052345", 114));
  CHECK_EQ(1234567890123456789052345e115,
           StrtodChar("1234567890123456789052345", 115));

  CHECK_EQ(5.445618932859895e-255,
           StrtodChar("5445618932859895362967233318697132813618813095743952975"
                      "4392982234069699615600475529427176366709107287468930197"
                      "8628345413991790019316974825934906752493984055268219809"
                      "5012176093045431437495773903922425632551857520884625114"
                      "6241265881735209066709685420744388526014389929047617597"
                      "0302268848374508109029268898695825171158085457567481507"
                      "4162979705098246243690189880319928315307816832576838178"
                      "2563074014542859888710209237525873301724479666744537857"
                      "9026553346649664045621387124193095870305991178772256504"
                      "4368663670643970181259143319016472430928902201239474588"
                      "1392338901353291306607057623202353588698746085415097902"
                      "6640064319118728664842287477491068264828851624402189317"
                      "2769161449825765517353755844373640588822904791244190695"
                      "2998382932630754670573838138825217065450843010498555058"
                      "88186560731",
                      -1035));

  // Boundary cases. Boundaries themselves should round to even.
  //
  // 0x1FFFFFFFFFFFF * 2^3 = 72057594037927928
  //                   next: 72057594037927936
  //               boundary: 72057594037927932  should round up.
  CHECK_EQ(72057594037927928.0, StrtodChar("72057594037927928", 0));
  CHECK_EQ(72057594037927936.0, StrtodChar("72057594037927936", 0));
  CHECK_EQ(72057594037927936.0, StrtodChar("72057594037927932", 0));
  CHECK_EQ(72057594037927928.0, StrtodChar("7205759403792793199999", -5));
  CHECK_EQ(72057594037927936.0, StrtodChar("7205759403792793200001", -5));

  // 0x1FFFFFFFFFFFF * 2^10 = 9223372036854774784
  //                    next: 9223372036854775808
  //                boundary: 9223372036854775296 should round up.
  CHECK_EQ(9223372036854774784.0, StrtodChar("9223372036854774784", 0));
  CHECK_EQ(9223372036854775808.0, StrtodChar("9223372036854775808", 0));
  CHECK_EQ(9223372036854775808.0, StrtodChar("9223372036854775296", 0));
  CHECK_EQ(9223372036854774784.0, StrtodChar("922337203685477529599999", -5));
  CHECK_EQ(9223372036854775808.0, StrtodChar("922337203685477529600001", -5));

  // 0x1FFFFFFFFFFFF * 2^50 = 10141204801825834086073718800384
  //                    next: 10141204801825835211973625643008
  //                boundary: 10141204801825834649023672221696 should round up.
  CHECK_EQ(10141204801825834086073718800384.0,
           StrtodChar("10141204801825834086073718800384", 0));
  CHECK_EQ(10141204801825835211973625643008.0,
           StrtodChar("10141204801825835211973625643008", 0));
  CHECK_EQ(10141204801825835211973625643008.0,
           StrtodChar("10141204801825834649023672221696", 0));
  CHECK_EQ(10141204801825834086073718800384.0,
           StrtodChar("1014120480182583464902367222169599999", -5));
  CHECK_EQ(10141204801825835211973625643008.0,
           StrtodChar("1014120480182583464902367222169600001", -5));

  // 0x1FFFFFFFFFFFF * 2^99 = 5708990770823838890407843763683279797179383808
  //                    next: 5708990770823839524233143877797980545530986496
  //                boundary: 5708990770823839207320493820740630171355185152
  // The boundary should round up.
  CHECK_EQ(5708990770823838890407843763683279797179383808.0,
           StrtodChar("5708990770823838890407843763683279797179383808", 0));
  CHECK_EQ(5708990770823839524233143877797980545530986496.0,
           StrtodChar("5708990770823839524233143877797980545530986496", 0));
  CHECK_EQ(5708990770823839524233143877797980545530986496.0,
           StrtodChar("5708990770823839207320493820740630171355185152", 0));
  CHECK_EQ(5708990770823838890407843763683279797179383808.0,
           StrtodChar("5708990770823839207320493820740630171355185151999", -3));
  CHECK_EQ(5708990770823839524233143877797980545530986496.0,
           StrtodChar("5708990770823839207320493820740630171355185152001", -3));

  // The following test-cases got some public attention in early 2011 when they
  // sent Java and PHP into an infinite loop.
  CHECK_EQ(2.225073858507201e-308, StrtodChar("22250738585072011", -324));
  CHECK_EQ(2.22507385850720138309e-308,
           StrtodChar("22250738585072011360574097967091319759348195463516456480"
                      "23426109724822222021076945516529523908135087914149158913"
                      "03962110687008643869459464552765720740782062174337998814"
                      "10632673292535522868813721490129811224514518898490572223"
                      "07285255133155755015914397476397983411801999323962548289"
                      "01710708185069063066665599493827577257201576306269066333"
                      "26475653000092458883164330377797918696120494973903778297"
                      "04905051080609940730262937128958950003583799967207254304"
                      "36028407889577179615094551674824347103070260914462157228"
                      "98802581825451803257070188608721131280795122334262883686"
                      "22321503775666622503982534335974568884423900265498198385"
                      "48794829220689472168983109969836584681402285424333066033"
                      "98508864458040010349339704275671864433837704860378616227"
                      "71738545623065874679014086723327636718751",
                      -1076));
}

static int CompareBignumToDiyFp(const Bignum& bignum_digits,
                                int bignum_exponent, DiyFp diy_fp) {
  Bignum bignum;
  bignum.AssignBignum(bignum_digits);
  Bignum other;
  other.AssignUInt64(diy_fp.f());
  if (bignum_exponent >= 0) {
    bignum.MultiplyByPowerOfTen(bignum_exponent);
  } else {
    other.MultiplyByPowerOfTen(-bignum_exponent);
  }
  if (diy_fp.e() >= 0) {
    other.ShiftLeft(diy_fp.e());
  } else {
    bignum.ShiftLeft(-diy_fp.e());
  }
  return Bignum::Compare(bignum, other);
}

static bool CheckDouble(Vector<const char> buffer, int exponent,
                        double to_check) {
  DiyFp lower_boundary;
  DiyFp upper_boundary;
  Bignum input_digits;
  input_digits.AssignDecimalString(buffer);
  if (to_check == 0.0) {
    const double kMinDouble = 4e-324;
    // Check that the buffer*10^exponent < (0 + kMinDouble)/2.
    Double d(kMinDouble);
    d.NormalizedBoundaries(&lower_boundary, &upper_boundary);
    return CompareBignumToDiyFp(input_digits, exponent, lower_boundary) <= 0;
  }
  if (to_check == V8_INFINITY) {
    const double kMaxDouble = 1.7976931348623157e308;
    // Check that the buffer*10^exponent >= boundary between kMaxDouble and inf.
    Double d(kMaxDouble);
    d.NormalizedBoundaries(&lower_boundary, &upper_boundary);
    return CompareBignumToDiyFp(input_digits, exponent, upper_boundary) >= 0;
  }
  Double d(to_check);
  d.NormalizedBoundaries(&lower_boundary, &upper_boundary);
  if ((d.Significand() & 1) == 0) {
    return CompareBignumToDiyFp(input_digits, exponent, lower_boundary) >= 0 &&
           CompareBignumToDiyFp(input_digits, exponent, upper_boundary) <= 0;
  } else {
    return CompareBignumToDiyFp(input_digits, exponent, lower_boundary) > 0 &&
           CompareBignumToDiyFp(input_digits, exponent, upper_boundary) < 0;
  }
}

// Copied from v8.cc and adapted to make the function deterministic.
static uint32_t DeterministicRandom() {
  // Random number generator using George Marsaglia's MWC algorithm.
  static uint32_t hi = 0;
  static uint32_t lo = 0;

  // Initialization values don't have any special meaning. (They are the result
  // of two calls to rand().)
  if (hi == 0) hi = 0xBFE166E7;
  if (lo == 0) lo = 0x64D1C3C9;

  // Mix the bits.
  hi = 36969 * (hi & 0xFFFF) + (hi >> 16);
  lo = 18273 * (lo & 0xFFFF) + (lo >> 16);
  return (hi << 16) + (lo & 0xFFFF);
}

static const int kBufferSize = 1024;
static const int kShortStrtodRandomCount = 2;
static const int kLargeStrtodRandomCount = 2;

TEST_F(StrtodTest, RandomStrtod) {
  base::RandomNumberGenerator rng;
  char buffer[kBufferSize];
  for (int length = 1; length < 15; length++) {
    for (int i = 0; i < kShortStrtodRandomCount; ++i) {
      int pos = 0;
      for (int j = 0; j < length; ++j) {
        buffer[pos++] = rng.NextInt(10) + '0';
      }
      int exponent = DeterministicRandom() % (25 * 2 + 1) - 25 - length;
      buffer[pos] = '\0';
      Vector<const char> vector(buffer, pos);
      double strtod_result = Strtod(vector, exponent);
      CHECK(CheckDouble(vector, exponent, strtod_result));
    }
  }
  for (int length = 15; length < 800; length += 2) {
    for (int i = 0; i < kLargeStrtodRandomCount; ++i) {
      int pos = 0;
      for (int j = 0; j < length; ++j) {
        buffer[pos++] = rng.NextInt(10) + '0';
      }
      int exponent = DeterministicRandom() % (308 * 2 + 1) - 308 - length;
      buffer[pos] = '\0';
      Vector<const char> vector(buffer, pos);
      double strtod_result = Strtod(vector, exponent);
      CHECK(CheckDouble(vector, exponent, strtod_result));
    }
  }
}

}  // namespace base
}  // namespace v8
```