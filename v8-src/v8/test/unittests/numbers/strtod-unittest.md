Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understanding the Goal:** The request asks for a summary of the C++ file's functionality and its relation to JavaScript, providing an example if a connection exists. The file path `v8/test/unittests/numbers/strtod-unittest.cc` immediately suggests this is a *test* file for a function related to number conversion, specifically `strtod`.

2. **Initial Code Scan (Keywords and Structure):**  I'll quickly scan the code for important keywords and structural elements:
    * `#include`:  Shows dependencies on other V8 components (`strtod.h`, `bignum.h`, `diy-fp.h`, `double.h`), standard library (`stdlib.h`), and testing frameworks (`gtest`). This hints at the types of operations and the testing methodology.
    * `namespace v8 { namespace base {`: Indicates this code is part of the V8 JavaScript engine. This is a crucial piece of information.
    * `TEST_F(StrtodTest, ...)`:  Confirms this is a test file using Google Test. Each `TEST_F` block represents a specific test case.
    * `Strtod(CStrVector(str), exponent)` or `StrtodChar(str, exponent)`: This is the function under test. It takes a string and an exponent. The name strongly suggests "string to double".
    * `CHECK_EQ(...)`:  Assertions used to verify the correctness of the `Strtod` function. The first argument is the expected value, and the second is the actual result.
    * Constants like `V8_INFINITY`: Suggests handling of special floating-point values.
    * Loops and random number generation in `RandomStrtod`:  Indicates testing with a variety of inputs.
    * `CompareBignumToDiyFp` and `CheckDouble`: These helper functions are used for more rigorous verification, likely due to the complexities of floating-point representation.

3. **Inferring Functionality of `Strtod`:** Based on the test cases, the `Strtod` function appears to:
    * Take a string representation of a number and an integer exponent.
    * Convert the string to a double-precision floating-point number.
    * Apply the exponent to the number (effectively multiplying or dividing by powers of 10).

4. **Connecting to JavaScript:** The crucial connection is the `namespace v8`. V8 is the JavaScript engine used in Chrome and Node.js. JavaScript has a built-in function for converting strings to numbers: `parseFloat()`. This is the likely counterpart to the C++ `Strtod`. While `parseFloat` doesn't directly take an exponent argument, the underlying functionality of parsing a string and converting it to a floating-point number is the same.

5. **Constructing the JavaScript Example:**  The C++ test cases provide direct inspiration for JavaScript examples. I can take the string inputs from the `CStrVector` calls and simulate the exponent manipulation in JavaScript using multiplication by powers of 10. For instance, `Strtod(CStrVector("1"), 2)` resulting in `100.0` can be replicated in JavaScript with `parseFloat("1") * Math.pow(10, 2)`.

6. **Explaining the Relationship:** I need to clearly state that the C++ code is part of V8, and `Strtod` is a low-level function within the engine responsible for the core string-to-number conversion. The JavaScript `parseFloat` (and `Number()`) rely on this kind of underlying implementation in the engine.

7. **Summarizing the C++ File's Purpose:** I can now summarize the file's main goal: testing the correctness of the `Strtod` function within V8. The tests cover various edge cases, including different magnitudes, exponents, and boundary conditions for floating-point numbers.

8. **Review and Refine:** I'll reread my analysis to ensure clarity, accuracy, and completeness. I'll double-check that the JavaScript examples accurately reflect the C++ behavior. I will also ensure the explanation of the relationship between `Strtod` and JavaScript's number conversion functions is clear. For instance, initially, I might have just said "It's like `parseFloat`," but refining it to explain the underlying engine role provides more depth. I should also mention `Number()` as it performs similar conversions.

By following these steps, I can systematically analyze the C++ code, identify its purpose, and establish its connection to relevant JavaScript features, ultimately providing a comprehensive and informative answer.
这个C++源代码文件 `strtod-unittest.cc` 的主要功能是 **对 V8 JavaScript 引擎中用于将字符串转换为双精度浮点数的 `Strtod` 函数进行单元测试。**

更具体地说，这个文件包含了多个测试用例，用于验证 `Strtod` 函数在各种输入情况下的行为是否正确。 这些测试用例涵盖了以下方面：

* **基本的数字转换:** 测试将简单的整数和小数字符串转换为对应的浮点数。
* **指数的处理:**  `Strtod` 函数除了接收数字字符串外，还可以接收一个额外的 `exponent` 参数，用于指定 10 的幂次方。测试用例验证了不同 `exponent` 值对转换结果的影响。
* **边界情况:** 测试了零、正无穷大 (V8_INFINITY)、非常大和非常小的数字的转换。
* **精度测试:** 包含了一些高精度数字的转换，并与预期结果进行比较，以确保转换的精度。
* **随机测试:**  通过生成随机的数字字符串和指数，进行大量的随机测试，以提高测试覆盖率，发现潜在的边界情况或错误。
* **与 `Bignum` 和 `DiyFp` 的比较:** 使用 V8 内部的 `Bignum` (用于高精度整数运算) 和 `DiyFp` (Double-Integer representation of floating-point numbers) 类型进行更精确的比较，以验证 `Strtod` 函数的转换结果是否在正确的浮点数边界内。
* **特定的错误或边界情况:**  例如，文件中提到了 2011 年初导致 Java 和 PHP 进入无限循环的特定测试用例，这表明这些测试用例旨在暴露和验证潜在的解析问题。

**它与 JavaScript 的功能有关系，因为 `Strtod` 函数是 V8 引擎的核心组成部分，而 V8 引擎正是 JavaScript 的执行环境。**  当你在 JavaScript 中使用将字符串转换为数字的函数，例如 `parseFloat()` 或 `Number()` 时，V8 引擎在底层很可能就会调用类似 `Strtod` 这样的函数来进行实际的转换工作。

**JavaScript 举例说明:**

在 JavaScript 中，我们可以使用 `parseFloat()` 函数将字符串转换为浮点数。  `strtod-unittest.cc` 中的测试用例实际上是在测试 V8 引擎内部实现 `parseFloat()` 功能的核心逻辑。

例如，在 `strtod-unittest.cc` 中有以下测试用例：

```c++
TEST_F(StrtodTest, Strtod) {
  // ...
  vector = CStrVector("12345");
  CHECK_EQ(12345.0, Strtod(vector, 0));
  CHECK_EQ(123450.0, Strtod(vector, 1));
  CHECK_EQ(12345e-2, Strtod(vector, -2));
  // ...
}
```

在 JavaScript 中，我们可以得到类似的结果：

```javascript
console.log(parseFloat("12345")); // 输出: 12345
console.log(parseFloat("12345") * Math.pow(10, 1)); // 输出: 123450
console.log(parseFloat("12345") * Math.pow(10, -2)); // 输出: 123.45

// 或者更直接的表示
console.log(parseFloat("12345e0"));   // 输出: 12345
console.log(parseFloat("12345e1"));   // 输出: 123450
console.log(parseFloat("12345e-2"));  // 输出: 123.45
```

在这个例子中，C++ 的 `Strtod(vector, exponent)` 函数的功能与 JavaScript 的 `parseFloat()` 函数结合指数运算的功能是相似的。  `parseFloat()` 可以解析带有指数表示的字符串（如 "12345e-2"），V8 引擎内部的 `Strtod` 函数在处理这类字符串时起着关键作用。

再比如，测试文件中处理边界情况的例子：

```c++
CHECK_EQ(V8_INFINITY, StrtodChar("1", 309));
```

在 JavaScript 中，也会得到类似的结果：

```javascript
console.log(parseFloat("1e309")); // 输出: Infinity
```

总而言之，`strtod-unittest.cc` 是 V8 引擎中一个重要的测试文件，它确保了 JavaScript 中字符串到数字转换功能的正确性和可靠性。  理解这个文件可以帮助我们更好地理解 JavaScript 引擎的内部工作原理以及浮点数转换的复杂性。

Prompt: 
```
这是目录为v8/test/unittests/numbers/strtod-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```