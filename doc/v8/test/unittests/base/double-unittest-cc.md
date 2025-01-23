Response:
Let's break down the thought process for analyzing the provided C++ unit test code.

1. **Understand the Goal:** The request asks for the functionality of the `double-unittest.cc` file within the V8 project. It also asks about its nature (Torque/JavaScript relevance), provides examples, and points out common errors.

2. **Initial Code Scan:**  The first step is to quickly scan the code to identify key elements:
    * `#include` directives: These tell us what other code this file relies on. `src/base/numbers/double.h` is crucial, suggesting this file tests the `Double` class. `gtest/gtest.h` indicates it's a unit test file using the Google Test framework.
    * `namespace v8`, `namespace base`:  This indicates the code belongs to the V8 JavaScript engine's base library.
    * `using DoubleTest = ::testing::Test;`: This sets up the test fixture.
    * `TEST_F(DoubleTest, ...)`: These are the individual test cases. The names of these tests give strong hints about what's being tested.

3. **Analyze Individual Test Cases:** Go through each `TEST_F` block and determine its purpose. The names are quite descriptive:
    * `Uint64Conversions`:  Likely tests conversions between `uint64_t` and the `Double` class.
    * `AsDiyFp`:  Probably tests conversion to a `DiyFp` (Do-It-Yourself Floating Point) representation.
    * `AsNormalizedDiyFp`:  Similar to the above, but a "normalized" version.
    * `IsDenormal`: Checks the `IsDenormal()` method.
    * `IsSpecial`: Checks the `IsSpecial()` method (infinity, NaN).
    * `IsInfinite`: Checks the `IsInfinite()` method.
    * `Sign`: Checks the `Sign()` method.
    * `NormalizedBoundaries`: Tests the `NormalizedBoundaries()` method, likely related to precision.
    * `NextDouble`: Tests the `NextDouble()` method.

4. **Determine Overall Functionality:** Based on the individual test case analysis, the overall functionality is clear: This file contains unit tests for the `v8::base::Double` class. It tests various aspects of representing and manipulating double-precision floating-point numbers, including:
    * Construction from `uint64_t` bit patterns.
    * Conversion to and from the `DiyFp` representation.
    * Identification of special values (infinity, NaN).
    * Identification of denormal numbers.
    * Determining the sign.
    * Calculating the next representable double.
    * Finding the boundaries of a normalized double.

5. **Check for Torque Relevance:** The prompt specifically asks if the file ends in `.tq`. It doesn't, so it's **not** a Torque file.

6. **Check for JavaScript Relevance:**  The `Double` class is fundamental to how JavaScript represents numbers. Therefore, this testing code is **directly related** to JavaScript's functionality.

7. **Provide JavaScript Examples:**  To illustrate the connection to JavaScript, think about scenarios where the functionality being tested is important.
    * **Uint64 Conversions:**  While not directly exposed, understanding the underlying bit representation is important for low-level operations or when interacting with native code. Showing how JavaScript handles large integers provides context.
    * **DiyFp:** This is an internal representation, so a direct JavaScript example is less relevant. Mentioning its use in efficient float manipulation is enough.
    * **IsDenormal/IsSpecial/IsInfinite:** These map directly to JavaScript concepts like `Number.MIN_VALUE`, `Infinity`, `-Infinity`, and `NaN`. These are good examples.
    * **Sign:**  Basic arithmetic operations in JavaScript demonstrate the concept of sign.
    * **NormalizedBoundaries/NextDouble:** These are more subtle. Illustrate the limitations of floating-point precision and how small increments work.

8. **Code Logic Inference and Examples:**  For most tests, the logic is straightforward (comparison of expected and actual values).
    * **Uint64Conversions:** Show how a specific `uint64_t` maps to a double.
    * **AsDiyFp/AsNormalizedDiyFp:**  Illustrate the bit manipulation and exponent calculations.
    * **IsDenormal/IsSpecial/IsInfinite/Sign:**  The input is a double, and the output is a boolean or integer. Provide examples of various inputs and their expected outputs.
    * **NormalizedBoundaries:**  Pick a number and show how the boundaries are calculated.
    * **NextDouble:**  Show how incrementing a double works, including edge cases like 0 and infinity.

9. **Common Programming Errors:**  Think about typical mistakes developers make when working with floating-point numbers in JavaScript (or any language).
    * **Equality Comparisons:**  Floating-point numbers are rarely exactly equal.
    * **Assuming Exact Arithmetic:**  Small errors can accumulate.
    * **Not Handling Special Values:**  Forgetting to check for `NaN` or `Infinity`.
    * **Loss of Precision with Large Integers:** JavaScript's `Number` type can lose precision with very large integers.

10. **Structure and Refine:** Organize the information logically:
    * Start with a summary of the file's purpose.
    * Explain the functionality of each test case.
    * Address the Torque question.
    * Explain the JavaScript relevance and provide examples.
    * Give examples of code logic inference with inputs and outputs.
    * Discuss common programming errors and illustrate them.
    * Ensure the language is clear and concise.

11. **Review and Verify:**  Read through the entire response to make sure it's accurate, comprehensive, and addresses all parts of the original request. Check for any inconsistencies or areas that could be clearer. For instance, make sure the JavaScript examples are correct and relevant to the C++ code being tested.
`v8/test/unittests/base/double-unittest.cc` 是 V8 JavaScript 引擎中一个 C++ 单元测试文件，专门用于测试 `src/base/numbers/double.h` 中 `Double` 类的功能。这个类很可能提供了对双精度浮点数的一些底层操作和表示。

**功能列表:**

该文件主要测试了 `v8::base::Double` 类的以下功能：

1. **`Uint64Conversions`**: 测试将 `uint64_t` (无符号 64 位整数) 转换为 `Double` 类型的能力，并验证转换后的双精度浮点数值是否符合预期。这可能涉及到理解双精度浮点数的内存布局。

2. **`AsDiyFp`**: 测试将 `Double` 对象转换为 `DiyFp` (Do-It-Yourself Floating Point) 结构的能力。`DiyFp` 是 V8 内部用于更精确地表示浮点数的一种结构，它包含尾数 (mantissa) 和指数 (exponent)。测试验证转换后的 `DiyFp` 结构的尾数和指数是否正确。

3. **`AsNormalizedDiyFp`**: 测试将 `Double` 对象转换为 *规范化* 的 `DiyFp` 结构的能力。规范化涉及到调整尾数和指数，使得尾数最高位为 1。测试验证转换后的规范化 `DiyFp` 结构的尾数和指数是否正确。

4. **`IsDenormal`**: 测试 `Double` 对象是否表示一个非规范化数 (denormal number)。非规范化数是指绝对值非常小的浮点数，其指数部分为最小值，尾数部分不为零。

5. **`IsSpecial`**: 测试 `Double` 对象是否表示一个特殊值，例如正无穷 (`Infinity`)、负无穷 (`-Infinity`) 或 NaN (Not a Number)。

6. **`IsInfinite`**: 测试 `Double` 对象是否表示正无穷或负无穷。

7. **`Sign`**: 测试获取 `Double` 对象的符号，返回 1 表示正数，-1 表示负数。

8. **`NormalizedBoundaries`**: 测试获取一个 `Double` 对象的规范化边界值。对于一个给定的双精度浮点数，存在两个相邻的可表示的浮点数，分别比它略大和略小。这个测试验证计算出的边界值是否正确。

9. **`NextDouble`**: 测试获取紧邻给定 `Double` 对象的下一个可表示的双精度浮点数的能力。这在数值计算和精度分析中很有用。

**关于文件后缀 `.tq`:**

`v8/test/unittests/base/double-unittest.cc` 的文件后缀是 `.cc`，这意味着它是一个 C++ 源文件。如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部函数的领域特定语言。

**与 JavaScript 功能的关系:**

`v8::base::Double` 类是 V8 引擎中表示和操作双精度浮点数的底层机制。JavaScript 中的 `Number` 类型在底层就是使用双精度浮点数 (IEEE 754 标准) 来表示的。 因此，`double-unittest.cc` 中测试的功能直接关系到 JavaScript 中数值的表示和运算的正确性。

**JavaScript 示例:**

```javascript
// JavaScript 中的 Number 类型对应 C++ 中的 double

// 测试 Uint64Conversions：虽然 JavaScript 不直接操作 uint64_t，
// 但理解底层的二进制表示有助于理解浮点数的存储。
let largeNumber = 9007199254740991; // 接近 JavaScript 安全整数上限
console.log(largeNumber);

// 测试 IsDenormal 和 IsSpecial
console.log(Number.MIN_VALUE); // 接近于 0 的最小正数，可能对应 denormal
console.log(Number.POSITIVE_INFINITY);
console.log(Number.NEGATIVE_INFINITY);
console.log(NaN);

// 测试 Sign
console.log(Math.sign(5));   // 1
console.log(Math.sign(-5));  // -1
console.log(Math.sign(0));   // 0 或 +0
console.log(Math.sign(-0));  // -0

// 测试 NextDouble（JavaScript 中没有直接对应的 API，但概念是相关的）
// 可以通过不断加上极小的数来逼近下一个可表示的浮点数
let num = 1;
let nextNum = num + Number.EPSILON; // Number.EPSILON 是 1 和大于 1 的最小浮点数之间的差值
console.log(nextNum);
```

**代码逻辑推理和假设输入输出:**

**示例：`TEST_F(DoubleTest, Uint64Conversions)`**

* **假设输入:** `uint64_t ordered = 0x0123'4567'89AB'CDEF;`
* **代码逻辑:** 将这个 64 位整数的二进制表示解释为双精度浮点数的二进制表示 (根据 IEEE 754 标准)，并转换为 `double` 类型。`Double(ordered).value()` 会返回转换后的 `double` 值。
* **预期输出:** `CHECK_EQ(3512700564088504e-318, Double(ordered).value());`  这个十六进制数会被解释为一个非常小的正数。具体的转换涉及到指数和尾数的计算。

**示例：`TEST_F(DoubleTest, IsDenormal)`**

* **假设输入:** `uint64_t min_double64 = 0x0000'0000'0000'0001;`
* **代码逻辑:** 创建一个 `Double` 对象，其二进制表示对应于最小的正非零双精度浮点数（很可能是一个非规范化数）。然后调用 `IsDenormal()` 方法。
* **预期输出:** `CHECK(Double(min_double64).IsDenormal());`  因为这个数非常小，指数部分为最小值，所以它应该是一个非规范化数。

**涉及用户常见的编程错误:**

1. **浮点数比较的精度问题:**  直接使用 `==` 比较两个浮点数是否相等是很危险的，因为浮点数的表示存在精度限制。
   ```javascript
   let a = 0.1 + 0.2;
   console.log(a == 0.3); // 输出 false，因为浮点数运算可能存在微小误差

   // 应该使用一个误差范围进行比较
   const EPSILON = Number.EPSILON;
   console.log(Math.abs(a - 0.3) < EPSILON); // 输出 true
   ```

2. **对特殊值的处理不当:**  没有正确处理 `Infinity` 和 `NaN` 可能导致程序出现意外行为。
   ```javascript
   let result = 1 / 0; // Infinity
   console.log(result);

   let notANumber = Math.sqrt(-1); // NaN
   console.log(notANumber);
   console.log(notANumber == NaN);   // 输出 false，NaN 不等于自身
   console.log(isNaN(notANumber));  // 应该使用 isNaN() 判断是否为 NaN
   ```

3. **误解浮点数的表示范围和精度:**  不了解双精度浮点数的最大值、最小值以及精度限制，可能导致溢出或精度丢失。
   ```javascript
   let maxVal = Number.MAX_VALUE;
   console.log(maxVal);
   console.log(maxVal * 2); // 输出 Infinity

   let verySmall = Number.MIN_VALUE;
   console.log(verySmall);
   ```

4. **在需要精确计算的场景中使用浮点数:**  例如，在金融计算中，由于浮点数的精度问题，直接使用浮点数进行计算可能会导致误差。应该使用专门的库或者整数来处理这类问题。

总而言之，`v8/test/unittests/base/double-unittest.cc` 是 V8 引擎中一个重要的测试文件，它确保了 `Double` 类（双精度浮点数的底层表示）的各种操作的正确性，这对于 JavaScript 中数值运算的可靠性至关重要。 理解这个文件中的测试用例可以帮助我们更深入地理解浮点数的特性和潜在的陷阱。

### 提示词
```
这是目录为v8/test/unittests/base/double-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/double-unittest.cc以.tq结尾，那它是个v8 torque源代码，
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

#include "src/base/numbers/double.h"

#include <stdlib.h>

#include "src/base/numbers/diy-fp.h"
#include "src/common/globals.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using DoubleTest = ::testing::Test;

namespace base {

TEST_F(DoubleTest, Uint64Conversions) {
  // Start by checking the byte-order.
  uint64_t ordered = 0x0123'4567'89AB'CDEF;
  CHECK_EQ(3512700564088504e-318, Double(ordered).value());

  uint64_t min_double64 = 0x0000'0000'0000'0001;
  CHECK_EQ(5e-324, Double(min_double64).value());

  uint64_t max_double64 = 0x7FEF'FFFF'FFFF'FFFF;
  CHECK_EQ(1.7976931348623157e308, Double(max_double64).value());
}

TEST_F(DoubleTest, AsDiyFp) {
  uint64_t ordered = 0x0123'4567'89AB'CDEF;
  DiyFp diy_fp = Double(ordered).AsDiyFp();
  CHECK_EQ(0x12 - 0x3FF - 52, diy_fp.e());
  // The 52 mantissa bits, plus the implicit 1 in bit 52 as a UINT64.
  CHECK(0x0013'4567'89AB'CDEF == diy_fp.f());  // NOLINT

  uint64_t min_double64 = 0x0000'0000'0000'0001;
  diy_fp = Double(min_double64).AsDiyFp();
  CHECK_EQ(-0x3FF - 52 + 1, diy_fp.e());
  // This is a denormal; so no hidden bit.
  CHECK_EQ(1, diy_fp.f());

  uint64_t max_double64 = 0x7FEF'FFFF'FFFF'FFFF;
  diy_fp = Double(max_double64).AsDiyFp();
  CHECK_EQ(0x7FE - 0x3FF - 52, diy_fp.e());
  CHECK(0x001F'FFFF'FFFF'FFFF == diy_fp.f());  // NOLINT
}

TEST_F(DoubleTest, AsNormalizedDiyFp) {
  uint64_t ordered = 0x0123'4567'89AB'CDEF;
  DiyFp diy_fp = Double(ordered).AsNormalizedDiyFp();
  CHECK_EQ(0x12 - 0x3FF - 52 - 11, diy_fp.e());
  CHECK((uint64_t{0x0013'4567'89AB'CDEF} << 11) == diy_fp.f());  // NOLINT

  uint64_t min_double64 = 0x0000'0000'0000'0001;
  diy_fp = Double(min_double64).AsNormalizedDiyFp();
  CHECK_EQ(-0x3FF - 52 + 1 - 63, diy_fp.e());
  // This is a denormal; so no hidden bit.
  CHECK(0x8000'0000'0000'0000 == diy_fp.f());  // NOLINT

  uint64_t max_double64 = 0x7FEF'FFFF'FFFF'FFFF;
  diy_fp = Double(max_double64).AsNormalizedDiyFp();
  CHECK_EQ(0x7FE - 0x3FF - 52 - 11, diy_fp.e());
  CHECK((uint64_t{0x001F'FFFF'FFFF'FFFF} << 11) == diy_fp.f());
}

TEST_F(DoubleTest, IsDenormal) {
  uint64_t min_double64 = 0x0000'0000'0000'0001;
  CHECK(Double(min_double64).IsDenormal());
  uint64_t bits = 0x000F'FFFF'FFFF'FFFF;
  CHECK(Double(bits).IsDenormal());
  bits = 0x0010'0000'0000'0000;
  CHECK(!Double(bits).IsDenormal());
}

TEST_F(DoubleTest, IsSpecial) {
  CHECK(Double(V8_INFINITY).IsSpecial());
  CHECK(Double(-V8_INFINITY).IsSpecial());
  CHECK(Double(std::numeric_limits<double>::quiet_NaN()).IsSpecial());
  uint64_t bits = 0xFFF1'2345'0000'0000;
  CHECK(Double(bits).IsSpecial());
  // Denormals are not special:
  CHECK(!Double(5e-324).IsSpecial());
  CHECK(!Double(-5e-324).IsSpecial());
  // And some random numbers:
  CHECK(!Double(0.0).IsSpecial());
  CHECK(!Double(-0.0).IsSpecial());
  CHECK(!Double(1.0).IsSpecial());
  CHECK(!Double(-1.0).IsSpecial());
  CHECK(!Double(1000000.0).IsSpecial());
  CHECK(!Double(-1000000.0).IsSpecial());
  CHECK(!Double(1e23).IsSpecial());
  CHECK(!Double(-1e23).IsSpecial());
  CHECK(!Double(1.7976931348623157e308).IsSpecial());
  CHECK(!Double(-1.7976931348623157e308).IsSpecial());
}

TEST_F(DoubleTest, IsInfinite) {
  CHECK(Double(V8_INFINITY).IsInfinite());
  CHECK(Double(-V8_INFINITY).IsInfinite());
  CHECK(!Double(std::numeric_limits<double>::quiet_NaN()).IsInfinite());
  CHECK(!Double(0.0).IsInfinite());
  CHECK(!Double(-0.0).IsInfinite());
  CHECK(!Double(1.0).IsInfinite());
  CHECK(!Double(-1.0).IsInfinite());
  uint64_t min_double64 = 0x0000'0000'0000'0001;
  CHECK(!Double(min_double64).IsInfinite());
}

TEST_F(DoubleTest, Sign) {
  CHECK_EQ(1, Double(1.0).Sign());
  CHECK_EQ(1, Double(V8_INFINITY).Sign());
  CHECK_EQ(-1, Double(-V8_INFINITY).Sign());
  CHECK_EQ(1, Double(0.0).Sign());
  CHECK_EQ(-1, Double(-0.0).Sign());
  uint64_t min_double64 = 0x0000'0000'0000'0001;
  CHECK_EQ(1, Double(min_double64).Sign());
}

TEST_F(DoubleTest, NormalizedBoundaries) {
  DiyFp boundary_plus;
  DiyFp boundary_minus;
  DiyFp diy_fp = Double(1.5).AsNormalizedDiyFp();
  Double(1.5).NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  // 1.5 does not have a significand of the form 2^p (for some p).
  // Therefore its boundaries are at the same distance.
  CHECK(diy_fp.f() - boundary_minus.f() == boundary_plus.f() - diy_fp.f());
  CHECK((1 << 10) == diy_fp.f() - boundary_minus.f());

  diy_fp = Double(1.0).AsNormalizedDiyFp();
  Double(1.0).NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  // 1.0 does have a significand of the form 2^p (for some p).
  // Therefore its lower boundary is twice as close as the upper boundary.
  CHECK_GT(boundary_plus.f() - diy_fp.f(), diy_fp.f() - boundary_minus.f());
  CHECK((1 << 9) == diy_fp.f() - boundary_minus.f());
  CHECK((1 << 10) == boundary_plus.f() - diy_fp.f());

  uint64_t min_double64 = 0x0000'0000'0000'0001;
  diy_fp = Double(min_double64).AsNormalizedDiyFp();
  Double(min_double64).NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  // min-value does not have a significand of the form 2^p (for some p).
  // Therefore its boundaries are at the same distance.
  CHECK(diy_fp.f() - boundary_minus.f() == boundary_plus.f() - diy_fp.f());
  // Denormals have their boundaries much closer.
  CHECK((static_cast<uint64_t>(1) << 62) == diy_fp.f() - boundary_minus.f());

  uint64_t smallest_normal64 = 0x0010'0000'0000'0000;
  diy_fp = Double(smallest_normal64).AsNormalizedDiyFp();
  Double(smallest_normal64)
      .NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  // Even though the significand is of the form 2^p (for some p), its boundaries
  // are at the same distance. (This is the only exception).
  CHECK(diy_fp.f() - boundary_minus.f() == boundary_plus.f() - diy_fp.f());
  CHECK((1 << 10) == diy_fp.f() - boundary_minus.f());

  uint64_t largest_denormal64 = 0x000F'FFFF'FFFF'FFFF;
  diy_fp = Double(largest_denormal64).AsNormalizedDiyFp();
  Double(largest_denormal64)
      .NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  CHECK(diy_fp.f() - boundary_minus.f() == boundary_plus.f() - diy_fp.f());
  CHECK((1 << 11) == diy_fp.f() - boundary_minus.f());

  uint64_t max_double64 = 0x7FEF'FFFF'FFFF'FFFF;
  diy_fp = Double(max_double64).AsNormalizedDiyFp();
  Double(max_double64).NormalizedBoundaries(&boundary_minus, &boundary_plus);
  CHECK_EQ(diy_fp.e(), boundary_minus.e());
  CHECK_EQ(diy_fp.e(), boundary_plus.e());
  // max-value does not have a significand of the form 2^p (for some p).
  // Therefore its boundaries are at the same distance.
  CHECK(diy_fp.f() - boundary_minus.f() == boundary_plus.f() - diy_fp.f());
  CHECK((1 << 10) == diy_fp.f() - boundary_minus.f());
}

TEST_F(DoubleTest, NextDouble) {
  CHECK_EQ(4e-324, Double(0.0).NextDouble());
  CHECK_EQ(0.0, Double(-0.0).NextDouble());
  CHECK_EQ(-0.0, Double(-4e-324).NextDouble());
  Double d0(-4e-324);
  Double d1(d0.NextDouble());
  Double d2(d1.NextDouble());
  CHECK_EQ(-0.0, d1.value());
  CHECK_EQ(0.0, d2.value());
  CHECK_EQ(4e-324, d2.NextDouble());
  CHECK_EQ(-1.7976931348623157e308, Double(-V8_INFINITY).NextDouble());
  CHECK_EQ(V8_INFINITY, Double(uint64_t{0x7FEF'FFFF'FFFF'FFFF}).NextDouble());
}

}  // namespace base
}  // namespace v8
```