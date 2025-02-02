Response:
Let's break down the thought process for analyzing the given C++ code and generating the informative response.

**1. Understanding the Goal:**

The core request is to analyze a C++ unit test file for IEEE 754 floating-point functions and explain its purpose, relate it to JavaScript if applicable, provide examples, and point out potential programming errors.

**2. Initial Examination and Key Observations:**

* **Filename:** `ieee754-unittest.cc` clearly indicates this is a unit test file related to IEEE 754 standards.
* **Includes:**  `src/base/ieee754.h`, `<limits>`, `src/base/overflowing-math.h`, and `testing/gmock-support.h` provide crucial context. It uses Google Mock (`testing::BitEq`, `testing::IsNaN`) for assertions. The inclusion of `ieee754.h` is the most important – it suggests the file tests functions declared in that header.
* **Namespaces:** The code resides within `v8::base::ieee754`, indicating it's part of the V8 JavaScript engine's base library, specifically the part dealing with IEEE 754.
* **`TEST()` Macros:**  The presence of numerous `TEST(Ieee754, FunctionName)` macros immediately reveals the structure – it's a series of unit tests for different mathematical functions.
* **Constants:**  The definition of constants like `kE`, `kPI`, `kInfinity`, `kQNaN`, `kSNaN` hints at the domain being tested – floating-point numbers and their special values.
* **`EXPECT_THAT()` and `EXPECT_EQ()`:** These are Google Mock assertion macros. `EXPECT_THAT` is often used with matchers like `IsNaN()` or `BitEq()`, while `EXPECT_EQ` checks for direct equality. `EXPECT_DOUBLE_EQ` is for comparing floating-point numbers with tolerance.

**3. Identifying the Tested Functions:**

By looking at the names of the `TEST` cases (e.g., `TEST(Ieee754, Acos)`), we can directly list the functions being tested: `acos`, `acosh`, `asin`, `asinh`, `atan`, `atan2`, `atanh`, `cos` (and potentially `libm_cos`, `fdlibm_cos`), `sin` (and potentially `libm_sin`, `fdlibm_sin`), `cosh`, `exp`, `expm1`, `log`, `log1p`, `log2`, `log10`, `cbrt`, `sinh`, `tan`, `tanh`.

**4. Determining Functionality:**

For each tested function, the test cases provide clues about its behavior. Common patterns emerge:

* **Handling of Special Values:**  Tests consistently check how functions handle infinity (`kInfinity`, `-kInfinity`), NaN (`kQNaN`, `kSNaN`), and zero (`0.0`, `-0.0`).
* **Basic Functionality:** Tests with specific numerical inputs verify the core mathematical operation.
* **Edge Cases:** Tests explore values close to zero, large values, and values that might trigger overflow or underflow.
* **Comparison with Expected Values:**  Test cases often compare the function's output with known mathematical constants or pre-calculated values.

**5. Connecting to JavaScript:**

Since V8 is a JavaScript engine, there's a strong connection to JavaScript's `Math` object. The tested C++ functions directly correspond to methods in `Math` like `Math.acos()`, `Math.acosh()`, etc.

**6. Providing JavaScript Examples:**

For each C++ function, a corresponding JavaScript example can be created to illustrate its usage and behavior in a JavaScript context. This involves using the relevant `Math` object methods. Special attention should be paid to how JavaScript handles special values like `Infinity` and `NaN`.

**7. Code Logic Inference and Examples:**

For trigonometric functions (sin, cos, tan), the tests implicitly demonstrate the periodic nature and specific values at key points (e.g., `cos(0)`, `sin(PI/2)`). For logarithmic and exponential functions, the tests show the inverse relationship. Choose a few representative functions to illustrate this. Provide simple input and expected output based on the mathematical definition.

**8. Identifying Common Programming Errors:**

Floating-point arithmetic is prone to certain errors. The tests themselves hint at common issues:

* **Incorrect NaN Handling:** Not checking for `NaN` results when expected.
* **Floating-Point Comparisons:** Using direct equality (`==`) for floating-point numbers instead of tolerance-based comparisons.
* **Infinite Loops/Recursion with Trigonometric Functions:**  Failing to normalize angles properly can lead to infinite calculations.
* **Overflow/Underflow:**  Not anticipating or handling extremely large or small results.
* **Precision Errors:**  Expecting exact results from floating-point operations.

**9. Addressing the `.tq` Question:**

The prompt specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for implementing built-in functions, this can be explained. However, since the provided file is `.cc`, it's important to state that it's *not* a Torque file.

**10. Structuring the Response:**

Organize the findings logically:

* Start with a concise summary of the file's purpose.
* List the functions being tested.
* Provide the requested information for each function (JavaScript examples, logic examples, common errors).
* Address the `.tq` question.
* Conclude with a summary of the importance of these tests.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the C++ code.
* **Correction:**  Realize the importance of connecting it to JavaScript given the context of V8.
* **Initial thought:** Explain each test case individually.
* **Correction:**  Group tests by the function they are testing for better clarity.
* **Initial thought:**  Provide very complex code logic examples.
* **Correction:**  Keep the logic examples simple and illustrative.

By following this thought process, iteratively refining the analysis, and focusing on the key aspects of the request, a comprehensive and informative response can be generated.
`v8/test/unittests/base/ieee754-unittest.cc` 是一个 V8 源代码文件，它包含了针对 `src/base/ieee754.h` 中定义的 IEEE 754 浮点数相关函数的单元测试。

**主要功能：**

该文件的主要功能是测试 V8 引擎中 IEEE 754 标准浮点数运算的正确性。它通过一系列的单元测试用例，验证了诸如三角函数、指数函数、对数函数等数学函数在处理各种输入（包括正常值、特殊值如 NaN、Infinity、正负零等）时的行为是否符合 IEEE 754 标准和预期。

**具体功能点：**

1. **测试 IEEE 754 数学函数:**  针对 `acos`, `acosh`, `asin`, `asinh`, `atan`, `atan2`, `atanh`, `cos`, `sin`, `cosh`, `exp`, `expm1`, `log`, `log1p`, `log2`, `log10`, `cbrt`, `sinh`, `tan`, `tanh` 等数学函数进行测试。
2. **测试特殊值处理:**  验证这些函数在接收到 `NaN` (Not a Number), `Infinity` (无穷大), `-Infinity` (负无穷大), `+0` (正零), `-0` (负零) 等特殊值作为输入时的行为。
3. **边界条件测试:**  测试函数在接近边界值时的行为，例如非常接近零的值，非常大的值等。
4. **精度验证:**  通过比较计算结果与预期值来验证计算的精度。使用了 `EXPECT_EQ`, `EXPECT_DOUBLE_EQ`, `EXPECT_THAT(..., BitEq(...))` 等宏进行精确或近似的比较。
5. **不同实现的测试 (可选):** 文件中使用了宏 `#if defined(V8_USE_LIBM_TRIG_FUNCTIONS)` 来区分使用 V8 自带的三角函数实现 (`LibmCos`, `LibmSin`) 和系统提供的 `fdlibm` 实现 (`FdlibmCos`, `FdlibmSin`) 的情况进行测试。这表明 V8 可能会有多种实现方式，并且需要对不同的实现进行测试。

**关于 .tq 结尾:**

如果 `v8/test/unittests/base/ieee754-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是 V8 使用的一种领域特定语言，用于实现 JavaScript 的内置函数和运行时功能。然而，根据你提供的文件名，它以 `.cc` 结尾，因此这是一个 **C++ 源代码**文件。

**与 JavaScript 的关系和示例:**

`v8/test/unittests/base/ieee754-unittest.cc` 中测试的许多函数都直接对应于 JavaScript 的 `Math` 对象中的方法。例如：

* `Ieee754::Acos` 测试对应于 `Math.acos()`
* `Ieee754::Sin` 测试对应于 `Math.sin()`
* `Ieee754::Log` 测试对应于 `Math.log()`

**JavaScript 示例：**

```javascript
console.log(Math.acos(1.0));   // 对应 C++ 中的 TEST(Ieee754, Acos) 中 EXPECT_EQ(0.0, acos(1.0));
console.log(Math.sin(0));     // 对应 C++ 中的 TEST(Ieee754, Sin) 中 EXPECT_THAT(sin(0.0), BitEq(0.0));
console.log(Math.log(Math.E)); // 对应 C++ 中的 TEST(Ieee754, Log) 中 EXPECT_EQ(1.0, log(kE));

console.log(Math.log(0));     // 对应 C++ 中的 TEST(Ieee754, Log) 中 EXPECT_EQ(-Infinity, log(0.0));
console.log(Math.sin(NaN));   // 对应 C++ 中的 TEST(Ieee754, Sin) 中 EXPECT_THAT(sin(kQNaN), IsNaN());
```

**代码逻辑推理和假设输入输出:**

以 `TEST(Ieee754, Acos)` 为例：

**假设输入:** `acos(1.0)`

**代码逻辑:**  `acos` 函数计算 1.0 的反余弦值。

**预期输出:** `0.0`

以 `TEST(Ieee754, Asin)` 为例：

**假设输入:** `asin(-0.0)`

**代码逻辑:** `asin` 函数计算 -0.0 的反正弦值。

**预期输出:** `-0.0` (使用 `BitEq` 比较，因为浮点数的正零和负零在位表示上是不同的)

以 `TEST(Ieee754, Exp)` 为例：

**假设输入:** `exp(1.0)`

**代码逻辑:** `exp` 函数计算自然常数 e 的 1.0 次方。

**预期输出:**  接近 `2.718281828459045` (即 `kE` 的值)

**涉及用户常见的编程错误及示例:**

1. **不正确地处理 NaN:** 用户可能没有检查函数的返回值是否为 `NaN`，导致后续使用 `NaN` 值进行计算时出现意外结果。

   ```javascript
   let result = Math.acos(2); // 2 超出了 acos 的定义域 [-1, 1]
   if (isNaN(result)) {
       console.log("输入无效");
   } else {
       console.log(result);
   }
   ```

2. **浮点数比较的精度问题:** 用户可能直接使用 `==` 比较浮点数，而没有考虑浮点数的精度误差。

   ```javascript
   let a = Math.sin(Math.PI); // 理论上应该为 0
   if (a === 0) { // 这样比较可能不成立
       console.log("sin(PI) 等于 0");
   }

   // 更安全的做法是比较差值的绝对值是否小于一个很小的数
   const EPSILON = Number.EPSILON;
   if (Math.abs(a - 0) < EPSILON) {
       console.log("sin(PI) 接近 0");
   }
   ```

3. **假设三角函数的参数单位是度而不是弧度:** JavaScript 的 `Math` 对象的三角函数方法使用弧度作为参数。

   ```javascript
   // 错误地将角度转换为弧度
   let angleInDegrees = 90;
   console.log(Math.sin(angleInDegrees)); // 错误的结果，因为 sin 期望的是弧度

   // 正确的做法
   let angleInRadians = angleInDegrees * Math.PI / 180;
   console.log(Math.sin(angleInRadians)); // 正确的结果
   ```

4. **对数函数的参数为负数或零:**  `Math.log()` 只能接受正数作为参数。

   ```javascript
   console.log(Math.log(-1)); // 输出 NaN
   console.log(Math.log(0));  // 输出 -Infinity

   // 在调用 log 之前应该检查参数
   let input = -1;
   if (input > 0) {
       console.log(Math.log(input));
   } else {
       console.log("对数函数的参数必须是正数");
   }
   ```

总而言之，`v8/test/unittests/base/ieee754-unittest.cc` 是 V8 引擎中至关重要的一个测试文件，它确保了 JavaScript 中与 IEEE 754 浮点数运算相关的核心功能的正确性和可靠性，从而避免了用户在使用 JavaScript 进行数值计算时遇到潜在的精度问题和错误。

### 提示词
```
这是目录为v8/test/unittests/base/ieee754-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/ieee754-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/ieee754.h"

#include <limits>

#include "src/base/overflowing-math.h"
#include "testing/gmock-support.h"

using testing::BitEq;
using testing::IsNaN;

namespace v8 {
namespace base {
namespace ieee754 {

namespace {

double const kE = 2.718281828459045;
double const kPI = 3.141592653589793;
double const kTwo120 = 1.329227995784916e+36;
double const kInfinity = std::numeric_limits<double>::infinity();
double const kQNaN = std::numeric_limits<double>::quiet_NaN();
double const kSNaN = std::numeric_limits<double>::signaling_NaN();

}  // namespace

TEST(Ieee754, Acos) {
  EXPECT_THAT(acos(kInfinity), IsNaN());
  EXPECT_THAT(acos(-kInfinity), IsNaN());
  EXPECT_THAT(acos(kQNaN), IsNaN());
  EXPECT_THAT(acos(kSNaN), IsNaN());

  EXPECT_EQ(0.0, acos(1.0));
}

TEST(Ieee754, Acosh) {
  // Tests for acosh for exceptional values
  EXPECT_EQ(kInfinity, acosh(kInfinity));
  EXPECT_THAT(acosh(-kInfinity), IsNaN());
  EXPECT_THAT(acosh(kQNaN), IsNaN());
  EXPECT_THAT(acosh(kSNaN), IsNaN());
  EXPECT_THAT(acosh(0.9), IsNaN());

  // Test basic acosh functionality
  EXPECT_EQ(0.0, acosh(1.0));
  // acosh(1.5) = log((sqrt(5)+3)/2), case 1 < x < 2
  EXPECT_EQ(0.9624236501192069e0, acosh(1.5));
  // acosh(4) = log(sqrt(15)+4), case 2 < x < 2^28
  EXPECT_EQ(2.0634370688955608e0, acosh(4.0));
  // acosh(2^50), case 2^28 < x
  EXPECT_EQ(35.35050620855721e0, acosh(1125899906842624.0));
  // acosh(most-positive-float), no overflow
  EXPECT_EQ(710.4758600739439e0, acosh(1.7976931348623157e308));
}

TEST(Ieee754, Asin) {
  EXPECT_THAT(asin(kInfinity), IsNaN());
  EXPECT_THAT(asin(-kInfinity), IsNaN());
  EXPECT_THAT(asin(kQNaN), IsNaN());
  EXPECT_THAT(asin(kSNaN), IsNaN());

  EXPECT_THAT(asin(0.0), BitEq(0.0));
  EXPECT_THAT(asin(-0.0), BitEq(-0.0));
}

TEST(Ieee754, Asinh) {
  // Tests for asinh for exceptional values
  EXPECT_EQ(kInfinity, asinh(kInfinity));
  EXPECT_EQ(-kInfinity, asinh(-kInfinity));
  EXPECT_THAT(asin(kQNaN), IsNaN());
  EXPECT_THAT(asin(kSNaN), IsNaN());

  // Test basic asinh functionality
  EXPECT_THAT(asinh(0.0), BitEq(0.0));
  EXPECT_THAT(asinh(-0.0), BitEq(-0.0));
  // asinh(2^-29) = 2^-29, case |x| < 2^-28, where acosh(x) = x
  EXPECT_EQ(1.862645149230957e-9, asinh(1.862645149230957e-9));
  // asinh(-2^-29) = -2^-29, case |x| < 2^-28, where acosh(x) = x
  EXPECT_EQ(-1.862645149230957e-9, asinh(-1.862645149230957e-9));
  // asinh(2^-28), case 2 > |x| >= 2^-28
  EXPECT_EQ(3.725290298461914e-9, asinh(3.725290298461914e-9));
  // asinh(-2^-28), case 2 > |x| >= 2^-28
  EXPECT_EQ(-3.725290298461914e-9, asinh(-3.725290298461914e-9));
  // asinh(1), case 2 > |x| > 2^-28
  EXPECT_EQ(0.881373587019543e0, asinh(1.0));
  // asinh(-1), case 2 > |x| > 2^-28
  EXPECT_EQ(-0.881373587019543e0, asinh(-1.0));
  // asinh(5), case 2^28 > |x| > 2
  EXPECT_EQ(2.3124383412727525e0, asinh(5.0));
  // asinh(-5), case 2^28 > |x| > 2
  EXPECT_EQ(-2.3124383412727525e0, asinh(-5.0));
  // asinh(2^28), case 2^28 > |x|
  EXPECT_EQ(20.101268236238415e0, asinh(268435456.0));
  // asinh(-2^28), case 2^28 > |x|
  EXPECT_EQ(-20.101268236238415e0, asinh(-268435456.0));
  // asinh(<most-positive-float>), no overflow
  EXPECT_EQ(710.4758600739439e0, asinh(1.7976931348623157e308));
  // asinh(-<most-positive-float>), no overflow
  EXPECT_EQ(-710.4758600739439e0, asinh(-1.7976931348623157e308));
}

TEST(Ieee754, Atan) {
  EXPECT_THAT(atan(kQNaN), IsNaN());
  EXPECT_THAT(atan(kSNaN), IsNaN());
  EXPECT_THAT(atan(-0.0), BitEq(-0.0));
  EXPECT_THAT(atan(0.0), BitEq(0.0));
  EXPECT_DOUBLE_EQ(1.5707963267948966, atan(kInfinity));
  EXPECT_DOUBLE_EQ(-1.5707963267948966, atan(-kInfinity));
}

TEST(Ieee754, Atan2) {
  EXPECT_THAT(atan2(kQNaN, kQNaN), IsNaN());
  EXPECT_THAT(atan2(kQNaN, kSNaN), IsNaN());
  EXPECT_THAT(atan2(kSNaN, kQNaN), IsNaN());
  EXPECT_THAT(atan2(kSNaN, kSNaN), IsNaN());
  EXPECT_DOUBLE_EQ(0.7853981633974483, atan2(kInfinity, kInfinity));
  EXPECT_DOUBLE_EQ(2.356194490192345, atan2(kInfinity, -kInfinity));
  EXPECT_DOUBLE_EQ(-0.7853981633974483, atan2(-kInfinity, kInfinity));
  EXPECT_DOUBLE_EQ(-2.356194490192345, atan2(-kInfinity, -kInfinity));
}

TEST(Ieee754, Atanh) {
  EXPECT_THAT(atanh(kQNaN), IsNaN());
  EXPECT_THAT(atanh(kSNaN), IsNaN());
  EXPECT_THAT(atanh(kInfinity), IsNaN());
  EXPECT_EQ(kInfinity, atanh(1));
  EXPECT_EQ(-kInfinity, atanh(-1));
  EXPECT_DOUBLE_EQ(0.54930614433405478, atanh(0.5));
}

#if defined(V8_USE_LIBM_TRIG_FUNCTIONS)
TEST(Ieee754, LibmCos) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(libm_cos(kQNaN), IsNaN());
  EXPECT_THAT(libm_cos(kSNaN), IsNaN());
  EXPECT_THAT(libm_cos(kInfinity), IsNaN());
  EXPECT_THAT(libm_cos(-kInfinity), IsNaN());

  // Tests for cos for |x| < pi/4
  EXPECT_EQ(1.0, 1 / libm_cos(-0.0));
  EXPECT_EQ(1.0, 1 / libm_cos(0.0));
  // cos(x) = 1 for |x| < 2^-27
  EXPECT_EQ(1, libm_cos(2.3283064365386963e-10));
  EXPECT_EQ(1, libm_cos(-2.3283064365386963e-10));
  // Test KERNELCOS for |x| < 0.3.
  // cos(pi/20) = sqrt(sqrt(2)*sqrt(sqrt(5)+5)+4)/2^(3/2)
  EXPECT_EQ(0.9876883405951378, libm_cos(0.15707963267948966));
  // Test KERNELCOS for x ~= 0.78125
  EXPECT_EQ(0.7100335477927638, libm_cos(0.7812504768371582));
  EXPECT_EQ(0.7100338835660797, libm_cos(0.78125));
  // Test KERNELCOS for |x| > 0.3.
  // cos(pi/8) = sqrt(sqrt(2)+1)/2^(3/4)
  EXPECT_EQ(0.9238795325112867, libm_cos(0.39269908169872414));
  // Test KERNELTAN for |x| < 0.67434.
  EXPECT_EQ(0.9238795325112867, libm_cos(-0.39269908169872414));

  // Tests for cos.
  EXPECT_EQ(1, libm_cos(3.725290298461914e-9));
  // Cover different code paths in KERNELCOS.
  EXPECT_EQ(0.9689124217106447, libm_cos(0.25));
  EXPECT_EQ(0.8775825618903728, libm_cos(0.5));
  EXPECT_EQ(0.7073882691671998, libm_cos(0.785));
  // Test that cos(Math.PI/2) != 0 since Math.PI is not exact.
  EXPECT_EQ(6.123233995736766e-17, libm_cos(1.5707963267948966));
  // Test cos for various phases.
  EXPECT_EQ(0.7071067811865474, libm_cos(7.0 / 4 * kPI));
  EXPECT_EQ(0.7071067811865477, libm_cos(9.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865467, libm_cos(11.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865471, libm_cos(13.0 / 4 * kPI));
  EXPECT_EQ(0.9367521275331447, libm_cos(1000000.0));
  EXPECT_EQ(-3.435757038074824e-12, libm_cos(1048575.0 / 2 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(-0.9258790228548379e0, libm_cos(kTwo120));
  EXPECT_EQ(-0.9258790228548379e0, libm_cos(-kTwo120));
}

TEST(Ieee754, LibmSin) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(libm_sin(kQNaN), IsNaN());
  EXPECT_THAT(libm_sin(kSNaN), IsNaN());
  EXPECT_THAT(libm_sin(kInfinity), IsNaN());
  EXPECT_THAT(libm_sin(-kInfinity), IsNaN());

  // Tests for sin for |x| < pi/4
  EXPECT_EQ(-kInfinity, Divide(1.0, libm_sin(-0.0)));
  EXPECT_EQ(kInfinity, Divide(1.0, libm_sin(0.0)));
  // sin(x) = x for x < 2^-27
  EXPECT_EQ(2.3283064365386963e-10, libm_sin(2.3283064365386963e-10));
  EXPECT_EQ(-2.3283064365386963e-10, libm_sin(-2.3283064365386963e-10));
  // sin(pi/8) = sqrt(sqrt(2)-1)/2^(3/4)
  EXPECT_EQ(0.3826834323650898, libm_sin(0.39269908169872414));
  EXPECT_EQ(-0.3826834323650898, libm_sin(-0.39269908169872414));

  // Tests for sin.
  EXPECT_EQ(0.479425538604203, libm_sin(0.5));
  EXPECT_EQ(-0.479425538604203, libm_sin(-0.5));
  EXPECT_EQ(1, libm_sin(kPI / 2.0));
  EXPECT_EQ(-1, libm_sin(-kPI / 2.0));
  // Test that sin(Math.PI) != 0 since Math.PI is not exact.
  EXPECT_EQ(1.2246467991473532e-16, libm_sin(kPI));
  EXPECT_EQ(-7.047032979958965e-14, libm_sin(2200.0 * kPI));
  // Test sin for various phases.
  EXPECT_EQ(-0.7071067811865477, libm_sin(7.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865474, libm_sin(9.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865483, libm_sin(11.0 / 4.0 * kPI));
  EXPECT_EQ(-0.7071067811865479, libm_sin(13.0 / 4.0 * kPI));
  EXPECT_EQ(-3.2103381051568376e-11, libm_sin(1048576.0 / 4 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(0.377820109360752e0, libm_sin(kTwo120));
  EXPECT_EQ(-0.377820109360752e0, libm_sin(-kTwo120));
}

TEST(Ieee754, FdlibmCos) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(fdlibm_cos(kQNaN), IsNaN());
  EXPECT_THAT(fdlibm_cos(kSNaN), IsNaN());
  EXPECT_THAT(fdlibm_cos(kInfinity), IsNaN());
  EXPECT_THAT(fdlibm_cos(-kInfinity), IsNaN());

  // Tests for cos for |x| < pi/4
  EXPECT_EQ(1.0, 1 / fdlibm_cos(-0.0));
  EXPECT_EQ(1.0, 1 / fdlibm_cos(0.0));
  // cos(x) = 1 for |x| < 2^-27
  EXPECT_EQ(1, fdlibm_cos(2.3283064365386963e-10));
  EXPECT_EQ(1, fdlibm_cos(-2.3283064365386963e-10));
  // Test KERNELCOS for |x| < 0.3.
  // cos(pi/20) = sqrt(sqrt(2)*sqrt(sqrt(5)+5)+4)/2^(3/2)
  EXPECT_EQ(0.9876883405951378, fdlibm_cos(0.15707963267948966));
  // Test KERNELCOS for x ~= 0.78125
  EXPECT_EQ(0.7100335477927638, fdlibm_cos(0.7812504768371582));
  EXPECT_EQ(0.7100338835660797, fdlibm_cos(0.78125));
  // Test KERNELCOS for |x| > 0.3.
  // cos(pi/8) = sqrt(sqrt(2)+1)/2^(3/4)
  EXPECT_EQ(0.9238795325112867, fdlibm_cos(0.39269908169872414));
  // Test KERNELTAN for |x| < 0.67434.
  EXPECT_EQ(0.9238795325112867, fdlibm_cos(-0.39269908169872414));

  // Tests for cos.
  EXPECT_EQ(1, fdlibm_cos(3.725290298461914e-9));
  // Cover different code paths in KERNELCOS.
  EXPECT_EQ(0.9689124217106447, fdlibm_cos(0.25));
  EXPECT_EQ(0.8775825618903728, fdlibm_cos(0.5));
  EXPECT_EQ(0.7073882691671998, fdlibm_cos(0.785));
  // Test that cos(Math.PI/2) != 0 since Math.PI is not exact.
  EXPECT_EQ(6.123233995736766e-17, fdlibm_cos(1.5707963267948966));
  // Test cos for various phases.
  EXPECT_EQ(0.7071067811865474, fdlibm_cos(7.0 / 4 * kPI));
  EXPECT_EQ(0.7071067811865477, fdlibm_cos(9.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865467, fdlibm_cos(11.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865471, fdlibm_cos(13.0 / 4 * kPI));
  EXPECT_EQ(0.9367521275331447, fdlibm_cos(1000000.0));
  EXPECT_EQ(-3.435757038074824e-12, fdlibm_cos(1048575.0 / 2 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(-0.9258790228548379e0, fdlibm_cos(kTwo120));
  EXPECT_EQ(-0.9258790228548379e0, fdlibm_cos(-kTwo120));
}

TEST(Ieee754, FdlibmSin) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(fdlibm_sin(kQNaN), IsNaN());
  EXPECT_THAT(fdlibm_sin(kSNaN), IsNaN());
  EXPECT_THAT(fdlibm_sin(kInfinity), IsNaN());
  EXPECT_THAT(fdlibm_sin(-kInfinity), IsNaN());

  // Tests for sin for |x| < pi/4
  EXPECT_EQ(-kInfinity, Divide(1.0, fdlibm_sin(-0.0)));
  EXPECT_EQ(kInfinity, Divide(1.0, fdlibm_sin(0.0)));
  // sin(x) = x for x < 2^-27
  EXPECT_EQ(2.3283064365386963e-10, fdlibm_sin(2.3283064365386963e-10));
  EXPECT_EQ(-2.3283064365386963e-10, fdlibm_sin(-2.3283064365386963e-10));
  // sin(pi/8) = sqrt(sqrt(2)-1)/2^(3/4)
  EXPECT_EQ(0.3826834323650898, fdlibm_sin(0.39269908169872414));
  EXPECT_EQ(-0.3826834323650898, fdlibm_sin(-0.39269908169872414));

  // Tests for sin.
  EXPECT_EQ(0.479425538604203, fdlibm_sin(0.5));
  EXPECT_EQ(-0.479425538604203, fdlibm_sin(-0.5));
  EXPECT_EQ(1, fdlibm_sin(kPI / 2.0));
  EXPECT_EQ(-1, fdlibm_sin(-kPI / 2.0));
  // Test that sin(Math.PI) != 0 since Math.PI is not exact.
  EXPECT_EQ(1.2246467991473532e-16, fdlibm_sin(kPI));
  EXPECT_EQ(-7.047032979958965e-14, fdlibm_sin(2200.0 * kPI));
  // Test sin for various phases.
  EXPECT_EQ(-0.7071067811865477, fdlibm_sin(7.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865474, fdlibm_sin(9.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865483, fdlibm_sin(11.0 / 4.0 * kPI));
  EXPECT_EQ(-0.7071067811865479, fdlibm_sin(13.0 / 4.0 * kPI));
  EXPECT_EQ(-3.2103381051568376e-11, fdlibm_sin(1048576.0 / 4 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(0.377820109360752e0, fdlibm_sin(kTwo120));
  EXPECT_EQ(-0.377820109360752e0, fdlibm_sin(-kTwo120));
}

#else

TEST(Ieee754, Cos) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(cos(kQNaN), IsNaN());
  EXPECT_THAT(cos(kSNaN), IsNaN());
  EXPECT_THAT(cos(kInfinity), IsNaN());
  EXPECT_THAT(cos(-kInfinity), IsNaN());

  // Tests for cos for |x| < pi/4
  EXPECT_EQ(1.0, 1 / cos(-0.0));
  EXPECT_EQ(1.0, 1 / cos(0.0));
  // cos(x) = 1 for |x| < 2^-27
  EXPECT_EQ(1, cos(2.3283064365386963e-10));
  EXPECT_EQ(1, cos(-2.3283064365386963e-10));
  // Test KERNELCOS for |x| < 0.3.
  // cos(pi/20) = sqrt(sqrt(2)*sqrt(sqrt(5)+5)+4)/2^(3/2)
  EXPECT_EQ(0.9876883405951378, cos(0.15707963267948966));
  // Test KERNELCOS for x ~= 0.78125
  EXPECT_EQ(0.7100335477927638, cos(0.7812504768371582));
  EXPECT_EQ(0.7100338835660797, cos(0.78125));
  // Test KERNELCOS for |x| > 0.3.
  // cos(pi/8) = sqrt(sqrt(2)+1)/2^(3/4)
  EXPECT_EQ(0.9238795325112867, cos(0.39269908169872414));
  // Test KERNELTAN for |x| < 0.67434.
  EXPECT_EQ(0.9238795325112867, cos(-0.39269908169872414));

  // Tests for cos.
  EXPECT_EQ(1, cos(3.725290298461914e-9));
  // Cover different code paths in KERNELCOS.
  EXPECT_EQ(0.9689124217106447, cos(0.25));
  EXPECT_EQ(0.8775825618903728, cos(0.5));
  EXPECT_EQ(0.7073882691671998, cos(0.785));
  // Test that cos(Math.PI/2) != 0 since Math.PI is not exact.
  EXPECT_EQ(6.123233995736766e-17, cos(1.5707963267948966));
  // Test cos for various phases.
  EXPECT_EQ(0.7071067811865474, cos(7.0 / 4 * kPI));
  EXPECT_EQ(0.7071067811865477, cos(9.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865467, cos(11.0 / 4 * kPI));
  EXPECT_EQ(-0.7071067811865471, cos(13.0 / 4 * kPI));
  EXPECT_EQ(0.9367521275331447, cos(1000000.0));
  EXPECT_EQ(-3.435757038074824e-12, cos(1048575.0 / 2 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(-0.9258790228548379e0, cos(kTwo120));
  EXPECT_EQ(-0.9258790228548379e0, cos(-kTwo120));
}

TEST(Ieee754, Sin) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(sin(kQNaN), IsNaN());
  EXPECT_THAT(sin(kSNaN), IsNaN());
  EXPECT_THAT(sin(kInfinity), IsNaN());
  EXPECT_THAT(sin(-kInfinity), IsNaN());

  // Tests for sin for |x| < pi/4
  EXPECT_EQ(-kInfinity, Divide(1.0, sin(-0.0)));
  EXPECT_EQ(kInfinity, Divide(1.0, sin(0.0)));
  // sin(x) = x for x < 2^-27
  EXPECT_EQ(2.3283064365386963e-10, sin(2.3283064365386963e-10));
  EXPECT_EQ(-2.3283064365386963e-10, sin(-2.3283064365386963e-10));
  // sin(pi/8) = sqrt(sqrt(2)-1)/2^(3/4)
  EXPECT_EQ(0.3826834323650898, sin(0.39269908169872414));
  EXPECT_EQ(-0.3826834323650898, sin(-0.39269908169872414));

  // Tests for sin.
  EXPECT_EQ(0.479425538604203, sin(0.5));
  EXPECT_EQ(-0.479425538604203, sin(-0.5));
  EXPECT_EQ(1, sin(kPI / 2.0));
  EXPECT_EQ(-1, sin(-kPI / 2.0));
  // Test that sin(Math.PI) != 0 since Math.PI is not exact.
  EXPECT_EQ(1.2246467991473532e-16, sin(kPI));
  EXPECT_EQ(-7.047032979958965e-14, sin(2200.0 * kPI));
  // Test sin for various phases.
  EXPECT_EQ(-0.7071067811865477, sin(7.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865474, sin(9.0 / 4.0 * kPI));
  EXPECT_EQ(0.7071067811865483, sin(11.0 / 4.0 * kPI));
  EXPECT_EQ(-0.7071067811865479, sin(13.0 / 4.0 * kPI));
  EXPECT_EQ(-3.2103381051568376e-11, sin(1048576.0 / 4 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(0.377820109360752e0, sin(kTwo120));
  EXPECT_EQ(-0.377820109360752e0, sin(-kTwo120));
}

#endif

TEST(Ieee754, Cosh) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(cosh(kQNaN), IsNaN());
  EXPECT_THAT(cosh(kSNaN), IsNaN());
  EXPECT_THAT(cosh(kInfinity), kInfinity);
  EXPECT_THAT(cosh(-kInfinity), kInfinity);
  EXPECT_EQ(1, cosh(0.0));
  EXPECT_EQ(1, cosh(-0.0));
}

TEST(Ieee754, Exp) {
  EXPECT_THAT(exp(kQNaN), IsNaN());
  EXPECT_THAT(exp(kSNaN), IsNaN());
  EXPECT_EQ(0.0, exp(-kInfinity));
  EXPECT_EQ(0.0, exp(-1000));
  EXPECT_EQ(0.0, exp(-745.1332191019412));
  EXPECT_EQ(2.2250738585072626e-308, exp(-708.39641853226408));
  EXPECT_EQ(3.307553003638408e-308, exp(-708.0));
  EXPECT_EQ(4.9406564584124654e-324, exp(-7.45133219101941108420e+02));
  EXPECT_EQ(0.36787944117144233, exp(-1.0));
  EXPECT_EQ(1.0, exp(-0.0));
  EXPECT_EQ(1.0, exp(0.0));
  EXPECT_EQ(1.0, exp(2.2250738585072014e-308));

  // Test that exp(x) is monotonic near 1.
  EXPECT_GE(exp(1.0), exp(0.9999999999999999));
  EXPECT_LE(exp(1.0), exp(1.0000000000000002));

  // Test that we produce the correctly rounded result for 1.
  EXPECT_EQ(kE, exp(1.0));

  EXPECT_EQ(7.38905609893065e0, exp(2.0));
  EXPECT_EQ(1.7976931348622732e308, exp(7.09782712893383973096e+02));
  EXPECT_EQ(2.6881171418161356e+43, exp(100.0));
  EXPECT_EQ(8.218407461554972e+307, exp(709.0));
  EXPECT_EQ(1.7968190737295725e308, exp(709.7822265625e0));
  EXPECT_EQ(kInfinity, exp(709.7827128933841e0));
  EXPECT_EQ(kInfinity, exp(710.0));
  EXPECT_EQ(kInfinity, exp(1000.0));
  EXPECT_EQ(kInfinity, exp(kInfinity));
}

TEST(Ieee754, Expm1) {
  EXPECT_THAT(expm1(kQNaN), IsNaN());
  EXPECT_THAT(expm1(kSNaN), IsNaN());
  EXPECT_EQ(-1.0, expm1(-kInfinity));
  EXPECT_EQ(kInfinity, expm1(kInfinity));
  EXPECT_EQ(0.0, expm1(-0.0));
  EXPECT_EQ(0.0, expm1(0.0));
  EXPECT_EQ(1.718281828459045, expm1(1.0));
  EXPECT_EQ(2.6881171418161356e+43, expm1(100.0));
  EXPECT_EQ(8.218407461554972e+307, expm1(709.0));
  EXPECT_EQ(kInfinity, expm1(710.0));
}

TEST(Ieee754, Log) {
  EXPECT_THAT(log(kQNaN), IsNaN());
  EXPECT_THAT(log(kSNaN), IsNaN());
  EXPECT_THAT(log(-kInfinity), IsNaN());
  EXPECT_THAT(log(-1.0), IsNaN());
  EXPECT_EQ(-kInfinity, log(-0.0));
  EXPECT_EQ(-kInfinity, log(0.0));
  EXPECT_EQ(0.0, log(1.0));
  EXPECT_EQ(kInfinity, log(kInfinity));

  // Test that log(E) produces the correctly rounded result.
  EXPECT_EQ(1.0, log(kE));
}

TEST(Ieee754, Log1p) {
  EXPECT_THAT(log1p(kQNaN), IsNaN());
  EXPECT_THAT(log1p(kSNaN), IsNaN());
  EXPECT_THAT(log1p(-kInfinity), IsNaN());
  EXPECT_EQ(-kInfinity, log1p(-1.0));
  EXPECT_EQ(0.0, log1p(0.0));
  EXPECT_EQ(-0.0, log1p(-0.0));
  EXPECT_EQ(kInfinity, log1p(kInfinity));
  EXPECT_EQ(6.9756137364252422e-03, log1p(0.007));
  EXPECT_EQ(709.782712893384, log1p(1.7976931348623157e308));
  EXPECT_EQ(2.7755575615628914e-17, log1p(2.7755575615628914e-17));
  EXPECT_EQ(9.313225741817976e-10, log1p(9.313225746154785e-10));
  EXPECT_EQ(-0.2876820724517809, log1p(-0.25));
  EXPECT_EQ(0.22314355131420976, log1p(0.25));
  EXPECT_EQ(2.3978952727983707, log1p(10));
  EXPECT_EQ(36.841361487904734, log1p(10e15));
  EXPECT_EQ(37.08337388996168, log1p(12738099905822720));
  EXPECT_EQ(37.08336444902049, log1p(12737979646738432));
  EXPECT_EQ(1.3862943611198906, log1p(3));
  EXPECT_EQ(1.3862945995384413, log1p(3 + 9.5367431640625e-7));
  EXPECT_EQ(0.5596157879354227, log1p(0.75));
  EXPECT_EQ(0.8109302162163288, log1p(1.25));
}

TEST(Ieee754, Log2) {
  EXPECT_THAT(log2(kQNaN), IsNaN());
  EXPECT_THAT(log2(kSNaN), IsNaN());
  EXPECT_THAT(log2(-kInfinity), IsNaN());
  EXPECT_THAT(log2(-1.0), IsNaN());
  EXPECT_EQ(-kInfinity, log2(0.0));
  EXPECT_EQ(-kInfinity, log2(-0.0));
  EXPECT_EQ(kInfinity, log2(kInfinity));
}

TEST(Ieee754, Log10) {
  EXPECT_THAT(log10(kQNaN), IsNaN());
  EXPECT_THAT(log10(kSNaN), IsNaN());
  EXPECT_THAT(log10(-kInfinity), IsNaN());
  EXPECT_THAT(log10(-1.0), IsNaN());
  EXPECT_EQ(-kInfinity, log10(0.0));
  EXPECT_EQ(-kInfinity, log10(-0.0));
  EXPECT_EQ(kInfinity, log10(kInfinity));
  EXPECT_EQ(3.0, log10(1000.0));
  EXPECT_EQ(14.0, log10(100000000000000));  // log10(10 ^ 14)
  EXPECT_EQ(3.7389561269540406, log10(5482.2158));
  EXPECT_EQ(14.661551142893833, log10(458723662312872.125782332587));
  EXPECT_EQ(-0.9083828622192334, log10(0.12348583358871));
  EXPECT_EQ(5.0, log10(100000.0));
}

TEST(Ieee754, Cbrt) {
  EXPECT_THAT(cbrt(kQNaN), IsNaN());
  EXPECT_THAT(cbrt(kSNaN), IsNaN());
  EXPECT_EQ(kInfinity, cbrt(kInfinity));
  EXPECT_EQ(-kInfinity, cbrt(-kInfinity));
  EXPECT_EQ(1.4422495703074083, cbrt(3));
  EXPECT_EQ(100, cbrt(100 * 100 * 100));
  EXPECT_EQ(46.415888336127786, cbrt(100000));
}

TEST(Ieee754, Sinh) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(sinh(kQNaN), IsNaN());
  EXPECT_THAT(sinh(kSNaN), IsNaN());
  EXPECT_THAT(sinh(kInfinity), kInfinity);
  EXPECT_THAT(sinh(-kInfinity), -kInfinity);
  EXPECT_EQ(0.0, sinh(0.0));
  EXPECT_EQ(-0.0, sinh(-0.0));
}

TEST(Ieee754, Tan) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(tan(kQNaN), IsNaN());
  EXPECT_THAT(tan(kSNaN), IsNaN());
  EXPECT_THAT(tan(kInfinity), IsNaN());
  EXPECT_THAT(tan(-kInfinity), IsNaN());

  // Tests for tan for |x| < pi/4
  EXPECT_EQ(kInfinity, Divide(1.0, tan(0.0)));
  EXPECT_EQ(-kInfinity, Divide(1.0, tan(-0.0)));
  // tan(x) = x for |x| < 2^-28
  EXPECT_EQ(2.3283064365386963e-10, tan(2.3283064365386963e-10));
  EXPECT_EQ(-2.3283064365386963e-10, tan(-2.3283064365386963e-10));
  // Test KERNELTAN for |x| > 0.67434.
  EXPECT_EQ(0.8211418015898941, tan(11.0 / 16.0));
  EXPECT_EQ(-0.8211418015898941, tan(-11.0 / 16.0));
  EXPECT_EQ(0.41421356237309503, tan(0.39269908169872414));
  // crbug/427468
  EXPECT_EQ(0.7993357819992383, tan(0.6743358));

  // Tests for tan.
  EXPECT_EQ(3.725290298461914e-9, tan(3.725290298461914e-9));
  // Test that tan(PI/2) != Infinity since PI is not exact.
  EXPECT_EQ(1.633123935319537e16, tan(kPI / 2));
  // Cover different code paths in KERNELTAN (tangent and cotangent)
  EXPECT_EQ(0.5463024898437905, tan(0.5));
  EXPECT_EQ(2.0000000000000027, tan(1.107148717794091));
  EXPECT_EQ(-1.0000000000000004, tan(7.0 / 4.0 * kPI));
  EXPECT_EQ(0.9999999999999994, tan(9.0 / 4.0 * kPI));
  EXPECT_EQ(-6.420676210313675e-11, tan(1048576.0 / 2.0 * kPI));
  EXPECT_EQ(2.910566692924059e11, tan(1048575.0 / 2.0 * kPI));

  // Test Hayne-Panek reduction.
  EXPECT_EQ(-0.40806638884180424e0, tan(kTwo120));
  EXPECT_EQ(0.40806638884180424e0, tan(-kTwo120));
}

TEST(Ieee754, Tanh) {
  // Test values mentioned in the ECMAScript spec.
  EXPECT_THAT(tanh(kQNaN), IsNaN());
  EXPECT_THAT(tanh(kSNaN), IsNaN());
  EXPECT_THAT(tanh(kInfinity), 1);
  EXPECT_THAT(tanh(-kInfinity), -1);
  EXPECT_EQ(0.0, tanh(0.0));
  EXPECT_EQ(-0.0, tanh(-0.0));
}

}  // namespace ieee754
}  // namespace base
}  // namespace v8
```