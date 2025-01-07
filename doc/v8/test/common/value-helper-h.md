Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for Obvious Clues:**  I first skimmed the file looking for keywords and patterns. I noticed:
    * `// Copyright 2022 the V8 project authors`: This immediately tells me it's part of the V8 JavaScript engine.
    * `#ifndef V8_COMMON_VALUE_HELPER_H_`:  Standard header guard, indicating it's a header file.
    * `#include ...`:  Various includes like `stdint.h`, `template-utils.h`, `compiler/...`, `execution/...`, `objects/...`. This suggests it's related to V8's internal workings, specifically the compiler and object representation.
    * `namespace v8 { namespace internal { namespace compiler {`:  Confirms it's deeply embedded within V8's internal compiler components.
    * `class ValueHelper`: The central element. The name strongly suggests it provides utilities related to *values*.
    * `static constexpr ... array[] = { ... }`:  Lots of statically defined arrays of various numeric types (float, double, int, uint). The values within the arrays look like edge cases, minimums, maximums, special values like NaN and infinity.
    * `static constexpr base::Vector<const type> type_vector()`:  Helper functions to wrap these arrays in a `base::Vector`.
    * `FOR_INPUTS`, `FOR_INT32_INPUTS`, etc.: Macros that look like they're for iterating over the predefined value arrays.
    * `FloatCompareWrapper`: A custom class for comparing floating-point numbers, handling NaN and sign.
    * `CHECK_FLOAT_EQ`, `CHECK_DOUBLE_EQ`: Macros using `FloatCompareWrapper` for custom floating-point equality checks.

2. **Deduction of Core Functionality:** Based on the initial scan, the central purpose of `ValueHelper` seems to be providing a *collection of representative numeric values* for testing and potentially other internal uses within the V8 compiler. The inclusion of min/max values, NaN, and infinity strengthens this idea. The macros suggest a way to easily iterate over these values in test cases.

3. **Addressing Specific Questions:** Now, I go through the prompt's questions systematically:

    * **Functionality:**  Summarize the core purpose identified in step 2. Mention the different data types covered.
    * **.tq extension:**  Recognize that `.tq` signifies Torque code in V8. Since this is a `.h` file, it's not Torque.
    * **Relationship to JavaScript:** This requires connecting the low-level C++ with high-level JavaScript concepts. Think about how JavaScript deals with numbers. JavaScript uses a double-precision floating-point format for numbers. The `ValueHelper` provides test cases for various numeric edge cases, including those relevant to JavaScript's number representation (though not *directly* JavaScript syntax). The provided JavaScript examples illustrate how these edge cases manifest in JavaScript. Consider integer limits, floating-point precision, and special values.
    * **Code Logic Inference (with input/output):** The macros are the primary "logic" here. Explain how `FOR_INT32_INPUTS(i)` expands. Provide a simple example showing how the loop iterates through the `int32_vector()`.
    * **Common Programming Errors:** Focus on errors related to numeric types:
        * **Integer Overflow/Underflow:**  The `INT_MAX`, `INT_MIN` examples in the arrays are clear indicators. Show a simple JavaScript example.
        * **Floating-Point Precision:**  The presence of very small and very large floats, as well as NaN and infinity, points to potential issues. Demonstrate the classic `0.1 + 0.2 != 0.3` problem in JavaScript.
        * **NaN Comparison:**  Highlight that `NaN !== NaN` in JavaScript and how the `FloatCompareWrapper` addresses this in the C++ tests.

4. **Refinement and Organization:** After drafting the initial answers, review for clarity and accuracy. Organize the information logically according to the prompt's questions. Ensure that the JavaScript examples are concise and relevant. Double-check for any technical inaccuracies. For example, initially I might think it's *directly* used in JavaScript execution, but the includes point more towards compiler testing. Refine the language to reflect this distinction.

5. **Self-Correction Example during Thought Process:**  Initially, I might focus heavily on the specific values in the arrays. However, the prompt asks for *functionality*. The specific values are *examples* supporting the core functionality of providing test inputs. I need to shift the emphasis to the broader purpose. Also, while thinking about JavaScript relationships, I need to avoid getting bogged down in V8 internals the average JavaScript developer wouldn't encounter. Focus on how these underlying numeric concepts manifest in JavaScript behavior.
This C++ header file, `v8/test/common/value-helper.h`, provides a collection of utility functions and data, specifically designed to aid in **testing the V8 JavaScript engine's handling of various numeric and heap values**.

Here's a breakdown of its functionalities:

**1. Predefined Sets of Numeric Values:**

* The header defines several static constant arrays containing a wide range of numeric values for different data types: `float32_array`, `float64_array`, `uint32_array`, `int32_array`, `uint64_array`, `int64_array`, `int16_array`, `uint16_array`, `int8_array`, `uint8_array`, and `ror_array`.
* These arrays include:
    * **Edge cases:** Minimum and maximum values for each data type (e.g., `INT32_MIN`, `INT64_MAX`).
    * **Special floating-point values:** Positive and negative infinity (`std::numeric_limits<float>::infinity()`, `-V8_INFINITY`), Not-a-Number (`std::numeric_limits<float>::quiet_NaN()`).
    * **Values around zero:** Positive and negative zero.
    * **Values with specific bit patterns:** Useful for testing low-level bitwise operations and representations.
    * **Values near representational boundaries:** To test the limits of precision and potential overflow/underflow.
* Corresponding `*_vector()` functions provide a convenient way to access these arrays as `base::Vector` objects.

**2. Macros for Iterating Through Value Sets:**

* The header defines several macros like `FOR_INT32_INPUTS(var)`, `FOR_UINT32_INPUTS(var)`, `FOR_FLOAT64_INPUTS(var)`, etc.
* These macros simplify writing test loops that iterate over the predefined arrays of values. This allows testers to easily feed a variety of inputs to test functions.

**3. `FloatCompareWrapper` for Robust Floating-Point Comparisons:**

* This template struct provides a custom equality comparison operator for floating-point numbers.
* It addresses the issue that `NaN` is not equal to itself (`NaN !== NaN`) in standard floating-point comparisons.
* The `FloatCompareWrapper` considers two `NaN` values to be equal and also takes the sign bit into account for zero.

**4. `CHECK_FLOAT_EQ` and `CHECK_DOUBLE_EQ` Macros:**

* These macros use `FloatCompareWrapper` to perform accurate equality checks for floating-point values in tests, ensuring that `NaN` comparisons work as expected.

**Is `v8/test/common/value-helper.h` a V8 Torque source code?**

No, `v8/test/common/value-helper.h` is **not** a V8 Torque source code. Torque files typically have the `.tq` extension. Since this file ends in `.h`, it's a standard C++ header file.

**Relationship to JavaScript Functionality and Examples:**

This header file plays a crucial role in testing how V8, the JavaScript engine, handles different numeric values. While the file itself is C++, the values it defines directly correspond to the kinds of numbers JavaScript can represent and manipulate.

**Example (JavaScript and how `ValueHelper` helps test it):**

Consider how JavaScript handles integer overflow and floating-point precision.

```javascript
// Integer Overflow
let maxInt = 2147483647;
console.log(maxInt + 1); // Output might be unexpected due to integer overflow if not handled correctly

// Floating-Point Precision
let a = 0.1;
let b = 0.2;
console.log(a + b); // Output: 0.30000000000000004 (due to how floats are represented)

// NaN
let notANumber = NaN;
console.log(notANumber === NaN); // Output: false
```

The `ValueHelper` provides constants like `2147483648.0f` (which is `INT32_MAX + 1` represented as a float) and various other large integers, small floats, and `NaN` values. V8's tests would use these values to ensure that:

* **Integer operations:**  Adding 1 to the maximum integer results in the expected behavior (wrapping around or converting to a larger number type, depending on the context).
* **Floating-point arithmetic:** Operations like adding `0.1` and `0.2` produce results that are within acceptable precision limits.
* **`NaN` comparisons:** The engine correctly implements the `NaN !== NaN` behavior.

The `FloatCompareWrapper` is especially relevant here, as it allows V8's C++ tests to reliably check if a JavaScript operation involving `NaN` produces the expected `NaN` result.

**Code Logic Inference with Input and Output (Focusing on the Macros):**

Let's consider the `FOR_INT32_INPUTS` macro:

**Assumption:** We have a test function in a `.cc` file that includes `value-helper.h`.

```c++
// Example usage in a .cc test file
#include "v8/test/common/value-helper.h"
#include <iostream>

void TestInt32Value(int32_t input) {
  std::cout << "Processing int32_t: " << input << std::endl;
  // ... perform some test with the input value ...
}

TEST(MyTestSuite, TestInt32Inputs) {
  FOR_INT32_INPUTS(i) {
    TestInt32Value(i);
  }
}
```

**Input:** The `FOR_INT32_INPUTS(i)` macro will iterate through the elements of the `int32_vector()`, which is derived from the `uint32_array` (casted to `int32_t`). This array contains values like: `0x00000000, 0x00000001, 0xFFFFFFFF, ...` (represented as their signed 32-bit integer interpretations).

**Output:** The `TestInt32Value` function will be called multiple times, once for each value in the `int32_vector()`. The `std::cout` statement will print:

```
Processing int32_t: 0
Processing int32_t: 1
Processing int32_t: -1
Processing int32_t: 453242043
Processing int32_t: 79169000
Processing int32_t: -896789249
... (and so on for all values in the array)
```

**Common Programming Errors the `ValueHelper` Helps to Detect:**

The `ValueHelper` is designed to help uncover common programming errors related to numeric types, both in the V8 engine itself and potentially in code that interacts with V8. Some examples include:

1. **Integer Overflow/Underflow:**  By providing maximum and minimum integer values, tests can check if operations involving these values produce correct results and don't wrap around unexpectedly or cause errors.

   **Example (C++ code that might have an overflow bug):**
   ```c++
   int32_t addOne(int32_t x) {
     return x + 1;
   }

   // A test using ValueHelper could reveal this issue:
   TEST(OverflowTest, AddOneMaxInt) {
     int32_t max_int = std::numeric_limits<int32_t>::max();
     // Without proper checks, addOne(max_int) might result in unexpected behavior.
     // ValueHelper provides max_int as a test input.
   }
   ```

2. **Floating-Point Precision Errors:** The inclusion of many decimal values helps test the accuracy of floating-point calculations. Comparing results directly using `==` can be problematic due to precision issues. The `FloatCompareWrapper` addresses this.

   **Example (JavaScript code with potential precision issues):**
   ```javascript
   let result = 0.1 + 0.2;
   if (result === 0.3) { // This comparison might fail
     console.log("Equal");
   } else {
     console.log("Not equal"); // Likely output
   }
   ```
   V8's tests use values from `float64_array` to ensure its internal floating-point operations are as accurate as possible.

3. **Incorrect Handling of Special Floating-Point Values (NaN, Infinity):**  The `ValueHelper` provides `NaN` and infinity values to ensure that V8's operators and functions handle these special cases according to the ECMAScript specification (e.g., `NaN` comparisons, operations involving infinity).

   **Example (JavaScript code demonstrating NaN behavior):**
   ```javascript
   console.log(NaN === NaN); // false
   console.log(NaN + 5);     // NaN
   ```
   V8 tests use the `NaN` constants to verify this behavior.

4. **Sign Errors with Zero:**  While `-0` and `+0` are considered equal in most JavaScript operations, their bit representations are different. The `FloatCompareWrapper`'s handling of the sign bit allows for more rigorous testing of scenarios where the sign of zero might be relevant at a lower level.

In summary, `v8/test/common/value-helper.h` is a crucial utility for ensuring the correctness and robustness of V8's numeric handling by providing a comprehensive set of test values and comparison tools. It helps identify and prevent common programming errors related to numeric data types.

Prompt: 
```
这是目录为v8/test/common/value-helper.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/common/value-helper.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_VALUE_HELPER_H_
#define V8_COMMON_VALUE_HELPER_H_

#include <stdint.h>

#include "src/base/template-utils.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node.h"
#include "src/execution/isolate.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {
namespace compiler {

// A collection of utilities related to numerical and heap values, including
// example input values of various types, including int32_t, uint32_t, double,
// etc.
class ValueHelper {
 public:
  static constexpr float float32_array[] = {
      -std::numeric_limits<float>::infinity(),
      -2.70497e+38f,
      -1.4698e+37f,
      -1.22813e+35f,
      -1.20555e+35f,
      -1.34584e+34f,
      -1.0079e+32f,
      -6.49364e+26f,
      -3.06077e+25f,
      -1.46821e+25f,
      -1.17658e+23f,
      -1.9617e+22f,
      -2.7357e+20f,
      -9223372036854775808.0f,  // INT64_MIN
      -1.48708e+13f,
      -1.89633e+12f,
      -4.66622e+11f,
      -2.22581e+11f,
      -1.45381e+10f,
      -2147483904.0f,  // First float32 after INT32_MIN
      -2147483648.0f,  // INT32_MIN
      -2147483520.0f,  // Last float32 before INT32_MIN
      -1.3956e+09f,
      -1.32951e+09f,
      -1.30721e+09f,
      -1.19756e+09f,
      -9.26822e+08f,
      -6.35647e+08f,
      -4.00037e+08f,
      -1.81227e+08f,
      -5.09256e+07f,
      -964300.0f,
      -192446.0f,
      -28455.0f,
      -27194.0f,
      -26401.0f,
      -20575.0f,
      -17069.0f,
      -9167.0f,
      -960.178f,
      -113.0f,
      -62.0f,
      -15.0f,
      -7.0f,
      -1.0f,
      -0.0256635f,
      -4.60374e-07f,
      -3.63759e-10f,
      -4.30175e-14f,
      -5.27385e-15f,
      -1.5707963267948966f,
      -1.48084e-15f,
      -2.220446049250313e-16f,
      -1.05755e-19f,
      -3.2995e-21f,
      -1.67354e-23f,
      -1.11885e-23f,
      -1.78506e-30f,
      -5.07594e-31f,
      -3.65799e-31f,
      -1.43718e-34f,
      -1.27126e-38f,
      -0.0f,
      0.0f,
      1.17549e-38f,
      1.56657e-37f,
      4.08512e-29f,
      3.31357e-28f,
      6.25073e-22f,
      4.1723e-13f,
      1.44343e-09f,
      1.5707963267948966f,
      5.27004e-08f,
      9.48298e-08f,
      5.57888e-07f,
      4.89988e-05f,
      0.244326f,
      1.0f,
      12.4895f,
      19.0f,
      47.0f,
      106.0f,
      538.324f,
      564.536f,
      819.124f,
      7048.0f,
      12611.0f,
      19878.0f,
      20309.0f,
      797056.0f,
      1.77219e+09f,
      2147483648.0f,  // INT32_MAX + 1
      2147483904.0f,  // INT32_MAX + 1 and significand = 1.
      4294967296.0f,  // UINT32_MAX + 1
      1.51116e+11f,
      4.18193e+13f,
      3.59167e+16f,
      9223372036854775808.0f,   // INT64_MAX + 1
      18446744073709551616.0f,  // UINT64_MAX + 1
      3.38211e+19f,
      2.67488e+20f,
      1.78831e+21f,
      9.20914e+21f,
      8.35654e+23f,
      1.4495e+24f,
      5.94015e+25f,
      4.43608e+30f,
      2.44502e+33f,
      2.61152e+33f,
      1.38178e+37f,
      1.71306e+37f,
      3.31899e+38f,
      3.40282e+38f,
      std::numeric_limits<float>::infinity(),
      std::numeric_limits<float>::quiet_NaN(),
      -std::numeric_limits<float>::quiet_NaN()};

  static constexpr base::Vector<const float> float32_vector() {
    return base::ArrayVector(float32_array);
  }

  static constexpr double float64_array[] = {
      -2e66,
      -2.220446049250313e-16,
      -9223373136366403584.0,
      -9223372036854775808.0,  // INT64_MIN
      -2147483649.5,
      -2147483648.25,
      -2147483648.0,
      -2147483647.875,
      -2147483647.125,
      -2147483647.0,
      -999.75,
      -2e66,
      -1.75,
      -1.5707963267948966,
      -1.0,
      -0.5,
      -0.0,
      0.0,
      3e-88,
      0.125,
      0.25,
      0.375,
      0.5,
      1.0,
      1.17549e-38,
      1.56657e-37,
      1.0000001,
      1.25,
      1.5707963267948966,
      2,
      3.1e7,
      5.125,
      6.25,
      888,
      982983.25,
      2147483647.0,
      2147483647.375,
      2147483647.75,
      2147483648.0,
      2147483648.25,
      2147483649.25,
      9223372036854775808.0,  // INT64_MAX + 1
      9223373136366403584.0,
      18446744073709551616.0,  // UINT64_MAX + 1
      2e66,
      V8_INFINITY,
      -V8_INFINITY,
      std::numeric_limits<double>::quiet_NaN(),
      -std::numeric_limits<double>::quiet_NaN()};

  static constexpr base::Vector<const double> float64_vector() {
    return base::ArrayVector(float64_array);
  }

  static constexpr uint32_t uint32_array[] = {
      0x00000000, 0x00000001, 0xFFFFFFFF, 0x1B09788B, 0x04C5FCE8, 0xCC0DE5BF,
      // This row is useful for testing lea optimizations on intel.
      0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000008, 0x00000009,
      0x273A798E, 0x187937A3, 0xECE3AF83, 0x5495A16B, 0x0B668ECC, 0x11223344,
      0x0000009E, 0x00000043, 0x0000AF73, 0x0000116B, 0x00658ECC, 0x002B3B4C,
      0x88776655, 0x70000000, 0x07200000, 0x7FFFFFFF, 0x56123761, 0x7FFFFF00,
      0x761C4761, 0x80000000, 0x88888888, 0xA0000000, 0xDDDDDDDD, 0xE0000000,
      0xEEEEEEEE, 0xFFFFFFFD, 0xF0000000, 0x007FFFFF, 0x003FFFFF, 0x001FFFFF,
      0x000FFFFF, 0x0007FFFF, 0x0003FFFF, 0x0001FFFF, 0x0000FFFF, 0x00007FFF,
      0x00003FFF, 0x00001FFF, 0x00000FFF, 0x000007FF, 0x000003FF, 0x000001FF,
      // Bit pattern of a quiet NaN and signaling NaN, with or without
      // additional payload.
      0x7FC00000, 0x7F800000, 0x7FFFFFFF, 0x7F876543};

  static constexpr base::Vector<const uint32_t> uint32_vector() {
    return base::ArrayVector(uint32_array);
  }

  static base::Vector<const int32_t> int32_vector() {
    return base::Vector<const int32_t>::cast(uint32_vector());
  }

  static constexpr uint64_t uint64_array[] = {
      0x00000000, 0x00000001, 0xFFFFFFFF, 0x1B09788B, 0x04C5FCE8, 0xCC0DE5BF,
      0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000008, 0x00000009,
      0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD,
      0x0000000000000000, 0x0000000100000000, 0xFFFFFFFF00000000,
      0x1B09788B00000000, 0x04C5FCE800000000, 0xCC0DE5BF00000000,
      0x0000000200000000, 0x0000000300000000, 0x0000000400000000,
      0x0000000500000000, 0x0000000800000000, 0x0000000900000000,
      0x273A798E187937A3, 0xECE3AF835495A16B, 0x0B668ECC11223344, 0x0000009E,
      0x00000043, 0x0000AF73, 0x0000116B, 0x00658ECC, 0x002B3B4C, 0x88776655,
      0x70000000, 0x07200000, 0x7FFFFFFF, 0x56123761, 0x7FFFFF00,
      0x761C4761EEEEEEEE, 0x80000000EEEEEEEE, 0x88888888DDDDDDDD,
      0xA0000000DDDDDDDD, 0xDDDDDDDDAAAAAAAA, 0xE0000000AAAAAAAA,
      0xEEEEEEEEEEEEEEEE, 0xFFFFFFFDEEEEEEEE, 0xF0000000DDDDDDDD,
      0x007FFFFFDDDDDDDD, 0x003FFFFFAAAAAAAA, 0x001FFFFFAAAAAAAA, 0x000FFFFF,
      0x0007FFFF, 0x0003FFFF, 0x0001FFFF, 0x0000FFFF, 0x00007FFF, 0x00003FFF,
      0x00001FFF, 0x00000FFF, 0x000007FF, 0x000003FF, 0x000001FF,
      0x00003FFFFFFFFFFF, 0x00001FFFFFFFFFFF, 0x00000FFFFFFFFFFF,
      0x000007FFFFFFFFFF, 0x000003FFFFFFFFFF, 0x000001FFFFFFFFFF,
      0x8000008000000000, 0x8000008000000001, 0x8000000000000400,
      0x8000000000000401, 0x0000000000000020,
      0x8000000000000000,  // int64_t min
      0x7FFFFFFFFFFFFFFF,  // int64_t max
      // Bit pattern of a quiet NaN and signaling NaN, with or without
      // additional payload.
      0x7FF8000000000000, 0x7FF0000000000000, 0x7FF8123456789ABC,
      0x7FF7654321FEDCBA};

  static constexpr base::Vector<const uint64_t> uint64_vector() {
    return base::ArrayVector(uint64_array);
  }

  static base::Vector<const int64_t> int64_vector() {
    return base::Vector<const int64_t>::cast(uint64_vector());
  }

  static constexpr int16_t int16_array[] = {
      0, 1, 2, INT16_MAX - 1, INT16_MAX, INT16_MIN, INT16_MIN + 1, -2, -1};

  static constexpr base::Vector<const int16_t> int16_vector() {
    return base::ArrayVector(int16_array);
  }

  static base::Vector<const uint16_t> uint16_vector() {
    return base::Vector<const uint16_t>::cast(int16_vector());
  }

  static constexpr int8_t int8_array[] = {
      0, 1, 2, INT8_MAX - 1, INT8_MAX, INT8_MIN, INT8_MIN + 1, -2, -1};

  static constexpr base::Vector<const int8_t> int8_vector() {
    return base::ArrayVector(int8_array);
  }

  static base::Vector<const uint8_t> uint8_vector() {
    return base::Vector<const uint8_t>::cast(base::ArrayVector(int8_array));
  }

  static constexpr uint32_t ror_array[31] = {
      1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

  static constexpr base::Vector<const uint32_t> ror_vector() {
    return base::ArrayVector(ror_array);
  }

  template <typename T>
  static inline base::Vector<const T> GetVector();
};

template <>
inline base::Vector<const int8_t> ValueHelper::GetVector() {
  return int8_vector();
}

template <>
inline base::Vector<const uint8_t> ValueHelper::GetVector() {
  return uint8_vector();
}

template <>
inline base::Vector<const int16_t> ValueHelper::GetVector() {
  return int16_vector();
}

template <>
inline base::Vector<const uint16_t> ValueHelper::GetVector() {
  return uint16_vector();
}

template <>
inline base::Vector<const int32_t> ValueHelper::GetVector() {
  return int32_vector();
}

template <>
inline base::Vector<const uint32_t> ValueHelper::GetVector() {
  return uint32_vector();
}

template <>
inline base::Vector<const int64_t> ValueHelper::GetVector() {
  return int64_vector();
}

template <>
inline base::Vector<const float> ValueHelper::GetVector() {
  return float32_vector();
}

template <>
inline base::Vector<const double> ValueHelper::GetVector() {
  return float64_vector();
}

// Helper macros that can be used in FOR_INT32_INPUTS(i) { ... i ... }
#define FOR_INPUTS(ctype, itype, var) \
  for (ctype var : ::v8::internal::compiler::ValueHelper::itype##_vector())

#define FOR_INT32_INPUTS(var) FOR_INPUTS(int32_t, int32, var)
#define FOR_UINT32_INPUTS(var) FOR_INPUTS(uint32_t, uint32, var)
#define FOR_INT16_INPUTS(var) FOR_INPUTS(int16_t, int16, var)
#define FOR_UINT16_INPUTS(var) FOR_INPUTS(uint16_t, uint16, var)
#define FOR_INT8_INPUTS(var) FOR_INPUTS(int8_t, int8, var)
#define FOR_UINT8_INPUTS(var) FOR_INPUTS(uint8_t, uint8, var)
#define FOR_INT64_INPUTS(var) FOR_INPUTS(int64_t, int64, var)
#define FOR_UINT64_INPUTS(var) FOR_INPUTS(uint64_t, uint64, var)
#define FOR_FLOAT32_INPUTS(var) FOR_INPUTS(float, float32, var)
#define FOR_FLOAT64_INPUTS(var) FOR_INPUTS(double, float64, var)

#define FOR_INT32_SHIFTS(var) for (int32_t var = 0; var < 32; var++)

#define FOR_UINT32_SHIFTS(var) for (uint32_t var = 0; var < 32; var++)

template <typename type>
struct FloatCompareWrapper {
  type value;
  explicit FloatCompareWrapper(type x) : value(x) {}
  bool operator==(FloatCompareWrapper<type> const& other) const {
    return std::isnan(value)
               ? std::isnan(other.value)
               : value == other.value &&
                     std::signbit(value) == std::signbit(other.value);
  }
};

template <typename type>
std::ostream& operator<<(std::ostream& out, FloatCompareWrapper<type> wrapper) {
  uint8_t bytes[sizeof(type)];
  memcpy(bytes, &wrapper.value, sizeof(type));
  out << wrapper.value << " (0x";
  const char* kHexDigits = "0123456789ABCDEF";
  for (unsigned i = 0; i < sizeof(type); ++i) {
    out << kHexDigits[bytes[i] >> 4] << kHexDigits[bytes[i] & 15];
  }
  return out << ")";
}

#define CHECK_FLOAT_EQ(lhs, rhs)                                               \
  do {                                                                         \
    using FloatWrapper = ::v8::internal::compiler::FloatCompareWrapper<float>; \
    CHECK_EQ(FloatWrapper(lhs), FloatWrapper(rhs));                            \
  } while (false)

#define CHECK_DOUBLE_EQ(lhs, rhs)                              \
  do {                                                         \
    using DoubleWrapper =                                      \
        ::v8::internal::compiler::FloatCompareWrapper<double>; \
    CHECK_EQ(DoubleWrapper(lhs), DoubleWrapper(rhs));          \
  } while (false)

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_VALUE_HELPER_H_

"""

```