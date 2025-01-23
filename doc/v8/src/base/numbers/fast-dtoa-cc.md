Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of the `fast-dtoa.cc` file within the V8 JavaScript engine. Key aspects to cover include:

* Core functionality.
* Whether it's a Torque file (it's not, based on the `.cc` extension).
* Relationship to JavaScript.
* Code logic with examples.
* Common programming errors it addresses (implicitly, by providing correct functionality).

**2. High-Level Skim and Keyword Spotting:**

A quick scan reveals several important terms and patterns:

* `dtoa`:  Likely stands for "double to ASCII" or "double to string," suggesting it's about converting floating-point numbers to their string representations. The "fast" prefix hints at optimization.
* `v8`, `namespace v8::base::numbers`: Confirms it's part of V8's number handling.
* `double`, `uint64_t`, `int`:  Data types indicating numerical operations.
* `DiyFp`:  A custom data structure, probably for representing floating-point numbers in a way that's easier to manipulate for this algorithm. The "Diy" suggests a "do-it-yourself" or custom implementation.
* `PowersOfTenCache`:  Suggests precomputed powers of ten are used for efficiency.
* `RoundWeed`, `DigitGen`, `Grisu3`:  Function names that seem to correspond to different stages or algorithms in the conversion process.
* Comments explaining intervals, rounding, and potential imprecision: Indicates the algorithm deals with the complexities of floating-point representation.

**3. Deeper Dive into Key Functions (Top-Down or Bottom-Up):**

* **`FastDtoa` (Entry Point):** This function is clearly the main entry point. It takes a `double`, a `FastDtoaMode` (likely specifying the desired precision), a buffer, and pointers to output length and decimal point. This confirms the core purpose: converting a double to a string. The `switch` statement based on `mode` suggests different algorithms are used.

* **`Grisu3` and `Grisu3Counted`:** These are called by `FastDtoa`. The comments for `Grisu3` mention generating the *shortest* representation, while `Grisu3Counted` generates a representation with a *specific number* of digits. This explains the different `FastDtoaMode` options. The name "Grisu3" likely refers to a specific algorithm.

* **`DigitGen` and `DigitGenCounted`:** These functions seem responsible for the core digit generation logic. They work with the `DiyFp` representation and the scaled values. The comments within these functions provide detailed explanations of the steps involved, including handling imprecision and ensuring the generated digits are within the correct range.

* **`RoundWeed` and `RoundWeedCounted`:** These appear to be refinement steps, adjusting the last digit and ensuring the generated representation is accurate and the closest possible. The detailed comments and the "unsafe interval" concept highlight the challenges of accurate floating-point to string conversion.

* **Helper Functions (`BiggestPowerTen`, `fast_divmod`):** These are utilities to perform common operations efficiently, like finding the largest power of ten and fast division/modulo.

**4. Connecting to JavaScript:**

The name "v8" strongly implies a connection to JavaScript. The core function of converting doubles to strings is fundamental in JavaScript when you need to display numbers or convert them to strings for other purposes. The example `console.log(0.1 + 0.2)` directly demonstrates a common JavaScript behavior where floating-point arithmetic can produce results that are not exactly what one might expect in base-10. The `FastDtoa` algorithm aims to produce the most human-readable and accurate string representation in such cases.

**5. Code Logic and Examples:**

For the logic examples, focusing on the core task of converting a `double` to a string is key. Choosing simple inputs like `12.345` and `0.000123` helps illustrate how the algorithm might handle different magnitudes and decimal places. The idea is to trace the conceptual steps without getting bogged down in the bit-level details of the `DiyFp` operations.

**6. Common Programming Errors:**

Thinking about the *problems* this code solves naturally leads to common errors. Inaccurate string representations of floating-point numbers are a frequent source of confusion and bugs in programming. Examples like `0.1 + 0.2` and issues with precision when storing or transmitting floating-point values are good illustrations.

**7. Torque Check:**

Checking the file extension (`.cc`) immediately answers the Torque question. Torque files in V8 typically end with `.tq`.

**8. Structuring the Answer:**

Organizing the findings into logical sections makes the answer clear and easy to understand:

* **Core Functionality:** Start with a concise overview.
* **Torque:** Address this specific question directly.
* **JavaScript Relationship:** Provide a clear connection and a relevant example.
* **Code Logic:**  Illustrate the process with simple inputs and outputs.
* **Common Errors:** Highlight the practical implications of this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the code directly manipulates the bits of the `double`.
* **Correction:** The `DiyFp` structure suggests an intermediate representation is used for easier arithmetic.
* **Initial thought:**  Focus on the mathematical formulas within the code.
* **Correction:** While the math is important, explaining the *purpose* of each step and how it contributes to accurate conversion is more valuable for a general understanding.
* **Initial thought:**  Provide very low-level code tracing.
* **Correction:** A high-level conceptual explanation of the digit generation and rounding process is sufficient and easier to grasp. The detailed comments in the code itself provide the lower-level information.

By following this thought process, we can systematically analyze the code and address all aspects of the request, resulting in a comprehensive and informative answer.
The provided code snippet is the C++ source code for `fast-dtoa.cc`, a part of the V8 JavaScript engine responsible for efficiently converting double-precision floating-point numbers (doubles) to their string representations (ASCII).

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Fast Double-to-ASCII Conversion:** The primary goal of this code is to implement a fast algorithm for converting `double` values into human-readable string formats. This is a crucial operation for JavaScript, as it's needed whenever a number is converted to a string (e.g., using `toString()`, string concatenation, or logging to the console).

2. **Shortest and Precise Representations:** The code provides two main modes of conversion:
   - **Shortest Representation (Grisu3):**  This mode aims to produce the shortest possible string representation that, when parsed back into a double, yields the original value. This avoids unnecessary trailing digits (e.g., "0.1" instead of "0.10000000000000001").
   - **Precise Representation (Grisu3Counted):** This mode allows the user to request a specific number of digits of precision. This is useful when a fixed-width output is required or when comparing numbers based on a certain level of precision.

3. **Handling Floating-Point Imprecision:**  Floating-point numbers have inherent imprecision due to their binary representation. This code takes this into account and strives to produce string representations that accurately reflect the intended value, even with these limitations. The `RoundWeed` and `RoundWeedCounted` functions are key to this, ensuring the generated digits are the closest possible representation.

4. **Optimization:** The "fast" in the filename suggests that the algorithm is optimized for speed. This is evident in techniques like:
   - **Cached Powers of Ten:**  The `PowersOfTenCache` is used to avoid repeatedly calculating powers of ten, which are frequently needed in the conversion process.
   - **DiyFp (Do-It-Yourself Floating Point):**  This custom structure likely provides a more efficient way to perform floating-point arithmetic for the specific needs of the conversion algorithm compared to directly using `double`.
   - **Fast Division (`fast_divmod`):**  This function utilizes optimized bitwise operations and precomputed magic numbers for faster division by powers of ten.

**Is it a Torque Source File?**

No, `v8/src/base/numbers/fast-dtoa.cc` is **not** a V8 Torque source file. Torque files in V8 use the `.tq` extension. The `.cc` extension indicates that this is a standard C++ source file.

**Relationship to JavaScript and Examples:**

This code is directly related to how JavaScript handles number-to-string conversions. Whenever you perform an operation in JavaScript that requires converting a number to its string representation, this code (or a similar part of V8's codebase) is involved.

**JavaScript Examples:**

```javascript
// Using the default shortest representation
let num1 = 0.1 + 0.2;
console.log(num1.toString()); // Output: "0.30000000000000004" (May vary slightly based on JS engine, but fast-dtoa aims for a concise representation)

let num2 = 123.456;
console.log(num2.toString()); // Output: "123.456"

// Implicit conversion to string
let num3 = 10;
let str1 = "The number is: " + num3;
console.log(str1); // Output: "The number is: 10"

// Using toFixed() for a specific number of decimal places (may indirectly use related logic)
let num4 = 3.14159;
console.log(num4.toFixed(2)); // Output: "3.14" (While toFixed has its own implementation, the underlying principles of accurate conversion are relevant)
```

**Code Logic Inference with Assumptions:**

Let's consider a simplified scenario of converting a positive `double` to its shortest string representation.

**Assumptions:**

* **Input `v`:** A `double` with the value `12.345`.
* **`FastDtoaMode`:** `FAST_DTOA_SHORTEST`.
* The `Grisu3` function is called.

**Simplified Logic Flow (Conceptual):**

1. **Normalization:** The input `double` (12.345) is likely converted into a normalized `DiyFp` representation, which involves separating the significand (the digits) and the exponent.

2. **Scaling:** The `Grisu3` function uses cached powers of ten (`ten_mk`) to scale the number into a range where the integer part is easier to work with. For example, it might multiply 12.345 by 1000 to get 12345.

3. **Digit Generation (`DigitGen`):** The `DigitGen` function is called with scaled boundaries (derived from the original number's precision limits). This function iteratively extracts digits from the scaled number.
   - It starts by finding the largest power of ten smaller than the integer part (e.g., for 12345, it would be 10000).
   - It divides the number by this power of ten to get the first digit (12345 / 10000 = 1).
   - It repeats this process with smaller powers of ten to extract subsequent digits (2, 3, 4, 5).

4. **Rounding and Weeding (`RoundWeed`):** After generating the digits, the `RoundWeed` function (in the `FAST_DTOA_SHORTEST` case) checks if the generated representation is indeed the shortest and closest to the original value, considering the imprecision of floating-point numbers. It might adjust the last digit if necessary.

5. **Decimal Point Placement:** The `decimal_exponent` variable (calculated in `Grisu3`) determines where the decimal point should be placed in the generated string.

**Hypothetical Input and Output:**

* **Input `v` (double):** `12.345`
* **`FastDtoaMode`:** `FAST_DTOA_SHORTEST`
* **Output `buffer`:**  The character array would contain '1', '2', '.', '3', '4', '5'.
* **Output `length`:** `5` (number of digits excluding the decimal point).
* **Output `decimal_point`:** `2` (indicating the decimal point is after the second digit from the left).

**Common Programming Errors Addressed (Implicitly):**

This code helps avoid several common pitfalls related to converting floating-point numbers to strings:

1. **Excessive Trailing Zeros:**  Without a mechanism like the shortest representation, simple conversion might produce strings like "0.10000000000000001", which is not ideal for display or data exchange.

2. **Loss of Precision:**  A naive conversion might truncate digits prematurely, leading to a loss of accuracy. The algorithms here strive to preserve the necessary precision.

3. **Inconsistent Representations Across Platforms:** Different systems might have slightly different ways of representing floating-point numbers. This code aims for a consistent and reliable conversion behavior within the V8 environment.

4. **Difficulties in Round-Tripping:**  Ideally, converting a number to a string and then parsing it back to a number should result in the original value (or a very close approximation). The shortest representation helps achieve this by avoiding ambiguous or overly precise strings.

**Example of a User's Potential Programming Error (that this code helps avoid):**

```javascript
let a = 0.1;
let b = 0.2;
let sum = a + b;

// A common mistake is to directly compare floating-point numbers for equality
if (sum === 0.3) { // This is often false due to floating-point imprecision
  console.log("Sum is exactly 0.3");
} else {
  console.log("Sum is not exactly 0.3, it's: " + sum.toString()); // fast-dtoa helps produce a reasonable string here
}

// Instead, compare within a tolerance
const tolerance = 0.000001;
if (Math.abs(sum - 0.3) < tolerance) {
  console.log("Sum is close enough to 0.3");
}
```

In the above example, if JavaScript used a naive string conversion, the output of `sum.toString()` might be something very long and confusing. `fast-dtoa` helps produce a more human-friendly and often shorter representation, making it easier for developers to understand the value.

### 提示词
```
这是目录为v8/src/base/numbers/fast-dtoa.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/numbers/fast-dtoa.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/fast-dtoa.h"

#include <stdint.h>

#include "src/base/logging.h"
#include "src/base/numbers/cached-powers.h"
#include "src/base/numbers/diy-fp.h"
#include "src/base/numbers/double.h"

namespace v8 {
namespace base {

// The minimal and maximal target exponent define the range of w's binary
// exponent, where 'w' is the result of multiplying the input by a cached power
// of ten.
//
// A different range might be chosen on a different platform, to optimize digit
// generation, but a smaller range requires more powers of ten to be cached.
static const int kMinimalTargetExponent = -60;
static const int kMaximalTargetExponent = -32;

// Adjusts the last digit of the generated number, and screens out generated
// solutions that may be inaccurate. A solution may be inaccurate if it is
// outside the safe interval, or if we ctannot prove that it is closer to the
// input than a neighboring representation of the same length.
//
// Input: * buffer containing the digits of too_high / 10^kappa
//        * the buffer's length
//        * distance_too_high_w == (too_high - w).f() * unit
//        * unsafe_interval == (too_high - too_low).f() * unit
//        * rest = (too_high - buffer * 10^kappa).f() * unit
//        * ten_kappa = 10^kappa * unit
//        * unit = the common multiplier
// Output: returns true if the buffer is guaranteed to contain the closest
//    representable number to the input.
//  Modifies the generated digits in the buffer to approach (round towards) w.
static bool RoundWeed(char* last_digit, uint64_t distance_too_high_w,
                      uint64_t unsafe_interval, uint64_t rest,
                      uint64_t ten_kappa, uint64_t unit) {
  uint64_t small_distance = distance_too_high_w - unit;
  uint64_t big_distance = distance_too_high_w + unit;
  // Let w_low  = too_high - big_distance, and
  //     w_high = too_high - small_distance.
  // Note: w_low < w < w_high
  //
  // The real w (* unit) must lie somewhere inside the interval
  // ]w_low; w_high[ (often written as "(w_low; w_high)")

  // Basically the buffer currently contains a number in the unsafe interval
  // ]too_low; too_high[ with too_low < w < too_high
  //
  //  too_high - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  //                     ^v 1 unit            ^      ^                 ^      ^
  //  boundary_high ---------------------     .      .                 .      .
  //                     ^v 1 unit            .      .                 .      .
  //   - - - - - - - - - - - - - - - - - - -  +  - - + - - - - - -     .      .
  //                                          .      .         ^       .      .
  //                                          .  big_distance  .       .      .
  //                                          .      .         .       .    rest
  //                              small_distance     .         .       .      .
  //                                          v      .         .       .      .
  //  w_high - - - - - - - - - - - - - - - - - -     .         .       .      .
  //                     ^v 1 unit                   .         .       .      .
  //  w ----------------------------------------     .         .       .      .
  //                     ^v 1 unit                   v         .       .      .
  //  w_low  - - - - - - - - - - - - - - - - - - - - -         .       .      .
  //                                                           .       .      v
  //  buffer --------------------------------------------------+-------+--------
  //                                                           .       .
  //                                                  safe_interval    .
  //                                                           v       .
  //   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -     .
  //                     ^v 1 unit                                     .
  //  boundary_low -------------------------                     unsafe_interval
  //                     ^v 1 unit                                     v
  //  too_low  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  //
  //
  // Note that the value of buffer could lie anywhere inside the range too_low
  // to too_high.
  //
  // boundary_low, boundary_high and w are approximations of the real boundaries
  // and v (the input number). They are guaranteed to be precise up to one unit.
  // In fact the error is guaranteed to be strictly less than one unit.
  //
  // Anything that lies outside the unsafe interval is guaranteed not to round
  // to v when read again.
  // Anything that lies inside the safe interval is guaranteed to round to v
  // when read again.
  // If the number inside the buffer lies inside the unsafe interval but not
  // inside the safe interval then we simply do not know and bail out (returning
  // false).
  //
  // Similarly we have to take into account the imprecision of 'w' when finding
  // the closest representation of 'w'. If we have two potential
  // representations, and one is closer to both w_low and w_high, then we know
  // it is closer to the actual value v.
  //
  // By generating the digits of too_high we got the largest (closest to
  // too_high) buffer that is still in the unsafe interval. In the case where
  // w_high < buffer < too_high we try to decrement the buffer.
  // This way the buffer approaches (rounds towards) w.
  // There are 3 conditions that stop the decrementation process:
  //   1) the buffer is already below w_high
  //   2) decrementing the buffer would make it leave the unsafe interval
  //   3) decrementing the buffer would yield a number below w_high and farther
  //      away than the current number. In other words:
  //              (buffer{-1} < w_high) && w_high - buffer{-1} > buffer - w_high
  // Instead of using the buffer directly we use its distance to too_high.
  // Conceptually rest ~= too_high - buffer
  // We need to do the following tests in this order to avoid over- and
  // underflows.
  DCHECK(rest <= unsafe_interval);
  while (rest < small_distance &&                // Negated condition 1
         unsafe_interval - rest >= ten_kappa &&  // Negated condition 2
         (rest + ten_kappa < small_distance ||   // buffer{-1} > w_high
          small_distance - rest >= rest + ten_kappa - small_distance)) {
    --*last_digit;
    rest += ten_kappa;
  }

  // We have approached w+ as much as possible. We now test if approaching w-
  // would require changing the buffer. If yes, then we have two possible
  // representations close to w, but we cannot decide which one is closer.
  if (rest < big_distance && unsafe_interval - rest >= ten_kappa &&
      (rest + ten_kappa < big_distance ||
       big_distance - rest > rest + ten_kappa - big_distance)) {
    return false;
  }

  // Weeding test.
  //   The safe interval is [too_low + 2 ulp; too_high - 2 ulp]
  //   Since too_low = too_high - unsafe_interval this is equivalent to
  //      [too_high - unsafe_interval + 4 ulp; too_high - 2 ulp]
  //   Conceptually we have: rest ~= too_high - buffer
  return (2 * unit <= rest) && (rest <= unsafe_interval - 4 * unit);
}

// Rounds the buffer upwards if the result is closer to v by possibly adding
// 1 to the buffer. If the precision of the calculation is not sufficient to
// round correctly, return false.
// The rounding might shift the whole buffer in which case the kappa is
// adjusted. For example "99", kappa = 3 might become "10", kappa = 4.
//
// If 2*rest > ten_kappa then the buffer needs to be round up.
// rest can have an error of +/- 1 unit. This function accounts for the
// imprecision and returns false, if the rounding direction cannot be
// unambiguously determined.
//
// Precondition: rest < ten_kappa.
static bool RoundWeedCounted(Vector<char> buffer, int length, uint64_t rest,
                             uint64_t ten_kappa, uint64_t unit, int* kappa) {
  DCHECK(rest < ten_kappa);
  // The following tests are done in a specific order to avoid overflows. They
  // will work correctly with any uint64 values of rest < ten_kappa and unit.
  //
  // If the unit is too big, then we don't know which way to round. For example
  // a unit of 50 means that the real number lies within rest +/- 50. If
  // 10^kappa == 40 then there is no way to tell which way to round.
  if (unit >= ten_kappa) return false;
  // Even if unit is just half the size of 10^kappa we are already completely
  // lost. (And after the previous test we know that the expression will not
  // over/underflow.)
  if (ten_kappa - unit <= unit) return false;
  // If 2 * (rest + unit) <= 10^kappa we can safely round down.
  if ((ten_kappa - rest > rest) && (ten_kappa - 2 * rest >= 2 * unit)) {
    return true;
  }
  // If 2 * (rest - unit) >= 10^kappa, then we can safely round up.
  if ((rest > unit) && (ten_kappa - (rest - unit) <= (rest - unit))) {
    // Increment the last digit recursively until we find a non '9' digit.
    buffer[length - 1]++;
    for (int i = length - 1; i > 0; --i) {
      if (buffer[i] != '0' + 10) break;
      buffer[i] = '0';
      buffer[i - 1]++;
    }
    // If the first digit is now '0'+ 10 we had a buffer with all '9's. With the
    // exception of the first digit all digits are now '0'. Simply switch the
    // first digit to '1' and adjust the kappa. Example: "99" becomes "10" and
    // the power (the kappa) is increased.
    if (buffer[0] == '0' + 10) {
      buffer[0] = '1';
      (*kappa) += 1;
    }
    return true;
  }
  return false;
}

static const uint32_t kTen4 = 10000;
static const uint32_t kTen5 = 100000;
static const uint32_t kTen6 = 1000000;
static const uint32_t kTen7 = 10000000;
static const uint32_t kTen8 = 100000000;
static const uint32_t kTen9 = 1000000000;

struct DivMagic {
  uint32_t mul;
  uint32_t shift;
};

// This table was computed by libdivide. Essentially, the shift is
// floor(log2(x)), and the mul is 2^(33 + shift) / x, rounded up and truncated
// to 32 bits.
static const DivMagic div[] = {
    {0, 0},            // Not used, since 1 is not supported by the algorithm.
    {0x9999999a, 3},   // 10
    {0x47ae147b, 6},   // 100
    {0x0624dd30, 9},   // 1000
    {0xa36e2eb2, 13},  // 10000
    {0x4f8b588f, 16},  // 100000
    {0x0c6f7a0c, 19},  // 1000000
    {0xad7f29ac, 23},  // 10000000
    {0x5798ee24, 26}   // 100000000
};

// Returns *val / divisor, and does *val %= divisor. d must be the DivMagic
// corresponding to the divisor.
//
// This algorithm is exactly the same as libdivide's branch-free u32 algorithm,
// except that we add back a branch anyway to support 1.
//
// GCC/Clang uses a slightly different algorithm that doesn't need
// the extra rounding step (and that would allow us to do 1 without
// a branch), but it requires a pre-shift for the case of 10000,
// so it ends up slower, at least on x86-64.
//
// Note that this is actually a small loss for certain CPUs with
// a very fast divider (e.g. Zen 3), but a significant win for most
// others (including the entire Skylake family).
static inline uint32_t fast_divmod(uint32_t* val, uint32_t divisor,
                                   const DivMagic& d) {
  if (divisor == 1) {
    uint32_t digit = *val;
    *val = 0;
    return digit;
  } else {
    uint32_t q = (static_cast<uint64_t>(*val) * d.mul) >> 32;
    uint32_t t = ((*val - q) >> 1) + q;
    uint32_t digit = t >> d.shift;
    *val -= digit * divisor;
    return digit;
  }
}

// Returns the biggest power of ten that is less than or equal than the given
// number. We furthermore receive the maximum number of bits 'number' has.
// If number_bits == 0 then 0^-1 is returned
// The number of bits must be <= 32.
// Precondition: number < (1 << (number_bits + 1)).
static inline void BiggestPowerTen(uint32_t number, int number_bits,
                                   uint32_t* power, unsigned* exponent) {
  switch (number_bits) {
    case 32:
    case 31:
    case 30:
      if (kTen9 <= number) {
        *power = kTen9;
        *exponent = 9;
        break;
      }
      [[fallthrough]];
    case 29:
    case 28:
    case 27:
      if (kTen8 <= number) {
        *power = kTen8;
        *exponent = 8;
        break;
      }
      [[fallthrough]];
    case 26:
    case 25:
    case 24:
      if (kTen7 <= number) {
        *power = kTen7;
        *exponent = 7;
        break;
      }
      [[fallthrough]];
    case 23:
    case 22:
    case 21:
    case 20:
      if (kTen6 <= number) {
        *power = kTen6;
        *exponent = 6;
        break;
      }
      [[fallthrough]];
    case 19:
    case 18:
    case 17:
      if (kTen5 <= number) {
        *power = kTen5;
        *exponent = 5;
        break;
      }
      [[fallthrough]];
    case 16:
    case 15:
    case 14:
      if (kTen4 <= number) {
        *power = kTen4;
        *exponent = 4;
        break;
      }
      [[fallthrough]];
    case 13:
    case 12:
    case 11:
    case 10:
      if (1000 <= number) {
        *power = 1000;
        *exponent = 3;
        break;
      }
      [[fallthrough]];
    case 9:
    case 8:
    case 7:
      if (100 <= number) {
        *power = 100;
        *exponent = 2;
        break;
      }
      [[fallthrough]];
    case 6:
    case 5:
    case 4:
      if (10 <= number) {
        *power = 10;
        *exponent = 1;
        break;
      }
      [[fallthrough]];
    case 3:
    case 2:
    case 1:
      if (1 <= number) {
        *power = 1;
        *exponent = 0;
        break;
      }
      [[fallthrough]];
    case 0:
      *power = 0;
      *exponent = -1;
      break;
    default:
      // Following assignments are here to silence compiler warnings.
      *power = 0;
      *exponent = 0;
      UNREACHABLE();
  }
}

// Generates the digits of input number w.
// w is a floating-point number (DiyFp), consisting of a significand and an
// exponent. Its exponent is bounded by kMinimalTargetExponent and
// kMaximalTargetExponent.
//       Hence -60 <= w.e() <= -32.
//
// Returns false if it fails, in which case the generated digits in the buffer
// should not be used.
// Preconditions:
//  * low, w and high are correct up to 1 ulp (unit in the last place). That
//    is, their error must be less than a unit of their last digits.
//  * low.e() == w.e() == high.e()
//  * low < w < high, and taking into account their error: low~ <= high~
//  * kMinimalTargetExponent <= w.e() <= kMaximalTargetExponent
// Postconditions: returns false if procedure fails.
//   otherwise:
//     * buffer is not null-terminated, but len contains the number of digits.
//     * buffer contains the shortest possible decimal digit-sequence
//       such that LOW < buffer * 10^kappa < HIGH, where LOW and HIGH are the
//       correct values of low and high (without their error).
//     * if more than one decimal representation gives the minimal number of
//       decimal digits then the one closest to W (where W is the correct value
//       of w) is chosen.
// Remark: this procedure takes into account the imprecision of its input
//   numbers. If the precision is not enough to guarantee all the postconditions
//   then false is returned. This usually happens rarely (~0.5%).
//
// Say, for the sake of example, that
//   w.e() == -48, and w.f() == 0x1234567890ABCDEF
// w's value can be computed by w.f() * 2^w.e()
// We can obtain w's integral digits by simply shifting w.f() by -w.e().
//  -> w's integral part is 0x1234
//  w's fractional part is therefore 0x567890ABCDEF.
// Printing w's integral part is easy (simply print 0x1234 in decimal).
// In order to print its fraction we repeatedly multiply the fraction by 10 and
// get each digit. Example the first digit after the point would be computed by
//   (0x567890ABCDEF * 10) >> 48. -> 3
// The whole thing becomes slightly more complicated because we want to stop
// once we have enough digits. That is, once the digits inside the buffer
// represent 'w' we can stop. Everything inside the interval low - high
// represents w. However we have to pay attention to low, high and w's
// imprecision.
static bool DigitGen(DiyFp low, DiyFp w, DiyFp high, char** outptr,
                     int* kappa) {
  DCHECK(low.e() == w.e() && w.e() == high.e());
  DCHECK(low.f() + 1 <= high.f() - 1);
  DCHECK(kMinimalTargetExponent <= w.e() && w.e() <= kMaximalTargetExponent);
  // low, w and high are imprecise, but by less than one ulp (unit in the last
  // place).
  // If we remove (resp. add) 1 ulp from low (resp. high) we are certain that
  // the new numbers are outside of the interval we want the final
  // representation to lie in.
  // Inversely adding (resp. removing) 1 ulp from low (resp. high) would yield
  // numbers that are certain to lie in the interval. We will use this fact
  // later on.
  // We will now start by generating the digits within the uncertain
  // interval. Later we will weed out representations that lie outside the safe
  // interval and thus _might_ lie outside the correct interval.
  uint64_t unit = 1;
  DiyFp too_low = DiyFp(low.f() - unit, low.e());
  DiyFp too_high = DiyFp(high.f() + unit, high.e());
  // too_low and too_high are guaranteed to lie outside the interval we want the
  // generated number in.
  DiyFp unsafe_interval = DiyFp::Minus(too_high, too_low);
  // We now cut the input number into two parts: the integral digits and the
  // fractionals. We will not write any decimal separator though, but adapt
  // kappa instead.
  // Reminder: we are currently computing the digits (stored inside the buffer)
  // such that:   too_low < buffer * 10^kappa < too_high
  // We use too_high for the digit_generation and stop as soon as possible.
  // If we stop early we effectively round down.
  DiyFp one = DiyFp(static_cast<uint64_t>(1) << -w.e(), w.e());
  // Division by one is a shift.
  uint32_t integrals = static_cast<uint32_t>(too_high.f() >> -one.e());
  // Modulo by one is an and.
  uint64_t fractionals = too_high.f() & (one.f() - 1);
  uint32_t divisor;
  unsigned divisor_exponent;
  BiggestPowerTen(integrals, DiyFp::kSignificandSize - (-one.e()), &divisor,
                  &divisor_exponent);
  *kappa = divisor_exponent + 1;
  // Loop invariant: buffer = too_high / 10^kappa  (integer division)
  // The invariant holds for the first iteration: kappa has been initialized
  // with the divisor exponent + 1. And the divisor is the biggest power of ten
  // that is smaller than integrals.
  while (*kappa > 0) {
    uint32_t digit = fast_divmod(&integrals, divisor, div[divisor_exponent]);
    **outptr = '0' + digit;
    (*outptr)++;
    (*kappa)--;
    // Note that kappa now equals the exponent of the divisor and that the
    // invariant thus holds again.
    uint64_t rest =
        (static_cast<uint64_t>(integrals) << -one.e()) + fractionals;
    // Invariant: too_high = buffer * 10^kappa + DiyFp(rest, one.e())
    // Reminder: unsafe_interval.e() == one.e()
    if (rest < unsafe_interval.f()) {
      // Rounding down (by not emitting the remaining digits) yields a number
      // that lies within the unsafe interval.
      return RoundWeed(*outptr - 1, DiyFp::Minus(too_high, w).f(),
                       unsafe_interval.f(), rest,
                       static_cast<uint64_t>(divisor) << -one.e(), unit);
    }
    if (*kappa <= 0) {
      // Don't bother doing the division below. (The compiler ought to
      // figure this out itself, but it doesn't.)
      break;
    }
    divisor /= 10;
    --divisor_exponent;
  }

  // The integrals have been generated. We are at the point of the decimal
  // separator. In the following loop we simply multiply the remaining digits by
  // 10 and divide by one. We just need to pay attention to multiply associated
  // data (like the interval or 'unit'), too.
  // Note that the multiplication by 10 does not overflow, because w.e >= -60
  // and thus one.e >= -60.
  DCHECK_GE(one.e(), -60);
  DCHECK(fractionals < one.f());
  DCHECK(0xFFFF'FFFF'FFFF'FFFF / 10 >= one.f());
  while (true) {
    fractionals *= 10;
    unit *= 10;
    unsafe_interval.set_f(unsafe_interval.f() * 10);
    // Integer division by one.
    int digit = static_cast<int>(fractionals >> -one.e());
    **outptr = '0' + digit;
    (*outptr)++;
    fractionals &= one.f() - 1;  // Modulo by one.
    (*kappa)--;
    if (fractionals < unsafe_interval.f()) {
      return RoundWeed(*outptr - 1, DiyFp::Minus(too_high, w).f() * unit,
                       unsafe_interval.f(), fractionals, one.f(), unit);
    }
  }
}

// Generates (at most) requested_digits of input number w.
// w is a floating-point number (DiyFp), consisting of a significand and an
// exponent. Its exponent is bounded by kMinimalTargetExponent and
// kMaximalTargetExponent.
//       Hence -60 <= w.e() <= -32.
//
// Returns false if it fails, in which case the generated digits in the buffer
// should not be used.
// Preconditions:
//  * w is correct up to 1 ulp (unit in the last place). That
//    is, its error must be strictly less than a unit of its last digit.
//  * kMinimalTargetExponent <= w.e() <= kMaximalTargetExponent
//
// Postconditions: returns false if procedure fails.
//   otherwise:
//     * buffer is not null-terminated, but length contains the number of
//       digits.
//     * the representation in buffer is the most precise representation of
//       requested_digits digits.
//     * buffer contains at most requested_digits digits of w. If there are less
//       than requested_digits digits then some trailing '0's have been removed.
//     * kappa is such that
//            w = buffer * 10^kappa + eps with |eps| < 10^kappa / 2.
//
// Remark: This procedure takes into account the imprecision of its input
//   numbers. If the precision is not enough to guarantee all the postconditions
//   then false is returned. This usually happens rarely, but the failure-rate
//   increases with higher requested_digits.
static bool DigitGenCounted(DiyFp w, int requested_digits, Vector<char> buffer,
                            int* length, int* kappa) {
  DCHECK(kMinimalTargetExponent <= w.e() && w.e() <= kMaximalTargetExponent);
  DCHECK_GE(kMinimalTargetExponent, -60);
  DCHECK_LE(kMaximalTargetExponent, -32);
  // w is assumed to have an error less than 1 unit. Whenever w is scaled we
  // also scale its error.
  uint64_t w_error = 1;
  // We cut the input number into two parts: the integral digits and the
  // fractional digits. We don't emit any decimal separator, but adapt kappa
  // instead. Example: instead of writing "1.2" we put "12" into the buffer and
  // increase kappa by 1.
  DiyFp one = DiyFp(static_cast<uint64_t>(1) << -w.e(), w.e());
  // Division by one is a shift.
  uint32_t integrals = static_cast<uint32_t>(w.f() >> -one.e());
  // Modulo by one is an and.
  uint64_t fractionals = w.f() & (one.f() - 1);
  uint32_t divisor;
  unsigned divisor_exponent;
  BiggestPowerTen(integrals, DiyFp::kSignificandSize - (-one.e()), &divisor,
                  &divisor_exponent);
  *kappa = divisor_exponent + 1;
  *length = 0;

  // Loop invariant: buffer = w / 10^kappa  (integer division)
  // The invariant holds for the first iteration: kappa has been initialized
  // with the divisor exponent + 1. And the divisor is the biggest power of ten
  // that is smaller than 'integrals'.
  while (*kappa > 0) {
    uint32_t digit = fast_divmod(&integrals, divisor, div[divisor_exponent]);
    buffer[*length] = '0' + digit;
    (*length)++;
    requested_digits--;
    (*kappa)--;
    // Note that kappa now equals the exponent of the divisor and that the
    // invariant thus holds again.
    if (requested_digits == 0) break;
    divisor /= 10;
    --divisor_exponent;
  }

  if (requested_digits == 0) {
    uint64_t rest =
        (static_cast<uint64_t>(integrals) << -one.e()) + fractionals;
    return RoundWeedCounted(buffer, *length, rest,
                            static_cast<uint64_t>(divisor) << -one.e(), w_error,
                            kappa);
  }

  // The integrals have been generated. We are at the point of the decimal
  // separator. In the following loop we simply multiply the remaining digits by
  // 10 and divide by one. We just need to pay attention to multiply associated
  // data (the 'unit'), too.
  // Note that the multiplication by 10 does not overflow, because w.e >= -60
  // and thus one.e >= -60.
  DCHECK_GE(one.e(), -60);
  DCHECK(fractionals < one.f());
  DCHECK(0xFFFF'FFFF'FFFF'FFFF / 10 >= one.f());
  while (requested_digits > 0 && fractionals > w_error) {
    fractionals *= 10;
    w_error *= 10;
    // Integer division by one.
    int digit = static_cast<int>(fractionals >> -one.e());
    buffer[*length] = '0' + digit;
    (*length)++;
    requested_digits--;
    fractionals &= one.f() - 1;  // Modulo by one.
    (*kappa)--;
  }
  if (requested_digits != 0) return false;
  return RoundWeedCounted(buffer, *length, fractionals, one.f(), w_error,
                          kappa);
}

// Provides a decimal representation of v.
// Returns true if it succeeds, otherwise the result cannot be trusted.
// There will be *length digits inside the buffer (not null-terminated).
// If the function returns true then
//        v == (double) (buffer * 10^decimal_exponent).
// The digits in the buffer are the shortest representation possible: no
// 0.09999999999999999 instead of 0.1. The shorter representation will even be
// chosen even if the longer one would be closer to v.
// The last digit will be closest to the actual v. That is, even if several
// digits might correctly yield 'v' when read again, the closest will be
// computed.
static bool Grisu3(double v, char** outptr, int* decimal_exponent) {
  DiyFp w = Double(v).AsNormalizedDiyFp();
  // boundary_minus and boundary_plus are the boundaries between v and its
  // closest floating-point neighbors. Any number strictly between
  // boundary_minus and boundary_plus will round to v when convert to a double.
  // Grisu3 will never output representations that lie exactly on a boundary.
  DiyFp boundary_minus, boundary_plus;
  Double(v).NormalizedBoundaries(&boundary_minus, &boundary_plus);
  DCHECK(boundary_plus.e() == w.e());
  DiyFp ten_mk;  // Cached power of ten: 10^-k
  int mk;        // -k
  int ten_mk_minimal_binary_exponent =
      kMinimalTargetExponent - (w.e() + DiyFp::kSignificandSize);
  int ten_mk_maximal_binary_exponent =
      kMaximalTargetExponent - (w.e() + DiyFp::kSignificandSize);
  PowersOfTenCache::GetCachedPowerForBinaryExponentRange(
      ten_mk_minimal_binary_exponent, ten_mk_maximal_binary_exponent, &ten_mk,
      &mk);
  DCHECK(
      (kMinimalTargetExponent <=
       w.e() + ten_mk.e() + DiyFp::kSignificandSize) &&
      (kMaximalTargetExponent >= w.e() + ten_mk.e() + DiyFp::kSignificandSize));
  // Note that ten_mk is only an approximation of 10^-k. A DiyFp only contains a
  // 64 bit significand and ten_mk is thus only precise up to 64 bits.

  // The DiyFp::Times procedure rounds its result, and ten_mk is approximated
  // too. The variable scaled_w (as well as scaled_boundary_minus/plus) are now
  // off by a small amount.
  // In fact: scaled_w - w*10^k < 1ulp (unit in the last place) of scaled_w.
  // In other words: let f = scaled_w.f() and e = scaled_w.e(), then
  //           (f-1) * 2^e < w*10^k < (f+1) * 2^e
  DiyFp scaled_w = DiyFp::Times(w, ten_mk);
  DCHECK(scaled_w.e() ==
         boundary_plus.e() + ten_mk.e() + DiyFp::kSignificandSize);
  // In theory it would be possible to avoid some recomputations by computing
  // the difference between w and boundary_minus/plus (a power of 2) and to
  // compute scaled_boundary_minus/plus by subtracting/adding from
  // scaled_w. However the code becomes much less readable and the speed
  // enhancements are not terriffic.
  DiyFp scaled_boundary_minus = DiyFp::Times(boundary_minus, ten_mk);
  DiyFp scaled_boundary_plus = DiyFp::Times(boundary_plus, ten_mk);

  // DigitGen will generate the digits of scaled_w. Therefore we have
  // v == (double) (scaled_w * 10^-mk).
  // Set decimal_exponent == -mk and pass it to DigitGen. If scaled_w is not an
  // integer than it will be updated. For instance if scaled_w == 1.23 then
  // the buffer will be filled with "123" und the decimal_exponent will be
  // decreased by 2.
  int kappa;
  bool result = DigitGen(scaled_boundary_minus, scaled_w, scaled_boundary_plus,
                         outptr, &kappa);
  *decimal_exponent = -mk + kappa;
  return result;
}

// The "counted" version of grisu3 (see above) only generates requested_digits
// number of digits. This version does not generate the shortest representation,
// and with enough requested digits 0.1 will at some point print as 0.9999999...
// Grisu3 is too imprecise for real halfway cases (1.5 will not work) and
// therefore the rounding strategy for halfway cases is irrelevant.
static bool Grisu3Counted(double v, int requested_digits, Vector<char> buffer,
                          int* length, int* decimal_exponent) {
  DiyFp w = Double(v).AsNormalizedDiyFp();
  DiyFp ten_mk;  // Cached power of ten: 10^-k
  int mk;        // -k
  int ten_mk_minimal_binary_exponent =
      kMinimalTargetExponent - (w.e() + DiyFp::kSignificandSize);
  int ten_mk_maximal_binary_exponent =
      kMaximalTargetExponent - (w.e() + DiyFp::kSignificandSize);
  PowersOfTenCache::GetCachedPowerForBinaryExponentRange(
      ten_mk_minimal_binary_exponent, ten_mk_maximal_binary_exponent, &ten_mk,
      &mk);
  DCHECK(
      (kMinimalTargetExponent <=
       w.e() + ten_mk.e() + DiyFp::kSignificandSize) &&
      (kMaximalTargetExponent >= w.e() + ten_mk.e() + DiyFp::kSignificandSize));
  // Note that ten_mk is only an approximation of 10^-k. A DiyFp only contains a
  // 64 bit significand and ten_mk is thus only precise up to 64 bits.

  // The DiyFp::Times procedure rounds its result, and ten_mk is approximated
  // too. The variable scaled_w (as well as scaled_boundary_minus/plus) are now
  // off by a small amount.
  // In fact: scaled_w - w*10^k < 1ulp (unit in the last place) of scaled_w.
  // In other words: let f = scaled_w.f() and e = scaled_w.e(), then
  //           (f-1) * 2^e < w*10^k < (f+1) * 2^e
  DiyFp scaled_w = DiyFp::Times(w, ten_mk);

  // We now have (double) (scaled_w * 10^-mk).
  // DigitGen will generate the first requested_digits digits of scaled_w and
  // return together with a kappa such that scaled_w ~= buffer * 10^kappa. (It
  // will not always be exactly the same since DigitGenCounted only produces a
  // limited number of digits.)
  int kappa;
  bool result =
      DigitGenCounted(scaled_w, requested_digits, buffer, length, &kappa);
  *decimal_exponent = -mk + kappa;
  return result;
}

bool FastDtoa(double v, FastDtoaMode mode, int requested_digits,
              Vector<char> buffer, int* length, int* decimal_point) {
  DCHECK_GT(v, 0);
  DCHECK(!Double(v).IsSpecial());

  bool result = false;
  char* outptr = buffer.data();
  int decimal_exponent = 0;
  switch (mode) {
    case FAST_DTOA_SHORTEST:
      result = Grisu3(v, &outptr, &decimal_exponent);
      *length = static_cast<int>(outptr - buffer.data());
      break;
    case FAST_DTOA_PRECISION: {
      int local_length = 0;
      result = Grisu3Counted(v, requested_digits, buffer, &local_length,
                             &decimal_exponent);
      *length = local_length;
      break;
    }
    default:
      UNREACHABLE();
  }
  if (result) {
    *decimal_point = *length + decimal_exponent;
    buffer[*length] = '\0';
  }
  return result;
}

}  // namespace base
}  // namespace v8
```