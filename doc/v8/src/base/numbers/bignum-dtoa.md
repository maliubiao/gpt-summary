Response: Let's break down the thought process for analyzing this C++ code and explaining its JavaScript relevance.

1. **Understand the Goal:** The request asks for the function of the C++ code and its connection to JavaScript. The filename `bignum-dtoa.cc` and the inclusion of headers like `cmath`, `src/base/logging.h`, `src/base/numbers/bignum.h`, and `src/base/numbers/double.h` immediately suggest this code is involved in converting floating-point numbers (`double`) to their string representations, potentially handling large numbers (`Bignum`). The "DTOA" in the filename likely stands for "Double To ASCII".

2. **High-Level Structure Analysis:** Quickly scan the included headers and the namespace declarations (`v8::base`). This confirms it's part of the V8 JavaScript engine's base library, dealing with number conversions. The presence of `DCHECK` statements indicates internal assertions for debugging and validating assumptions.

3. **Function Identification and Initial Interpretation:** Go through the function declarations and definitions. Note the core function `BignumDtoa` and the helper functions like `NormalizedExponent`, `EstimatePower`, `InitialScaledStartValues`, `FixupMultiply10`, `GenerateShortestDigits`, `BignumToFixed`, and `GenerateCountedDigits`. Try to infer their purpose from their names.

    * `NormalizedExponent`: Likely normalizes the representation of the double by shifting the significand.
    * `EstimatePower`: Seems to estimate the order of magnitude (power of 10) of the number.
    * `InitialScaledStartValues`:  Appears to set up the initial big-integer representation of the number.
    * `FixupMultiply10`: Might adjust the representation to ensure the significant part is within a specific range (1-10).
    * `GenerateShortestDigits`: This strongly suggests generating the shortest possible string representation.
    * `BignumToFixed`:  Looks like it's responsible for generating a fixed number of digits after the decimal point.
    * `GenerateCountedDigits`:  Likely generates a specific number of digits.

4. **Focus on the Main Function:**  `BignumDtoa` is the entry point. Analyze its arguments (`double v`, `BignumDtoaMode mode`, `int requested_digits`, `Vector<char> buffer`, `int* length`, `int* decimal_point`).

    * `v`: The double to convert.
    * `mode`:  This is key. The name "BIGNUM_DTOA_SHORTEST", "BIGNUM_DTOA_FIXED", "BIGNUM_DTOA_PRECISION" are strong hints about the different formatting modes.
    * `requested_digits`:  Clearly used for the `FIXED` and `PRECISION` modes.
    * `buffer`: The output buffer for the string.
    * `length`, `decimal_point`:  Pointers to store the length of the string and the position of the decimal point.

5. **Trace the Execution Flow:** Follow the steps within `BignumDtoa`. Notice how it calls the helper functions based on the `mode`. This confirms the initial guess about the different formatting options.

6. **Deep Dive into Key Helper Functions:**  Examine the logic of the most important helper functions. Pay attention to how they manipulate the `Bignum` objects.

    * `GenerateShortestDigits`:  The `while (true)` loop and the conditions `in_delta_room_minus` and `in_delta_room_plus` are crucial. They indicate the algorithm is generating digits until it finds the shortest representation that uniquely identifies the double. The handling of rounding (`compare < 0`, `compare > 0`, `compare == 0`) is also significant.
    * `BignumToFixed` and `GenerateCountedDigits`: These are more straightforward, focusing on generating a specific number of digits.

7. **Connect to JavaScript:** Now, think about how these C++ functions relate to JavaScript's number-to-string conversions. JavaScript's `Number.prototype.toString()`, `Number.prototype.toFixed()`, and `Number.prototype.toPrecision()` directly correspond to the three modes in the C++ code:

    * `BIGNUM_DTOA_SHORTEST` maps to `toString()` (or implicit conversion).
    * `BIGNUM_DTOA_FIXED` maps to `toFixed()`.
    * `BIGNUM_DTOA_PRECISION` maps to `toPrecision()`.

8. **Illustrate with JavaScript Examples:** Create simple JavaScript code snippets demonstrating the behavior of `toString()`, `toFixed()`, and `toPrecision()` and relate them back to the C++ code's functionality. Focus on showing how the different modes produce different string representations.

9. **Refine and Summarize:** Organize the findings into a clear and concise explanation. Start with the overall function of the C++ code. Then, explain each mode and its corresponding JavaScript method. Use the JavaScript examples to reinforce the connection. Highlight any important aspects, such as the use of `Bignum` for high precision.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code is only for very large or very small numbers.
* **Correction:** While `Bignum` handles large numbers, the code is used for *all* double-to-string conversions in V8, as the shortest representation logic needs to be precise.
* **Initial thought:** The `estimated_power` is just a rough guess.
* **Refinement:** The code carefully handles potential off-by-one errors in `estimated_power` using the `FixupMultiply10` function.
* **Initial thought:** The boundary deltas are for some edge cases.
* **Refinement:** The boundary deltas are crucial for the "shortest representation" algorithm to determine when to stop generating digits and whether to round up or down.

By following these steps, iterating through the code, and connecting it to familiar JavaScript concepts, a comprehensive and accurate explanation can be constructed.
这个C++源代码文件 `bignum-dtoa.cc` 的功能是 **将双精度浮点数 (double) 转换为字符串表示**，并提供了多种转换模式，尤其关注于生成 **最短且精确** 的字符串表示。由于它位于 V8 引擎的源代码中，因此直接关联着 **JavaScript 中数字到字符串的转换**。

**功能归纳:**

1. **高精度处理 (Bignum):**  代码使用了 `Bignum` 类来处理可能非常大或非常小的数字，确保在转换过程中不会丢失精度。这对于生成精确的字符串表示至关重要。

2. **多种转换模式:**  `BignumDtoa` 函数接受一个 `BignumDtoaMode` 参数，支持以下转换模式：
   - **`BIGNUM_DTOA_SHORTEST` (最短模式):**  生成能够**无歧义地**表示原始浮点数的**最短**字符串。这意味着生成的字符串转换回浮点数后，会得到原始值。这是 JavaScript 中默认的数字到字符串转换的行为。
   - **`BIGNUM_DTOA_FIXED` (定点模式):** 生成小数点后指定位数的字符串表示，类似于 JavaScript 的 `toFixed()` 方法。
   - **`BIGNUM_DTOA_PRECISION` (精度模式):** 生成总共指定位数的字符串表示，类似于 JavaScript 的 `toPrecision()` 方法。

3. **处理边界情况:** 代码中包含对浮点数边界情况的处理，例如确定何时可以停止生成数字以获得最短表示，以及如何进行四舍五入以保证精度。

4. **效率考量:** 代码中包含一些优化，例如在 `GenerateShortestDigits` 中如果上下界差值相等则复用 `Bignum` 对象，以提高性能。

**与 JavaScript 的关系及示例:**

`bignum-dtoa.cc` 中的代码是 V8 引擎实现 JavaScript 中数字到字符串转换的核心部分。当你在 JavaScript 中执行以下操作时，V8 引擎最终会调用类似 `BignumDtoa` 的函数来完成转换：

**JavaScript 示例:**

```javascript
const number = 123.456;

// 默认转换 (对应 BIGNUM_DTOA_SHORTEST)
const defaultString = number.toString();
console.log(defaultString); // 输出 "123.456"

const anotherNumber = 0.1 + 0.2;
console.log(anotherNumber.toString()); // 输出 "0.30000000000000004" (最短但精确的表示)

// toFixed() (对应 BIGNUM_DTOA_FIXED)
const fixedString = number.toFixed(2);
console.log(fixedString); // 输出 "123.46"

// toPrecision() (对应 BIGNUM_DTOA_PRECISION)
const precisionString = number.toPrecision(4);
console.log(precisionString); // 输出 "123.5"

const smallNumber = 0.00000123;
console.log(smallNumber.toString()); // 输出 "1.23e-6" (最短且易读的表示)
```

**解释:**

- 当你直接使用 `toString()` 或进行隐式类型转换时，JavaScript 会尝试生成能够精确表示该数字的最短字符串。这与 `BIGNUM_DTOA_SHORTEST` 模式的目标一致。例如，`0.1 + 0.2` 在浮点数中存在精度问题，`toString()` 会尽可能准确地反映这个结果。
- `toFixed()` 方法允许你指定小数点后的位数，这对应于 `BIGNUM_DTOA_FIXED` 模式。
- `toPrecision()` 方法允许你指定总的有效数字位数，这对应于 `BIGNUM_DTOA_PRECISION` 模式。

**核心机制:**

`BignumDtoa` 的工作流程大致如下：

1. **提取浮点数的组成部分:** 从 `double` 值中提取符号位、尾数 (significand) 和指数 (exponent)。
2. **估计数量级:** 使用 `EstimatePower` 估计数字的数量级 (10 的幂)。
3. **初始化大数:** 使用 `InitialScaledStartValues` 将浮点数表示为一个大整数的分子和分母的比例，以及与相邻浮点数的差值（用于最短表示模式）。
4. **调整比例:**  `FixupMultiply10` 调整分子和分母，使它们的比值落在 1 到 10 之间，并计算出正确的十进制小数点位置。
5. **生成数字:**
   - **最短模式:** `GenerateShortestDigits` 从左到右生成数字，直到生成的数字能够唯一确定原始浮点数。它会根据与上下界的比较来决定何时停止并进行四舍五入。
   - **定点模式:** `BignumToFixed` 生成指定小数点后位数的数字。
   - **精度模式:** `GenerateCountedDigits` 生成指定总位数的数字。
6. **返回字符串:** 将生成的数字存储在提供的缓冲区中，并返回字符串的长度和十进制小数点位置。

**总结:**

`v8/src/base/numbers/bignum-dtoa.cc` 是 V8 引擎中负责将双精度浮点数转换为字符串的关键组件。它提供了多种转换模式，并使用高精度的 `Bignum` 类来确保转换的准确性，尤其是在生成能够无歧义地表示浮点数的最短字符串方面。这直接影响了 JavaScript 中 `Number.prototype.toString()`, `Number.prototype.toFixed()`, 和 `Number.prototype.toPrecision()` 等方法的行为。

### 提示词
```
这是目录为v8/src/base/numbers/bignum-dtoa.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/bignum-dtoa.h"

#include <cmath>

#include "src/base/logging.h"
#include "src/base/numbers/bignum.h"
#include "src/base/numbers/double.h"

namespace v8 {
namespace base {

static int NormalizedExponent(uint64_t significand, int exponent) {
  DCHECK_NE(significand, 0);
  while ((significand & Double::kHiddenBit) == 0) {
    significand = significand << 1;
    exponent = exponent - 1;
  }
  return exponent;
}

// Forward declarations:
// Returns an estimation of k such that 10^(k-1) <= v < 10^k.
static int EstimatePower(int exponent);
// Computes v / 10^estimated_power exactly, as a ratio of two bignums, numerator
// and denominator.
static void InitialScaledStartValues(double v, int estimated_power,
                                     bool need_boundary_deltas,
                                     Bignum* numerator, Bignum* denominator,
                                     Bignum* delta_minus, Bignum* delta_plus);
// Multiplies numerator/denominator so that its values lies in the range 1-10.
// Returns decimal_point s.t.
//  v = numerator'/denominator' * 10^(decimal_point-1)
//     where numerator' and denominator' are the values of numerator and
//     denominator after the call to this function.
static void FixupMultiply10(int estimated_power, bool is_even,
                            int* decimal_point, Bignum* numerator,
                            Bignum* denominator, Bignum* delta_minus,
                            Bignum* delta_plus);
// Generates digits from the left to the right and stops when the generated
// digits yield the shortest decimal representation of v.
static void GenerateShortestDigits(Bignum* numerator, Bignum* denominator,
                                   Bignum* delta_minus, Bignum* delta_plus,
                                   bool is_even, Vector<char> buffer,
                                   int* length);
// Generates 'requested_digits' after the decimal point.
static void BignumToFixed(int requested_digits, int* decimal_point,
                          Bignum* numerator, Bignum* denominator,
                          Vector<char>(buffer), int* length);
// Generates 'count' digits of numerator/denominator.
// Once 'count' digits have been produced rounds the result depending on the
// remainder (remainders of exactly .5 round upwards). Might update the
// decimal_point when rounding up (for example for 0.9999).
static void GenerateCountedDigits(int count, int* decimal_point,
                                  Bignum* numerator, Bignum* denominator,
                                  Vector<char>(buffer), int* length);

void BignumDtoa(double v, BignumDtoaMode mode, int requested_digits,
                Vector<char> buffer, int* length, int* decimal_point) {
  DCHECK_GT(v, 0);
  DCHECK(!Double(v).IsSpecial());
  uint64_t significand = Double(v).Significand();
  bool is_even = (significand & 1) == 0;
  int exponent = Double(v).Exponent();
  int normalized_exponent = NormalizedExponent(significand, exponent);
  // estimated_power might be too low by 1.
  int estimated_power = EstimatePower(normalized_exponent);

  // Shortcut for Fixed.
  // The requested digits correspond to the digits after the point. If the
  // number is much too small, then there is no need in trying to get any
  // digits.
  if (mode == BIGNUM_DTOA_FIXED && -estimated_power - 1 > requested_digits) {
    buffer[0] = '\0';
    *length = 0;
    // Set decimal-point to -requested_digits. This is what Gay does.
    // Note that it should not have any effect anyways since the string is
    // empty.
    *decimal_point = -requested_digits;
    return;
  }

  Bignum numerator;
  Bignum denominator;
  Bignum delta_minus;
  Bignum delta_plus;
  // Make sure the bignum can grow large enough. The smallest double equals
  // 4e-324. In this case the denominator needs fewer than 324*4 binary digits.
  // The maximum double is 1.7976931348623157e308 which needs fewer than
  // 308*4 binary digits.
  DCHECK_GE(Bignum::kMaxSignificantBits, 324 * 4);
  bool need_boundary_deltas = (mode == BIGNUM_DTOA_SHORTEST);
  InitialScaledStartValues(v, estimated_power, need_boundary_deltas, &numerator,
                           &denominator, &delta_minus, &delta_plus);
  // We now have v = (numerator / denominator) * 10^estimated_power.
  FixupMultiply10(estimated_power, is_even, decimal_point, &numerator,
                  &denominator, &delta_minus, &delta_plus);
  // We now have v = (numerator / denominator) * 10^(decimal_point-1), and
  //  1 <= (numerator + delta_plus) / denominator < 10
  switch (mode) {
    case BIGNUM_DTOA_SHORTEST:
      GenerateShortestDigits(&numerator, &denominator, &delta_minus,
                             &delta_plus, is_even, buffer, length);
      break;
    case BIGNUM_DTOA_FIXED:
      BignumToFixed(requested_digits, decimal_point, &numerator, &denominator,
                    buffer, length);
      break;
    case BIGNUM_DTOA_PRECISION:
      GenerateCountedDigits(requested_digits, decimal_point, &numerator,
                            &denominator, buffer, length);
      break;
    default:
      UNREACHABLE();
  }
  buffer[*length] = '\0';
}

// The procedure starts generating digits from the left to the right and stops
// when the generated digits yield the shortest decimal representation of v. A
// decimal representation of v is a number lying closer to v than to any other
// double, so it converts to v when read.
//
// This is true if d, the decimal representation, is between m- and m+, the
// upper and lower boundaries. d must be strictly between them if !is_even.
//           m- := (numerator - delta_minus) / denominator
//           m+ := (numerator + delta_plus) / denominator
//
// Precondition: 0 <= (numerator+delta_plus) / denominator < 10.
//   If 1 <= (numerator+delta_plus) / denominator < 10 then no leading 0 digit
//   will be produced. This should be the standard precondition.
static void GenerateShortestDigits(Bignum* numerator, Bignum* denominator,
                                   Bignum* delta_minus, Bignum* delta_plus,
                                   bool is_even, Vector<char> buffer,
                                   int* length) {
  // Small optimization: if delta_minus and delta_plus are the same just reuse
  // one of the two bignums.
  if (Bignum::Equal(*delta_minus, *delta_plus)) {
    delta_plus = delta_minus;
  }
  *length = 0;
  while (true) {
    uint16_t digit;
    digit = numerator->DivideModuloIntBignum(*denominator);
    DCHECK_LE(digit, 9);  // digit is a uint16_t and therefore always positive.
    // digit = numerator / denominator (integer division).
    // numerator = numerator % denominator.
    buffer[(*length)++] = digit + '0';

    // Can we stop already?
    // If the remainder of the division is less than the distance to the lower
    // boundary we can stop. In this case we simply round down (discarding the
    // remainder).
    // Similarly we test if we can round up (using the upper boundary).
    bool in_delta_room_minus;
    bool in_delta_room_plus;
    if (is_even) {
      in_delta_room_minus = Bignum::LessEqual(*numerator, *delta_minus);
    } else {
      in_delta_room_minus = Bignum::Less(*numerator, *delta_minus);
    }
    if (is_even) {
      in_delta_room_plus =
          Bignum::PlusCompare(*numerator, *delta_plus, *denominator) >= 0;
    } else {
      in_delta_room_plus =
          Bignum::PlusCompare(*numerator, *delta_plus, *denominator) > 0;
    }
    if (!in_delta_room_minus && !in_delta_room_plus) {
      // Prepare for next iteration.
      numerator->Times10();
      delta_minus->Times10();
      // We optimized delta_plus to be equal to delta_minus (if they share the
      // same value). So don't multiply delta_plus if they point to the same
      // object.
      if (delta_minus != delta_plus) {
        delta_plus->Times10();
      }
    } else if (in_delta_room_minus && in_delta_room_plus) {
      // Let's see if 2*numerator < denominator.
      // If yes, then the next digit would be < 5 and we can round down.
      int compare = Bignum::PlusCompare(*numerator, *numerator, *denominator);
      if (compare < 0) {
        // Remaining digits are less than .5. -> Round down (== do nothing).
      } else if (compare > 0) {
        // Remaining digits are more than .5 of denominator. -> Round up.
        // Note that the last digit could not be a '9' as otherwise the whole
        // loop would have stopped earlier.
        // We still have an assert here in case the preconditions were not
        // satisfied.
        DCHECK_NE(buffer[(*length) - 1], '9');
        buffer[(*length) - 1]++;
      } else {
        // Halfway case.
        // TODO(floitsch): need a way to solve half-way cases.
        //   For now let's round towards even (since this is what Gay seems to
        //   do).

        if ((buffer[(*length) - 1] - '0') % 2 == 0) {
          // Round down => Do nothing.
        } else {
          DCHECK_NE(buffer[(*length) - 1], '9');
          buffer[(*length) - 1]++;
        }
      }
      return;
    } else if (in_delta_room_minus) {
      // Round down (== do nothing).
      return;
    } else {  // in_delta_room_plus
      // Round up.
      // Note again that the last digit could not be '9' since this would have
      // stopped the loop earlier.
      // We still have an DCHECK here, in case the preconditions were not
      // satisfied.
      DCHECK_NE(buffer[(*length) - 1], '9');
      buffer[(*length) - 1]++;
      return;
    }
  }
}

// Let v = numerator / denominator < 10.
// Then we generate 'count' digits of d = x.xxxxx... (without the decimal point)
// from left to right. Once 'count' digits have been produced we decide wether
// to round up or down. Remainders of exactly .5 round upwards. Numbers such
// as 9.999999 propagate a carry all the way, and change the
// exponent (decimal_point), when rounding upwards.
static void GenerateCountedDigits(int count, int* decimal_point,
                                  Bignum* numerator, Bignum* denominator,
                                  Vector<char>(buffer), int* length) {
  DCHECK_GE(count, 0);
  for (int i = 0; i < count - 1; ++i) {
    uint16_t digit;
    digit = numerator->DivideModuloIntBignum(*denominator);
    DCHECK_LE(digit, 9);  // digit is a uint16_t and therefore always positive.
    // digit = numerator / denominator (integer division).
    // numerator = numerator % denominator.
    buffer[i] = digit + '0';
    // Prepare for next iteration.
    numerator->Times10();
  }
  // Generate the last digit.
  uint16_t digit;
  digit = numerator->DivideModuloIntBignum(*denominator);
  if (Bignum::PlusCompare(*numerator, *numerator, *denominator) >= 0) {
    digit++;
  }
  buffer[count - 1] = digit + '0';
  // Correct bad digits (in case we had a sequence of '9's). Propagate the
  // carry until we hat a non-'9' or til we reach the first digit.
  for (int i = count - 1; i > 0; --i) {
    if (buffer[i] != '0' + 10) break;
    buffer[i] = '0';
    buffer[i - 1]++;
  }
  if (buffer[0] == '0' + 10) {
    // Propagate a carry past the top place.
    buffer[0] = '1';
    (*decimal_point)++;
  }
  *length = count;
}

// Generates 'requested_digits' after the decimal point. It might omit
// trailing '0's. If the input number is too small then no digits at all are
// generated (ex.: 2 fixed digits for 0.00001).
//
// Input verifies:  1 <= (numerator + delta) / denominator < 10.
static void BignumToFixed(int requested_digits, int* decimal_point,
                          Bignum* numerator, Bignum* denominator,
                          Vector<char>(buffer), int* length) {
  // Note that we have to look at more than just the requested_digits, since
  // a number could be rounded up. Example: v=0.5 with requested_digits=0.
  // Even though the power of v equals 0 we can't just stop here.
  if (-(*decimal_point) > requested_digits) {
    // The number is definitively too small.
    // Ex: 0.001 with requested_digits == 1.
    // Set decimal-point to -requested_digits. This is what Gay does.
    // Note that it should not have any effect anyways since the string is
    // empty.
    *decimal_point = -requested_digits;
    *length = 0;
    return;
  } else if (-(*decimal_point) == requested_digits) {
    // We only need to verify if the number rounds down or up.
    // Ex: 0.04 and 0.06 with requested_digits == 1.
    DCHECK(*decimal_point == -requested_digits);
    // Initially the fraction lies in range (1, 10]. Multiply the denominator
    // by 10 so that we can compare more easily.
    denominator->Times10();
    if (Bignum::PlusCompare(*numerator, *numerator, *denominator) >= 0) {
      // If the fraction is >= 0.5 then we have to include the rounded
      // digit.
      buffer[0] = '1';
      *length = 1;
      (*decimal_point)++;
    } else {
      // Note that we caught most of similar cases earlier.
      *length = 0;
    }
    return;
  } else {
    // The requested digits correspond to the digits after the point.
    // The variable 'needed_digits' includes the digits before the point.
    int needed_digits = (*decimal_point) + requested_digits;
    GenerateCountedDigits(needed_digits, decimal_point, numerator, denominator,
                          buffer, length);
  }
}

// Returns an estimation of k such that 10^(k-1) <= v < 10^k where
// v = f * 2^exponent and 2^52 <= f < 2^53.
// v is hence a normalized double with the given exponent. The output is an
// approximation for the exponent of the decimal approimation .digits * 10^k.
//
// The result might undershoot by 1 in which case 10^k <= v < 10^k+1.
// Note: this property holds for v's upper boundary m+ too.
//    10^k <= m+ < 10^k+1.
//   (see explanation below).
//
// Examples:
//  EstimatePower(0)   => 16
//  EstimatePower(-52) => 0
//
// Note: e >= 0 => EstimatedPower(e) > 0. No similar claim can be made for e<0.
static int EstimatePower(int exponent) {
  // This function estimates log10 of v where v = f*2^e (with e == exponent).
  // Note that 10^floor(log10(v)) <= v, but v <= 10^ceil(log10(v)).
  // Note that f is bounded by its container size. Let p = 53 (the double's
  // significand size). Then 2^(p-1) <= f < 2^p.
  //
  // Given that log10(v) == log2(v)/log2(10) and e+(len(f)-1) is quite close
  // to log2(v) the function is simplified to (e+(len(f)-1)/log2(10)).
  // The computed number undershoots by less than 0.631 (when we compute log3
  // and not log10).
  //
  // Optimization: since we only need an approximated result this computation
  // can be performed on 64 bit integers. On x86/x64 architecture the speedup is
  // not really measurable, though.
  //
  // Since we want to avoid overshooting we decrement by 1e10 so that
  // floating-point imprecisions don't affect us.
  //
  // Explanation for v's boundary m+: the computation takes advantage of
  // the fact that 2^(p-1) <= f < 2^p. Boundaries still satisfy this requirement
  // (even for denormals where the delta can be much more important).

  const double k1Log10 = 0.30102999566398114;  // 1/lg(10)

  // For doubles len(f) == 53 (don't forget the hidden bit).
  const int kSignificandSize = 53;
  double estimate =
      std::ceil((exponent + kSignificandSize - 1) * k1Log10 - 1e-10);
  return static_cast<int>(estimate);
}

// See comments for InitialScaledStartValues.
static void InitialScaledStartValuesPositiveExponent(
    double v, int estimated_power, bool need_boundary_deltas, Bignum* numerator,
    Bignum* denominator, Bignum* delta_minus, Bignum* delta_plus) {
  // A positive exponent implies a positive power.
  DCHECK_GE(estimated_power, 0);
  // Since the estimated_power is positive we simply multiply the denominator
  // by 10^estimated_power.

  // numerator = v.
  numerator->AssignUInt64(Double(v).Significand());
  numerator->ShiftLeft(Double(v).Exponent());
  // denominator = 10^estimated_power.
  denominator->AssignPowerUInt16(10, estimated_power);

  if (need_boundary_deltas) {
    // Introduce a common denominator so that the deltas to the boundaries are
    // integers.
    denominator->ShiftLeft(1);
    numerator->ShiftLeft(1);
    // Let v = f * 2^e, then m+ - v = 1/2 * 2^e; With the common
    // denominator (of 2) delta_plus equals 2^e.
    delta_plus->AssignUInt16(1);
    delta_plus->ShiftLeft(Double(v).Exponent());
    // Same for delta_minus (with adjustments below if f == 2^p-1).
    delta_minus->AssignUInt16(1);
    delta_minus->ShiftLeft(Double(v).Exponent());

    // If the significand (without the hidden bit) is 0, then the lower
    // boundary is closer than just half a ulp (unit in the last place).
    // There is only one exception: if the next lower number is a denormal then
    // the distance is 1 ulp. This cannot be the case for exponent >= 0 (but we
    // have to test it in the other function where exponent < 0).
    uint64_t v_bits = Double(v).AsUint64();
    if ((v_bits & Double::kSignificandMask) == 0) {
      // The lower boundary is closer at half the distance of "normal" numbers.
      // Increase the common denominator and adapt all but the delta_minus.
      denominator->ShiftLeft(1);  // *2
      numerator->ShiftLeft(1);    // *2
      delta_plus->ShiftLeft(1);   // *2
    }
  }
}

// See comments for InitialScaledStartValues
static void InitialScaledStartValuesNegativeExponentPositivePower(
    double v, int estimated_power, bool need_boundary_deltas, Bignum* numerator,
    Bignum* denominator, Bignum* delta_minus, Bignum* delta_plus) {
  uint64_t significand = Double(v).Significand();
  int exponent = Double(v).Exponent();
  // v = f * 2^e with e < 0, and with estimated_power >= 0.
  // This means that e is close to 0 (have a look at how estimated_power is
  // computed).

  // numerator = significand
  //  since v = significand * 2^exponent this is equivalent to
  //  numerator = v * / 2^-exponent
  numerator->AssignUInt64(significand);
  // denominator = 10^estimated_power * 2^-exponent (with exponent < 0)
  denominator->AssignPowerUInt16(10, estimated_power);
  denominator->ShiftLeft(-exponent);

  if (need_boundary_deltas) {
    // Introduce a common denominator so that the deltas to the boundaries are
    // integers.
    denominator->ShiftLeft(1);
    numerator->ShiftLeft(1);
    // Let v = f * 2^e, then m+ - v = 1/2 * 2^e; With the common
    // denominator (of 2) delta_plus equals 2^e.
    // Given that the denominator already includes v's exponent the distance
    // to the boundaries is simply 1.
    delta_plus->AssignUInt16(1);
    // Same for delta_minus (with adjustments below if f == 2^p-1).
    delta_minus->AssignUInt16(1);

    // If the significand (without the hidden bit) is 0, then the lower
    // boundary is closer than just one ulp (unit in the last place).
    // There is only one exception: if the next lower number is a denormal
    // then the distance is 1 ulp. Since the exponent is close to zero
    // (otherwise estimated_power would have been negative) this cannot happen
    // here either.
    uint64_t v_bits = Double(v).AsUint64();
    if ((v_bits & Double::kSignificandMask) == 0) {
      // The lower boundary is closer at half the distance of "normal" numbers.
      // Increase the denominator and adapt all but the delta_minus.
      denominator->ShiftLeft(1);  // *2
      numerator->ShiftLeft(1);    // *2
      delta_plus->ShiftLeft(1);   // *2
    }
  }
}

// See comments for InitialScaledStartValues
static void InitialScaledStartValuesNegativeExponentNegativePower(
    double v, int estimated_power, bool need_boundary_deltas, Bignum* numerator,
    Bignum* denominator, Bignum* delta_minus, Bignum* delta_plus) {
  const uint64_t kMinimalNormalizedExponent = 0x0010'0000'0000'0000;
  uint64_t significand = Double(v).Significand();
  int exponent = Double(v).Exponent();
  // Instead of multiplying the denominator with 10^estimated_power we
  // multiply all values (numerator and deltas) by 10^-estimated_power.

  // Use numerator as temporary container for power_ten.
  Bignum* power_ten = numerator;
  power_ten->AssignPowerUInt16(10, -estimated_power);

  if (need_boundary_deltas) {
    // Since power_ten == numerator we must make a copy of 10^estimated_power
    // before we complete the computation of the numerator.
    // delta_plus = delta_minus = 10^estimated_power
    delta_plus->AssignBignum(*power_ten);
    delta_minus->AssignBignum(*power_ten);
  }

  // numerator = significand * 2 * 10^-estimated_power
  //  since v = significand * 2^exponent this is equivalent to
  // numerator = v * 10^-estimated_power * 2 * 2^-exponent.
  // Remember: numerator has been abused as power_ten. So no need to assign it
  //  to itself.
  DCHECK(numerator == power_ten);
  numerator->MultiplyByUInt64(significand);

  // denominator = 2 * 2^-exponent with exponent < 0.
  denominator->AssignUInt16(1);
  denominator->ShiftLeft(-exponent);

  if (need_boundary_deltas) {
    // Introduce a common denominator so that the deltas to the boundaries are
    // integers.
    numerator->ShiftLeft(1);
    denominator->ShiftLeft(1);
    // With this shift the boundaries have their correct value, since
    // delta_plus = 10^-estimated_power, and
    // delta_minus = 10^-estimated_power.
    // These assignments have been done earlier.

    // The special case where the lower boundary is twice as close.
    // This time we have to look out for the exception too.
    uint64_t v_bits = Double(v).AsUint64();
    if ((v_bits & Double::kSignificandMask) == 0 &&
        // The only exception where a significand == 0 has its boundaries at
        // "normal" distances:
        (v_bits & Double::kExponentMask) != kMinimalNormalizedExponent) {
      numerator->ShiftLeft(1);    // *2
      denominator->ShiftLeft(1);  // *2
      delta_plus->ShiftLeft(1);   // *2
    }
  }
}

// Let v = significand * 2^exponent.
// Computes v / 10^estimated_power exactly, as a ratio of two bignums, numerator
// and denominator. The functions GenerateShortestDigits and
// GenerateCountedDigits will then convert this ratio to its decimal
// representation d, with the required accuracy.
// Then d * 10^estimated_power is the representation of v.
// (Note: the fraction and the estimated_power might get adjusted before
// generating the decimal representation.)
//
// The initial start values consist of:
//  - a scaled numerator: s.t. numerator/denominator == v / 10^estimated_power.
//  - a scaled (common) denominator.
//  optionally (used by GenerateShortestDigits to decide if it has the shortest
//  decimal converting back to v):
//  - v - m-: the distance to the lower boundary.
//  - m+ - v: the distance to the upper boundary.
//
// v, m+, m-, and therefore v - m- and m+ - v all share the same denominator.
//
// Let ep == estimated_power, then the returned values will satisfy:
//  v / 10^ep = numerator / denominator.
//  v's boundarys m- and m+:
//    m- / 10^ep == v / 10^ep - delta_minus / denominator
//    m+ / 10^ep == v / 10^ep + delta_plus / denominator
//  Or in other words:
//    m- == v - delta_minus * 10^ep / denominator;
//    m+ == v + delta_plus * 10^ep / denominator;
//
// Since 10^(k-1) <= v < 10^k    (with k == estimated_power)
//  or       10^k <= v < 10^(k+1)
//  we then have 0.1 <= numerator/denominator < 1
//           or    1 <= numerator/denominator < 10
//
// It is then easy to kickstart the digit-generation routine.
//
// The boundary-deltas are only filled if need_boundary_deltas is set.
static void InitialScaledStartValues(double v, int estimated_power,
                                     bool need_boundary_deltas,
                                     Bignum* numerator, Bignum* denominator,
                                     Bignum* delta_minus, Bignum* delta_plus) {
  if (Double(v).Exponent() >= 0) {
    InitialScaledStartValuesPositiveExponent(
        v, estimated_power, need_boundary_deltas, numerator, denominator,
        delta_minus, delta_plus);
  } else if (estimated_power >= 0) {
    InitialScaledStartValuesNegativeExponentPositivePower(
        v, estimated_power, need_boundary_deltas, numerator, denominator,
        delta_minus, delta_plus);
  } else {
    InitialScaledStartValuesNegativeExponentNegativePower(
        v, estimated_power, need_boundary_deltas, numerator, denominator,
        delta_minus, delta_plus);
  }
}

// This routine multiplies numerator/denominator so that its values lies in the
// range 1-10. That is after a call to this function we have:
//    1 <= (numerator + delta_plus) /denominator < 10.
// Let numerator the input before modification and numerator' the argument
// after modification, then the output-parameter decimal_point is such that
//  numerator / denominator * 10^estimated_power ==
//    numerator' / denominator' * 10^(decimal_point - 1)
// In some cases estimated_power was too low, and this is already the case. We
// then simply adjust the power so that 10^(k-1) <= v < 10^k (with k ==
// estimated_power) but do not touch the numerator or denominator.
// Otherwise the routine multiplies the numerator and the deltas by 10.
static void FixupMultiply10(int estimated_power, bool is_even,
                            int* decimal_point, Bignum* numerator,
                            Bignum* denominator, Bignum* delta_minus,
                            Bignum* delta_plus) {
  bool in_range;
  if (is_even) {
    // For IEEE doubles half-way cases (in decimal system numbers ending with 5)
    // are rounded to the closest floating-point number with even significand.
    in_range = Bignum::PlusCompare(*numerator, *delta_plus, *denominator) >= 0;
  } else {
    in_range = Bignum::PlusCompare(*numerator, *delta_plus, *denominator) > 0;
  }
  if (in_range) {
    // Since numerator + delta_plus >= denominator we already have
    // 1 <= numerator/denominator < 10. Simply update the estimated_power.
    *decimal_point = estimated_power + 1;
  } else {
    *decimal_point = estimated_power;
    numerator->Times10();
    if (Bignum::Equal(*delta_minus, *delta_plus)) {
      delta_minus->Times10();
      delta_plus->AssignBignum(*delta_minus);
    } else {
      delta_minus->Times10();
      delta_plus->Times10();
    }
  }
}

}  // namespace base
}  // namespace v8
```