Response:
Let's break down the thought process for analyzing the `tostring.cc` file.

1. **Understand the Request:** The request asks for the functionality of the provided C++ code, specifically the `v8/src/bigint/tostring.cc` file. It also asks about its relationship to JavaScript, potential Torque implementation, code logic, and common programming errors it might help avoid.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for keywords and patterns. Keywords like `namespace bigint`, function names like `ToString`, `BasecaseLast`, `DivideByMagic`, comments like "// Copyright", and includes like `<cstring>` and `"src/bigint/*"` immediately suggest this file deals with converting `bigint` types to string representations within the V8 JavaScript engine.

3. **Identify Core Functionality:** The presence of functions like `ToString`, `ToStringImpl`, `ToStringResultLength`, and the various helper functions within the anonymous namespace strongly indicates the primary function is converting `bigint` (V8's internal representation of arbitrary-precision integers) to strings in different bases (radix).

4. **Analyze Helper Functions:** Examine the smaller functions within the anonymous namespace:
    * `kMaxBitsPerChar`, `kConversionChars`: These look like lookup tables for string conversion.
    * `digit_pow`, `digit_pow_rec`:  These calculate powers, likely used for base conversions.
    * `BasecaseFixedLast`, `DivideByMagic`:  These appear to be optimized conversion routines for specific cases (fixed radix, avoiding direct division).
    * `ToStringFormatter`: This is a class that seems to encapsulate the entire conversion process, holding state like the digits, radix, and output buffer. Its methods (`Start`, `Finish`, `Classic`, `BasePowerOfTwo`, `Fast`, `ProcessLevel`) suggest different conversion strategies.

5. **Connect to JavaScript:**  The name "bigint" strongly links this code to the JavaScript `BigInt` type. The purpose of converting to a string is a core functionality of any number type in JavaScript. Think about how you'd use `BigInt` in JavaScript and what operations involve string conversion (e.g., `String(myBigInt)`, `myBigInt.toString()`, template literals).

6. **Address Torque Question:** The request specifically asks about `.tq` files. Based on the file extension being `.cc`, it's **not** a Torque file. Explain what Torque is and why this isn't one.

7. **Code Logic and Algorithms:**  Focus on the different conversion methods within `ToStringFormatter`:
    * `Classic`:  This likely implements a more standard base conversion algorithm, possibly involving repeated division. The comments mentioning "magic numbers" and division by the chunk divisor provide clues.
    * `BasePowerOfTwo`:  This is an optimization for converting to bases that are powers of 2, which can be done with bitwise operations.
    * `Fast`: This appears to be a more advanced, divide-and-conquer algorithm, potentially using techniques like Barrett reduction (mentioned in the `ProcessLevel` function). The detailed comments and the `RecursionLevel` class are key to understanding this.

8. **Illustrate with JavaScript Examples:** Provide simple JavaScript code snippets that demonstrate the functionality this C++ code implements. Show conversions to different bases.

9. **Identify Potential Programming Errors:** Consider the context of string conversion. Common errors include:
    * **Buffer Overflow:**  Ensuring the output buffer is large enough is crucial.
    * **Incorrect Radix:** Providing an invalid radix (outside the allowed range).
    * **Sign Handling:**  Properly handling negative signs.
    * **Leading Zeros:** Understanding when leading zeros are included or omitted.

10. **Hypothesize Input and Output:** Create simple examples to illustrate the `ToString` function. Choose easy-to-understand cases.

11. **Structure the Answer:** Organize the information logically into the requested categories: Functionality, Torque, JavaScript examples, code logic, and common errors. Use clear and concise language.

12. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For instance, initially, I might have just said "it converts BigInt to string". But refining that to explain *how* (different algorithms for different bases) is important. Similarly, elaborating on the "Fast" algorithm and the `RecursionLevel` is crucial for a deeper understanding.

This systematic approach, combining code analysis, understanding the surrounding context (V8, JavaScript), and focusing on the specific questions in the request, allows for a comprehensive and informative answer.
好的，让我们来分析一下 `v8/src/bigint/tostring.cc` 这个 V8 源代码文件的功能。

**1. 主要功能：BigInt 到字符串的转换**

这个文件的核心功能是将 V8 内部表示的 `BigInt` 对象转换为字符串。它考虑了不同的进制（radix），并实现了多种优化算法来提高转换效率。

**2. 详细功能分解：**

* **支持不同的进制 (Radix):** 代码中的 `radix` 参数表明它可以将 `BigInt` 转换为指定进制的字符串，例如：二进制 (2), 八进制 (8), 十进制 (10), 十六进制 (16)，以及其他 2 到 36 之间的进制。
* **处理正负号 (Sign):**  `sign` 参数用于指示 `BigInt` 是否为负数，并在必要时在输出字符串前添加负号 `-`。
* **多种转换算法:**  该文件实现了多种 BigInt 转换为字符串的算法，包括：
    * **`Classic()`:**  一个通用的、可能较慢的转换算法，适用于所有进制。它通过不断地除以基数来提取每一位数字。
    * **`BasePowerOfTwo()`:** 针对基数为 2 的幂次（如 2, 4, 8, 16 等）的优化算法。这种情况下，可以使用位运算来高效地提取数字。
    * **`Fast()`:**  一种更高级的、分而治之的算法，用于加速较大 `BigInt` 的转换。它通过递归地将 `BigInt` 分成两半进行处理。
* **性能优化:** 代码中包含了一些性能优化的技巧，例如：
    * **查表 (`kMaxBitsPerChar`, `kConversionChars`):** 使用预先计算好的查找表来加速某些操作。
    * **避免除法 (`DivideByMagic`):** 对于某些常见的进制（如十进制），使用乘以“魔数”（模逆）的方式来代替昂贵的除法运算。
    * **分块处理:** 将 `BigInt` 分成多个“块”进行处理，以提高效率。
* **内存管理:** 使用 V8 内部的内存管理机制（例如 `ScratchDigits`, `Storage`）来高效地分配和管理临时存储空间。
* **中断处理:**  代码中存在 `MAYBE_INTERRUPT` 宏，表明在某些耗时的操作中会检查中断请求，以便及时停止长时间运行的任务。
* **预估结果长度 (`ToStringResultLength`):**  在转换之前，会计算转换后字符串的长度，以避免缓冲区溢出。

**3. 关于 `.tq` 文件：**

根据你的描述，如果 `v8/src/bigint/tostring.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是 V8 自研的一种类型化的汇编语言，用于编写 V8 的内置函数和运行时代码。然而，**当前提供的文件是以 `.cc` 结尾，这是一个标准的 C++ 源代码文件。**

**4. 与 JavaScript 功能的关系及示例：**

`v8/src/bigint/tostring.cc` 中实现的功能直接对应于 JavaScript 中 `BigInt` 对象的以下操作：

* **`BigInt.prototype.toString(radix)`:**  将 `BigInt` 对象转换为指定进制的字符串。如果没有提供 `radix`，则默认为 10。
* **隐式类型转换:** 在某些情况下，JavaScript 会尝试将 `BigInt` 隐式转换为字符串，例如在使用模板字符串或字符串连接时。

**JavaScript 示例：**

```javascript
const bigIntNum = 9007199254740991n; // 一个 BigInt 字面量

// 使用 toString() 方法转换为不同进制的字符串
console.log(bigIntNum.toString());      // 输出 "9007199254740991" (十进制，默认)
console.log(bigIntNum.toString(2));     // 输出 "1111111111111111111111111111111111111111111111111111" (二进制)
console.log(bigIntNum.toString(16));    // 输出 "1fffffffffffff" (十六进制)
console.log(bigIntNum.toString(36));    // 输出 "lnjq0gg68hc" (三十六进制)

// 隐式类型转换
console.log(`The number is ${bigIntNum}`); // 输出 "The number is 9007199254740991"
console.log(bigIntNum + "");              // 输出 "9007199254740991" (注意：与数字相加会报错)
```

**5. 代码逻辑推理及假设输入输出：**

假设我们调用了 `ProcessorImpl::ToString` 函数，并传入以下参数：

* **`X` (Digits):**  表示 BigInt 的内部表示，假设它代表数字 `12345`。为了简化，假设内部表示是一个包含两个 digit 的数组 `[45, 1]` (低位在前，每个 digit 可以存储一部分数字)。
* **`radix` (int):**  `10` (十进制)
* **`sign` (bool):** `false` (正数)
* **`out` (char*):**  指向一个足够大的字符数组。
* **`out_length` (uint32_t*):**  指向一个存储 `out` 数组长度的变量，假设初始值为 10。

**推理过程 (简化版，针对 `Classic()` 算法):**

1. **`ToStringFormatter` 初始化:** 创建 `ToStringFormatter` 对象，传入 `X`, `radix`, `sign`, `out`, 和 `out_length`。
2. **`Start()`:** 计算 `chunk_chars_` 和 `chunk_divisor_` (对于 radix=10，可能会优化使用 `DivideByMagic`)。
3. **`Classic()`:**
   * 因为 `digits_.len()` (2) 大于 1，所以不会直接进入 base case。
   * **循环开始:**
     * **第一次迭代:**
       * 如果使用 `DivideByMagic<10>`，则会优化地将 `12345` 除以某个 10 的幂（例如 100 或 1000），得到余数和商。假设 chunk_divisor 是 100。
       * `DivideByMagic` 会计算出余数 `45`，并将其转换为字符串 `"45"` (逆序写入 `out` 缓冲区)。
       * 新的 `rest` 将代表商 `123`。
     * **第二次迭代:**
       * `DivideByMagic` 处理 `rest` (代表 `123`)，计算余数 `23`，并转换为字符串 `"23"`。
       * 新的 `rest` 代表商 `1`。
   * **循环结束:**  `rest.len()` 为 1。
   * **`BasecaseLast(rest[0], out_)`:** 处理最后的 digit `1`，将其转换为字符串 `"1"`。
4. **`Finish()`:** 将输出缓冲区中的字符 `"1"`, `"2"`, `"3"`, `"4"`, `"5"` 整理好顺序，并将多余的 `0` 移除。
5. **输出:** `out` 数组中将包含字符串 `"12345"`， `*out_length` 的值会被更新为 5。

**假设输入与输出：**

**输入:**  `BigInt` 代表 `12345`, `radix = 10`

**输出:**  字符串 `"12345"`

**假设输入与输出：**

**输入:**  `BigInt` 代表 `-100`, `radix = 16`

**输出:** 字符串 `"-64"`

**6. 涉及用户常见的编程错误：**

这个文件中的代码旨在安全高效地执行 BigInt 到字符串的转换，它在一定程度上可以避免用户在手动实现类似功能时可能犯的错误：

* **缓冲区溢出:** `ToStringResultLength` 函数可以预先计算所需的缓冲区大小，避免因缓冲区不足导致的内存错误。用户在手动转换时可能没有考虑到 BigInt 可能非常大，导致分配的缓冲区过小。
* **进制转换错误:**  手动实现进制转换容易出错，尤其是在处理大于 10 的进制时。V8 的实现经过了严格的测试和优化，确保了转换的正确性。
* **性能问题:**  对于大的 BigInt，简单的逐位除法效率较低。V8 实现了多种优化算法（如 `Fast()`），可以显著提高性能，而用户自己编写可能没有考虑到这些优化。
* **符号处理错误:**  正确处理负数的符号也是一个需要注意的点，V8 的实现确保了负号的正确添加。
* **处理 `0n` 的特殊情况:**  确保 `0n` 正确转换为字符串 `"0"`。

**举例说明用户常见的编程错误（JavaScript 环境下）：**

虽然这个 C++ 文件是 V8 的内部实现，但了解其功能可以帮助我们理解 JavaScript 中 BigInt 转换的机制，并避免在 JavaScript 中使用 BigInt 时犯类似的错误。

* **错误地估计字符串长度:**  在需要将 BigInt 转换为字符串并存储时，没有考虑到 BigInt 可能非常大，导致分配的字符串变量或缓冲区过小。

```javascript
const veryLargeBigInt = 10n ** 100n;
const str = String(veryLargeBigInt);
// 如果你事先分配了一个固定大小的字符串 buffer，可能会溢出
```

* **手动实现进制转换时的错误:**  用户尝试自己编写 BigInt 的进制转换逻辑，可能出现计算错误、边界条件处理不当等问题。

```javascript
function bigIntToHex(bigInt) {
  // 手动实现的十六进制转换，可能存在错误
  let hexString = "";
  while (bigInt > 0n) {
    const remainder = bigInt % 16n;
    hexString = "0123456789abcdef"[Number(remainder)] + hexString;
    bigInt = bigInt / 16n; // 注意：BigInt 的除法
  }
  return hexString || "0";
}

const myBigInt = 100n;
console.log(myBigInt.toString(16)); // V8 的正确实现
console.log(bigIntToHex(myBigInt));  // 自定义实现，可能存在 bug
```

总而言之，`v8/src/bigint/tostring.cc` 是 V8 引擎中负责将 `BigInt` 对象高效、正确地转换为各种进制字符串的关键组件。它通过多种优化算法和严谨的代码逻辑，确保了 JavaScript 中 `BigInt` 到字符串转换的可靠性。

### 提示词
```
这是目录为v8/src/bigint/tostring.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/bigint/tostring.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>
#include <limits>

#include "src/bigint/bigint-internal.h"
#include "src/bigint/digit-arithmetic.h"
#include "src/bigint/div-helpers.h"
#include "src/bigint/util.h"
#include "src/bigint/vector-arithmetic.h"

namespace v8 {
namespace bigint {

namespace {

// Lookup table for the maximum number of bits required per character of a
// base-N string representation of a number. To increase accuracy, the array
// value is the actual value multiplied by 32. To generate this table:
// for (var i = 0; i <= 36; i++) { print(Math.ceil(Math.log2(i) * 32) + ","); }
constexpr uint8_t kMaxBitsPerChar[] = {
    0,   0,   32,  51,  64,  75,  83,  90,  96,  // 0..8
    102, 107, 111, 115, 119, 122, 126, 128,      // 9..16
    131, 134, 136, 139, 141, 143, 145, 147,      // 17..24
    149, 151, 153, 154, 156, 158, 159, 160,      // 25..32
    162, 163, 165, 166,                          // 33..36
};

static const int kBitsPerCharTableShift = 5;
static const size_t kBitsPerCharTableMultiplier = 1u << kBitsPerCharTableShift;

static const char kConversionChars[] = "0123456789abcdefghijklmnopqrstuvwxyz";

// Raises {base} to the power of {exponent}. Does not check for overflow.
digit_t digit_pow(digit_t base, digit_t exponent) {
  digit_t result = 1ull;
  while (exponent > 0) {
    if (exponent & 1) {
      result *= base;
    }
    exponent >>= 1;
    base *= base;
  }
  return result;
}

// Compile-time version of the above.
constexpr digit_t digit_pow_rec(digit_t base, digit_t exponent) {
  return exponent == 1 ? base : base * digit_pow_rec(base, exponent - 1);
}

// A variant of ToStringFormatter::BasecaseLast, specialized for a radix
// known at compile-time.
template <int radix>
char* BasecaseFixedLast(digit_t chunk, char* out) {
  while (chunk != 0) {
    DCHECK(*(out - 1) == kStringZapValue);
    if (radix <= 10) {
      *(--out) = '0' + (chunk % radix);
    } else {
      *(--out) = kConversionChars[chunk % radix];
    }
    chunk /= radix;
  }
  return out;
}

// By making {radix} a compile-time constant and computing {chunk_divisor}
// as another compile-time constant from it, we allow the compiler to emit
// an optimized instruction sequence based on multiplications with "magic"
// numbers (modular multiplicative inverses) instead of actual divisions.
// The price we pay is having to work on half digits; the technique doesn't
// work with twodigit_t-by-digit_t divisions.
// Includes an equivalent of ToStringFormatter::BasecaseMiddle, accordingly
// specialized for a radix known at compile time.
template <digit_t radix>
char* DivideByMagic(RWDigits rest, Digits input, char* output) {
  constexpr uint8_t max_bits_per_char = kMaxBitsPerChar[radix];
  constexpr int chunk_chars =
      kHalfDigitBits * kBitsPerCharTableMultiplier / max_bits_per_char;
  constexpr digit_t chunk_divisor = digit_pow_rec(radix, chunk_chars);
  digit_t remainder = 0;
  for (int i = input.len() - 1; i >= 0; i--) {
    digit_t d = input[i];
    digit_t upper = (remainder << kHalfDigitBits) | (d >> kHalfDigitBits);
    digit_t u_result = upper / chunk_divisor;
    remainder = upper % chunk_divisor;
    digit_t lower = (remainder << kHalfDigitBits) | (d & kHalfDigitMask);
    digit_t l_result = lower / chunk_divisor;
    remainder = lower % chunk_divisor;
    rest[i] = (u_result << kHalfDigitBits) | l_result;
  }
  // {remainder} is now the current chunk to be written out.
  for (int i = 0; i < chunk_chars; i++) {
    DCHECK(*(output - 1) == kStringZapValue);
    if (radix <= 10) {
      *(--output) = '0' + (remainder % radix);
    } else {
      *(--output) = kConversionChars[remainder % radix];
    }
    remainder /= radix;
  }
  DCHECK(remainder == 0);
  return output;
}

class RecursionLevel;

// The classic algorithm must check for interrupt requests if no faster
// algorithm is available.
#if V8_ADVANCED_BIGINT_ALGORITHMS
#define MAYBE_INTERRUPT(code) ((void)0)
#else
#define MAYBE_INTERRUPT(code) code
#endif

class ToStringFormatter {
 public:
  ToStringFormatter(Digits X, int radix, bool sign, char* out,
                    uint32_t chars_available, ProcessorImpl* processor)
      : digits_(X),
        radix_(radix),
        sign_(sign),
        out_start_(out),
        out_end_(out + chars_available),
        out_(out_end_),
        processor_(processor) {
    digits_.Normalize();
    DCHECK(chars_available >= ToStringResultLength(digits_, radix_, sign_));
  }

  void Start();
  int Finish();

  void Classic() {
    if (digits_.len() == 0) {
      *(--out_) = '0';
      return;
    }
    if (digits_.len() == 1) {
      out_ = BasecaseLast(digits_[0], out_);
      return;
    }
    // {rest} holds the part of the BigInt that we haven't looked at yet.
    // Not to be confused with "remainder"!
    ScratchDigits rest(digits_.len());
    // In the first round, divide the input, allocating a new BigInt for
    // the result == rest; from then on divide the rest in-place.
    Digits dividend = digits_;
    do {
      if (radix_ == 10) {
        // Faster but costs binary size, so we optimize the most common case.
        out_ = DivideByMagic<10>(rest, dividend, out_);
        MAYBE_INTERRUPT(processor_->AddWorkEstimate(rest.len() * 2));
      } else {
        digit_t chunk;
        processor_->DivideSingle(rest, &chunk, dividend, chunk_divisor_);
        out_ = BasecaseMiddle(chunk, out_);
        // Assume that a division is about ten times as expensive as a
        // multiplication.
        MAYBE_INTERRUPT(processor_->AddWorkEstimate(rest.len() * 10));
      }
      MAYBE_INTERRUPT(if (processor_->should_terminate()) return );
      rest.Normalize();
      dividend = rest;
    } while (rest.len() > 1);
    out_ = BasecaseLast(rest[0], out_);
  }

  void BasePowerOfTwo();

  void Fast();
  char* FillWithZeros(RecursionLevel* level, char* prev_cursor, char* out,
                      bool is_last_on_level);
  char* ProcessLevel(RecursionLevel* level, Digits chunk, char* out,
                     bool is_last_on_level);

 private:
  // When processing the last (most significant) digit, don't write leading
  // zeros.
  char* BasecaseLast(digit_t digit, char* out) {
    if (radix_ == 10) return BasecaseFixedLast<10>(digit, out);
    do {
      DCHECK(*(out - 1) == kStringZapValue);
      *(--out) = kConversionChars[digit % radix_];
      digit /= radix_;
    } while (digit > 0);
    return out;
  }

  // When processing a middle (non-most significant) digit, always write the
  // same number of characters (as many '0' as necessary).
  char* BasecaseMiddle(digit_t digit, char* out) {
    for (int i = 0; i < chunk_chars_; i++) {
      DCHECK(*(out - 1) == kStringZapValue);
      *(--out) = kConversionChars[digit % radix_];
      digit /= radix_;
    }
    DCHECK(digit == 0);
    return out;
  }

  Digits digits_;
  int radix_;
  int max_bits_per_char_ = 0;
  int chunk_chars_ = 0;
  bool sign_;
  char* out_start_;
  char* out_end_;
  char* out_;
  digit_t chunk_divisor_ = 0;
  ProcessorImpl* processor_;
};

#undef MAYBE_INTERRUPT

// Prepares data for {Classic}. Not needed for {BasePowerOfTwo}.
void ToStringFormatter::Start() {
  max_bits_per_char_ = kMaxBitsPerChar[radix_];
  chunk_chars_ = kDigitBits * kBitsPerCharTableMultiplier / max_bits_per_char_;
  chunk_divisor_ = digit_pow(radix_, chunk_chars_);
  // By construction of chunk_chars_, there can't have been overflow.
  DCHECK(chunk_divisor_ != 0);
}

int ToStringFormatter::Finish() {
  DCHECK(out_ >= out_start_);
  DCHECK(out_ < out_end_);  // At least one character was written.
  while (out_ < out_end_ && *out_ == '0') out_++;
  if (sign_) *(--out_) = '-';
  int excess = 0;
  if (out_ > out_start_) {
    size_t actual_length = out_end_ - out_;
    excess = static_cast<int>(out_ - out_start_);
    std::memmove(out_start_, out_, actual_length);
  }
  return excess;
}

void ToStringFormatter::BasePowerOfTwo() {
  const int bits_per_char = CountTrailingZeros(radix_);
  const int char_mask = radix_ - 1;
  digit_t digit = 0;
  // Keeps track of how many unprocessed bits there are in {digit}.
  int available_bits = 0;
  for (int i = 0; i < digits_.len() - 1; i++) {
    digit_t new_digit = digits_[i];
    // Take any leftover bits from the last iteration into account.
    int current = (digit | (new_digit << available_bits)) & char_mask;
    *(--out_) = kConversionChars[current];
    int consumed_bits = bits_per_char - available_bits;
    digit = new_digit >> consumed_bits;
    available_bits = kDigitBits - consumed_bits;
    while (available_bits >= bits_per_char) {
      *(--out_) = kConversionChars[digit & char_mask];
      digit >>= bits_per_char;
      available_bits -= bits_per_char;
    }
  }
  // Take any leftover bits from the last iteration into account.
  digit_t msd = digits_.msd();
  int current = (digit | (msd << available_bits)) & char_mask;
  *(--out_) = kConversionChars[current];
  digit = msd >> (bits_per_char - available_bits);
  while (digit != 0) {
    *(--out_) = kConversionChars[digit & char_mask];
    digit >>= bits_per_char;
  }
}

#if V8_ADVANCED_BIGINT_ALGORITHMS

// "Fast" divide-and-conquer conversion to string. The basic idea is to
// recursively cut the BigInt in half (using a division with remainder,
// the divisor being ~half as large (in bits) as the current dividend).
//
// As preparation, we build up a linked list of metadata for each recursion
// level. We do this bottom-up, i.e. start with the level that will produce
// two halves that are register-sized and bail out to the base case.
// Each higher level (executed earlier, prepared later) uses a divisor that is
// the square of the previously-created "next" level's divisor. Preparation
// terminates when the current divisor is at least half as large as the bigint.
// We also precompute each level's divisor's inverse, so we can use
// Barrett division later.
//
// Example: say we want to format 1234567890123, and we can fit two decimal
// digits into a register for the base case.
//
//              1234567890123
//                    ↓
//               %100000000 (a)              // RecursionLevel 2,
//             /            \                // is_toplevel_ == true.
//         12345            67890123
//           ↓                  ↓
//    (e) %10000             %10000 (b)      // RecursionLevel 1
//        /    \            /      \
//       1     2345      6789      0123
//       ↓   (f) ↓         ↓ (d)     ↓
// (g) %100    %100      %100      %100 (c)  // RecursionLevel 0
//     / \     /   \     /   \     /   \
//    00 01   23   45   67   89   01   23
//        ↓    ↓    ↓    ↓    ↓    ↓    ↓    // Base case.
//       "1" "23" "45" "67" "89" "01" "23"
//
// We start building RecursionLevels in order 0 -> 1 -> 2, performing the
// squarings 100² = 10000 and 10000² = 100000000 each only once. Execution
// then happens in order (a) through (g); lower-level divisors are used
// repeatedly. We build the string from right to left.
// Note that we can skip the division at (g) and fall through directly.
// Also, note that there are two chunks with value 1: one of them must produce
// a leading "0" in its string representation, the other must not.
//
// In this example, {base_divisor} is 100 and {base_char_count} is 2.

// TODO(jkummerow): Investigate whether it is beneficial to build one or two
// fewer RecursionLevels, and use the topmost level for more than one division.

class RecursionLevel {
 public:
  static RecursionLevel* CreateLevels(digit_t base_divisor, int base_char_count,
                                      int target_bit_length,
                                      ProcessorImpl* processor);
  ~RecursionLevel() { delete next_; }

  void ComputeInverse(ProcessorImpl* proc, int dividend_length = 0);
  Digits GetInverse(int dividend_length);

 private:
  friend class ToStringFormatter;
  RecursionLevel(digit_t base_divisor, int base_char_count)
      : char_count_(base_char_count), divisor_(1) {
    divisor_[0] = base_divisor;
  }
  explicit RecursionLevel(RecursionLevel* next)
      : char_count_(next->char_count_ * 2),
        next_(next),
        divisor_(next->divisor_.len() * 2) {
    next->is_toplevel_ = false;
  }

  void LeftShiftDivisor() {
    leading_zero_shift_ = CountLeadingZeros(divisor_.msd());
    LeftShift(divisor_, divisor_, leading_zero_shift_);
  }

  int leading_zero_shift_{0};
  // The number of characters generated by *each half* of this level.
  int char_count_;
  bool is_toplevel_{true};
  RecursionLevel* next_{nullptr};
  ScratchDigits divisor_;
  std::unique_ptr<Storage> inverse_storage_;
  Digits inverse_;
};

// static
RecursionLevel* RecursionLevel::CreateLevels(digit_t base_divisor,
                                             int base_char_count,
                                             int target_bit_length,
                                             ProcessorImpl* processor) {
  RecursionLevel* level = new RecursionLevel(base_divisor, base_char_count);
  // We can stop creating levels when the next level's divisor, which is the
  // square of the current level's divisor, would be strictly bigger (in terms
  // of its numeric value) than the input we're formatting. Since computing that
  // next divisor is expensive, we want to predict the necessity based on bit
  // lengths. Bit lengths are an imperfect predictor of numeric value, so we
  // have to be careful:
  // - since we can't estimate which one of two numbers of equal bit length
  //   is bigger, we have to aim for a strictly bigger bit length.
  // - when squaring, the bit length sometimes doubles (e.g. 0b11² == 0b1001),
  //   but usually we "lose" a bit (e.g. 0b10² == 0b100).
  while (BitLength(level->divisor_) * 2 - 1 <= target_bit_length) {
    RecursionLevel* prev = level;
    level = new RecursionLevel(prev);
    processor->Multiply(level->divisor_, prev->divisor_, prev->divisor_);
    if (processor->should_terminate()) {
      delete level;
      return nullptr;
    }
    level->divisor_.Normalize();
    // Left-shifting the divisor must only happen after it's been used to
    // compute the next divisor.
    prev->LeftShiftDivisor();
    prev->ComputeInverse(processor);
  }
  level->LeftShiftDivisor();
  // Not calling info->ComputeInverse here so that it can take the input's
  // length into account to save some effort on inverse generation.
  return level;
}

// The top level might get by with a smaller inverse than we could maximally
// compute, so the caller should provide the dividend length.
void RecursionLevel::ComputeInverse(ProcessorImpl* processor,
                                    int dividend_length) {
  int inverse_len = divisor_.len();
  if (dividend_length != 0) {
    inverse_len = dividend_length - divisor_.len();
    DCHECK(inverse_len <= divisor_.len());
  }
  int scratch_len = InvertScratchSpace(inverse_len);
  ScratchDigits scratch(scratch_len);
  Storage* inv_storage = new Storage(inverse_len + 1);
  inverse_storage_.reset(inv_storage);
  RWDigits inverse_initializer(inv_storage->get(), inverse_len + 1);
  Digits input(divisor_, divisor_.len() - inverse_len, inverse_len);
  processor->Invert(inverse_initializer, input, scratch);
  inverse_initializer.TrimOne();
  inverse_ = inverse_initializer;
}

Digits RecursionLevel::GetInverse(int dividend_length) {
  DCHECK(inverse_.len() != 0);
  int inverse_len = dividend_length - divisor_.len();
  DCHECK(inverse_len <= inverse_.len());
  return inverse_ + (inverse_.len() - inverse_len);
}

void ToStringFormatter::Fast() {
  std::unique_ptr<RecursionLevel> recursion_levels(RecursionLevel::CreateLevels(
      chunk_divisor_, chunk_chars_, BitLength(digits_), processor_));
  if (processor_->should_terminate()) return;
  out_ = ProcessLevel(recursion_levels.get(), digits_, out_, true);
}

// Writes '0' characters right-to-left, starting at {out}-1, until the distance
// from {right_boundary} to {out} equals the number of characters that {level}
// is supposed to produce.
char* ToStringFormatter::FillWithZeros(RecursionLevel* level,
                                       char* right_boundary, char* out,
                                       bool is_last_on_level) {
  // Fill up with zeros up to the character count expected to be generated
  // on this level; unless this is the left edge of the result.
  if (is_last_on_level) return out;
  int chunk_chars = level == nullptr ? chunk_chars_ : level->char_count_ * 2;
  char* end = right_boundary - chunk_chars;
  DCHECK(out >= end);
  while (out > end) {
    *(--out) = '0';
  }
  return out;
}

char* ToStringFormatter::ProcessLevel(RecursionLevel* level, Digits chunk,
                                      char* out, bool is_last_on_level) {
  // Step 0: if only one digit is left, bail out to the base case.
  Digits normalized = chunk;
  normalized.Normalize();
  if (normalized.len() <= 1) {
    char* right_boundary = out;
    if (normalized.len() == 1) {
      out = BasecaseLast(normalized[0], out);
    }
    return FillWithZeros(level, right_boundary, out, is_last_on_level);
  }

  // Step 1: If the chunk is guaranteed to remain smaller than the divisor
  // even after left-shifting, fall through to the next level immediately.
  if (normalized.len() < level->divisor_.len()) {
    char* right_boundary = out;
    out = ProcessLevel(level->next_, chunk, out, is_last_on_level);
    return FillWithZeros(level, right_boundary, out, is_last_on_level);
  }
  // Step 2: Prepare the chunk.
  bool allow_inplace_modification = chunk.digits() != digits_.digits();
  Digits original_chunk = chunk;
  ShiftedDigits chunk_shifted(chunk, level->leading_zero_shift_,
                              allow_inplace_modification);
  chunk = chunk_shifted;
  chunk.Normalize();
  // Check (now precisely) if the chunk is smaller than the divisor.
  int comparison = Compare(chunk, level->divisor_);
  if (comparison <= 0) {
    char* right_boundary = out;
    if (comparison < 0) {
      // If the chunk is strictly smaller than the divisor, we can process
      // it directly on the next level as the right half, and know that the
      // left half is all '0'.
      // In case we shifted {chunk} in-place, we must undo that
      // before the call...
      chunk_shifted.Reset();
      // ...and otherwise undo the {chunk = chunk_shifted} assignment above.
      chunk = original_chunk;
      out = ProcessLevel(level->next_, chunk, out, is_last_on_level);
    } else {
      DCHECK(comparison == 0);
      // If the chunk is equal to the divisor, we know that the right half
      // is all '0', and the left half is '...0001'.
      // Handling this case specially is an optimization; we could also
      // fall through to the generic "chunk > divisor" path below.
      out = FillWithZeros(level->next_, right_boundary, out, false);
      *(--out) = '1';
    }
    // In both cases, make sure the left half is fully written.
    return FillWithZeros(level, right_boundary, out, is_last_on_level);
  }
  // Step 3: Allocate space for the results.
  // Allocate one extra digit so the next level can left-shift in-place.
  ScratchDigits right(level->divisor_.len() + 1);
  // Allocate one extra digit because DivideBarrett requires it.
  ScratchDigits left(chunk.len() - level->divisor_.len() + 1);

  // Step 4: Divide to split {chunk} into {left} and {right}.
  int inverse_len = chunk.len() - level->divisor_.len();
  if (inverse_len == 0) {
    processor_->DivideSchoolbook(left, right, chunk, level->divisor_);
  } else if (level->divisor_.len() == 1) {
    processor_->DivideSingle(left, right.digits(), chunk, level->divisor_[0]);
    for (int i = 1; i < right.len(); i++) right[i] = 0;
  } else {
    ScratchDigits scratch(DivideBarrettScratchSpace(chunk.len()));
    // The top level only computes its inverse when {chunk.len()} is
    // available. Other levels have precomputed theirs.
    if (level->is_toplevel_) {
      level->ComputeInverse(processor_, chunk.len());
      if (processor_->should_terminate()) return out;
    }
    Digits inverse = level->GetInverse(chunk.len());
    processor_->DivideBarrett(left, right, chunk, level->divisor_, inverse,
                              scratch);
    if (processor_->should_terminate()) return out;
  }
  RightShift(right, right, level->leading_zero_shift_);
#if DEBUG
  Digits left_test = left;
  left_test.Normalize();
  DCHECK(left_test.len() <= level->divisor_.len());
#endif

  // Step 5: Recurse.
  char* end_of_right_part = ProcessLevel(level->next_, right, out, false);
  if (processor_->should_terminate()) return out;
  // The recursive calls are required and hence designed to write exactly as
  // many characters as their level is responsible for.
  DCHECK(end_of_right_part == out - level->char_count_);
  USE(end_of_right_part);
  // We intentionally don't use {end_of_right_part} here to be prepared for
  // potential future multi-threaded execution.
  return ProcessLevel(level->next_, left, out - level->char_count_,
                      is_last_on_level);
}

#endif  // V8_ADVANCED_BIGINT_ALGORITHMS

}  // namespace

void ProcessorImpl::ToString(char* out, uint32_t* out_length, Digits X,
                             int radix, bool sign) {
  const bool use_fast_algorithm = X.len() >= kToStringFastThreshold;
  ToStringImpl(out, out_length, X, radix, sign, use_fast_algorithm);
}

// Factored out so that tests can call it.
void ProcessorImpl::ToStringImpl(char* out, uint32_t* out_length, Digits X,
                                 int radix, bool sign, bool fast) {
#if DEBUG
  for (uint32_t i = 0; i < *out_length; i++) out[i] = kStringZapValue;
#endif
  ToStringFormatter formatter(X, radix, sign, out, *out_length, this);
  if (IsPowerOfTwo(radix)) {
    formatter.BasePowerOfTwo();
#if V8_ADVANCED_BIGINT_ALGORITHMS
  } else if (fast) {
    formatter.Start();
    formatter.Fast();
    if (should_terminate()) return;
#else
    USE(fast);
#endif  // V8_ADVANCED_BIGINT_ALGORITHMS
  } else {
    formatter.Start();
    formatter.Classic();
  }
  int excess = formatter.Finish();
  *out_length -= excess;
  memset(out + *out_length, 0, excess);
}

Status Processor::ToString(char* out, uint32_t* out_length, Digits X, int radix,
                           bool sign) {
  ProcessorImpl* impl = static_cast<ProcessorImpl*>(this);
  impl->ToString(out, out_length, X, radix, sign);
  return impl->get_and_clear_status();
}

uint32_t ToStringResultLength(Digits X, int radix, bool sign) {
  const uint32_t bit_length = BitLength(X);
  uint32_t result;
  if (IsPowerOfTwo(radix)) {
    const uint32_t bits_per_char = CountTrailingZeros(radix);
    result = DIV_CEIL(bit_length, bits_per_char) + sign;
  } else {
    // Maximum number of bits we can represent with one character.
    const uint8_t max_bits_per_char = kMaxBitsPerChar[radix];
    // For estimating the result length, we have to be pessimistic and work with
    // the minimum number of bits one character can represent.
    const uint8_t min_bits_per_char = max_bits_per_char - 1;
    // Perform the following computation with uint64_t to avoid overflows.
    uint64_t chars_required = bit_length;
    chars_required *= kBitsPerCharTableMultiplier;
    chars_required = DIV_CEIL(chars_required, min_bits_per_char);
    DCHECK(chars_required <
           static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()));
    result = static_cast<uint32_t>(chars_required);
  }
  result += sign;
  return result;
}

}  // namespace bigint
}  // namespace v8
```