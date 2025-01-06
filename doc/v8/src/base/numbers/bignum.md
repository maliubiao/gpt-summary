Response: Let's break down the thought process to analyze the C++ code and connect it to JavaScript.

1. **Understand the Goal:** The core request is to summarize the functionality of the `bignum.cc` file and relate it to JavaScript, providing examples. This means we need to identify the key data structures and operations, and then think about where similar concepts exist in JS.

2. **Initial Scan for Key Terms:**  I'll quickly scan the code for recurring terms and patterns. I see "Bignum," "bigits," "exponent," "UInt64," "DecimalString," "HexString," "Add," "Subtract," "Multiply," "Divide," "ShiftLeft," "Compare," etc. These strongly suggest this code deals with representing and manipulating very large numbers, beyond the standard integer types.

3. **Identify the Core Data Structure:** The `Bignum` class is the central element. Its members `bigits_`, `used_digits_`, and `exponent_` are crucial.
    * `bigits_`: An array (or vector) likely used to store the digits of the large number. The name "bigit" suggests it's breaking the number into chunks.
    * `used_digits_`:  Indicates how many of the `bigits_` array are actually used. This is important for efficiency.
    * `exponent_`:  This is a strong clue that the `Bignum` likely supports representing numbers with a scaling factor, similar to scientific notation.

4. **Analyze Key Methods (Categorize Operations):** Now, let's look at the methods and group them logically:
    * **Initialization/Assignment:**  Methods like `Bignum()`, `AssignUInt16`, `AssignUInt64`, `AssignBignum`, `AssignDecimalString`, `AssignHexString`, `AssignPowerUInt16`, `Zero()`. These are all about creating and setting the value of a `Bignum` from various sources.
    * **Arithmetic Operations:** `AddUInt64`, `AddBignum`, `SubtractBignum`, `MultiplyByUInt32`, `MultiplyByUInt64`, `MultiplyByPowerOfTen`, `Square()`, `DivideModuloIntBignum`. These are the core math operations.
    * **Bit Manipulation/Shifting:** `ShiftLeft`, `BigitsShiftLeft`. These manipulate the internal representation at the bit level.
    * **Comparison:** `Compare`, `PlusCompare`, `LessEqual`, `Equal`. Needed for ordering and equality checks.
    * **Conversion/Output:** `ToHexString`. Converting the internal representation to a string.
    * **Internal Helpers:** `Clamp`, `Align`, `EnsureCapacity`, `BigitAt`. These are utility functions for managing the internal state and memory.

5. **Infer Functionality:** Based on the above, it's clear the `Bignum` class implements arbitrary-precision arithmetic. It can handle integers much larger than standard integer types. The handling of decimal and hexadecimal strings confirms this. The `exponent_` suggests it might also be used for representing very small numbers or numbers with a large magnitude but with a trailing decimal point effectively factored out.

6. **Connect to JavaScript:** This is where we bridge the gap. Ask yourself: "Does JavaScript have a built-in way to handle these large numbers?" The answer is no, *directly*. JavaScript's `Number` type is a double-precision floating-point number, which has limitations in precision, especially for large integers.

7. **Identify JavaScript Equivalents (or Lack Thereof):**
    * **Built-in Limitations:**  Explain the limitations of JavaScript's `Number`. Give an example of precision loss with large integers.
    * **`BigInt`:**  Recognize that ES2020 introduced `BigInt`. This is the direct JavaScript counterpart for arbitrary-precision integers. Show examples of `BigInt` usage for addition, multiplication, etc. Highlight the key differences (e.g., the `n` suffix).
    * **Decimal Handling (indirect):**  Acknowledge that JavaScript doesn't have a built-in arbitrary-precision *decimal* type. Mention libraries like `decimal.js` or `big.js` that provide this functionality. Connect the `AssignDecimalString` function to the need for such libraries in JS.

8. **Provide Concrete JavaScript Examples:** For each relevant C++ function category, provide a corresponding JavaScript example using `BigInt` (or mention the need for libraries for decimals). This makes the connection tangible.

9. **Explain the "Why":**  Briefly explain *why* V8 needs this `Bignum` class. It's used internally for parsing and representing numbers, especially during operations where precision is critical, even if the final JavaScript `Number` might be a floating-point value. This relates to how JavaScript engines handle numeric literals and intermediate calculations.

10. **Refine and Structure:** Organize the findings into a clear and logical summary. Start with a general overview, then delve into specifics, and finally provide the JavaScript connection. Use headings and bullet points for readability. Make sure the language is understandable to someone with a basic understanding of programming concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `Bignum` is only for very large *integers*.
* **Correction:** The presence of `AssignDecimalString` and the `exponent_` member suggests it can handle fractional parts as well, even if it's internally represented as an integer with a scaling factor. However, focus on the integer aspect when connecting to `BigInt`.
* **Consider the audience:** The request mentions "javascript的功能有关系," so prioritize making the JS connection clear and understandable. Don't get too bogged down in the low-level C++ details unless they are directly relevant to the JS comparison.
* **Ensure accuracy:** Double-check the JavaScript examples and the explanations of `BigInt` and its limitations.

By following these steps, iteratively analyzing the code, and actively seeking connections to JavaScript, we can arrive at a comprehensive and helpful answer.
这个 C++ 源代码文件 `bignum.cc` 定义了一个名为 `Bignum` 的类，其功能是**实现任意精度的整数运算**。  这意味着它可以表示和操作非常大的整数，超出标准 C++ 整型（如 `int`, `long long`）所能表示的范围。

**具体功能归纳:**

* **存储大整数:** `Bignum` 类使用一个 `Chunk` 类型的数组 `bigits_` 来存储大整数的各个“位”（bigits），每个 `Chunk` 可以存储一部分数字。 `used_digits_` 记录了实际使用的位数，`exponent_` 用于处理类似科学计数法的表示，可以理解为相对于最低位的偏移。
* **初始化和赋值:**
    * 提供默认构造函数。
    * 可以从 `uint16_t`, `uint64_t` 以及另一个 `Bignum` 对象赋值。
    * 可以从十进制字符串 (`AssignDecimalString`) 和十六进制字符串 (`AssignHexString`) 解析并赋值。
    * 可以将自身赋值为另一个 `Bignum` 对象 (`AssignBignum`)。
    * 可以计算一个小的无符号整数的幂 (`AssignPowerUInt16`)。
* **算术运算:**
    * **加法:** 提供 `AddUInt64` (与 `uint64_t` 相加) 和 `AddBignum` (与另一个 `Bignum` 相加)。
    * **减法:** 提供 `SubtractBignum` (减去另一个 `Bignum`) 和 `SubtractTimes` (减去另一个 `Bignum` 的若干倍)。
    * **乘法:** 提供 `MultiplyByUInt32`, `MultiplyByUInt64` (分别乘以 32 位和 64 位无符号整数), `MultiplyByPowerOfTen` (乘以 10 的幂), `Square` (计算平方)。
    * **除法与取模:** 提供 `DivideModuloIntBignum` (除以另一个 `Bignum` 并返回 16 位余数)。
* **位操作:** 提供 `ShiftLeft` (左移指定位数) 和内部使用的 `BigitsShiftLeft`。
* **比较:** 提供 `Compare` (比较两个 `Bignum` 的大小) 和 `PlusCompare` (比较 a + b 和 c 的大小)。
* **转换:** 提供 `ToHexString` (将 `Bignum` 转换为十六进制字符串)。
* **内部管理:** 提供 `Clamp` (清理尾部的零位), `Align` (对齐两个 `Bignum` 的指数), `Zero` (将 `Bignum` 置零), `EnsureCapacity` (确保 `bigits_` 数组有足够的容量)。

**与 JavaScript 的关系:**

`Bignum` 类在 V8 引擎中扮演着重要的角色，因为它负责处理 JavaScript 中**超出标准 IEEE 754 双精度浮点数 (Number 类型)** 表示范围的整数。  虽然 JavaScript 的 `Number` 类型使用 64 位浮点数，它可以精确表示的整数范围是有限的（大约 -2<sup>53</sup> 到 2<sup>53</sup>）。

当 JavaScript 代码中涉及到超出此范围的整数运算时，V8 内部会使用类似 `Bignum` 这样的机制来保证精度。  这通常发生在以下场景：

* **解析大整数常量:** 当 JavaScript 代码中出现非常大的整数常量时，V8 需要用 `Bignum` 来存储其准确的值。
* **位运算:** JavaScript 的位运算符（如 `|`, `&`, `^`, `<<`, `>>`, `>>>`）在操作大整数时，会将其转换为 32 位有符号整数。为了支持对超出 32 位范围的大整数进行精确的位运算，V8 内部可能使用 `Bignum`。
* **某些特定的内置函数:**  某些 JavaScript 内置函数在处理大整数时可能会依赖于内部的任意精度运算。

**JavaScript 示例:**

虽然 JavaScript 自身并没有直接暴露像 `Bignum` 这样的类，但 ES2020 引入了 `BigInt` 类型，它提供了对任意精度整数的支持。  `BigInt` 的功能与 `Bignum` 在概念上是相似的。

例如，在 JavaScript 中表示和操作超出 `Number` 安全整数范围的数字：

```javascript
// 使用 Number 类型，可能会丢失精度
let num1 = 9007199254740991;
let num2 = 9007199254740991 + 1;
console.log(num1 === num2); // 输出 true，因为 Number 无法精确表示这么大的连续整数

// 使用 BigInt 类型，可以保证精度
let bigInt1 = 9007199254740991n;
let bigInt2 = 9007199254740991n + 1n;
console.log(bigInt1 === bigInt2); // 输出 false，BigInt 可以区分这两个值

// BigInt 的加法和乘法
let sum = bigInt1 + bigInt2;
let product = bigInt1 * 1000n;

console.log(sum);     // 输出 18014398509481983n
console.log(product); // 输出 9007199254740991000n
```

在这个 JavaScript 示例中，`BigInt` 类型允许我们进行精确的大整数运算，这与 `Bignum` 在 V8 内部提供的功能是对应的。  V8 内部的 `Bignum` 可以被认为是 `BigInt` 在引擎底层的 C++ 实现基础。

**总结:**

`v8/src/base/numbers/bignum.cc` 文件中的 `Bignum` 类是 V8 引擎用于处理任意精度整数的关键组件。它提供了存储、初始化、算术运算、位操作和比较等功能，使得 V8 能够精确地处理 JavaScript 中超出标准 `Number` 类型范围的整数，而 JavaScript 的 `BigInt` 类型在很大程度上借鉴了这种思想。

Prompt: 
```
这是目录为v8/src/base/numbers/bignum.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/bignum.h"

#include "src/base/strings.h"

namespace v8 {
namespace base {

Bignum::Bignum()
    : bigits_(bigits_buffer_, kBigitCapacity), used_digits_(0), exponent_(0) {
  for (int i = 0; i < kBigitCapacity; ++i) {
    bigits_[i] = 0;
  }
}

template <typename S>
static int BitSize(S value) {
  return 8 * sizeof(value);
}

// Guaranteed to lie in one Bigit.
void Bignum::AssignUInt16(uint16_t value) {
  DCHECK_GE(kBigitSize, BitSize(value));
  Zero();
  if (value == 0) return;

  EnsureCapacity(1);
  bigits_[0] = value;
  used_digits_ = 1;
}

void Bignum::AssignUInt64(uint64_t value) {
  const int kUInt64Size = 64;

  Zero();
  if (value == 0) return;

  int needed_bigits = kUInt64Size / kBigitSize + 1;
  EnsureCapacity(needed_bigits);
  for (int i = 0; i < needed_bigits; ++i) {
    bigits_[i] = static_cast<Chunk>(value & kBigitMask);
    value = value >> kBigitSize;
  }
  used_digits_ = needed_bigits;
  Clamp();
}

void Bignum::AssignBignum(const Bignum& other) {
  exponent_ = other.exponent_;
  for (int i = 0; i < other.used_digits_; ++i) {
    bigits_[i] = other.bigits_[i];
  }
  // Clear the excess digits (if there were any).
  for (int i = other.used_digits_; i < used_digits_; ++i) {
    bigits_[i] = 0;
  }
  used_digits_ = other.used_digits_;
}

static uint64_t ReadUInt64(Vector<const char> buffer, int from,
                           int digits_to_read) {
  uint64_t result = 0;
  int to = from + digits_to_read;

  for (int i = from; i < to; ++i) {
    int digit = buffer[i] - '0';
    DCHECK(0 <= digit && digit <= 9);
    result = result * 10 + digit;
  }
  return result;
}

void Bignum::AssignDecimalString(Vector<const char> value) {
  // 2^64 = 18446744073709551616 > 10^19
  const int kMaxUint64DecimalDigits = 19;
  Zero();
  int length = value.length();
  int pos = 0;
  // Let's just say that each digit needs 4 bits.
  while (length >= kMaxUint64DecimalDigits) {
    uint64_t digits = ReadUInt64(value, pos, kMaxUint64DecimalDigits);
    pos += kMaxUint64DecimalDigits;
    length -= kMaxUint64DecimalDigits;
    MultiplyByPowerOfTen(kMaxUint64DecimalDigits);
    AddUInt64(digits);
  }
  uint64_t digits = ReadUInt64(value, pos, length);
  MultiplyByPowerOfTen(length);
  AddUInt64(digits);
  Clamp();
}

static int HexCharValue(char c) {
  if ('0' <= c && c <= '9') return c - '0';
  if ('a' <= c && c <= 'f') return 10 + c - 'a';
  if ('A' <= c && c <= 'F') return 10 + c - 'A';
  UNREACHABLE();
}

void Bignum::AssignHexString(Vector<const char> value) {
  Zero();
  int length = value.length();

  int needed_bigits = length * 4 / kBigitSize + 1;
  EnsureCapacity(needed_bigits);
  int string_index = length - 1;
  for (int i = 0; i < needed_bigits - 1; ++i) {
    // These bigits are guaranteed to be "full".
    Chunk current_bigit = 0;
    for (int j = 0; j < kBigitSize / 4; j++) {
      current_bigit += HexCharValue(value[string_index--]) << (j * 4);
    }
    bigits_[i] = current_bigit;
  }
  used_digits_ = needed_bigits - 1;

  Chunk most_significant_bigit = 0;  // Could be = 0;
  for (int j = 0; j <= string_index; ++j) {
    most_significant_bigit <<= 4;
    most_significant_bigit += HexCharValue(value[j]);
  }
  if (most_significant_bigit != 0) {
    bigits_[used_digits_] = most_significant_bigit;
    used_digits_++;
  }
  Clamp();
}

void Bignum::AddUInt64(uint64_t operand) {
  if (operand == 0) return;
  Bignum other;
  other.AssignUInt64(operand);
  AddBignum(other);
}

void Bignum::AddBignum(const Bignum& other) {
  DCHECK(IsClamped());
  DCHECK(other.IsClamped());

  // If this has a greater exponent than other append zero-bigits to this.
  // After this call exponent_ <= other.exponent_.
  Align(other);

  // There are two possibilities:
  //   aaaaaaaaaaa 0000  (where the 0s represent a's exponent)
  //     bbbbb 00000000
  //   ----------------
  //   ccccccccccc 0000
  // or
  //    aaaaaaaaaa 0000
  //  bbbbbbbbb 0000000
  //  -----------------
  //  cccccccccccc 0000
  // In both cases we might need a carry bigit.

  EnsureCapacity(1 + std::max(BigitLength(), other.BigitLength()) - exponent_);
  Chunk carry = 0;
  int bigit_pos = other.exponent_ - exponent_;
  DCHECK_GE(bigit_pos, 0);
  for (int i = 0; i < other.used_digits_; ++i) {
    Chunk sum = bigits_[bigit_pos] + other.bigits_[i] + carry;
    bigits_[bigit_pos] = sum & kBigitMask;
    carry = sum >> kBigitSize;
    bigit_pos++;
  }

  while (carry != 0) {
    Chunk sum = bigits_[bigit_pos] + carry;
    bigits_[bigit_pos] = sum & kBigitMask;
    carry = sum >> kBigitSize;
    bigit_pos++;
  }
  used_digits_ = std::max(bigit_pos, used_digits_);
  DCHECK(IsClamped());
}

void Bignum::SubtractBignum(const Bignum& other) {
  DCHECK(IsClamped());
  DCHECK(other.IsClamped());
  // We require this to be bigger than other.
  DCHECK(LessEqual(other, *this));

  Align(other);

  int offset = other.exponent_ - exponent_;
  Chunk borrow = 0;
  int i;
  for (i = 0; i < other.used_digits_; ++i) {
    DCHECK((borrow == 0) || (borrow == 1));
    Chunk difference = bigits_[i + offset] - other.bigits_[i] - borrow;
    bigits_[i + offset] = difference & kBigitMask;
    borrow = difference >> (kChunkSize - 1);
  }
  while (borrow != 0) {
    Chunk difference = bigits_[i + offset] - borrow;
    bigits_[i + offset] = difference & kBigitMask;
    borrow = difference >> (kChunkSize - 1);
    ++i;
  }
  Clamp();
}

void Bignum::ShiftLeft(int shift_amount) {
  if (used_digits_ == 0) return;
  exponent_ += shift_amount / kBigitSize;
  int local_shift = shift_amount % kBigitSize;
  EnsureCapacity(used_digits_ + 1);
  BigitsShiftLeft(local_shift);
}

void Bignum::MultiplyByUInt32(uint32_t factor) {
  if (factor == 1) return;
  if (factor == 0) {
    Zero();
    return;
  }
  if (used_digits_ == 0) return;

  // The product of a bigit with the factor is of size kBigitSize + 32.
  // Assert that this number + 1 (for the carry) fits into double chunk.
  DCHECK_GE(kDoubleChunkSize, kBigitSize + 32 + 1);
  DoubleChunk carry = 0;
  for (int i = 0; i < used_digits_; ++i) {
    DoubleChunk product = static_cast<DoubleChunk>(factor) * bigits_[i] + carry;
    bigits_[i] = static_cast<Chunk>(product & kBigitMask);
    carry = (product >> kBigitSize);
  }
  while (carry != 0) {
    EnsureCapacity(used_digits_ + 1);
    bigits_[used_digits_] = static_cast<Chunk>(carry & kBigitMask);
    used_digits_++;
    carry >>= kBigitSize;
  }
}

void Bignum::MultiplyByUInt64(uint64_t factor) {
  if (factor == 1) return;
  if (factor == 0) {
    Zero();
    return;
  }
  DCHECK_LT(kBigitSize, 32);
  uint64_t carry = 0;
  uint64_t low = factor & 0xFFFFFFFF;
  uint64_t high = factor >> 32;
  for (int i = 0; i < used_digits_; ++i) {
    uint64_t product_low = low * bigits_[i];
    uint64_t product_high = high * bigits_[i];
    uint64_t tmp = (carry & kBigitMask) + product_low;
    bigits_[i] = static_cast<Chunk>(tmp & kBigitMask);
    carry = (carry >> kBigitSize) + (tmp >> kBigitSize) +
            (product_high << (32 - kBigitSize));
  }
  while (carry != 0) {
    EnsureCapacity(used_digits_ + 1);
    bigits_[used_digits_] = static_cast<Chunk>(carry & kBigitMask);
    used_digits_++;
    carry >>= kBigitSize;
  }
}

void Bignum::MultiplyByPowerOfTen(int exponent) {
  const uint64_t kFive27 = 0x6765'C793'FA10'079D;
  const uint16_t kFive1 = 5;
  const uint16_t kFive2 = kFive1 * 5;
  const uint16_t kFive3 = kFive2 * 5;
  const uint16_t kFive4 = kFive3 * 5;
  const uint16_t kFive5 = kFive4 * 5;
  const uint16_t kFive6 = kFive5 * 5;
  const uint32_t kFive7 = kFive6 * 5;
  const uint32_t kFive8 = kFive7 * 5;
  const uint32_t kFive9 = kFive8 * 5;
  const uint32_t kFive10 = kFive9 * 5;
  const uint32_t kFive11 = kFive10 * 5;
  const uint32_t kFive12 = kFive11 * 5;
  const uint32_t kFive13 = kFive12 * 5;
  const uint32_t kFive1_to_12[] = {kFive1, kFive2,  kFive3,  kFive4,
                                   kFive5, kFive6,  kFive7,  kFive8,
                                   kFive9, kFive10, kFive11, kFive12};

  DCHECK_GE(exponent, 0);
  if (exponent == 0) return;
  if (used_digits_ == 0) return;

  // We shift by exponent at the end just before returning.
  int remaining_exponent = exponent;
  while (remaining_exponent >= 27) {
    MultiplyByUInt64(kFive27);
    remaining_exponent -= 27;
  }
  while (remaining_exponent >= 13) {
    MultiplyByUInt32(kFive13);
    remaining_exponent -= 13;
  }
  if (remaining_exponent > 0) {
    MultiplyByUInt32(kFive1_to_12[remaining_exponent - 1]);
  }
  ShiftLeft(exponent);
}

void Bignum::Square() {
  DCHECK(IsClamped());
  int product_length = 2 * used_digits_;
  EnsureCapacity(product_length);

  // Comba multiplication: compute each column separately.
  // Example: r = a2a1a0 * b2b1b0.
  //    r =  1    * a0b0 +
  //        10    * (a1b0 + a0b1) +
  //        100   * (a2b0 + a1b1 + a0b2) +
  //        1000  * (a2b1 + a1b2) +
  //        10000 * a2b2
  //
  // In the worst case we have to accumulate nb-digits products of digit*digit.
  //
  // Assert that the additional number of bits in a DoubleChunk are enough to
  // sum up used_digits of Bigit*Bigit.
  if ((1 << (2 * (kChunkSize - kBigitSize))) <= used_digits_) {
    UNIMPLEMENTED();
  }
  DoubleChunk accumulator = 0;
  // First shift the digits so we don't overwrite them.
  int copy_offset = used_digits_;
  for (int i = 0; i < used_digits_; ++i) {
    bigits_[copy_offset + i] = bigits_[i];
  }
  // We have two loops to avoid some 'if's in the loop.
  for (int i = 0; i < used_digits_; ++i) {
    // Process temporary digit i with power i.
    // The sum of the two indices must be equal to i.
    int bigit_index1 = i;
    int bigit_index2 = 0;
    // Sum all of the sub-products.
    while (bigit_index1 >= 0) {
      Chunk chunk1 = bigits_[copy_offset + bigit_index1];
      Chunk chunk2 = bigits_[copy_offset + bigit_index2];
      accumulator += static_cast<DoubleChunk>(chunk1) * chunk2;
      bigit_index1--;
      bigit_index2++;
    }
    bigits_[i] = static_cast<Chunk>(accumulator) & kBigitMask;
    accumulator >>= kBigitSize;
  }
  for (int i = used_digits_; i < product_length; ++i) {
    int bigit_index1 = used_digits_ - 1;
    int bigit_index2 = i - bigit_index1;
    // Invariant: sum of both indices is again equal to i.
    // Inner loop runs 0 times on last iteration, emptying accumulator.
    while (bigit_index2 < used_digits_) {
      Chunk chunk1 = bigits_[copy_offset + bigit_index1];
      Chunk chunk2 = bigits_[copy_offset + bigit_index2];
      accumulator += static_cast<DoubleChunk>(chunk1) * chunk2;
      bigit_index1--;
      bigit_index2++;
    }
    // The overwritten bigits_[i] will never be read in further loop iterations,
    // because bigit_index1 and bigit_index2 are always greater
    // than i - used_digits_.
    bigits_[i] = static_cast<Chunk>(accumulator) & kBigitMask;
    accumulator >>= kBigitSize;
  }
  // Since the result was guaranteed to lie inside the number the
  // accumulator must be 0 now.
  DCHECK_EQ(accumulator, 0);

  // Don't forget to update the used_digits and the exponent.
  used_digits_ = product_length;
  exponent_ *= 2;
  Clamp();
}

void Bignum::AssignPowerUInt16(uint16_t base, int power_exponent) {
  DCHECK_NE(base, 0);
  DCHECK_GE(power_exponent, 0);
  if (power_exponent == 0) {
    AssignUInt16(1);
    return;
  }
  Zero();
  int shifts = 0;
  // We expect base to be in range 2-32, and most often to be 10.
  // It does not make much sense to implement different algorithms for counting
  // the bits.
  while ((base & 1) == 0) {
    base >>= 1;
    shifts++;
  }
  int bit_size = 0;
  int tmp_base = base;
  while (tmp_base != 0) {
    tmp_base >>= 1;
    bit_size++;
  }
  int final_size = bit_size * power_exponent;
  // 1 extra bigit for the shifting, and one for rounded final_size.
  EnsureCapacity(final_size / kBigitSize + 2);

  // Left to Right exponentiation.
  int mask = 1;
  while (power_exponent >= mask) mask <<= 1;

  // The mask is now pointing to the bit above the most significant 1-bit of
  // power_exponent.
  // Get rid of first 1-bit;
  mask >>= 2;
  uint64_t this_value = base;

  bool delayed_multipliciation = false;
  const uint64_t max_32bits = 0xFFFFFFFF;
  while (mask != 0 && this_value <= max_32bits) {
    this_value = this_value * this_value;
    // Verify that there is enough space in this_value to perform the
    // multiplication.  The first bit_size bits must be 0.
    if ((power_exponent & mask) != 0) {
      uint64_t base_bits_mask =
          ~((static_cast<uint64_t>(1) << (64 - bit_size)) - 1);
      bool high_bits_zero = (this_value & base_bits_mask) == 0;
      if (high_bits_zero) {
        this_value *= base;
      } else {
        delayed_multipliciation = true;
      }
    }
    mask >>= 1;
  }
  AssignUInt64(this_value);
  if (delayed_multipliciation) {
    MultiplyByUInt32(base);
  }

  // Now do the same thing as a bignum.
  while (mask != 0) {
    Square();
    if ((power_exponent & mask) != 0) {
      MultiplyByUInt32(base);
    }
    mask >>= 1;
  }

  // And finally add the saved shifts.
  ShiftLeft(shifts * power_exponent);
}

// Precondition: this/other < 16bit.
uint16_t Bignum::DivideModuloIntBignum(const Bignum& other) {
  DCHECK(IsClamped());
  DCHECK(other.IsClamped());
  DCHECK_GT(other.used_digits_, 0);

  // Easy case: if we have less digits than the divisor than the result is 0.
  // Note: this handles the case where this == 0, too.
  if (BigitLength() < other.BigitLength()) {
    return 0;
  }

  Align(other);

  uint16_t result = 0;

  // Start by removing multiples of 'other' until both numbers have the same
  // number of digits.
  while (BigitLength() > other.BigitLength()) {
    // This naive approach is extremely inefficient if the this divided other
    // might be big. This function is implemented for doubleToString where
    // the result should be small (less than 10).
    DCHECK(other.bigits_[other.used_digits_ - 1] >= ((1 << kBigitSize) / 16));
    // Remove the multiples of the first digit.
    // Example this = 23 and other equals 9. -> Remove 2 multiples.
    result += bigits_[used_digits_ - 1];
    SubtractTimes(other, bigits_[used_digits_ - 1]);
  }

  DCHECK(BigitLength() == other.BigitLength());

  // Both bignums are at the same length now.
  // Since other has more than 0 digits we know that the access to
  // bigits_[used_digits_ - 1] is safe.
  Chunk this_bigit = bigits_[used_digits_ - 1];
  Chunk other_bigit = other.bigits_[other.used_digits_ - 1];

  if (other.used_digits_ == 1) {
    // Shortcut for easy (and common) case.
    int quotient = this_bigit / other_bigit;
    bigits_[used_digits_ - 1] = this_bigit - other_bigit * quotient;
    result += quotient;
    Clamp();
    return result;
  }

  int division_estimate = this_bigit / (other_bigit + 1);
  result += division_estimate;
  SubtractTimes(other, division_estimate);

  if (other_bigit * (division_estimate + 1) > this_bigit) {
    // No need to even try to subtract. Even if other's remaining digits were 0
    // another subtraction would be too much.
    return result;
  }

  while (LessEqual(other, *this)) {
    SubtractBignum(other);
    result++;
  }
  return result;
}

template <typename S>
static int SizeInHexChars(S number) {
  DCHECK_GT(number, 0);
  int result = 0;
  while (number != 0) {
    number >>= 4;
    result++;
  }
  return result;
}

bool Bignum::ToHexString(char* buffer, int buffer_size) const {
  DCHECK(IsClamped());
  // Each bigit must be printable as separate hex-character.
  DCHECK_EQ(kBigitSize % 4, 0);
  const int kHexCharsPerBigit = kBigitSize / 4;

  if (used_digits_ == 0) {
    if (buffer_size < 2) return false;
    buffer[0] = '0';
    buffer[1] = '\0';
    return true;
  }
  // We add 1 for the terminating '\0' character.
  int needed_chars = (BigitLength() - 1) * kHexCharsPerBigit +
                     SizeInHexChars(bigits_[used_digits_ - 1]) + 1;
  if (needed_chars > buffer_size) return false;
  int string_index = needed_chars - 1;
  buffer[string_index--] = '\0';
  for (int i = 0; i < exponent_; ++i) {
    for (int j = 0; j < kHexCharsPerBigit; ++j) {
      buffer[string_index--] = '0';
    }
  }
  for (int i = 0; i < used_digits_ - 1; ++i) {
    Chunk current_bigit = bigits_[i];
    for (int j = 0; j < kHexCharsPerBigit; ++j) {
      buffer[string_index--] = HexCharOfValue(current_bigit & 0xF);
      current_bigit >>= 4;
    }
  }
  // And finally the last bigit.
  Chunk most_significant_bigit = bigits_[used_digits_ - 1];
  while (most_significant_bigit != 0) {
    buffer[string_index--] = HexCharOfValue(most_significant_bigit & 0xF);
    most_significant_bigit >>= 4;
  }
  return true;
}

Bignum::Chunk Bignum::BigitAt(int index) const {
  if (index >= BigitLength()) return 0;
  if (index < exponent_) return 0;
  return bigits_[index - exponent_];
}

int Bignum::Compare(const Bignum& a, const Bignum& b) {
  DCHECK(a.IsClamped());
  DCHECK(b.IsClamped());
  int bigit_length_a = a.BigitLength();
  int bigit_length_b = b.BigitLength();
  if (bigit_length_a < bigit_length_b) return -1;
  if (bigit_length_a > bigit_length_b) return +1;
  for (int i = bigit_length_a - 1; i >= std::min(a.exponent_, b.exponent_);
       --i) {
    Chunk bigit_a = a.BigitAt(i);
    Chunk bigit_b = b.BigitAt(i);
    if (bigit_a < bigit_b) return -1;
    if (bigit_a > bigit_b) return +1;
    // Otherwise they are equal up to this digit. Try the next digit.
  }
  return 0;
}

int Bignum::PlusCompare(const Bignum& a, const Bignum& b, const Bignum& c) {
  DCHECK(a.IsClamped());
  DCHECK(b.IsClamped());
  DCHECK(c.IsClamped());
  if (a.BigitLength() < b.BigitLength()) {
    return PlusCompare(b, a, c);
  }
  if (a.BigitLength() + 1 < c.BigitLength()) return -1;
  if (a.BigitLength() > c.BigitLength()) return +1;
  // The exponent encodes 0-bigits. So if there are more 0-digits in 'a' than
  // 'b' has digits, then the bigit-length of 'a'+'b' must be equal to the one
  // of 'a'.
  if (a.exponent_ >= b.BigitLength() && a.BigitLength() < c.BigitLength()) {
    return -1;
  }

  Chunk borrow = 0;
  // Starting at min_exponent all digits are == 0. So no need to compare them.
  int min_exponent = std::min({a.exponent_, b.exponent_, c.exponent_});
  for (int i = c.BigitLength() - 1; i >= min_exponent; --i) {
    Chunk chunk_a = a.BigitAt(i);
    Chunk chunk_b = b.BigitAt(i);
    Chunk chunk_c = c.BigitAt(i);
    Chunk sum = chunk_a + chunk_b;
    if (sum > chunk_c + borrow) {
      return +1;
    } else {
      borrow = chunk_c + borrow - sum;
      if (borrow > 1) return -1;
      borrow <<= kBigitSize;
    }
  }
  if (borrow == 0) return 0;
  return -1;
}

void Bignum::Clamp() {
  while (used_digits_ > 0 && bigits_[used_digits_ - 1] == 0) {
    used_digits_--;
  }
  if (used_digits_ == 0) {
    // Zero.
    exponent_ = 0;
  }
}

bool Bignum::IsClamped() const {
  return used_digits_ == 0 || bigits_[used_digits_ - 1] != 0;
}

void Bignum::Zero() {
  for (int i = 0; i < used_digits_; ++i) {
    bigits_[i] = 0;
  }
  used_digits_ = 0;
  exponent_ = 0;
}

void Bignum::Align(const Bignum& other) {
  if (exponent_ > other.exponent_) {
    // If "X" represents a "hidden" digit (by the exponent) then we are in the
    // following case (a == this, b == other):
    // a:  aaaaaaXXXX   or a:   aaaaaXXX
    // b:     bbbbbbX      b: bbbbbbbbXX
    // We replace some of the hidden digits (X) of a with 0 digits.
    // a:  aaaaaa000X   or a:   aaaaa0XX
    int zero_digits = exponent_ - other.exponent_;
    EnsureCapacity(used_digits_ + zero_digits);
    for (int i = used_digits_ - 1; i >= 0; --i) {
      bigits_[i + zero_digits] = bigits_[i];
    }
    for (int i = 0; i < zero_digits; ++i) {
      bigits_[i] = 0;
    }
    used_digits_ += zero_digits;
    exponent_ -= zero_digits;
    DCHECK_GE(used_digits_, 0);
    DCHECK_GE(exponent_, 0);
  }
}

void Bignum::BigitsShiftLeft(int shift_amount) {
  DCHECK_LT(shift_amount, kBigitSize);
  DCHECK_GE(shift_amount, 0);
  Chunk carry = 0;
  for (int i = 0; i < used_digits_; ++i) {
    Chunk new_carry = bigits_[i] >> (kBigitSize - shift_amount);
    bigits_[i] = ((bigits_[i] << shift_amount) + carry) & kBigitMask;
    carry = new_carry;
  }
  if (carry != 0) {
    bigits_[used_digits_] = carry;
    used_digits_++;
  }
}

void Bignum::SubtractTimes(const Bignum& other, int factor) {
#ifdef DEBUG
  Bignum a, b;
  a.AssignBignum(*this);
  b.AssignBignum(other);
  b.MultiplyByUInt32(factor);
  a.SubtractBignum(b);
#endif
  DCHECK(exponent_ <= other.exponent_);
  if (factor < 3) {
    for (int i = 0; i < factor; ++i) {
      SubtractBignum(other);
    }
    return;
  }
  Chunk borrow = 0;
  int exponent_diff = other.exponent_ - exponent_;
  for (int i = 0; i < other.used_digits_; ++i) {
    DoubleChunk product = static_cast<DoubleChunk>(factor) * other.bigits_[i];
    DoubleChunk remove = borrow + product;
    Chunk difference =
        bigits_[i + exponent_diff] - static_cast<Chunk>(remove & kBigitMask);
    bigits_[i + exponent_diff] = difference & kBigitMask;
    borrow = static_cast<Chunk>((difference >> (kChunkSize - 1)) +
                                (remove >> kBigitSize));
  }
  for (int i = other.used_digits_ + exponent_diff; i < used_digits_; ++i) {
    if (borrow == 0) return;
    Chunk difference = bigits_[i] - borrow;
    bigits_[i] = difference & kBigitMask;
    borrow = difference >> (kChunkSize - 1);
  }
  Clamp();
  DCHECK(Bignum::Equal(a, *this));
}

}  // namespace base
}  // namespace v8

"""

```