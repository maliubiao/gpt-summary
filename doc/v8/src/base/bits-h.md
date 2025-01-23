Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Identification:**

   - The first thing I notice is the header guard (`#ifndef V8_BASE_BITS_H_ ... #endif`). This confirms it's a header file.
   - The copyright notice indicates it belongs to the V8 project.
   - Includes like `<stdint.h>` and `<type_traits>` suggest it deals with low-level operations on data types. The presence of `<intrin.h>` (for MSVC) and `win32-headers.h` hints at platform-specific optimizations or functionalities.
   - The `namespace v8 { namespace base { namespace bits { ... }}}` structure clearly indicates its purpose: providing bit manipulation utilities within the V8 engine's base library.

2. **Categorizing the Functions:**

   - I start reading through the functions and try to group them based on their apparent purpose. This immediately reveals several categories:
      - **Counting Bits:** `CountPopulation`, `CountLeadingZeros`, `CountTrailingZeros`, `CountLeadingSignBits`.
      - **Bit/Byte Reversal:** `ReverseBits`, `ReverseBytes`.
      - **Type Conversion:** `Unsigned`, `Signed`.
      - **Power of Two Checks/Manipulation:** `IsPowerOfTwo`, `WhichPowerOfTwo`, `RoundUpToPowerOfTwo32/64`, `RoundDownToPowerOfTwo32`.
      - **Bit Rotation:** `RotateRight32/64`, `RotateLeft32/64`.
      - **Overflow Checking Arithmetic:** `SignedAddOverflow32/64`, `SignedSubOverflow32/64`, `SignedMulOverflow32/64`, `UnsignedAddOverflow32`.
      - **Extended Precision Multiplication:** `SignedMulHigh32/64`, `UnsignedMulHigh32/64`, `SignedMulHighAndAdd32`.
      - **Division and Modulo:** `SignedDiv32/64`, `SignedMod32/64`, `UnsignedDiv32/64`, `UnsignedMod32/64`.
      - **Wraparound Arithmetic:** `WraparoundAdd32`, `WraparoundNeg32`.
      - **Saturated Arithmetic:** `SignedSaturatedAdd64`, `SignedSaturatedSub64`.
      - **Bit Width:** `BitWidth`.

3. **Analyzing Individual Functions (and identifying potential JavaScript relevance):**

   - For each function, I try to understand its core functionality:
     - **`CountPopulation`:**  Clearly counts set bits. This relates to JavaScript's bitwise operations and can be useful in scenarios where you need to know how many flags are set.
     - **`ReverseBits` and `ReverseBytes`:** These are straightforward bit and byte reversal operations. Less direct relevance to typical JavaScript, but could be used in specific algorithms (e.g., networking protocols, data serialization).
     - **`CountLeadingZeros` and `CountTrailingZeros`:**  Useful for bit manipulation and potentially for optimizing certain algorithms. Again, less direct JavaScript relevance but could be used in implementing low-level functionality.
     - **`IsPowerOfTwo` and `RoundUpToPowerOfTwo`:**  Common operations, especially in memory allocation, data structures (like hash tables), and graphics. JavaScript doesn't have direct equivalents but the *concept* is used in sizing things.
     - **Rotation functions:** Used in cryptography, hashing algorithms, and low-level data manipulation. Less direct JavaScript connection.
     - **Overflow checking functions:** Very important for ensuring the correctness of arithmetic operations, particularly in languages without built-in arbitrary precision integers like JavaScript. While JavaScript handles overflow differently (wraps around or uses Infinity), the *concept* of overflow is crucial for understanding integer limits.
     - **Extended multiplication functions:**  Useful when you need the full result of a multiplication that might exceed the standard integer size. Less direct JavaScript relevance.
     - **Division and modulo functions:**  Directly correspond to JavaScript's `/` and `%` operators. The header clarifies the behavior for division by zero, which is important.
     - **Wraparound arithmetic:**  This explains how V8 handles arithmetic overflows internally (wrapping around). While JavaScript has its own overflow behavior, understanding wraparound is essential in low-level programming.
     - **Saturated arithmetic:**  This is less common in standard JavaScript but can be relevant in contexts like audio or image processing where you want to clamp values.
     - **`BitWidth`:** Useful for determining the number of bits needed to represent a value. Relates to JavaScript's integer representation.

4. **Considering `.tq` extension:**

   - The prompt specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for implementing built-in functions and runtime code is crucial here. If the file *were* `bits.tq`, it would mean these functions are implemented using Torque, likely for performance reasons or to interact directly with V8's internals.

5. **Generating JavaScript Examples:**

   - For functions with clear JavaScript equivalents or related concepts, I formulate simple examples to illustrate the connection. This involves thinking about how these low-level bit manipulations translate to higher-level JavaScript operations or scenarios.

6. **Code Logic Reasoning and Examples:**

   - For functions with more complex logic (like `CountPopulation` or `RoundUpToPowerOfTwo`), I think about:
     - **Assumptions:** What are the valid inputs? What are the constraints?
     - **Steps:** How does the algorithm work?
     - **Illustrative examples:**  Pick a simple input and trace the execution to demonstrate the output.

7. **Identifying Common Programming Errors:**

   - Based on the function names and their purpose, I can infer potential pitfalls:
     - **Overflow:**  A major concern with fixed-size integers.
     - **Division by zero:**  Specifically addressed in the division functions.
     - **Incorrect bit manipulation:**  Shifting by too much, misunderstanding bitwise operators.
     - **Assuming two's complement:** While most systems use two's complement, it's a good point to mention.

8. **Structuring the Output:**

   - I organize the information logically:
     - Start with the file purpose.
     - Address the `.tq` extension question.
     - Provide detailed explanations of each function category.
     - Include JavaScript examples where relevant.
     - Give concrete examples of code logic reasoning.
     - Highlight common programming errors.

9. **Refinement and Review:**

   - I reread the generated output to ensure clarity, accuracy, and completeness. I check for any inconsistencies or areas where more explanation might be needed. For instance, initially, I might have just said "counts set bits" for `CountPopulation`, but then I expand on *how* it does it (built-in vs. fallback).

This iterative process of scanning, categorizing, analyzing, connecting to JavaScript, providing examples, and refining helps in generating a comprehensive and informative response about the functionality of the C++ header file.
This C++ header file `v8/src/base/bits.h` provides a collection of utility functions for performing bitwise operations and other low-level manipulations on integer types. Let's break down its functionality:

**Core Functionality:**

* **Bit Counting:**
    * `CountPopulation(value)`: Counts the number of set bits (bits with a value of 1) in an unsigned integer.
    * `CountLeadingZeros(value)`: Counts the number of leading zero bits before the most significant set bit.
    * `CountTrailingZeros(value)`: Counts the number of trailing zero bits after the least significant set bit.
    * `CountLeadingSignBits(value)`: Counts the number of leading sign bits (0 for positive, 1 for negative).

* **Bit/Byte Reversal:**
    * `ReverseBits(value)`: Reverses the order of bits within an integer.
    * `ReverseBytes(value)`: Reverses the order of bytes within an integer.

* **Type Conversion (related to signedness):**
    * `Unsigned(value)`: Converts a signed integer to its unsigned equivalent.
    * `Signed(value)`: Converts an unsigned integer to its signed equivalent.

* **Power of Two Operations:**
    * `IsPowerOfTwo(value)`: Checks if a number is a power of two.
    * `WhichPowerOfTwo(value)`:  Returns the exponent (which power of 2) if the number is a power of two.
    * `RoundUpToPowerOfTwo32/64(value)`: Rounds a number up to the nearest power of two.
    * `RoundDownToPowerOfTwo32(value)`: Rounds a number down to the nearest power of two.

* **Bit Rotation:**
    * `RotateRight32/64(value, shift)`: Rotates the bits of an integer to the right by a specified number of positions.
    * `RotateLeft32/64(value, shift)`: Rotates the bits of an integer to the left by a specified number of positions.

* **Overflow Detection for Arithmetic Operations:**
    * `SignedAddOverflow32/64(lhs, rhs, val*)`: Performs signed addition and detects overflow, storing the result in `val`.
    * `SignedSubOverflow32/64(lhs, rhs, val*)`: Performs signed subtraction and detects overflow, storing the result in `val`.
    * `SignedMulOverflow32/64(lhs, rhs, val*)`: Performs signed multiplication and detects overflow, storing the result in `val`.
    * `UnsignedAddOverflow32(lhs, rhs, val*)`: Performs unsigned addition and detects overflow, storing the result in `val`.

* **Extended Precision Multiplication (returning high bits):**
    * `SignedMulHigh32/64(lhs, rhs)`: Multiplies two signed integers and returns the most significant bits of the result.
    * `UnsignedMulHigh32/64(lhs, rhs)`: Multiplies two unsigned integers and returns the most significant bits of the result.
    * `SignedMulHighAndAdd32(lhs, rhs, acc)`: Multiplies two signed integers, takes the high bits, and adds an accumulator.

* **Division and Modulo Operations with Specific Handling:**
    * `SignedDiv32/64(lhs, rhs)`: Performs signed division with specific behavior for division by zero and the case of dividing the minimum integer by -1.
    * `SignedMod32/64(lhs, rhs)`: Performs signed modulo with specific behavior for division by zero and the case of dividing the minimum integer by -1.
    * `UnsignedDiv32/64(lhs, rhs)`: Performs unsigned division with specific behavior for division by zero.
    * `UnsignedMod32/64(lhs, rhs)`: Performs unsigned modulo with specific behavior for division by zero.

* **Wraparound Arithmetic:**
    * `WraparoundAdd32(lhs, rhs)`: Performs addition with wraparound behavior (like unsigned addition).
    * `WraparoundNeg32(x)`: Performs negation with wraparound behavior.

* **Saturated Arithmetic:**
    * `SignedSaturatedAdd64(lhs, rhs)`: Performs signed addition, clamping the result to the maximum or minimum representable value on overflow.
    * `SignedSaturatedSub64(lhs, rhs)`: Performs signed subtraction, clamping the result on overflow.

* **Bit Width Calculation:**
    * `BitWidth(x)`: Returns the number of bits required to represent the integer `x`.

**Is `v8/src/base/bits.h` a Torque file?**

No, the file extension is `.h`, which is the standard extension for C++ header files. If it were a Torque file, its extension would be `.tq`.

**Relationship to JavaScript and Examples:**

Many of the functionalities in `bits.h` are directly related to how JavaScript engines (like V8) handle numbers at a low level. JavaScript numbers are typically represented as double-precision floating-point values, but internally, V8 needs to perform integer operations for various tasks, including:

* **Array indexing:** Accessing elements in arrays.
* **Bitwise operators:** JavaScript supports bitwise operators (`&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`).
* **Memory management:**  Calculating sizes and offsets.
* **Low-level optimizations:**  Certain operations can be optimized using bit manipulation.

Here are some examples of how the functions in `bits.h` relate to JavaScript concepts:

**1. `CountPopulation` (Counting Set Bits):**

While JavaScript doesn't have a direct equivalent function, you can achieve this using bitwise operations and loops:

```javascript
function countSetBits(n) {
  let count = 0;
  while (n > 0) {
    count += (n & 1); // Check the last bit
    n >>= 1;         // Right shift to check the next bit
  }
  return count;
}

console.log(countSetBits(7)); // Output: 3 (binary 0111)
console.log(countSetBits(10)); // Output: 2 (binary 1010)
```

Internally, V8 might use an optimized `CountPopulation` implementation (potentially from `bits.h`) for performance when dealing with bitmasks or flags.

**2. `IsPowerOfTwo`:**

JavaScript doesn't have a built-in function for this, but it's a common check:

```javascript
function isPowerOfTwo(n) {
  return (n > 0) && ((n & (n - 1)) === 0);
}

console.log(isPowerOfTwo(8));   // Output: true
console.log(isPowerOfTwo(10));  // Output: false
```

V8 might use `IsPowerOfTwo` when allocating memory for data structures that benefit from power-of-two sizes (e.g., hash tables).

**3. Bitwise Operators and `RotateLeft/Right`:**

JavaScript has bitwise left shift (`<<`) and right shift (`>>`, `>>>`) operators. While it doesn't have direct rotate operators, the concept is used in cryptographic algorithms and other low-level manipulations:

```javascript
function rotateLeft(n, bits) {
  return (n << bits) | (n >>> (32 - bits)); // Assuming 32-bit integer
}

function rotateRight(n, bits) {
  return (n >>> bits) | (n << (32 - bits)); // Assuming 32-bit integer
}

console.log(rotateLeft(1, 1));  // Output: 2
console.log(rotateRight(2, 1)); // Output: 1
```

V8's implementation of bitwise operators likely relies on optimized bit manipulation functions similar to those in `bits.h`.

**4. Overflow Detection:**

JavaScript's number type is a double-precision floating-point, so it doesn't have the same kind of integer overflow as fixed-size integers in C++. However, when performing bitwise operations, JavaScript internally treats numbers as 32-bit integers, and overflow can occur in that context.

```javascript
let maxInt32 = 2147483647;
console.log(maxInt32 + 1); // Output: -2147483648 (wraparound due to 32-bit integer behavior)
```

The `SignedAddOverflow32` and similar functions in `bits.h` are crucial for V8's internal workings when it needs to perform arithmetic on fixed-size integers and ensure correctness.

**Code Logic Reasoning (Example: `CountPopulation`):**

**Algorithm (Fallback Implementation):**

The fallback implementation of `CountPopulation` uses a divide-and-conquer approach based on "Hacker's Delight":

1. **Pairwise Addition:** It starts by adding adjacent bits together. For example, if you have `0b0110`, it becomes `0b01 01`.
2. **Iterative Merging:**  It repeats this process, merging groups of bits and accumulating the counts. The masks (`0x55...`, `0x33...`, `0x0f...`) are used to isolate the relevant bits during the additions.

**Hypothetical Input and Output:**

**Input:** `value = 0b10110100` (decimal 180)

**Steps:**

1. `value = ((value >> 1) & mask[0]) + (value & mask[0]);`
   - `value >> 1`: `0b01011010`
   - `value & mask[0]`: `0b00010000` (mask[0] = `0x55...` isolates odd bits)
   - Result: `0b01 + 00  01 + 01  10 + 00  10 + 00` = `0b01 02 02 00` (Conceptual, operates on pairs)

2. `value = ((value >> 2) & mask[1]) + (value & mask[1]);`
   - `value >> 2`: (roughly) shifts pairs by 2
   - `value & mask[1]`: isolates pairs
   - Result: Adds adjacent pairs

3. ... and so on until the count is accumulated.

**Output:** `CountPopulation(0b10110100)` would return `4` (four set bits).

**Common Programming Errors:**

* **Integer Overflow:**  Performing arithmetic operations that exceed the maximum or minimum value representable by the integer type. The overflow detection functions in `bits.h` are designed to help prevent or detect these errors.
    ```c++
    int32_t max_int = std::numeric_limits<int32_t>::max();
    int32_t result;
    if (v8::base::bits::SignedAddOverflow32(max_int, 1, &result)) {
      // Handle overflow
      std::cerr << "Overflow occurred!" << std::endl;
    } else {
      std::cout << "Result: " << result << std::endl; // Would not reach here due to overflow
    }
    ```

* **Incorrect Bitwise Operations:**  Misunderstanding the behavior of bitwise operators (`&`, `|`, `^`, `~`, `<<`, `>>`). For example, using logical AND (`&&`) instead of bitwise AND (`&`).
    ```c++
    uint8_t a = 0b00001111;
    uint8_t b = 0b11110000;
    uint8_t wrong_and = a && b; // Logical AND, result is 1 (true)
    uint8_t correct_and = a & b; // Bitwise AND, result is 0b00000000 (0)
    ```

* **Off-by-One Errors in Bit Shifting/Rotation:** Shifting or rotating by the wrong number of bits can lead to unexpected results.

* **Assuming Two's Complement:** While most modern systems use two's complement for representing negative numbers, it's a detail to be aware of when working with bitwise operations on signed integers.

In summary, `v8/src/base/bits.h` is a foundational header file in the V8 JavaScript engine, providing essential low-level bit manipulation utilities that are crucial for its performance and correct operation. It is a C++ header file, not a Torque file. Its functionalities are closely related to how JavaScript engines handle numbers and perform bitwise operations internally.

### 提示词
```
这是目录为v8/src/base/bits.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/bits.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_BITS_H_
#define V8_BASE_BITS_H_

#include <stdint.h>
#include <type_traits>

#include "src/base/base-export.h"
#include "src/base/macros.h"
#if V8_CC_MSVC
#include <intrin.h>
#endif
#if V8_OS_WIN32
#include "src/base/win32-headers.h"
#endif

namespace v8 {
namespace base {
namespace bits {

// CountPopulation(value) returns the number of bits set in |value|.
template <typename T>
constexpr inline
    typename std::enable_if<std::is_unsigned<T>::value && sizeof(T) <= 8,
                            unsigned>::type
    CountPopulation(T value) {
  static_assert(sizeof(T) <= 8);
#if V8_HAS_BUILTIN_POPCOUNT
  return sizeof(T) == 8 ? __builtin_popcountll(static_cast<uint64_t>(value))
                        : __builtin_popcount(static_cast<uint32_t>(value));
#else
  // Fall back to divide-and-conquer popcount (see "Hacker's Delight" by Henry
  // S. Warren, Jr.), chapter 5-1.
  constexpr uint64_t mask[] = {0x5555555555555555, 0x3333333333333333,
                               0x0f0f0f0f0f0f0f0f};
  // Start with 64 buckets of 1 bits, holding values from [0,1].
  value = ((value >> 1) & mask[0]) + (value & mask[0]);
  // Having 32 buckets of 2 bits, holding values from [0,2] now.
  value = ((value >> 2) & mask[1]) + (value & mask[1]);
  // Having 16 buckets of 4 bits, holding values from [0,4] now.
  value = ((value >> 4) & mask[2]) + (value & mask[2]);
  // Having 8 buckets of 8 bits, holding values from [0,8] now.
  // From this point on, the buckets are bigger than the number of bits
  // required to hold the values, and the buckets are bigger the maximum
  // result, so there's no need to mask value anymore, since there's no
  // more risk of overflow between buckets.
  if (sizeof(T) > 1) value = (value >> (sizeof(T) > 1 ? 8 : 0)) + value;
  // Having 4 buckets of 16 bits, holding values from [0,16] now.
  if (sizeof(T) > 2) value = (value >> (sizeof(T) > 2 ? 16 : 0)) + value;
  // Having 2 buckets of 32 bits, holding values from [0,32] now.
  if (sizeof(T) > 4) value = (value >> (sizeof(T) > 4 ? 32 : 0)) + value;
  // Having 1 buckets of 64 bits, holding values from [0,64] now.
  return static_cast<unsigned>(value & 0xff);
#endif
}

// ReverseBits(value) returns |value| in reverse bit order.
template <typename T>
T ReverseBits(T value) {
  static_assert((sizeof(value) == 1) || (sizeof(value) == 2) ||
                (sizeof(value) == 4) || (sizeof(value) == 8));
  T result = 0;
  for (unsigned i = 0; i < (sizeof(value) * 8); i++) {
    result = (result << 1) | (value & 1);
    value >>= 1;
  }
  return result;
}

// ReverseBytes(value) returns |value| in reverse byte order.
template <typename T>
T ReverseBytes(T value) {
  static_assert((sizeof(value) == 1) || (sizeof(value) == 2) ||
                (sizeof(value) == 4) || (sizeof(value) == 8));
  T result = 0;
  for (unsigned i = 0; i < sizeof(value); i++) {
    result = (result << 8) | (value & 0xff);
    value >>= 8;
  }
  return result;
}

template <class T>
inline constexpr std::make_unsigned_t<T> Unsigned(T value) {
  static_assert(std::is_signed_v<T>);
  return static_cast<std::make_unsigned_t<T>>(value);
}
template <class T>
inline constexpr std::make_signed_t<T> Signed(T value) {
  static_assert(std::is_unsigned_v<T>);
  return static_cast<std::make_signed_t<T>>(value);
}

// CountLeadingZeros(value) returns the number of zero bits following the most
// significant 1 bit in |value| if |value| is non-zero, otherwise it returns
// {sizeof(T) * 8}.
template <typename T, unsigned bits = sizeof(T) * 8>
inline constexpr
    typename std::enable_if<std::is_unsigned<T>::value && sizeof(T) <= 8,
                            unsigned>::type
    CountLeadingZeros(T value) {
  static_assert(bits > 0, "invalid instantiation");
#if V8_HAS_BUILTIN_CLZ
  return value == 0
             ? bits
             : bits == 64
                   ? __builtin_clzll(static_cast<uint64_t>(value))
                   : __builtin_clz(static_cast<uint32_t>(value)) - (32 - bits);
#else
  // Binary search algorithm taken from "Hacker's Delight" (by Henry S. Warren,
  // Jr.), figures 5-11 and 5-12.
  if (bits == 1) return static_cast<unsigned>(value) ^ 1;
  T upper_half = value >> (bits / 2);
  T next_value = upper_half != 0 ? upper_half : value;
  unsigned add = upper_half != 0 ? 0 : bits / 2;
  constexpr unsigned next_bits = bits == 1 ? 1 : bits / 2;
  return CountLeadingZeros<T, next_bits>(next_value) + add;
#endif
}

inline constexpr unsigned CountLeadingZeros32(uint32_t value) {
  return CountLeadingZeros(value);
}
inline constexpr unsigned CountLeadingZeros64(uint64_t value) {
  return CountLeadingZeros(value);
}

// The number of leading zeros for a positive number,
// the number of leading ones for a negative number.
template <class T>
constexpr unsigned CountLeadingSignBits(T value) {
  static_assert(std::is_signed_v<T>);
  return value < 0 ? CountLeadingZeros(~Unsigned(value))
                   : CountLeadingZeros(Unsigned(value));
}

// CountTrailingZeros(value) returns the number of zero bits preceding the
// least significant 1 bit in |value| if |value| is non-zero, otherwise it
// returns {sizeof(T) * 8}.
// See CountTrailingZerosNonZero for an optimized version for the case that
// |value| is guaranteed to be non-zero.
template <typename T, unsigned bits = sizeof(T) * 8>
inline constexpr
    typename std::enable_if<std::is_integral<T>::value && sizeof(T) <= 8,
                            unsigned>::type
    CountTrailingZeros(T value) {
#if V8_HAS_BUILTIN_CTZ
  return value == 0 ? bits
                    : bits == 64 ? __builtin_ctzll(static_cast<uint64_t>(value))
                                 : __builtin_ctz(static_cast<uint32_t>(value));
#else
  // Fall back to popcount (see "Hacker's Delight" by Henry S. Warren, Jr.),
  // chapter 5-4. On x64, since is faster than counting in a loop and faster
  // than doing binary search.
  using U = typename std::make_unsigned<T>::type;
  U u = value;
  return CountPopulation(static_cast<U>(~u & (u - 1u)));
#endif
}

inline constexpr unsigned CountTrailingZeros32(uint32_t value) {
  return CountTrailingZeros(value);
}
inline constexpr unsigned CountTrailingZeros64(uint64_t value) {
  return CountTrailingZeros(value);
}

// CountTrailingZerosNonZero(value) returns the number of zero bits preceding
// the least significant 1 bit in |value| if |value| is non-zero, otherwise the
// behavior is undefined.
// See CountTrailingZeros for an alternative version that allows |value| == 0.
template <typename T, unsigned bits = sizeof(T) * 8>
inline constexpr
    typename std::enable_if<std::is_integral<T>::value && sizeof(T) <= 8,
                            unsigned>::type
    CountTrailingZerosNonZero(T value) {
  DCHECK_NE(0, value);
#if V8_HAS_BUILTIN_CTZ
  return bits == 64 ? __builtin_ctzll(static_cast<uint64_t>(value))
                    : __builtin_ctz(static_cast<uint32_t>(value));
#else
  return CountTrailingZeros<T, bits>(value);
#endif
}

// Returns true iff |value| is a power of 2.
template <typename T,
          typename = typename std::enable_if<std::is_integral<T>::value ||
                                             std::is_enum<T>::value>::type>
constexpr inline bool IsPowerOfTwo(T value) {
  return value > 0 && (value & (value - 1)) == 0;
}

// Identical to {CountTrailingZeros}, but only works for powers of 2.
template <typename T,
          typename = typename std::enable_if<std::is_integral<T>::value>::type>
inline constexpr int WhichPowerOfTwo(T value) {
  DCHECK(IsPowerOfTwo(value));
#if V8_HAS_BUILTIN_CTZ
  static_assert(sizeof(T) <= 8);
  return sizeof(T) == 8 ? __builtin_ctzll(static_cast<uint64_t>(value))
                        : __builtin_ctz(static_cast<uint32_t>(value));
#else
  // Fall back to popcount (see "Hacker's Delight" by Henry S. Warren, Jr.),
  // chapter 5-4. On x64, since is faster than counting in a loop and faster
  // than doing binary search.
  using U = typename std::make_unsigned<T>::type;
  U u = value;
  return CountPopulation(static_cast<U>(u - 1));
#endif
}

// RoundUpToPowerOfTwo32(value) returns the smallest power of two which is
// greater than or equal to |value|. If you pass in a |value| that is already a
// power of two, it is returned as is. |value| must be less than or equal to
// 0x80000000u. Uses computation based on leading zeros if we have compiler
// support for that. Falls back to the implementation from "Hacker's Delight" by
// Henry S. Warren, Jr., figure 3-3, page 48, where the function is called clp2.
V8_BASE_EXPORT constexpr uint32_t RoundUpToPowerOfTwo32(uint32_t value) {
  DCHECK_LE(value, uint32_t{1} << 31);
  if (value) --value;
// Use computation based on leading zeros if we have compiler support for that.
#if V8_HAS_BUILTIN_CLZ || V8_CC_MSVC
  return 1u << (32 - CountLeadingZeros(value));
#else
  value |= value >> 1;
  value |= value >> 2;
  value |= value >> 4;
  value |= value >> 8;
  value |= value >> 16;
  return value + 1;
#endif
}
// Same for 64 bit integers. |value| must be <= 2^63
V8_BASE_EXPORT constexpr uint64_t RoundUpToPowerOfTwo64(uint64_t value) {
  DCHECK_LE(value, uint64_t{1} << 63);
  if (value) --value;
// Use computation based on leading zeros if we have compiler support for that.
#if V8_HAS_BUILTIN_CLZ
  return uint64_t{1} << (64 - CountLeadingZeros(value));
#else
  value |= value >> 1;
  value |= value >> 2;
  value |= value >> 4;
  value |= value >> 8;
  value |= value >> 16;
  value |= value >> 32;
  return value + 1;
#endif
}
// Same for size_t integers.
inline constexpr size_t RoundUpToPowerOfTwo(size_t value) {
  if (sizeof(size_t) == sizeof(uint64_t)) {
    return RoundUpToPowerOfTwo64(value);
  } else {
    // Without windows.h included this line triggers a truncation warning on
    // 64-bit builds. Presumably windows.h disables the relevant warning.
    return RoundUpToPowerOfTwo32(static_cast<uint32_t>(value));
  }
}

// RoundDownToPowerOfTwo32(value) returns the greatest power of two which is
// less than or equal to |value|. If you pass in a |value| that is already a
// power of two, it is returned as is.
inline uint32_t RoundDownToPowerOfTwo32(uint32_t value) {
  if (value > 0x80000000u) return 0x80000000u;
  uint32_t result = RoundUpToPowerOfTwo32(value);
  if (result > value) result >>= 1;
  return result;
}


// Precondition: 0 <= shift < 32
inline constexpr uint32_t RotateRight32(uint32_t value, uint32_t shift) {
  return (value >> shift) | (value << ((32 - shift) & 31));
}

// Precondition: 0 <= shift < 32
inline constexpr uint32_t RotateLeft32(uint32_t value, uint32_t shift) {
  return (value << shift) | (value >> ((32 - shift) & 31));
}

// Precondition: 0 <= shift < 64
inline constexpr uint64_t RotateRight64(uint64_t value, uint64_t shift) {
  return (value >> shift) | (value << ((64 - shift) & 63));
}

// Precondition: 0 <= shift < 64
inline constexpr uint64_t RotateLeft64(uint64_t value, uint64_t shift) {
  return (value << shift) | (value >> ((64 - shift) & 63));
}

// SignedAddOverflow32(lhs,rhs,val) performs a signed summation of |lhs| and
// |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed summation resulted in an overflow.
inline bool SignedAddOverflow32(int32_t lhs, int32_t rhs, int32_t* val) {
#if V8_HAS_BUILTIN_SADD_OVERFLOW
  return __builtin_sadd_overflow(lhs, rhs, val);
#else
  uint32_t res = static_cast<uint32_t>(lhs) + static_cast<uint32_t>(rhs);
  *val = base::bit_cast<int32_t>(res);
  return ((res ^ lhs) & (res ^ rhs) & (1U << 31)) != 0;
#endif
}


// SignedSubOverflow32(lhs,rhs,val) performs a signed subtraction of |lhs| and
// |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed subtraction resulted in an overflow.
inline bool SignedSubOverflow32(int32_t lhs, int32_t rhs, int32_t* val) {
#if V8_HAS_BUILTIN_SSUB_OVERFLOW
  return __builtin_ssub_overflow(lhs, rhs, val);
#else
  uint32_t res = static_cast<uint32_t>(lhs) - static_cast<uint32_t>(rhs);
  *val = base::bit_cast<int32_t>(res);
  return ((res ^ lhs) & (res ^ ~rhs) & (1U << 31)) != 0;
#endif
}

// SignedMulOverflow32(lhs,rhs,val) performs a signed multiplication of |lhs|
// and |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed multiplication resulted in an overflow.
inline bool SignedMulOverflow32(int32_t lhs, int32_t rhs, int32_t* val) {
#if V8_HAS_BUILTIN_SMUL_OVERFLOW
  return __builtin_smul_overflow(lhs, rhs, val);
#else
  // Compute the result as {int64_t}, then check for overflow.
  int64_t result = int64_t{lhs} * int64_t{rhs};
  *val = static_cast<int32_t>(result);
  using limits = std::numeric_limits<int32_t>;
  return result < limits::min() || result > limits::max();
#endif
}

// SignedAddOverflow64(lhs,rhs,val) performs a signed summation of |lhs| and
// |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed summation resulted in an overflow.
inline bool SignedAddOverflow64(int64_t lhs, int64_t rhs, int64_t* val) {
#if V8_HAS_BUILTIN_ADD_OVERFLOW
  return __builtin_add_overflow(lhs, rhs, val);
#else
  uint64_t res = static_cast<uint64_t>(lhs) + static_cast<uint64_t>(rhs);
  *val = base::bit_cast<int64_t>(res);
  return ((res ^ lhs) & (res ^ rhs) & (1ULL << 63)) != 0;
#endif
}


// SignedSubOverflow64(lhs,rhs,val) performs a signed subtraction of |lhs| and
// |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed subtraction resulted in an overflow.
inline bool SignedSubOverflow64(int64_t lhs, int64_t rhs, int64_t* val) {
#if V8_HAS_BUILTIN_SUB_OVERFLOW
  return __builtin_sub_overflow(lhs, rhs, val);
#else
  uint64_t res = static_cast<uint64_t>(lhs) - static_cast<uint64_t>(rhs);
  *val = base::bit_cast<int64_t>(res);
  return ((res ^ lhs) & (res ^ ~rhs) & (1ULL << 63)) != 0;
#endif
}

// SignedMulOverflow64(lhs,rhs,val) performs a signed multiplication of |lhs|
// and |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the signed multiplication resulted in an overflow.
inline bool SignedMulOverflow64(int64_t lhs, int64_t rhs, int64_t* val) {
#if V8_HAS_BUILTIN_MUL_OVERFLOW
  return __builtin_mul_overflow(lhs, rhs, val);
#else
  int64_t res = base::bit_cast<int64_t>(static_cast<uint64_t>(lhs) *
                                        static_cast<uint64_t>(rhs));
  *val = res;

  // Check for INT64_MIN / -1 as it's undefined behaviour and could cause
  // hardware exceptions.
  if ((res == INT64_MIN && lhs == -1)) {
    return true;
  }

  return lhs != 0 && (res / lhs) != rhs;
#endif
}

// SignedMulHigh32(lhs, rhs) multiplies two signed 32-bit values |lhs| and
// |rhs|, extracts the most significant 32 bits of the result, and returns
// those.
V8_BASE_EXPORT int32_t SignedMulHigh32(int32_t lhs, int32_t rhs);

// UnsignedMulHigh32(lhs, rhs) multiplies two unsigned 32-bit values |lhs| and
// |rhs|, extracts the most significant 32 bits of the result, and returns
// those.
V8_BASE_EXPORT uint32_t UnsignedMulHigh32(uint32_t lhs, uint32_t rhs);

// SignedMulHigh64(lhs, rhs) multiplies two signed 64-bit values |lhs| and
// |rhs|, extracts the most significant 64 bits of the result, and returns
// those.
V8_BASE_EXPORT int64_t SignedMulHigh64(int64_t lhs, int64_t rhs);

// UnsignedMulHigh64(lhs, rhs) multiplies two unsigned 64-bit values |lhs| and
// |rhs|, extracts the most significant 64 bits of the result, and returns
// those.
V8_BASE_EXPORT uint64_t UnsignedMulHigh64(uint64_t lhs, uint64_t rhs);

// SignedMulHighAndAdd32(lhs, rhs, acc) multiplies two signed 32-bit values
// |lhs| and |rhs|, extracts the most significant 32 bits of the result, and
// adds the accumulate value |acc|.
V8_BASE_EXPORT int32_t SignedMulHighAndAdd32(int32_t lhs, int32_t rhs,
                                             int32_t acc);

// SignedDiv32(lhs, rhs) divides |lhs| by |rhs| and returns the quotient
// truncated to int32. If |rhs| is zero, then zero is returned. If |lhs|
// is minint and |rhs| is -1, it returns minint.
V8_BASE_EXPORT int32_t SignedDiv32(int32_t lhs, int32_t rhs);

// SignedDiv64(lhs, rhs) divides |lhs| by |rhs| and returns the quotient
// truncated to int64. If |rhs| is zero, then zero is returned. If |lhs|
// is minint and |rhs| is -1, it returns minint.
V8_BASE_EXPORT int64_t SignedDiv64(int64_t lhs, int64_t rhs);

// SignedMod32(lhs, rhs) divides |lhs| by |rhs| and returns the remainder
// truncated to int32. If either |rhs| is zero or |lhs| is minint and |rhs|
// is -1, it returns zero.
V8_BASE_EXPORT int32_t SignedMod32(int32_t lhs, int32_t rhs);

// SignedMod64(lhs, rhs) divides |lhs| by |rhs| and returns the remainder
// truncated to int64. If either |rhs| is zero or |lhs| is minint and |rhs|
// is -1, it returns zero.
V8_BASE_EXPORT int64_t SignedMod64(int64_t lhs, int64_t rhs);

// UnsignedAddOverflow32(lhs,rhs,val) performs an unsigned summation of |lhs|
// and |rhs| and stores the result into the variable pointed to by |val| and
// returns true if the unsigned summation resulted in an overflow.
inline bool UnsignedAddOverflow32(uint32_t lhs, uint32_t rhs, uint32_t* val) {
#if V8_HAS_BUILTIN_SADD_OVERFLOW
  return __builtin_uadd_overflow(lhs, rhs, val);
#else
  *val = lhs + rhs;
  return *val < (lhs | rhs);
#endif
}


// UnsignedDiv32(lhs, rhs) divides |lhs| by |rhs| and returns the quotient
// truncated to uint32. If |rhs| is zero, then zero is returned.
inline uint32_t UnsignedDiv32(uint32_t lhs, uint32_t rhs) {
  return rhs ? lhs / rhs : 0u;
}

// UnsignedDiv64(lhs, rhs) divides |lhs| by |rhs| and returns the quotient
// truncated to uint64. If |rhs| is zero, then zero is returned.
inline uint64_t UnsignedDiv64(uint64_t lhs, uint64_t rhs) {
  return rhs ? lhs / rhs : 0u;
}

// UnsignedMod32(lhs, rhs) divides |lhs| by |rhs| and returns the remainder
// truncated to uint32. If |rhs| is zero, then zero is returned.
inline uint32_t UnsignedMod32(uint32_t lhs, uint32_t rhs) {
  return rhs ? lhs % rhs : 0u;
}

// UnsignedMod64(lhs, rhs) divides |lhs| by |rhs| and returns the remainder
// truncated to uint64. If |rhs| is zero, then zero is returned.
inline uint64_t UnsignedMod64(uint64_t lhs, uint64_t rhs) {
  return rhs ? lhs % rhs : 0u;
}

// Wraparound integer arithmetic without undefined behavior.

inline int32_t WraparoundAdd32(int32_t lhs, int32_t rhs) {
  return static_cast<int32_t>(static_cast<uint32_t>(lhs) +
                              static_cast<uint32_t>(rhs));
}

inline int32_t WraparoundNeg32(int32_t x) {
  return static_cast<int32_t>(-static_cast<uint32_t>(x));
}

// SignedSaturatedAdd64(lhs, rhs) adds |lhs| and |rhs|,
// checks and returns the result.
V8_BASE_EXPORT int64_t SignedSaturatedAdd64(int64_t lhs, int64_t rhs);

// SignedSaturatedSub64(lhs, rhs) subtracts |lhs| by |rhs|,
// checks and returns the result.
V8_BASE_EXPORT int64_t SignedSaturatedSub64(int64_t lhs, int64_t rhs);

template <class T>
V8_BASE_EXPORT constexpr int BitWidth(T x) {
  return std::numeric_limits<T>::digits - CountLeadingZeros(x);
}

}  // namespace bits
}  // namespace base
}  // namespace v8

#endif  // V8_BASE_BITS_H_
```