Response: Let's break down the thought process for analyzing this C++ unit test file and relating it to JavaScript.

**1. Understanding the Goal:**

The first step is to understand what the question asks. It's asking for a summary of the C++ code's functionality and how it relates to JavaScript, with JavaScript examples. This means we need to identify what the C++ code *does* and then see if similar concepts or operations exist in JavaScript.

**2. Initial Scan and Keyword Identification:**

A quick scan of the code reveals several key patterns and keywords:

* **`#include "src/base/bits.h"`:** This immediately tells us the code is testing functionality related to bit manipulation.
* **`TEST(Bits, ...)`:**  These are Google Test framework test cases. The first argument, "Bits," suggests a suite of tests for something named "Bits."
* **Function names like `CountPopulation`, `CountLeadingZeros`, `CountTrailingZeros`, `IsPowerOfTwo`, `RoundUpToPowerOfTwo`, `RotateRight`, `SignedAddOverflow`, `SignedSubOverflow`, `SignedMulHigh`, `SignedDiv`, `SignedMod`, `UnsignedAddOverflow`, `UnsignedDiv`, `UnsignedMod`:** These names are highly descriptive and give us a strong indication of the individual functionalities being tested. They all revolve around bitwise operations, arithmetic with potential overflow, and powers of two.
* **Data types like `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, `int64_t`:** These indicate the code is working with fixed-size integer types, crucial for bit manipulation.
* **`EXPECT_EQ(...)`, `EXPECT_TRUE(...)`, `EXPECT_FALSE(...)`:** These are assertion macros from the Google Test framework, used to verify the correctness of the tested functions.
* **`TRACED_FORRANGE(...)`:** This appears to be a custom macro for iterating through ranges, likely for testing various inputs.

**3. Deeper Dive into Functionality (Mental Grouping):**

Based on the function names, we can mentally group the tested functionalities:

* **Counting Bits:** `CountPopulation`, `CountLeadingZeros`, `CountTrailingZeros`
* **Powers of Two:** `IsPowerOfTwo`, `WhichPowerOfTwo`, `RoundUpToPowerOfTwo`, `RoundDownToPowerOfTwo`
* **Bit Rotation:** `RotateRight`
* **Arithmetic with Overflow Detection:** `SignedAddOverflow`, `SignedSubOverflow`, `UnsignedAddOverflow`
* **Specialized Arithmetic:** `SignedMulHigh`, `SignedMulHighAndAdd`, `SignedDiv`, `SignedMod`, `UnsignedDiv`, `UnsignedMod`

**4. Summarizing the Functionality:**

Now, we can formulate a concise summary of what the code does:

> This C++ source code file `bits-unittest.cc` contains unit tests for the `bits.h` header file within the V8 JavaScript engine project. It specifically tests various utility functions related to bit manipulation and integer arithmetic. These functions include counting set bits (population count), counting leading/trailing zeros, checking for powers of two, finding the exponent of a power of two, rounding to the nearest power of two, rotating bits, and detecting overflow in signed and unsigned integer arithmetic operations (addition, subtraction, multiplication, division, and modulo).

**5. Connecting to JavaScript:**

The next step is to consider how these bit manipulation concepts relate to JavaScript. JavaScript itself doesn't have the same level of direct bit manipulation primitives as C++. However, it does have:

* **Bitwise Operators:** `&` (AND), `|` (OR), `^` (XOR), `~` (NOT), `<<` (Left Shift), `>>` (Sign-propagating Right Shift), `>>>` (Zero-fill Right Shift). These are the most direct connection.
* **`Math.pow()`:**  Related to powers of two.
* **`Number.isInteger()`, checking for remainders:** Can be used to determine if a number is a power of two (though not as efficiently).
* **Limitations:**  JavaScript numbers are generally floating-point (doubles) or arbitrary-precision BigInts. Direct manipulation of fixed-size integers like `uint32_t` isn't a core feature. Overflow behavior is different in JavaScript (wraps around for some operations).

**6. Providing JavaScript Examples:**

With the connections in mind, we can create JavaScript examples that illustrate similar concepts, even if the implementation details differ:

* **`CountPopulation`:** Simulate counting set bits using string conversion and filtering.
* **`CountLeadingZeros`:**  Find the position of the most significant '1' bit.
* **`IsPowerOfTwo`:** Use logarithms or bitwise tricks.
* **`RoundUpToPowerOfTwo`:**  A common algorithm exists for this.
* **Arithmetic with Overflow:**  Demonstrate JavaScript's behavior (wrapping) compared to the C++ overflow detection.

**7. Refining and Organizing:**

Finally, organize the information clearly:

* Start with the overall purpose of the C++ file.
* Explain the different categories of bit manipulation functions tested.
* Explicitly state the relationship (or lack thereof) with JavaScript's capabilities.
* Provide well-commented JavaScript examples that clearly relate to the C++ functions.
*  Conclude with a summary highlighting the differences and similarities.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Maybe I should explain the Google Test framework in detail."  **Correction:**  Focus on the *functionality* being tested, not the testing framework itself. A brief mention of it being unit tests is sufficient.
* **Initial thought:** "JavaScript doesn't have direct equivalents for all these functions." **Refinement:**  Focus on *conceptual* similarities and how to achieve similar results in JavaScript, even if the methods are different. Highlight the *differences* in areas like fixed-size integers and overflow behavior.
* **Reviewing examples:** Ensure the JavaScript examples are clear, concise, and accurately demonstrate the intended concept. Add comments to make the connection explicit.

By following these steps, we arrive at a comprehensive and accurate answer that addresses all aspects of the question.
这个C++源代码文件 `bits-unittest.cc` 是 V8 JavaScript 引擎项目中的一个单元测试文件。它的主要功能是**测试 `v8/src/base/bits.h` 头文件中定义的关于位操作的各种实用工具函数是否正确工作。**

这些被测试的位操作函数通常用于执行底层的、高性能的位级别操作，这在 JavaScript 引擎的实现中是至关重要的。

具体来说，这个文件测试了以下类型的位操作函数：

* **`CountPopulation(x)`:** 计算一个整数 `x` 的二进制表示中 '1' 的个数 (也称为 population count 或 Hamming weight)。
* **`CountLeadingZeros(x)`:** 计算一个整数 `x` 的二进制表示中，从最高位开始连续 '0' 的个数。
* **`CountTrailingZeros(x)`:** 计算一个整数 `x` 的二进制表示中，从最低位开始连续 '0' 的个数。
* **`IsPowerOfTwo(x)`:** 检查一个无符号整数 `x` 是否是 2 的幂。
* **`WhichPowerOfTwo(x)`:**  如果一个整数 `x` 是 2 的幂，则返回其指数 (即 log2(x))。
* **`RoundUpToPowerOfTwo(x)`:** 将一个无符号整数 `x` 向上舍入到最接近的 2 的幂。
* **`RoundDownToPowerOfTwo(x)`:** 将一个无符号整数 `x` 向下舍入到最接近的 2 的幂。
* **`RotateRight(x, shift)`:** 将一个整数 `x` 的二进制表示向右循环移动 `shift` 位。
* **`SignedAddOverflow32(a, b, out)` / `UnsignedAddOverflow32(a, b, out)`:**  检查两个有符号/无符号 32 位整数相加是否溢出，并将结果存储在 `out` 中。
* **`SignedSubOverflow32(a, b, out)`:** 检查两个有符号 32 位整数相减是否溢出，并将结果存储在 `out` 中。
* **`SignedMulHigh32(a, b)`:** 返回两个有符号 32 位整数相乘的高 32 位结果。
* **`SignedMulHighAndAdd32(a, b, c)`:** 返回 `a * b` 的高 32 位结果与 `c` 相加的结果。
* **`SignedDiv32(a, b)` / `UnsignedDiv32(a, b)`:** 执行有符号/无符号 32 位整数除法。
* **`SignedMod32(a, b)` / `UnsignedMod32(a, b)`:** 执行有符号/无符号 32 位整数取模运算。

**与 JavaScript 的关系 (JavaScript 示例):**

这些底层的位操作函数虽然在 JavaScript 中没有直接的对应物，但与 JavaScript 的一些功能和性能优化密切相关。V8 引擎使用这些优化来提高 JavaScript 代码的执行效率。

例如：

1. **整数表示和优化:** JavaScript 中的数字类型是双精度浮点数，但 V8 内部会尝试使用更高效的整数表示（例如，小的整数会使用小整数 (Smi) 表示）。 位操作函数可以帮助 V8 引擎在内部进行这些优化，例如判断一个数字是否可以安全地表示为小整数。

2. **内存管理:** V8 的垃圾回收机制可能使用位图来跟踪对象的分配和标记。 `CountPopulation` 等函数可以用于快速计算位图中已设置的位的数量，从而了解内存的使用情况。

3. **哈希表和数据结构:**  一些数据结构的实现会用到位操作进行高效的索引和查找。例如，计算哈希值和在哈希表中定位桶位可能会涉及位运算。

4. **WebAssembly:** WebAssembly 是一种可以在浏览器中运行的低级字节码格式。它提供了对位操作的直接支持，并且 V8 需要能够有效地执行 WebAssembly 代码。 V8 的 `bits.h` 中的函数可能与执行 WebAssembly 的位操作指令有关。

**JavaScript 示例 (模拟部分功能):**

虽然 JavaScript 没有直接的 `CountPopulation` 函数，但我们可以使用循环和位运算符来模拟其功能：

```javascript
function countPopulation(n) {
  let count = 0;
  while (n > 0) {
    count += (n & 1); // 检查最低位是否为 1
    n >>= 1;         // 右移一位
  }
  return count;
}

console.log(countPopulation(0b101101)); // 输出 4
```

JavaScript 提供了位运算符，可以进行一些基本的位操作：

```javascript
console.log(10 & 5);   // 位与 (AND)
console.log(10 | 5);   // 位或 (OR)
console.log(10 ^ 5);   // 位异或 (XOR)
console.log(~10);     // 位非 (NOT)
console.log(10 << 2);  // 左移
console.log(10 >> 2);  // 有符号右移
console.log(10 >>> 2); // 无符号右移
```

JavaScript 中没有直接检测整数溢出的机制，但可以进行一些间接的检查：

```javascript
function signedAddOverflow(a, b) {
  const result = a + b;
  if ((a > 0 && b > 0 && result < 0) || (a < 0 && b < 0 && result > 0)) {
    return true; // 溢出
  }
  return false;
}

console.log(signedAddOverflow(2147483647, 1)); // 输出 true (接近 32 位有符号整数最大值)
```

**总结:**

`bits-unittest.cc` 文件是 V8 引擎中一个重要的测试文件，用于确保其底层的位操作工具函数的正确性。 这些函数虽然在 JavaScript 中不可直接使用，但对于 V8 引擎的性能和内部实现至关重要，影响着 JavaScript 代码的执行效率、内存管理和对 WebAssembly 等低级语言的支持。 JavaScript 开发者可以通过位运算符进行一些基本的位操作，但 V8 引擎内部使用了更高级和优化的位操作技术。

Prompt: 
```
这是目录为v8/test/unittests/base/bits-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/bits.h"

#include <limits>

#include "testing/gtest-support.h"

#ifdef DEBUG
#define DISABLE_IN_RELEASE(Name) Name
#else
#define DISABLE_IN_RELEASE(Name) DISABLED_##Name
#endif

namespace v8 {
namespace base {
namespace bits {

TEST(Bits, CountPopulation8) {
  EXPECT_EQ(0u, CountPopulation(uint8_t{0}));
  EXPECT_EQ(1u, CountPopulation(uint8_t{1}));
  EXPECT_EQ(2u, CountPopulation(uint8_t{0x11}));
  EXPECT_EQ(4u, CountPopulation(uint8_t{0x0F}));
  EXPECT_EQ(6u, CountPopulation(uint8_t{0x3F}));
  EXPECT_EQ(8u, CountPopulation(uint8_t{0xFF}));
}

TEST(Bits, CountPopulation16) {
  EXPECT_EQ(0u, CountPopulation(uint16_t{0}));
  EXPECT_EQ(1u, CountPopulation(uint16_t{1}));
  EXPECT_EQ(4u, CountPopulation(uint16_t{0x1111}));
  EXPECT_EQ(8u, CountPopulation(uint16_t{0xF0F0}));
  EXPECT_EQ(12u, CountPopulation(uint16_t{0xF0FF}));
  EXPECT_EQ(16u, CountPopulation(uint16_t{0xFFFF}));
}

TEST(Bits, CountPopulation32) {
  EXPECT_EQ(0u, CountPopulation(uint32_t{0}));
  EXPECT_EQ(1u, CountPopulation(uint32_t{1}));
  EXPECT_EQ(8u, CountPopulation(uint32_t{0x11111111}));
  EXPECT_EQ(16u, CountPopulation(uint32_t{0xF0F0F0F0}));
  EXPECT_EQ(24u, CountPopulation(uint32_t{0xFFF0F0FF}));
  EXPECT_EQ(32u, CountPopulation(uint32_t{0xFFFFFFFF}));
}

TEST(Bits, CountPopulation64) {
  EXPECT_EQ(0u, CountPopulation(uint64_t{0}));
  EXPECT_EQ(1u, CountPopulation(uint64_t{1}));
  EXPECT_EQ(2u, CountPopulation(uint64_t{0x8000000000000001}));
  EXPECT_EQ(8u, CountPopulation(uint64_t{0x11111111}));
  EXPECT_EQ(16u, CountPopulation(uint64_t{0xF0F0F0F0}));
  EXPECT_EQ(24u, CountPopulation(uint64_t{0xFFF0F0FF}));
  EXPECT_EQ(32u, CountPopulation(uint64_t{0xFFFFFFFF}));
  EXPECT_EQ(16u, CountPopulation(uint64_t{0x1111111111111111}));
  EXPECT_EQ(32u, CountPopulation(uint64_t{0xF0F0F0F0F0F0F0F0}));
  EXPECT_EQ(48u, CountPopulation(uint64_t{0xFFF0F0FFFFF0F0FF}));
  EXPECT_EQ(64u, CountPopulation(uint64_t{0xFFFFFFFFFFFFFFFF}));
}

TEST(Bits, CountLeadingZeros16) {
  EXPECT_EQ(16u, CountLeadingZeros(uint16_t{0}));
  EXPECT_EQ(15u, CountLeadingZeros(uint16_t{1}));
  TRACED_FORRANGE(uint16_t, shift, 0, 15) {
    EXPECT_EQ(15u - shift,
              CountLeadingZeros(static_cast<uint16_t>(1 << shift)));
  }
  EXPECT_EQ(4u, CountLeadingZeros(uint16_t{0x0F0F}));
}

TEST(Bits, CountLeadingZeros32) {
  EXPECT_EQ(32u, CountLeadingZeros(uint32_t{0}));
  EXPECT_EQ(31u, CountLeadingZeros(uint32_t{1}));
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(31u - shift, CountLeadingZeros(uint32_t{1} << shift));
  }
  EXPECT_EQ(4u, CountLeadingZeros(uint32_t{0x0F0F0F0F}));
}

TEST(Bits, CountLeadingZeros64) {
  EXPECT_EQ(64u, CountLeadingZeros(uint64_t{0}));
  EXPECT_EQ(63u, CountLeadingZeros(uint64_t{1}));
  TRACED_FORRANGE(uint32_t, shift, 0, 63) {
    EXPECT_EQ(63u - shift, CountLeadingZeros(uint64_t{1} << shift));
  }
  EXPECT_EQ(36u, CountLeadingZeros(uint64_t{0x0F0F0F0F}));
  EXPECT_EQ(4u, CountLeadingZeros(uint64_t{0x0F0F0F0F00000000}));
}

TEST(Bits, CountTrailingZeros16) {
  EXPECT_EQ(16u, CountTrailingZeros(uint16_t{0}));
  EXPECT_EQ(15u, CountTrailingZeros(uint16_t{0x8000}));
  TRACED_FORRANGE(uint16_t, shift, 0, 15) {
    EXPECT_EQ(shift, CountTrailingZeros(static_cast<uint16_t>(1 << shift)));
  }
  EXPECT_EQ(4u, CountTrailingZeros(uint16_t{0xF0F0u}));
}

TEST(Bits, CountTrailingZerosu32) {
  EXPECT_EQ(32u, CountTrailingZeros(uint32_t{0}));
  EXPECT_EQ(31u, CountTrailingZeros(uint32_t{0x80000000}));
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(shift, CountTrailingZeros(uint32_t{1} << shift));
  }
  EXPECT_EQ(4u, CountTrailingZeros(uint32_t{0xF0F0F0F0u}));
}

TEST(Bits, CountTrailingZerosi32) {
  EXPECT_EQ(32u, CountTrailingZeros(int32_t{0}));
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(shift, CountTrailingZeros(int32_t{1} << shift));
  }
  EXPECT_EQ(4u, CountTrailingZeros(int32_t{0x70F0F0F0u}));
  EXPECT_EQ(2u, CountTrailingZeros(int32_t{-4}));
  EXPECT_EQ(0u, CountTrailingZeros(int32_t{-1}));
}

TEST(Bits, CountTrailingZeros64) {
  EXPECT_EQ(64u, CountTrailingZeros(uint64_t{0}));
  EXPECT_EQ(63u, CountTrailingZeros(uint64_t{0x8000000000000000}));
  TRACED_FORRANGE(uint32_t, shift, 0, 63) {
    EXPECT_EQ(shift, CountTrailingZeros(uint64_t{1} << shift));
  }
  EXPECT_EQ(4u, CountTrailingZeros(uint64_t{0xF0F0F0F0}));
  EXPECT_EQ(36u, CountTrailingZeros(uint64_t{0xF0F0F0F000000000}));
}

TEST(Bits, IsPowerOfTwo32) {
  EXPECT_FALSE(IsPowerOfTwo(0U));
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_TRUE(IsPowerOfTwo(1U << shift));
    EXPECT_FALSE(IsPowerOfTwo((1U << shift) + 5U));
    EXPECT_FALSE(IsPowerOfTwo(~(1U << shift)));
  }
  TRACED_FORRANGE(uint32_t, shift, 2, 31) {
    EXPECT_FALSE(IsPowerOfTwo((1U << shift) - 1U));
  }
  EXPECT_FALSE(IsPowerOfTwo(0xFFFFFFFF));
}

TEST(Bits, IsPowerOfTwo64) {
  EXPECT_FALSE(IsPowerOfTwo(uint64_t{0}));
  TRACED_FORRANGE(uint32_t, shift, 0, 63) {
    EXPECT_TRUE(IsPowerOfTwo(uint64_t{1} << shift));
    EXPECT_FALSE(IsPowerOfTwo((uint64_t{1} << shift) + 5U));
    EXPECT_FALSE(IsPowerOfTwo(~(uint64_t{1} << shift)));
  }
  TRACED_FORRANGE(uint32_t, shift, 2, 63) {
    EXPECT_FALSE(IsPowerOfTwo((uint64_t{1} << shift) - 1U));
  }
  EXPECT_FALSE(IsPowerOfTwo(uint64_t{0xFFFFFFFFFFFFFFFF}));
}

TEST(Bits, WhichPowerOfTwo32) {
  TRACED_FORRANGE(int, shift, 0, 30) {
    EXPECT_EQ(shift, WhichPowerOfTwo(int32_t{1} << shift));
  }
  TRACED_FORRANGE(int, shift, 0, 31) {
    EXPECT_EQ(shift, WhichPowerOfTwo(uint32_t{1} << shift));
  }
}

TEST(Bits, WhichPowerOfTwo64) {
  TRACED_FORRANGE(int, shift, 0, 62) {
    EXPECT_EQ(shift, WhichPowerOfTwo(int64_t{1} << shift));
  }
  TRACED_FORRANGE(int, shift, 0, 63) {
    EXPECT_EQ(shift, WhichPowerOfTwo(uint64_t{1} << shift));
  }
}

TEST(Bits, RoundUpToPowerOfTwo32) {
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(1u << shift, RoundUpToPowerOfTwo32(1u << shift));
  }
  EXPECT_EQ(1u, RoundUpToPowerOfTwo32(0));
  EXPECT_EQ(1u, RoundUpToPowerOfTwo32(1));
  EXPECT_EQ(4u, RoundUpToPowerOfTwo32(3));
  EXPECT_EQ(0x80000000u, RoundUpToPowerOfTwo32(0x7FFFFFFFu));
}


TEST(BitsDeathTest, DISABLE_IN_RELEASE(RoundUpToPowerOfTwo32)) {
  ASSERT_DEATH_IF_SUPPORTED({ RoundUpToPowerOfTwo32(0x80000001u); },
                            ".*heck failed:.* << 31");
}

TEST(Bits, RoundUpToPowerOfTwo64) {
  TRACED_FORRANGE(uint64_t, shift, 0, 63) {
    uint64_t value = uint64_t{1} << shift;
    EXPECT_EQ(value, RoundUpToPowerOfTwo64(value));
  }
  EXPECT_EQ(uint64_t{1}, RoundUpToPowerOfTwo64(0));
  EXPECT_EQ(uint64_t{1}, RoundUpToPowerOfTwo64(1));
  EXPECT_EQ(uint64_t{4}, RoundUpToPowerOfTwo64(3));
  EXPECT_EQ(uint64_t{1} << 63, RoundUpToPowerOfTwo64((uint64_t{1} << 63) - 1));
  EXPECT_EQ(uint64_t{1} << 63, RoundUpToPowerOfTwo64(uint64_t{1} << 63));
}

TEST(BitsDeathTest, DISABLE_IN_RELEASE(RoundUpToPowerOfTwo64)) {
  ASSERT_DEATH_IF_SUPPORTED({ RoundUpToPowerOfTwo64((uint64_t{1} << 63) + 1); },
                            ".*heck failed:.* << 63");
}


TEST(Bits, RoundDownToPowerOfTwo32) {
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(1u << shift, RoundDownToPowerOfTwo32(1u << shift));
  }
  EXPECT_EQ(0u, RoundDownToPowerOfTwo32(0));
  EXPECT_EQ(4u, RoundDownToPowerOfTwo32(5));
  EXPECT_EQ(0x80000000u, RoundDownToPowerOfTwo32(0x80000001u));
}


TEST(Bits, RotateRight32) {
  TRACED_FORRANGE(uint32_t, shift, 0, 31) {
    EXPECT_EQ(0u, RotateRight32(0u, shift));
  }
  EXPECT_EQ(1u, RotateRight32(1, 0));
  EXPECT_EQ(1u, RotateRight32(2, 1));
  EXPECT_EQ(0x80000000u, RotateRight32(1, 1));
}


TEST(Bits, RotateRight64) {
  TRACED_FORRANGE(uint64_t, shift, 0, 63) {
    EXPECT_EQ(0u, RotateRight64(0u, shift));
  }
  EXPECT_EQ(1u, RotateRight64(1, 0));
  EXPECT_EQ(1u, RotateRight64(2, 1));
  EXPECT_EQ(uint64_t{0x8000000000000000}, RotateRight64(1, 1));
}


TEST(Bits, SignedAddOverflow32) {
  int32_t val = 0;
  EXPECT_FALSE(SignedAddOverflow32(0, 0, &val));
  EXPECT_EQ(0, val);
  EXPECT_TRUE(
      SignedAddOverflow32(std::numeric_limits<int32_t>::max(), 1, &val));
  EXPECT_EQ(std::numeric_limits<int32_t>::min(), val);
  EXPECT_TRUE(
      SignedAddOverflow32(std::numeric_limits<int32_t>::min(), -1, &val));
  EXPECT_EQ(std::numeric_limits<int32_t>::max(), val);
  EXPECT_TRUE(SignedAddOverflow32(std::numeric_limits<int32_t>::max(),
                                  std::numeric_limits<int32_t>::max(), &val));
  EXPECT_EQ(-2, val);
  TRACED_FORRANGE(int32_t, i, 1, 50) {
    TRACED_FORRANGE(int32_t, j, 1, i) {
      EXPECT_FALSE(SignedAddOverflow32(i, j, &val));
      EXPECT_EQ(i + j, val);
    }
  }
}


TEST(Bits, SignedSubOverflow32) {
  int32_t val = 0;
  EXPECT_FALSE(SignedSubOverflow32(0, 0, &val));
  EXPECT_EQ(0, val);
  EXPECT_TRUE(
      SignedSubOverflow32(std::numeric_limits<int32_t>::min(), 1, &val));
  EXPECT_EQ(std::numeric_limits<int32_t>::max(), val);
  EXPECT_TRUE(
      SignedSubOverflow32(std::numeric_limits<int32_t>::max(), -1, &val));
  EXPECT_EQ(std::numeric_limits<int32_t>::min(), val);
  TRACED_FORRANGE(int32_t, i, 1, 50) {
    TRACED_FORRANGE(int32_t, j, 1, i) {
      EXPECT_FALSE(SignedSubOverflow32(i, j, &val));
      EXPECT_EQ(i - j, val);
    }
  }
}


TEST(Bits, SignedMulHigh32) {
  EXPECT_EQ(0, SignedMulHigh32(0, 0));
  TRACED_FORRANGE(int32_t, i, 1, 50) {
    TRACED_FORRANGE(int32_t, j, 1, i) { EXPECT_EQ(0, SignedMulHigh32(i, j)); }
  }
  EXPECT_EQ(-1073741824, SignedMulHigh32(std::numeric_limits<int32_t>::max(),
                                         std::numeric_limits<int32_t>::min()));
  EXPECT_EQ(-1073741824, SignedMulHigh32(std::numeric_limits<int32_t>::min(),
                                         std::numeric_limits<int32_t>::max()));
  EXPECT_EQ(1, SignedMulHigh32(1024 * 1024 * 1024, 4));
  EXPECT_EQ(2, SignedMulHigh32(8 * 1024, 1024 * 1024));
}


TEST(Bits, SignedMulHighAndAdd32) {
  TRACED_FORRANGE(int32_t, i, 1, 50) {
    EXPECT_EQ(i, SignedMulHighAndAdd32(0, 0, i));
    TRACED_FORRANGE(int32_t, j, 1, i) {
      EXPECT_EQ(i, SignedMulHighAndAdd32(j, j, i));
    }
    EXPECT_EQ(i + 1, SignedMulHighAndAdd32(1024 * 1024 * 1024, 4, i));
  }
}


TEST(Bits, SignedDiv32) {
  EXPECT_EQ(std::numeric_limits<int32_t>::min(),
            SignedDiv32(std::numeric_limits<int32_t>::min(), -1));
  EXPECT_EQ(std::numeric_limits<int32_t>::max(),
            SignedDiv32(std::numeric_limits<int32_t>::max(), 1));
  TRACED_FORRANGE(int32_t, i, 0, 50) {
    EXPECT_EQ(0, SignedDiv32(i, 0));
    TRACED_FORRANGE(int32_t, j, 1, i) {
      EXPECT_EQ(1, SignedDiv32(j, j));
      EXPECT_EQ(i / j, SignedDiv32(i, j));
      EXPECT_EQ(-i / j, SignedDiv32(i, -j));
    }
  }
}


TEST(Bits, SignedMod32) {
  EXPECT_EQ(0, SignedMod32(std::numeric_limits<int32_t>::min(), -1));
  EXPECT_EQ(0, SignedMod32(std::numeric_limits<int32_t>::max(), 1));
  TRACED_FORRANGE(int32_t, i, 0, 50) {
    EXPECT_EQ(0, SignedMod32(i, 0));
    TRACED_FORRANGE(int32_t, j, 1, i) {
      EXPECT_EQ(0, SignedMod32(j, j));
      EXPECT_EQ(i % j, SignedMod32(i, j));
      EXPECT_EQ(i % j, SignedMod32(i, -j));
    }
  }
}


TEST(Bits, UnsignedAddOverflow32) {
  uint32_t val = 0;
  EXPECT_FALSE(UnsignedAddOverflow32(0, 0, &val));
  EXPECT_EQ(0u, val);
  EXPECT_TRUE(
      UnsignedAddOverflow32(std::numeric_limits<uint32_t>::max(), 1u, &val));
  EXPECT_EQ(std::numeric_limits<uint32_t>::min(), val);
  EXPECT_TRUE(UnsignedAddOverflow32(std::numeric_limits<uint32_t>::max(),
                                    std::numeric_limits<uint32_t>::max(),
                                    &val));
  TRACED_FORRANGE(uint32_t, i, 1, 50) {
    TRACED_FORRANGE(uint32_t, j, 1, i) {
      EXPECT_FALSE(UnsignedAddOverflow32(i, j, &val));
      EXPECT_EQ(i + j, val);
    }
  }
}


TEST(Bits, UnsignedDiv32) {
  TRACED_FORRANGE(uint32_t, i, 0, 50) {
    EXPECT_EQ(0u, UnsignedDiv32(i, 0));
    TRACED_FORRANGE(uint32_t, j, i + 1, 100) {
      EXPECT_EQ(1u, UnsignedDiv32(j, j));
      EXPECT_EQ(i / j, UnsignedDiv32(i, j));
    }
  }
}


TEST(Bits, UnsignedMod32) {
  TRACED_FORRANGE(uint32_t, i, 0, 50) {
    EXPECT_EQ(0u, UnsignedMod32(i, 0));
    TRACED_FORRANGE(uint32_t, j, i + 1, 100) {
      EXPECT_EQ(0u, UnsignedMod32(j, j));
      EXPECT_EQ(i % j, UnsignedMod32(i, j));
    }
  }
}

}  // namespace bits
}  // namespace base
}  // namespace v8

"""

```