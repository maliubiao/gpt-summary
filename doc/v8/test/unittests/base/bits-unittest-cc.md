Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The request asks for the functionality of the `bits-unittest.cc` file,  its relation to JavaScript (if any), code logic reasoning with examples, and common programming errors it might highlight.

**2. Initial Scan and Key Observations:**

I quickly scanned the code for keywords and patterns. I noticed:

* **`// Copyright ...` and `#include ...`**: This indicates a standard C++ source file within the V8 project.
* **`TEST(Bits, ...)`**: This immediately flags the use of Google Test framework. The file is clearly a unit test file.
* **Function names like `CountPopulation`, `CountLeadingZeros`, `IsPowerOfTwo`, `RoundUpToPowerOfTwo`, `RotateRight`, `SignedAddOverflow`, `SignedMulHigh`, `SignedDiv`, `UnsignedDiv`, etc.**: These names strongly suggest that the file tests various bit manipulation functions.
* **Data types like `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, `int64_t`**:  This confirms the bit manipulation focus and the different sizes of integers being tested.
* **`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`**: These are Google Test assertion macros. They are used to verify the expected behavior of the tested functions.
* **`TRACED_FORRANGE`**: This looks like a custom macro, probably for generating multiple test cases. The name suggests it iterates through a range.
* **`DISABLE_IN_RELEASE`**: This macro suggests certain tests are only run in debug builds, likely performance-sensitive or those triggering intentional errors for validation.
* **`ASSERT_DEATH_IF_SUPPORTED`**: This confirms the intention to test scenarios where the code should intentionally cause a program termination (assertion failure).

**3. Deconstructing the Functionality (Step-by-Step):**

I went through each `TEST` block and deduced the purpose of the underlying function being tested:

* **`CountPopulation`**:  The examples clearly show it's counting the number of set bits (1s). The different suffixes (8, 16, 32, 64) indicate versions for different integer sizes.
* **`CountLeadingZeros`**: The examples show it counts the number of leading zero bits.
* **`CountTrailingZeros`**: Counts the number of trailing zero bits. The inclusion of signed integers (`i32`) is noteworthy.
* **`IsPowerOfTwo`**: Checks if a number is a power of two.
* **`WhichPowerOfTwo`**: Determines the exponent if a number is a power of two.
* **`RoundUpToPowerOfTwo`**: Finds the smallest power of two greater than or equal to the input. The `BitsDeathTest` highlights potential overflow.
* **`RoundDownToPowerOfTwo`**: Finds the largest power of two less than or equal to the input.
* **`RotateRight`**: Performs a bitwise right rotation.
* **`SignedAddOverflow`**: Checks for signed integer addition overflow. The `&val` indicates it modifies a passed-in variable to hold the result (even if overflow occurs).
* **`SignedSubOverflow`**: Checks for signed integer subtraction overflow.
* **`SignedMulHigh`**: Computes the high-order bits of a signed integer multiplication.
* **`SignedMulHighAndAdd`**: Combines multiplication and addition, potentially optimizing some operations.
* **`SignedDiv`**: Performs signed integer division, including handling division by zero.
* **`SignedMod`**: Performs signed integer modulo operation, including handling modulo by zero.
* **`UnsignedAddOverflow`**: Checks for unsigned integer addition overflow.
* **`UnsignedDiv`**: Performs unsigned integer division.
* **`UnsignedMod`**: Performs unsigned integer modulo operation.

**4. Connecting to JavaScript (If Applicable):**

I considered how these bit manipulation concepts relate to JavaScript. JavaScript doesn't have explicit integer sizes like C++. However, bitwise operators exist and operate on 32-bit integers internally. I looked for direct equivalents and analogous scenarios.

* **`CountPopulation`**:  While no direct function exists, one could implement it using bitwise operations in a loop or clever bit manipulation tricks.
* **`CountLeadingZeros`/`CountTrailingZeros`**:  Similarly, these can be implemented.
* **`IsPowerOfTwo`**: A common and easily implementable check in JavaScript using the `n & (n - 1) === 0` trick.
* **`RoundUpToPowerOfTwo`**: Can be implemented using logarithms and powers, or through bit manipulation.
* **`RotateRight`**:  Achievable with bitwise shifts and ORing.
* **Overflow Detection**: JavaScript's number type can represent large integers, but bitwise operations implicitly treat numbers as 32-bit. Overflow in the C++ sense might not be as readily apparent, but the result of bitwise operations would wrap around.

**5. Code Logic Reasoning and Examples:**

For each function, I thought about simple input/output examples to illustrate their behavior. I picked test cases that covered edge conditions and typical scenarios, mirroring the structure of the unit tests.

**6. Common Programming Errors:**

I considered what kinds of mistakes programmers might make when working with bit manipulation, especially considering the functions being tested:

* **Off-by-one errors in shifts or rotations.**
* **Incorrectly handling signed vs. unsigned integers.**
* **Forgetting about overflow conditions, leading to unexpected results.**
* **Misunderstanding the behavior of bitwise operators.**
* **Not handling edge cases like zero or the maximum/minimum values for integer types.**

**7. Structuring the Output:**

Finally, I organized the information into the requested categories:

* **Functionality:**  A concise summary of what the file does.
* **Torque Source:**  Checking the file extension.
* **Relationship to JavaScript:**  Explaining the connection and providing JavaScript examples.
* **Code Logic Reasoning:**  Providing input/output examples for key functions.
* **Common Programming Errors:**  Listing typical pitfalls.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of each test case. I then shifted to a higher-level understanding of the purpose of each tested function.
* I made sure to explicitly address the "Torque source" question, even though the answer was straightforward based on the file extension.
* I double-checked the JavaScript examples to ensure they were accurate and relevant.
* I tried to connect the C++ concepts to practical scenarios a JavaScript developer might encounter, even if indirectly.

By following this structured approach, I was able to comprehensively analyze the provided C++ code and generate the detailed explanation requested.
好的，让我们来分析一下 `v8/test/unittests/base/bits-unittest.cc` 这个文件。

**功能列举**

这个 C++ 文件是 V8 引擎中 `base` 模块下 `bits` 子模块的单元测试文件。它的主要功能是：

1. **测试 `src/base/bits.h` 头文件中定义的位操作相关函数。**  这些函数通常用于高效地执行底层的位级操作，例如：
    * **`CountPopulation(x)`:**  计算一个整数 `x` 的二进制表示中 1 的个数（也称为 popcount 或 hamming weight）。
    * **`CountLeadingZeros(x)`:** 计算一个整数 `x` 的二进制表示中，从最高位开始连续 0 的个数。
    * **`CountTrailingZeros(x)`:** 计算一个整数 `x` 的二进制表示中，从最低位开始连续 0 的个数。
    * **`IsPowerOfTwo(x)`:** 检查一个无符号整数 `x` 是否为 2 的幂。
    * **`WhichPowerOfTwo(x)`:** 如果一个整数 `x` 是 2 的幂，则返回其指数。
    * **`RoundUpToPowerOfTwo(x)`:** 将一个无符号整数 `x` 向上取整到最接近的 2 的幂。
    * **`RoundDownToPowerOfTwo(x)`:** 将一个无符号整数 `x` 向下取整到最接近的 2 的幂。
    * **`RotateRight(x, k)`:** 将一个整数 `x` 的二进制表示向右循环移位 `k` 位。
    * **`SignedAddOverflow32(a, b, out)`:** 检查两个有符号 32 位整数 `a` 和 `b` 相加是否溢出，如果未溢出，将结果存储在 `out` 中。
    * **`SignedSubOverflow32(a, b, out)`:** 检查两个有符号 32 位整数 `a` 和 `b` 相减是否溢出，如果未溢出，将结果存储在 `out` 中。
    * **`SignedMulHigh32(a, b)`:** 计算两个有符号 32 位整数 `a` 和 `b` 相乘结果的高 32 位。
    * **`SignedMulHighAndAdd32(a, b, c)`:** 计算 `a * b` 的高 32 位，然后加到 `c` 上。
    * **`SignedDiv32(a, b)`:** 执行有符号 32 位整数除法，并处理除零的情况。
    * **`SignedMod32(a, b)`:** 执行有符号 32 位整数取模运算，并处理除零的情况。
    * **`UnsignedAddOverflow32(a, b, out)`:** 检查两个无符号 32 位整数 `a` 和 `b` 相加是否溢出，如果未溢出，将结果存储在 `out` 中。
    * **`UnsignedDiv32(a, b)`:** 执行无符号 32 位整数除法，并处理除零的情况。
    * **`UnsignedMod32(a, b)`:** 执行无符号 32 位整数取模运算，并处理除零的情况。

2. **使用 Google Test 框架编写测试用例。** 每个 `TEST` 宏定义了一个独立的测试用例，用于验证特定函数的行为是否符合预期。

3. **覆盖不同数据类型。** 测试用例针对 `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int32_t`, `int64_t` 等不同大小的整数类型，确保位操作函数在各种情况下都能正确工作。

4. **包含边界条件和典型用例。** 测试用例涵盖了 0、1、最大值、最小值、2 的幂等边界情况，以及一些典型的数值，以确保代码的健壮性。

5. **使用 `TRACED_FORRANGE` 宏生成多组测试数据。**  这个宏可以方便地生成一系列测试输入，减少重复代码。

6. **使用 `ASSERT_DEATH_IF_SUPPORTED` 宏测试预期会崩溃的情况。**  例如，`RoundUpToPowerOfTwo32` 在输入超出范围时应该导致断言失败，这个宏用于验证这种行为（仅在 DEBUG 模式下）。

**是否为 Torque 源代码**

根据描述，`v8/test/unittests/base/bits-unittest.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件扩展名是 `.tq`，那么它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系**

虽然这是一个 C++ 文件，但其中测试的位操作功能与 JavaScript 密切相关。JavaScript 虽然没有像 C++ 那样直接暴露底层的位操作接口，但在其内部实现中，V8 引擎大量使用了这些高效的位操作来完成各种任务，例如：

* **数字的内部表示:** JavaScript 的 Number 类型在内部使用双精度浮点数表示，但对于整数运算，V8 也会利用底层的位操作进行优化。
* **内存管理:** V8 的垃圾回收机制和对象表示中，可能使用位操作来标记对象的状态。
* **Tagged pointers:** 为了区分不同的数据类型（例如，整数、指针、对象），V8 使用 tagged pointers 技术，这涉及到对指针的低位进行位操作。
* **编译器优化:**  V8 的编译器（TurboFan）在进行代码优化时，可能会将一些高级操作转换为更底层的位操作，以提高执行效率。
* **特定 API 的实现:** 某些 JavaScript API 的实现可能依赖于位操作。

**JavaScript 示例**

虽然 JavaScript 没有直接对应的 `CountPopulation` 函数，但我们可以用 JavaScript 模拟类似的功能：

```javascript
function countSetBits(n) {
  let count = 0;
  while (n > 0) {
    n &= (n - 1); // 清除最低位的 1
    count++;
  }
  return count;
}

console.log(countSetBits(0b00001011)); // 输出 3
```

其他一些位操作在 JavaScript 中也有对应的运算符：

* **与运算 (`&`)**:  类似于 C++ 的 `&`
* **或运算 (`|`)**:  类似于 C++ 的 `|`
* **异或运算 (`^`)**: 类似于 C++ 的 `^`
* **非运算 (`~`)**: 类似于 C++ 的 `~`
* **左移 (`<<`)**: 类似于 C++ 的 `<<`
* **右移 (`>>`)**: 类似于 C++ 的 `>>` (算术右移)
* **无符号右移 (`>>>`)**:  C++ 中没有直接对应的运算符，但可以通过类型转换和位运算模拟。

**代码逻辑推理 (假设输入与输出)**

让我们以 `CountLeadingZeros32` 函数为例进行推理：

**假设输入:** `uint32_t input = 0b00000000000010100000000000000000;` (十进制 2621440)

1. **函数目标:** `CountLeadingZeros32` 函数旨在计算 32 位无符号整数从最高位开始的连续 0 的个数。

2. **二进制表示:** 输入的二进制表示中，前 19 位都是 0，然后是 `1010`，后面都是 0。

3. **推理过程:** 函数会从最高位开始扫描，直到遇到第一个 1。在这个例子中，前 19 位都是 0。

4. **预期输出:** 因此，`CountLeadingZeros32(0b00000000000010100000000000000000)` 应该返回 `19u`。

**涉及用户常见的编程错误**

这个单元测试文件实际上是为了防止和验证与位操作相关的编程错误。以下是一些用户在进行位操作时常见的错误，这些测试用例可以帮助发现这些错误：

1. **错误的位移量:**  例如，希望右移 2 位，却写成了右移 3 位。测试用例会覆盖不同的位移量，确保移位操作的正确性。

   ```c++
   // 错误示例
   uint8_t value = 0b00001000; // 8
   uint8_t shifted = value >> 3; // 期望右移 2 位，得到 2，但这里右移了 3 位，得到 1

   // 正确示例
   uint8_t shifted_correct = value >> 2; // 得到 2
   ```

2. **有符号数和无符号数的混淆:**  有符号数的位移操作（尤其是右移）与无符号数有所不同。算术右移会保留符号位，而逻辑右移会在高位补 0。

   ```c++
   // 错误示例
   int8_t signed_value = -4; // 二进制补码表示可能是 11111100
   uint8_t unsigned_shifted = signed_value >> 1; // 结果可能不是期望的，取决于编译器如何处理

   // 推荐使用明确的类型转换或无符号类型进行位操作
   uint8_t unsigned_value = static_cast<uint8_t>(signed_value);
   uint8_t shifted_correct = unsigned_value >> 1;
   ```

3. **位运算优先级错误:** 位运算符的优先级低于算术运算符，如果不加括号，可能会导致意想不到的结果。

   ```c++
   // 错误示例
   uint8_t result = 1 << 2 + 1; // 实际计算的是 1 << 3，而不是 (1 << 2) + 1

   // 正确示例
   uint8_t result_correct = (1 << 2) + 1;
   ```

4. **整数溢出:**  在进行位运算或算术运算时，如果结果超出数据类型的表示范围，可能会发生溢出。`SignedAddOverflow32` 和 `UnsignedAddOverflow32` 等测试用例专门用于检查溢出情况。

   ```c++
   // 错误示例
   uint8_t max_value = 255;
   uint8_t overflow = max_value + 1; // 发生溢出，结果会是 0

   // 需要注意溢出情况，或使用更大的数据类型
   ```

5. **对 0 进行位移操作或除法:**  虽然某些位移操作对 0 是安全的，但除以 0 会导致程序崩溃。测试用例中包含了对 0 的处理，以确保相关函数的健壮性。

总而言之，`v8/test/unittests/base/bits-unittest.cc` 是一个至关重要的文件，它通过大量的测试用例确保了 V8 引擎中位操作相关函数的正确性和可靠性，从而间接地保证了 JavaScript 引擎的性能和稳定性。

### 提示词
```
这是目录为v8/test/unittests/base/bits-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/bits-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```