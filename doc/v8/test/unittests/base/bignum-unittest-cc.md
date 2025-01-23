Response:
The user wants a summary of the functionality of the C++ code provided.
The code is a unit test file for a `Bignum` class in the V8 JavaScript engine.
The file name `bignum-unittest.cc` suggests it's testing the functionality of a big number implementation.
The tests use the Google Test framework.
The tests cover various operations on `Bignum` objects, including:
- Assignment from different types (unsigned integers, hex strings, decimal strings)
- Left shift
- Addition (with unsigned 64-bit integers and other `Bignum` objects)
- Subtraction (with other `Bignum` objects)
- Multiplication (with unsigned 32-bit integers, unsigned 64-bit integers, and powers of ten)

If the file ended with `.tq`, it would be a Torque file, which is a domain-specific language used in V8 for implementing built-in functions. This is not the case here.

The code is related to JavaScript because `Bignum` likely handles numbers that exceed the standard JavaScript number type's precision.

I will go through each `TEST_F` block and summarize its purpose.

**Plan:**
1. Identify the core functionality being tested.
2. List the specific operations tested within each `TEST_F` block.
3. Determine if any JavaScript examples are relevant.
4. Identify any code logic or assumptions for input/output.
5. Note any potential programming errors related to the tested functionality.
v8/test/unittests/base/bignum-unittest.cc 是 V8 JavaScript 引擎中用于测试 `Bignum` 类功能的单元测试文件。 `Bignum` 类很可能用于处理超出 JavaScript 标准数字类型精度范围的大整数。

以下是该文件各个测试用例的功能归纳：

*   **`Assign`**: 测试 `Bignum` 对象的赋值操作，包括：
    *   从 `uint16_t` 和 `uint64_t` 类型赋值。
    *   从另一个 `Bignum` 对象赋值。
    *   从十六进制字符串赋值。
    *   从十进制字符串赋值。
    *   验证赋值后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`ShiftLeft`**: 测试 `Bignum` 对象的左移操作，验证左移指定位数后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`AddUInt64`**: 测试 `Bignum` 对象与 `uint64_t` 类型数值相加的操作，验证相加后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`AddBignum`**: 测试两个 `Bignum` 对象相加的操作，验证相加后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`SubtractBignum`**: 测试一个 `Bignum` 对象减去另一个 `Bignum` 对象的操作，验证相减后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`MultiplyUInt32`**: 测试 `Bignum` 对象与 `uint32_t` 类型数值相乘的操作，验证相乘后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`MultiplyUInt64`**: 测试 `Bignum` 对象与 `uint64_t` 类型数值相乘的操作，验证相乘后 `Bignum` 对象转换为十六进制字符串是否符合预期。

*   **`MultiplyPowerOfTen`**: 测试 `Bignum` 对象乘以 10 的幂次的操作，验证相乘后 `Bignum` 对象转换为十六进制字符串是否符合预期。

如果 `v8/test/unittests/base/bignum-unittest.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。但当前的文件名是 `.cc`，表明它是一个 C++ 源代码文件。

这个文件中的 `Bignum` 类与 JavaScript 的 `BigInt` 功能有关系。`BigInt` 是 ES2020 引入的一种新的原始数据类型，用于表示任意精度的整数。

**JavaScript 示例:**

```javascript
// JavaScript BigInt 示例

// 创建 BigInt
const bigInt1 = 1234567890123456789012345n;
const bigInt2 = BigInt("9876543210987654321098765");

// 加法
const sum = bigInt1 + bigInt2;
console.log(sum); // 输出: 1111111110222222220111111111111111115n

// 左移
const shifted = bigInt1 << 10n;
console.log(shifted);

// 注意：BigInt 不能与普通 Number 类型直接进行算术运算，需要先转换为 BigInt
// const num = 10;
// const errorSum = bigInt1 + num; // TypeError: Cannot mix BigInt and other types, use explicit conversions

const num = 10n;
const correctSum = bigInt1 + num;
console.log(correctSum);
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(BignumTest, AddUInt64)` 中的一个用例为例：

*   **假设输入:**
    *   `Bignum` 对象 `bignum` 初始化后通过 `AssignHexString` 赋值为十六进制字符串 "1"。
    *   `uint64_t` 类型的数值 `0x100` (十进制 256)。
*   **代码逻辑:** `bignum.AddUInt64(0x100)` 将 `bignum` 的值（当前为 1）与 256 相加。
*   **预期输出:** 相加后的 `bignum` 对象转换为十六进制字符串应该为 "101" (1 + 256 = 257，257 的十六进制表示为 101)。

**用户常见的编程错误:**

*   **整数溢出:**  在 JavaScript 中，对于超出 Number 类型安全范围的整数进行运算可能会导致精度丢失。`BigInt` 的出现正是为了解决这个问题。
    ```javascript
    // JavaScript Number 溢出
    const largeNumber = Number.MAX_SAFE_INTEGER + 1;
    const largerNumber = largeNumber + 1;
    console.log(largeNumber === largerNumber); // 输出: true，精度丢失

    // 使用 BigInt 避免溢出
    const largeBigInt = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    const largerBigInt = largeBigInt + 1n;
    console.log(largeBigInt === largerBigInt); // 输出: false
    ```

*   **类型不匹配:** 尝试将 `BigInt` 与普通 `Number` 类型直接进行算术运算会导致错误。必须显式地将 `Number` 转换为 `BigInt` 才能进行运算。

**功能归纳:**

`v8/test/unittests/base/bignum-unittest.cc` 这个 C++ 文件是 V8 引擎中 `Bignum` 类的单元测试，旨在验证该类在各种赋值、移位、加法、减法和乘法运算中的正确性。`Bignum` 类是 V8 用来实现 JavaScript 中 `BigInt` 功能的关键组成部分，用于处理任意精度的整数，避免了标准数字类型可能出现的精度丢失和溢出问题。

### 提示词
```
这是目录为v8/test/unittests/base/bignum-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/bignum-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/bignum.h"

#include <stdlib.h>

#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using BignumTest = ::testing::Test;

namespace base {
namespace test_bignum {

static const int kBufferSize = 1024;

static void AssignHexString(Bignum* bignum, const char* str) {
  bignum->AssignHexString(CStrVector(str));
}

static void AssignDecimalString(Bignum* bignum, const char* str) {
  bignum->AssignDecimalString(CStrVector(str));
}

TEST_F(BignumTest, Assign) {
  char buffer[kBufferSize];
  Bignum bignum;
  Bignum bignum2;
  bignum.AssignUInt16(0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));
  bignum.AssignUInt16(0xA);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));
  bignum.AssignUInt16(0x20);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("20", buffer));

  bignum.AssignUInt64(0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));
  bignum.AssignUInt64(0xA);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));
  bignum.AssignUInt64(0x20);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("20", buffer));
  bignum.AssignUInt64(0x100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100", buffer));

  // The first real test, since this will not fit into one bigit.
  bignum.AssignUInt64(0x12345678);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("12345678", buffer));

  uint64_t big = 0xFFFF'FFFF'FFFF'FFFF;
  bignum.AssignUInt64(big);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFF", buffer));

  big = 0x1234'5678'9ABC'DEF0;
  bignum.AssignUInt64(big);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("123456789ABCDEF0", buffer));

  bignum2.AssignBignum(bignum);
  EXPECT_TRUE(bignum2.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("123456789ABCDEF0", buffer));

  AssignDecimalString(&bignum, "0");
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  AssignDecimalString(&bignum, "1");
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  AssignDecimalString(&bignum, "1234567890");
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("499602D2", buffer));

  AssignHexString(&bignum, "0");
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  AssignHexString(&bignum, "123456789ABCDEF0");
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("123456789ABCDEF0", buffer));
}

TEST_F(BignumTest, ShiftLeft) {
  char buffer[kBufferSize];
  Bignum bignum;
  AssignHexString(&bignum, "0");
  bignum.ShiftLeft(100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  AssignHexString(&bignum, "1");
  bignum.ShiftLeft(1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2", buffer));

  AssignHexString(&bignum, "1");
  bignum.ShiftLeft(4);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10", buffer));

  AssignHexString(&bignum, "1");
  bignum.ShiftLeft(32);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000000", buffer));

  AssignHexString(&bignum, "1");
  bignum.ShiftLeft(64);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000", buffer));

  AssignHexString(&bignum, "123456789ABCDEF");
  bignum.ShiftLeft(64);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("123456789ABCDEF0000000000000000", buffer));
  bignum.ShiftLeft(1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2468ACF13579BDE0000000000000000", buffer));
}

TEST_F(BignumTest, AddUInt64) {
  char buffer[kBufferSize];
  Bignum bignum;
  AssignHexString(&bignum, "0");
  bignum.AddUInt64(0xA);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0xA);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("B", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0x100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("101", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.AddUInt64(0x1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.AddUInt64(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000000000000000000000FFFF", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  bignum.AddUInt64(0x1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000000000000000000000000000000000000000000", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddUInt64(1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000001", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddUInt64(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000FFFF", buffer));

  AssignHexString(&bignum, "0");
  bignum.AddUInt64(0xA'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A00000000", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0xA'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A00000001", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0x100'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000001", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddUInt64(0xFFFF'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFF00000001", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.AddUInt64(0x1'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10FFFFFFF", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.AddUInt64(0xFFFF'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000000000FFFF00000000", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  bignum.AddUInt64(0x1'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000000000000000000FFFFFFFF", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddUInt64(0x1'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000100000000", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddUInt64(0xFFFF'0000'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000FFFF00000000", buffer));
}

TEST_F(BignumTest, AddBignum) {
  char buffer[kBufferSize];
  Bignum bignum;
  Bignum other;

  AssignHexString(&other, "1");
  AssignHexString(&bignum, "0");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  AssignHexString(&bignum, "1");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000000000000", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000000000000000000001", buffer));

  AssignHexString(&other, "1000000000000");

  AssignHexString(&bignum, "1");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000001", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000FFFFFFF", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000000001000000000000", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000000000000FFFFFFFFFFFF", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000001000000000000", buffer));

  other.ShiftLeft(64);
  // other == "10000000000000000000000000000"

  bignum.AssignUInt16(0x1);
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000001", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000FFFFFFF", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000010000000000000000000000000000", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFF", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  bignum.AddBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10010000000000000000000000000", buffer));
}

TEST_F(BignumTest, SubtractBignum) {
  char buffer[kBufferSize];
  Bignum bignum;
  Bignum other;

  AssignHexString(&bignum, "1");
  AssignHexString(&other, "0");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  AssignHexString(&bignum, "2");
  AssignHexString(&other, "0");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2", buffer));

  AssignHexString(&bignum, "10000000");
  AssignHexString(&other, "1");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFF", buffer));

  AssignHexString(&bignum, "100000000000000");
  AssignHexString(&other, "1");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFF", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000001");
  AssignHexString(&other, "1");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000000000000000000000", buffer));

  AssignHexString(&bignum, "1000000000001");
  AssignHexString(&other, "1000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  AssignHexString(&bignum, "100000FFFFFFF");
  AssignHexString(&other, "1000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFF", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000001000000000000");
  AssignHexString(&other, "1000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000000000000000000000", buffer));

  AssignHexString(&bignum, "1000000000000000000000000000000FFFFFFFFFFFF");
  AssignHexString(&other, "1000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // "10 0000 0000 0000 0000 0000 0000"
  AssignHexString(&other, "1000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFF000000000000", buffer));

  AssignHexString(&other, "1000000000000");
  other.ShiftLeft(48);
  // other == "1000000000000000000000000"

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // bignum == "10000000000000000000000000"
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("F000000000000000000000000", buffer));

  other.AssignUInt16(0x1);
  other.ShiftLeft(35);
  // other == "800000000"
  AssignHexString(&bignum, "FFFFFFF");
  bignum.ShiftLeft(60);
  // bignum = FFFFFFF000000000000000
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFEFFFFFF800000000", buffer));

  AssignHexString(&bignum, "10000000000000000000000000000000000000000000");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF800000000", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  bignum.SubtractBignum(other);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFF", buffer));
}

TEST_F(BignumTest, MultiplyUInt32) {
  char buffer[kBufferSize];
  Bignum bignum;

  AssignHexString(&bignum, "0");
  bignum.MultiplyByUInt32(0x25);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  AssignHexString(&bignum, "2");
  bignum.MultiplyByUInt32(0x5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));

  AssignHexString(&bignum, "10000000");
  bignum.MultiplyByUInt32(0x9);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("90000000", buffer));

  AssignHexString(&bignum, "100000000000000");
  bignum.MultiplyByUInt32(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFF00000000000000", buffer));

  AssignHexString(&bignum, "100000000000000");
  bignum.MultiplyByUInt32(0xFFFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFF00000000000000", buffer));

  AssignHexString(&bignum, "1234567ABCD");
  bignum.MultiplyByUInt32(0xFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("12333335552433", buffer));

  AssignHexString(&bignum, "1234567ABCD");
  bignum.MultiplyByUInt32(0xFFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("12345679998A985433", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt32(0x2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1FFFFFFFFFFFFFFFE", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt32(0x4);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3FFFFFFFFFFFFFFFC", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt32(0xF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("EFFFFFFFFFFFFFFF1", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt32(0xFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFEFFFFFFFFFF000001", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // "10 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt32(2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("20000000000000000000000000", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // "10 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt32(0xF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("F0000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt32(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFE00010000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt32(0xFFFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFEFFFF00010000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt32(0xFFFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFEFFFF00010000000000000000000000000", buffer));

  AssignDecimalString(&bignum, "15611230384529777");
  bignum.MultiplyByUInt32(10000000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("210EDD6D4CDD2580EE80", buffer));
}

TEST_F(BignumTest, MultiplyUInt64) {
  char buffer[kBufferSize];
  Bignum bignum;

  AssignHexString(&bignum, "0");
  bignum.MultiplyByUInt64(0x25);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  AssignHexString(&bignum, "2");
  bignum.MultiplyByUInt64(0x5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));

  AssignHexString(&bignum, "10000000");
  bignum.MultiplyByUInt64(0x9);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("90000000", buffer));

  AssignHexString(&bignum, "100000000000000");
  bignum.MultiplyByUInt64(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFF00000000000000", buffer));

  AssignHexString(&bignum, "100000000000000");
  bignum.MultiplyByUInt64(0xFFFF'FFFF'FFFF'FFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFF00000000000000", buffer));

  AssignHexString(&bignum, "1234567ABCD");
  bignum.MultiplyByUInt64(0xFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("12333335552433", buffer));

  AssignHexString(&bignum, "1234567ABCD");
  bignum.MultiplyByUInt64(0xFF'FFFF'FFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1234567ABCBDCBA985433", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt64(0x2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1FFFFFFFFFFFFFFFE", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt64(0x4);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3FFFFFFFFFFFFFFFC", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt64(0xF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("EFFFFFFFFFFFFFFF1", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFFFF");
  bignum.MultiplyByUInt64(0xFFFF'FFFF'FFFF'FFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFFFE0000000000000001", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // "10 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt64(2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("20000000000000000000000000", buffer));

  bignum.AssignUInt16(0x1);
  bignum.ShiftLeft(100);
  // "10 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt64(0xF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("F0000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt64(0xFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFE00010000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt64(0xFFFFFFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFEFFFF00010000000000000000000000000", buffer));

  bignum.AssignUInt16(0xFFFF);
  bignum.ShiftLeft(100);
  // "FFFF0 0000 0000 0000 0000 0000 0000"
  bignum.MultiplyByUInt64(0xFFFF'FFFF'FFFF'FFFF);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFEFFFFFFFFFFFF00010000000000000000000000000", buffer));

  AssignDecimalString(&bignum, "15611230384529777");
  bignum.MultiplyByUInt64(0x8AC7'2304'89E8'0000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1E10EE4B11D15A7F3DE7F3C7680000", buffer));
}

TEST_F(BignumTest, MultiplyPowerOfTen) {
  char buffer[kBufferSize];
  Bignum bignum;

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3034", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1E208", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(3);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("12D450", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(4);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("BC4B20", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("75AEF40", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(6);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("498D5880", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(7);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2DF857500", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(8);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1CBB369200", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(9);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("11F5021B400", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(10);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("B3921510800", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(11);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("703B4D2A5000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(12);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("4625103A72000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(13);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2BD72A24874000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(14);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1B667A56D488000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(15);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("11200C7644D50000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(16);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("AB407C9EB0520000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(17);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("6B084DE32E3340000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(18);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("42E530ADFCE0080000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(19);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("29CF3E6CBE0C0500000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(20);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1A218703F6C783200000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(21);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1054F4627A3CB1F400000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(22);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A3518BD8C65EF38800000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(23);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("6612F7677BFB5835000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(24);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3FCBDAA0AD7D17212000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(25);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("27DF68A46C6E2E74B4000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(26);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("18EBA166C3C4DD08F08000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(27);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("F9344E03A5B0A259650000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(28);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("9BC0B0C2478E6577DF20000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(29);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("61586E796CB8FF6AEB740000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(30);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3CD7450BE3F39FA2D32880000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(31);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("26068B276E7843C5C3F9500000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(50);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("149D1B4CFED03B23AB5F4E1196EF45C08000000000000", buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("5827249F27165024FBC47DFCA9359BF316332D1B91ACEECF471FBAB06D9B2"
                "0000000000000000000000000",
                buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(200);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("64C1F5C06C3816AFBF8DAFD5A3D756365BB0FD020E6F084E759C1F7C99E4F"
                "55B9ACC667CEC477EB958C2AEEB3C6C19BA35A1AD30B35C51EB72040920000"
                "0000000000000000000000000000000000000000000000",
                buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(500);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("96741A625EB5D7C91039FEB5C5ACD6D9831EDA5B083D800E6019442C8C8223"
                "3EAFB3501FE2058062221E15121334928880827DEE1EC337A8B26489F3A40A"
                "CB440A2423734472D10BFCE886F41B3AF9F9503013D86D088929CA86EEB4D8"
                "B9C831D0BD53327B994A0326227CFD0ECBF2EB48B02387AAE2D4CCCDF1F1A1"
                "B8CC4F1FA2C56AD40D0E4DAA9C28CDBF0A549098EA13200000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000",
                buffer));

  AssignDecimalString(&bignum, "1234");
  bignum.MultiplyByPowerOfTen(1000);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("1258040F99B1CD1CC9819C676D413EA50E4A6A8F114BB0C65418C62D399B81"
                "6361466CA8E095193E1EE97173553597C96673AF67FAFE27A66E7EF2E5EF2E"
                "E3F5F5070CC17FE83BA53D40A66A666A02F9E00B0E11328D2224B8694C7372"
                "F3D536A0AD1985911BD361496F268E8B23112500EAF9B88A9BC67B2AB04D38"
                "7FEFACD00F5AF4F764F9ABC3ABCDE54612DE38CD90CB6647CA389EA0E86B16"
                "BF7A1F34086E05ADBE00BD1673BE00FAC4B34AF1091E8AD50BA675E0381440"
                "EA8E9D93E75D816BAB37C9844B1441C38FC65CF30ABB71B36433AF26DD97BD"
                "ABBA96C03B4919B8F3515B92826B85462833380DC193D79F69D20DD6038C99"
                "6114EF6C446F0BA28CC772ACBA58B81C04F8FFDE7B18C4E5A3ABC51E637FDF"
                "6E37FDFF04C940919390F4FF92000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000",
                buffer));

  Bignum bignum2;
  AssignHexString(&bignum2,
                  "3DA774C07FB5DF54284D09C675A492165B830D5DAAEB2A7501"
                  "DA17CF9DFA1CA2282269F92A25A97314296B717E3DCBB9FE17"
                  "41A842FE2913F540F40796F2381155763502C58B15AF7A7F88"
                  "6F744C9164FF409A28F7FA0C41F89ED79C1BE9F322C8578B97"
                  "841F1CBAA17D901BE1230E3C00E1C643AF32638B5674E01FEA"
                  "96FC90864E621B856A9E1CE56E6EB545B9C2F8F0CC10DDA88D"
                  "CC6D282605F8DB67044F2DFD3695E7BA63877AE16701536AE6"
                  "567C794D0BFE338DFBB42D92D4215AF3BB22BF0A8B283FDDC2"
                  "C667A10958EA6D2");
  EXPECT_TRUE(bignum2.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("3DA774C07FB5DF54284D09C675A492165B830D5DAAEB2A7501"
                      "DA17CF9DFA1CA2282269F92A25A97314296B717E3DCBB9FE17"
                      "41A842FE2913F540F40796F2381155763502C58B15AF7A7F88"
                      "6F744C9164FF409A28F7FA0C41F89ED79C1BE9F322C8578B97"
                      "841F1CBAA17D901BE1230E3C00E1C643AF32638B5674E01FEA"
                      "96FC90864E621B856A9E1CE56E6EB545B9C2F8F0CC10DDA88D"
                      "CC6D282605F8DB67044F2DFD3695E7BA63877AE16701536AE6"
                      "567C794D0BFE338DFBB42D92D4215AF3BB22BF0A8B283FDDC2"
                      "C667A10958EA6D2",
                      buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("2688A8F84FD1AB949930261C0986DB4DF931E85A8AD2FA8921284EE1C2BC51"
                "E55915823BBA5789E7EC99E326EEE69F543ECE890929DED9AC79489884BE57"
                "630AD569E121BB76ED8DAC8FB545A8AFDADF1F8860599AFC47A93B6346C191"
                "7237F5BD36B73EB29371F4A4EE7A116CB5E8E5808D1BEA4D7F7E3716090C13"
                "F29E5DDA53F0FD513362A2D20F6505314B9419DB967F8A8A89589FC43917C3"
                "BB892062B17CBE421DB0D47E34ACCCE060D422CFF60DCBD0277EE038BD509C"
                "7BC494D8D854F5B76696F927EA99BC00C4A5D7928434",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0,
```