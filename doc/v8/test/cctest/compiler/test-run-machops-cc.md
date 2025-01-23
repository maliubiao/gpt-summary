Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code seems to be a series of unit tests for low-level machine operations in V8's compiler.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The filename `test-run-machops.cc` strongly suggests that the code tests the execution of machine operations. The `TEST(...)` macros confirm this is a unit testing file.

2. **Look for recurring patterns:**  Notice the pattern of `RawMachineAssemblerTester` and `BufferedRawMachineAssemblerTester`. These are classes used to create and execute snippets of machine code for testing purposes. The `<int32_t>`, `<uint32_t>`, `<int64_t>`, `<uint64_t>`, `<float>`, `<double>` template arguments indicate the data types being operated on.

3. **Examine individual tests:**  Each `TEST(...)` block focuses on a specific machine operation. The names of the tests clearly indicate which operation is being tested (e.g., `RunInt32Add`, `RunWord32ReverseBits`, `RunFloat64Select`).

4. **Understand the test structure:** Inside each test, there's a common structure:
    * Create a `RawMachineAssemblerTester` or `BufferedRawMachineAssemblerTester`.
    * Use the tester's methods (e.g., `Int32Add`, `Word32Shl`, `Word64ReverseBytes`) to build a simple sequence of machine instructions.
    * Use `m.Return(...)` to specify the return value of the generated code.
    * Use `CHECK_EQ(...)` or `CHECK_FLOAT_EQ(...)` or `CHECK_DOUBLE_EQ(...)` to assert that the result of executing the generated code matches the expected value for various inputs.

5. **Identify tested operations:**  Go through the `TEST(...)` blocks and list the machine operations being tested. This includes arithmetic operations (`Int32Add`, `Int64AddWithOverflow`), bitwise operations (`Word32ReverseBits`, `Word32ReverseBytes`, `Word32Ctz`, `Word32Clz`, `Word32Popcnt`), shift operations (`Word32Shl`), select operations (`Word32Select`, `Word64Select`, `Float32Select`, `Float64Select`), and potentially others.

6. **Pay attention to conditional compilation:**  Notice the `#if V8_TARGET_ARCH_64_BIT` blocks. This means some tests are specific to 64-bit architectures.

7. **Look for helper functions/structures:**  The `RunInt32AddShift` function and the `Test_case` struct within it are helper structures for running parameterized tests.

8. **Consider potential connections to JavaScript:** While the code directly tests machine operations, these operations are the building blocks for implementing JavaScript features. Consider how these low-level operations might be used in JavaScript (e.g., bitwise operators, arithmetic, comparisons).

9. **Infer potential programming errors:** Think about common mistakes developers make related to the tested operations (e.g., integer overflow, incorrect bit manipulation).

10. **Formulate the summary:** Combine the observations from the previous steps to create a concise summary of the code's functionality. Emphasize the testing aspect, the types of operations tested, and the use of the `RawMachineAssemblerTester`.

11. **Address the ".tq" question:** The code is clearly C++, not Torque, based on the file extension and syntax.

12. **Provide JavaScript examples:**  Give concrete JavaScript code snippets that demonstrate the higher-level equivalents of the tested machine operations.

13. **Illustrate code logic and assumptions:** For tests with more complex logic (like `RunInt32AddShift`), provide example inputs and expected outputs to clarify the operation.

14. **Give examples of common programming errors:** Show JavaScript examples of how developers might misuse the concepts being tested (e.g., integer overflow in JavaScript bitwise operations).

15. **Consolidate the findings for part 1:**  Summarize the functionality covered in the first part of the file.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include <cmath>
#include <functional>
#include <limits>

#include "src/base/bits.h"
#include "src/base/ieee754.h"
#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins.h"
#include "src/common/ptr-compr-inl.h"
#include "src/objects/objects-inl.h"
#include "src/utils/boxed-float.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/flag-utils.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

TEST(RunInt32Add) {
  RawMachineAssemblerTester<int32_t> m;
  Node* add = m.Int32Add(m.Int32Constant(0), m.Int32Constant(1));
  m.Return(add);
  CHECK_EQ(1, m.Call());
}

static int RunInt32AddShift(bool is_left, int32_t add_left, int32_t add_right,
                            int32_t shift_left, int32_t shift_right) {
  RawMachineAssemblerTester<int32_t> m;
  Node* shift =
      m.Word32Shl(m.Int32Constant(shift_left), m.Int32Constant(shift_right));
  Node* add = m.Int32Add(m.Int32Constant(add_left), m.Int32Constant(add_right));
  Node* lsa = is_left ? m.Int32Add(shift, add) : m.Int32Add(add, shift);
  m.Return(lsa);
  return m.Call();
}

TEST(RunInt32AddShift) {
  struct Test_case {
    int32_t add_left, add_right, shift_left, shift_right, expected;
  };

  Test_case tc[] = {
      {20, 22, 4, 2, 58},
      {20, 22, 4, 1, 50},
      {20, 22, 1, 6, 106},
      {INT_MAX - 2, 1, 1, 1, INT_MIN},  // INT_MAX - 2 + 1 + (1 << 1), overflow.
  };
  const size_t tc_size = sizeof(tc) / sizeof(Test_case);

  for (size_t i = 0; i < tc_size; ++i) {
    CHECK_EQ(tc[i].expected,
             RunInt32AddShift(false, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
    CHECK_EQ(tc[i].expected,
             RunInt32AddShift(true, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
  }
}

TEST(RunWord32ReverseBits) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32ReverseBits().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32ReverseBits().op(), m.Parameter(0)));

  CHECK_EQ(uint32_t(0x00000000), m.Call(uint32_t(0x00000000)));
  CHECK_EQ(uint32_t(0x12345678), m.Call(uint32_t(0x1E6A2C48)));
  CHECK_EQ(uint32_t(0xFEDCBA09), m.Call(uint32_t(0x905D3B7F)));
  CHECK_EQ(uint32_t(0x01010101), m.Call(uint32_t(0x80808080)));
  CHECK_EQ(uint32_t(0x01020408), m.Call(uint32_t(0x10204080)));
  CHECK_EQ(uint32_t(0xF0703010), m.Call(uint32_t(0x080C0E0F)));
  CHECK_EQ(uint32_t(0x1F8D0A3A), m.Call(uint32_t(0x5C50B1F8)));
  CHECK_EQ(uint32_t(0xFFFFFFFF), m.Call(uint32_t(0xFFFFFFFF)));
}

TEST(RunWord32ReverseBytes) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.AddNode(m.machine()->Word32ReverseBytes(), m.Parameter(0)));

  CHECK_EQ(uint32_t(0x00000000), m.Call(uint32_t(0x00000000)));
  CHECK_EQ(uint32_t(0x12345678), m.Call(uint32_t(0x78563412)));
  CHECK_EQ(uint32_t(0xFEDCBA09), m.Call(uint32_t(0x09BADCFE)));
  CHECK_EQ(uint32_t(0x01010101), m.Call(uint32_t(0x01010101)));
  CHECK_EQ(uint32_t(0x01020408), m.Call(uint32_t(0x08040201)));
  CHECK_EQ(uint32_t(0xF0703010), m.Call(uint32_t(0x103070F0)));
  CHECK_EQ(uint32_t(0x1F8D0A3A), m.Call(uint32_t(0x3A0A8D1F)));
  CHECK_EQ(uint32_t(0xFFFFFFFF), m.Call(uint32_t(0xFFFFFFFF)));
}

TEST(RunWord32Ctz) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32Ctz().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32Ctz().op(), m.Parameter(0)));

  CHECK_EQ(32, m.Call(uint32_t(0x00000000)));
  CHECK_EQ(31, m.Call(uint32_t(0x80000000)));
  CHECK_EQ(30, m.Call(uint32_t(0x40000000)));
  CHECK_EQ(29, m.Call(uint32_t(0x20000000)));
  CHECK_EQ(28, m.Call(uint32_t(0x10000000)));
  CHECK_EQ(27, m.Call(uint32_t(0xA8000000)));
  CHECK_EQ(26, m.Call(uint32_t(0xF4000000)));
  CHECK_EQ(25, m.Call(uint32_t(0x62000000)));
  CHECK_EQ(24, m.Call(uint32_t(0x91000000)));
  CHECK_EQ(23, m.Call(uint32_t(0xCD800000)));
  CHECK_EQ(22, m.Call(uint32_t(0x09400000)));
  CHECK_EQ(21, m.Call(uint32_t(0xAF200000)));
  CHECK_EQ(20, m.Call(uint32_t(0xAC100000)));
  CHECK_EQ(19, m.Call(uint32_t(0xE0B80000)));
  CHECK_EQ(18, m.Call(uint32_t(0x9CE40000)));
  CHECK_EQ(17, m.Call(uint32_t(0xC7920000)));
  CHECK_EQ(16, m.Call(uint32_t(0xB8F10000)));
  CHECK_EQ(15, m.Call(uint32_t(0x3B9F8000)));
  CHECK_EQ(14, m.Call(uint32_t(0xDB4C4000)));
  CHECK_EQ(13, m.Call(uint32_t(0xE9A32000)));
  CHECK_EQ(12, m.Call(uint32_t(0xFCA61000)));
  CHECK_EQ(11, m.Call(uint32_t(0x6C8A7800)));
  CHECK_EQ(10, m.Call(uint32_t(0x8CE5A400)));
  CHECK_EQ(9, m.Call(uint32_t(0xCB7D0200)));
  CHECK_EQ(8, m.Call(uint32_t(0xCB4DC100)));
  CHECK_EQ(7, m.Call(uint32_t(0xDFBEC580)));
  CHECK_EQ(6, m.Call(uint32_t(0x27A9DB40)));
  CHECK_EQ(5, m.Call(uint32_t(0xDE3BCB20)));
  CHECK_EQ(4, m.Call(uint32_t(0xD7E8A610)));
  CHECK_EQ(3, m.Call(uint32_t(0x9AFDBC88)));
  CHECK_EQ(2, m.Call(uint32_t(0x9AFDBC84)));
  CHECK_EQ(1, m.Call(uint32_t(0x9AFDBC82)));
  CHECK_EQ(0, m.Call(uint32_t(0x9AFDBC81)));
}

TEST(RunWord32Clz) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  m.Return(m.Word32Clz(m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint32_t(0x80001000)));
  CHECK_EQ(1, m.Call(uint32_t(0x40000500)));
  CHECK_EQ(2, m.Call(uint32_t(0x20000300)));
  CHECK_EQ(3, m.Call(uint32_t(0x10000003)));
  CHECK_EQ(4, m.Call(uint32_t(0x08050000)));
  CHECK_EQ(5, m.Call(uint32_t(0x04006000)));
  CHECK_EQ(6, m.Call(uint32_t(0x02000000)));
  CHECK_EQ(7, m.Call(uint32_t(0x010000A0)));
  CHECK_EQ(8, m.Call(uint32_t(0x00800C00)));
  CHECK_EQ(9, m.Call(uint32_t(0x00400000)));
  CHECK_EQ(10, m.Call(uint32_t(0x0020000D)));
  CHECK_EQ(11, m.Call(uint32_t(0x00100F00)));
  CHECK_EQ(12, m.Call(uint32_t(0x00080000)));
  CHECK_EQ(13, m.Call(uint32_t(0x00041000)));
  CHECK_EQ(14, m.Call(uint32_t(0x00020020)));
  CHECK_EQ(15, m.Call(uint32_t(0x00010300)));
  CHECK_EQ(16, m.Call(uint32_t(0x00008040)));
  CHECK_EQ(17, m.Call(uint32_t(0x00004005)));
  CHECK_EQ(18, m.Call(uint32_t(0x00002050)));
  CHECK_EQ(19, m.Call(uint32_t(0x00001700)));
  CHECK_EQ(20, m.Call(uint32_t(0x00000870)));
  CHECK_EQ(21, m.Call(uint32_t(0x00000405)));
  CHECK_EQ(22, m.Call(uint32_t(0x00000203)));
  CHECK_EQ(23, m.Call(uint32_t(0x00000101)));
  CHECK_EQ(24, m.Call(uint32_t(0x00000089)));
  CHECK_EQ(25, m.Call(uint32_t(0x00000041)));
  CHECK_EQ(26, m.Call(uint32_t(0x00000022)));
  CHECK_EQ(27, m.Call(uint32_t(0x00000013)));
  CHECK_EQ(28, m.Call(uint32_t(0x00000008)));
  CHECK_EQ(29, m.Call(uint32_t(0x00000004)));
  CHECK_EQ(30, m.Call(uint32_t(0x00000002)));
  CHECK_EQ(31, m.Call(uint32_t(0x00000001)));
  CHECK_EQ(32, m.Call(uint32_t(0x00000000)));
}

TEST(RunWord32Popcnt) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32Popcnt().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32Popcnt().op(), m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint32_t(0x00000000)));
  CHECK_EQ(1, m.Call(uint32_t(0x00000001)));
  CHECK_EQ(1, m.Call(uint32_t(0x80000000)));
  CHECK_EQ(32, m.Call(uint32_t(0xFFFFFFFF)));
  CHECK_EQ(6, m.Call(uint32_t(0x000DC100)));
  CHECK_EQ(9, m.Call(uint32_t(0xE00DC100)));
  CHECK_EQ(11, m.Call(uint32_t(0xE00DC103)));
  CHECK_EQ(9, m.Call(uint32_t(0x000DC107)));
}
```

### 功能列举:

* **单元测试框架:**  该文件是V8 JavaScript 引擎的一部分，专门用于测试编译器中机器操作码（machine ops）的执行。它使用了 V8 的内部测试框架 `cctest`.
* **测试目标:**  它测试了各种 32 位整数 (`int32_t`, `uint32_t`) 的机器操作，例如：
    * **算术运算:** 加法 (`Int32Add`)
    * **位运算:** 左移 (`Word32Shl`), 位反转 (`Word32ReverseBits`), 字节反转 (`Word32ReverseBytes`), 计算尾部零个数 (`Word32Ctz`), 计算头部零个数 (`Word32Clz`), 计算置位比特数 (`Word32Popcnt`)
* **测试方法:**
    * 使用 `RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester` 类来构建简单的机器代码片段。
    * 使用 V8 内部的节点表示 (`Node*`) 来表示操作数和操作。
    * 通过 `m.Return()` 指定代码片段的返回值。
    * 使用 `CHECK_EQ()` 宏来断言执行结果是否符合预期。
* **参数化测试:**  `RunInt32AddShift` 函数和 `Test_case` 结构体展示了如何使用参数化的方式运行多个测试用例。
* **平台依赖性:** `Word32ReverseBits` 和 `Word32Ctz` 的测试会检查当前平台是否支持相应的指令，如果不支持则跳过测试。

### 关于文件扩展名:

`v8/test/cctest/compiler/test-run-machops.cc` 的文件扩展名是 `.cc`，这表明它是一个 C++ 源代码文件，而不是 Torque 源代码文件（Torque 文件的扩展名通常是 `.tq`）。

### 与 JavaScript 的关系和示例:

虽然这段代码是 C++，用于测试 V8 内部的机器操作，但这些机器操作是 JavaScript 引擎执行 JavaScript 代码的基础。以下是一些 JavaScript 示例，它们在底层可能会使用到这里测试的机器操作：

* **加法 (`Int32Add`):**
   ```javascript
   let a = 10;
   let b = 20;
   let sum = a + b; // 底层可能会使用 Int32Add
   console.log(sum); // 输出 30
   ```

* **左移 (`Word32Shl`):**
   ```javascript
   let num = 4; // 二进制 0100
   let shifted = num << 2; // 二进制 010000 (相当于乘以 4)
   console.log(shifted); // 输出 16
   ```

* **位反转 (没有直接对应的 JavaScript 操作符，但可以通过一些技巧实现):**
   虽然 JavaScript 没有直接的位反转操作符，但 V8 内部的 `Word32ReverseBits` 可能用于实现某些特定的优化或算法。

* **字节反转 (也没有直接对应的 JavaScript 操作符):**  类似地，`Word32ReverseBytes` 可能在处理二进制数据时被 V8 内部使用。

* **计算尾部零个数 (`Word32Ctz`) 和头部零个数 (`Word32Clz`):**  这些操作在 JavaScript 中没有直接的语法，但可能用于优化某些算法，例如计算对数或者处理位掩码。

* **计算置位比特数 (`Word32Popcnt`):**
   ```javascript
   function countSetBits(n) {
     let count = 0;
     while (n > 0) {
       n &= (n - 1); // 清除最低位的 1
       count++;
     }
     return count;
   }
   console.log(countSetBits(0b101101)); // 输出 4
   ```
   V8 内部可能会使用 `Word32Popcnt` 来更高效地实现类似的功能。

### 代码逻辑推理 (假设输入与输出):

**测试 `RunInt32AddShift`:**

* **假设输入:** `is_left = false`, `add_left = 20`, `add_right = 22`, `shift_left = 4`, `shift_right = 2`
* **推理过程:**
    1. `shift` 计算 `4 << 2` (4 左移 2 位)，结果为 `16`。
    2. `add` 计算 `20 + 22`，结果为 `42`。
    3. `lsa` 计算 `add + shift`，即 `42 + 16`，结果为 `58`。
* **预期输出:** `58`

* **假设输入:** `is_left = true`, `add_left = INT_MAX - 2`, `add_right = 1`, `shift_left = 1`, `shift_right = 1`
* **推理过程:**
    1. `shift` 计算 `1 << 1`，结果为 `2`。
    2. `add` 计算 `(INT_MAX - 2) + 1`，结果为 `INT_MAX - 1`。
    3. `lsa` 计算 `shift + add`，即 `2 + (INT_MAX - 1)`。由于整数溢出，结果会回绕到 `INT_MIN`。
* **预期输出:** `INT_MIN`

### 涉及用户常见的编程错误 (JavaScript 举例):

* **整数溢出:** JavaScript 中的位运算符将数字视为 32 位有符号整数。当运算结果超出这个范围时，会发生回绕。
   ```javascript
   let maxInt = 2147483647; // 2^31 - 1
   console.log(maxInt + 1);   // 输出 -2147483648 (溢出回绕)

   let a = 2147483640;
   let b = 10;
   console.log(a + b); // 输出 -2147483646 (溢出)
   ```
   `RunInt32AddShift` 中的一个测试用例就演示了这种溢出情况。

* **位运算的误用:** 不理解位运算符的作用，导致得到意想不到的结果。
   ```javascript
   let num = 5; // 二进制 0101
   let result = num & 10; // 二进制 1010
   console.log(result); // 输出 0 (因为 0101 & 1010 = 0000)
   ```
   开发者可能期望得到其他结果，但由于对按位与运算符 `&` 的理解不足而出错。

### 第 1 部分功能归纳:

该 C++ 源代码文件 (`test-run-machops.cc`) 的第一部分主要功能是：

1. **为 V8 编译器的特定 32 位整数机器操作提供单元测试。**
2. **使用 `RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester` 构建和执行简单的机器代码片段。**
3. **测试了包括基本算术运算（加法）和多种位运算（位反转、字节反转、计算前导/尾部零、计算置位比特数）在内的操作。**
4. **展示了如何编写参数化的测试用例。**
5. **考虑了平台依赖性，并在不支持某些指令的平台上跳过相应的测试。**

总而言之，这部分代码是 V8 引擎质量保证的重要组成部分，确保了编译器生成的机器代码对于基本的 32 位整数操作是正确无误的。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved. Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

#include <cmath>
#include <functional>
#include <limits>

#include "src/base/bits.h"
#include "src/base/ieee754.h"
#include "src/base/overflowing-math.h"
#include "src/base/safe_conversions.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/builtins.h"
#include "src/common/ptr-compr-inl.h"
#include "src/objects/objects-inl.h"
#include "src/utils/boxed-float.h"
#include "src/utils/utils.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/flag-utils.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {


TEST(RunInt32Add) {
  RawMachineAssemblerTester<int32_t> m;
  Node* add = m.Int32Add(m.Int32Constant(0), m.Int32Constant(1));
  m.Return(add);
  CHECK_EQ(1, m.Call());
}

static int RunInt32AddShift(bool is_left, int32_t add_left, int32_t add_right,
                            int32_t shift_left, int32_t shift_right) {
  RawMachineAssemblerTester<int32_t> m;
  Node* shift =
      m.Word32Shl(m.Int32Constant(shift_left), m.Int32Constant(shift_right));
  Node* add = m.Int32Add(m.Int32Constant(add_left), m.Int32Constant(add_right));
  Node* lsa = is_left ? m.Int32Add(shift, add) : m.Int32Add(add, shift);
  m.Return(lsa);
  return m.Call();
}

TEST(RunInt32AddShift) {
  struct Test_case {
    int32_t add_left, add_right, shift_left, shift_right, expected;
  };

  Test_case tc[] = {
      {20, 22, 4, 2, 58},
      {20, 22, 4, 1, 50},
      {20, 22, 1, 6, 106},
      {INT_MAX - 2, 1, 1, 1, INT_MIN},  // INT_MAX - 2 + 1 + (1 << 1), overflow.
  };
  const size_t tc_size = sizeof(tc) / sizeof(Test_case);

  for (size_t i = 0; i < tc_size; ++i) {
    CHECK_EQ(tc[i].expected,
             RunInt32AddShift(false, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
    CHECK_EQ(tc[i].expected,
             RunInt32AddShift(true, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
  }
}

TEST(RunWord32ReverseBits) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32ReverseBits().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32ReverseBits().op(), m.Parameter(0)));

  CHECK_EQ(uint32_t(0x00000000), m.Call(uint32_t(0x00000000)));
  CHECK_EQ(uint32_t(0x12345678), m.Call(uint32_t(0x1E6A2C48)));
  CHECK_EQ(uint32_t(0xFEDCBA09), m.Call(uint32_t(0x905D3B7F)));
  CHECK_EQ(uint32_t(0x01010101), m.Call(uint32_t(0x80808080)));
  CHECK_EQ(uint32_t(0x01020408), m.Call(uint32_t(0x10204080)));
  CHECK_EQ(uint32_t(0xF0703010), m.Call(uint32_t(0x080C0E0F)));
  CHECK_EQ(uint32_t(0x1F8D0A3A), m.Call(uint32_t(0x5C50B1F8)));
  CHECK_EQ(uint32_t(0xFFFFFFFF), m.Call(uint32_t(0xFFFFFFFF)));
}

TEST(RunWord32ReverseBytes) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Return(m.AddNode(m.machine()->Word32ReverseBytes(), m.Parameter(0)));

  CHECK_EQ(uint32_t(0x00000000), m.Call(uint32_t(0x00000000)));
  CHECK_EQ(uint32_t(0x12345678), m.Call(uint32_t(0x78563412)));
  CHECK_EQ(uint32_t(0xFEDCBA09), m.Call(uint32_t(0x09BADCFE)));
  CHECK_EQ(uint32_t(0x01010101), m.Call(uint32_t(0x01010101)));
  CHECK_EQ(uint32_t(0x01020408), m.Call(uint32_t(0x08040201)));
  CHECK_EQ(uint32_t(0xF0703010), m.Call(uint32_t(0x103070F0)));
  CHECK_EQ(uint32_t(0x1F8D0A3A), m.Call(uint32_t(0x3A0A8D1F)));
  CHECK_EQ(uint32_t(0xFFFFFFFF), m.Call(uint32_t(0xFFFFFFFF)));
}

TEST(RunWord32Ctz) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32Ctz().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32Ctz().op(), m.Parameter(0)));

  CHECK_EQ(32, m.Call(uint32_t(0x00000000)));
  CHECK_EQ(31, m.Call(uint32_t(0x80000000)));
  CHECK_EQ(30, m.Call(uint32_t(0x40000000)));
  CHECK_EQ(29, m.Call(uint32_t(0x20000000)));
  CHECK_EQ(28, m.Call(uint32_t(0x10000000)));
  CHECK_EQ(27, m.Call(uint32_t(0xA8000000)));
  CHECK_EQ(26, m.Call(uint32_t(0xF4000000)));
  CHECK_EQ(25, m.Call(uint32_t(0x62000000)));
  CHECK_EQ(24, m.Call(uint32_t(0x91000000)));
  CHECK_EQ(23, m.Call(uint32_t(0xCD800000)));
  CHECK_EQ(22, m.Call(uint32_t(0x09400000)));
  CHECK_EQ(21, m.Call(uint32_t(0xAF200000)));
  CHECK_EQ(20, m.Call(uint32_t(0xAC100000)));
  CHECK_EQ(19, m.Call(uint32_t(0xE0B80000)));
  CHECK_EQ(18, m.Call(uint32_t(0x9CE40000)));
  CHECK_EQ(17, m.Call(uint32_t(0xC7920000)));
  CHECK_EQ(16, m.Call(uint32_t(0xB8F10000)));
  CHECK_EQ(15, m.Call(uint32_t(0x3B9F8000)));
  CHECK_EQ(14, m.Call(uint32_t(0xDB4C4000)));
  CHECK_EQ(13, m.Call(uint32_t(0xE9A32000)));
  CHECK_EQ(12, m.Call(uint32_t(0xFCA61000)));
  CHECK_EQ(11, m.Call(uint32_t(0x6C8A7800)));
  CHECK_EQ(10, m.Call(uint32_t(0x8CE5A400)));
  CHECK_EQ(9, m.Call(uint32_t(0xCB7D0200)));
  CHECK_EQ(8, m.Call(uint32_t(0xCB4DC100)));
  CHECK_EQ(7, m.Call(uint32_t(0xDFBEC580)));
  CHECK_EQ(6, m.Call(uint32_t(0x27A9DB40)));
  CHECK_EQ(5, m.Call(uint32_t(0xDE3BCB20)));
  CHECK_EQ(4, m.Call(uint32_t(0xD7E8A610)));
  CHECK_EQ(3, m.Call(uint32_t(0x9AFDBC88)));
  CHECK_EQ(2, m.Call(uint32_t(0x9AFDBC84)));
  CHECK_EQ(1, m.Call(uint32_t(0x9AFDBC82)));
  CHECK_EQ(0, m.Call(uint32_t(0x9AFDBC81)));
}

TEST(RunWord32Clz) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  m.Return(m.Word32Clz(m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint32_t(0x80001000)));
  CHECK_EQ(1, m.Call(uint32_t(0x40000500)));
  CHECK_EQ(2, m.Call(uint32_t(0x20000300)));
  CHECK_EQ(3, m.Call(uint32_t(0x10000003)));
  CHECK_EQ(4, m.Call(uint32_t(0x08050000)));
  CHECK_EQ(5, m.Call(uint32_t(0x04006000)));
  CHECK_EQ(6, m.Call(uint32_t(0x02000000)));
  CHECK_EQ(7, m.Call(uint32_t(0x010000A0)));
  CHECK_EQ(8, m.Call(uint32_t(0x00800C00)));
  CHECK_EQ(9, m.Call(uint32_t(0x00400000)));
  CHECK_EQ(10, m.Call(uint32_t(0x0020000D)));
  CHECK_EQ(11, m.Call(uint32_t(0x00100F00)));
  CHECK_EQ(12, m.Call(uint32_t(0x00080000)));
  CHECK_EQ(13, m.Call(uint32_t(0x00041000)));
  CHECK_EQ(14, m.Call(uint32_t(0x00020020)));
  CHECK_EQ(15, m.Call(uint32_t(0x00010300)));
  CHECK_EQ(16, m.Call(uint32_t(0x00008040)));
  CHECK_EQ(17, m.Call(uint32_t(0x00004005)));
  CHECK_EQ(18, m.Call(uint32_t(0x00002050)));
  CHECK_EQ(19, m.Call(uint32_t(0x00001700)));
  CHECK_EQ(20, m.Call(uint32_t(0x00000870)));
  CHECK_EQ(21, m.Call(uint32_t(0x00000405)));
  CHECK_EQ(22, m.Call(uint32_t(0x00000203)));
  CHECK_EQ(23, m.Call(uint32_t(0x00000101)));
  CHECK_EQ(24, m.Call(uint32_t(0x00000089)));
  CHECK_EQ(25, m.Call(uint32_t(0x00000041)));
  CHECK_EQ(26, m.Call(uint32_t(0x00000022)));
  CHECK_EQ(27, m.Call(uint32_t(0x00000013)));
  CHECK_EQ(28, m.Call(uint32_t(0x00000008)));
  CHECK_EQ(29, m.Call(uint32_t(0x00000004)));
  CHECK_EQ(30, m.Call(uint32_t(0x00000002)));
  CHECK_EQ(31, m.Call(uint32_t(0x00000001)));
  CHECK_EQ(32, m.Call(uint32_t(0x00000000)));
}


TEST(RunWord32Popcnt) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  if (!m.machine()->Word32Popcnt().IsSupported()) {
    // We can only test the operator if it exists on the testing platform.
    return;
  }
  m.Return(m.AddNode(m.machine()->Word32Popcnt().op(), m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint32_t(0x00000000)));
  CHECK_EQ(1, m.Call(uint32_t(0x00000001)));
  CHECK_EQ(1, m.Call(uint32_t(0x80000000)));
  CHECK_EQ(32, m.Call(uint32_t(0xFFFFFFFF)));
  CHECK_EQ(6, m.Call(uint32_t(0x000DC100)));
  CHECK_EQ(9, m.Call(uint32_t(0xE00DC100)));
  CHECK_EQ(11, m.Call(uint32_t(0xE00DC103)));
  CHECK_EQ(9, m.Call(uint32_t(0x000DC107)));
}


#if V8_TARGET_ARCH_64_BIT
TEST(RunWord64ReverseBits) {
  RawMachineAssemblerTester<uint64_t> m(MachineType::Uint64());
  if (!m.machine()->Word64ReverseBits().IsSupported()) {
    return;
  }

  m.Return(m.AddNode(m.machine()->Word64ReverseBits().op(), m.Parameter(0)));

  CHECK_EQ(uint64_t(0x0000000000000000), m.Call(uint64_t(0x0000000000000000)));
  CHECK_EQ(uint64_t(0x1234567890ABCDEF), m.Call(uint64_t(0xF7B3D5091E6A2C48)));
  CHECK_EQ(uint64_t(0xFEDCBA0987654321), m.Call(uint64_t(0x84C2A6E1905D3B7F)));
  CHECK_EQ(uint64_t(0x0101010101010101), m.Call(uint64_t(0x8080808080808080)));
  CHECK_EQ(uint64_t(0x0102040803060C01), m.Call(uint64_t(0x803060C010204080)));
  CHECK_EQ(uint64_t(0xF0703010E060200F), m.Call(uint64_t(0xF0040607080C0E0F)));
  CHECK_EQ(uint64_t(0x2F8A6DF01C21FA3B), m.Call(uint64_t(0xDC5F84380FB651F4)));
  CHECK_EQ(uint64_t(0xFFFFFFFFFFFFFFFF), m.Call(uint64_t(0xFFFFFFFFFFFFFFFF)));
}

TEST(RunWord64ReverseBytes) {
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Uint64());
  m.Return(m.AddNode(m.machine()->Word64ReverseBytes(), m.Parameter(0)));

  CHECK_EQ(uint64_t(0x0000000000000000), m.Call(uint64_t(0x0000000000000000)));
  CHECK_EQ(uint64_t(0x1234567890ABCDEF), m.Call(uint64_t(0xEFCDAB9078563412)));
  CHECK_EQ(uint64_t(0xFEDCBA0987654321), m.Call(uint64_t(0x2143658709BADCFE)));
  CHECK_EQ(uint64_t(0x0101010101010101), m.Call(uint64_t(0x0101010101010101)));
  CHECK_EQ(uint64_t(0x0102040803060C01), m.Call(uint64_t(0x010C060308040201)));
  CHECK_EQ(uint64_t(0xF0703010E060200F), m.Call(uint64_t(0x0F2060E0103070F0)));
  CHECK_EQ(uint64_t(0x2F8A6DF01C21FA3B), m.Call(uint64_t(0x3BFA211CF06D8A2F)));
  CHECK_EQ(uint64_t(0xFFFFFFFFFFFFFFFF), m.Call(uint64_t(0xFFFFFFFFFFFFFFFF)));
}

TEST(RunWord64Clz) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint64());
  m.Return(m.Word64Clz(m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint64_t(0x8000100000000000)));
  CHECK_EQ(1, m.Call(uint64_t(0x4000050000000000)));
  CHECK_EQ(2, m.Call(uint64_t(0x2000030000000000)));
  CHECK_EQ(3, m.Call(uint64_t(0x1000000300000000)));
  CHECK_EQ(4, m.Call(uint64_t(0x0805000000000000)));
  CHECK_EQ(5, m.Call(uint64_t(0x0400600000000000)));
  CHECK_EQ(6, m.Call(uint64_t(0x0200000000000000)));
  CHECK_EQ(7, m.Call(uint64_t(0x010000A000000000)));
  CHECK_EQ(8, m.Call(uint64_t(0x00800C0000000000)));
  CHECK_EQ(9, m.Call(uint64_t(0x0040000000000000)));
  CHECK_EQ(10, m.Call(uint64_t(0x0020000D00000000)));
  CHECK_EQ(11, m.Call(uint64_t(0x00100F0000000000)));
  CHECK_EQ(12, m.Call(uint64_t(0x0008000000000000)));
  CHECK_EQ(13, m.Call(uint64_t(0x0004100000000000)));
  CHECK_EQ(14, m.Call(uint64_t(0x0002002000000000)));
  CHECK_EQ(15, m.Call(uint64_t(0x0001030000000000)));
  CHECK_EQ(16, m.Call(uint64_t(0x0000804000000000)));
  CHECK_EQ(17, m.Call(uint64_t(0x0000400500000000)));
  CHECK_EQ(18, m.Call(uint64_t(0x0000205000000000)));
  CHECK_EQ(19, m.Call(uint64_t(0x0000170000000000)));
  CHECK_EQ(20, m.Call(uint64_t(0x0000087000000000)));
  CHECK_EQ(21, m.Call(uint64_t(0x0000040500000000)));
  CHECK_EQ(22, m.Call(uint64_t(0x0000020300000000)));
  CHECK_EQ(23, m.Call(uint64_t(0x0000010100000000)));
  CHECK_EQ(24, m.Call(uint64_t(0x0000008900000000)));
  CHECK_EQ(25, m.Call(uint64_t(0x0000004100000000)));
  CHECK_EQ(26, m.Call(uint64_t(0x0000002200000000)));
  CHECK_EQ(27, m.Call(uint64_t(0x0000001300000000)));
  CHECK_EQ(28, m.Call(uint64_t(0x0000000800000000)));
  CHECK_EQ(29, m.Call(uint64_t(0x0000000400000000)));
  CHECK_EQ(30, m.Call(uint64_t(0x0000000200000000)));
  CHECK_EQ(31, m.Call(uint64_t(0x0000000100000000)));
  CHECK_EQ(32, m.Call(uint64_t(0x0000000080001000)));
  CHECK_EQ(33, m.Call(uint64_t(0x0000000040000500)));
  CHECK_EQ(34, m.Call(uint64_t(0x0000000020000300)));
  CHECK_EQ(35, m.Call(uint64_t(0x0000000010000003)));
  CHECK_EQ(36, m.Call(uint64_t(0x0000000008050000)));
  CHECK_EQ(37, m.Call(uint64_t(0x0000000004006000)));
  CHECK_EQ(38, m.Call(uint64_t(0x0000000002000000)));
  CHECK_EQ(39, m.Call(uint64_t(0x00000000010000A0)));
  CHECK_EQ(40, m.Call(uint64_t(0x0000000000800C00)));
  CHECK_EQ(41, m.Call(uint64_t(0x0000000000400000)));
  CHECK_EQ(42, m.Call(uint64_t(0x000000000020000D)));
  CHECK_EQ(43, m.Call(uint64_t(0x0000000000100F00)));
  CHECK_EQ(44, m.Call(uint64_t(0x0000000000080000)));
  CHECK_EQ(45, m.Call(uint64_t(0x0000000000041000)));
  CHECK_EQ(46, m.Call(uint64_t(0x0000000000020020)));
  CHECK_EQ(47, m.Call(uint64_t(0x0000000000010300)));
  CHECK_EQ(48, m.Call(uint64_t(0x0000000000008040)));
  CHECK_EQ(49, m.Call(uint64_t(0x0000000000004005)));
  CHECK_EQ(50, m.Call(uint64_t(0x0000000000002050)));
  CHECK_EQ(51, m.Call(uint64_t(0x0000000000001700)));
  CHECK_EQ(52, m.Call(uint64_t(0x0000000000000870)));
  CHECK_EQ(53, m.Call(uint64_t(0x0000000000000405)));
  CHECK_EQ(54, m.Call(uint64_t(0x0000000000000203)));
  CHECK_EQ(55, m.Call(uint64_t(0x0000000000000101)));
  CHECK_EQ(56, m.Call(uint64_t(0x0000000000000089)));
  CHECK_EQ(57, m.Call(uint64_t(0x0000000000000041)));
  CHECK_EQ(58, m.Call(uint64_t(0x0000000000000022)));
  CHECK_EQ(59, m.Call(uint64_t(0x0000000000000013)));
  CHECK_EQ(60, m.Call(uint64_t(0x0000000000000008)));
  CHECK_EQ(61, m.Call(uint64_t(0x0000000000000004)));
  CHECK_EQ(62, m.Call(uint64_t(0x0000000000000002)));
  CHECK_EQ(63, m.Call(uint64_t(0x0000000000000001)));
  CHECK_EQ(64, m.Call(uint64_t(0x0000000000000000)));
}


TEST(RunWord64Ctz) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Uint64());
  if (!m.machine()->Word64Ctz().IsSupported()) {
    return;
  }

  m.Return(m.AddNode(m.machine()->Word64Ctz().op(), m.Parameter(0)));

  CHECK_EQ(64, m.Call(uint64_t(0x0000000000000000)));
  CHECK_EQ(63, m.Call(uint64_t(0x8000000000000000)));
  CHECK_EQ(62, m.Call(uint64_t(0x4000000000000000)));
  CHECK_EQ(61, m.Call(uint64_t(0x2000000000000000)));
  CHECK_EQ(60, m.Call(uint64_t(0x1000000000000000)));
  CHECK_EQ(59, m.Call(uint64_t(0xA800000000000000)));
  CHECK_EQ(58, m.Call(uint64_t(0xF400000000000000)));
  CHECK_EQ(57, m.Call(uint64_t(0x6200000000000000)));
  CHECK_EQ(56, m.Call(uint64_t(0x9100000000000000)));
  CHECK_EQ(55, m.Call(uint64_t(0xCD80000000000000)));
  CHECK_EQ(54, m.Call(uint64_t(0x0940000000000000)));
  CHECK_EQ(53, m.Call(uint64_t(0xAF20000000000000)));
  CHECK_EQ(52, m.Call(uint64_t(0xAC10000000000000)));
  CHECK_EQ(51, m.Call(uint64_t(0xE0B8000000000000)));
  CHECK_EQ(50, m.Call(uint64_t(0x9CE4000000000000)));
  CHECK_EQ(49, m.Call(uint64_t(0xC792000000000000)));
  CHECK_EQ(48, m.Call(uint64_t(0xB8F1000000000000)));
  CHECK_EQ(47, m.Call(uint64_t(0x3B9F800000000000)));
  CHECK_EQ(46, m.Call(uint64_t(0xDB4C400000000000)));
  CHECK_EQ(45, m.Call(uint64_t(0xE9A3200000000000)));
  CHECK_EQ(44, m.Call(uint64_t(0xFCA6100000000000)));
  CHECK_EQ(43, m.Call(uint64_t(0x6C8A780000000000)));
  CHECK_EQ(42, m.Call(uint64_t(0x8CE5A40000000000)));
  CHECK_EQ(41, m.Call(uint64_t(0xCB7D020000000000)));
  CHECK_EQ(40, m.Call(uint64_t(0xCB4DC10000000000)));
  CHECK_EQ(39, m.Call(uint64_t(0xDFBEC58000000000)));
  CHECK_EQ(38, m.Call(uint64_t(0x27A9DB4000000000)));
  CHECK_EQ(37, m.Call(uint64_t(0xDE3BCB2000000000)));
  CHECK_EQ(36, m.Call(uint64_t(0xD7E8A61000000000)));
  CHECK_EQ(35, m.Call(uint64_t(0x9AFDBC8800000000)));
  CHECK_EQ(34, m.Call(uint64_t(0x9AFDBC8400000000)));
  CHECK_EQ(33, m.Call(uint64_t(0x9AFDBC8200000000)));
  CHECK_EQ(32, m.Call(uint64_t(0x9AFDBC8100000000)));
  CHECK_EQ(31, m.Call(uint64_t(0x0000000080000000)));
  CHECK_EQ(30, m.Call(uint64_t(0x0000000040000000)));
  CHECK_EQ(29, m.Call(uint64_t(0x0000000020000000)));
  CHECK_EQ(28, m.Call(uint64_t(0x0000000010000000)));
  CHECK_EQ(27, m.Call(uint64_t(0x00000000A8000000)));
  CHECK_EQ(26, m.Call(uint64_t(0x00000000F4000000)));
  CHECK_EQ(25, m.Call(uint64_t(0x0000000062000000)));
  CHECK_EQ(24, m.Call(uint64_t(0x0000000091000000)));
  CHECK_EQ(23, m.Call(uint64_t(0x00000000CD800000)));
  CHECK_EQ(22, m.Call(uint64_t(0x0000000009400000)));
  CHECK_EQ(21, m.Call(uint64_t(0x00000000AF200000)));
  CHECK_EQ(20, m.Call(uint64_t(0x00000000AC100000)));
  CHECK_EQ(19, m.Call(uint64_t(0x00000000E0B80000)));
  CHECK_EQ(18, m.Call(uint64_t(0x000000009CE40000)));
  CHECK_EQ(17, m.Call(uint64_t(0x00000000C7920000)));
  CHECK_EQ(16, m.Call(uint64_t(0x00000000B8F10000)));
  CHECK_EQ(15, m.Call(uint64_t(0x000000003B9F8000)));
  CHECK_EQ(14, m.Call(uint64_t(0x00000000DB4C4000)));
  CHECK_EQ(13, m.Call(uint64_t(0x00000000E9A32000)));
  CHECK_EQ(12, m.Call(uint64_t(0x00000000FCA61000)));
  CHECK_EQ(11, m.Call(uint64_t(0x000000006C8A7800)));
  CHECK_EQ(10, m.Call(uint64_t(0x000000008CE5A400)));
  CHECK_EQ(9, m.Call(uint64_t(0x00000000CB7D0200)));
  CHECK_EQ(8, m.Call(uint64_t(0x00000000CB4DC100)));
  CHECK_EQ(7, m.Call(uint64_t(0x00000000DFBEC580)));
  CHECK_EQ(6, m.Call(uint64_t(0x0000000027A9DB40)));
  CHECK_EQ(5, m.Call(uint64_t(0x00000000DE3BCB20)));
  CHECK_EQ(4, m.Call(uint64_t(0x00000000D7E8A610)));
  CHECK_EQ(3, m.Call(uint64_t(0x000000009AFDBC88)));
  CHECK_EQ(2, m.Call(uint64_t(0x000000009AFDBC84)));
  CHECK_EQ(1, m.Call(uint64_t(0x000000009AFDBC82)));
  CHECK_EQ(0, m.Call(uint64_t(0x000000009AFDBC81)));
}


TEST(RunWord64Popcnt) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Uint64());
  if (!m.machine()->Word64Popcnt().IsSupported()) {
    return;
  }

  m.Return(m.AddNode(m.machine()->Word64Popcnt().op(), m.Parameter(0)));

  CHECK_EQ(0, m.Call(uint64_t(0x0000000000000000)));
  CHECK_EQ(1, m.Call(uint64_t(0x0000000000000001)));
  CHECK_EQ(1, m.Call(uint64_t(0x8000000000000000)));
  CHECK_EQ(64, m.Call(uint64_t(0xFFFFFFFFFFFFFFFF)));
  CHECK_EQ(12, m.Call(uint64_t(0x000DC100000DC100)));
  CHECK_EQ(18, m.Call(uint64_t(0xE00DC100E00DC100)));
  CHECK_EQ(22, m.Call(uint64_t(0xE00DC103E00DC103)));
  CHECK_EQ(18, m.Call(uint64_t(0x000DC107000DC107)));
}

#endif  // V8_TARGET_ARCH_64_BIT

TEST(RunWord32Select) {
  BufferedRawMachineAssemblerTester<int32_t> m(
      MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
  if (!m.machine()->Word32Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Word32Equal(m.Parameter(2), m.Int32Constant(0));
  m.Return(m.Word32Select(cmp, m.Parameter(0), m.Parameter(1)));
  constexpr int input1 = 16;
  constexpr int input2 = 3443;

  for (int i = 0; i < 2; ++i) {
    int expected = i == 0 ? input1 : input2;
    CHECK_EQ(expected, m.Call(input1, input2, i));
  }
}

TEST(RunWord64Select) {
  BufferedRawMachineAssemblerTester<int64_t> m(
      MachineType::Int64(), MachineType::Int64(), MachineType::Int32());
  if (!m.machine()->Word64Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Word32Equal(m.Parameter(2), m.Int32Constant(0));
  m.Return(m.Word64Select(cmp, m.Parameter(0), m.Parameter(1)));
  constexpr int64_t input1 = 16;
  constexpr int64_t input2 = 0x123456789abc;

  for (int i = 0; i < 2; ++i) {
    int64_t expected = i == 0 ? input1 : input2;
    CHECK_EQ(expected, m.Call(input1, input2, i));
  }
}

TEST(RunSelectUnorderedEqual) {
  BufferedRawMachineAssemblerTester<int64_t> m(
      MachineType::Int64(), MachineType::Int64(), MachineType::Float32());
  if (!m.machine()->Word64Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Float32Equal(m.Parameter(2), m.Float32Constant(0));
  m.Return(m.Word64Select(cmp, m.Parameter(0), m.Parameter(1)));
  constexpr int64_t input1 = 16;
  constexpr int64_t input2 = 0x123456789abc;

  CHECK_EQ(input1, m.Call(input1, input2, float{0}));
  CHECK_EQ(input2, m.Call(input1, input2, float{1}));
  CHECK_EQ(input2, m.Call(input1, input2, std::nanf("")));
}

TEST(RunSelectUnorderedNotEqual) {
  BufferedRawMachineAssemblerTester<int64_t> m(
      MachineType::Int64(), MachineType::Int64(), MachineType::Float32());
  if (!m.machine()->Word64Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Float32NotEqual(m.Parameter(2), m.Float32Constant(0));
  m.Return(m.Word64Select(cmp, m.Parameter(0), m.Parameter(1)));
  constexpr int64_t input1 = 16;
  constexpr int64_t input2 = 0x123456789abc;

  CHECK_EQ(input2, m.Call(input1, input2, float{0}));
  CHECK_EQ(input1, m.Call(input1, input2, float{1}));
  CHECK_EQ(input1, m.Call(input1, input2, std::nanf("")));
}

namespace {
template <typename T>
ExternalReference ExternalRefFromFunc(RawMachineAssemblerTester<T>* m,
                                      Address func_address) {
  ExternalReference::Type func_type = ExternalReference::FAST_C_CALL;
  ApiFunction func(func_address);
  ExternalReference ref = ExternalReference::Create(&func, func_type);
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  EncodedCSignature sig = m->call_descriptor()->ToEncodedCSignature();
  m->main_isolate()->simulator_data()->AddSignatureForTargetForTesting(
      func_address, sig);
#endif
  return ref;
}
}  // namespace

namespace {
void FooForSelect() {}
}  // namespace

TEST(RunWord32SelectWithMemoryInput) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                               MachineType::Int32());
  if (!m.machine()->Word32Select().IsSupported()) {
    return;
  }

  // Test that the generated code also works with values spilled on the stack.
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(FooForSelect));
  constexpr int input1 = 16;
  int input2 = 3443;
  // Load {value2} before the function call so that it gets spilled.
  Node* value2 = m.LoadFromPointer(&input2, MachineType::Int32());
  // Call a function so that {value2} gets spilled on the stack.
  Node* function = m.ExternalConstant(ref);
  m.CallCFunction(function, MachineType::Int32());
  Node* cmp = m.Word32Equal(m.Parameter(1), m.Int32Constant(0));
  m.Return(m.Word32Select(cmp, m.Parameter(0), value2));

  for (int i = 0; i < 2; ++i) {
    int32_t expected = i == 0 ? input1 : input2;
    CHECK_EQ(expected, m.Call(input1, i));
  }
}

TEST(RunWord64SelectWithMemoryInput) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64(),
                                               MachineType::Int32());
  if (!m.machine()->Word64Select().IsSupported()) {
    return;
  }

  // Test that the generated code also works with values spilled on the stack.

  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(FooForSelect));
  constexpr int64_t input1 = 16;
  int64_t input2 = 0x12345678ABCD;
  // Load {value2} before the function call so that it gets spilled.
  Node* value2 = m.LoadFromPointer(&input2, MachineType::Int64());
  // Call a function so that {value2} gets spilled on the stack.
  Node* function = m.ExternalConstant(ref);
  m.CallCFunction(function, MachineType::Int32());
  Node* cmp = m.Word32Equal(m.Parameter(1), m.Int32Constant(0));
  m.Return(m.Word64Select(cmp, m.Parameter(0), value2));

  for (int i = 0; i < 2; ++i) {
    int64_t expected = i == 0 ? input1 : input2;
    CHECK_EQ(expected, m.Call(input1, i));
  }
}

TEST(RunFloat32SelectRegFloatCompare) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32(),
                                             MachineType::Float32());
  if (!m.machine()->Float32Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Float32Equal(m.Parameter(0), m.Parameter(1));
  m.Return(m.Float32Select(cmp, m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT32_INPUTS(pl) {
    FOR_FLOAT32_INPUTS(pr) {
      float expected_result = pl == pr ? pl : pr;
      CHECK_FLOAT_EQ(expected_result, m.Call(pl, pr));
    }
  }
}

TEST(RunFloat64SelectRegFloatCompare) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  if (!m.machine()->Float64Select().IsSupported()) {
    return;
  }

  Node* cmp = m.Float64LessThan(m.Parameter(0), m.Parameter(1));
  m.Return(m.Float64Select(cmp, m.Parameter(0), m.Parameter(1)));

  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      double expected_result = pl < pr ? pl : pr;
      CHECK_DOUBLE_EQ(expected_result, m.Call(pl, pr));
    }
  }
}

TEST(RunFloat32SelectImmediateOnLeftFloatCompare) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  if (!m.machine()->Float32Select().IsSupported()) {
    return;
  }

  const float pl = -5.0;
  Node* a = m.Float32Constant(pl);
  Node* cmp = m.Float32LessThan(a, m.Parameter(0));
  m.Return(m.Float32Select(cmp, a, m.Parameter(0)));

  FOR_FLOAT32_INPUTS(pr) {
    float expected_result = pl < pr ? pl : pr;
    CHECK_FLOAT_EQ(expected_result, m.Call(pr));
  }
}

TEST(RunFloat64SelectImmediateOnRightFloatCompare) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64Select().IsSupported()) {
    return;
  }

  double pr = 5.0;
  Node* b = m.Float64Constant(pr);
  Node* cmp = m.Float64LessThanOrEqual(m.Parameter(0), b);
  m.Return(m.Float64Select(cmp, m.Parameter(0), b));

  FOR_FLOAT64_INPUTS(pl) {
    double expected_result = pl <= pr ? pl : pr;
    CHECK_DOUBLE_EQ(expected_result, m.Call(pl));
  }
}

TEST(RunFloat32SelectImmediateIntCompare) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Int32(),
                                             MachineType::Int32());
  if (!m.machine()->Float32Select().IsSupported()) {
    return;
  }

  float tval = -0.0;
  float fval = 1.0;
  Node* cmp = m.Int32LessThanOrEqual(m.Parameter(0), m.Parameter(1));
  m.Return(
      m.Float32Select(cmp, m.Float32Constant(tval), m.Float32Constant(fval)));

  FOR_INT32_INPUTS(pl) {
    FOR_INT32_INPUTS(pr) {
      float expected_result = pl <= pr ? tval : fval;
      float actual_result = m.Call(pl, pr);
      CHECK_FLOAT_EQ(expected_result, actual_result);
      CHECK_EQ(std::signbit(expected_result), std::signbit(actual_result));
    }
  }
}

TEST(RunFloat64SelectImmediateIntCompare) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Int64(),
                                              MachineType::Int64());
  if (!m.machine()->Float64Select().IsSupported()) {
    return;
  }

  double tval = -1.0;
  double fval = 0.0;
  Node* cmp = m.Int64LessThan(m.Parameter(0), m.Parameter(1));
  m.Return(m.Float64Select(cmp, m.Float64Constant(tval),
                           m.Float64Constant(fval)));

  FOR_INT64_INPUTS(pl) {
    FOR_INT64_INPUTS(pr) {
      double expected_result = pl < pr ? tval : fval;
      double actual_result = m.Call(pl, pr);
      CHECK_DOUBLE_EQ(expected_result, actual_result);
      CHECK_EQ(std::signbit(expected_result), std::signbit(actual_result));
    }
  }
}

static Node* Int32Input(RawMachineAssemblerTester<int32_t>* m, int index) {
  switch (index) {
    case 0:
      return m->Parameter(0);
    case 1:
      return m->Parameter(1);
    case 2:
      return m->Int32Constant(0);
    case 3:
      return m->Int32Constant(1);
    case 4:
      return m->Int32Constant(-1);
    case 5:
      return m->Int32Constant(0xFF);
    case 6:
      return m->Int32Constant(0x01234567);
    case 7:
      return m->Load(MachineType::Int32(), m->PointerConstant(nullptr));
    default:
      return nullptr;
  }
}


TEST(CodeGenInt32Binop) {
  RawMachineAssemblerTester<void> m;

  const Operator* kOps[] = {
      m.machine()->Word32And(),      m.machine()->Word32Or(),
      m.machine()->Word32Xor(),      m.machine()->Word32Shl(),
      m.machine()->Word32Shr(),      m.machine()->Word32Sar(),
      m.machine()->Word32Equal(),    m.machine()->Int32Add(),
      m.machine()->Int32Sub(),       m.machine()->Int32Mul(),
      m.machine()->Int32MulHigh(),   m.machine()->Int32Div(),
      m.machine()->Uint32Div(),      m.machine()->Int32Mod(),
      m.machine()->Uint32Mod(),      m.machine()->Uint32MulHigh(),
      m.machine()->Int32LessThan(),  m.machine()->Int32LessThanOrEqual(),
      m.machine()->Uint32LessThan(), m.machine()->Uint32LessThanOrEqual()};

  for (size_t i = 0; i < arraysize(kOps); ++i) {
    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 8; k++) {
        RawMachineAssemblerTester<int32_t> t(MachineType::Int32(),
                                             MachineType::Int32());
        Node* a = Int32Input(&t, j);
        Node* b = Int32Input(&t, k);
        t.Return(t.AddNode(kOps[i], a, b));
        t.GenerateCode();
      }
    }
  }
}


TEST(CodeGenNop) {
  RawMachineAssemblerTester<void> m;
  m.Return(m.Int32Constant(0));
  m.GenerateCode();
}


#if V8_TARGET_ARCH_64_BIT
static Node* Int64Input(RawMachineAssemblerTester<int64_t>* m, int index) {
  switch (index) {
    case 0:
      return m->Parameter(0);
    case 1:
      return m->Parameter(1);
    case 2:
      return m->Int64Constant(0);
    case 3:
      return m->Int64Constant(1);
    case 4:
      return m->Int64Constant(-1);
    case 5:
      return m->Int64Constant(0xFF);
    case 6:
      return m->Int64Constant(0x0123456789ABCDEFLL);
    case 7:
      return m->Load(MachineType::Int64(), m->PointerConstant(nullptr));
    default:
      return nullptr;
  }
}


TEST(CodeGenInt64Binop) {
  RawMachineAssemblerTester<void> m;

  const Operator* kOps[] = {
      m.machine()->Word64And(), m.machine()->Word64Or(),
      m.machine()->Word64Xor(), m.machine()->Word64Shl(),
      m.machine()->Word64Shr(), m.machine()->Word64Sar(),
      m.machine()->Word64Equal(), m.machine()->Int64Add(),
      m.machine()->Int64Sub(), m.machine()->Int64Mul(), m.machine()->Int64Div(),
      m.machine()->Uint64Div(), m.machine()->Int64Mod(),
      m.machine()->Uint64Mod(), m.machine()->Int64LessThan(),
      m.machine()->Int64LessThanOrEqual(), m.machine()->Uint64LessThan(),
      m.machine()->Uint64LessThanOrEqual()};

  for (size_t i = 0; i < arraysize(kOps); ++i) {
    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 8; k++) {
        RawMachineAssemblerTester<int64_t> t(MachineType::Int64(),
                                             MachineType::Int64());
        Node* a = Int64Input(&t, j);
        Node* b = Int64Input(&t, k);
        t.Return(t.AddNode(kOps[i], a, b));
        t.GenerateCode();
      }
    }
  }
}


TEST(RunInt64AddWithOverflowP) {
  int64_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* add = m.Int64AddWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
  bt.AddReturn(ovf);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int64_t expected_val;
      int expected_ovf = base::bits::SignedAddOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64AddWithOverflowImm) {
  int64_t actual_val = -1, expected_val = 0;
  FOR_INT64_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64AddWithOverflow(m.Int64Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64AddWithOverflow(m.Parameter(0), m.Int64Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT64_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int64AddWithOverflow(m.Int64Constant(i), m.Int64Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedAddOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64AddWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* add = m.Int64AddWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int64Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  Node* truncated = m.TruncateInt64ToInt32(val);
  bt.AddReturn(truncated);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = constant;
      int64_t result;
      if (!base::bits::SignedAddOverflow64(i, j, &result)) {
        expected = static_cast<int32_t>(result);
      }
```