Response: The user wants a summary of the C++ code provided in the file `v8/test/cctest/compiler/test-run-machops.cc`.
The goal is to understand the functionality of this code.
Since the filename includes "test", it's likely that this file contains unit tests.
The code uses `RawMachineAssemblerTester` and `BufferedRawMachineAssemblerTester`, which suggests that it's testing the code generation for machine operations within the V8 compiler.

The tests seem to cover various machine-level operations like:
- Integer arithmetic (addition, subtraction, multiplication, division, modulo)
- Bitwise operations (AND, OR, XOR, shifts, reverse bits, reverse bytes, count leading zeros, count trailing zeros, population count)
- Comparisons (equal, less than, less than or equal)
- Conditional selection (select based on a boolean condition)
- Control flow (goto, branch, loops, switches)

The tests are structured using the `TEST()` macro, and they use `CHECK_EQ()` and other assertion macros to verify the correctness of the generated code.

The prompt also asks about the relationship with JavaScript. V8 is the JavaScript engine, so these tests directly relate to how JavaScript operations are translated into machine code. For example, an integer addition in JavaScript will eventually be handled by a machine instruction like `Int32Add`.

Let's break down the functionality section by section:

- **Basic Integer Addition:** Tests the `Int32Add` machine operation.
- **Integer Addition with Shift:** Tests the combination of shift and add operations.
- **Bit Manipulation Operations (ReverseBits, ReverseBytes, Ctz, Clz, Popcnt):**  Tests various bit manipulation instructions. These can be related to low-level optimizations or specific JavaScript features.
- **64-bit Operations:**  Tests for 64-bit versions of bit manipulation operations, relevant for architectures that support 64-bit integers.
- **Conditional Selection (Select):** Tests the `Word32Select` and `Word64Select` operations, which are like ternary operators at the machine level.
- **Conditional Selection with Memory Input:** Tests scenarios where the input to the select operation is loaded from memory, ensuring correct handling of stack spilling.
- **Floating-Point Conditional Selection:** Tests `Float32Select` and `Float64Select` for floating-point comparisons.
- **Code Generation Tests:** Tests the code generation for various binary integer operations.
- **Control Flow Tests (Goto, Branch, Loop, Switch):** Tests the generation of code for basic control flow structures.
- **Phi Nodes:** Tests the creation and usage of Phi nodes, which are essential for representing values that can come from different control flow paths (used in `if` statements and loops).
- **More Complex Integer Arithmetic Tests:** Tests combinations of `Int32Add` with other operations like `Word32Equal`, `Word32NotEqual`, and bitwise shifts, ensuring correct operator precedence and code generation.
- **Integer Addition in Branch/Comparison:** Tests how `Int32Add` is used within conditional branches and comparisons.

Now, let's provide a JavaScript example that relates to some of these tests.
这个C++源代码文件是V8 JavaScript引擎的一部分，其主要功能是**测试编译器生成的机器码的正确性，特别是针对各种机器操作 (machine operations) 的测试。**

更具体地说，这个文件的第1部分包含了针对以下功能的单元测试：

1. **基本的32位整数算术运算:**  例如 `Int32Add`（32位整数加法）。
2. **包含位移操作的32位整数算术运算:** 例如，先进行左移 (`Word32Shl`)，然后再进行加法 (`Int32Add`)。
3. **32位整数的位操作:** 例如，反转比特位 (`Word32ReverseBits`)，反转字节序 (`Word32ReverseBytes`)，计算尾部零的个数 (`Word32Ctz`)，计算头部零的个数 (`Word32Clz`)，计算置位比特的个数 (`Word32Popcnt`)。
4. **部分64位整数的位操作:**  在64位架构下，测试了 `Word64ReverseBits`, `Word64ReverseBytes`, `Word64Clz`, `Word64Ctz`, `Word64Popcnt`。
5. **条件选择操作:**  `Word32Select` 和 `Word64Select`，类似于C++和JavaScript中的三元运算符 `condition ? value1 : value2`。
6. **条件选择操作与内存输入:** 测试了当条件选择的输入值来自内存时的情况。
7. **浮点数的条件选择操作:**  `Float32Select` 和 `Float64Select`，用于根据条件选择不同的浮点数值。
8. **代码生成测试:**  测试了编译器针对各种32位整数二元操作符生成代码的能力。
9. **空操作:** `CodeGenNop` 测试。
10. **部分64位整数二元操作符的代码生成测试:** 在64位架构下，测试了各种64位整数二元操作符的代码生成。
11. **带溢出检查的64位整数加法和减法:**  测试了 `Int64AddWithOverflow` 和 `Int64SubWithOverflow` 操作，以及它们在分支语句中的使用。
12. **带溢出检查的64位整数乘法:** 测试了 `Int64MulWithOverflow` 操作，以及它在分支语句中的使用。
13. **包含位移操作的64位整数算术运算:** 例如，先进行左移 (`Word64Shl`)，然后再进行加法 (`Int64Add`)。
14. **基本的控制流操作:** 例如，`Goto`（跳转），`Branch`（分支），`Loop`（循环），`Switch`（开关语句）。
15. **Phi 节点测试:** 测试了 Phi 节点在条件分支和循环中的使用，Phi 节点用于合并来自不同控制流路径的值。
16. **更复杂的整数算术运算测试:**  测试了 `Int32Add` 与其他操作（如比较和位移）的组合。

**与 JavaScript 的关系:**

V8 是 JavaScript 的引擎，这个测试文件直接测试了 V8 编译器如何将 JavaScript 代码中涉及到的整数和位操作转换为底层的机器码。

**JavaScript 举例说明:**

假设 JavaScript 代码中有以下操作：

```javascript
let a = 10;
let b = 5;
let c = a + b; // 对应于 C++ 测试中的 RunInt32Add
let d = a << 2; // 对应于 C++ 测试中涉及的 Word32Shl
let e = a > b ? a : b; // 对应于 C++ 测试中的 RunWord32Select
let f = Math.clz32(a); // 对应于 C++ 测试中的 RunWord32Clz
```

当 V8 编译这段 JavaScript 代码时，`a + b` 这个操作可能会被编译成一个 `Int32Add` 的机器操作。 `a << 2` 可能会被编译成 `Word32Shl`。 三元运算符 `a > b ? a : b` 可能会被编译成一个包含比较和条件选择 (`Word32Select`) 的指令序列。 `Math.clz32(a)` 会被编译成 `Word32Clz` 机器指令（如果目标架构支持）。

这个 `test-run-machops.cc` 文件中的测试用例，就是用来验证 V8 编译器在生成这些机器操作码时的正确性，确保 JavaScript 的整数和位运算在底层能够按照预期执行。 例如，`TEST(RunInt32Add)` 就是确保 V8 编译器生成的 `Int32Add` 指令能够正确地执行 32 位整数的加法。 `TEST(RunWord32Clz)` 就是测试生成的 `Word32Clz` 指令是否能正确计算前导零的数量。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
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
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt64SubWithOverflowP) {
  int64_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* add = m.Int64SubWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
  bt.AddReturn(ovf);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int64_t expected_val;
      int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64SubWithOverflowImm) {
  int64_t actual_val = -1, expected_val = 0;
  FOR_INT64_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64SubWithOverflow(m.Int64Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* add = m.Int64SubWithOverflow(m.Parameter(0), m.Int64Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow64(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT64_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int64SubWithOverflow(m.Int64Constant(i), m.Int64Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedSubOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt64SubWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* sub = m.Int64SubWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, sub);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int64Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, sub);
  Node* truncated = m.TruncateInt64ToInt32(val);
  bt.AddReturn(truncated);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = constant;
      int64_t result;
      if (!base::bits::SignedSubOverflow64(i, j, &result)) {
        expected = static_cast<int32_t>(result);
      }
      CHECK_EQ(expected, static_cast<int32_t>(bt.call(i, j)));
    }
  }
}

TEST(RunInt64MulWithOverflowImm) {
  int64_t actual_val = -1, expected_val = 0;
  FOR_INT64_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* mul = m.Int64MulWithOverflow(m.Int64Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow64(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int64());
      Node* mul = m.Int64MulWithOverflow(m.Parameter(0), m.Int64Constant(i));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      FOR_INT64_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow64(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT64_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* mul =
          m.Int64MulWithOverflow(m.Int64Constant(i), m.Int64Constant(j));
      Node* val = m.Projection(0, mul);
      Node* ovf = m.Projection(1, mul);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord64, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedMulOverflow64(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}

TEST(RunInt64MulWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int64BinopTester bt(&m);
  Node* mul = m.Int64MulWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, mul);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int64Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, mul);
  Node* truncated = m.TruncateInt64ToInt32(val);
  bt.AddReturn(truncated);
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      int32_t expected = constant;
      int64_t result;
      if (!base::bits::SignedMulOverflow64(i, j, &result)) {
        expected = static_cast<int32_t>(result);
      }
      CHECK_EQ(expected, static_cast<int32_t>(bt.call(i, j)));
    }
  }
}

static int64_t RunInt64AddShift(bool is_left, int64_t add_left,
                                int64_t add_right, int64_t shift_left,
                                int64_t shift_right) {
  RawMachineAssemblerTester<int64_t> m;
  Node* shift =
      m.Word64Shl(m.Int64Constant(shift_left), m.Int64Constant(shift_right));
  Node* add = m.Int64Add(m.Int64Constant(add_left), m.Int64Constant(add_right));
  Node* dlsa = is_left ? m.Int64Add(shift, add) : m.Int64Add(add, shift);
  m.Return(dlsa);
  return m.Call();
}

TEST(RunInt64AddShift) {
  struct Test_case {
    int64_t add_left, add_right, shift_left, shift_right, expected;
  };

  Test_case tc[] = {
      {20, 22, 4, 2, 58},
      {20, 22, 4, 1, 50},
      {20, 22, 1, 6, 106},
      {INT64_MAX - 2, 1, 1, 1,
       INT64_MIN},  // INT64_MAX - 2 + 1 + (1 << 1), overflow.
  };
  const size_t tc_size = sizeof(tc) / sizeof(Test_case);

  for (size_t i = 0; i < tc_size; ++i) {
    CHECK_EQ(tc[i].expected,
             RunInt64AddShift(false, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
    CHECK_EQ(tc[i].expected,
             RunInt64AddShift(true, tc[i].add_left, tc[i].add_right,
                              tc[i].shift_left, tc[i].shift_right));
  }
}

// TODO(titzer): add tests that run 64-bit integer operations.
#endif  // V8_TARGET_ARCH_64_BIT


TEST(RunGoto) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 99999;

  RawMachineLabel next;
  m.Goto(&next);
  m.Bind(&next);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunGotoMultiple) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 9999977;

  RawMachineLabel labels[10];
  for (size_t i = 0; i < arraysize(labels); i++) {
    m.Goto(&labels[i]);
    m.Bind(&labels[i]);
  }
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunBranch) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 999777;

  RawMachineLabel blocka, blockb;
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(0 - constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunDiamond2) {
  RawMachineAssemblerTester<int32_t> m;

  int constant = 995666;

  RawMachineLabel blocka, blockb, end;
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);
  m.Bind(&end);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunLoop) {
  RawMachineAssemblerTester<int32_t> m;
  int constant = 999555;

  RawMachineLabel header, body, exit;
  m.Goto(&header);
  m.Bind(&header);
  m.Branch(m.Int32Constant(0), &body, &exit);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&exit);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


template <typename R>
static void BuildDiamondPhi(RawMachineAssemblerTester<R>* m, Node* cond_node,
                            MachineRepresentation rep, Node* true_node,
                            Node* false_node) {
  RawMachineLabel blocka, blockb, end;
  m->Branch(cond_node, &blocka, &blockb);
  m->Bind(&blocka);
  m->Goto(&end);
  m->Bind(&blockb);
  m->Goto(&end);

  m->Bind(&end);
  Node* phi = m->Phi(rep, true_node, false_node);
  m->Return(phi);
}


TEST(RunDiamondPhiConst) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int false_val = 0xFF666;
  int true_val = 0x00DDD;
  Node* true_node = m.Int32Constant(true_val);
  Node* false_node = m.Int32Constant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kWord32, true_node,
                  false_node);
  CHECK_EQ(false_val, m.Call(0));
  CHECK_EQ(true_val, m.Call(1));
}


TEST(RunDiamondPhiNumber) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());
  double false_val = -11.1;
  double true_val = 200.1;
  Node* true_node = m.NumberConstant(true_val);
  Node* false_node = m.NumberConstant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kTagged, true_node,
                  false_node);
  m.CheckNumber(false_val, m.Call(0));
  m.CheckNumber(true_val, m.Call(1));
}


TEST(RunDiamondPhiString) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());
  const char* false_val = "false";
  const char* true_val = "true";
  Node* true_node = m.StringConstant(true_val);
  Node* false_node = m.StringConstant(false_val);
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kTagged, true_node,
                  false_node);
  m.CheckString(false_val, m.Call(0));
  m.CheckString(true_val, m.Call(1));
}


TEST(RunDiamondPhiParam) {
  RawMachineAssemblerTester<int32_t> m(
      MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
  BuildDiamondPhi(&m, m.Parameter(0), MachineRepresentation::kWord32,
                  m.Parameter(1), m.Parameter(2));
  int32_t c1 = 0x260CB75A;
  int32_t c2 = 0xCD3E9C8B;
  int result = m.Call(0, c1, c2);
  CHECK_EQ(c2, result);
  result = m.Call(1, c1, c2);
  CHECK_EQ(c1, result);
}


TEST(RunLoopPhiConst) {
  RawMachineAssemblerTester<int32_t> m;
  int true_val = 0x44000;
  int false_val = 0x00888;

  Node* cond_node = m.Int32Constant(0);
  Node* true_node = m.Int32Constant(true_val);
  Node* false_node = m.Int32Constant(false_val);

  // x = false_val; while(false) { x = true_val; } return x;
  RawMachineLabel body, header, end;

  m.Goto(&header);
  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, false_node, true_node);
  m.Branch(cond_node, &body, &end);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&end);
  m.Return(phi);

  CHECK_EQ(false_val, m.Call());
}


TEST(RunLoopPhiParam) {
  RawMachineAssemblerTester<int32_t> m(
      MachineType::Int32(), MachineType::Int32(), MachineType::Int32());

  RawMachineLabel blocka, blockb, end;

  m.Goto(&blocka);

  m.Bind(&blocka);
  Node* phi =
      m.Phi(MachineRepresentation::kWord32, m.Parameter(1), m.Parameter(2));
  Node* cond =
      m.Phi(MachineRepresentation::kWord32, m.Parameter(0), m.Int32Constant(0));
  m.Branch(cond, &blockb, &end);

  m.Bind(&blockb);
  m.Goto(&blocka);

  m.Bind(&end);
  m.Return(phi);

  int32_t c1 = 0xA81903B4;
  int32_t c2 = 0x5A1207DA;
  int result = m.Call(0, c1, c2);
  CHECK_EQ(c1, result);
  result = m.Call(1, c1, c2);
  CHECK_EQ(c2, result);
}


TEST(RunLoopPhiInduction) {
  RawMachineAssemblerTester<int32_t> m;

  int false_val = 0x10777;

  // x = false_val; while(false) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* false_node = m.Int32Constant(false_val);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, false_node, false_node);
  m.Branch(m.Int32Constant(0), &body, &end);

  m.Bind(&body);
  Node* add = m.Int32Add(phi, m.Int32Constant(1));
  phi->ReplaceInput(1, add);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(phi);

  CHECK_EQ(false_val, m.Call());
}


TEST(RunLoopIncrement) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x ^ param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.WordXor(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
}


TEST(RunLoopIncrement2) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x < param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.Int32LessThan(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
  CHECK_EQ(0, bt.call(-200, 0));
}


TEST(RunLoopIncrement3) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = 0; while(x < param) { x++; } return x;
  RawMachineLabel header, body, end;
  Node* zero = m.Int32Constant(0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Branch(m.Uint32LessThan(phi, bt.param0), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Add(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(11, bt.call(11, 0));
  CHECK_EQ(110, bt.call(110, 0));
  CHECK_EQ(176, bt.call(176, 0));
  CHECK_EQ(200, bt.call(200, 0));
}


TEST(RunLoopDecrement) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  // x = param; while(x) { x--; } return x;
  RawMachineLabel header, body, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* phi =
      m.Phi(MachineRepresentation::kWord32, bt.param0, m.Int32Constant(0));
  m.Branch(phi, &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Int32Sub(phi, m.Int32Constant(1)));
  m.Goto(&header);

  m.Bind(&end);
  bt.AddReturn(phi);

  CHECK_EQ(0, bt.call(11, 0));
  CHECK_EQ(0, bt.call(110, 0));
  CHECK_EQ(0, bt.call(197, 0));
}


TEST(RunLoopIncrementFloat32) {
  RawMachineAssemblerTester<int32_t> m;

  // x = -3.0f; while(x < 10f) { x = x + 0.5f; } return (int) (double) x;
  RawMachineLabel header, body, end;
  Node* minus_3 = m.Float32Constant(-3.0f);
  Node* ten = m.Float32Constant(10.0f);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat32, minus_3, ten);
  m.Branch(m.Float32LessThan(phi, ten), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Float32Add(phi, m.Float32Constant(0.5f)));
  m.Goto(&header);

  m.Bind(&end);
  m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(phi)));

  CHECK_EQ(10, m.Call());
}


TEST(RunLoopIncrementFloat64) {
  RawMachineAssemblerTester<int32_t> m;

  // x = -3.0; while(x < 10) { x = x + 0.5; } return (int) x;
  RawMachineLabel header, body, end;
  Node* minus_3 = m.Float64Constant(-3.0);
  Node* ten = m.Float64Constant(10.0);

  m.Goto(&header);

  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, minus_3, ten);
  m.Branch(m.Float64LessThan(phi, ten), &body, &end);

  m.Bind(&body);
  phi->ReplaceInput(1, m.Float64Add(phi, m.Float64Constant(0.5)));
  m.Goto(&header);

  m.Bind(&end);
  m.Return(m.ChangeFloat64ToInt32(phi));

  CHECK_EQ(10, m.Call());
}


TEST(RunSwitch1) {
  RawMachineAssemblerTester<int32_t> m;

  int constant = 11223344;

  RawMachineLabel block0, block1, def, end;
  RawMachineLabel* case_labels[] = {&block0, &block1};
  int32_t case_values[] = {0, 1};
  m.Switch(m.Int32Constant(0), &def, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&block0);
  m.Goto(&end);
  m.Bind(&block1);
  m.Goto(&end);
  m.Bind(&def);
  m.Goto(&end);
  m.Bind(&end);
  m.Return(m.Int32Constant(constant));

  CHECK_EQ(constant, m.Call());
}


TEST(RunSwitch2) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  RawMachineLabel blocka, blockb, blockc;
  RawMachineLabel* case_labels[] = {&blocka, &blockb};
  int32_t case_values[] = {std::numeric_limits<int32_t>::min(),
                           std::numeric_limits<int32_t>::max()};
  m.Switch(m.Parameter(0), &blockc, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&blocka);
  m.Return(m.Int32Constant(-1));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockc);
  m.Return(m.Int32Constant(0));

  CHECK_EQ(1, m.Call(std::numeric_limits<int32_t>::max()));
  CHECK_EQ(-1, m.Call(std::numeric_limits<int32_t>::min()));
  for (int i = -100; i < 100; i += 25) {
    CHECK_EQ(0, m.Call(i));
  }
}


TEST(RunSwitch3) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  RawMachineLabel blocka, blockb, blockc;
  RawMachineLabel* case_labels[] = {&blocka, &blockb};
  int32_t case_values[] = {std::numeric_limits<int32_t>::min() + 0,
                           std::numeric_limits<int32_t>::min() + 1};
  m.Switch(m.Parameter(0), &blockc, case_values, case_labels,
           arraysize(case_labels));
  m.Bind(&blocka);
  m.Return(m.Int32Constant(0));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockc);
  m.Return(m.Int32Constant(2));

  CHECK_EQ(0, m.Call(std::numeric_limits<int32_t>::min() + 0));
  CHECK_EQ(1, m.Call(std::numeric_limits<int32_t>::min() + 1));
  for (int i = -100; i < 100; i += 25) {
    CHECK_EQ(2, m.Call(i));
  }
}


TEST(RunSwitch4) {
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

  const size_t kNumCases = 512;
  const size_t kNumValues = kNumCases + 1;
  int32_t values[kNumValues];
  m.main_isolate()->random_number_generator()->NextBytes(values,
                                                         sizeof(values));
  RawMachineLabel end, def;
  int32_t case_values[kNumCases];
  RawMachineLabel* case_labels[kNumCases];
  Node* results[kNumValues];
  for (size_t i = 0; i < kNumCases; ++i) {
    case_values[i] = static_cast<int32_t>(i);
    case_labels[i] = m.main_zone()->New<RawMachineLabel>();
  }
  m.Switch(m.Parameter(0), &def, case_values, case_labels,
           arraysize(case_labels));
  for (size_t i = 0; i < kNumCases; ++i) {
    m.Bind(case_labels[i]);
    results[i] = m.Int32Constant(values[i]);
    m.Goto(&end);
  }
  m.Bind(&def);
  results[kNumCases] = m.Int32Constant(values[kNumCases]);
  m.Goto(&end);
  m.Bind(&end);
  const int num_results = static_cast<int>(arraysize(results));
  Node* phi =
      m.AddNode(m.common()->Phi(MachineRepresentation::kWord32, num_results),
                num_results, results);
  m.Return(phi);

  for (size_t i = 0; i < kNumValues; ++i) {
    CHECK_EQ(values[i], m.Call(static_cast<int>(i)));
  }
}


TEST(RunInt32AddP) {
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);

  bt.AddReturn(m.Int32Add(bt.param0, bt.param1));

  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      // Use uint32_t because signed overflow is UB in C.
      int expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                          static_cast<uint32_t>(j));
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt32AddAndWord32EqualP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Equal(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j == k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Word32Equal(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i == j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32EqualImm) {
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
  m.Return(m.Int32Add(m.Int32Constant(i),
                      m.Word32Equal(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(j) {
    FOR_INT32_INPUTS(k) {
      // Use uint32_t because signed overflow is UB in C.
      int32_t const expected =
          base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j == k));
      CHECK_EQ(expected, m.Call(j, k));
    }
  }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
      m.Return(m.Int32Add(m.Word32Equal(m.Int32Constant(i), m.Parameter(0)),
                          m.Parameter(1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i == j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32NotEqualP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32NotEqual(m.Parameter(1), m.Parameter(2))));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j != k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Word32NotEqual(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i != j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(i, j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32NotEqualImm) {
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
  m.Return(m.Int32Add(m.Int32Constant(i),
                      m.Word32NotEqual(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(j) {
    FOR_INT32_INPUTS(k) {
      // Use uint32_t because signed overflow is UB in C.
      int32_t const expected =
          base::bit_cast<int32_t>(base::bit_cast<uint32_t>(i) + (j != k));
      CHECK_EQ(expected, m.Call(j, k));
    }
  }
    }
  }
  {
    FOR_INT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                           MachineType::Int32());
      m.Return(m.Int32Add(m.Word32NotEqual(m.Int32Constant(i), m.Parameter(0)),
                          m.Parameter(1)));
      FOR_INT32_INPUTS(j) {
        FOR_INT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t const expected =
              base::bit_cast<int32_t>((i != j) + base::bit_cast<uint32_t>(k));
          CHECK_EQ(expected, m.Call(j, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32SarP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Int32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Sar(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Int32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Sar(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_INT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i >> shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32ShlP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Shl(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j << shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Shl(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i << shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddAndWord32ShrP) {
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Parameter(0),
                        m.Word32Shr(m.Parameter(1), m.Parameter(2))));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        FOR_UINT32_SHIFTS(shift) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = i + (j >> shift);
          CHECK_EQ(expected, m.Call(i, j, shift));
        }
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32());
    m.Return(m.Int32Add(m.Word32Shr(m.Parameter(0), m.Parameter(1)),
                        m.Parameter(2)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_SHIFTS(shift) {
        FOR_UINT32_INPUTS(k) {
          // Use uint32_t because signed overflow is UB in C.
          int32_t expected = (i >> shift) + k;
          CHECK_EQ(expected, m.Call(i, shift, k));
        }
      }
    }
  }
}


TEST(RunInt32AddInBranch) {
  static const int32_t constant = 987654321;
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32Equal(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Int32BinopTester bt(&m);
    RawMachineLabel blocka, blockb;
    m.Branch(
        m.Word32NotEqual(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)),
        &blocka, &blockb);
    m.Bind(&blocka);
    bt.AddReturn(m.Int32Constant(constant));
    m.Bind(&blockb);
    bt.AddReturn(m.Int32Constant(0 - constant));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32Equal(m.Int32Add(m.Int32Constant(i), m.Parameter(0)),
                             m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) == 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      m.Branch(m.Word32NotEqual(m.Int32Add(m.Int32Constant(i), m.Parameter(0)),
                                m.Int32Constant(0)),
               &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(j) {
        int32_t expected = (i + j) != 0 ? constant : 0 - constant;
        CHECK_EQ(expected, m.Call(j));
      }
    }
  }
  {
    RawMachineAssemblerTester<void> m;
    const Operator* shops[] = {m.machine()->Word32Sar(),
                               m.machine()->Word32Shl(),
                               m.machine()->Word32Shr()};
    for (size_t n = 0; n < arraysize(shops); n++) {
      RawMachineAssemblerTester<int32_t> t(
          MachineType::Uint32(), MachineType::Int32(), MachineType::Uint32());
      RawMachineLabel blocka, blockb;
      t.Branch(t.Word32Equal(t.Int32Add(t.Parameter(0),
                                        t.AddNode(shops[n], t.Parameter(1),
                                                  t.Parameter(2))),
                             t.Int32Constant(0)),
               &blocka, &blockb);
      t.Bind(&blocka);
      t.Return(t.Int32Constant(constant));
      t.Bind(&blockb);
      t.Return(t.Int32Constant(0 - constant));
      FOR_UINT32_INPUTS(i) {
        FOR_INT32_INPUTS(j) {
          FOR_UINT32_SHIFTS(shift) {
            int32_t right;
            switch (shops[n]->opcode()) {
              default:
                UNREACHABLE();
              case IrOpcode::kWord32Sar:
                right = j >> shift;
                break;
              case IrOpcode::kWord32Shl:
                right = static_cast<uint32_t>(j) << shift;
                break;
              case IrOpcode::kWord32Shr:
                right = static_cast<uint32_t>(j) >> shift;
                break;
            }
            int32_t expected = ((i + right) == 0) ? constant : 0 - constant;
            CHECK_EQ(expected, t.Call(i, j, shift));
          }
        }
      }
    }
  }
}


TEST(RunInt32AddInComparison) {
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Add(bt.param0, bt.param1), m.Int32Constant(0)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i + j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    RawMachineAssemblerTester<int32_t> m;
    Uint32BinopTester bt(&m);
    bt.AddReturn(
        m.Word32Equal(m.Int32Constant(0), m.Int32Add(bt.param0, bt.param1)));
    FOR_UINT32_INPUTS(i) {
      FOR_UINT32_INPUTS(j) {
        uint32_t expected = (i + j) == 0;
        CHECK_EQ(expected, bt.call(i, j));
      }
    }
  }
  {
    FOR_UINT32_INPUTS(i) {
      RawMachineAssemblerTester<uint32_t> m(MachineType::Uint32());
  m.Retu
"""


```