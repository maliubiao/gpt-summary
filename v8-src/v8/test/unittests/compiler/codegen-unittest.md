Response: The user wants to understand the functionality of the C++ source code file `codegen-unittest.cc`. I need to:
1. Summarize the purpose of the code.
2. Explain its relationship with JavaScript, if any.
3. Provide illustrative examples in JavaScript if a connection exists.

Based on the file name and content, it appears to be a unit test file for the code generation component of the V8 JavaScript engine. It tests the functionality of the `RawMachineAssemblerTester` and `BufferedRawMachineAssemblerTester` classes, which are used to generate machine code snippets for testing purposes.

The tests cover:
- Creating and returning constant values (Smis, Numbers, Strings, Heap Objects).
- Passing and returning parameters to generated code.
- Performing basic arithmetic and comparison operations within the generated code.

The connection to JavaScript lies in the fact that V8 compiles JavaScript code into machine code. This file tests the low-level code generation aspects of that compilation process.

Let's formulate the summary and JavaScript examples.
这个C++源代码文件 `codegen-unittest.cc` 是 V8 JavaScript 引擎的一部分，具体来说，它是 **编译器 (compiler)** 模块中 **代码生成 (codegen)** 部分的单元测试。

**功能归纳:**

该文件的主要目的是 **测试 V8 编译器在代码生成阶段的各种功能和特性是否正确工作**。它通过以下方式实现：

1. **创建测试环境:** 它定义了一个名为 `CodeGenTest` 的测试类，继承自 `TestWithIsolateAndZone`，用于设置 V8 隔离环境和内存区域，以便进行代码生成和执行测试。
2. **使用 Assembler Tester:**  它使用了 `RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester` 这两个工具类，允许在 C++ 代码中方便地构建底层的机器代码片段，并执行这些代码片段。
3. **测试各种代码生成场景:**  文件中包含了多个以 `TEST_F` 开头的测试用例，涵盖了代码生成的各种方面，例如：
    - **常量生成:** 测试生成不同类型的常量（例如，小的整数 Smi、浮点数、字符串、堆对象）是否正确。
    - **参数传递:** 测试向生成的代码传递参数并返回结果是否正确。
    - **基本运算:** 测试生成的代码执行基本的算术运算（加法）和比较运算是否正确。
    - **比较操作:** 专门测试 `CompareWrapper` 类，用于确保各种类型的比较操作（整数、无符号整数、浮点数）在代码生成后能按预期工作。
4. **断言验证:**  每个测试用例都使用 `CHECK_EQ`， `CHECK_DOUBLE_EQ`， `m.CheckString` 等宏来断言生成的代码执行的结果是否与预期一致。

**与 JavaScript 的关系及 JavaScript 举例:**

这个文件直接关系到 JavaScript 的执行效率。 V8 引擎负责将 JavaScript 代码编译成高效的机器码来执行。 `codegen-unittest.cc`  确保了编译器在将 JavaScript 代码转换成机器码的过程中，对于各种不同的 JavaScript 语法结构和数据类型，都能生成正确的机器指令。

以下是一些与文件中测试的功能相关的 JavaScript 例子：

1. **常量生成:**
   ```javascript
   // JavaScript 代码，V8 编译后会生成加载常量的机器码
   const smallInteger = 10;
   const floatingPoint = 3.14;
   const text = "hello";
   ```
   `CodeGenTest` 中的 `RunSmiConstants`, `RunNumberConstants`, `RunEmptyString`, `RunHeapConstant`, `RunHeapNumberConstant` 等测试用例都在验证 V8 能否正确地为这些 JavaScript 常量生成机器码。

2. **参数传递:**
   ```javascript
   // JavaScript 函数，接收参数并返回
   function add(a, b) {
     return a + b;
   }

   const result = add(5, 3); // 调用函数，传递参数
   ```
   `CodeGenTest` 中的 `RunParam1`, `RunParam2_1`, `RunParam2_2`, `RunParam3` 等测试用例模拟了 V8 如何处理 JavaScript 函数调用时参数的传递和返回值的处理。

3. **基本运算:**
   ```javascript
   // JavaScript 中的加法运算
   const sum = 10 + 5;
   ```
   `CodeGenTest` 中的 `RunBinopTester` 以及针对 64 位架构的测试用例 (`RunBufferedRawMachineAssemblerTesterTester`) 都在测试 V8 能否正确生成执行 JavaScript 算术运算（例如加法）的机器码。

4. **比较操作:**
   ```javascript
   // JavaScript 中的比较运算
   const isEqual = 5 == 5;
   const isLessThan = 3 < 7;
   ```
   `CodeGenTest` 中的 `CompareWrapper` 测试用例确保了 V8 能否正确生成执行 JavaScript 比较操作的机器码，包括各种数据类型的比较和特殊值（如 NaN 和 Infinity）的处理。

总而言之，`codegen-unittest.cc` 是 V8 引擎中至关重要的测试文件，它直接保证了 V8 编译器生成机器码的正确性，从而确保了 JavaScript 代码能够高效且正确地执行。 它通过模拟各种 JavaScript 代码结构，并在底层机器码层面进行验证，来保障 JavaScript 引擎的质量。

Prompt: 
```
这是目录为v8/test/unittests/compiler/codegen-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/objects/objects-inl.h"
#include "test/common/value-helper.h"
#include "test/unittests/compiler/codegen-tester.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

class CodeGenTest : public TestWithIsolateAndZone {
 public:
  CodeGenTest() : TestWithIsolateAndZone(kCompressGraphZone) {}

 protected:
  void RunSmiConstant(int32_t v) {
// TODO(dcarney): on x64 Smis are generated with the SmiConstantRegister
#if !V8_TARGET_ARCH_X64
    if (Smi::IsValid(v)) {
      RawMachineAssemblerTester<Tagged<Object>> m(i_isolate(), zone());
      m.Return(m.NumberConstant(v));
      CHECK_EQ(Smi::FromInt(v), m.Call());
    }
#endif
  }

  void RunNumberConstant(double v) {
    RawMachineAssemblerTester<Tagged<Object>> m(i_isolate(), zone());
#if V8_TARGET_ARCH_X64
    // TODO(dcarney): on x64 Smis are generated with the SmiConstantRegister
    DirectHandle<Object> number = m.isolate()->factory()->NewNumber(v);
    if (IsSmi(*number)) return;
#endif
    m.Return(m.NumberConstant(v));
    Tagged<Object> result = m.Call();
    m.CheckNumber(v, result);
  }
};

TEST_F(CodeGenTest, CompareWrapper) {
  // Who tests the testers?
  // If CompareWrapper is broken, then test expectations will be broken.
  CompareWrapper wWord32Equal(IrOpcode::kWord32Equal);
  CompareWrapper wInt32LessThan(IrOpcode::kInt32LessThan);
  CompareWrapper wInt32LessThanOrEqual(IrOpcode::kInt32LessThanOrEqual);
  CompareWrapper wUint32LessThan(IrOpcode::kUint32LessThan);
  CompareWrapper wUint32LessThanOrEqual(IrOpcode::kUint32LessThanOrEqual);

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      CHECK_EQ(a == b, wWord32Equal.Int32Compare(a, b));
      CHECK_EQ(a < b, wInt32LessThan.Int32Compare(a, b));
      CHECK_EQ(a <= b, wInt32LessThanOrEqual.Int32Compare(a, b));
    }
  }

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      CHECK_EQ(a == b, wWord32Equal.Int32Compare(a, b));
      CHECK_EQ(a < b, wUint32LessThan.Int32Compare(a, b));
      CHECK_EQ(a <= b, wUint32LessThanOrEqual.Int32Compare(a, b));
    }
  }

  CHECK_EQ(true, wWord32Equal.Int32Compare(0, 0));
  CHECK_EQ(true, wWord32Equal.Int32Compare(257, 257));
  CHECK_EQ(true, wWord32Equal.Int32Compare(65539, 65539));
  CHECK_EQ(true, wWord32Equal.Int32Compare(-1, -1));
  CHECK_EQ(true, wWord32Equal.Int32Compare(0xFFFFFFFF, 0xFFFFFFFF));

  CHECK_EQ(false, wWord32Equal.Int32Compare(0, 1));
  CHECK_EQ(false, wWord32Equal.Int32Compare(257, 256));
  CHECK_EQ(false, wWord32Equal.Int32Compare(65539, 65537));
  CHECK_EQ(false, wWord32Equal.Int32Compare(-1, -2));
  CHECK_EQ(false, wWord32Equal.Int32Compare(0xFFFFFFFF, 0xFFFFFFFE));

  CHECK_EQ(false, wInt32LessThan.Int32Compare(0, 0));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(357, 357));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(75539, 75539));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(-1, -1));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(0xFFFFFFFF, 0xFFFFFFFF));

  CHECK_EQ(true, wInt32LessThan.Int32Compare(0, 1));
  CHECK_EQ(true, wInt32LessThan.Int32Compare(456, 457));
  CHECK_EQ(true, wInt32LessThan.Int32Compare(85537, 85539));
  CHECK_EQ(true, wInt32LessThan.Int32Compare(-2, -1));
  CHECK_EQ(true, wInt32LessThan.Int32Compare(0xFFFFFFFE, 0xFFFFFFFF));

  CHECK_EQ(false, wInt32LessThan.Int32Compare(1, 0));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(457, 456));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(85539, 85537));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(-1, -2));
  CHECK_EQ(false, wInt32LessThan.Int32Compare(0xFFFFFFFF, 0xFFFFFFFE));

  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(0, 0));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(357, 357));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(75539, 75539));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(-1, -1));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(0xFFFFFFFF, 0xFFFFFFFF));

  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(0, 1));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(456, 457));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(85537, 85539));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(-2, -1));
  CHECK_EQ(true, wInt32LessThanOrEqual.Int32Compare(0xFFFFFFFE, 0xFFFFFFFF));

  CHECK_EQ(false, wInt32LessThanOrEqual.Int32Compare(1, 0));
  CHECK_EQ(false, wInt32LessThanOrEqual.Int32Compare(457, 456));
  CHECK_EQ(false, wInt32LessThanOrEqual.Int32Compare(85539, 85537));
  CHECK_EQ(false, wInt32LessThanOrEqual.Int32Compare(-1, -2));
  CHECK_EQ(false, wInt32LessThanOrEqual.Int32Compare(0xFFFFFFFF, 0xFFFFFFFE));

  // Unsigned comparisons.
  CHECK_EQ(false, wUint32LessThan.Int32Compare(0, 0));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(357, 357));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(75539, 75539));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(-1, -1));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(0xFFFFFFFF, 0xFFFFFFFF));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(0xFFFFFFFF, 0));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(-2999, 0));

  CHECK_EQ(true, wUint32LessThan.Int32Compare(0, 1));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(456, 457));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(85537, 85539));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(-11, -10));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(0xFFFFFFFE, 0xFFFFFFFF));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(0, 0xFFFFFFFF));
  CHECK_EQ(true, wUint32LessThan.Int32Compare(0, -2996));

  CHECK_EQ(false, wUint32LessThan.Int32Compare(1, 0));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(457, 456));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(85539, 85537));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(-10, -21));
  CHECK_EQ(false, wUint32LessThan.Int32Compare(0xFFFFFFFF, 0xFFFFFFFE));

  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(0, 0));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(357, 357));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(75539, 75539));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(-1, -1));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(0xFFFFFFFF, 0xFFFFFFFF));

  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(0, 1));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(456, 457));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(85537, 85539));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(-300, -299));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(-300, -300));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(0xFFFFFFFE, 0xFFFFFFFF));
  CHECK_EQ(true, wUint32LessThanOrEqual.Int32Compare(0, -2995));

  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(1, 0));
  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(457, 456));
  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(85539, 85537));
  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(-130, -170));
  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(0xFFFFFFFF, 0xFFFFFFFE));
  CHECK_EQ(false, wUint32LessThanOrEqual.Int32Compare(-2997, 0));

  CompareWrapper wFloat64Equal(IrOpcode::kFloat64Equal);
  CompareWrapper wFloat64LessThan(IrOpcode::kFloat64LessThan);
  CompareWrapper wFloat64LessThanOrEqual(IrOpcode::kFloat64LessThanOrEqual);

  // Check NaN handling.
  double nan = std::numeric_limits<double>::quiet_NaN();
  double inf = V8_INFINITY;
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, 0.0));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, 1.0));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, -inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, nan));

  CHECK_EQ(false, wFloat64Equal.Float64Compare(0.0, nan));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(1.0, nan));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(inf, nan));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-inf, nan));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(nan, nan));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, 0.0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, 1.0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, -inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, nan));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(0.0, nan));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(1.0, nan));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, nan));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(-inf, nan));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(nan, nan));

  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, 0.0));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, 1.0));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, inf));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, -inf));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, nan));

  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(0.0, nan));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(1.0, nan));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(inf, nan));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(-inf, nan));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(nan, nan));

  // Check inf handling.
  CHECK_EQ(false, wFloat64Equal.Float64Compare(inf, 0.0));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(inf, 1.0));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(inf, inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(inf, -inf));

  CHECK_EQ(false, wFloat64Equal.Float64Compare(0.0, inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(1.0, inf));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(inf, inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-inf, inf));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, 0.0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, 1.0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, -inf));

  CHECK_EQ(true, wFloat64LessThan.Float64Compare(0.0, inf));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(1.0, inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, inf));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(-inf, inf));

  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(inf, 0.0));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(inf, 1.0));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(inf, inf));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(inf, -inf));

  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(0.0, inf));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(1.0, inf));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(inf, inf));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, inf));

  // Check -inf handling.
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-inf, 0.0));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-inf, 1.0));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-inf, inf));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(-inf, -inf));

  CHECK_EQ(false, wFloat64Equal.Float64Compare(0.0, -inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(1.0, -inf));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(inf, -inf));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(-inf, -inf));

  CHECK_EQ(true, wFloat64LessThan.Float64Compare(-inf, 0.0));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(-inf, 1.0));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(-inf, inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(-inf, -inf));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(0.0, -inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(1.0, -inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(inf, -inf));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(-inf, -inf));

  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, 0.0));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, 1.0));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, inf));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, -inf));

  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(0.0, -inf));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(1.0, -inf));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(inf, -inf));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-inf, -inf));

  // Check basic values.
  CHECK_EQ(true, wFloat64Equal.Float64Compare(0, 0));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(257.1, 257.1));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(65539.1, 65539.1));
  CHECK_EQ(true, wFloat64Equal.Float64Compare(-1.1, -1.1));

  CHECK_EQ(false, wFloat64Equal.Float64Compare(0, 1));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(257.2, 256.2));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(65539.2, 65537.2));
  CHECK_EQ(false, wFloat64Equal.Float64Compare(-1.2, -2.2));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(0, 0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(357.3, 357.3));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(75539.3, 75539.3));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(-1.3, -1.3));

  CHECK_EQ(true, wFloat64LessThan.Float64Compare(0, 1));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(456.4, 457.4));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(85537.4, 85539.4));
  CHECK_EQ(true, wFloat64LessThan.Float64Compare(-2.4, -1.4));

  CHECK_EQ(false, wFloat64LessThan.Float64Compare(1, 0));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(457.5, 456.5));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(85539.5, 85537.5));
  CHECK_EQ(false, wFloat64LessThan.Float64Compare(-1.5, -2.5));

  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(0, 0));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(357.6, 357.6));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(75539.6, 75539.6));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-1.6, -1.6));

  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(0, 1));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(456.7, 457.7));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(85537.7, 85539.7));
  CHECK_EQ(true, wFloat64LessThanOrEqual.Float64Compare(-2.7, -1.7));

  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(1, 0));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(457.8, 456.8));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(85539.8, 85537.8));
  CHECK_EQ(false, wFloat64LessThanOrEqual.Float64Compare(-1.8, -2.8));
}

TEST_F(CodeGenTest, ParametersEqual) {
  RawMachineAssemblerTester<int32_t> m(
      i_isolate(), zone(), MachineType::Int32(), MachineType::Int32());
  Node* p1 = m.Parameter(1);
  CHECK(p1);
  Node* p0 = m.Parameter(0);
  CHECK(p0);
  CHECK_EQ(p0, m.Parameter(0));
  CHECK_EQ(p1, m.Parameter(1));
}

TEST_F(CodeGenTest, RunEmpty) {
  RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
  m.Return(m.Int32Constant(0));
  CHECK_EQ(0, m.Call());
}

TEST_F(CodeGenTest, RunInt32Constants) {
  FOR_INT32_INPUTS(i) {
    RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
    m.Return(m.Int32Constant(i));
    CHECK_EQ(i, m.Call());
  }
}

TEST_F(CodeGenTest, RunSmiConstants) {
  for (int32_t i = 1; i < Smi::kMaxValue && i != 0;
       i = base::ShlWithWraparound(i, 1)) {
    RunSmiConstant(i);
    RunSmiConstant(base::MulWithWraparound(3, i));
    RunSmiConstant(base::MulWithWraparound(5, i));
    RunSmiConstant(base::NegateWithWraparound(i));
    RunSmiConstant(i | 1);
    RunSmiConstant(i | 3);
  }
  RunSmiConstant(Smi::kMaxValue);
  RunSmiConstant(Smi::kMaxValue - 1);
  RunSmiConstant(Smi::kMinValue);
  RunSmiConstant(Smi::kMinValue + 1);

  FOR_INT32_INPUTS(i) { RunSmiConstant(i); }
}

TEST_F(CodeGenTest, RunNumberConstants) {
  FOR_FLOAT64_INPUTS(i) { RunNumberConstant(i); }
  FOR_INT32_INPUTS(i) { RunNumberConstant(i); }

  for (int32_t i = 1; i < Smi::kMaxValue && i != 0;
       i = base::ShlWithWraparound(i, 1)) {
    RunNumberConstant(i);
    RunNumberConstant(base::NegateWithWraparound(i));
    RunNumberConstant(i | 1);
    RunNumberConstant(i | 3);
  }
  RunNumberConstant(Smi::kMaxValue);
  RunNumberConstant(Smi::kMaxValue - 1);
  RunNumberConstant(Smi::kMinValue);
  RunNumberConstant(Smi::kMinValue + 1);
}

TEST_F(CodeGenTest, RunEmptyString) {
  RawMachineAssemblerTester<Tagged<Object>> m(i_isolate(), zone());
  m.Return(m.StringConstant("empty"));
  m.CheckString("empty", m.Call());
}

TEST_F(CodeGenTest, RunHeapConstant) {
  RawMachineAssemblerTester<Tagged<Object>> m(i_isolate(), zone());
  m.Return(m.StringConstant("empty"));
  m.CheckString("empty", m.Call());
}

TEST_F(CodeGenTest, RunHeapNumberConstant) {
  RawMachineAssemblerTester<void*> m(i_isolate(), zone());
  Handle<HeapObject> number = m.isolate()->factory()->NewHeapNumber(100.5);
  m.Return(m.HeapConstant(number));
  Tagged<HeapObject> result =
      Cast<HeapObject>(Tagged<Object>(reinterpret_cast<Address>(m.Call())));
  CHECK_EQ(result, *number);
}

TEST_F(CodeGenTest, RunParam1) {
  RawMachineAssemblerTester<int32_t> m(i_isolate(), zone(),
                                       MachineType::Int32());
  m.Return(m.Parameter(0));

  FOR_INT32_INPUTS(i) {
    int32_t result = m.Call(i);
    CHECK_EQ(i, result);
  }
}

TEST_F(CodeGenTest, RunParam2_1) {
  RawMachineAssemblerTester<int32_t> m(
      i_isolate(), zone(), MachineType::Int32(), MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  m.Return(p0);
  USE(p1);

  FOR_INT32_INPUTS(i) {
    int32_t result = m.Call(i, -9999);
    CHECK_EQ(i, result);
  }
}

TEST_F(CodeGenTest, RunParam2_2) {
  RawMachineAssemblerTester<int32_t> m(
      i_isolate(), zone(), MachineType::Int32(), MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  m.Return(p1);
  USE(p0);

  FOR_INT32_INPUTS(i) {
    int32_t result = m.Call(-7777, i);
    CHECK_EQ(i, result);
  }
}

TEST_F(CodeGenTest, RunParam3) {
  for (int i = 0; i < 3; i++) {
    RawMachineAssemblerTester<int32_t> m(
        i_isolate(), zone(), MachineType::Int32(), MachineType::Int32(),
        MachineType::Int32());
    Node* nodes[] = {m.Parameter(0), m.Parameter(1), m.Parameter(2)};
    m.Return(nodes[i]);

    int p[] = {-99, -77, -88};
    FOR_INT32_INPUTS(j) {
      p[i] = j;
      int32_t result = m.Call(p[0], p[1], p[2]);
      CHECK_EQ(j, result);
    }
  }
}

TEST_F(CodeGenTest, RunBinopTester) {
  {
    RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
    Int32BinopTester bt(&m);
    bt.AddReturn(bt.param0);

    FOR_INT32_INPUTS(i) { CHECK_EQ(i, bt.call(i, 777)); }
  }

  {
    RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
    Int32BinopTester bt(&m);
    bt.AddReturn(bt.param1);

    FOR_INT32_INPUTS(i) { CHECK_EQ(i, bt.call(666, i)); }
  }

  {
    RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
    Float64BinopTester bt(&m);
    bt.AddReturn(bt.param0);

    FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, bt.call(i, 9.0)); }
  }

  {
    RawMachineAssemblerTester<int32_t> m(i_isolate(), zone());
    Float64BinopTester bt(&m);
    bt.AddReturn(bt.param1);

    FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, bt.call(-11.25, i)); }
  }
}

#if V8_TARGET_ARCH_64_BIT
// TODO(ahaas): run int64 tests on all platforms when supported.

namespace {

int64_t Add4(int64_t a, int64_t b, int64_t c, int64_t d) {
  // Operate on uint64_t values to avoid undefined behavior.
  return static_cast<int64_t>(
      static_cast<uint64_t>(a) + static_cast<uint64_t>(b) +
      static_cast<uint64_t>(c) + static_cast<uint64_t>(d));
}

int64_t Add3(int64_t a, int64_t b, int64_t c) { return Add4(a, b, c, 0); }

}  // namespace

TEST_F(CodeGenTest, RunBufferedRawMachineAssemblerTesterTester) {
  {
    BufferedRawMachineAssemblerTester<int64_t> m(i_isolate(), zone());
    m.Return(m.Int64Constant(0x12500000000));
    CHECK_EQ(0x12500000000, m.Call());
  }
  {
    BufferedRawMachineAssemblerTester<double> m(i_isolate(), zone(),
                                                MachineType::Float64());
    m.Return(m.Parameter(0));
    FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, m.Call(i)); }
  }
  {
    BufferedRawMachineAssemblerTester<int64_t> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64());
    m.Return(m.Int64Add(m.Parameter(0), m.Parameter(1)));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        CHECK_EQ(base::AddWithWraparound(i, j), m.Call(i, j));
        CHECK_EQ(base::AddWithWraparound(j, i), m.Call(j, i));
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<int64_t> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64(),
        MachineType::Int64());
    m.Return(
        m.Int64Add(m.Int64Add(m.Parameter(0), m.Parameter(1)), m.Parameter(2)));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        CHECK_EQ(Add3(i, i, j), m.Call(i, i, j));
        CHECK_EQ(Add3(i, j, i), m.Call(i, j, i));
        CHECK_EQ(Add3(j, i, i), m.Call(j, i, i));
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<int64_t> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64(),
        MachineType::Int64(), MachineType::Int64());
    m.Return(m.Int64Add(
        m.Int64Add(m.Int64Add(m.Parameter(0), m.Parameter(1)), m.Parameter(2)),
        m.Parameter(3)));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        CHECK_EQ(Add4(i, i, i, j), m.Call(i, i, i, j));
        CHECK_EQ(Add4(i, i, j, i), m.Call(i, i, j, i));
        CHECK_EQ(Add4(i, j, i, i), m.Call(i, j, i, i));
        CHECK_EQ(Add4(j, i, i, i), m.Call(j, i, i, i));
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<void> m(i_isolate(), zone());
    int64_t result;
    m.Store(MachineTypeForC<int64_t>().representation(),
            m.PointerConstant(&result), m.Int64Constant(0x12500000000),
            kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    m.Call();
    CHECK_EQ(0x12500000000, result);
  }
  {
    BufferedRawMachineAssemblerTester<void> m(i_isolate(), zone(),
                                              MachineType::Float64());
    double result;
    m.Store(MachineTypeForC<double>().representation(),
            m.PointerConstant(&result), m.Parameter(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    FOR_FLOAT64_INPUTS(i) {
      m.Call(i);
      CHECK_DOUBLE_EQ(i, result);
    }
  }
  {
    BufferedRawMachineAssemblerTester<void> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64());
    int64_t result;
    m.Store(MachineTypeForC<int64_t>().representation(),
            m.PointerConstant(&result),
            m.Int64Add(m.Parameter(0), m.Parameter(1)), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        m.Call(i, j);
        CHECK_EQ(base::AddWithWraparound(i, j), result);

        m.Call(j, i);
        CHECK_EQ(base::AddWithWraparound(j, i), result);
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<void> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64(),
        MachineType::Int64());
    int64_t result;
    m.Store(
        MachineTypeForC<int64_t>().representation(), m.PointerConstant(&result),
        m.Int64Add(m.Int64Add(m.Parameter(0), m.Parameter(1)), m.Parameter(2)),
        kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        m.Call(i, i, j);
        CHECK_EQ(Add3(i, i, j), result);

        m.Call(i, j, i);
        CHECK_EQ(Add3(i, j, i), result);

        m.Call(j, i, i);
        CHECK_EQ(Add3(j, i, i), result);
      }
    }
  }
  {
    BufferedRawMachineAssemblerTester<void> m(
        i_isolate(), zone(), MachineType::Int64(), MachineType::Int64(),
        MachineType::Int64(), MachineType::Int64());
    int64_t result;
    m.Store(MachineTypeForC<int64_t>().representation(),
            m.PointerConstant(&result),
            m.Int64Add(m.Int64Add(m.Int64Add(m.Parameter(0), m.Parameter(1)),
                                  m.Parameter(2)),
                       m.Parameter(3)),
            kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    FOR_INT64_INPUTS(i) {
      FOR_INT64_INPUTS(j) {
        m.Call(i, i, i, j);
        CHECK_EQ(Add4(i, i, i, j), result);

        m.Call(i, i, j, i);
        CHECK_EQ(Add4(i, i, j, i), result);

        m.Call(i, j, i, i);
        CHECK_EQ(Add4(i, j, i, i), result);

        m.Call(j, i, i, i);
        CHECK_EQ(Add4(j, i, i, i), result);
      }
    }
  }
}

#endif
}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```