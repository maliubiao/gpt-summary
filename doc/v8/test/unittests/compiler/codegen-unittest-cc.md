Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Context:** The first step is to recognize the file path: `v8/test/unittests/compiler/codegen-unittest.cc`. This immediately tells us this is a *unit test* for the *code generation* part of the *V8 compiler*. Unit tests are designed to isolate and verify small, specific units of code. The `.cc` extension confirms it's C++ source.

2. **High-Level Overview:** Quickly scan the code for major structures. We see:
    * Includes:  Standard V8 headers related to objects, compilation, and testing.
    * Namespaces: `v8`, `internal`, `compiler`. This reinforces the location within V8's architecture.
    * A Class: `CodeGenTest` inheriting from `TestWithIsolateAndZone`. This is a common pattern in V8 unit tests, setting up the necessary environment for running V8 code.
    * Member functions within `CodeGenTest`: `RunSmiConstant`, `RunNumberConstant`. These look like helper functions for running specific kinds of tests.
    * `TEST_F` macros: These are the actual test cases. Each `TEST_F` defines an individual test function within the `CodeGenTest` class.

3. **Analyze Individual Components:** Now, let's examine the key parts in more detail:

    * **`CodeGenTest` Class:**
        * The constructor sets up the zone for graph compression (optimization related).
        * `RunSmiConstant`:  This function takes an integer, creates a `RawMachineAssemblerTester` (a tool for building machine code snippets), generates a Smi constant (a small integer representation in V8), and checks if the generated code returns the expected Smi. The `#if !V8_TARGET_ARCH_X64` suggests architecture-specific behavior. *Self-correction: Initially, I might have just thought it tests Smi constants generally, but the architecture check hints at a specific generation strategy on x64.*
        * `RunNumberConstant`: Similar to `RunSmiConstant`, but for general JavaScript numbers (doubles). The `#if V8_TARGET_ARCH_X64` again indicates platform-specific logic, particularly related to Smi handling on x64. *Self-correction: Noticed the `IsSmi` check, indicating that even when testing number constants, the code might optimize to a Smi if the value fits.*

    * **`CompareWrapper` Test:** This test is crucial. It doesn't directly test *code generation* in the same way as the others, but it tests a *utility class* used in code generation. It verifies that the `CompareWrapper` correctly performs comparisons (equal, less than, less than or equal) for both signed and unsigned 32-bit integers and 64-bit floating-point numbers, including special cases like NaN and infinity. The extensive set of `CHECK_EQ` calls provides thorough coverage.

    * **`ParametersEqual` Test:**  A simple test to ensure that the `Parameter()` method of `RawMachineAssemblerTester` returns the same node for the same parameter index. This verifies the basic functionality of accessing function arguments within the test framework.

    * **`RunEmpty` Test:**  Tests the simplest case: generating a function that returns a constant.

    * **`RunInt32Constants`, `RunSmiConstants`, `RunNumberConstants` Tests:** These test the generation of code for different types of constant values. The loops and specific values tested aim to cover various edge cases and common scenarios.

    * **`RunEmptyString`, `RunHeapConstant`, `RunHeapNumberConstant` Tests:** These test the generation of code for string constants and heap object constants.

    * **`RunParam1`, `RunParam2_1`, `RunParam2_2`, `RunParam3` Tests:** These tests verify the correct handling of function parameters in the generated code. They test different numbers of parameters and the ability to return specific parameters.

    * **`RunBinopTester` Test:** This test uses helper classes (`Int32BinopTester`, `Float64BinopTester`) to test the basic functionality of these testers by returning one of the input parameters. This is a form of testing the testing infrastructure itself.

    * **`RunBufferedRawMachineAssemblerTesterTester` Test (x64 only):** This section, enabled only on 64-bit architectures, tests a more advanced assembler tester (`BufferedRawMachineAssemblerTester`). It focuses on generating code for 64-bit integer operations (addition) and memory stores.

4. **Identify Core Functionality:** Based on the analysis, the primary function of `codegen-unittest.cc` is to verify the correctness of the V8 code generator. It does this by:
    * Using `RawMachineAssemblerTester` (and its buffered variant) to construct small snippets of machine code.
    * Executing the generated code.
    * Comparing the actual results with expected results using `CHECK_EQ` and `CHECK_DOUBLE_EQ`.
    * Testing various scenarios involving constants, parameters, and basic operations.
    * Testing a utility class used in code generation (`CompareWrapper`).

5. **Address Specific Questions:**  Now, directly answer the questions posed:

    * **Functionality:** List the identified functionalities.
    * **Torque:** Check the file extension (`.cc`). It's not `.tq`, so it's not Torque.
    * **JavaScript Relation:** The tests are about *code generation*, which is the process of converting JavaScript (or its intermediate representation) into machine code. Provide examples of JavaScript code that would trigger the tested code generation scenarios (e.g., simple arithmetic, comparisons).
    * **Logic and I/O:** For tests involving specific operations (like comparisons), give examples of input values and their expected boolean output.
    * **Common Errors:** Think about what mistakes developers might make when working with code generation or low-level operations (e.g., incorrect comparison logic, assuming specific representations of numbers). Relate these to the concepts tested in the unit test.

6. **Structure the Output:** Organize the findings into a clear and logical format, addressing each part of the initial request. Use headings and bullet points for readability. Provide code examples and explanations where necessary.

By following this structured approach, combining high-level understanding with detailed analysis, and explicitly addressing each question, we can generate a comprehensive and accurate description of the `codegen-unittest.cc` file.
`v8/test/unittests/compiler/codegen-unittest.cc` 是 V8 JavaScript 引擎中编译器部分的单元测试文件，主要用于测试代码生成器的功能。 代码生成器负责将中间表示（IR）转换为特定架构的机器码。

**功能列举:**

1. **测试常量生成:**
   - 测试生成各种类型的常量，包括 Smi（小整数）、普通数字、字符串和堆对象。
   - 针对不同架构（例如 x64）可能存在的特殊处理进行测试。

2. **测试参数传递:**
   - 测试生成的代码能否正确处理函数参数的传递，包括不同数量的参数。

3. **测试基本运算符:**
   - 使用 `CompareWrapper` 类测试比较运算符（等于、小于、小于等于）对于不同数据类型（32位有符号/无符号整数、64位浮点数）的正确性。这虽然不是直接测试代码生成，但验证了代码生成器可能依赖的工具类的正确性。
   - 使用 `Int32BinopTester` 和 `Float64BinopTester` 等辅助类，测试基本算术运算符（虽然示例中只展示了返回参数，但这些测试器可以用于测试加减乘除等）。

4. **测试机器码生成框架 (`RawMachineAssemblerTester` 和 `BufferedRawMachineAssemblerTester`):**
   - 验证测试框架本身的功能是否正常，例如能否正确设置返回值、调用生成的代码并获取结果。
   - 特别地，`BufferedRawMachineAssemblerTester` 在 64 位架构上被用于测试更复杂的场景，例如存储操作。

**关于文件后缀和 Torque:**

`v8/test/unittests/compiler/codegen-unittest.cc` 的后缀是 `.cc`，这表明它是一个 C++ 源代码文件，而不是以 `.tq` 结尾的 Torque 源代码文件。 Torque 是一种用于定义 V8 内部实现的领域特定语言。

**与 Javascript 的关系 (及 Javascript 示例):**

`codegen-unittest.cc` 中测试的代码生成器是 V8 编译 JavaScript 代码的核心组件。当 V8 执行 JavaScript 代码时，它首先会将 JavaScript 源代码解析成抽象语法树（AST），然后通过一系列的优化阶段生成中间表示（IR），最后由代码生成器将 IR 转换为机器码。

以下是一些与测试用例相关的 JavaScript 例子：

1. **常量生成:**
   ```javascript
   function testSmi() {
     return 10; // 生成 Smi 常量
   }

   function testNumber() {
     return 3.14; // 生成浮点数常量
   }

   function testString() {
     return "hello"; // 生成字符串常量
   }

   let obj = {};
   function testObject() {
     return obj; // 生成堆对象常量
   }
   ```
   `RunSmiConstant`, `RunNumberConstant`, `RunEmptyString`, `RunHeapConstant`, `RunHeapNumberConstant` 等测试用例会验证编译器能否为这些 JavaScript 常量生成正确的机器码。

2. **参数传递:**
   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(5, 3);
   ```
   `RunParam1`, `RunParam2_1`, `RunParam2_2`, `RunParam3` 等测试用例模拟了函数调用和参数传递的场景，用于测试代码生成器能否正确处理参数。

3. **基本运算符:**
   ```javascript
   function compare(x, y) {
     return x < y;
   }

   function calculate(a, b) {
     return a * b;
   }
   ```
   `CompareWrapper` 测试了底层比较操作的正确性，这与 JavaScript 中的比较运算符 (`<`, `>`, `==`, `<=`, `>=`) 相关。虽然 `codegen-unittest.cc` 中没有直接展示算术运算符的代码生成测试，但 `Int32BinopTester` 和 `Float64BinopTester` 的设计是为了方便测试这些运算符的代码生成。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(CodeGenTest, CompareWrapper)` 中的部分代码为例：

**假设输入:**

- `wWord32Equal` (用于测试 32 位整数相等比较)
- `a = 5`, `b = 5`
- `a = 10`, `b = 7`

**预期输出:**

- `wWord32Equal.Int32Compare(5, 5)` 返回 `true`
- `wWord32Equal.Int32Compare(10, 7)` 返回 `false`

**解释:** `CompareWrapper` 类封装了比较操作的实现。对于 `wWord32Equal`，当两个输入的 32 位整数相等时，`Int32Compare` 方法应该返回 `true`，否则返回 `false`。

**涉及用户常见的编程错误 (举例说明):**

虽然这个测试文件是针对编译器内部的，但它测试的内容与开发者在编写 JavaScript 时可能遇到的错误有关：

1. **类型混淆导致的比较错误:**
   ```javascript
   console.log(5 == "5"); // true (类型转换后相等)
   console.log(5 === "5"); // false (类型不同)
   ```
   `CompareWrapper` 测试了严格的类型比较，这有助于确保编译器在处理 JavaScript 的不同比较方式时生成正确的代码。用户可能会混淆 `==` 和 `===`，导致逻辑错误。

2. **浮点数比较的精度问题:**
   ```javascript
   let a = 0.1 + 0.2;
   let b = 0.3;
   console.log(a == b); // 可能是 false，因为浮点数运算存在精度问题
   ```
   `CompareWrapper` 对浮点数的比较进行了详细的测试，包括 NaN 和无穷大的处理。这反映了 JavaScript 中浮点数比较的复杂性，用户需要注意精度误差。

3. **无符号整数的溢出和比较:**
   虽然 JavaScript 中没有直接的无符号整数类型，但了解无符号整数的比较方式对于理解计算机底层原理很重要。 `CompareWrapper` 中对无符号整数的测试可以帮助理解在某些底层操作中如何处理无符号数的比较，避免因误解而产生错误。

总而言之，`v8/test/unittests/compiler/codegen-unittest.cc` 是 V8 编译器代码生成功能的关键测试文件，它通过构建各种代码片段并验证其执行结果，确保编译器能够正确地将 JavaScript 代码转换为高效的机器码。虽然它主要面向 V8 开发者，但其测试的许多方面与 JavaScript 语言的特性和用户可能遇到的编程问题密切相关。

### 提示词
```
这是目录为v8/test/unittests/compiler/codegen-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/codegen-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```