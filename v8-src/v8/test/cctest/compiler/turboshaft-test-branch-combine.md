Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example if it relates to JavaScript features.

2. **Initial Scan - Keywords and Structure:**  Quickly scan the file for recognizable keywords and structural elements. I see:
    * `#include`: Standard C++ headers, hinting at basic data types and testing frameworks.
    * `namespace v8::internal::compiler::turboshaft`:  This immediately signals it's part of the V8 JavaScript engine's compiler, specifically the Turboshaft pipeline.
    * `TEST(...)`:  These are clearly unit tests. Each `TEST` block focuses on a specific scenario.
    * `RawMachineAssemblerTester`: This class name suggests it's for testing low-level code generation within the compiler. It's likely used to create simple code snippets and verify their behavior.
    * `m.Branch(...)`: This indicates the core functionality being tested involves conditional branching in the generated code.
    * `m.Word32Equal`, `m.Int32LessThan`, `m.Uint32LessThan`, etc.: These are likely operations related to comparing 32-bit integers (signed and unsigned).
    * `m.Word32Constant(...)`:  Used to create constant integer values.
    * `m.Parameter(...)`: Used to represent input parameters to the generated code.
    * `m.Return(...)`: Represents the return statement in the generated code.
    * `FOR_INT32_INPUTS(a)`, `FOR_UINT32_INPUTS(a)`:  Macros likely used to iterate through a range of integer values for testing.
    * `CHECK_EQ(...)`:  Assertion macro for verifying expected results.

3. **Identify the Core Functionality:**  The repeated use of `m.Branch` with different comparison operations (`Word32Equal`, `Int32LessThan`, etc.) suggests the file is testing how the compiler handles conditional branches based on these comparisons. The "Combine" in the filename (`turboshaft-test-branch-combine.cc`) further reinforces this idea – it's testing the *optimization* or combination of branch instructions.

4. **Analyze Individual Tests:** Look at the names of the `TEST` functions. They provide valuable clues:
    * `BranchCombineWord32EqualZero_1`, `BranchCombineWord32EqualZero_chain`: Testing branches where a value is compared to zero. The "chain" test suggests testing multiple chained comparisons.
    * `BranchCombineInt32LessThanZero_1`: Testing branches based on "less than zero" comparisons.
    * `BranchCombineUint32LessThan100_1`, `BranchCombineUint32LessThanOrEqual100_1`: Testing branches with comparisons against non-zero constants.
    * `BranchCombineWord32EqualP`, `BranchCombineWord32EqualI`: Testing comparisons with parameters and immediate values (constants).
    * The tests with `CmpMaterializeBoolGen` and `CmpBranchGen`: These seem to be more generalized testing strategies, likely iterating through different comparison operations and input shapes.
    * `BranchCombineEffectLevel`: This test name suggests focusing on side effects and ensuring optimizations don't introduce bugs related to the order of operations (like loads and stores).
    * The tests with `Word32Add`, `Word32BitwiseAnd`: Testing branches conditioned on the results of arithmetic and bitwise operations.

5. **Synthesize the Functionality:** Based on the individual tests and the keywords, I can summarize the file's purpose:  This file tests the "branch combining" optimization in the Turboshaft compiler. It checks if the compiler can correctly and efficiently generate code for conditional branches based on various comparison operations (equality, less than, greater than, etc.) involving integers (signed and unsigned), floating-point numbers, and the results of arithmetic/bitwise operations. It also considers different input forms (parameters, constants) and potential side effects.

6. **Connect to JavaScript:**  Since V8 is the JavaScript engine, there must be a connection to JavaScript. Conditional statements are fundamental to JavaScript. Keywords like `if`, `else if`, `else`, and the ternary operator (`? :`) all rely on evaluating conditions and branching execution.

7. **Create a JavaScript Example:**  Choose a simple example that directly mirrors one of the tested scenarios. The `BranchCombineWord32EqualZero_1` test is a good candidate because it's straightforward: checking if a number is equal to zero. Translate the C++ logic (branching based on a comparison and returning different constants) into equivalent JavaScript using an `if/else` statement. The constants used in the C++ test can be used in the JavaScript example to show the direct correspondence.

8. **Refine the Explanation:**  Explain the connection between the C++ tests and the JavaScript example. Highlight that the C++ code tests the *underlying implementation* of how JavaScript's conditional logic is handled by the V8 engine. Mention that optimizations like "branch combining" improve the performance of JavaScript code execution.

9. **Review and Polish:** Read through the summary and the JavaScript example to ensure they are clear, concise, and accurate. Check for any potential misunderstandings or ambiguities.

This step-by-step process, starting from a high-level overview and gradually drilling down into the details, helps in understanding the functionality of the C++ file and making the connection to JavaScript. The key is to look for patterns, recognize familiar compiler concepts, and relate them to user-facing language features.
这个C++源代码文件 `v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` 是 V8 JavaScript 引擎中 Turboshaft 编译器的**分支合并 (Branch Combining)** 功能的单元测试。

**功能归纳:**

该文件的主要目的是测试 Turboshaft 编译器在处理条件分支时的优化能力，特别是如何将比较操作与后续的分支指令有效地结合起来。它通过编写一系列测试用例来验证以下场景：

* **基本的比较分支:** 测试基于各种整数和浮点数比较操作（等于、小于、大于等等）的分支指令是否能正确执行。这些比较操作包括：
    * 与零的比较 (例如 `x == 0`, `x < 0`)
    * 与常数的比较 (例如 `x < 100`)
    * 两个变量之间的比较 (例如 `x == y`)
* **比较操作的多种输入形式:** 测试比较操作的操作数可以是参数、常量或者其他操作的结果。
* **链式比较:** 测试多个连续的比较操作是否能被正确处理和优化 (例如 `x == 0 == 0`).
* **比较结果的物化 (Materialization):** 测试将比较结果显式地存储为布尔值 (0 或 1) 的情况。
* **分支合并对副作用的考虑:** 测试在比较操作和分支指令之间存在副作用操作（例如内存存储）时，编译器是否能正确处理，避免错误的优化。
* **基于算术和位运算结果的分支:** 测试基于加法 (`Word32Add`) 和按位与 (`Word32BitwiseAnd`) 等运算结果的比较分支。
* **不同类型的整数比较:** 测试有符号整数 (`Int32`) 和无符号整数 (`Uint32`) 的各种比较操作。
* **浮点数比较:** 测试 `Float64` 类型的比较操作。
* **分支的真假分支顺序:** 测试真分支和假分支在代码中的顺序是否影响分支合并的正确性。

**与 JavaScript 的关系及举例说明:**

这个文件测试的是 V8 引擎内部的编译器优化，直接与 JavaScript 代码的执行性能相关。JavaScript 中的条件语句（如 `if...else`，三元运算符 `? :`）以及循环语句（如 `for`, `while`）都依赖于条件判断和分支。

**当 JavaScript 代码中存在比较操作并且基于这些比较结果进行条件判断时，Turboshaft 编译器的分支合并优化就能发挥作用，提高代码的执行效率。**

**JavaScript 例子:**

假设有以下简单的 JavaScript 代码：

```javascript
function testBranchCombine(x) {
  const constant = 100;
  if (x < constant) {
    return -1;
  } else {
    return 1;
  }
}

console.log(testBranchCombine(50));  // 输出 -1
console.log(testBranchCombine(150)); // 输出 1
```

在这个 JavaScript 例子中，`if (x < constant)` 语句就是一个条件分支。当 V8 引擎执行这段代码时，Turboshaft 编译器会将其转换为底层的机器指令。 `v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` 中的 `TEST(BranchCombineUint32LessThan100_1)` 和类似的测试用例，就是在模拟和验证编译器如何高效地处理像 `x < constant` 这样的比较，并将其与后续的分支操作结合起来。

具体来说，Turboshaft 的分支合并优化可能会将以下步骤结合起来：

1. **计算比较结果:**  比较 `x` 和 `constant` 的值。
2. **根据比较结果跳转:**  如果 `x < constant` 为真，则跳转到执行 `return -1;` 的代码块；否则跳转到执行 `return 1;` 的代码块。

通过分支合并，编译器可以避免一些冗余的中间步骤，例如显式地将比较结果存储到一个布尔变量中再进行判断，从而提升性能。

**总结:**

`v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` 这个 C++ 文件是 V8 引擎中用于测试 Turboshaft 编译器分支合并优化功能的单元测试。它通过各种测试用例确保编译器能够正确且高效地处理 JavaScript 代码中常见的条件分支结构，从而提升 JavaScript 代码的执行效率。虽然开发者不会直接编写或接触这些 C++ 代码，但这些测试保证了 V8 引擎能更好地执行我们编写的 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-test-branch-combine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/turboshaft-codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8::internal::compiler::turboshaft {

static TurboshaftComparison int32cmp_opcodes[] = {
    TurboshaftComparison::kWord32Equal, TurboshaftComparison::kInt32LessThan,
    TurboshaftComparison::kInt32LessThanOrEqual,
    TurboshaftComparison::kUint32LessThan,
    TurboshaftComparison::kUint32LessThanOrEqual};

TEST(BranchCombineWord32EqualZero_1) {
  // Test combining a branch with x == 0
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t eq_constant = -1033;
  int32_t ne_constant = 825118;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Word32Equal(p0, m.Word32Constant(0)), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_INT32_INPUTS(a) {
    int32_t expect = a == 0 ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineWord32EqualZero_chain) {
  // Test combining a branch with a chain of x == 0 == 0 == 0 ...
  int32_t eq_constant = -1133;
  int32_t ne_constant = 815118;

  for (int k = 0; k < 6; k++) {
    RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
    OpIndex p0 = m.Parameter(0);
    Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
    V<Word32> cond = p0;
    for (int j = 0; j < k; j++) {
      cond = m.Word32Equal(cond, m.Word32Constant(0));
    }
    m.Branch(cond, blocka, blockb);
    m.Bind(blocka);
    m.Return(m.Word32Constant(eq_constant));
    m.Bind(blockb);
    m.Return(m.Word32Constant(ne_constant));

    FOR_INT32_INPUTS(a) {
      int32_t expect = (k & 1) == 1 ? (a == 0 ? eq_constant : ne_constant)
                                    : (a == 0 ? ne_constant : eq_constant);
      CHECK_EQ(expect, m.Call(a));
    }
  }
}

TEST(BranchCombineInt32LessThanZero_1) {
  // Test combining a branch with x < 0
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t eq_constant = -1433;
  int32_t ne_constant = 845118;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Int32LessThan(p0, m.Word32Constant(0)), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_INT32_INPUTS(a) {
    int32_t expect = a < 0 ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineUint32LessThan100_1) {
  // Test combining a branch with x < 100
  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  int32_t eq_constant = 1471;
  int32_t ne_constant = 88845718;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Uint32LessThan(p0, m.Word32Constant(100)), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_UINT32_INPUTS(a) {
    int32_t expect = a < 100 ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineUint32LessThanOrEqual100_1) {
  // Test combining a branch with x <= 100
  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  int32_t eq_constant = 1479;
  int32_t ne_constant = 77845719;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Uint32LessThanOrEqual(p0, m.Word32Constant(100)), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_UINT32_INPUTS(a) {
    int32_t expect = a <= 100 ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineZeroLessThanInt32_1) {
  // Test combining a branch with 0 < x
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t eq_constant = -2033;
  int32_t ne_constant = 225118;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Int32LessThan(m.Word32Constant(0), p0), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_INT32_INPUTS(a) {
    int32_t expect = 0 < a ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineInt32GreaterThanZero_1) {
  // Test combining a branch with x > 0
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t eq_constant = -1073;
  int32_t ne_constant = 825178;
  OpIndex p0 = m.Parameter(0);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Int32GreaterThan(p0, m.Word32Constant(0)), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_INT32_INPUTS(a) {
    int32_t expect = a > 0 ? eq_constant : ne_constant;
    CHECK_EQ(expect, m.Call(a));
  }
}

TEST(BranchCombineWord32EqualP) {
  // Test combining a branch with an Word32Equal.
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  int32_t eq_constant = -1035;
  int32_t ne_constant = 825018;
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(m.Word32Equal(p0, p1), blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(eq_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(ne_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = a == b ? eq_constant : ne_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32EqualI) {
  int32_t eq_constant = -1135;
  int32_t ne_constant = 925718;

  for (int left = 0; left < 2; left++) {
    FOR_INT32_INPUTS(a) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());

      OpIndex p0 = m.Word32Constant(a);
      OpIndex p1 = m.Parameter(0);

      Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
      if (left == 1) m.Branch(m.Word32Equal(p0, p1), blocka, blockb);
      if (left == 0) m.Branch(m.Word32Equal(p1, p0), blocka, blockb);
      m.Bind(blocka);
      m.Return(m.Word32Constant(eq_constant));
      m.Bind(blockb);
      m.Return(m.Word32Constant(ne_constant));

      FOR_INT32_INPUTS(b) {
        int32_t expect = a == b ? eq_constant : ne_constant;
        CHECK_EQ(expect, m.Call(b));
      }
    }
  }
}

TEST(BranchCombineInt32CmpP) {
  int32_t eq_constant = -1235;
  int32_t ne_constant = 725018;

  for (int op = 0; op < 2; op++) {
    RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                         MachineType::Int32());
    OpIndex p0 = m.Parameter(0);
    OpIndex p1 = m.Parameter(1);

    Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
    if (op == 0) m.Branch(m.Int32LessThan(p0, p1), blocka, blockb);
    if (op == 1) m.Branch(m.Int32LessThanOrEqual(p0, p1), blocka, blockb);
    m.Bind(blocka);
    m.Return(m.Word32Constant(eq_constant));
    m.Bind(blockb);
    m.Return(m.Word32Constant(ne_constant));

    FOR_INT32_INPUTS(a) {
      FOR_INT32_INPUTS(b) {
        int32_t expect = 0;
        if (op == 0) expect = a < b ? eq_constant : ne_constant;
        if (op == 1) expect = a <= b ? eq_constant : ne_constant;
        CHECK_EQ(expect, m.Call(a, b));
      }
    }
  }
}

TEST(BranchCombineInt32CmpI) {
  int32_t eq_constant = -1175;
  int32_t ne_constant = 927711;

  for (int op = 0; op < 2; op++) {
    FOR_INT32_INPUTS(a) {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      OpIndex p0 = m.Word32Constant(a);
      OpIndex p1 = m.Parameter(0);

      Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
      if (op == 0) m.Branch(m.Int32LessThan(p0, p1), blocka, blockb);
      if (op == 1) m.Branch(m.Int32LessThanOrEqual(p0, p1), blocka, blockb);
      m.Bind(blocka);
      m.Return(m.Word32Constant(eq_constant));
      m.Bind(blockb);
      m.Return(m.Word32Constant(ne_constant));

      FOR_INT32_INPUTS(b) {
        int32_t expect = 0;
        if (op == 0) expect = a < b ? eq_constant : ne_constant;
        if (op == 1) expect = a <= b ? eq_constant : ne_constant;
        CHECK_EQ(expect, m.Call(b));
      }
    }
  }
}

// Now come the sophisticated tests for many input shape combinations.

// Materializes a boolean (1 or 0) from a comparison.
class CmpMaterializeBoolGen : public BinopGen<int32_t> {
 public:
  CompareWrapper w;
  bool invert;

  CmpMaterializeBoolGen(TurboshaftComparison op, bool i) : w(op), invert(i) {}

  void gen(RawMachineAssemblerTester<int32_t>* m, OpIndex a,
           OpIndex b) override {
    OpIndex cond = w.MakeNode(m, a, b);
    if (invert) cond = m->Word32Equal(cond, m->Word32Constant(0));
    m->Return(cond);
  }
  int32_t expected(int32_t a, int32_t b) override {
    if (invert) return !w.Int32Compare(a, b) ? 1 : 0;
    return w.Int32Compare(a, b) ? 1 : 0;
  }
};

// Generates a branch and return one of two values from a comparison.
class CmpBranchGen : public BinopGen<int32_t> {
 public:
  CompareWrapper w;
  bool invert;
  bool true_first;
  int32_t eq_constant;
  int32_t ne_constant;

  CmpBranchGen(TurboshaftComparison op, bool i, bool t, int32_t eq, int32_t ne)
      : w(op), invert(i), true_first(t), eq_constant(eq), ne_constant(ne) {}

  void gen(RawMachineAssemblerTester<int32_t>* m, OpIndex a,
           OpIndex b) override {
    Block *blocka = m->NewBlock(), *blockb = m->NewBlock();
    V<Word32> cond = w.MakeNode(m, a, b);
    if (invert) cond = m->Word32Equal(cond, m->Word32Constant(0));
    m->Branch(cond, blocka, blockb);
    if (true_first) {
      m->Bind(blocka);
      m->Return(m->Word32Constant(eq_constant));
      m->Bind(blockb);
      m->Return(m->Word32Constant(ne_constant));
    } else {
      m->Bind(blockb);
      m->Return(m->Word32Constant(ne_constant));
      m->Bind(blocka);
      m->Return(m->Word32Constant(eq_constant));
    }
  }
  int32_t expected(int32_t a, int32_t b) override {
    if (invert) return !w.Int32Compare(a, b) ? eq_constant : ne_constant;
    return w.Int32Compare(a, b) ? eq_constant : ne_constant;
  }
};

TEST(BranchCombineInt32CmpAllInputShapes_materialized) {
  for (size_t i = 0; i < arraysize(int32cmp_opcodes); i++) {
    CmpMaterializeBoolGen gen(int32cmp_opcodes[i], false);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineInt32CmpAllInputShapes_inverted_materialized) {
  for (size_t i = 0; i < arraysize(int32cmp_opcodes); i++) {
    CmpMaterializeBoolGen gen(int32cmp_opcodes[i], true);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineInt32CmpAllInputShapes_branch_true) {
  for (int i = 0; i < static_cast<int>(arraysize(int32cmp_opcodes)); i++) {
    CmpBranchGen gen(int32cmp_opcodes[i], false, false, 995 + i, -1011 - i);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineInt32CmpAllInputShapes_branch_false) {
  for (int i = 0; i < static_cast<int>(arraysize(int32cmp_opcodes)); i++) {
    CmpBranchGen gen(int32cmp_opcodes[i], false, true, 795 + i, -2011 - i);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineInt32CmpAllInputShapes_inverse_branch_true) {
  for (int i = 0; i < static_cast<int>(arraysize(int32cmp_opcodes)); i++) {
    CmpBranchGen gen(int32cmp_opcodes[i], true, false, 695 + i, -3011 - i);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineInt32CmpAllInputShapes_inverse_branch_false) {
  for (int i = 0; i < static_cast<int>(arraysize(int32cmp_opcodes)); i++) {
    CmpBranchGen gen(int32cmp_opcodes[i], true, true, 595 + i, -4011 - i);
    Int32BinopInputShapeTester tester(&gen);
    tester.TestAllInputShapes();
  }
}

TEST(BranchCombineFloat64Compares) {
  double inf = V8_INFINITY;
  double nan = std::numeric_limits<double>::quiet_NaN();
  double inputs[] = {0.0, 1.0, -1.0, -inf, inf, nan};

  int32_t eq_constant = -1733;
  int32_t ne_constant = 915118;

  double input_a = 0.0;
  double input_b = 0.0;

  CompareWrapper cmps[] = {
      CompareWrapper(TurboshaftComparison::kFloat64Equal),
      CompareWrapper(TurboshaftComparison::kFloat64LessThan),
      CompareWrapper(TurboshaftComparison::kFloat64LessThanOrEqual)};

  for (size_t c = 0; c < arraysize(cmps); c++) {
    CompareWrapper cmp = cmps[c];
    for (int invert = 0; invert < 2; invert++) {
      RawMachineAssemblerTester<int32_t> m;
      OpIndex a = m.LoadFromPointer(&input_a, MachineType::Float64());
      OpIndex b = m.LoadFromPointer(&input_b, MachineType::Float64());

      Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
      V<Word32> cond = cmp.MakeNode(&m, a, b);
      if (invert) cond = m.Word32Equal(cond, m.Word32Constant(0));
      m.Branch(cond, blocka, blockb);
      m.Bind(blocka);
      m.Return(m.Word32Constant(eq_constant));
      m.Bind(blockb);
      m.Return(m.Word32Constant(ne_constant));

      for (size_t i = 0; i < arraysize(inputs); ++i) {
        for (size_t j = 0; j < arraysize(inputs); ++j) {
          input_a = inputs[i];
          input_b = inputs[j];
          int32_t expected =
              invert ? (cmp.Float64Compare(input_a, input_b) ? ne_constant
                                                             : eq_constant)
                     : (cmp.Float64Compare(input_a, input_b) ? eq_constant
                                                             : ne_constant);
          CHECK_EQ(expected, m.Call());
        }
      }
    }
  }
}

TEST(BranchCombineEffectLevel) {
  // Test that the load doesn't get folded into the branch, as there's a store
  // between them. See http://crbug.com/611976.
  int32_t input = 0;

  RawMachineAssemblerTester<int32_t> m;
  OpIndex a = m.LoadFromPointer(&input, MachineType::Int32());
  V<Word32> compare = m.Word32BitwiseAnd(a, m.Word32Constant(1));
  V<Word32> equal = m.Word32Equal(compare, m.Word32Constant(0));
  m.StoreToPointer(&input, MachineRepresentation::kWord32, m.Word32Constant(1));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(equal, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(42));
  m.Bind(blockb);
  m.Return(m.Word32Constant(0));

  CHECK_EQ(42, m.Call());
}

TEST(BranchCombineWord32AddLessThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Int32LessThan(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (base::AddWithWraparound(a, b) < 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32AddGreaterThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Int32GreaterThanOrEqual(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (base::AddWithWraparound(a, b) >= 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineInt32ZeroGreaterThanAdd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Int32GreaterThan(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (0 > base::AddWithWraparound(a, b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineInt32ZeroLessThanOrEqualAdd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Int32LessThanOrEqual(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (0 <= base::AddWithWraparound(a, b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUWord32AddLessThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Uint32LessThanOrEqual(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (a + b <= 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUWord32AddGreaterThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Uint32GreaterThan(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (a + b > 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32ZeroGreaterThanOrEqualAdd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Uint32GreaterThanOrEqual(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 >= a + b) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32ZeroLessThanAdd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32Add(p0, p1);
  V<Word32> compare = m.Uint32LessThan(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 < a + b) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32BitwiseAndLessThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Int32LessThan(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = ((a & b) < 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32BitwiseAndGreaterThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Int32GreaterThanOrEqual(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = ((a & b) >= 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineInt32ZeroGreaterThanAnd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Int32GreaterThan(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = (0 > (a & b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineInt32ZeroLessThanOrEqualAnd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Int32LessThanOrEqual(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = (0 <= (a & b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32AndLessThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Uint32LessThanOrEqual(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = ((a & b) <= 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32AndGreaterThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Uint32GreaterThan(add, m.Word32Constant(0));

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = ((a & b) > 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32ZeroGreaterThanOrEqualAnd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Uint32GreaterThanOrEqual(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 >= (a & b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32ZeroLessThanAnd) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  OpIndex add = m.Word32BitwiseAnd(p0, p1);
  V<Word32> compare = m.Uint32LessThan(m.Word32Constant(0), add);

  Block *blocka = m.NewBlock(), *blockb = m.NewBlock();
  m.Branch(compare, blocka, blockb);
  m.Bind(blocka);
  m.Return(m.Word32Constant(t_constant));
  m.Bind(blockb);
  m.Return(m.Word32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 < (a & b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

}  // namespace v8::internal::compiler::turboshaft

"""

```