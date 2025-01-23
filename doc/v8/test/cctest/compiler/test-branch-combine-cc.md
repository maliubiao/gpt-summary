Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understanding the Request:** The request asks for the functionality of the provided C++ code, specifically focusing on its purpose within V8, whether it's related to JavaScript, illustrative examples, logical reasoning, and common programming errors it might address.

2. **Initial Code Scan - Keywords and Structure:** I'll first scan the code for familiar keywords and structural elements:
    * `#include`: Standard C++ includes, suggesting it's a C++ test file. The includes point to V8 internal components (`src/`, `test/cctest/`, `test/common/`).
    * `namespace v8`, `namespace internal`, `namespace compiler`:  Clearly within the V8 project, in the compiler component.
    * `TEST(...)`:  These look like Google Test framework macros, indicating this file contains unit tests.
    * `RawMachineAssemblerTester`: This class name strongly suggests it's testing code generation at a low level, likely related to the V8's TurboFan compiler (which deals with machine code generation).
    * `MachineType::...`: Enumerations related to data types at the machine level.
    * `IrOpcode::...`:  Likely instruction opcodes for the intermediate representation (IR) used in the compiler. The presence of comparison opcodes like `kWord32Equal`, `kInt32LessThan` is a key indicator.
    * `m.Branch(...)`, `m.Bind(...)`, `m.Return(...)`: These resemble assembly-like control flow constructs, reinforcing the idea of low-level code generation testing.
    * `FOR_INT32_INPUTS(...)`, `FOR_UINT32_INPUTS(...)`: Macros for iterating through various integer input values, typical for testing different scenarios.

3. **Inferring the Core Functionality:** Based on the keywords and structure, the primary function of this code is to **test the "branch combining" optimization in V8's compiler**. Branch combining is a compiler optimization that aims to simplify or eliminate redundant conditional branches, potentially improving performance. The tests seem to be constructed by:
    * Building small code snippets using `RawMachineAssemblerTester`.
    * Creating conditional branches based on comparisons.
    * Returning different constant values depending on the branch taken.
    * Running these snippets with various inputs and asserting that the output matches the expected behavior.

4. **Addressing Specific Questions:**

    * **Functionality:**  As identified above, the core function is testing the branch combining optimization.

    * **.tq Extension:** The file has a `.cc` extension, not `.tq`. Torque is a separate language used in V8 for defining built-in functions. This file is standard C++ testing compiler optimizations.

    * **Relationship to JavaScript:**  While this is a low-level compiler test, it directly impacts the performance of JavaScript code. The optimizations being tested here are applied to the generated machine code for JavaScript functions. To illustrate, a simple `if` statement in JavaScript relies on conditional branching at the machine code level.

    * **JavaScript Example:**  I need a simple JavaScript `if` statement that would likely benefit from branch combining. Something like `if (x === 0) { return a; } else { return b; }` is a good starting point because it involves a direct comparison and conditional execution.

    * **Code Logic Reasoning (Input/Output):** I need to select one of the `TEST` functions and trace its logic. `TEST(BranchCombineWord32EqualZero_1)` is a good choice as it's relatively simple. I'll analyze the code, identify the comparison, and determine the expected output for different inputs.

    * **Common Programming Errors:**  Branch combining optimizations can sometimes reveal subtle bugs in compiler implementations. However, the *tests* themselves aren't directly related to common *user* programming errors. The optimizations aim to *handle* user code efficiently. However, I can think of a scenario where a poorly written `if` condition in JavaScript could be a target for these optimizations, and the tests ensure the compiler handles such cases correctly. A good example is a condition that always evaluates to the same thing.

5. **Structuring the Output:**  I need to organize the information clearly, addressing each point in the request. Using headings and bullet points will improve readability.

6. **Refinement and Review:**  After drafting the initial response, I'll review it for accuracy and completeness. Are the JavaScript examples clear?  Is the logic reasoning easy to follow?  Have I addressed all parts of the request?  For example, I initially might not have emphasized *why* branch combining is important (performance). I'll add that during the review phase. I'll also double-check that the assumptions about the input and output of the chosen test case are correct.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and informative response that addresses all aspects of the user's request.
这个C++源代码文件 `v8/test/cctest/compiler/test-branch-combine.cc` 的主要功能是 **测试 V8 编译器中的 "分支合并 (branch combining)" 优化**。

**具体功能拆解:**

1. **测试分支合并优化:**  该文件包含一系列的单元测试 (以 `TEST(...)` 宏定义)，每个测试都旨在验证编译器是否能够正确地识别和优化特定的分支结构。分支合并是一种编译器优化技术，它尝试简化或消除冗余的条件分支，从而提高代码执行效率。

2. **使用 RawMachineAssemblerTester:**  测试使用 `RawMachineAssemblerTester` 类来构建底层的机器码指令序列。这允许开发者精确地控制生成的代码，并测试编译器在特定指令模式下的优化行为。

3. **模拟不同的分支场景:**  每个 `TEST` 函数都模拟了一个特定的分支场景，例如：
    *  判断一个值是否等于零 (`BranchCombineWord32EqualZero_1`)
    *  判断一个值是否小于零 (`BranchCombineInt32LessThanZero_1`)
    *  比较两个值 (`BranchCombineWord32EqualP`, `BranchCombineInt32CmpP`)
    *  比较一个值和一个常量 (`BranchCombineUint32LessThan100_1`)
    *  以及更复杂的组合，例如将比较的结果作为分支条件 (`BranchCombineInt32CmpAllInputShapes_materialized`)

4. **验证优化结果:**  每个测试用不同的输入值运行生成的代码，并断言返回的结果是否符合预期。如果编译器成功进行了分支合并，生成的代码应该在逻辑上等价于原始代码，但执行效率更高。

5. **测试不同数据类型和操作:**  测试覆盖了不同的数据类型 (如 `int32_t`, `uint32_t`, `double`) 和比较操作 (`==`, `<`, `<=`, `>`, `>=`)。

**关于 .tq 扩展名:**

你提到如果文件以 `.tq` 结尾，它将是 V8 Torque 源代码。这是正确的。`.tq` 文件用于定义 V8 的内置函数和运行时代码，使用一种名为 Torque 的领域特定语言。  `v8/test/cctest/compiler/test-branch-combine.cc`  以 `.cc` 结尾，因此它是 **C++ 源代码**，用于测试编译器的功能。

**与 JavaScript 的关系:**

`v8/test/cctest/compiler/test-branch-combine.cc` 中测试的 "分支合并" 优化直接影响 JavaScript 代码的性能。当 V8 编译 JavaScript 代码时，它会生成底层的机器码，其中包含条件分支语句来实现 `if` 语句、循环等控制流结构。  分支合并优化能够减少这些分支的数量，从而提高 JavaScript 代码的执行速度。

**JavaScript 示例:**

以下 JavaScript 代码片段可能会受益于分支合并优化：

```javascript
function testBranchCombine(x) {
  if (x === 0) {
    return 10;
  } else {
    return 20;
  }
}

console.log(testBranchCombine(0));  // 输出 10
console.log(testBranchCombine(5));  // 输出 20
```

在编译器层面，`x === 0` 的比较会产生一个条件分支。分支合并优化可能会尝试简化这个分支，例如，如果编译器能推断出 `x` 的某些属性，它可以直接生成跳转到特定代码块的指令，而无需执行实际的比较。

**代码逻辑推理 (假设输入与输出):**

以 `TEST(BranchCombineWord32EqualZero_1)` 为例：

**假设输入:**

*  `a = 0`
*  `a = 5`

**代码逻辑:**

1. `m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), &blocka, &blockb);`  创建一个分支，如果输入参数 `p0` 等于 0，则跳转到 `blocka`，否则跳转到 `blockb`。
2. `blocka` 返回常量 `-1033`。
3. `blockb` 返回常量 `825118`。

**预期输出:**

*   当输入 `a = 0` 时，`p0` 等于 0，分支跳转到 `blocka`，函数返回 `-1033`。
*   当输入 `a = 5` 时，`p0` 不等于 0，分支跳转到 `blockb`，函数返回 `825118`。

**涉及用户常见的编程错误:**

虽然这个测试文件主要是关于编译器优化的，但它间接涉及了一些用户可能犯的编程错误，这些错误可能会导致代码效率低下，而分支合并优化可以帮助缓解这些问题。

**例子 1：不必要的条件判断**

```javascript
function unnecessaryCondition(x) {
  if (true) { // 这里的条件始终为真
    return x + 1;
  } else {
    return x - 1; // 这部分代码永远不会执行
  }
}
```

虽然分支合并不能完全消除这种错误（因为它更多是逻辑错误），但它可以优化掉始终不会执行的分支，提高性能。

**例子 2：重复的条件判断**

```javascript
function redundantCondition(x) {
  if (x > 0) {
    // ... 一些操作
    if (x > 0) { // 相同的条件再次判断
      return x * 2;
    }
  }
  return 0;
}
```

分支合并优化可能会识别出第二个 `if (x > 0)` 是冗余的，因为它已经在外部的 `if` 语句中判断过了。

**总结:**

`v8/test/cctest/compiler/test-branch-combine.cc` 是一个关键的测试文件，用于验证 V8 编译器中分支合并优化的正确性和有效性。它通过构建底层的机器码指令序列来模拟各种分支场景，并确保编译器能够正确地进行优化，从而最终提高 JavaScript 代码的执行性能。它也间接关联到用户可能犯的一些导致代码效率低下的编程错误。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-branch-combine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-branch-combine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/overflowing-math.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace compiler {

static IrOpcode::Value int32cmp_opcodes[] = {
    IrOpcode::kWord32Equal, IrOpcode::kInt32LessThan,
    IrOpcode::kInt32LessThanOrEqual, IrOpcode::kUint32LessThan,
    IrOpcode::kUint32LessThanOrEqual};


TEST(BranchCombineWord32EqualZero_1) {
  // Test combining a branch with x == 0
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  int32_t eq_constant = -1033;
  int32_t ne_constant = 825118;
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
    Node* p0 = m.Parameter(0);
    RawMachineLabel blocka, blockb;
    Node* cond = p0;
    for (int j = 0; j < k; j++) {
      cond = m.Word32Equal(cond, m.Int32Constant(0));
    }
    m.Branch(cond, &blocka, &blockb);
    m.Bind(&blocka);
    m.Return(m.Int32Constant(eq_constant));
    m.Bind(&blockb);
    m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Int32LessThan(p0, m.Int32Constant(0)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Uint32LessThan(p0, m.Int32Constant(100)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Uint32LessThanOrEqual(p0, m.Int32Constant(100)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Int32LessThan(m.Int32Constant(0), p0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Int32GreaterThan(p0, m.Int32Constant(0)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);

  RawMachineLabel blocka, blockb;
  m.Branch(m.Word32Equal(p0, p1), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(eq_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(ne_constant));

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

      Node* p0 = m.Int32Constant(a);
      Node* p1 = m.Parameter(0);

      RawMachineLabel blocka, blockb;
      if (left == 1) m.Branch(m.Word32Equal(p0, p1), &blocka, &blockb);
      if (left == 0) m.Branch(m.Word32Equal(p1, p0), &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(eq_constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(ne_constant));

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
    Node* p0 = m.Parameter(0);
    Node* p1 = m.Parameter(1);

    RawMachineLabel blocka, blockb;
    if (op == 0) m.Branch(m.Int32LessThan(p0, p1), &blocka, &blockb);
    if (op == 1) m.Branch(m.Int32LessThanOrEqual(p0, p1), &blocka, &blockb);
    m.Bind(&blocka);
    m.Return(m.Int32Constant(eq_constant));
    m.Bind(&blockb);
    m.Return(m.Int32Constant(ne_constant));

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
      Node* p0 = m.Int32Constant(a);
      Node* p1 = m.Parameter(0);

      RawMachineLabel blocka, blockb;
      if (op == 0) m.Branch(m.Int32LessThan(p0, p1), &blocka, &blockb);
      if (op == 1) m.Branch(m.Int32LessThanOrEqual(p0, p1), &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(eq_constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(ne_constant));

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

  CmpMaterializeBoolGen(IrOpcode::Value opcode, bool i)
      : w(opcode), invert(i) {}

  void gen(RawMachineAssemblerTester<int32_t>* m, Node* a, Node* b) override {
    Node* cond = w.MakeNode(m, a, b);
    if (invert) cond = m->Word32Equal(cond, m->Int32Constant(0));
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

  CmpBranchGen(IrOpcode::Value opcode, bool i, bool t, int32_t eq, int32_t ne)
      : w(opcode), invert(i), true_first(t), eq_constant(eq), ne_constant(ne) {}

  void gen(RawMachineAssemblerTester<int32_t>* m, Node* a, Node* b) override {
    RawMachineLabel blocka, blockb;
    Node* cond = w.MakeNode(m, a, b);
    if (invert) cond = m->Word32Equal(cond, m->Int32Constant(0));
    m->Branch(cond, &blocka, &blockb);
    if (true_first) {
      m->Bind(&blocka);
      m->Return(m->Int32Constant(eq_constant));
      m->Bind(&blockb);
      m->Return(m->Int32Constant(ne_constant));
    } else {
      m->Bind(&blockb);
      m->Return(m->Int32Constant(ne_constant));
      m->Bind(&blocka);
      m->Return(m->Int32Constant(eq_constant));
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

  CompareWrapper cmps[] = {CompareWrapper(IrOpcode::kFloat64Equal),
                           CompareWrapper(IrOpcode::kFloat64LessThan),
                           CompareWrapper(IrOpcode::kFloat64LessThanOrEqual)};

  for (size_t c = 0; c < arraysize(cmps); c++) {
    CompareWrapper cmp = cmps[c];
    for (int invert = 0; invert < 2; invert++) {
      RawMachineAssemblerTester<int32_t> m;
      Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
      Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());

      RawMachineLabel blocka, blockb;
      Node* cond = cmp.MakeNode(&m, a, b);
      if (invert) cond = m.Word32Equal(cond, m.Int32Constant(0));
      m.Branch(cond, &blocka, &blockb);
      m.Bind(&blocka);
      m.Return(m.Int32Constant(eq_constant));
      m.Bind(&blockb);
      m.Return(m.Int32Constant(ne_constant));

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
  Node* a = m.LoadFromPointer(&input, MachineType::Int32());
  Node* compare = m.Word32And(a, m.Int32Constant(1));
  Node* equal = m.Word32Equal(compare, m.Int32Constant(0));
  m.StoreToPointer(&input, MachineRepresentation::kWord32, m.Int32Constant(1));

  RawMachineLabel blocka, blockb;
  m.Branch(equal, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(42));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(0));

  CHECK_EQ(42, m.Call());
}

TEST(BranchCombineInt32AddLessThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Int32LessThan(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (base::AddWithWraparound(a, b) < 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineInt32AddGreaterThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Int32GreaterThanOrEqual(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Int32GreaterThan(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Int32LessThanOrEqual(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect =
          (0 <= base::AddWithWraparound(a, b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32AddLessThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Uint32LessThanOrEqual(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (a + b <= 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineUint32AddGreaterThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32(),
                                       MachineType::Uint32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Uint32GreaterThan(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Uint32GreaterThanOrEqual(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Int32Add(p0, p1);
  Node* compare = m.Uint32LessThan(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 < a + b) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32AndLessThanZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Int32LessThan(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_INT32_INPUTS(a) {
    FOR_INT32_INPUTS(b) {
      int32_t expect = ((a & b) < 0) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

TEST(BranchCombineWord32AndGreaterThanOrEqualZero) {
  int32_t t_constant = -1033;
  int32_t f_constant = 825118;

  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Int32GreaterThanOrEqual(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Int32GreaterThan(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Int32LessThanOrEqual(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Uint32LessThanOrEqual(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Uint32GreaterThan(add, m.Int32Constant(0));

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Uint32GreaterThanOrEqual(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

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
  Node* p0 = m.Parameter(0);
  Node* p1 = m.Parameter(1);
  Node* add = m.Word32And(p0, p1);
  Node* compare = m.Uint32LessThan(m.Int32Constant(0), add);

  RawMachineLabel blocka, blockb;
  m.Branch(compare, &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(t_constant));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(f_constant));

  FOR_UINT32_INPUTS(a) {
    FOR_UINT32_INPUTS(b) {
      int32_t expect = (0 < (a & b)) ? t_constant : f_constant;
      CHECK_EQ(expect, m.Call(a, b));
    }
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```