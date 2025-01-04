Response: Let's break down the thought process for analyzing the C++ code and relating it to JavaScript.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the C++ code and then illustrate its relevance to JavaScript with examples. The filename "test-branch-combine.cc" and the presence of "TEST" macros immediately suggest this is a testing file within the V8 JavaScript engine. The "branch combine" part hints at optimizations related to conditional branching in the compiled code.

**2. Deconstructing the C++ Code (High-Level):**

* **Headers:**  The `#include` directives give us clues about the context. `src/base/overflowing-math.h` and `src/objects/objects-inl.h` point towards the core V8 implementation. `test/cctest/cctest.h` and `test/cctest/compiler/codegen-tester.h` confirm it's a compiler testing file.
* **Namespaces:** The code is within `v8::internal::compiler`, indicating it's specifically testing the compiler component of V8.
* **`static IrOpcode::Value int32cmp_opcodes[]`:** This array lists different integer comparison operations (equal, less than, less than or equal, etc.). This suggests the tests will focus on these comparisons.
* **`TEST(...)` Macros:**  These are the core test cases. Each `TEST` represents a specific scenario being tested.
* **`RawMachineAssemblerTester`:** This class is used to construct sequences of low-level machine instructions (or an abstraction of them). It's a way to directly control what the compiler sees and test its behavior on specific instruction patterns.
* **`Node*`:** The code manipulates `Node` objects. These represent operations or values in the intermediate representation (IR) of the code within the compiler. Think of them as building blocks of the compiler's internal representation.
* **`m.Parameter(0)`, `m.Int32Constant(0)`, `m.Word32Equal(p0, ...)`:** These are methods of the `RawMachineAssemblerTester` that create nodes representing parameters, constants, and specific machine instructions (like comparing two 32-bit words for equality).
* **`RawMachineLabel blocka, blockb; m.Branch(..., &blocka, &blockb);`:**  This constructs a conditional branch. If the condition is true, execution jumps to `blocka`; otherwise, it jumps to `blockb`.
* **`m.Bind(&blocka); m.Return(...)`:**  These define the target labels for the branch and specify the return value in each branch.
* **`FOR_INT32_INPUTS(a)`, `FOR_UINT32_INPUTS(a)`:** These macros iterate through various integer values to test the generated code with different inputs.
* **`CHECK_EQ(expect, m.Call(a))`:** This asserts that the actual output of the generated code (`m.Call(a)`) matches the expected output.

**3. Identifying the Core Functionality (Branch Combining):**

The names of the tests (e.g., `BranchCombineWord32EqualZero_1`, `BranchCombineInt32LessThanZero_1`) clearly point to the functionality being tested: "branch combining."  By examining the structure of the tests, we can infer what this means:

* **Simplifying Conditional Branches:** The tests construct a branch based on a comparison (e.g., `x == 0`, `x < 0`). The goal of "branch combining" is to optimize these branches. Instead of performing the comparison and then branching, the compiler might be able to directly determine the outcome of the branch in certain cases.

**4. Connecting to JavaScript (Conceptual):**

The C++ code tests a *compiler optimization*. This optimization occurs when V8 *compiles* JavaScript code into lower-level machine code. Therefore, the connection to JavaScript lies in how JavaScript code *triggers* these optimizations. Specifically, conditional statements (`if`, `else if`, `else`) and comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`) are the JavaScript constructs that lead to the creation of conditional branches in the compiled code.

**5. Generating JavaScript Examples:**

Now we need to create concrete JavaScript examples that correspond to the C++ tests. The strategy is to:

* **Look at the comparison in the C++ test.**  For example, `m.Word32Equal(p0, m.Int32Constant(0))` translates to `x == 0`.
* **Construct a simple JavaScript `if`/`else` statement using that comparison.**
* **Make the return values of the `if`/`else` match the constants in the C++ test.** This helps to directly illustrate the compiler optimization.

**Example Construction (Following the above steps for `BranchCombineWord32EqualZero_1`):**

1. **C++ Comparison:** `m.Word32Equal(p0, m.Int32Constant(0))`  (Checks if input `p0` is equal to 0).
2. **JavaScript Equivalent:** `x == 0`
3. **JavaScript `if`/`else`:**
   ```javascript
   function test(x) {
     if (x == 0) {
       return -1033; // Matches eq_constant in C++
     } else {
       return 825118; // Matches ne_constant in C++
     }
   }
   ```

**6. Refining the JavaScript Explanation:**

Once the examples are generated, the explanation needs to clarify:

* **What "branch combining" is:**  Explain that it's an optimization that simplifies conditional jumps.
* **How the JavaScript relates:**  Emphasize that the JavaScript code *results in* the kind of branching that the C++ test is verifying the optimization for.
* **Why the C++ tests are needed:** Explain that these tests ensure the V8 compiler correctly performs these optimizations across various scenarios.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "The C++ code *is* JavaScript functionality."  **Correction:** The C++ code *tests* the *compiled output* of JavaScript functionality. It's about the underlying engine, not the language itself.
* **Potential confusion:** "Why are there `RawMachineAssemblerTester` and `Node*`?" **Clarification:** These are internal V8 compiler concepts used for testing the compiler at a low level. The JavaScript user doesn't interact with these directly.
* **Ensuring Clarity of Examples:** The JavaScript examples should be as simple and direct as possible to clearly illustrate the corresponding C++ test case. Avoid adding unnecessary complexity.

By following these steps, we can systematically analyze the C++ code, understand its purpose within the V8 project, and then effectively explain its relevance to JavaScript developers using clear and illustrative examples.
这个C++源代码文件 `test-branch-combine.cc` 的功能是**测试V8 JavaScript引擎中编译器的一个优化功能，叫做“分支合并”（Branch Combining）**。

**具体来说，它测试了编译器在遇到条件分支语句时，如何将某些比较操作与分支指令结合起来，从而简化生成的机器码，提高执行效率。**

这个文件通过编写一系列的测试用例，来验证编译器是否能够正确地识别和优化各种不同形式的条件分支，包括：

* **与零的比较：**  例如 `x == 0`, `x < 0`, `0 < x` 等。
* **与其他常量的比较：** 例如 `x < 100`, `x <= 100` 等。
* **两个变量之间的比较：** 例如 `x == y`, `x < y` 等。
* **浮点数比较：** 例如 `float_a == float_b`, `float_a < float_b` 等。
* **涉及算术运算的比较：** 例如 `x + y < 0`, `(x & y) >= 0` 等。

**每个测试用例都做了以下事情：**

1. **使用 `RawMachineAssemblerTester` 创建一个简单的代码片段。**  这个类允许以接近机器指令的级别构造代码，用于测试编译器的特定行为。
2. **定义输入参数和预期输出值。**
3. **构造包含条件分支的代码。** 例如，使用 `m.Branch(condition, &blocka, &blockb)` 创建一个基于 `condition` 跳转到 `blocka` 或 `blockb` 的分支。
4. **在不同的分支中返回不同的常量值。** 这使得我们可以通过观察最终的返回值来判断代码是否按照预期的方式执行了分支。
5. **使用 `FOR_INT32_INPUTS` 或 `FOR_UINT32_INPUTS` 等宏遍历各种可能的输入值。**
6. **调用生成的代码并使用 `CHECK_EQ` 断言实际的返回值与预期值是否一致。**

**与JavaScript的功能的关系以及示例：**

分支合并是一种底层的编译器优化，它发生在JavaScript代码被V8引擎编译成机器码的过程中。虽然JavaScript开发者不会直接编写像 `m.Word32Equal` 这样的代码，但他们在编写JavaScript的条件语句时，会触发编译器进行分支合并的优化。

**JavaScript 示例：**

假设我们有以下 JavaScript 代码：

```javascript
function testBranchCombine(x) {
  if (x === 0) {
    return -1033;
  } else {
    return 825118;
  }
}

console.log(testBranchCombine(0));    // 输出: -1033
console.log(testBranchCombine(5));    // 输出: 825118
```

当 V8 引擎编译这段 JavaScript 代码时，它会生成类似于 `TEST(BranchCombineWord32EqualZero_1)` 中测试的机器码结构。  **分支合并优化可能会将 `x === 0` 的比较直接融入到分支指令中，而不是先进行比较再根据比较结果跳转。**

**更具体地说，`TEST(BranchCombineWord32EqualZero_1)` 测试的就是 V8 编译器是否能够优化像上面这个 JavaScript 例子中的 `if (x === 0)` 这样的比较。**

再例如，`TEST(BranchCombineInt32LessThanZero_1)` 测试的是形如 `if (x < 0)` 的优化：

```javascript
function testLessThanZero(x) {
  if (x < 0) {
    return -1433;
  } else {
    return 845118;
  }
}

console.log(testLessThanZero(-1));   // 输出: -1433
console.log(testLessThanZero(1));    // 输出: 845118
```

`TEST(BranchCombineInt32AddLessThanZero)` 测试的是涉及算术运算的比较，对应如下 JavaScript 代码：

```javascript
function testAddLessThanZero(a, b) {
  if (a + b < 0) {
    return -1033;
  } else {
    return 825118;
  }
}

console.log(testAddLessThanZero(-5, 2));  // 输出: -1033
console.log(testAddLessThanZero(5, 2));   // 输出: 825118
```

**总结：**

`test-branch-combine.cc` 这个文件是 V8 引擎的测试代码，它专门用来验证编译器是否能够正确地进行分支合并优化。这种优化能够提高 JavaScript 代码的执行效率，因为它减少了执行的指令数量，使得条件分支更加高效。虽然 JavaScript 开发者不会直接接触到这些底层的编译器细节，但他们编写的条件语句（`if`, `else if`, `else`）正是这些优化的目标。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-branch-combine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```