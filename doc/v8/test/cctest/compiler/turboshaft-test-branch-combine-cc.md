Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Context:** The filename `v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` immediately tells us this is a test file within the V8 JavaScript engine, specifically for the Turboshaft compiler's branch combining optimization. The `.cc` extension confirms it's C++ code.

2. **High-Level Goal:** The core purpose of this file is to test the "branch combining" optimization in Turboshaft. This means it's verifying that the compiler can intelligently simplify or merge conditional branches in the generated machine code.

3. **Identify Key Components:** Scan the code for structural elements:
    * `#include` directives: These indicate dependencies and the general area of V8 the code interacts with (base utilities, objects, testing frameworks, and Turboshaft itself).
    * `namespace`: The `v8::internal::compiler::turboshaft` namespace clearly pinpoints the code's location within V8's architecture.
    * `static TurboshaftComparison int32cmp_opcodes[]`: This array lists different comparison operators used in the tests, giving a clue about the kinds of branch conditions being tested.
    * `TEST(...)` macros:  These are the core test cases. Each `TEST` block focuses on a specific aspect of branch combining.
    * `RawMachineAssemblerTester`: This class is used to build and execute small code snippets within the tests. It's crucial for simulating the code the compiler would generate.
    * `Block`:  Represents basic blocks in the control flow graph, used for constructing branches.
    * `m.Branch(...)`: The central operation being tested – creating conditional branches.
    * `m.Return(...)`: Used to define the outcome of different branches.
    * `FOR_INT32_INPUTS`, `FOR_UINT32_INPUTS`: Macros for iterating through different input values to thoroughly test the branch combining logic.
    * Helper classes (`CmpMaterializeBoolGen`, `CmpBranchGen`): These encapsulate common test patterns, making the code more organized and reusable.

4. **Analyze Individual Test Cases (Iterative Process):**  Pick a few representative test cases and dissect them:
    * **`TEST(BranchCombineWord32EqualZero_1)`:**
        * **Goal:** Test combining a branch with the condition `x == 0`.
        * **Mechanism:**  It sets up a branch that goes to `blocka` if the input `p0` is 0, and `blockb` otherwise. Each block returns a different constant.
        * **Verification:** The `FOR_INT32_INPUTS` loop iterates through various integer inputs. For each input, it calculates the expected return value based on the condition `a == 0` and compares it to the actual result of executing the generated code.
    * **`TEST(BranchCombineWord32EqualZero_chain)`:**
        * **Goal:** Tests combining a chain of `x == 0 == 0 ...` comparisons. This verifies that the compiler handles nested or chained equality checks correctly.
        * **Mechanism:** The outer loop controls the length of the chain. The inner loop builds the chain of `Word32Equal` operations. The expected result logic considers the parity of the chain length because each `== 0` effectively inverts the boolean outcome.
    * **`TEST(BranchCombineInt32LessThanZero_1)`:**
        * **Goal:** Tests combining a branch with the condition `x < 0`. Similar structure to the equality test.
    * **`TEST(BranchCombineUint32LessThan100_1)`:**
        * **Goal:** Tests combining a branch with an unsigned less-than comparison against a constant. Highlights handling of unsigned types.
    * **`TEST(BranchCombineEffectLevel)`:**
        * **Goal:** Tests a scenario where branch combining *shouldn't* happen due to a side effect (the store operation) between the load and the branch. This is a crucial negative test.

5. **Identify Common Patterns:**  Notice the recurring structure in many test cases:
    * Set up a `RawMachineAssemblerTester`.
    * Define input parameters.
    * Create `Block` objects for the branch targets.
    * Use `m.Branch()` with a comparison operation.
    * Bind the blocks and define the return values for each branch.
    * Use `FOR_..._INPUTS` to iterate through test data.
    * Calculate the expected result and use `CHECK_EQ` for verification.

6. **Connect to Compiler Optimization:**  Realize that the tests are specifically designed to trigger the "branch combining" optimization. The compiler should be able to look at the comparison condition and the branching structure and potentially simplify the generated code. For instance, multiple identical comparisons might be optimized into a single check.

7. **Consider JavaScript Relevance:** The code operates on low-level concepts like `Word32`, `Int32`, `Uint32`, and machine instructions. While not directly writing JavaScript, this code *directly tests the correctness of the compiler that translates JavaScript into machine code*. Think about JavaScript scenarios that would lead to these kinds of comparisons (e.g., `if (x == 0)`, `if (y < 100)`, etc.).

8. **Infer Code Logic and Examples:** Based on the test structures and the comparison operators, infer the logic being tested. For example:
    * `m.Word32Equal(p0, m.Word32Constant(0))` corresponds to `x === 0` in JavaScript.
    * `m.Int32LessThan(p0, m.Word32Constant(0))` corresponds to `x < 0` in JavaScript.
    * The test with chained `Word32Equal` relates to something like `if (x == 0 && x == 0)`.

9. **Identify Potential Programming Errors:** Consider how the tested scenarios relate to common mistakes:
    * Incorrectly comparing signed and unsigned integers.
    * Failing to account for the order of operations or side effects when combining conditions.
    * Off-by-one errors in comparisons (e.g., using `<` instead of `<=`).
    * Confusion between equality (`==` or `===`) and assignment (`=`).

10. **Structure the Answer:** Organize the findings into logical sections (functionality, relation to Torque, JavaScript examples, code logic, programming errors). Use clear and concise language. Provide concrete examples to illustrate the points.

By following these steps, you can effectively analyze and understand the purpose and workings of the given C++ test code. The key is to combine code-level inspection with an understanding of the underlying concepts of compiler optimization and the relationship to the JavaScript language.
This C++ code snippet is a test file for the Turboshaft compiler in the V8 JavaScript engine. Specifically, it focuses on testing the "branch combining" optimization.

Here's a breakdown of its functionality:

**Core Functionality: Testing Branch Combining**

The primary goal of this code is to verify that the Turboshaft compiler correctly optimizes conditional branches. Branch combining is a compiler optimization technique that aims to simplify or eliminate redundant or related conditional branches in the generated machine code. This can lead to more efficient execution.

**How it Works:**

1. **Uses `RawMachineAssemblerTester`:** The code utilizes the `RawMachineAssemblerTester` class to construct small, isolated code snippets at a low level, mimicking the kind of code the Turboshaft compiler might generate. This allows for fine-grained control over the structure of the control flow graph.

2. **Creates Basic Blocks and Branches:** It defines basic blocks (`Block`) and uses the `m.Branch()` instruction to create conditional jumps based on various comparison operations.

3. **Tests Different Comparison Scenarios:** The code includes numerous test cases (`TEST(...)`) that cover different scenarios for branch combining, including:
   - Comparing an integer to zero (equality, less than).
   - Comparing unsigned integers to constants.
   - Comparing two variables.
   - Using the results of other operations (like addition, bitwise AND) in branch conditions.
   - Testing floating-point comparisons.

4. **Sets Expected Outcomes:** Each branch in the test cases leads to a different return value (e.g., `eq_constant` for the "true" branch, `ne_constant` for the "false" branch).

5. **Iterates Through Inputs:** The `FOR_INT32_INPUTS` and `FOR_UINT32_INPUTS` macros are used to systematically test the generated code with a range of different input values.

6. **Asserts Correctness:** The `CHECK_EQ` macro verifies that the actual return value of the generated code matches the expected return value based on the input and the branch condition.

**Regarding `.tq` files:**

The prompt correctly states that if a file ends with `.tq`, it's a V8 Torque source file. However, `v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` ends with `.cc`, indicating it is a **C++** source file. Therefore, it is **not** a Torque file.

**Relationship to JavaScript and Examples:**

While this code is C++ and deals with low-level compiler details, it directly tests the optimization of code generated from JavaScript. Here are some JavaScript examples that would lead to the kinds of branch conditions tested in this file:

* **`TEST(BranchCombineWord32EqualZero_1)`:**
   ```javascript
   function test(x) {
     if (x === 0) {
       return -1033;
     } else {
       return 825118;
     }
   }
   ```

* **`TEST(BranchCombineInt32LessThanZero_1)`:**
   ```javascript
   function test(x) {
     if (x < 0) {
       return -1433;
     } else {
       return 845118;
     }
   }
   ```

* **`TEST(BranchCombineUint32LessThan100_1)`:**
   ```javascript
   function test(x) {
     if (x < 100) { // Assuming x is treated as an unsigned integer in this context
       return 1471;
     } else {
       return 88845718;
     }
   }
   ```

* **`TEST(BranchCombineWord32AddLessThanZero)`:**
   ```javascript
   function test(a, b) {
     if (a + b < 0) {
       return -1033;
     } else {
       return 825118;
     }
   }
   ```

**Code Logic Inference (Example):**

Let's take the `TEST(BranchCombineWord32EqualZero_1)` as an example:

**Assumptions:**

* The Turboshaft compiler performs branch combining.
* The `RawMachineAssemblerTester` accurately simulates code generation.

**Input:** An integer value passed as the first parameter to the generated code.

**Logic:**

1. A comparison `p0 == 0` is performed.
2. If the comparison is true, the code branches to `blocka` and returns `eq_constant` (-1033).
3. If the comparison is false, the code branches to `blockb` and returns `ne_constant` (825118).

**Example Input and Output:**

* **Input:** `a = 0`
   * **Expected Output:** `eq_constant` (-1033) because the condition `0 == 0` is true.
* **Input:** `a = 5`
   * **Expected Output:** `ne_constant` (825118) because the condition `5 == 0` is false.
* **Input:** `a = -3`
   * **Expected Output:** `ne_constant` (825118) because the condition `-3 == 0` is false.

**User-Common Programming Errors:**

This test file implicitly helps detect errors related to how branch conditions are handled in the compiler. Here are some user-level programming errors that might expose issues in the branch combining optimization (and thus be tested by this file):

1. **Incorrectly assuming boolean logic:**
   ```javascript
   function test(x) {
     if (x == 0 == 0) { // Intent might be to check if x is 0
       return -1133;
     } else {
       return 815118;
     }
   }
   ```
   In JavaScript, `x == 0 == 0` is evaluated from left to right. `x == 0` will be a boolean, and then that boolean will be compared to `0`. This is likely not the intended behavior. The `BranchCombineWord32EqualZero_chain` test explores how the compiler handles chains of equality, which can be related to this kind of error, although the test constructs the chain explicitly for testing purposes.

2. **Off-by-one errors in comparisons:**
   ```javascript
   function test(x) {
     if (x < 100) {
       // ...
     } else if (x = 100) { // Intent was likely x === 100, but used assignment
       // ...
     }
   }
   ```
   While not directly testing user code, the tests with `<` and `<=` (`BranchCombineUint32LessThan100_1`, `BranchCombineUint32LessThanOrEqual100_1`) ensure the compiler correctly handles these different comparison operators, which are often sources of errors for programmers.

3. **Mixing signed and unsigned comparisons:**  While JavaScript doesn't have explicit unsigned integers, the underlying compiler needs to handle them correctly. Tests like `BranchCombineUint32LessThan100_1` verify that unsigned comparisons are optimized correctly. A user error might involve implicitly treating a signed value as unsigned, or vice-versa, leading to unexpected results.

4. **Forgetting about side effects in conditions:** The `TEST(BranchCombineEffectLevel)` is a specific example of this. If a user writes code where a variable is modified within a conditional expression that's being optimized, the compiler needs to be careful not to reorder or eliminate operations in a way that changes the program's behavior.

In summary, `v8/test/cctest/compiler/turboshaft-test-branch-combine.cc` is a crucial part of ensuring the correctness and efficiency of V8's Turboshaft compiler by rigorously testing its branch combining optimization across a wide range of scenarios. While not directly writing JavaScript, understanding its purpose helps to understand how JavaScript code is optimized at a lower level.

### 提示词
```
这是目录为v8/test/cctest/compiler/turboshaft-test-branch-combine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/turboshaft-test-branch-combine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```