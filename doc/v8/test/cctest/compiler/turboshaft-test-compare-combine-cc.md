Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `turboshaft-test-compare-combine.cc` and the content (especially the function names like `CombineCompareLogic1`, `CombineCompareLogic2`, etc.) immediately suggest this file tests the "combine" operation of comparisons within the Turboshaft compiler pipeline. The presence of `TurboshaftBinop` and `TurboshaftComparison` enums confirms this.

2. **Understand the Setup:** The file includes various headers related to V8 internals (`objects-inl.h`, `cctest.h`, `turboshaft-codegen-tester.h`). This indicates it's part of V8's internal testing framework. The `namespace v8::internal::compiler::turboshaft` clarifies the specific area being tested.

3. **Analyze Key Data Structures:**
    * `kLogicOpcodes`: Defines the logical operations being tested (bitwise AND and OR).
    * `kInt32CmpOpcodes`, `kInt64CmpOpcodes`: Lists the integer comparison operations. The `#if V8_TARGET_ARCH_64_BIT` shows architecture-specific testing.
    * `GraphShape`:  Indicates different ways the comparisons and logic can be structured (balanced vs. unbalanced). The ASCII diagrams are crucial for understanding this.
    * `InvertPattern`: Shows different ways the results of comparisons and logic operations can be inverted (negated).
    * `BranchPattern`: Defines how the final combined result is used in a control flow context (direct branch, branch on zero, etc.).
    * `uint32_test_array`, `uint64_test_array`:  These are the input values used for testing. The `base::VectorOf` wraps them.

4. **Deconstruct the `CombineCompares` Template:**  This is the heart of the test structure.
    * **Purpose:**  It's a template class responsible for generating the Turboshaft IR (Intermediate Representation) for different combinations of comparisons and logical operations.
    * **Key Members:**
        * `m_`:  A `RawMachineAssemblerTester` instance for building the IR.
        * `graph_shape_`, `invert_pattern_`, `branch_pattern_`: Control the test scenario.
        * `logic_ops_`, `compare_ops_`: The specific operations to be combined.
        * `BuildGraph()`: The core method that constructs the IR based on the configuration. The ASCII diagrams are directly implemented here.
        * `ExpectedReturn()`: Calculates the expected result of the combined operations.
        * `Expected()`:  Evaluates the comparisons and logic in a step-by-step manner (simulating the Turboshaft execution) to determine the expected outcome.
        * `MakeBinop()`, `MakeCompare()`, `MakeNot*()`: Helper functions to create the corresponding Turboshaft IR nodes.
        * `EvalCompare()`: A virtual method that needs to be implemented by derived classes to perform the actual comparison.
    * **Template Parameters:** `NumLogic` (number of logical operations) and `CompareType` (the type being compared).

5. **Analyze the Derived Classes:** `CombineCompareWord32` and `CombineCompareWord64` specialize `CombineCompares` for 32-bit and 64-bit integers, respectively. They provide the concrete implementation for `EvalCompare()` and the constant values (Zero, One, ThirtyTwo).

6. **Examine the Test Functions (e.g., `CombineCompareLogic1`, `CombineCompareLogic2`):**
    * **Purpose:** These functions set up specific test scenarios by iterating through combinations of comparison operations, logical operations, invert patterns, and branch patterns.
    * **Key Actions:**
        * They create a `RawMachineAssemblerTester`.
        * They instantiate the appropriate `CombineCompareWord32` or `CombineCompareWord64` object.
        * They call `BuildGraph()` to generate the IR.
        * They iterate through the `input_vector` to provide test inputs.
        * They call `gen.Expected()` to get the expected result.
        * They call `m.Call()` to execute the generated Turboshaft code.
        * They use `CHECK_EQ()` to assert that the actual result matches the expected result.

7. **Connect to JavaScript (if applicable):** While this C++ code *tests* the compiler, the comparisons and logical operations it's exercising directly correspond to JavaScript's comparison and bitwise operators. The JavaScript examples in the generated answer illustrate this connection.

8. **Identify Potential Programming Errors:** The code implicitly tests for correctness when combining comparisons and logical operations. A common programming error is incorrect operator precedence or misunderstanding the behavior of bitwise vs. logical operators. The example provided in the generated answer highlights this.

9. **Summarize the Functionality:**  Based on the analysis, synthesize a concise summary of the file's purpose, which is to test the Turboshaft compiler's ability to correctly combine and optimize sequences of comparison and logical operations.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This looks like a standard C++ unit test."  **Correction:**  Realize it's testing a *compiler*, so the "unit" is a piece of compiler functionality (combining comparisons), and it involves generating and executing intermediate code.
* **Confusion with graph shapes:** Initially, the purpose of "balanced" vs. "unbalanced" might not be immediately clear. **Clarification:** The ASCII diagrams are essential for understanding how the comparisons and logic are structured in these two cases, impacting the order of operations.
* **Understanding `InvertPattern`:** Recognizing that this is about testing the handling of negations at different stages (comparison result, logic result, or both) is important.
* **Connecting to JavaScript:** Actively thinking about the JavaScript equivalents of the C++ operations helps contextualize the testing.

By following these steps and paying close attention to the code structure, data structures, and test logic, a comprehensive understanding of the file's functionality can be achieved.
好的，我们来分析一下 `v8/test/cctest/compiler/turboshaft-test-compare-combine.cc` 这个文件的功能。

**功能归纳:**

这个 C++ 文件是 V8 JavaScript 引擎中 Turboshaft 编译器的一个测试文件。它的主要功能是测试 Turboshaft 编译器在处理和组合多个比较操作以及逻辑操作时的正确性。具体来说，它测试了以下几个方面：

1. **组合比较操作:**  测试 Turboshaft 能否正确地将多个比较操作（例如等于、小于、大于等）组合在一起。
2. **组合逻辑操作:** 测试 Turboshaft 能否正确地将多个逻辑操作（例如与、或）组合在一起，并将它们与比较操作的结果进行组合。
3. **不同的图结构 (GraphShape):** 测试在不同的计算图结构下（平衡和非平衡），组合操作是否仍然正确。这涉及到编译器如何安排指令的执行顺序。
4. **反转模式 (InvertPattern):** 测试在不同的反转模式下，例如反转比较结果、反转逻辑结果，组合操作是否仍然正确。这涉及到编译器如何处理逻辑非运算。
5. **分支模式 (BranchPattern):** 测试当组合操作的结果被用于控制流分支时（例如 if 语句），Turboshaft 是否能正确处理。
6. **不同的数据类型:**  测试针对 32 位和 64 位整数的比较和逻辑操作组合。
7. **常量输入:**  测试当比较操作的输入包含常量时，组合操作是否正确。

**关于文件扩展名 `.tq`:**

你提到的 `.tq` 结尾的文件通常是 V8 的 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。  `v8/test/cctest/compiler/turboshaft-test-compare-combine.cc`  是以 `.cc` 结尾的 C++ 文件，因此它不是 Torque 源代码。它是直接使用 C++ 编写的测试代码，用于测试 Turboshaft 编译器生成的代码。

**与 JavaScript 功能的关系:**

这个测试文件直接关系到 JavaScript 中的比较运算符和逻辑运算符。  JavaScript 引擎需要正确地编译和执行这些操作。

**JavaScript 示例:**

```javascript
function test(a, b, c, d) {
  // 多个比较操作和逻辑操作的组合
  const condition1 = a < b && c > d;
  const condition2 = a === b || c !== d;
  const combinedCondition = (a < b && c > d) || (a === b || c !== d);

  // 使用组合条件进行分支
  if (combinedCondition) {
    return 1;
  } else {
    return 0;
  }
}

console.log(test(1, 2, 3, 4)); // 输出 0 (因为 (1 < 2 && 3 > 4) 为 false, (1 === 2 || 3 !== 4) 为 true, false || true 为 true)
console.log(test(1, 1, 3, 2)); // 输出 1 (因为 (1 < 1 && 3 > 2) 为 false, (1 === 1 || 3 !== 2) 为 true, false || true 为 true)
```

这个 JavaScript 示例展示了多个比较运算符 (`<`, `>`, `===`, `!==`) 和逻辑运算符 (`&&`, `||`) 组合在一起的情况。`v8/test/cctest/compiler/turboshaft-test-compare-combine.cc` 的目标就是测试 Turboshaft 编译器能否正确地将类似这样的 JavaScript 代码编译成高效且正确的机器码。

**代码逻辑推理 (假设输入与输出):**

我们以 `CombineCompareWord32Logic1` 测试中的一个场景为例，假设：

* **比较操作:** `TurboshaftComparison::kInt32LessThan` (小于)
* **逻辑操作:** `TurboshaftBinop::kWord32BitwiseAnd` (按位与)
* **输入:** `a = 1`, `b = 2`, `c = 3`, `d = 4`

根据代码，会进行以下比较：

1. `a < b`  (1 < 2)  结果为 `true` (在测试代码中表示为 1)
2. `c < d`  (3 < 4)  结果为 `true` (在测试代码中表示为 1)

然后进行逻辑操作：

`true AND true` (1 AND 1) 结果为 `1`

因此，假设 `branch_pattern` 为 `kNone`，则 `CombineCompareWord32Logic1`  的预期输出应该为 `1`。

如果 `branch_pattern` 为 `kDirect`，则会根据最终的组合结果进行分支：如果结果为非零（真），则返回 1，否则返回 0。在这个例子中，结果为 1，所以输出也是 1。

如果 `branch_pattern` 为 `kEqualZero`，则当组合结果为 0 时返回 1，否则返回 0。在这个例子中，结果为 1，所以输出为 0。

如果 `branch_pattern` 为 `kNotEqualZero`，则当组合结果不为 0 时返回 1，否则返回 0。在这个例子中，结果为 1，所以输出为 1。

**涉及用户常见的编程错误:**

虽然这个测试文件本身是在测试编译器，但它所覆盖的功能与用户常见的编程错误息息相关，例如：

1. **逻辑运算符优先级错误:** 用户可能不清楚 `&&` 和 `||` 的优先级，导致逻辑运算的顺序错误。例如，`a < b && c > d || e === f` 的解析顺序可能会出错。Turboshaft 需要正确处理这些情况。
2. **误用位运算符作为逻辑运算符:** 用户可能会错误地使用位运算符 (`&`, `|`) 代替逻辑运算符 (`&&`, `||`)，导致意想不到的结果。例如：

   ```javascript
   let x = 1;
   let y = 2;
   if (x & y) { // 错误地使用了位与，结果为 0，条件为假
       console.log("This won't print");
   }

   if (x && y) { // 正确地使用了逻辑与，结果为 true，条件为真
       console.log("This will print");
   }
   ```

   `v8/test/cctest/compiler/turboshaft-test-compare-combine.cc` 中包含了对 `TurboshaftBinop::kWord32BitwiseAnd` 和 `TurboshaftBinop::kWord32BitwiseOr` 的测试，这间接地确保了当用户在 JavaScript 中使用位运算符时，Turboshaft 也能正确处理。虽然测试用例侧重于编译器的组合能力，但其测试的基础是这些运算符的正确语义。

3. **布尔值的隐式转换理解不足:** 用户可能不清楚 JavaScript 中各种类型的值在布尔上下文中如何被隐式转换为 `true` 或 `false`。 虽然这个测试文件不直接测试类型转换，但比较运算符的结果是布尔值，逻辑运算符处理的是布尔值，因此底层的正确性是相关的。

**第 1 部分功能归纳:**

总而言之，`v8/test/cctest/compiler/turboshaft-test-compare-combine.cc` 的第 1 部分主要定义了测试框架和基础结构，用于测试 Turboshaft 编译器在组合多个比较操作和逻辑操作时的正确性。它包含了：

* **测试配置:** 定义了不同的图结构、反转模式和分支模式。
* **测试数据:**  提供了用于测试的 32 位和 64 位整数数组。
* **核心测试类 `CombineCompares`:**  这是一个模板类，负责生成用于测试的 Turboshaft IR 代码，并计算预期结果。
* **针对 32 位和 64 位的特化类:** `CombineCompareWord32` 和 `CombineCompareWord64` 继承自 `CombineCompares`，并针对特定的数据类型进行测试。
* **具体的测试函数:** 例如 `CombineCompareWord32Logic1`，设置特定的测试场景并执行测试。

这个文件的目的是通过各种组合和配置来验证 Turboshaft 编译器在处理复杂的比较和逻辑运算组合时的正确性和鲁棒性，从而确保 V8 能够正确高效地执行相应的 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-test-compare-combine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/turboshaft-test-compare-combine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/vector.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/turboshaft-codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8::internal::compiler::turboshaft {

namespace {

constexpr TurboshaftBinop kLogicOpcodes[] = {TurboshaftBinop::kWord32BitwiseAnd,
                                             TurboshaftBinop::kWord32BitwiseOr};
constexpr std::array kInt32CmpOpcodes = {
    TurboshaftComparison::kWord32Equal, TurboshaftComparison::kInt32LessThan,
    TurboshaftComparison::kInt32LessThanOrEqual,
    TurboshaftComparison::kUint32LessThan,
    TurboshaftComparison::kUint32LessThanOrEqual};
#if V8_TARGET_ARCH_64_BIT
constexpr std::array kInt64CmpOpcodes = {
    TurboshaftComparison::kWord64Equal, TurboshaftComparison::kInt64LessThan,
    TurboshaftComparison::kInt64LessThanOrEqual,
    TurboshaftComparison::kUint64LessThan,
    TurboshaftComparison::kUint64LessThanOrEqual};
#endif

enum GraphShape { kBalanced, kUnbalanced };
enum InvertPattern {
  kNoInvert,
  kInvertCompare,
  kInvertLogic,
  kInvertCompareAndLogic,
  kInvertCompareDouble,
  kInvertLogicDouble
};
enum BranchPattern { kNone, kDirect, kEqualZero, kNotEqualZero };

constexpr GraphShape kGraphShapes[] = {kBalanced, kUnbalanced};
constexpr InvertPattern kInvertPatterns[] = {kNoInvert,
                                             kInvertCompare,
                                             kInvertLogic,
                                             kInvertCompareAndLogic,
                                             kInvertCompareDouble,
                                             kInvertLogicDouble};
constexpr BranchPattern kBranchPatterns[] = {kNone, kDirect, kEqualZero,
                                             kNotEqualZero};

// These are shorter versions of ValueHelper::uint32_vector() and
// ValueHelper::uint64_vector() (which are used by FOR_UINT32_INPUTS and
// FOR_UINT64_INPUTS).
static constexpr uint32_t uint32_test_array[] = {
    0x00000000, 0x00000001, 0xFFFFFFFF, 0x1B09788B, 0x00000005,
    0x00000008, 0x273A798E, 0x56123761, 0xFFFFFFFD, 0x001FFFFF,
    0x0007FFFF, 0x7FC00000, 0x7F876543};
static constexpr auto uint32_test_vector = base::VectorOf(uint32_test_array);
#ifdef V8_TARGET_ARCH_64_BIT
static constexpr uint64_t uint64_test_array[] = {
    0x00000000,         0x00000001,         0xFFFFFFFF,
    0x1B09788B,         0x00000008,         0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE, 0x0000000100000000, 0x1B09788B00000000,
    0x273A798E187937A3, 0xECE3AF835495A16B, 0x80000000EEEEEEEE,
    0x007FFFFFDDDDDDDD, 0x8000000000000000, 0x7FF8000000000000,
    0x7FF7654321FEDCBA};
static constexpr auto uint64_test_vector = base::VectorOf(uint64_test_array);
#endif

// Given kGraphShapes and kInvertPatterns, defined above, the graphs produced by
// the test framework, with four compares, are illustrated below. In the cases
// where we insert a branch, this takes the final logic node as the input.

// kBalanced - kNoInvert
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//           ---------> logic <--------
//

// kBalanced - kInvertCompare
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//           |                         |
//           ---------> logic <--------

// kBalanced - kInvertCompareDouble
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//           |                         |
//           ---------> logic <--------

// kBalanced - kInvertLogic
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//          not                        |
//           ---------> logic <--------

// kBalanced - kInvertLogicDouble
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//          not                        |
//           |                         |
//          not                        |
//           ---------> logic <--------

// kBalanced - kInvertCompareAndLogic
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             --> logic <--
//           |                         |
//          not                        |
//           ---------> logic <--------

// kUnbalanced - kNoInvert
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//            --------> logic <--             |
//                        |                   |
//                         -----> logic <-----

// kUnbalanced - kInvertCompare
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//            --------> logic <--             |
//                        |                   |
//                         -----> logic <-----

// kUnbalanced - kInvertCompareDouble
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//            --------> logic <--             |
//                        |                   |
//                         -----> logic <-----

// kUnbalanced - kInvertLogic
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//          not                  |            |
//            --------> logic <--             |
//                        |                   |
//                       not                  |
//                        |                   |
//                         -----> logic <-----

// kUnbalanced - kInvertLogicDouble
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//          not                  |            |
//           |                   |            |
//          not                  |            |
//            --------> logic <--             |
//                        |                   |
//                       not                  |
//                        |                   |
//                       not                  |
//                        |                   |
//                         -----> logic <-----

// kUnbalanced - kInvertCompareAndLogic
// a       b    c       d    a        b   c       d
// |       |    |       |    |        |   |       |
// |       |    |       |    |        |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-
//     |            |            |            |
//    not           |           not           |
//     |            |            |            |
//     --> logic <--             |            |
//           |                   |            |
//          not                  |            |
//            --------> logic <--             |
//                        |                   |
//                       not                  |
//                        |                   |
//                         -----> logic <-----

template <uint32_t NumLogic, typename CompareType>
class CombineCompares {
  static constexpr uint32_t NumInputs = 4;
  static constexpr uint32_t NumCompares = NumLogic + 1;
  static_assert(NumLogic > 0);

  // a       b    c       d    a        b       NumInputs = 4
  // |       |    |       |    |        |
  // |       |    |       |    |        |
  // -> cmp <-    -> cmp <-    -> cmp <-        NumCompares = 3
  //     |            |            |
  //     --> logic <--             |            ---------
  //           |                   |            NumLogic = 2
  //           ------> logic <-----             ---------

 public:
  CombineCompares(RawMachineAssemblerTester<uint32_t>& m, GraphShape shape,
                  InvertPattern invert_pattern, BranchPattern branch_pattern,
                  std::array<TurboshaftBinop, NumLogic> logic_ops,
                  std::array<TurboshaftComparison, NumCompares> compare_ops)
      : m_(m),
        graph_shape_(shape),
        invert_pattern_(invert_pattern),
        branch_pattern_(branch_pattern),
        logic_ops_(logic_ops),
        compare_ops_(compare_ops) {}

  void GenerateReturn(V<Word32> combine) {
    if (branch_pattern() == kNone) {
      m().Return(combine);
    } else {
      blocka_ = m().NewBlock();
      blockb_ = m().NewBlock();
      if (branch_pattern() == kDirect) {
        m().Branch(static_cast<V<Word32>>(combine), blocka(), blockb());
      } else if (branch_pattern() == kEqualZero) {
        m().Branch(m().Word32Equal(combine, m().Word32Constant(0)), blocka(),
                   blockb());
      } else {
        auto cond = static_cast<V<Word32>>(
            MakeNot(m().Word32Equal(combine, m().Word32Constant(0))));
        m().Branch(cond, blocka(), blockb());
      }
      m().Bind(blocka());
      m().Return(m().Word32Constant(1));
      m().Bind(blockb());
      m().Return(m().Word32Constant(0));
    }
  }

  V<Word32> MakeBinop(TurboshaftBinop op, V<Word32> lhs, V<Word32> rhs) {
    switch (op) {
      case TurboshaftBinop::kWord32BitwiseAnd:
        return m().Word32BitwiseAnd(lhs, rhs);
      case TurboshaftBinop::kWord32BitwiseOr:
        return m().Word32BitwiseOr(lhs, rhs);
      default:
        UNREACHABLE();
    }
  }

  V<Word32> MakeCompare(TurboshaftComparison op, OpIndex lhs, OpIndex rhs) {
    switch (op) {
      default:
        UNREACHABLE();
      case TurboshaftComparison::kWord32Equal:
        return m().Word32Equal(lhs, rhs);
      case TurboshaftComparison::kInt32LessThan:
        return m().Int32LessThan(lhs, rhs);
      case TurboshaftComparison::kInt32LessThanOrEqual:
        return m().Int32LessThanOrEqual(lhs, rhs);
      case TurboshaftComparison::kUint32LessThan:
        return m().Uint32LessThan(lhs, rhs);
      case TurboshaftComparison::kUint32LessThanOrEqual:
        return m().Uint32LessThanOrEqual(lhs, rhs);
      case TurboshaftComparison::kWord64Equal:
        return m().Word64Equal(lhs, rhs);
      case TurboshaftComparison::kInt64LessThan:
        return m().Int64LessThan(lhs, rhs);
      case TurboshaftComparison::kInt64LessThanOrEqual:
        return m().Int64LessThanOrEqual(lhs, rhs);
      case TurboshaftComparison::kUint64LessThan:
        return m().Uint64LessThan(lhs, rhs);
      case TurboshaftComparison::kUint64LessThanOrEqual:
        return m().Uint64LessThanOrEqual(lhs, rhs);
    }
  }

  V<Word32> MakeNot(V<Word32> node) {
    return m().Word32Equal(node, m().Word32Constant(0));
  }

  V<Word32> MakeNotCompare(V<Word32> node) {
    V<Word32> inverted = MakeNot(node);
    if (invert_pattern() == kInvertCompareDouble) {
      return MakeNot(inverted);
    } else {
      return inverted;
    }
  }

  V<Word32> MakeNotLogic(V<Word32> node) {
    V<Word32> inverted = MakeNot(node);
    if (invert_pattern() == kInvertLogicDouble) {
      return MakeNot(inverted);
    } else {
      return inverted;
    }
  }

  bool ShouldDoubleInvert() const {
    return invert_pattern() == kInvertLogicDouble ||
           invert_pattern() == kInvertCompareDouble;
  }

  bool ShouldInvertLogic() const {
    return invert_pattern() == kInvertLogic ||
           invert_pattern() == kInvertCompareAndLogic ||
           invert_pattern() == kInvertLogicDouble;
  }

  bool ShouldInvertCompare() const {
    return invert_pattern() == kInvertCompare ||
           invert_pattern() == kInvertCompareAndLogic ||
           invert_pattern() == kInvertCompareDouble;
  }

  void BuildGraph(std::array<OpIndex, NumInputs>& inputs) {
    std::array<V<Word32>, NumCompares> compares;

    for (unsigned i = 0; i < NumCompares; ++i) {
      OpIndex a = inputs.at((2 * i) % NumInputs);
      OpIndex b = inputs.at((2 * i + 1) % NumInputs);
      V<Word32> cmp = MakeCompare(CompareOpcode(i), a, b);
      // Invert every other compare, starting with the first.
      if (ShouldInvertCompare() && (i % 1)) {
        compares[i] = MakeNotCompare(cmp);
      } else {
        compares[i] = cmp;
      }
    }

    V<Word32> first_combine =
        MakeBinop(LogicOpcode(0), compares[0], compares[1]);
    if (NumLogic == 1) {
      if (ShouldInvertLogic()) {
        return GenerateReturn(MakeNotLogic(first_combine));
      }
      return GenerateReturn(first_combine);
    }

    if (graph_shape() == kUnbalanced) {
      V<Word32> combine = first_combine;
      for (unsigned i = 1; i < NumLogic; ++i) {
        // Invert every other logic operation, beginning with the first.
        if (ShouldInvertLogic() && (i % 1)) {
          combine = MakeNotLogic(combine);
        }
        combine = MakeBinop(LogicOpcode(i), compares.at(i + 1), combine);
      }
      return GenerateReturn(combine);
    } else {
      constexpr uint32_t NumFirstLayerLogic = NumCompares / 2;
      std::array<V<Word32>, NumFirstLayerLogic> first_layer_logic{
          first_combine};
      for (unsigned i = 1; i < NumFirstLayerLogic; ++i) {
        first_layer_logic[i] = MakeBinop(LogicOpcode(i), compares.at(2 * i),
                                         compares.at(2 * i + 1));
      }
      V<Word32> combine = first_combine;
      // Invert every other first layer logic operation, beginning with the
      // first.
      if (ShouldInvertLogic()) {
        combine = MakeNotLogic(combine);
      }
      for (unsigned i = 1; i < NumFirstLayerLogic; ++i) {
        V<Word32> logic_node = first_layer_logic.at(i);
        if (ShouldInvertLogic() && !(i % 2)) {
          logic_node = MakeNotLogic(logic_node);
        }
        uint32_t logic_idx = NumFirstLayerLogic + i - 1;
        combine = MakeBinop(LogicOpcode(logic_idx), logic_node, combine);
      }
      GenerateReturn(combine);
    }
  }

  uint32_t ExpectedReturn(uint32_t combine) const {
    if (branch_pattern() == kNone) {
      return combine;
    } else if (branch_pattern() == kDirect) {
      return combine == 0 ? 0 : 1;
    } else if (branch_pattern() == kEqualZero) {
      return combine == 0 ? 1 : 0;
    } else {
      return combine != 0 ? 1 : 0;
    }
  }

  uint32_t InvertCompare(uint32_t v) const {
    return invert_pattern() == kInvertCompareDouble ? v : !v;
  }

  uint32_t InvertLogic(uint32_t v) const {
    return invert_pattern() == kInvertLogicDouble ? v : !v;
  }

  uint32_t Expected(std::array<CompareType, NumInputs>& inputs) {
    std::array<uint32_t, NumCompares> compare_results;
    for (unsigned i = 0; i < NumCompares; ++i) {
      CompareType cmp_lhs = inputs.at((2 * i) % NumInputs);
      CompareType cmp_rhs = inputs.at((2 * i + 1) % NumInputs);
      CompareWrapper cmpw = CompareWrapper(CompareOpcode(i));
      uint32_t cmp_res = EvalCompare(cmpw, cmp_lhs, cmp_rhs);
      // Invert every other compare, starting with the first.
      if (ShouldInvertCompare() && (i % 1)) {
        compare_results[i] = InvertCompare(cmp_res);
      } else {
        compare_results[i] = cmp_res;
      }
    }

    auto logicw = IntBinopWrapper<uint32_t>(LogicOpcode(0));
    uint32_t first_combine =
        logicw.eval(compare_results[0], compare_results[1]);
    if (NumLogic == 1) {
      if (ShouldInvertLogic()) {
        first_combine = InvertLogic(first_combine);
      }
      return ExpectedReturn(first_combine);
    }

    if (graph_shape() == kUnbalanced) {
      uint32_t combine = first_combine;
      for (unsigned i = 1; i < NumLogic; ++i) {
        // Invert every other logic operation, beginning with the first.
        if (ShouldInvertLogic() && (i % 1)) {
          combine = InvertLogic(combine);
        }
        logicw = IntBinopWrapper<uint32_t>(LogicOpcode(i));
        combine = logicw.eval(compare_results.at(i + 1), combine);
      }
      return ExpectedReturn(combine);
    } else {
      constexpr uint32_t NumFirstLayerLogic = NumCompares / 2;
      std::array<uint32_t, NumFirstLayerLogic> first_layer_logic{first_combine};
      for (unsigned i = 1; i < NumFirstLayerLogic; ++i) {
        logicw = IntBinopWrapper<uint32_t>(LogicOpcode(i));
        first_layer_logic[i] = logicw.eval(compare_results.at(2 * i),
                                           compare_results.at(2 * i + 1));
      }
      uint32_t combine = first_combine;
      // Invert every other first layer logic operation, beginning with the
      // first.
      if (ShouldInvertLogic()) {
        combine = InvertLogic(combine);
      }
      for (unsigned i = 1; i < NumFirstLayerLogic; ++i) {
        uint32_t logic_res = first_layer_logic.at(i);
        if (ShouldInvertLogic() && !(i % 2)) {
          logic_res = InvertLogic(logic_res);
        }
        uint32_t logic_idx = NumFirstLayerLogic + i - 1;
        logicw = IntBinopWrapper<uint32_t>(LogicOpcode(logic_idx));
        combine = logicw.eval(logic_res, combine);
      }
      return ExpectedReturn(combine);
    }
  }

  virtual uint32_t EvalCompare(CompareWrapper& cmpw, CompareType lhs,
                               CompareType rhs) const = 0;
  virtual OpIndex Zero() const = 0;
  virtual OpIndex One() const = 0;
  virtual OpIndex ThirtyTwo() const = 0;

  RawMachineAssemblerTester<uint32_t>& m() const { return m_; }
  GraphShape graph_shape() const { return graph_shape_; }
  InvertPattern invert_pattern() const { return invert_pattern_; }
  BranchPattern branch_pattern() const { return branch_pattern_; }
  TurboshaftBinop LogicOpcode(uint32_t i) const { return logic_ops_.at(i); }
  TurboshaftComparison CompareOpcode(uint32_t i) const {
    return compare_ops_.at(i);
  }
  Block* blocka() { return blocka_; }
  Block* blockb() { return blockb_; }

 private:
  RawMachineAssemblerTester<uint32_t>& m_;
  GraphShape graph_shape_;
  InvertPattern invert_pattern_;
  BranchPattern branch_pattern_;
  Block* blocka_;
  Block* blockb_;
  std::array<TurboshaftBinop, NumLogic> logic_ops_;
  std::array<TurboshaftComparison, NumCompares> compare_ops_;
};

template <uint32_t NumLogic>
class CombineCompareWord32 : public CombineCompares<NumLogic, uint32_t> {
 public:
  using CombineCompares<NumLogic, uint32_t>::CombineCompares;
  uint32_t EvalCompare(CompareWrapper& cmpw, uint32_t lhs,
                       uint32_t rhs) const override {
    return cmpw.Int32Compare(lhs, rhs);
  }
  OpIndex Zero() const override { return this->m().Word32Constant(0); }
  OpIndex One() const override { return this->m().Word32Constant(1); }
  OpIndex ThirtyTwo() const override { return this->m().Word32Constant(32); }
};

template <uint32_t NumLogic>
class CombineCompareWord64 : public CombineCompares<NumLogic, uint64_t> {
 public:
  using CombineCompares<NumLogic, uint64_t>::CombineCompares;
  uint32_t EvalCompare(CompareWrapper& cmpw, uint64_t lhs,
                       uint64_t rhs) const override {
    return cmpw.Int64Compare(lhs, rhs);
  }
  OpIndex Zero() const override {
    return this->m().Word64Constant(static_cast<uint64_t>(0));
  }
  OpIndex One() const override {
    return this->m().Word64Constant(static_cast<uint64_t>(1));
  }
  OpIndex ThirtyTwo() const override {
    return this->m().Word64Constant(static_cast<uint64_t>(32));
  }
};

template <typename Combiner, typename InputType>
void CombineCompareLogic1(
    const std::array<TurboshaftComparison, 5>& cmp_opcodes,
    MachineType (*input_type)(void),
    const base::Vector<const InputType>& input_vector) {
  constexpr GraphShape shape = kBalanced;
  for (auto cmp0 : cmp_opcodes) {
    for (auto cmp1 : cmp_opcodes) {
      for (auto logic : kLogicOpcodes) {
        for (auto invert_pattern : kInvertPatterns) {
          for (auto branch_pattern : kBranchPatterns) {
            RawMachineAssemblerTester<uint32_t> m(input_type(), input_type(),
                                                  input_type(), input_type());
            std::array logic_ops = {logic};
            std::array compare_ops = {cmp0, cmp1};
            Combiner gen(m, shape, invert_pattern, branch_pattern, logic_ops,
                         compare_ops);
            std::array inputs = {
                m.Parameter(0),
                m.Parameter(1),
                m.Parameter(2),
                m.Parameter(3),
            };
            gen.BuildGraph(inputs);

            for (auto a : input_vector) {
              for (auto b : input_vector) {
                std::array<InputType, 4> inputs{a, b, b, a};
                uint32_t expected = gen.Expected(inputs);
                uint32_t actual = m.Call(a, b, b, a);
                CHECK_EQ(expected, actual);
              }
            }
          }
        }
      }
    }
  }
}
TEST(CombineCompareWord32Logic1) {
  CombineCompareLogic1<CombineCompareWord32<1>, uint32_t>(
      kInt32CmpOpcodes, MachineType::Uint32, uint32_test_vector);
}
#if V8_TARGET_ARCH_64_BIT
TEST(CombineCompareWord64Logic1) {
  CombineCompareLogic1<CombineCompareWord64<1>, uint64_t>(
      kInt64CmpOpcodes, MachineType::Uint64, uint64_test_vector);
}
#endif

template <typename Combiner, typename InputType>
void CombineCompareLogic2(
    const std::array<TurboshaftComparison, 5>& cmp_opcodes,
    MachineType (*input_type)(void),
    const base::Vector<const InputType>& input_vector) {
  constexpr GraphShape shape = kUnbalanced;
  constexpr BranchPattern branch_pattern = kNone;
  auto cmp0 = cmp_opcodes[3];
  auto cmp1 = cmp_opcodes[2];
  auto cmp2 = cmp_opcodes[1];
  std::array compare_ops = {cmp0, cmp1, cmp2};
  for (auto logic0 : kLogicOpcodes) {
    for (auto logic1 : kLogicOpcodes) {
      for (auto invert_pattern : kInvertPatterns) {
        RawMachineAssemblerTester<uint32_t> m(input_type(), input_type(),
                                              input_type(), input_type());
        std::array logic_ops = {logic0, logic1};
        Combiner gen(m, shape, invert_pattern, branch_pattern, logic_ops,
                     compare_ops);
        std::array inputs = {
            m.Parameter(0),
            m.Parameter(1),
            m.Parameter(2),
            m.Parameter(3),
        };
        gen.BuildGraph(inputs);

        for (auto a : input_vector) {
          for (auto b : input_vector) {
            std::array<InputType, 4> inputs{a, b, b, a};
            uint32_t expected = gen.Expected(inputs);
            uint32_t actual = m.Call(a, b, b, a);
            CHECK_EQ(expected, actual);
          }
        }
      }
    }
  }
}
TEST(CombineCompareWord32Logic2) {
  CombineCompareLogic2<CombineCompareWord32<2>, uint32_t>(
      kInt32CmpOpcodes, MachineType::Uint32, uint32_test_vector);
}
#if V8_TARGET_ARCH_64_BIT
TEST(CombineCompareWord64Logic2) {
  CombineCompareLogic2<CombineCompareWord64<2>, uint64_t>(
      kInt64CmpOpcodes, MachineType::Uint64, uint64_test_vector);
}
#endif

template <typename Combiner, typename InputType>
void CombineCompareLogic3Zero(
    const std::array<TurboshaftComparison, 5>& cmp_opcodes,
    MachineType (*input_type)(void),
    const base::Vector<const InputType>& input_vector) {
  constexpr BranchPattern branch_pattern = kNone;
  auto cmp0 = cmp_opcodes[0];
  auto cmp1 = cmp_opcodes[1];
  auto cmp2 = cmp_opcodes[2];
  auto cmp3 = cmp_opcodes[3];
  std::array compare_ops = {cmp0, cmp1, cmp2, cmp3};
  for (auto logic0 : kLogicOpcodes) {
    for (auto logic1 : kLogicOpcodes) {
      for (auto logic2 : kLogicOpcodes) {
        for (auto shape : kGraphShapes) {
          for (auto invert_pattern : kInvertPatterns) {
            RawMachineAssemblerTester<uint32_t> m(input_type(), input_type(),
                                                  input_type(), input_type());
            std::array logic_ops = {logic0, logic1, logic2};
            Combiner gen(m, shape, invert_pattern, branch_pattern, logic_ops,
                         compare_ops);
            std::array inputs = {
                m.Parameter(0),
                m.Parameter(1),
                gen.Zero(),
                m.Parameter(3),
            };
            gen.BuildGraph(inputs);

            for (auto a : input_vector) {
              for (auto b : input_vector) {
                std::array<InputType, 4> inputs{a, b, 0, a};
                uint32_t expected = gen.Expected(inputs);
                uint32_t actual = m.Call(a, b, b, a);
                CHECK_EQ(expected, actual);
              }
            }
          }
        }
      }
    }
  }
}
TEST(CombineCompareWord32Logic3Zero) {
  CombineCompareLogic3Zero<CombineCompareWord32<3>, uint32_t>(
      kInt32CmpOpcodes, MachineType::Uint32, uint32_test_vector);
}
#if V8_TARGET_ARCH_64_BIT
TEST(CombineCompareWord64Logic3Zero) {
  CombineCompareLogic3Zero<CombineCompareWord64<3>, uint64_t>(
      kInt64CmpOpcodes, MachineType::Uint64, uint64_test_vector);
}
#endif

template <typename Combiner, typename InputType>
void CombineCompareLogic3One(
    const std::array<TurboshaftComparison, 5>& cmp_opcodes,
    MachineType (*input_type)(void),
    const base::Vector<const InputType>& input_vector) {
  constexpr BranchPattern branch_pattern = kNone;
  auto cmp0 = cmp_opcodes[4];
  auto cmp1 = cmp_opcodes[1];
  auto cmp2 = cmp_opcodes[2];
  auto cmp3 = cmp_opcodes[0];
  std::array compare_ops = {cmp0, cmp1, cmp2, cmp3};
  for (auto logic0 : kLogicOpcodes) {
    for (auto logic1 : kLogicOpcodes) {
      for (auto logic2 : kLogicOpcodes) {
        for (auto shape : kGraphShapes) {
          for (auto invert_pattern : kInvertPatterns) {
            RawMachineAssemblerTester<uint32_t> m(input_type(), input_type(),
                                                  input_type(), input_type());
            std::array logic_ops = {logic0, logic1, logic2};
            Combiner gen(m, shape, invert_pattern, branch_pattern, logic_ops,
                         compare_ops);
            std::array inputs = {
                gen.One(),
                m.Parameter(1),
                m.Parameter(2),
                m.Parameter(3),
            };
            gen.BuildGraph(inputs);

            for (auto a : input_vector) {
              for (auto b : input_vector) {
                std::array<InputType, 4> inputs{1, b, b, a};
                uint32_t expected = gen.Expected(inputs);
                uint32_t actual = m.Call(a, b, b, a);
                CHECK_EQ(expected, actual);
              }
            }
          }
        }
      }
    }
  }
}
TEST(CombineCompareWord32Logic3One) {
  CombineCompareLogic3One<CombineCompareWord32<3>, uint32_t>(
      kInt32CmpOpcodes, MachineType::Uint32, uint32_test_vector);
}
#if V8_TARGET_ARCH_64_BIT
TEST(CombineCompareWord64Logic3One) {
  CombineCompareLogic3One<CombineCompareWord64<3>, uint64_t>(
      kInt64CmpOpcodes, MachineType::Uint64, uint64_test_vector);
}
#endif

template <typename Combiner, typename InputType>
void CombineCompareLogic3ThirtyTwo(
    const std::array<TurboshaftComparison, 5>& cmp_opcodes,
    MachineType (*input_type)(void),
    const base::Vector<const InputType>& input_vector) {
  constexpr BranchPattern branch_pattern = kNone;
  auto cmp0 = cmp_opcodes[0];
  auto cmp1 = cmp_opcodes[3];
  auto cmp2 = cmp_opcodes[2];
  auto cmp3 = cmp_opcodes[4];
  std::array compare_ops = {cmp0, cmp1, cmp2, cmp3};
  for (auto logic0 : kLogicOpcodes) {
    for (auto logic1 : kLogicOpcodes) {
      for (auto logic2 : kLogicOpcodes) {
        for (auto shape : kGraphShapes) {
          for (auto invert_pattern : kInvertPatterns) {
            RawMachineAssemblerTester<uint32_t> m(input_type(), input_type(),
                                                  input_type(), input_type());
            std::array logic_ops = {logic0, logic1, logic2};
            Combiner gen(m, shape, invert_pattern, branch_pattern, logic_ops,
                         compare_ops);
            std::array inputs = {
                m.Parameter(0),
                gen.ThirtyTwo(),
                m.Parameter(2),
                m.Parameter(3),
            };
            gen.BuildGraph(inputs);

            for (auto a : input_vector) {
              for (auto b : input_vector) {
                std::array<InputType, 4> inputs{a, 32, b, a};
                uint32_t expected = gen.Expected(inputs);
                uint32_t actual = m.Call(a, b, b, a);
                CHECK_EQ(expected, actual);
              }
            }
          }
        }
      }
    }
  }
}
TEST(CombineCompareWord32Logic3ThirtyTwo) {
  CombineCompareLogic3ThirtyTwo<CombineCompareWord32<3>, uint32_t>(
      kInt32CmpOpcodes, MachineType::Uint32, uint32_test_vector);
}
#if V8_TARGET_ARCH_64_BIT
TEST(CombineCompareWord64Logic3ThirtyTwo) {
  CombineCompareLogic3ThirtyTwo<CombineCompareWord64<3>, uint64_t>(
      kInt64CmpOpcodes, MachineType::Uint64, uint64_test_vector);
}
#endif

constexpr uint32_t kMaxDepth = 4;
// a       b    b       a    a        b   b       a   a       b
// |       |    |       |    |        |   |       |   |       |
// |       |    |       |    |        |   |       |   |       |
// -> cmp <-    -> cmp <-    -> cmp <-    -> cmp <-   -> cmp <-
//     |            |            |            |           |
//     ---> and <---             |            |           |
//           |                   |            |           |
//            ---------> or <----             |           |
//                        |                   |           |
//                         ------> and <------            |
//                                  |                     |
//                             
"""


```