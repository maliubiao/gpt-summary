Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality with JavaScript examples.

1. **Identify the Core Purpose:** The file name `turboshaft-test-compare-combine.cc` and the directory `v8/test/cctest/compiler/` immediately suggest this is a test file for the Turboshaft compiler within the V8 JavaScript engine. The "compare-combine" part hints at testing how the compiler handles combinations of comparison and logical operations.

2. **Scan for Key Data Structures and Constants:**  Look for declarations of arrays, enums, and constants that define the scope of the tests.
    * `kLogicOpcodes`:  Bitwise AND and OR. This tells us the type of logical operations being tested.
    * `kInt32CmpOpcodes`, `kInt64CmpOpcodes`:  Various integer comparison operations (equal, less than, etc.). This indicates the range of comparisons being tested.
    * `GraphShape`, `InvertPattern`, `BranchPattern`: Enums defining different ways the comparison and logic nodes are arranged and manipulated. These are crucial for understanding the test scenarios.
    * `kGraphShapes`, `kInvertPatterns`, `kBranchPatterns`: Arrays containing the possible values for the enums, indicating the combinatorial nature of the tests.
    * `uint32_test_array`, `uint64_test_array`: Sample data used for testing the compiled code.

3. **Understand the Test Framework:** Recognize the use of `TEST(...)` macros, which is a common pattern in C++ testing frameworks (like Google Test, which V8 uses). This tells us that each `TEST(...)` block represents an independent test case.

4. **Focus on the `CombineCompares` Template:** This class is the heart of the testing logic. Analyze its members and methods:
    * **Template Parameters:** `NumLogic` and `CompareType`. This indicates the tests are parameterized by the number of logical operations and the data type being compared (32-bit or 64-bit integers).
    * **`BuildGraph`:** This method is responsible for constructing the computational graph that will be compiled. Pay close attention to how it combines comparison operations using logical operations, influenced by `graph_shape_` and `invert_pattern_`. The ASCII art diagrams are extremely helpful here!
    * **`ExpectedReturn`:** This calculates the expected result of the compiled code based on the `branch_pattern_`.
    * **`Expected`:** This function *simulates* the execution of the comparison and logic operations in C++ to determine the expected outcome. This is the "ground truth" against which the compiled code's output is compared.
    * **`MakeBinop`, `MakeCompare`, `MakeNot`, `MakeNotCompare`, `MakeNotLogic`:** These methods are wrappers around the `RawMachineAssemblerTester` to create nodes in the Turboshaft graph. The "MakeNot" variations are key to understanding the `InvertPattern` scenarios.
    * **`EvalCompare`:**  A virtual method that handles the actual comparison based on the `CompareType`.

5. **Analyze Individual `TEST` Functions:**  Examine how each `TEST` function uses the `CombineCompares` template:
    * **Instantiation:** Look at the template arguments used (e.g., `CombineCompareWord32<1>`).
    * **Looping over Opcodes and Patterns:** Notice how the tests iterate through different comparison opcodes, logical opcodes, graph shapes, invert patterns, and branch patterns to cover a wide range of scenarios.
    * **Data Input:** See how `uint32_test_vector` and `uint64_test_vector` are used to provide input data.
    * **`m.Call(...)` and `CHECK_EQ(...)`:**  These are the core of the test execution and verification. `m.Call` executes the compiled code, and `CHECK_EQ` asserts that the actual result matches the expected result.

6. **Connect to JavaScript (the "aha!" moment):** Now that you understand the C++ code's testing purpose, think about how these comparison and logical operations translate to JavaScript.
    * **Comparison Operators:** JavaScript has `==`, `!=`, `<`, `>`, `<=`, `>=`. Relate these to the `TurboshaftComparison` enum values.
    * **Logical Operators:** JavaScript has `&&` (AND), `||` (OR), `!` (NOT). Connect these to `TurboshaftBinop::kWord32BitwiseAnd` and `TurboshaftBinop::kWord32BitwiseOr`. Recognize that JavaScript's logical operators work on boolean values, while the C++ code is testing bitwise operations as well. Point out this nuance.
    * **Control Flow:** The `BranchPattern` enum relates to `if` statements and conditional logic in JavaScript.

7. **Construct JavaScript Examples:** Create simple, illustrative JavaScript code snippets that mirror the scenarios being tested in the C++ code. Focus on:
    * **Basic Comparisons and Logical Combinations:** Show direct equivalents of the tested operations.
    * **Illustrating `InvertPattern`:**  Demonstrate how the "not" operations change the outcome.
    * **Relating to Control Flow:** Show how the `BranchPattern` scenarios translate to `if/else` statements.

8. **Explain the "Why":**  Articulate *why* this type of testing is important for a JavaScript engine:
    * **Optimization:**  Highlight that Turboshaft aims to optimize JavaScript code, and these tests ensure that complex combinations of comparisons and logic are handled correctly and efficiently.
    * **Correctness:** Emphasize the fundamental importance of accurate comparison and logical operations for the correctness of JavaScript programs.
    * **Edge Cases:** Explain that the various graph shapes and inversion patterns likely represent different optimization challenges and potential edge cases for the compiler.

9. **Review and Refine:** Read through your explanation and examples. Ensure they are clear, concise, and accurately reflect the functionality of the C++ code. Make sure the connection to JavaScript is explicit and easy to understand. For example, initially, I might only think of JavaScript's boolean logical operators. But rereading the C++ code reminds me that *bitwise* AND and OR are also being tested, even though the comparison results are boolean. This nuance is important to include in the explanation.

By following this structured approach, you can effectively analyze complex C++ code and explain its relevance to JavaScript development.
这个C++源代码文件 `turboshaft-test-compare-combine.cc` 是 V8 JavaScript 引擎中 Turboshaft 编译器的一个测试文件。它的主要功能是**测试 Turboshaft 编译器如何正确地组合和优化比较运算以及逻辑运算**。

具体来说，这个测试文件会生成各种不同的由比较运算和逻辑运算组成的计算图，然后使用 Turboshaft 编译器进行编译，并验证编译后的代码是否能够产生预期的结果。

以下是该文件的一些关键功能点：

* **定义了多种测试场景:**  通过 `GraphShape`, `InvertPattern`, 和 `BranchPattern` 这几个枚举类型以及它们的组合，定义了多种不同的计算图结构和逻辑反转模式。例如：
    * `GraphShape`: 定义了逻辑运算组合的结构是平衡的还是非平衡的。
    * `InvertPattern`: 定义了是否以及如何反转比较运算或逻辑运算的结果。
    * `BranchPattern`: 定义了是否以及如何基于最终的逻辑运算结果进行分支。
* **测试不同的比较运算符:** 使用 `kInt32CmpOpcodes` 和 `kInt64CmpOpcodes` 定义了要测试的各种整数比较运算符，例如等于、小于、小于等于等等。
* **测试不同的逻辑运算符:** 使用 `kLogicOpcodes` 定义了要测试的逻辑运算符，目前主要是按位与和按位或。
* **使用模板化的测试框架:**  使用了模板类 `CombineCompares` 来生成和验证不同类型的比较和逻辑运算组合。这个模板类可以方便地针对不同的数据类型（例如 `uint32_t` 和 `uint64_t`）进行测试。
* **生成并执行测试代码:**  使用 `RawMachineAssemblerTester` 来构建 Turboshaft 的中间表示 (IR)，然后运行生成的代码，并与预期的结果进行比较。
* **覆盖多种组合情况:**  通过多层循环遍历不同的比较运算符、逻辑运算符、图结构和反转模式，力求覆盖尽可能多的组合情况，以确保 Turboshaft 编译器在处理这些复杂组合时的正确性。

**与 JavaScript 的关系及 JavaScript 举例:**

这个测试文件直接关系到 JavaScript 的性能和正确性。Turboshaft 是 V8 引擎中用于优化 JavaScript 代码的编译器。JavaScript 代码中经常会包含复杂的比较和逻辑运算组合，例如 `if` 语句中的条件判断：

```javascript
function test(a, b, c, d) {
  if ((a < b && c > d) || (a === 10 && b !== 20)) {
    return 1;
  } else {
    return 0;
  }
}
```

在这个 JavaScript 例子中，我们有多个比较运算符 (`<`, `>`, `===`, `!==`) 和逻辑运算符 (`&&`, `||`) 组合在一起。Turboshaft 的目标就是高效地将这样的 JavaScript 代码编译成机器码。

`turboshaft-test-compare-combine.cc`  中的测试用例，例如那些使用 `kInt32CmpOpcodes` 和 `kLogicOpcodes` 的测试，实际上就是在模拟 JavaScript 中类似 `if` 语句的场景。

让我们用一个更具体的例子来说明 `CombineCompares` 类在测试什么：

假设 `CombineCompareWord32<2>` 被用来测试两个逻辑运算符连接三个比较运算的情况，并且 `graph_shape_` 是 `kUnbalanced`，`invert_pattern_` 是 `kNoInvert`， 逻辑运算符是 `kWord32BitwiseAnd` 和 `kWord32BitwiseOr`，比较运算符是小于。

那么，这个测试可能会生成类似下面逻辑的计算图：

```
a       b    c       d    e       f
|       |    |       |    |       |
-> cmp <-    -> cmp <-    -> cmp <-
     |            |            |
     --> and <----             |
           |                   |
            ---------> or <-----
```

这在 JavaScript 中可以对应于类似这样的代码：

```javascript
function test(a, b, c, d, e, f) {
  return (a < b) && (c < d) || (e < f);
}
```

测试文件会生成各种不同的 `a`, `b`, `c`, `d`, `e`, `f` 的值，然后：

1. **C++ 代码模拟预期结果:**  `CombineCompares::Expected()` 方法会根据输入的 `a`, `b`, `c`, `d`, `e`, `f` 的值，按照逻辑运算的顺序，计算出 JavaScript 代码的预期返回值（0 或 1）。
2. **Turboshaft 编译并执行:**  `CombineCompares::BuildGraph()` 方法会使用 `RawMachineAssemblerTester` 构建 Turboshaft 的 IR，表示类似的比较和逻辑运算。然后，V8 会编译并执行这段 IR。
3. **验证结果:** 测试框架会比较 Turboshaft 编译执行的实际结果和 `CombineCompares::Expected()` 计算出的预期结果，如果两者一致，则说明 Turboshaft 在这种情况下正确地处理了比较和逻辑运算的组合。

总而言之，`turboshaft-test-compare-combine.cc`  是一个关键的测试文件，用于确保 V8 引擎的 Turboshaft 编译器能够正确且高效地处理 JavaScript 代码中常见的比较和逻辑运算组合，从而保证 JavaScript 代码的性能和正确性。  它通过详尽的组合测试，覆盖了各种可能的场景，帮助 V8 开发者发现和修复编译器中的潜在问题。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-test-compare-combine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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
//                                  --------> or <--------
TEST(CombineCompareMaxDepth) {
  constexpr GraphShape shape = kUnbalanced;
  constexpr BranchPattern branch_pattern = kNone;
  std::array logic_ops = {
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr,
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr};
  std::array compare_ops = {TurboshaftComparison::kWord32Equal,
                            TurboshaftComparison::kInt32LessThan,
                            TurboshaftComparison::kInt32LessThanOrEqual,
                            TurboshaftComparison::kUint32LessThan,
                            TurboshaftComparison::kUint32LessThanOrEqual};
  for (auto invert_pattern : kInvertPatterns) {
    RawMachineAssemblerTester<uint32_t> m(
        MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
        MachineType::Uint32());
    CombineCompareWord32<kMaxDepth> gen(m, shape, invert_pattern,
                                        branch_pattern, logic_ops, compare_ops);
    std::array inputs = {
        m.Parameter(0),
        m.Parameter(1),
        m.Parameter(2),
        m.Parameter(3),
    };
    gen.BuildGraph(inputs);

    FOR_UINT32_INPUTS(a) {
      FOR_UINT32_INPUTS(b) {
        std::array inputs{a, b, b, a};
        uint32_t expected = gen.Expected(inputs);
        uint32_t actual = m.Call(a, b, b, a);
        CHECK_EQ(expected, actual);
      }
    }
  }
}

TEST(CombineCompareBranchesMaxDepth) {
  constexpr GraphShape shape = kUnbalanced;
  std::array logic_ops = {
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr,
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr};
  std::array compare_ops = {TurboshaftComparison::kWord32Equal,
                            TurboshaftComparison::kInt32LessThan,
                            TurboshaftComparison::kInt32LessThanOrEqual,
                            TurboshaftComparison::kUint32LessThan,
                            TurboshaftComparison::kUint32LessThanOrEqual};
  for (auto branch_pattern : kBranchPatterns) {
    for (auto invert_pattern : kInvertPatterns) {
      RawMachineAssemblerTester<uint32_t> m(
          MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
          MachineType::Uint32());
      CombineCompareWord32<kMaxDepth> gen(
          m, shape, invert_pattern, branch_pattern, logic_ops, compare_ops);
      std::array inputs = {
          m.Parameter(0),
          m.Parameter(1),
          m.Parameter(2),
          m.Parameter(3),
      };
      gen.BuildGraph(inputs);

      FOR_UINT32_INPUTS(a) {
        FOR_UINT32_INPUTS(b) {
          std::array inputs{a, b, b, a};
          uint32_t expected = gen.Expected(inputs);
          uint32_t actual = m.Call(a, b, b, a);
          CHECK_EQ(expected, actual);
        }
      }
    }
  }
}

TEST(CombineCompareMaxDepthPlusOne) {
  std::array logic_ops = {
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr,
      TurboshaftBinop::kWord32BitwiseAnd, TurboshaftBinop::kWord32BitwiseOr,
      TurboshaftBinop::kWord32BitwiseAnd};
  std::array compare_ops = {
      TurboshaftComparison::kWord32Equal,
      TurboshaftComparison::kInt32LessThan,
      TurboshaftComparison::kInt32LessThanOrEqual,
      TurboshaftComparison::kUint32LessThan,
      TurboshaftComparison::kUint32LessThanOrEqual,
      TurboshaftComparison::kWord32Equal,
  };
  constexpr BranchPattern branch_pattern = kNone;
  for (auto shape : kGraphShapes) {
    for (auto invert_pattern : kInvertPatterns) {
      RawMachineAssemblerTester<uint32_t> m(
          MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
          MachineType::Uint32());
      CombineCompareWord32<kMaxDepth + 1> gen(
          m, shape, invert_pattern, branch_pattern, logic_ops, compare_ops);
      std::array inputs = {
          m.Parameter(0),
          m.Parameter(1),
          m.Parameter(2),
          m.Parameter(3),
      };
      gen.BuildGraph(inputs);

      FOR_UINT32_INPUTS(a) {
        FOR_UINT32_INPUTS(b) {
          std::array inputs{a, b, b, a};
          uint32_t expected = gen.Expected(inputs);
          uint32_t actual = m.Call(a, b, b, a);
          CHECK_EQ(expected, actual);
        }
      }
    }
  }
}

TEST(CombineCompareTwoLogicInputs) {
  // cmp cmp cmp cmp cmp cmp
  //  |   |   |   |   |   |
  //  logic   logic   logic
  //    |       |       |
  //     - cmp -        |
  //        |           |
  //         -- logic --
  auto run = [](uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    bool cmp1 = static_cast<int32_t>(a) < static_cast<int32_t>(b);
    bool cmp2 = static_cast<int32_t>(a) <= 1024;
    bool cmp3 = static_cast<int32_t>(c) < static_cast<int32_t>(d);
    bool cmp4 = static_cast<int32_t>(c) < 4096;
    bool cmp5 = a < d;
    bool cmp6 = b <= c;
    bool logic1 = cmp1 && cmp2;
    bool logic2 = cmp3 || cmp4;
    bool logic3 = cmp5 && cmp6;
    bool cmp7 = logic1 == logic2;
    return static_cast<uint32_t>(cmp7 || logic3);
  };

  RawMachineAssemblerTester<uint32_t> m(
      MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint32(),
      MachineType::Uint32());

  V<Word32> cmp1 = m.Int32LessThan(m.Parameter(0), m.Parameter(1));
  V<Word32> cmp2 =
      m.Int32LessThanOrEqual(m.Parameter(0), m.Word32Constant(1024));
  V<Word32> cmp3 = m.Int32LessThan(m.Parameter(2), m.Parameter(3));
  V<Word32> cmp4 =
      m.Int32LessThanOrEqual(m.Parameter(2), m.Word32Constant(4096));
  V<Word32> cmp5 = m.Uint32LessThan(m.Parameter(0), m.Parameter(3));
  V<Word32> cmp6 = m.Uint32LessThanOrEqual(m.Parameter(1), m.Parameter(2));

  V<Word32> logic1 = m.Word32BitwiseAnd(cmp1, cmp2);
  V<Word32> logic2 = m.Word32BitwiseOr(cmp3, cmp4);
  V<Word32> logic3 = m.Word32BitwiseAnd(cmp5, cmp6);

  V<Word32> cmp7 = m.Word32Equal(logic1, logic2);

  m.Return(m.Word32BitwiseOr(cmp7, logic3));

  for (uint32_t a : uint32_test_vector) {
    for (uint32_t b : uint32_test_vector) {
      for (uint32_t c : uint32_test_vector) {
        for (uint32_t d : uint32_test_vector) {
          uint32_t result = m.Call(a, b, c, d);
          uint32_t expected = run(a, b, c, d);
          CHECK_EQ(result, expected);
        }
      }
    }
  }
}

}  // end namespace

}  // namespace v8::internal::compiler::turboshaft

"""

```