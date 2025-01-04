Response: The user wants to understand the functionality of the C++ source code file `loop-unrolling-analyzer-unittest.cc`.
This file seems to be testing a component called `LoopUnrollingAnalyzer` within the V8 JavaScript engine's Turboshaft compiler.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename and the class `LoopUnrollingAnalyzerTest` strongly suggest that this file is dedicated to testing the `LoopUnrollingAnalyzer`.

2. **Examine the Test Structure:** The code uses Google Test (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`). This indicates parameterized tests, meaning the same test logic is run with different sets of input data.

3. **Analyze the Test Cases:**  Look at the different test suites and the data structures used for parameterization (`BoundedLoop`, `BoundedPartialLoop`). These structures describe different loop scenarios.

4. **Understand the `LoopUnrollingAnalyzer`'s Goal:** The term "loop unrolling" implies optimizing loops by duplicating their bodies. The analyzer likely determines if and how a loop can be unrolled.

5. **Connect to JavaScript:** Loop unrolling is a common compiler optimization technique applicable to any language with loops, including JavaScript. Consider how different loop structures in JavaScript might benefit from unrolling.

6. **Provide a JavaScript Example:** Create a simple JavaScript loop and explain how unrolling could optimize it.

**Mental Walkthrough of the Code:**

* **Includes:**  Standard includes for testing and the specific Turboshaft components being tested (`loop-unrolling-reducer.h`).
* **Test Fixture:** `LoopUnrollingAnalyzerTest` sets up the testing environment. `LoopUnrollingAnalyzerTestWithParam` enables parameterized tests.
* **Helper Functions:** `CountLoops`, `GetFirstLoop` are utilities to inspect the generated graph representation of the code.
* **Macros and Enums:** `BUILTIN_CMP_LIST`, `CMP_LIST`, `Binop` define the set of comparison and binary operations the tests cover. These represent common operations in loops.
* **Helper Functions (Cmp, Binop):** `EmitCmp` and `EmitBinop` are used within the test cases to construct the loop conditions and body.
* **`BoundedLoop` Structure:** This is the core data structure driving many tests. It defines loop characteristics: initial value, comparison, maximum value, increment operation, expected iterations, and a descriptive name.
* **Test Cases (`ExactLoopIterCount`, `LargeLoopIterCount`, `LargeLoopIterCount` (overflow), `PartialUnrollCount`):** Each test case constructs a loop in the Turboshaft graph based on the `BoundedLoop` parameters and then uses the `LoopUnrollingAnalyzer` to verify its properties (like iteration count or whether it should be partially unrolled).
* **JavaScript Connection:**  Consider how the concepts of loop counters, conditions, and increments map to JavaScript `for` loops.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the C++ details. The key is to extract the high-level functionality and its relevance to JavaScript.
* Ensure the JavaScript example is clear and directly relates to the concept of loop unrolling.
* Pay attention to the different types of tests (exact iteration count, handling large loops, overflow scenarios, partial unrolling). This provides a comprehensive understanding of the analyzer's capabilities.

By following these steps, I can generate a well-structured and informative summary of the C++ code's functionality and its connection to JavaScript.
这个C++源代码文件 `loop-unrolling-analyzer-unittest.cc` 是V8 JavaScript引擎中 **Turboshaft编译器** 的一个单元测试文件。它的主要功能是 **测试 `LoopUnrollingAnalyzer` 这个组件的功能**。

`LoopUnrollingAnalyzer` 的作用是 **分析循环结构，判断是否适合进行循环展开（loop unrolling）优化**，并计算循环展开的相关信息，例如循环的迭代次数。

**具体来说，这个测试文件会构建各种不同类型的循环结构，然后使用 `LoopUnrollingAnalyzer` 来分析这些循环，并验证分析结果是否符合预期。** 测试的方面包括：

* **精确计算小循环的迭代次数:**  测试各种小型的有明确边界的循环，验证 `LoopUnrollingAnalyzer` 能否正确计算出循环的精确迭代次数。
* **近似计算大循环的迭代次数:** 测试大型循环，验证 `LoopUnrollingAnalyzer` 能否正确判断循环迭代次数是否超过某个阈值（用于判断是否需要移除栈溢出检查）。
* **处理可能溢出的循环:** 测试循环计数器可能发生溢出的情况，验证 `LoopUnrollingAnalyzer` 能否正确识别这类循环，并判断其迭代次数为未知。
* **判断是否需要部分展开循环 (WebAssembly 特性):**  针对WebAssembly代码，测试 `LoopUnrollingAnalyzer` 能否根据循环体的大小判断是否应该进行部分循环展开，并计算部分展开的次数。

**与 JavaScript 的关系及示例：**

循环展开是一种常见的编译器优化技术，旨在通过复制循环体来减少循环控制的开销，提高代码执行效率。  尽管这个测试文件是用 C++ 编写的，用于测试 V8 引擎的内部组件，但其测试的优化技术是直接应用于 JavaScript 代码的。

当 V8 引擎执行 JavaScript 代码时，Turboshaft 编译器会对 JavaScript 代码进行编译和优化，其中就可能包括循环展开。 `LoopUnrollingAnalyzer` 的作用就是辅助 Turboshaft 编译器做出是否展开循环的决策。

**JavaScript 示例：**

假设有以下 JavaScript 循环：

```javascript
function sumArray(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i];
  }
  return sum;
}
```

**循环展开优化:**

如果 Turboshaft 编译器决定对这个循环进行展开，它可能会将循环体复制多次，例如展开 4 次：

```javascript
function sumArrayOptimized(arr) {
  let sum = 0;
  const length = arr.length;
  for (let i = 0; i < length - 3; i += 4) {
    sum += arr[i];
    sum += arr[i + 1];
    sum += arr[i + 2];
    sum += arr[i + 3];
  }
  // 处理剩余的元素
  for (let i = length - (length % 4); i < length; i++) {
    sum += arr[i];
  }
  return sum;
}
```

**`LoopUnrollingAnalyzer` 在其中的作用：**

`LoopUnrollingAnalyzer` 会分析原始的 JavaScript 循环，判断其是否适合展开。  它会考虑以下因素：

* **循环的迭代次数:** 如果循环迭代次数很少，展开可能带来的收益不大，甚至可能因为增加了代码体积而降低性能。
* **循环体的大小:** 如果循环体很小，展开的收益可能更明显。
* **是否存在复杂的控制流:**  复杂的循环结构可能不适合展开。

基于这些分析，`LoopUnrollingAnalyzer` 会告知 Turboshaft 编译器是否应该展开循环，以及展开的次数。  这个 C++ 测试文件就是为了确保 `LoopUnrollingAnalyzer` 在各种不同的循环场景下都能做出正确的分析和判断。

**总结：**

`loop-unrolling-analyzer-unittest.cc` 是一个用于测试 V8 引擎中 `LoopUnrollingAnalyzer` 组件的单元测试文件。 `LoopUnrollingAnalyzer` 的功能是分析循环结构，判断是否适合进行循环展开优化，这直接影响到 JavaScript 代码的执行效率。 虽然测试是用 C++ 编写的，但其验证的优化技术是应用于 JavaScript 代码的。

Prompt: 
```
这是目录为v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/loop-unrolling-reducer.h"
#include "test/unittests/compiler/turboshaft/reducer-test.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

class LoopUnrollingAnalyzerTest : public ReducerTest {};

template <typename T>
class LoopUnrollingAnalyzerTestWithParam
    : public LoopUnrollingAnalyzerTest,
      public ::testing::WithParamInterface<T> {};

size_t CountLoops(const Graph& graph) {
  size_t count = 0;
  for (const Block& block : graph.blocks()) {
    if (block.IsLoop()) count++;
  }
  return count;
}

const Block& GetFirstLoop(const Graph& graph) {
  DCHECK_GE(CountLoops(graph), 1u);
  for (const Block& block : graph.blocks()) {
    if (block.IsLoop()) return block;
  }
  UNREACHABLE();
}

#define BUILTIN_CMP_LIST(V) \
  V(Uint32LessThan)         \
  V(Uint32LessThanOrEqual)  \
  V(Int32LessThan)          \
  V(Int32LessThanOrEqual)   \
  V(Word32Equal)

#define CMP_GREATER_THAN_LIST(V) \
  V(Uint32GreaterThan)           \
  V(Uint32GreaterThanOrEqual)    \
  V(Int32GreaterThan)            \
  V(Int32GreaterThanOrEqual)

#define CMP_LIST(V)   \
  BUILTIN_CMP_LIST(V) \
  CMP_GREATER_THAN_LIST(V)

enum class Cmp {
#define DEF_CMP_OP(name) k##name,
  CMP_LIST(DEF_CMP_OP)
#undef DEF_CMP_OP
};
std::ostream& operator<<(std::ostream& os, const Cmp& cmp) {
  switch (cmp) {
    case Cmp::kUint32LessThan:
      return os << "<ᵘ";
    case Cmp::kUint32LessThanOrEqual:
      return os << "<=ᵘ";
    case Cmp::kInt32LessThan:
      return os << "<ˢ";
    case Cmp::kInt32LessThanOrEqual:
      return os << "<=ˢ";
    case Cmp::kUint32GreaterThan:
      return os << ">ᵘ";
    case Cmp::kUint32GreaterThanOrEqual:
      return os << ">=ᵘ";
    case Cmp::kInt32GreaterThan:
      return os << ">ˢ";
    case Cmp::kInt32GreaterThanOrEqual:
      return os << ">=ᵘ";
    case Cmp::kWord32Equal:
      return os << "!=";
  }
}

bool IsGreaterThan(Cmp cmp) {
  switch (cmp) {
#define GREATER_THAN_CASE(name) \
  case Cmp::k##name:            \
    return true;
    CMP_GREATER_THAN_LIST(GREATER_THAN_CASE)
    default:
      return false;
  }
}

Cmp GreaterThanToLessThan(Cmp cmp, ConstOrV<Word32>* left,
                          ConstOrV<Word32>* right) {
  if (IsGreaterThan(cmp)) std::swap(*left, *right);
  switch (cmp) {
    case Cmp::kUint32GreaterThan:
      return Cmp::kUint32LessThan;
    case Cmp::kUint32GreaterThanOrEqual:
      return Cmp::kUint32LessThanOrEqual;
    case Cmp::kInt32GreaterThan:
      return Cmp::kInt32LessThan;
    case Cmp::kInt32GreaterThanOrEqual:
      return Cmp::kInt32LessThanOrEqual;

    default:
      return cmp;
  }
}

#define NO_OVERFLOW_BINOP_LIST(V) \
  V(Word32Add)                    \
  V(Word32Sub)                    \
  V(Word32Mul)                    \
  V(Int32Div)                     \
  V(Uint32Div)

#define OVERFLOW_CHECKED_BINOP_LIST(V) \
  V(Int32AddCheckOverflow)             \
  V(Int32SubCheckOverflow)             \
  V(Int32MulCheckOverflow)

#define BINOP_LIST(V)       \
  NO_OVERFLOW_BINOP_LIST(V) \
  OVERFLOW_CHECKED_BINOP_LIST(V)

enum class Binop {
#define DEF_BINOP_OP(name) k##name,
  BINOP_LIST(DEF_BINOP_OP)
#undef DEF_BINOP_OP
};
std::ostream& operator<<(std::ostream& os, const Binop& binop) {
  switch (binop) {
    case Binop::kWord32Add:
      return os << "+";
    case Binop::kWord32Sub:
      return os << "-";
    case Binop::kWord32Mul:
      return os << "*";
    case Binop::kInt32Div:
      return os << "/ˢ";
    case Binop::kUint32Div:
      return os << "/ᵘ";
    case Binop::kInt32AddCheckOverflow:
      return os << "+ᵒ";
    case Binop::kInt32SubCheckOverflow:
      return os << "-ᵒ";
    case Binop::kInt32MulCheckOverflow:
      return os << "*ᵒ";
  }
}

V<Word32> EmitCmp(TestInstance& test_instance, Cmp cmp, ConstOrV<Word32> left,
                  ConstOrV<Word32> right) {
  cmp = GreaterThanToLessThan(cmp, &left, &right);
  switch (cmp) {
#define CASE(name)   \
  case Cmp::k##name: \
    return test_instance.Asm().name(left, right);
    BUILTIN_CMP_LIST(CASE)
#undef CASE
    default:
      UNREACHABLE();
  }
}

V<Word32> EmitBinop(TestInstance& test_instance, Binop binop,
                    ConstOrV<Word32> left, ConstOrV<Word32> right) {
  switch (binop) {
#define CASE_NO_OVERFLOW(name) \
  case Binop::k##name:         \
    return test_instance.Asm().name(left, right);
    NO_OVERFLOW_BINOP_LIST(CASE_NO_OVERFLOW)
#undef CASE_NO_OVERFLOW

#define CASE_OVERFLOW(name)                   \
  case Binop::k##name:                        \
    return test_instance.Asm().Projection<0>( \
        test_instance.Asm().name(left, right));
    OVERFLOW_CHECKED_BINOP_LIST(CASE_OVERFLOW)
#undef CASE_OVERFLOW
  }
}

struct BoundedLoop {
  int init;
  Cmp cmp;
  int max;
  Binop binop;
  int increment;
  uint32_t expected_iter_count;
  const char* name;
  uint32_t expected_unroll_count = 0;
};
std::ostream& operator<<(std::ostream& os, const BoundedLoop& loop) {
  return os << loop.name;
}

static const BoundedLoop kSmallBoundedLoops[] = {
    // Increasing positive counter with add increment.
    {0, Cmp::kInt32LessThan, 3, Binop::kWord32Add, 1, 3,
     "for (int32_t i = 0;  i < 3;  i += 1)"},
    {0, Cmp::kInt32LessThanOrEqual, 3, Binop::kWord32Add, 1, 4,
     "for (int32_t i = 0;  i <= 3; i += 1)"},
    {0, Cmp::kUint32LessThan, 3, Binop::kWord32Add, 1, 3,
     "for (uint32_t i = 0; i < 3;  i += 1)"},
    {0, Cmp::kUint32LessThanOrEqual, 3, Binop::kWord32Add, 1, 4,
     "for (uint32_t i = 0; i <= 3; i += 1)"},

    // Decreasing counter with add/sub increment.
    {1, Cmp::kInt32GreaterThan, -2, Binop::kWord32Sub, 1, 3,
     "for (int32_t i = 1; i > -2; i -= 1)"},
    {1, Cmp::kInt32GreaterThan, -2, Binop::kWord32Add, -1, 3,
     "for (int32_t i = 1; i > -2; i += -1)"},
    {1, Cmp::kInt32GreaterThanOrEqual, -2, Binop::kWord32Sub, 1, 4,
     "for (int32_t i = 1; i >= -2; i -= 1)"},
    {1, Cmp::kInt32GreaterThanOrEqual, -2, Binop::kWord32Add, -1, 4,
     "for (int32_t i = 1; i >= -2; i += -1)"},

    // Increasing negative counter with add increment.
    {-5, Cmp::kInt32LessThan, -2, Binop::kWord32Add, 1, 3,
     "for (int32_t i = -5; i < -2; i += 1)"},
    {-5, Cmp::kInt32LessThanOrEqual, -2, Binop::kWord32Add, 1, 4,
     "for (int32_t i = -5; i <= -2; i += 1)"},

    // Increasing positive counter with mul increment.
    {3, Cmp::kInt32LessThan, 13, Binop::kWord32Mul, 2, 3,
     "for (int32_t i = 3; i < 13;  i *= 2)"},
    {3, Cmp::kInt32LessThanOrEqual, 13, Binop::kWord32Mul, 2, 3,
     "for (int32_t i = 3; i <= 13; i *= 2)"},
};

static const BoundedLoop kLargeBoundedLoops[] = {
    // Increasing positive counter with add increment.
    {0, Cmp::kInt32LessThan, 4500, Binop::kWord32Add, 1, 4500,
     "for (int32_t i = 0; i < 4500; i += 1)"},
    {0, Cmp::kInt32LessThan, 1000000, Binop::kWord32Add, 1, 1000000,
     "for (int32_t i = 0; i < 1000000; i += 1)"},
    {0, Cmp::kUint32LessThan, 4500, Binop::kWord32Add, 1, 4500,
     "for (uint32_t i = 0; i < 4500; i += 1)"},
    {0, Cmp::kUint32LessThan, 1000000, Binop::kWord32Add, 1, 1000000,
     "for (uint32_t i = 0; i < 1000000; i += 1)"},

    // Decreasing counter with add increment.
    {700, Cmp::kInt32GreaterThan, -1000, Binop::kWord32Add, -2, 850,
     "for (int32_t i = 700; i > -1000; i += -1)"},
    {700, Cmp::kInt32GreaterThanOrEqual, -1000, Binop::kWord32Add, -2, 851,
     "for (int32_t i = 700; i >= -1000; i += -1)"},
};

static const BoundedLoop kUnderOverflowBoundedLoops[] = {
    // Increasing positive to negative with add increment and signed overflow.
    // Small loop.
    {std::numeric_limits<int32_t>::max() - 2, Cmp::kInt32GreaterThan,
     std::numeric_limits<int32_t>::min() + 10, Binop::kWord32Add, 1, 3,
     "for (int32_i = MAX_INT-2; i > MIN_INT+10; i += 1)"},
    {std::numeric_limits<int32_t>::max() - 2, Cmp::kInt32GreaterThanOrEqual,
     std::numeric_limits<int32_t>::min() + 10, Binop::kWord32Add, 1, 3,
     "for (int32_i = MAX_INT-2; i >= MIN_INT+10; i += 1)"},
    // Larger loop.
    {std::numeric_limits<int32_t>::max() - 100, Cmp::kInt32GreaterThan,
     std::numeric_limits<int32_t>::min() + 100, Binop::kWord32Add, 1, 200,
     "for (int32_i = MAX_INT-100; i > MIN_INT+100; i += 1)"},
    {std::numeric_limits<int32_t>::max() - 100, Cmp::kInt32GreaterThanOrEqual,
     std::numeric_limits<int32_t>::min() + 100, Binop::kWord32Add, 1, 201,
     "for (int32_i = MAX_INT-100; i >= MIN_INT+100; i += 1)"},

    // Decreasing negative to positive with add/sub increment and signed
    // underflow.
    // Small loop.
    {std::numeric_limits<int32_t>::min() + 2, Cmp::kInt32LessThan,
     std::numeric_limits<int32_t>::max() - 10, Binop::kWord32Add, -1, 3,
     "for (int32_t i = MIN_INT+2; i < MAX_INT-10; i += -1)"},
    {std::numeric_limits<int32_t>::min() + 2, Cmp::kInt32LessThan,
     std::numeric_limits<int32_t>::max() - 10, Binop::kWord32Sub, 1, 3,
     "for (int32_t i = MIN_INT+2; i < MAX_INT-10; i -= 1)"},
    {std::numeric_limits<int32_t>::min() + 2, Cmp::kInt32LessThanOrEqual,
     std::numeric_limits<int32_t>::max() - 10, Binop::kWord32Add, -1, 3,
     "for (int32_t i = MIN_INT+2; i <= MAX_INT-10; i += -1)"},
    {std::numeric_limits<int32_t>::min() + 2, Cmp::kInt32LessThanOrEqual,
     std::numeric_limits<int32_t>::max() - 10, Binop::kWord32Sub, 1, 3,
     "for (int32_t i = MIN_INT+2; i <= MAX_INT-10; i -= 1)"},
    // Large loop.
    {std::numeric_limits<int32_t>::min() + 100, Cmp::kInt32LessThan,
     std::numeric_limits<int32_t>::max() - 100, Binop::kWord32Add, -1, 200,
     "for (int32_t i = MIN_INT+100; i < MAX_INT-100; i -= 1)"},
    {std::numeric_limits<int32_t>::min() + 100, Cmp::kInt32LessThanOrEqual,
     std::numeric_limits<int32_t>::max() - 100, Binop::kWord32Add, -1, 201,
     "for (int32_t i = MIN_INT+100; i <= MAX_INT-100; i -= 1)"},
};

using LoopUnrollingAnalyzerSmallLoopTest =
    LoopUnrollingAnalyzerTestWithParam<BoundedLoop>;

// Checking that the LoopUnrollingAnalyzer correctly computes the number of
// iterations of small loops.
TEST_P(LoopUnrollingAnalyzerSmallLoopTest, ExactLoopIterCount) {
  BoundedLoop params = GetParam();
  auto test = CreateFromGraph(1, [&params](auto& Asm) {
    using AssemblerT = std::remove_reference<decltype(Asm)>::type::Assembler;
    OpIndex cond = Asm.GetParameter(0);

    ScopedVar<Word32, AssemblerT> index(&Asm, params.init);

    WHILE(EmitCmp(Asm, params.cmp, index, params.max)) {
      __ JSLoopStackCheck(__ NoContextConstant(), Asm.BuildFrameState());

      // Advance the {index}.
      index = EmitBinop(Asm, params.binop, index, params.increment);
    }

    __ Return(index);
  });

  LoopUnrollingAnalyzer analyzer(test.zone(), &test.graph(), false);
  auto stack_checks_to_remove = test.graph().stack_checks_to_remove();

  const Block& loop = GetFirstLoop(test.graph());
  ASSERT_EQ(1u, stack_checks_to_remove.size());
  EXPECT_TRUE(stack_checks_to_remove.contains(loop.index().id()));

  IterationCount iter_count = analyzer.GetIterationCount(&loop);
  ASSERT_TRUE(iter_count.IsExact());
  EXPECT_EQ(params.expected_iter_count, iter_count.exact_count());
}

INSTANTIATE_TEST_SUITE_P(LoopUnrollingAnalyzerTest,
                         LoopUnrollingAnalyzerSmallLoopTest,
                         ::testing::ValuesIn(kSmallBoundedLoops));

using LoopUnrollingAnalyzerLargeLoopTest =
    LoopUnrollingAnalyzerTestWithParam<BoundedLoop>;

// Checking that the LoopUnrollingAnalyzer correctly computes the number of
// iterations of small loops.
TEST_P(LoopUnrollingAnalyzerLargeLoopTest, LargeLoopIterCount) {
  BoundedLoop params = GetParam();
  auto test = CreateFromGraph(1, [&params](auto& Asm) {
    using AssemblerT = std::remove_reference<decltype(Asm)>::type::Assembler;
    OpIndex cond = Asm.GetParameter(0);

    ScopedVar<Word32, AssemblerT> index(&Asm, params.init);

    WHILE(EmitCmp(Asm, params.cmp, index, params.max)) {
      __ JSLoopStackCheck(__ NoContextConstant(), Asm.BuildFrameState());

      // Advance the {index}.
      index = EmitBinop(Asm, params.binop, index, params.increment);
    }

    __ Return(index);
  });

  LoopUnrollingAnalyzer analyzer(test.zone(), &test.graph(), false);
  auto stack_checks_to_remove = test.graph().stack_checks_to_remove();

  const Block& loop = GetFirstLoop(test.graph());

  if (params.expected_iter_count <=
      LoopUnrollingAnalyzer::kMaxIterForStackCheckRemoval) {
    EXPECT_EQ(1u, stack_checks_to_remove.size());
    EXPECT_TRUE(stack_checks_to_remove.contains(loop.index().id()));

    IterationCount iter_count = analyzer.GetIterationCount(&loop);
    ASSERT_TRUE(iter_count.IsApprox());
    EXPECT_TRUE(iter_count.IsSmallerThan(
        LoopUnrollingAnalyzer::kMaxIterForStackCheckRemoval));
  } else {
    EXPECT_EQ(0u, stack_checks_to_remove.size());
    EXPECT_FALSE(stack_checks_to_remove.contains(loop.index().id()));

    IterationCount iter_count = analyzer.GetIterationCount(&loop);
    ASSERT_TRUE(iter_count.IsApprox());
    EXPECT_FALSE(iter_count.IsSmallerThan(
        LoopUnrollingAnalyzer::kMaxIterForStackCheckRemoval));
  }
}

INSTANTIATE_TEST_SUITE_P(LoopUnrollingAnalyzerTest,
                         LoopUnrollingAnalyzerLargeLoopTest,
                         ::testing::ValuesIn(kLargeBoundedLoops));

using LoopUnrollingAnalyzerOverflowTest =
    LoopUnrollingAnalyzerTestWithParam<BoundedLoop>;

// Checking that the LoopUnrollingAnalyzer correctly computes the number of
// iterations of small loops.
TEST_P(LoopUnrollingAnalyzerOverflowTest, LargeLoopIterCount) {
  BoundedLoop params = GetParam();
  auto test = CreateFromGraph(1, [&params](auto& Asm) {
    using AssemblerT = std::remove_reference<decltype(Asm)>::type::Assembler;
    OpIndex cond = Asm.GetParameter(0);

    ScopedVar<Word32, AssemblerT> index(&Asm, params.init);

    WHILE(EmitCmp(Asm, params.cmp, index, params.max)) {
      __ JSLoopStackCheck(__ NoContextConstant(), Asm.BuildFrameState());

      // Advance the {index}.
      index = EmitBinop(Asm, params.binop, index, params.increment);
    }

    __ Return(index);
  });

  LoopUnrollingAnalyzer analyzer(test.zone(), &test.graph(), false);
  auto stack_checks_to_remove = test.graph().stack_checks_to_remove();

  const Block& loop = GetFirstLoop(test.graph());
  EXPECT_EQ(0u, stack_checks_to_remove.size());
  EXPECT_FALSE(stack_checks_to_remove.contains(loop.index().id()));

  IterationCount iter_count = analyzer.GetIterationCount(&loop);
  EXPECT_TRUE(iter_count.IsUnknown());
}

INSTANTIATE_TEST_SUITE_P(LoopUnrollingAnalyzerTest,
                         LoopUnrollingAnalyzerOverflowTest,
                         ::testing::ValuesIn(kUnderOverflowBoundedLoops));

#ifdef V8_ENABLE_WEBASSEMBLY
struct BoundedPartialLoop {
  int init;
  Cmp cmp;
  Binop binop;
  int max;
  uint32_t loop_body_size;
  uint32_t expected_unroll_count;
  const char* name;
};
std::ostream& operator<<(std::ostream& os, const BoundedPartialLoop& loop) {
  return os << loop.name;
}

static const BoundedPartialLoop kPartiallyUnrolledLoops[] = {
    {0, Cmp::kInt32LessThan, Binop::kWord32Add, 80, 8, 4,
     "for (int32_t i = 0;  i < 80;  i += 8)"},
    {0, Cmp::kInt32LessThan, Binop::kWord32Add, 160, 16, 4,
     "for (int32_t i = 0;  i < 160;  i += 16)"},
    {0, Cmp::kInt32LessThan, Binop::kWord32Add, 240, 24, 4,
     "for (int32_t i = 0;  i < 240;  i += 24)"},
    {0, Cmp::kInt32LessThan, Binop::kWord32Add, 320, 32, 3,
     "for (int32_t i = 0;  i < 320;  i += 32)"},
    {0, Cmp::kInt32LessThan, Binop::kWord32Add, 400, 40, 0,
     "for (int32_t i = 0;  i < 400;  i += 40)"},
};

using LoopUnrollingAnalyzerPartialUnrollTest =
    LoopUnrollingAnalyzerTestWithParam<BoundedPartialLoop>;

// Checking that the LoopUnrollingAnalyzer determines the partial unroll count
// base upon the size of the loop.
TEST_P(LoopUnrollingAnalyzerPartialUnrollTest, PartialUnrollCount) {
  BoundedPartialLoop params = GetParam();
  auto test = CreateFromGraph(1, [&params](auto& Asm) {
    using AssemblerT = std::remove_reference<decltype(Asm)>::type::Assembler;
    OpIndex cond = Asm.GetParameter(0);

    ScopedVar<Word32, AssemblerT> index(&Asm, params.init);

    WHILE(EmitCmp(Asm, params.cmp, index, params.max)) {
      __ WasmStackCheck(WasmStackCheckOp::Kind::kLoop);

      // Advance the {index} a number of times.
      for (uint32_t i = 0; i < params.loop_body_size; ++i) {
        index = EmitBinop(Asm, params.binop, index, 1);
      }
    }

    __ Return(index);
  });

  constexpr bool is_wasm = true;
  LoopUnrollingAnalyzer analyzer(test.zone(), &test.graph(), is_wasm);

  const Block& loop = GetFirstLoop(test.graph());
  EXPECT_EQ(analyzer.ShouldPartiallyUnrollLoop(&loop),
            params.expected_unroll_count != 0);
  if (analyzer.ShouldPartiallyUnrollLoop(&loop)) {
    EXPECT_EQ(params.expected_unroll_count,
              analyzer.GetPartialUnrollCount(&loop));
  }
}

INSTANTIATE_TEST_SUITE_P(LoopUnrollingAnalyzerTest,
                         LoopUnrollingAnalyzerPartialUnrollTest,
                         ::testing::ValuesIn(kPartiallyUnrolledLoops));
#endif  // V8_ENABLE_WEBASSEMBLY

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

"""

```