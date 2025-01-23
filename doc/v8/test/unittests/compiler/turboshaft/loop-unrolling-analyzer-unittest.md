Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Identify the Core Purpose:** The filename `loop-unrolling-analyzer-unittest.cc` immediately suggests this code tests the functionality of something called `LoopUnrollingAnalyzer`. The "unittest" part confirms it's a testing file.

2. **Look for Key Classes and Functions:**  Scan the code for class definitions. We see `LoopUnrollingAnalyzerTest` and `LoopUnrollingAnalyzerTestWithParam`. The latter uses `::testing::WithParamInterface`, indicating parameterized testing (testing the same logic with different inputs). The presence of `LoopUnrollingAnalyzer` (from the `#include`) is crucial.

3. **Understand the Test Setup:**  `ReducerTest` in the inheritance suggests this is testing a compiler optimization pass (reducers transform the intermediate representation of code). The `CreateFromGraph` function, taking a lambda, hints at constructing a control flow graph for testing.

4. **Focus on the Testing Logic:**  The code uses macros like `WHILE` and functions like `EmitCmp` and `EmitBinop`. These likely create the structure of loops and the operations within them in the test graph. The `BoundedLoop` struct and the `kSmallBoundedLoops`, `kLargeBoundedLoops`, etc. arrays clearly represent different loop scenarios used as test cases.

5. **Analyze the Test Cases:** Examine the `BoundedLoop` struct members: `init`, `cmp`, `max`, `binop`, `increment`, `expected_iter_count`, `name`, `expected_unroll_count`. These fields describe the initial value of a loop counter, the comparison condition, the loop termination value, the increment operation, the increment value, the expected number of iterations, a descriptive name, and the expected unroll count. This strongly suggests the analyzer's primary function is to determine loop characteristics.

6. **Connect the Dots to Loop Unrolling:** The name `LoopUnrollingAnalyzer` and the `expected_unroll_count` strongly link the code to the compiler optimization technique of loop unrolling. Loop unrolling aims to improve performance by reducing loop overhead.

7. **Infer Functionality:** Based on the structure and the test cases, we can deduce the `LoopUnrollingAnalyzer` analyzes loops in a compiler's intermediate representation (likely Turboshaft) and determines:
    * The number of iterations (exact or approximate).
    * Whether the loop is suitable for unrolling.
    * The optimal number of times to unroll the loop.

8. **Consider Edge Cases and Limitations:** The existence of `kUnderOverflowBoundedLoops` suggests testing scenarios where loop counters might overflow or underflow. The `kMaxIterForStackCheckRemoval` constant and the logic around it point to a limit on how large loops can be before stack checks are no longer removed. The `kPartiallyUnrolledLoops` and the `#ifdef V8_ENABLE_WEBASSEMBLY` indicate special handling for WebAssembly loops and partial unrolling.

9. **Relate to JavaScript (If Applicable):** Since V8 compiles JavaScript, it's natural to think about how this relates to JavaScript loops. Provide simple JavaScript `for` loop examples that correspond to the scenarios tested in the C++ code (e.g., increasing/decreasing counters, different comparison operators).

10. **Code Logic Reasoning (Hypothetical Inputs and Outputs):** Choose a simple test case from `kSmallBoundedLoops` and manually trace the loop's execution to confirm the `expected_iter_count`. Explain how the analyzer would likely process the loop's components (initial value, condition, increment) to arrive at this count.

11. **Common Programming Errors:** Think about typical mistakes developers make with loops that the analyzer might be relevant to. Infinite loops due to incorrect conditions or increments are a prime example. Also, consider less obvious errors that might impact optimization, such as unnecessarily complex loop conditions.

12. **Torque Consideration:** Note the comment about `.tq` files and Torque. Since the file doesn't end in `.tq`, it's not Torque. Briefly explain what Torque is in the V8 context (a domain-specific language for defining built-in functions).

13. **Structure the Answer:** Organize the findings logically:
    * Overall purpose.
    * Key functionalities.
    * Relationship to JavaScript (with examples).
    * Code logic reasoning (with a specific example).
    * Common programming errors.
    * Torque information.

By following this process of examining the filename, code structure, test cases, and comments, we can systematically understand the purpose and functionality of the provided C++ source code.
好的，让我们来分析一下 `v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc` 这个文件的功能。

**文件功能概述**

`v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc` 是 V8 引擎中 Turboshaft 编译器的单元测试文件。它专门用于测试 `LoopUnrollingAnalyzer` 类的功能。`LoopUnrollingAnalyzer` 的作用是分析循环结构，判断是否可以进行循环展开（loop unrolling）优化，并计算展开的次数。

**具体功能拆解**

1. **测试 LoopUnrollingAnalyzer 的核心功能:**  这个文件通过编写各种测试用例来验证 `LoopUnrollingAnalyzer` 是否能正确地：
    * **计算循环的迭代次数:**  测试用例中定义了不同类型的有界循环（bounded loops），包括递增、递减、正数、负数、以及可能发生溢出的情况。`LoopUnrollingAnalyzer` 需要能够准确或近似地计算出这些循环的迭代次数。
    * **判断循环是否可以展开:**  根据循环的特性（例如迭代次数、循环体大小），分析器需要判断是否值得进行循环展开。
    * **计算部分展开的次数 (Partial Unrolling):**  特别针对 WebAssembly 代码，分析器需要能根据循环体的大小，计算出适合进行部分展开的次数。
    * **移除不必要的栈检查 (Stack Check Removal):** 对于迭代次数较小的循环，分析器能够识别并移除不必要的栈溢出检查，以提高性能。

2. **定义测试辅助工具:** 文件中定义了一些辅助函数和宏来简化测试用例的编写：
    * `CountLoops(const Graph& graph)`:  计算给定控制流图中的循环数量。
    * `GetFirstLoop(const Graph& graph)`: 获取给定控制流图中的第一个循环块。
    * `EmitCmp`:  根据枚举 `Cmp` 生成不同的比较操作的节点。
    * `EmitBinop`: 根据枚举 `Binop` 生成不同的二元运算操作的节点。
    * `BoundedLoop` 结构体：定义了用于测试的有界循环的各种属性，例如初始值、比较条件、最大值、递增/递减操作、步长、期望的迭代次数等。
    * `BoundedPartialLoop` 结构体： 专门用于测试部分展开的循环，包含循环体大小等信息。

3. **使用参数化测试:**  使用了 Google Test 框架的参数化测试功能 (`::testing::WithParamInterface`)，允许用不同的输入参数（`BoundedLoop` 或 `BoundedPartialLoop` 结构体的实例）运行相同的测试逻辑，有效地覆盖各种循环场景。

**关于文件名的推断**

正如你所说，如果 `v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc` 以 `.tq` 结尾，那么它会是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义内置函数的一种领域特定语言。但由于这里是 `.cc` 结尾，所以它是一个 C++ 文件。

**与 Javascript 的关系**

虽然这个文件本身是 C++ 代码，但它测试的 `LoopUnrollingAnalyzer` 是 Turboshaft 编译器的一部分，而 Turboshaft 编译器负责编译 JavaScript 代码。循环展开是一种常见的编译器优化技术，可以提高 JavaScript 代码的执行效率。

**JavaScript 示例**

考虑以下简单的 JavaScript 循环：

```javascript
let sum = 0;
for (let i = 0; i < 10; i++) {
  sum += i;
}
```

`LoopUnrollingAnalyzer` 的目标就是分析像这样的循环，并决定是否以及如何进行展开。例如，可以将循环展开 2 次，变成类似下面的形式（这只是一个概念上的例子，实际编译器生成的代码会更复杂）：

```javascript
let sum = 0;
for (let i = 0; i < 10; i += 2) {
  sum += i;
  if (i + 1 < 10) {
    sum += (i + 1);
  }
}
```

通过展开循环，可以减少循环的条件判断和跳转次数，从而提高性能。

**代码逻辑推理 (假设输入与输出)**

假设我们有一个 `BoundedLoop` 的实例：

```c++
{0, Cmp::kInt32LessThan, 3, Binop::kWord32Add, 1, 3, "for (int32_t i = 0;  i < 3;  i += 1)"}
```

对应于以下 C++ 风格的 for 循环：

```c++
for (int32_t i = 0; i < 3; i += 1) {
  // 循环体
}
```

**假设输入:**  将上述 `BoundedLoop` 实例作为参数传递给 `LoopUnrollingAnalyzer` 进行分析。

**预期输出:**

* **`GetIterationCount()`:**  分析器应该返回 `IterationCount`，并且 `IsExact()` 为真，`exact_count()` 的值为 3。
* **`ShouldPartiallyUnrollLoop()`:** 对于这个较小的循环，如果是非 WebAssembly 代码，分析器可能不会建议部分展开，所以返回 `false`。
* **`GetPartialUnrollCount()`:**  如果 `ShouldPartiallyUnrollLoop()` 返回 `false`，则此方法的返回值可能不重要，或者返回 0。
* **栈检查移除:**  由于迭代次数较小，分析器应该会标记这个循环的栈检查可以被移除。

**涉及用户常见的编程错误**

1. **死循环:**  循环条件永远为真，导致程序无法终止。`LoopUnrollingAnalyzer` 虽然不能直接阻止死循环的发生，但它可以帮助识别出迭代次数非常大以至于超出优化范围的循环，这可能是死循环的一个迹象。

   ```javascript
   // 常见的死循环错误
   let i = 0;
   while (i >= 0) { // 错误的条件，i 永远大于等于 0
     console.log(i);
     i++;
   }
   ```

2. **循环边界条件错误 (Off-by-one error):**  循环执行的次数比预期多一次或少一次。`LoopUnrollingAnalyzer` 通过精确计算迭代次数，可以帮助开发者理解循环的实际执行次数，从而更容易发现这类错误。

   ```javascript
   // 边界条件错误，本意是循环 10 次，但实际只循环了 9 次
   for (let i = 0; i < 10; i++) {
     if (i === 9) {
       // 最后一次循环的特殊处理，但由于条件是 < 10，所以 i=9 是倒数第二次循环
     }
   }
   ```

3. **整数溢出:**  循环计数器超出其数据类型的最大值或最小值。测试用例中包含了 `kUnderOverflowBoundedLoops`，就是为了测试分析器在面对可能发生溢出的循环时的行为。

   ```javascript
   // 整数溢出 (JavaScript 中 Number 类型可以表示大整数，但如果使用特定的位运算可能会出现类似问题)
   let count = 2147483647; // 32位有符号整数的最大值
   for (let i = 0; i < 5; i++) {
     count++; // count 会溢出变成负数
     console.log(count);
   }
   ```

**总结**

`v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc` 是一个关键的测试文件，用于确保 V8 引擎的 Turboshaft 编译器能够正确地分析和优化循环结构，特别是关于循环展开的决策。它通过各种精心设计的测试用例，覆盖了不同类型的循环场景，并验证了分析器计算迭代次数、判断展开可行性以及计算展开次数的功能。这对于提升 V8 编译后的 JavaScript 代码的性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/turboshaft/loop-unrolling-analyzer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```