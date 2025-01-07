Response:
Let's break down the thought process to analyze the given C++ code.

1. **Understand the Goal:** The core purpose is stated in the initial comment: to test the "merge" of an arithmetic operation and a comparison within a `select` operation in Turboshaft (V8's compiler). This immediately tells us it's a test file for compiler optimizations.

2. **Identify the Key Components:**  The code defines several enums and a templated class. These are the building blocks of the tests.

    * `GraphConfig`: Defines different ways the generated code graph can be structured (single use, two uses in one block, two uses in different blocks). This suggests testing different scenarios for the optimization.
    * `SelectOperator`: Lists the different `select` operations being tested (word32, word64, float32, float64).
    * `ConditionalSelectGen`:  The main class responsible for generating the test code. It's templated on the condition type and result type, indicating it's designed to handle different data types.

3. **Analyze `ConditionalSelectGen`:** This is the heart of the code. Let's break down its methods:

    * `BuildGraph`:  This is where the test graph is constructed. It takes a `SelectOperator` and input values and calls `CompareAndSelect`. The `switch` statement based on `config_` indicates different graph layouts are being created.
    * `CompareAndSelect`:  Generates the binary operation, compares the result to zero, and then creates the `select` operation. This directly implements the optimization scenario being tested.
    * `AddBranchAndUse`: This method specifically handles the `kTwoUsesTwoBlocks` case. It introduces a conditional branch based on the result of the `select` operation. This is important for testing how the optimization handles control flow.
    * `expected`: This method calculates the *expected* result of the generated code. This is crucial for verifying the correctness of the optimization. It simulates the operations performed in the generated graph. The logic within the `expected` method needs careful examination to understand the tested scenario.
    * `AddBinopUse`:  An abstract method that's implemented by the derived classes. It determines how the result of the binary operation is used in addition to the `select` operation.
    * `Is32`: Another abstract method indicating whether the underlying data type is 32-bit.

4. **Analyze Derived Classes (`UInt32ConditionalSelectGen`, `UInt64ConditionalSelectGen`):** These classes provide concrete implementations for the abstract methods in `ConditionalSelectGen`. They specify how the binary operation's result is used based on the `SelectOperator`. Note the type conversions happening here (e.g., `ChangeUint32ToFloat32`).

5. **Examine the `TEST` Macros:** These are the actual test cases. Each test focuses on a specific combination of `SelectOperator` and compare/binary operation types.

    * The tests iterate through different `GraphConfig`s, compare operations, and binary operations. This shows a systematic approach to testing various scenarios.
    * Inside each test, a `BufferedRawMachineAssemblerTester` is created. This is V8's testing framework for generating machine code.
    * The `FOR_UINT32_INPUTS` and `FOR_UINT64_INPUTS` macros indicate the test uses a range of input values to ensure robustness.
    * The `CHECK_EQ` and `CHECK_FLOAT_EQ`/`CHECK_DOUBLE_EQ` macros are used to compare the actual result of the generated code with the expected result calculated by the `expected` method.

6. **Infer Functionality:** Based on the structure and components, we can deduce the functionality: The code tests whether the Turboshaft compiler can combine a binary arithmetic operation (like addition, subtraction, etc.) followed by a comparison with zero into a single operation when used by a `select` instruction. This is a common compiler optimization to reduce the number of instructions. The different `GraphConfig` options explore how this optimization works in different control flow scenarios.

7. **Consider `.tq` Extension:** The comment explicitly mentions the `.tq` extension indicating Torque. While this file is `.cc`, the comment serves as a reminder that *similar* logic could be implemented using Torque, V8's type-safe dialect.

8. **Relate to JavaScript:**  Since this is about compiler optimizations, it directly impacts the performance of JavaScript code. Any JavaScript code that involves conditional logic based on the result of an arithmetic operation is a potential candidate for this optimization.

9. **Generate JavaScript Examples:**  Think of common JavaScript patterns that would trigger this. `if` statements based on arithmetic results are the most obvious.

10. **Consider Code Logic and Assumptions:** The `expected` function is key to understanding the assumptions. It directly calculates the expected outcome based on standard arithmetic and comparison rules.

11. **Think about Common Errors:**  Since the optimization is about combining operations, a common error *before* the optimization might be redundant calculations or separate comparison and selection steps. The optimization aims to prevent this.

By following this systematic analysis, we can accurately describe the functionality of the C++ code and relate it to JavaScript and common programming scenarios.
这个C++源代码文件 `v8/test/cctest/compiler/turboshaft-test-select-combine.cc` 的主要功能是**测试 Turboshaft 编译器中的一种优化，即如何将二元运算（如加法、减法等）与随后的与零比较以及条件选择（select）操作进行合并**。

以下是更详细的解释：

**1. 功能概述:**

该测试文件的目的是验证 Turboshaft 编译器能否有效地将以下模式的代码结构进行优化：

* 计算一个二元运算的结果（例如，`a + b`）。
* 将该结果与零进行比较。
* 基于比较的结果，从两个不同的值中选择一个（使用 `select` 操作）。

这种模式在编程中很常见，尤其是在实现条件逻辑时。编译器如果能将这些操作合并成更高效的机器指令，就能提高代码的执行效率。

**2. 测试场景:**

为了全面测试这种优化，该文件针对多种不同的场景进行了测试：

* **不同的选择操作类型:**  测试了针对 32 位整数 (`Word32Select`)、64 位整数 (`Word64Select`)、32 位浮点数 (`Float32Select`) 和 64 位浮点数 (`Float64Select`) 的选择操作。
* **不同的二元运算:** 测试了加法 (`add`)、减法 (`sub`)、乘法 (`mul`)、按位与 (`and`)、按位或 (`or`) 和按位异或 (`xor`) 等二元运算。
* **不同的数据类型:** 测试了 `int32_t`、`uint32_t`、`int64_t`、`uint64_t`、`float` 和 `double` 等数据类型。
* **二元运算结果的使用方式:**
    * **单次使用 (`kOneUse`):** 二元运算的结果仅被用于比较和选择操作。
    * **多次使用 (`kTwoUsesOneBlock`, `kTwoUsesTwoBlocks`):** 二元运算的结果除了用于比较和选择外，还被用于其他操作（例如加法）。这测试了在有多个使用者的情况下，编译器是否仍然能进行优化。 `kTwoUsesTwoBlocks` 特别测试了在不同的代码块中使用的情况。
* **不同的比较条件:**  测试了等于零、小于零、小于等于零等不同的比较条件。

**3. 代码结构:**

* **`GraphConfig` 枚举:** 定义了测试图中二元运算结果的不同使用方式（单次使用、多次使用在同一代码块、多次使用在不同代码块）。
* **`SelectOperator` 枚举:** 列出了要测试的不同类型的选择操作。
* **`ConditionalSelectGen` 模板类:**  这是一个核心的模板类，用于生成测试代码。它接受比较操作、二元运算等参数，并根据不同的 `GraphConfig` 构建不同的代码图。
* **派生类 (`UInt32ConditionalSelectGen`, `UInt64ConditionalSelectGen`):**  这些类继承自 `ConditionalSelectGen`，并针对特定的数据类型提供了 `AddBinopUse` 方法的实现，该方法定义了如何使用二元运算的结果。
* **`TEST` 宏:**  使用了 Google Test 框架的 `TEST` 宏来定义具体的测试用例。每个测试用例都针对特定的选择操作类型、比较操作和二元运算组合。

**4. 与 JavaScript 的关系:**

虽然这个文件是 C++ 代码，但它测试的是 V8 JavaScript 引擎的编译器优化。当 JavaScript 代码中出现类似的模式时，Turboshaft 编译器就可能会应用这种合并优化。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
function test(a, b, c, d) {
  const result = a + b;
  if (result > 0) {
    return c;
  } else {
    return d;
  }
}

console.log(test(5, -2, 10, 20)); // 输出 10
console.log(test(-5, -2, 10, 20)); // 输出 20
```

在这个例子中：

* `a + b` 是一个二元运算。
* `result > 0` 是将运算结果与零进行比较。
* `return c` 和 `return d` 是基于比较结果的选择。

Turboshaft 编译器在编译这段 JavaScript 代码时，就可能会尝试将加法运算和大于零的比较以及条件返回操作进行合并优化，从而提高性能。

**5. 代码逻辑推理 (假设输入与输出):**

以 `TEST(Word32SelectCombineInt32CompareZero)` 中的一个迭代为例：

* **假设输入:** `a = 5`, `b = -2`, `tval = 2`, `fval = 1`
* **二元运算:** `bin = a + b = 5 + (-2) = 3`
* **比较:**  假设比较操作是 `TurboshaftComparison::kInt32LessThan` (小于零)。那么 `3 < 0` 的结果是 `false`。
* **选择操作 (`Word32Select`):**  如果条件为 `false`，则选择 `fval`。
* **单次使用 (`kOneUse`):**  预期输出为 `fval`，即 `1`。
* **多次使用 (`kTwoUsesOneBlock`):** 预期输出为 `select_result + bin_result = 1 + 3 = 4`。
* **多次使用 (`kTwoUsesTwoBlocks`):**  根据条件判断，可能返回 `select_result` 或 `select_result + bin_result`。

**6. 涉及用户常见的编程错误 (与优化相关):**

虽然这个测试文件本身不直接涉及用户编程错误，但它所测试的优化可以帮助提升性能，即使在用户编写了可能略有冗余的代码时。 例如：

* **冗余的比较和选择:** 用户可能会写出类似先计算一个值，然后比较，再选择的代码，而编译器可以将这些步骤合并。

**示例 (JavaScript - 虽然不是错误，但优化可以提升效率):**

```javascript
function calculateAndChoose(x, y, trueValue, falseValue) {
  const sum = x + y;
  if (sum > 0) {
    return trueValue;
  } else {
    return falseValue;
  }
}
```

编译器可以优化这个过程，避免显式地将 `sum` 存储到一个临时变量中，而是直接在比较和选择操作中使用 `x + y` 的结果。

**总结:**

`v8/test/cctest/compiler/turboshaft-test-select-combine.cc` 是一个关键的测试文件，用于验证 Turboshaft 编译器在处理涉及二元运算、零比较和条件选择的代码模式时的优化能力。它通过构建各种不同的测试场景，确保编译器能够正确且高效地进行这些优化，从而提升 JavaScript 代码的性能。

**关于 `.tq` 结尾:**

你提到的如果文件以 `.tq` 结尾，则它是 v8 Torque 源代码。这是正确的。Torque 是 V8 用来编写一些底层运行时代码的领域特定语言。这个文件是 `.cc` 结尾，所以它是标准的 C++ 源代码。 该注释只是提醒读者 Torque 也是 V8 开发中常用的语言。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-test-select-combine.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/turboshaft-test-select-combine.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/compiler/turboshaft-codegen-tester.h"
#include "test/common/value-helper.h"

namespace v8::internal::compiler::turboshaft {

// Generates a binop arithmetic instruction, followed by an integer compare zero
// and select. This is to test a possible merge of the arithmetic op and the
// compare for use by the select. We test a matrix of configurations:
// - floating-point and integer select.
// - add, sub, mul, and, or and xor.
// - int32, uint32t, int64_t, uint64_t, float and double.
// - one or multiple users of the binary operation.
// - two different graph layouts (single block vs three blocks).

namespace {

enum GraphConfig { kOneUse, kTwoUsesOneBlock, kTwoUsesTwoBlocks };
constexpr GraphConfig graph_configs[] = {GraphConfig::kOneUse,
                                         GraphConfig::kTwoUsesOneBlock,
                                         GraphConfig::kTwoUsesTwoBlocks};

#define SELECT_OP_LIST(V) \
  V(Word32Select)         \
  V(Word64Select)         \
  V(Float32Select)        \
  V(Float64Select)

enum class SelectOperator {
#define DEF(kind) k##kind,
  SELECT_OP_LIST(DEF)
#undef DEF
};

bool SelectIsSupported(SelectOperator op) {
  // SupportedOperations::Initialize is usually called by the Turboshaft
  // Assembler, but some tests use this function before having created an
  // Assembler, so we manually call it here to make sure that the
  // SupportedOperations list is indeed initialized.
  SupportedOperations::Initialize();

  switch (op) {
    case SelectOperator::kWord32Select:
      return SupportedOperations::word32_select();
    case SelectOperator::kWord64Select:
      return SupportedOperations::word64_select();
    case SelectOperator::kFloat32Select:
      return SupportedOperations::float32_select();
    case SelectOperator::kFloat64Select:
      return SupportedOperations::float64_select();
  }
}

// kOneUse:
// (bin_res = binop lhs, rhs)
// (return (select (compare bin_res, zero, cond), tval, fval))
//
// kTwoUsesOneBlock:
// (bin_res = binop lhs, rhs)
// (return (add (select (compare bin_res, zero, cond), tval, fval), bin_res))
//
// kTwoUsesTwoBlocks:
// Same as above, but the final addition is conditionally executed in a
// different block.
// (bin_res = binop lhs, rhs)
// (select_res = (select (compare bin_res, zero, cond), tval, fval))
// (select_res >= tval)
//   ? (return select_res)
//   : (return (add select_res, bin_res))

template <typename CondType, typename ResultType>
class ConditionalSelectGen {
 public:
  ConditionalSelectGen(BufferedRawMachineAssemblerTester<ResultType>& m,
                       GraphConfig c, TurboshaftComparison icmp_op,
                       TurboshaftBinop bin_op)
      : m_(m),
        config_(c),
        cmpw_(icmp_op),
        binw_(bin_op),
        blocka_(m.NewBlock()),
        blockb_(m.NewBlock()) {}

  void BuildGraph(SelectOperator select_op, OpIndex lhs, OpIndex rhs,
                  OpIndex tval, OpIndex fval) {
    CompareAndSelect(select_op, lhs, rhs, tval, fval);

    switch (config()) {
      case GraphConfig::kOneUse:
        m().Return(select());
        break;
      case GraphConfig::kTwoUsesOneBlock:
        m().Return(AddBinopUse());
        break;
      case GraphConfig::kTwoUsesTwoBlocks:
        m().Return(AddBranchAndUse());
        break;
      default:
        UNREACHABLE();
    }
  }

  void CompareAndSelect(SelectOperator selectop, OpIndex lhs, OpIndex rhs,
                        OpIndex tval, OpIndex fval) {
    OpIndex zero = Is32()
                       ? OpIndex{m().Word32Constant(0)}
                       : OpIndex{m().Word64Constant(static_cast<uint64_t>(0))};
    bin_node_ = binw().MakeNode(m(), lhs, rhs);
    OpIndex cond = cmpw().MakeNode(m(), bin_node(), zero);
    select_ = MakeSelect(selectop, cond, tval, fval);
    select_op_ = selectop;
  }

  OpIndex AddBranchAndUse() {
    OpIndex cond_second_input =
        m().Get(select()).template Cast<SelectOp>().vtrue();
    V<Word32> cond;
    switch (select_op()) {
      case SelectOperator::kFloat32Select:
        cond = m().Float32LessThan(select(), cond_second_input);
        break;
      case SelectOperator::kFloat64Select:
        cond = m().Float64LessThan(select(), cond_second_input);
        break;
      case SelectOperator::kWord32Select:
        cond = m().Int32LessThan(select(), cond_second_input);
        break;
      case SelectOperator::kWord64Select:
        cond = m().Int64LessThan(select(), cond_second_input);
        break;
    }
    m().Branch(cond, blocka(), blockb());
    m().Bind(blocka());
    OpIndex res = AddBinopUse();
    m().Return(res);
    m().Bind(blockb());
    return select();
  }

  ResultType expected(CondType lhs, CondType rhs, ResultType tval,
                      ResultType fval) {
    CondType bin_node_res = binw().eval(lhs, rhs);
    ResultType res =
        Is32() ? cmpw().Int32Compare(static_cast<uint32_t>(bin_node_res), 0)
                     ? tval
                     : fval
        : cmpw().Int64Compare(static_cast<uint64_t>(bin_node_res), 0) ? tval
                                                                      : fval;
    if (config() == GraphConfig::kTwoUsesTwoBlocks && res >= tval) {
      return res;
    }
    if (config() != GraphConfig::kOneUse) {
      res += static_cast<ResultType>(bin_node_res);
    }
    return res;
  }

  BufferedRawMachineAssemblerTester<ResultType>& m() { return m_; }
  GraphConfig config() const { return config_; }
  IntBinopWrapper<CondType>& binw() { return binw_; }
  CompareWrapper& cmpw() { return cmpw_; }
  OpIndex select() const { return select_; }
  SelectOperator select_op() const { return select_op_; }
  OpIndex bin_node() const { return bin_node_; }
  Block* blocka() { return blocka_; }
  Block* blockb() { return blockb_; }

  virtual OpIndex AddBinopUse() = 0;
  virtual bool Is32() const = 0;

 private:
  OpIndex MakeSelect(SelectOperator op, OpIndex cond, OpIndex vtrue,
                     OpIndex vfalse) {
    switch (op) {
#define CASE(kind)              \
  case SelectOperator::k##kind: \
    return m().kind(cond, vtrue, vfalse);
      SELECT_OP_LIST(CASE)
#undef CASE
    }
  }

  BufferedRawMachineAssemblerTester<ResultType>& m_;
  GraphConfig config_;
  CompareWrapper cmpw_;
  IntBinopWrapper<CondType> binw_;
  OpIndex bin_node_;
  OpIndex select_;
  SelectOperator select_op_;
  Block *blocka_, *blockb_;
};

template <typename ResultType>
class UInt32ConditionalSelectGen
    : public ConditionalSelectGen<uint32_t, ResultType> {
 public:
  using ConditionalSelectGen<uint32_t, ResultType>::ConditionalSelectGen;

  OpIndex AddBinopUse() override {
    BufferedRawMachineAssemblerTester<ResultType>& m = this->m();
    switch (this->select_op()) {
      case SelectOperator::kFloat32Select:
        return m.Float32Add(this->select(),
                            m.ChangeUint32ToFloat32(this->bin_node()));
      case SelectOperator::kFloat64Select:
        return m.Float64Add(this->select(),
                            m.ChangeUint32ToFloat64(this->bin_node()));
      case SelectOperator::kWord32Select:
        return m.Word32Add(this->select(), this->bin_node());
      case SelectOperator::kWord64Select:
        return m.Word64Add(this->select(),
                           m.ChangeUint32ToUint64(this->bin_node()));
    }
  }

  bool Is32() const override { return true; }
};

template <typename ResultType>
class UInt64ConditionalSelectGen
    : public ConditionalSelectGen<uint64_t, ResultType> {
 public:
  using ConditionalSelectGen<uint64_t, ResultType>::ConditionalSelectGen;

  OpIndex AddBinopUse() override {
    BufferedRawMachineAssemblerTester<ResultType>& m = this->m();
    switch (this->select_op()) {
      case SelectOperator::kFloat32Select:
        return m.Float32Add(this->select(),
                            m.ChangeUint64ToFloat32(this->bin_node()));
      case SelectOperator::kFloat64Select:
        return m.Float64Add(this->select(),
                            m.ChangeUint64ToFloat64(this->bin_node()));
      case SelectOperator::kWord32Select:
        return m.Word32Add(this->select(),
                           m.TruncateWord64ToWord32(this->bin_node()));
      case SelectOperator::kWord64Select:
        return m.Word64Add(this->select(), this->bin_node());
    }
  }

  bool Is32() const override { return false; }
};

constexpr TurboshaftComparison int32_cmp_opcodes[] = {
    TurboshaftComparison::kWord32Equal, TurboshaftComparison::kInt32LessThan,
    TurboshaftComparison::kInt32LessThanOrEqual,
    TurboshaftComparison::kUint32LessThan,
    TurboshaftComparison::kUint32LessThanOrEqual};
constexpr TurboshaftBinop int32_bin_opcodes[] = {
    TurboshaftBinop::kWord32Add,       TurboshaftBinop::kWord32Sub,
    TurboshaftBinop::kWord32Mul,       TurboshaftBinop::kWord32BitwiseAnd,
    TurboshaftBinop::kWord32BitwiseOr, TurboshaftBinop::kWord32BitwiseXor,
};

TEST(Word32SelectCombineInt32CompareZero) {
  if (!SelectIsSupported(SelectOperator::kWord32Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int32_cmp_opcodes) {
      for (auto bin : int32_bin_opcodes) {
        BufferedRawMachineAssemblerTester<uint32_t> m(
            MachineType::Uint32(), MachineType::Uint32(), MachineType::Int32(),
            MachineType::Int32());
        UInt32ConditionalSelectGen<uint32_t> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kWord32Select, lhs, rhs, tval, fval);

        FOR_UINT32_INPUTS(a) {
          FOR_UINT32_INPUTS(b) {
            uint32_t expected = gen.expected(a, b, 2, 1);
            uint32_t actual = m.Call(a, b, 2, 1);
            CHECK_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Word64SelectCombineInt32CompareZero) {
  if (!SelectIsSupported(SelectOperator::kWord64Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int32_cmp_opcodes) {
      for (auto bin : int32_bin_opcodes) {
        BufferedRawMachineAssemblerTester<uint64_t> m(
            MachineType::Uint32(), MachineType::Uint32(), MachineType::Uint64(),
            MachineType::Uint64());
        UInt32ConditionalSelectGen<uint64_t> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kWord64Select, lhs, rhs, tval, fval);

        FOR_UINT32_INPUTS(a) {
          FOR_UINT32_INPUTS(b) {
            uint64_t c = 2;
            uint64_t d = 1;
            uint64_t expected = gen.expected(a, b, c, d);
            uint64_t actual = m.Call(a, b, c, d);
            CHECK_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Float32SelectCombineInt32CompareZero) {
  if (!SelectIsSupported(SelectOperator::kFloat32Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int32_cmp_opcodes) {
      for (auto bin : int32_bin_opcodes) {
        BufferedRawMachineAssemblerTester<float> m(
            MachineType::Uint32(), MachineType::Uint32(),
            MachineType::Float32(), MachineType::Float32());
        UInt32ConditionalSelectGen<float> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kFloat32Select, lhs, rhs, tval, fval);

        FOR_UINT32_INPUTS(a) {
          FOR_UINT32_INPUTS(b) {
            float expected = gen.expected(a, b, 2.0f, 1.0f);
            float actual = m.Call(a, b, 2.0f, 1.0f);
            CHECK_FLOAT_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Float64SelectCombineInt32CompareZero) {
  if (!SelectIsSupported(SelectOperator::kFloat64Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int32_cmp_opcodes) {
      for (auto bin : int32_bin_opcodes) {
        BufferedRawMachineAssemblerTester<double> m(
            MachineType::Uint32(), MachineType::Uint32(),
            MachineType::Float64(), MachineType::Float64());
        UInt32ConditionalSelectGen<double> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kFloat64Select, lhs, rhs, tval, fval);

        FOR_UINT32_INPUTS(a) {
          FOR_UINT32_INPUTS(b) {
            double expected = gen.expected(a, b, 2.0, 1.0);
            double actual = m.Call(a, b, 2.0, 1.0);
            CHECK_DOUBLE_EQ(expected, actual);
          }
        }
      }
    }
  }
}

constexpr TurboshaftBinop int64_bin_opcodes[] = {
    TurboshaftBinop::kWord64Add,       TurboshaftBinop::kWord64Sub,
    TurboshaftBinop::kWord64Mul,       TurboshaftBinop::kWord64BitwiseAnd,
    TurboshaftBinop::kWord64BitwiseOr, TurboshaftBinop::kWord64BitwiseXor,
};
constexpr TurboshaftComparison int64_cmp_opcodes[] = {
    TurboshaftComparison::kWord64Equal, TurboshaftComparison::kInt64LessThan,
    TurboshaftComparison::kInt64LessThanOrEqual,
    TurboshaftComparison::kUint64LessThan,
    TurboshaftComparison::kUint64LessThanOrEqual};

TEST(Word32SelectCombineInt64CompareZero) {
  RawMachineAssemblerTester<int32_t> features(MachineType::Int32());
  if (!SelectIsSupported(SelectOperator::kWord32Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int64_cmp_opcodes) {
      for (auto bin : int64_bin_opcodes) {
        BufferedRawMachineAssemblerTester<uint32_t> m(
            MachineType::Uint64(), MachineType::Uint64(), MachineType::Int32(),
            MachineType::Int32());
        UInt64ConditionalSelectGen<uint32_t> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kWord32Select, lhs, rhs, tval, fval);

        FOR_UINT64_INPUTS(a) {
          FOR_UINT64_INPUTS(b) {
            uint32_t expected = gen.expected(a, b, 2, 1);
            uint32_t actual = m.Call(a, b, 2, 1);
            CHECK_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Word64SelectCombineInt64CompareZero) {
  RawMachineAssemblerTester<uint32_t> features(MachineType::Uint32());
  if (!SelectIsSupported(SelectOperator::kWord64Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int64_cmp_opcodes) {
      for (auto bin : int64_bin_opcodes) {
        BufferedRawMachineAssemblerTester<uint64_t> m(
            MachineType::Uint64(), MachineType::Uint64(), MachineType::Uint64(),
            MachineType::Uint64());
        UInt64ConditionalSelectGen<uint64_t> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kWord64Select, lhs, rhs, tval, fval);

        FOR_UINT64_INPUTS(a) {
          FOR_UINT64_INPUTS(b) {
            uint64_t c = 2;
            uint64_t d = 1;
            uint64_t expected = gen.expected(a, b, c, d);
            uint64_t actual = m.Call(a, b, c, d);
            CHECK_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Float32SelectCombineInt64CompareZero) {
  RawMachineAssemblerTester<uint32_t> features(MachineType::Uint32());
  if (!SelectIsSupported(SelectOperator::kFloat32Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int64_cmp_opcodes) {
      for (auto bin : int64_bin_opcodes) {
        BufferedRawMachineAssemblerTester<float> m(
            MachineType::Uint64(), MachineType::Uint64(),
            MachineType::Float32(), MachineType::Float32());
        UInt64ConditionalSelectGen<float> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kFloat32Select, lhs, rhs, tval, fval);

        FOR_UINT64_INPUTS(a) {
          FOR_UINT64_INPUTS(b) {
            float expected = gen.expected(a, b, 2.0f, 1.0f);
            float actual = m.Call(a, b, 2.0f, 1.0f);
            CHECK_FLOAT_EQ(expected, actual);
          }
        }
      }
    }
  }
}

TEST(Float64SelectCombineInt64CompareZero) {
  RawMachineAssemblerTester<uint32_t> features(MachineType::Uint32());
  if (!SelectIsSupported(SelectOperator::kFloat64Select)) {
    return;
  }

  for (auto config : graph_configs) {
    for (auto cmp : int64_cmp_opcodes) {
      for (auto bin : int64_bin_opcodes) {
        BufferedRawMachineAssemblerTester<double> m(
            MachineType::Uint64(), MachineType::Uint64(),
            MachineType::Float64(), MachineType::Float64());
        UInt64ConditionalSelectGen<double> gen(m, config, cmp, bin);
        OpIndex lhs = m.Parameter(0);
        OpIndex rhs = m.Parameter(1);
        OpIndex tval = m.Parameter(2);
        OpIndex fval = m.Parameter(3);
        gen.BuildGraph(SelectOperator::kFloat64Select, lhs, rhs, tval, fval);

        FOR_UINT64_INPUTS(a) {
          FOR_UINT64_INPUTS(b) {
            double expected = gen.expected(a, b, 2.0, 1.0);
            double actual = m.Call(a, b, 2.0, 1.0);
            CHECK_DOUBLE_EQ(expected, actual);
          }
        }
      }
    }
  }
}

}  // end namespace

}  // namespace v8::internal::compiler::turboshaft

"""

```