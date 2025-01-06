Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The initial comments clearly state the primary objective: testing the "select combine" optimization in Turboshaft. This involves combining an arithmetic operation, a comparison with zero, and a select operation into a more efficient single operation.

2. **Identify Key Data Structures and Concepts:**
    * **`GraphConfig` enum:**  This controls different ways the generated code uses the result of the binary operation (one use, two uses in one block, two uses in separate blocks). This suggests testing how the optimization works under varying usage patterns.
    * **`SelectOperator` enum:** Lists the different `select` operations being tested (Word32, Word64, Float32, Float64). This indicates the optimization targets different data types.
    * **`ConditionalSelectGen` template class:** This is the core code generation logic. It takes the result type and condition type as template parameters and seems to build the instruction sequence described in the initial comment.
    * **`BufferedRawMachineAssemblerTester`:** This class (from the `test` directory) is used to generate machine code snippets for testing. It takes the input and output types of the generated code.
    * **`TurboshaftComparison` and `TurboshaftBinop` enums:** These likely represent different comparison and binary arithmetic operations supported by the Turboshaft compiler.
    * **`OpIndex`:** This probably represents an index or handle to an operation within the generated graph.
    * **`Block*`:**  Used for control flow, suggesting the tests cover scenarios with branching.
    * **`FOR_UINT32_INPUTS` and `FOR_UINT64_INPUTS` macros:** These are for iterating through various input values for testing.
    * **`CHECK_EQ`, `CHECK_FLOAT_EQ`, `CHECK_DOUBLE_EQ`:** These are assertion macros used to verify the generated code produces the expected results.

3. **Analyze the Code Generation Logic (`ConditionalSelectGen`):**
    * The constructor takes the assembler, graph configuration, comparison operator, and binary operator as arguments.
    * `BuildGraph` orchestrates the generation of the instruction sequence based on the `GraphConfig`.
    * `CompareAndSelect` generates the binary operation, the comparison with zero, and the `select` operation.
    * `AddBranchAndUse` and `AddBinopUse` handle the different usage scenarios defined by `GraphConfig`.
    * The `expected` method calculates the expected result of the generated code for verification.
    * The derived classes `UInt32ConditionalSelectGen` and `UInt64ConditionalSelectGen` specialize the `AddBinopUse` method to handle type conversions when the binary operation and select result have different types.

4. **Examine the Test Cases:**
    * The `TEST` macros define individual test cases.
    * Each test case iterates through different `GraphConfig`, comparison operators, and binary operators.
    * They create a `BufferedRawMachineAssemblerTester` instance with appropriate input/output types.
    * They instantiate the relevant `ConditionalSelectGen` specialization.
    * They call `BuildGraph` to generate the code.
    * They use the `FOR_UINT*INPUTS` macros to test with various input values.
    * They compare the `expected` result with the `actual` result obtained by calling the generated code using the assembler's `Call` method.

5. **Identify the Connection to JavaScript:**
    * **Turboshaft is a compiler for JavaScript:** This is the crucial link. The code tests optimizations within V8's Turboshaft compiler, which is responsible for optimizing JavaScript code.
    * **The operations have JavaScript equivalents:** The binary operations (`+`, `-`, `*`, `&`, `|`, `^`), comparisons (`==`, `<`, `<=`), and conditional selection (similar to the ternary operator `? :`) are all fundamental JavaScript operations.

6. **Formulate the Summary:**  Combine the above observations into a concise description of the file's purpose.

7. **Create JavaScript Examples:**  Translate the tested C++ patterns into equivalent JavaScript code snippets. This involves:
    * Identifying the corresponding JavaScript operators for the tested C++ operations.
    * Showing the different usage scenarios (one use, two uses) in JavaScript.
    * Emphasizing the *optimization* aspect and how the compiler *might* combine these operations internally.

8. **Review and Refine:**  Read through the summary and examples to ensure clarity, accuracy, and proper terminology. For example, ensuring the explanation highlights *compiler optimization* rather than suggesting developers write code in this specific pattern directly. Also double-check the JavaScript examples for correctness.

**(Self-Correction Example During Thought Process):**

*Initial thought:* "This file is just about testing some low-level stuff; it doesn't directly relate to what JavaScript developers write."
*Correction:* "Wait, the file is in the `compiler/turboshaft-test` directory. Turboshaft is a JavaScript compiler. This means the tests are about how Turboshaft optimizes *JavaScript* code. The operations being tested have direct equivalents in JavaScript." This correction is key to making the connection.

*Initial thought for JavaScript example:*  Just show the simple `if` statement.
*Correction:* The tests explicitly explore different usage scenarios (one use, two uses). The JavaScript examples should reflect these scenarios to better illustrate what the compiler is trying to optimize. The ternary operator is a closer analogy to the "select" operation.

By following these steps, we can arrive at a comprehensive understanding of the C++ code and its relevance to JavaScript.
这个C++源代码文件 `v8/test/cctest/compiler/turboshaft-test-select-combine.cc` 的主要功能是 **测试 V8 引擎中 Turboshaft 编译器的 "select combine" 优化**。

**具体功能归纳:**

1. **测试目标：**  该文件专门测试 Turboshaft 编译器是否能将特定模式的代码结构优化合并为一个更高效的操作。这个模式包括：
   - 一个二元算术运算 (binary operation, binop)。
   - 紧随其后的一个与零的比较运算 (compare zero)。
   - 一个基于比较结果进行选择的 "select" 操作。

2. **测试场景覆盖：**  为了全面测试这种优化，该文件构造了各种不同的测试场景，涵盖了：
   - **不同的 "select" 操作类型：**  包括对 32 位整数 (`Word32Select`)、64 位整数 (`Word64Select`)、32 位浮点数 (`Float32Select`) 和 64 位浮点数 (`Float64Select`) 的选择。
   - **不同的二元算术运算：**  测试了加法 (`add`)、减法 (`sub`)、乘法 (`mul`)、按位与 (`and`)、按位或 (`or`) 和按位异或 (`xor`) 等运算。
   - **不同的数据类型：**  涉及 `int32_t`、`uint32_t`、`int64_t`、`uint64_t`、`float` 和 `double` 等数据类型。
   - **二元运算结果的使用方式：**
      - **单次使用 (kOneUse):**  二元运算的结果仅被用于比较和选择操作。
      - **多次使用 (kTwoUsesOneBlock, kTwoUsesTwoBlocks):** 二元运算的结果除了用于比较和选择外，还在后续的计算中被使用，测试在不同代码块布局下的优化效果。

3. **测试框架：**  该文件使用了 V8 引擎的测试框架 (`cctest`) 和 Turboshaft 编译器的代码生成测试工具 (`BufferedRawMachineAssemblerTester`) 来构建和执行测试用例。

4. **代码生成和验证：**  测试用例通过 `BufferedRawMachineAssemblerTester` 创建 Turboshaft 的中间表示 (IR) 图，模拟目标代码结构，然后执行生成的代码，并与预期结果进行比较，验证 "select combine" 优化是否按预期工作。

**与 JavaScript 的关系及 JavaScript 示例：**

该文件测试的是 V8 引擎的编译器优化，而 V8 引擎是 JavaScript 的运行时环境。因此，这个文件直接关系到 JavaScript 代码的执行效率。

"select combine" 优化旨在提升 JavaScript 中一些特定模式的代码的性能。这种模式在 JavaScript 中很常见，例如使用三元运算符或者 `if-else` 语句进行条件赋值时。

**JavaScript 示例：**

考虑以下 JavaScript 代码片段：

```javascript
function example(a, b) {
  const sum = a + b;
  const result = sum > 0 ? 10 : 5;
  return result;
}
```

在这个例子中：

1. `a + b` 是一个二元算术运算 (加法)。
2. `sum > 0` 是一个与零的比较运算。
3. `sum > 0 ? 10 : 5` 是一个基于比较结果的选择操作（三元运算符）。

Turboshaft 编译器在进行优化时，可能会将这三个操作合并为一个更底层的、更高效的机器指令。这就是 "select combine" 优化想要实现的目标。

**另一个例子，使用按位与运算：**

```javascript
function bitwiseExample(value) {
  const andResult = value & 0xFF; // 按位与运算
  const result = andResult ? 1 : 0; // 隐式比较与 0，然后选择
  return result;
}
```

在这个例子中，虽然比较是隐式的（非零值被认为是 true），但其逻辑结构与被测试的模式类似。Turboshaft 可能会将按位与运算和后续的选择操作结合起来优化。

**总结 JavaScript 的关联：**

虽然 C++ 测试代码直接操作的是 Turboshaft 的内部结构，但它所测试的优化直接影响了 JavaScript 代码的执行效率。  JavaScript 中常见的算术运算、比较运算以及条件选择结构是 "select combine" 优化的潜在目标。该测试文件确保了 Turboshaft 编译器能够有效地识别和优化这些模式，从而提升 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/test/cctest/compiler/turboshaft-test-select-combine.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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