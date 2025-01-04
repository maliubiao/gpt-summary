Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

1. **Understanding the Goal:** The primary request is to summarize the functionality of the C++ file `instruction-selector-unittest.cc` and illustrate its connection to JavaScript using examples.

2. **Initial Scan and Keywords:**  I'd start by quickly scanning the code for prominent keywords and patterns. Things that immediately jump out are:

    * `InstructionSelectorTest`: This strongly suggests the file is about testing the instruction selection phase of a compiler.
    * `compiler`:  Confirms it's related to compilation.
    * `backend`: Indicates a lower-level part of the compiler, closer to machine code generation.
    * `unittests`:  Clearly states this is a unit testing file.
    * `v8`:  Identifies the project as the V8 JavaScript engine.
    * `InstructionSelector`:  This is likely the core class being tested.
    * `StreamBuilder`, `Stream`: These appear to be helper classes for building and examining the generated instructions.
    * `MachineType`:  Suggests the code deals with different data types.
    * `Return`, `Parameter`, `TruncateFloat64ToWord32`, `Phi`, `Load`, `CallJSFunctionWithDeopt`, `CallStubWithDeopt`: These look like specific compiler operations or instructions being tested.
    * `kArch...`:  These constants likely represent architecture-specific opcodes.

3. **Inferring Core Functionality:** Based on the keywords, I can deduce that the file's main purpose is to unit test the `InstructionSelector` class in the V8 compiler. This involves:

    * **Creating compiler graphs:** The `StreamBuilder` seems to be responsible for constructing simplified versions of the compiler's intermediate representation (likely a graph).
    * **Simulating instruction selection:** The `InstructionSelector` class takes this graph and converts it into a sequence of low-level instructions.
    * **Verifying the generated instructions:** The tests use assertions (`ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_TRUE`, etc.) to check if the generated instruction sequences match the expected output for various input graph structures.
    * **Testing different scenarios:** The presence of specific test functions (like `ReturnFloat32Constant`, `TruncateFloat64ToWord32WithParameter`, `CallJSFunctionWithDeopt`) suggests that the tests cover a range of common compiler operations and edge cases.
    * **Handling deoptimization:** The `...WithDeopt` tests indicate that the instruction selector is also tested for its ability to generate instructions that support deoptimization (reverting to interpreted execution).

4. **Connecting to JavaScript:**  The file is part of the V8 engine, which compiles JavaScript. Therefore, the instruction selection process directly translates JavaScript code into machine code. Each test case in the C++ file represents a simplified scenario derived from how the compiler handles specific JavaScript constructs or operations.

5. **Generating JavaScript Examples:**  Now, the goal is to find JavaScript code snippets that would trigger the specific compiler operations being tested in the C++ file. This requires thinking about:

    * **Data types:** JavaScript has numbers (which can be integers or floating-point), and the tests explicitly mention `Float32`, `Float64`, `Int32`. So, examples involving different number types are relevant.
    * **Function calls:**  The `CallJSFunctionWithDeopt` test directly relates to calling JavaScript functions.
    * **Built-in functions:** `CallStubWithDeopt` hints at calls to internal V8 functions (stubs), which are often used for built-in JavaScript methods.
    * **Control flow:** The `Phi` tests involve branching and merging control flow, which corresponds to `if` statements, loops, etc.
    * **Type conversions:** `TruncateFloat64ToWord32` maps to explicit or implicit type conversions in JavaScript.

6. **Refining the Examples:**  The initial examples might be too simplistic. It's important to consider:

    * **Deoptimization triggers:** For the `...WithDeopt` tests, the JavaScript examples should involve scenarios where deoptimization might occur (e.g., calling a function with arguments of unexpected types, accessing uninitialized variables, etc.). However, for simplicity in the initial explanation, a basic function call is sufficient.
    * **Clarity and conciseness:** The examples should be easy to understand and directly relate to the tested functionality.
    * **Avoiding overly complex scenarios:** The goal is to illustrate the *connection*, not to provide exhaustive test cases.

7. **Structuring the Output:** Finally, organize the information into a clear and logical structure:

    * Start with a concise summary of the file's purpose.
    * Explicitly state the connection to JavaScript.
    * Provide specific examples, linking each C++ test case (or group of related tests) to a corresponding JavaScript example.
    * Explain *why* the JavaScript example is relevant (what compiler operation it triggers).

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and understandable summary with illustrative JavaScript examples. The process involves understanding the C++ code's structure and purpose, connecting it to the broader context of the V8 JavaScript engine, and then working backward to find corresponding JavaScript constructs.
这个C++源代码文件 `instruction-selector-unittest.cc` 是 **V8 JavaScript 引擎** 的一部分，专门用于 **单元测试** 编译器 **后端** 的一个关键组件：**指令选择器 (Instruction Selector)**。

**功能归纳:**

该文件的主要功能是测试 `InstructionSelector` 类的各种能力，验证它能否正确地将编译器的中间表示（通常是一个图结构）转换为目标机器的指令序列。具体来说，它通过以下方式进行测试：

1. **构建中间表示（图）：** 使用 `StreamBuilder` 类来创建各种简单的图结构，这些图模拟了 JavaScript 代码编译后可能产生的操作。例如，它能创建表示常量、参数、算术运算、函数调用等操作的节点。

2. **运行指令选择器：**  对构建的图运行 `InstructionSelector`，这个过程会将图中的节点映射到目标架构的指令。

3. **检查生成的指令序列：**  通过 `Stream` 类来访问和检查生成的指令序列，验证：
   - 指令的数量是否正确。
   - 指令的类型（操作码）是否符合预期（例如，是否生成了正确的返回指令 `kArchRet`，加法指令等）。
   - 指令的操作数（输入和输出）是否正确，包括寄存器分配、常量、立即数等。
   - 是否正确处理了不同的数据类型（如 `Float32`, `Float64`, `Int32` 等）。
   - 是否正确处理了控制流结构（例如，`Phi` 节点）。
   - 是否正确处理了函数调用，特别是带有去优化 (deoptimization) 的调用。

**与 JavaScript 的关系及 JavaScript 举例:**

`InstructionSelector` 的作用是将高级的、平台无关的中间表示转换为低级的、特定于目标架构的指令。这个过程是 JavaScript 代码最终被执行的关键一步。  该文件中的每个测试用例都旨在验证指令选择器在处理某种特定的 JavaScript 操作或模式时的正确性。

以下是一些测试用例与 JavaScript 功能对应的例子：

**1. `ReturnFloat32Constant`:**

   - **C++ 测试目标:** 验证返回一个浮点数常量的指令选择。
   - **JavaScript 例子:**
     ```javascript
     function foo() {
       return 4.2; // 4.2 在 V8 中可能被表示为 Float32 或 Float64，这里关注 Float32
     }
     ```
     当 V8 编译 `foo` 函数时，指令选择器需要生成一条指令，将浮点数常量 `4.2` 加载到返回值寄存器中。

**2. `ReturnParameter`:**

   - **C++ 测试目标:** 验证返回函数参数的指令选择。
   - **JavaScript 例子:**
     ```javascript
     function bar(x) {
       return x;
     }
     ```
     指令选择器需要生成指令，将参数 `x` 所在的位置（通常在寄存器或栈上）的值复制到返回值寄存器中。

**3. `TruncateFloat64ToWord32WithParameter`:**

   - **C++ 测试目标:** 验证将 64 位浮点数截断为 32 位整数的指令选择。
   - **JavaScript 例子:**
     ```javascript
     function baz(y) {
       return y | 0; // 使用位运算将浮点数转换为 32 位整数
     }
     ```
     或者
     ```javascript
     function qux(z) {
       return parseInt(z); // 显式将浮点数转换为整数
     }
     ```
     指令选择器需要生成类似 `cvttsd2si` (Convert Scalar Double-Precision Floating-Point Value to Scalar Doubleword Integer - x64 指令) 的指令。

**4. `CallJSFunctionWithDeopt` 和 `CallStubWithDeopt`:**

   - **C++ 测试目标:** 验证调用 JavaScript 函数或内置函数（stub）并处理去优化的指令选择。
   - **JavaScript 例子 (CallJSFunctionWithDeopt):**
     ```javascript
     function add(a, b) {
       return a + b;
     }

     function caller(p) {
       return add(p, 5); // 调用 JavaScript 函数 add
     }
     ```
   - **JavaScript 例子 (CallStubWithDeopt):**
     ```javascript
     function convertToString(n) {
       return n.toString(); // 调用内置的 toString 方法
     }
     ```
     当 V8 优化这些函数时，会生成高效的调用指令。如果运行时类型假设失败，可能需要进行去优化，回到解释执行。指令选择器需要确保生成的指令序列能够正确地处理去优化相关的逻辑（例如，保存现场信息）。

**5. `Phi`:**

   - **C++ 测试目标:** 验证处理 `Phi` 节点的指令选择，`Phi` 节点用于在控制流汇合点合并不同路径上的值。
   - **JavaScript 例子:**
     ```javascript
     function conditionalValue(flag) {
       let value;
       if (flag) {
         value = 10;
       } else {
         value = 20;
       }
       return value; // value 的值取决于 if 条件
     }
     ```
     在编译 `conditionalValue` 时，`value` 的值在 `if` 语句的不同分支中可能不同，需要在 `return` 语句前的汇合点使用 `Phi` 节点来表示。指令选择器需要能正确地为 `Phi` 节点分配寄存器或内存位置。

**总结:**

`instruction-selector-unittest.cc` 文件是 V8 编译器后端测试的重要组成部分，它通过模拟各种 JavaScript 代码场景，验证指令选择器能否正确地生成高效且正确的机器码。 这些测试覆盖了 JavaScript 的基本语法、数据类型、控制流和函数调用等核心概念，确保了 V8 引擎能够可靠地执行 JavaScript 代码。 每一个测试用例都反映了编译器在将 JavaScript 代码转换为可执行指令时需要处理的具体细节。

Prompt: 
```
这是目录为v8/test/unittests/compiler/backend/instruction-selector-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

#include "src/codegen/code-factory.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/schedule.h"
#include "src/compiler/turbofan-graph.h"
#include "src/flags/flags.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/compiler-test-utils.h"

namespace v8 {
namespace internal {
namespace compiler {

InstructionSelectorTest::InstructionSelectorTest()
    : TestWithNativeContextAndZone(kCompressGraphZone),
      rng_(v8_flags.random_seed) {}

InstructionSelectorTest::~InstructionSelectorTest() = default;

InstructionSelectorTest::Stream InstructionSelectorTest::StreamBuilder::Build(
    InstructionSelector::Features features,
    InstructionSelectorTest::StreamBuilderMode mode,
    InstructionSelector::SourcePositionMode source_position_mode) {
  Schedule* schedule = ExportForTest();
  if (v8_flags.trace_turbo) {
    StdoutStream{} << "=== Schedule before instruction selection ==="
                   << std::endl
                   << *schedule;
  }
  size_t const node_count = graph()->NodeCount();
  EXPECT_NE(0u, node_count);
  Linkage linkage(call_descriptor());
  InstructionBlocks* instruction_blocks =
      InstructionSequence::InstructionBlocksFor(test_->zone(), schedule);
  InstructionSequence sequence(test_->isolate(), test_->zone(),
                               instruction_blocks);
  SourcePositionTable source_position_table(graph());
  TickCounter tick_counter;
  size_t max_unoptimized_frame_height = 0;
  size_t max_pushed_argument_count = 0;
  InstructionSelector selector = InstructionSelector::ForTurbofan(
      test_->zone(), node_count, &linkage, &sequence, schedule,
      &source_position_table, nullptr,
      InstructionSelector::kEnableSwitchJumpTable, &tick_counter, nullptr,
      &max_unoptimized_frame_height, &max_pushed_argument_count,
      source_position_mode, features, InstructionSelector::kDisableScheduling,
      InstructionSelector::kEnableRootsRelativeAddressing);
  selector.SelectInstructions();
  if (v8_flags.trace_turbo) {
    StdoutStream{} << "=== Code sequence after instruction selection ==="
                   << std::endl
                   << sequence;
  }
  Stream s;
  s.virtual_registers_ = selector.GetVirtualRegistersForTesting();
  // Map virtual registers.
  for (Instruction* const instr : sequence) {
    if (instr->opcode() < 0) continue;
    if (mode == kTargetInstructions) {
      switch (instr->arch_opcode()) {
#define CASE(Name) \
  case k##Name:    \
    break;
        TARGET_ARCH_OPCODE_LIST(CASE)
#undef CASE
        default:
          continue;
      }
    }
    if (mode == kAllExceptNopInstructions && instr->arch_opcode() == kArchNop) {
      continue;
    }
    for (size_t i = 0; i < instr->OutputCount(); ++i) {
      InstructionOperand* output = instr->OutputAt(i);
      EXPECT_NE(InstructionOperand::IMMEDIATE, output->kind());
      if (output->IsConstant()) {
        int vreg = ConstantOperand::cast(output)->virtual_register();
        s.constants_.insert(std::make_pair(vreg, sequence.GetConstant(vreg)));
      }
    }
    for (size_t i = 0; i < instr->InputCount(); ++i) {
      InstructionOperand* input = instr->InputAt(i);
      EXPECT_NE(InstructionOperand::CONSTANT, input->kind());
      if (input->IsImmediate()) {
        auto imm = ImmediateOperand::cast(input);
        if (imm->type() == ImmediateOperand::INDEXED_IMM) {
          int index = imm->indexed_value();
          s.immediates_.insert(
              std::make_pair(index, sequence.GetImmediate(imm)));
        }
      }
    }
    s.instructions_.push_back(instr);
  }
  for (auto i : s.virtual_registers_) {
    int const virtual_register = i.second;
    if (sequence.IsFP(virtual_register)) {
      EXPECT_FALSE(sequence.IsReference(virtual_register));
      s.doubles_.insert(virtual_register);
    }
    if (sequence.IsReference(virtual_register)) {
      EXPECT_FALSE(sequence.IsFP(virtual_register));
      s.references_.insert(virtual_register);
    }
  }
  for (int i = 0; i < sequence.GetDeoptimizationEntryCount(); i++) {
    s.deoptimization_entries_.push_back(
        sequence.GetDeoptimizationEntry(i).descriptor());
  }
  return s;
}

int InstructionSelectorTest::Stream::ToVreg(const Node* node) const {
  VirtualRegisters::const_iterator i = virtual_registers_.find(node->id());
  CHECK(i != virtual_registers_.end());
  return i->second;
}

bool InstructionSelectorTest::Stream::IsFixed(const InstructionOperand* operand,
                                              Register reg) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  if (!unallocated->HasFixedRegisterPolicy()) return false;
  return unallocated->fixed_register_index() == reg.code();
}

bool InstructionSelectorTest::Stream::IsSameAsFirst(
    const InstructionOperand* operand) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->HasSameAsInputPolicy();
}

bool InstructionSelectorTest::Stream::IsSameAsInput(
    const InstructionOperand* operand, int input_index) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->HasSameAsInputPolicy() &&
         unallocated->input_index() == input_index;
}

bool InstructionSelectorTest::Stream::IsUsedAtStart(
    const InstructionOperand* operand) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->IsUsedAtStart();
}

const FrameStateFunctionInfo*
InstructionSelectorTest::StreamBuilder::GetFrameStateFunctionInfo(
    uint16_t parameter_count, int local_count) {
  const uint16_t max_arguments = 0;
  return common()->CreateFrameStateFunctionInfo(
      FrameStateType::kUnoptimizedFunction, parameter_count, max_arguments,
      local_count, {}, {});
}

// -----------------------------------------------------------------------------
// Return.

TARGET_TEST_F(InstructionSelectorTest, ReturnFloat32Constant) {
  const float kValue = 4.2f;
  StreamBuilder m(this, MachineType::Float32());
  m.Return(m.Float32Constant(kValue));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(InstructionOperand::CONSTANT, s[0]->OutputAt(0)->kind());
  EXPECT_FLOAT_EQ(kValue, s.ToFloat32(s[0]->OutputAt(0)));
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

TARGET_TEST_F(InstructionSelectorTest, ReturnParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Parameter(0));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

TARGET_TEST_F(InstructionSelectorTest, ReturnZero) {
  StreamBuilder m(this, MachineType::Int32());
  m.Return(m.Int32Constant(0));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(InstructionOperand::CONSTANT, s[0]->OutputAt(0)->kind());
  EXPECT_EQ(0, s.ToInt32(s[0]->OutputAt(0)));
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

// -----------------------------------------------------------------------------
// Conversions.

TARGET_TEST_F(InstructionSelectorTest, TruncateFloat64ToWord32WithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  m.Return(m.TruncateFloat64ToWord32(m.Parameter(0)));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(4U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  EXPECT_EQ(kArchTruncateDoubleToI, s[1]->arch_opcode());
  EXPECT_EQ(1U, s[1]->InputCount());
  EXPECT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArchRet, s[2]->arch_opcode());
}

// -----------------------------------------------------------------------------
// Parameters.

TARGET_TEST_F(InstructionSelectorTest, DoubleParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* param = m.Parameter(0);
  m.Return(param);
  Stream s = m.Build(kAllInstructions);
  EXPECT_TRUE(s.IsDouble(param));
}

TARGET_TEST_F(InstructionSelectorTest, ReferenceParameter) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged());
  Node* param = m.Parameter(0);
  m.Return(param);
  Stream s = m.Build(kAllInstructions);
  EXPECT_TRUE(s.IsReference(param));
}

// -----------------------------------------------------------------------------
// FinishRegion.

TARGET_TEST_F(InstructionSelectorTest, FinishRegion) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged());
  Node* param = m.Parameter(0);
  Node* finish =
      m.AddNode(m.common()->FinishRegion(), param, m.graph()->start());
  m.Return(finish);
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_TRUE(s[0]->Output()->IsUnallocated());
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(s.ToVreg(param), s.ToVreg(s[0]->Output()));
  EXPECT_EQ(s.ToVreg(param), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_TRUE(s.IsReference(finish));
}

// -----------------------------------------------------------------------------
// Phi.

using InstructionSelectorPhiTest =
    InstructionSelectorTestWithParam<MachineType>;

TARGET_TEST_P(InstructionSelectorPhiTest, Doubleness) {
  const MachineType type = GetParam();
  StreamBuilder m(this, type, type, type);
  Node* param0 = m.Parameter(0);
  Node* param1 = m.Parameter(1);
  RawMachineLabel a, b, c;
  m.Branch(m.Int32Constant(0), &a, &b);
  m.Bind(&a);
  m.Goto(&c);
  m.Bind(&b);
  m.Goto(&c);
  m.Bind(&c);
  Node* phi = m.Phi(type.representation(), param0, param1);
  m.Return(phi);
  Stream s = m.Build(kAllInstructions);
  EXPECT_EQ(s.IsDouble(phi), s.IsDouble(param0));
  EXPECT_EQ(s.IsDouble(phi), s.IsDouble(param1));
}

TARGET_TEST_P(InstructionSelectorPhiTest, Referenceness) {
  const MachineType type = GetParam();
  StreamBuilder m(this, type, type, type);
  Node* param0 = m.Parameter(0);
  Node* param1 = m.Parameter(1);
  RawMachineLabel a, b, c;
  m.Branch(m.Int32Constant(1), &a, &b);
  m.Bind(&a);
  m.Goto(&c);
  m.Bind(&b);
  m.Goto(&c);
  m.Bind(&c);
  Node* phi = m.Phi(type.representation(), param0, param1);
  m.Return(phi);
  Stream s = m.Build(kAllInstructions);
  EXPECT_EQ(s.IsReference(phi), s.IsReference(param0));
  EXPECT_EQ(s.IsReference(phi), s.IsReference(param1));
}

INSTANTIATE_TEST_SUITE_P(
    InstructionSelectorTest, InstructionSelectorPhiTest,
    ::testing::Values(MachineType::Float64(), MachineType::Int8(),
                      MachineType::Uint8(), MachineType::Int16(),
                      MachineType::Uint16(), MachineType::Int32(),
                      MachineType::Uint32(), MachineType::Int64(),
                      MachineType::Uint64(), MachineType::Pointer(),
                      MachineType::AnyTagged()));

// -----------------------------------------------------------------------------
// ValueEffect.

TARGET_TEST_F(InstructionSelectorTest, ValueEffect) {
  StreamBuilder m1(this, MachineType::Int32(), MachineType::Pointer());
  Node* p1 = m1.Parameter(0);
  m1.Return(m1.Load(MachineType::Int32(), p1, m1.Int32Constant(0)));
  Stream s1 = m1.Build(kAllInstructions);
  StreamBuilder m2(this, MachineType::Int32(), MachineType::Pointer());
  Node* p2 = m2.Parameter(0);
  m2.Return(m2.AddNode(
      m2.machine()->Load(MachineType::Int32()), p2, m2.Int32Constant(0),
      m2.AddNode(m2.common()->BeginRegion(RegionObservability::kObservable),
                 m2.graph()->start())));
  Stream s2 = m2.Build(kAllInstructions);
  EXPECT_LE(3U, s1.size());
  ASSERT_EQ(s1.size(), s2.size());
  TRACED_FORRANGE(size_t, i, 0, s1.size() - 1) {
    const Instruction* i1 = s1[i];
    const Instruction* i2 = s2[i];
    EXPECT_EQ(i1->arch_opcode(), i2->arch_opcode());
    EXPECT_EQ(i1->InputCount(), i2->InputCount());
    EXPECT_EQ(i1->OutputCount(), i2->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// Calls with deoptimization.

TARGET_TEST_F(InstructionSelectorTest, CallJSFunctionWithDeopt) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged(),
                  MachineType::AnyTagged(), MachineType::AnyTagged());

  BytecodeOffset bailout_id(42);

  Node* function_node = m.Parameter(0);
  Node* receiver = m.Parameter(1);
  Node* context = m.Parameter(2);

  ZoneVector<MachineType> int32_type(1, MachineType::Int32(), zone());
  ZoneVector<MachineType> tagged_type(1, MachineType::AnyTagged(), zone());
  ZoneVector<MachineType> empty_type(zone());

  auto call_descriptor = Linkage::GetJSCallDescriptor(
      zone(), false, 1,
      CallDescriptor::kNeedsFrameState | CallDescriptor::kCanUseRoots);

  // Build frame state for the state before the call.
  Node* parameters = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(1));
  Node* locals = m.AddNode(
      m.common()->TypedStateValues(&empty_type, SparseInputMask::Dense()));
  Node* stack = m.AddNode(
      m.common()->TypedStateValues(&tagged_type, SparseInputMask::Dense()),
      m.UndefinedConstant());
  Node* context_sentinel = m.Int32Constant(0);
  Node* state_node = m.AddNode(
      m.common()->FrameState(bailout_id, OutputFrameStateCombine::PokeAt(0),
                             m.GetFrameStateFunctionInfo(1, 0)),
      parameters, locals, stack, context_sentinel, function_node,
      m.graph()->start());

  // Build the call.
  Node* argc = m.Int32Constant(1);
#ifdef V8_ENABLE_LEAPTIERING
  Node* dispatch_handle = m.Int32Constant(-1);
  Node* nodes[] = {function_node, receiver,        m.UndefinedConstant(),
                   argc,          dispatch_handle, context,
                   state_node};
#else
  Node* nodes[] = {function_node, receiver, m.UndefinedConstant(),
                   argc,          context,  state_node};
#endif
  Node* call = m.CallNWithFrameState(call_descriptor, arraysize(nodes), nodes);
  m.Return(call);

  Stream s = m.Build(kAllExceptNopInstructions);

  // Skip until kArchCallJSFunction.
  size_t index = 0;
  for (; index < s.size() && s[index]->arch_opcode() != kArchCallJSFunction;
       index++) {
  }
  // Now we should have two instructions: call and return.
  ASSERT_EQ(index + 2, s.size());

  EXPECT_EQ(kArchCallJSFunction, s[index++]->arch_opcode());
  EXPECT_EQ(kArchRet, s[index++]->arch_opcode());

  // TODO(jarin) Check deoptimization table.
}

TARGET_TEST_F(InstructionSelectorTest, CallStubWithDeopt) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged(),
                  MachineType::AnyTagged(), MachineType::AnyTagged());

  BytecodeOffset bailout_id_before(42);

  // Some arguments for the call node.
  Node* function_node = m.Parameter(0);
  Node* receiver = m.Parameter(1);
  Node* context = m.Int32Constant(1);  // Context is ignored.

  ZoneVector<MachineType> int32_type(1, MachineType::Int32(), zone());
  ZoneVector<MachineType> float64_type(1, MachineType::Float64(), zone());
  ZoneVector<MachineType> tagged_type(1, MachineType::AnyTagged(), zone());

  Callable callable = Builtins::CallableFor(isolate(), Builtin::kToObject);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), 1, CallDescriptor::kNeedsFrameState,
      Operator::kNoProperties);

  // Build frame state for the state before the call.
  Node* parameters = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(43));
  Node* locals = m.AddNode(
      m.common()->TypedStateValues(&float64_type, SparseInputMask::Dense()),
      m.Float64Constant(0.5));
  Node* stack = m.AddNode(
      m.common()->TypedStateValues(&tagged_type, SparseInputMask::Dense()),
      m.UndefinedConstant());
  Node* context_sentinel = m.Int32Constant(0);
  Node* state_node =
      m.AddNode(m.common()->FrameState(bailout_id_before,
                                       OutputFrameStateCombine::PokeAt(0),
                                       m.GetFrameStateFunctionInfo(1, 1)),
                parameters, locals, stack, context_sentinel, function_node,
                m.graph()->start());

  // Build the call.
  Node* stub_code = m.HeapConstant(callable.code());
  Node* nodes[] = {stub_code, function_node, receiver, context, state_node};
  Node* call = m.CallNWithFrameState(call_descriptor, arraysize(nodes), nodes);
  m.Return(call);

  Stream s = m.Build(kAllExceptNopInstructions);

  // Skip until kArchCallCodeObject.
  size_t index = 0;
  for (; index < s.size() && s[index]->arch_opcode() != kArchCallCodeObject;
       index++) {
  }
  // Now we should have two instructions: call, return.
  ASSERT_EQ(index + 2, s.size());

  // Check the call instruction
  const Instruction* call_instr = s[index++];
  EXPECT_EQ(kArchCallCodeObject, call_instr->arch_opcode());
  size_t num_operands =
      1 +  // Code object.
      6 +  // Frame state deopt id + one input for each value in frame state.
      1 +  // Function.
      1 +  // Context.
      1;   // Entrypoint tag.
  ASSERT_EQ(num_operands, call_instr->InputCount());

  // Code object.
  EXPECT_TRUE(call_instr->InputAt(0)->IsImmediate());

  // Deoptimization id.
  int32_t deopt_id_before = s.ToInt32(call_instr->InputAt(1));
  FrameStateDescriptor* desc_before =
      s.GetFrameStateDescriptor(deopt_id_before);
  EXPECT_EQ(bailout_id_before, desc_before->bailout_id());
  EXPECT_EQ(1u, desc_before->parameters_count());
  EXPECT_EQ(1u, desc_before->locals_count());
  EXPECT_EQ(1u, desc_before->stack_count());
  EXPECT_EQ(43, s.ToInt32(call_instr->InputAt(3)));
  EXPECT_EQ(0, s.ToInt32(call_instr->InputAt(4)));  // This should be a context.
                                                    // We inserted 0 here.
  EXPECT_EQ(0.5, s.ToFloat64(call_instr->InputAt(5)));
  EXPECT_TRUE(IsUndefined(*s.ToHeapObject(call_instr->InputAt(6)), isolate()));

  // Function.
  EXPECT_EQ(s.ToVreg(function_node), s.ToVreg(call_instr->InputAt(7)));
  // Context.
  EXPECT_EQ(s.ToVreg(context), s.ToVreg(call_instr->InputAt(8)));
  // Entrypoint tag.
  EXPECT_TRUE(call_instr->InputAt(9)->IsImmediate());

  EXPECT_EQ(kArchRet, s[index++]->arch_opcode());

  EXPECT_EQ(index, s.size());
}

TARGET_TEST_F(InstructionSelectorTest, CallStubWithDeoptRecursiveFrameState) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged(),
                  MachineType::AnyTagged(), MachineType::AnyTagged());

  BytecodeOffset bailout_id_before(42);
  BytecodeOffset bailout_id_parent(62);

  // Some arguments for the call node.
  Node* function_node = m.Parameter(0);
  Node* receiver = m.Parameter(1);
  Node* context = m.Int32Constant(66);
  Node* context2 = m.Int32Constant(46);

  ZoneVector<MachineType> int32_type(1, MachineType::Int32(), zone());
  ZoneVector<MachineType> float64_type(1, MachineType::Float64(), zone());

  Callable callable = Builtins::CallableFor(isolate(), Builtin::kToObject);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), callable.descriptor(), 1, CallDescriptor::kNeedsFrameState,
      Operator::kNoProperties);

  // Build frame state for the state before the call.
  Node* parameters = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(63));
  Node* locals = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(64));
  Node* stack = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(65));
  Node* frame_state_parent = m.AddNode(
      m.common()->FrameState(bailout_id_parent,
                             OutputFrameStateCombine::Ignore(),
                             m.GetFrameStateFunctionInfo(1, 1)),
      parameters, locals, stack, context, function_node, m.graph()->start());

  Node* parameters2 = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(43));
  Node* locals2 = m.AddNode(
      m.common()->TypedStateValues(&float64_type, SparseInputMask::Dense()),
      m.Float64Constant(0.25));
  Node* stack2 = m.AddNode(
      m.common()->TypedStateValues(&int32_type, SparseInputMask::Dense()),
      m.Int32Constant(44));
  Node* state_node =
      m.AddNode(m.common()->FrameState(bailout_id_before,
                                       OutputFrameStateCombine::PokeAt(0),
                                       m.GetFrameStateFunctionInfo(1, 1)),
                parameters2, locals2, stack2, context2, function_node,
                frame_state_parent);

  // Build the call.
  Node* stub_code = m.HeapConstant(callable.code());
  Node* nodes[] = {stub_code, function_node, receiver, context2, state_node};
  Node* call = m.CallNWithFrameState(call_descriptor, arraysize(nodes), nodes);
  m.Return(call);

  Stream s = m.Build(kAllExceptNopInstructions);

  // Skip until kArchCallCodeObject.
  size_t index = 0;
  for (; index < s.size() && s[index]->arch_opcode() != kArchCallCodeObject;
       index++) {
  }
  // Now we should have three instructions: call, return.
  EXPECT_EQ(index + 2, s.size());

  // Check the call instruction
  const Instruction* call_instr = s[index++];
  EXPECT_EQ(kArchCallCodeObject, call_instr->arch_opcode());
  size_t num_operands =
      1 +  // Code object.
      1 +  // Frame state deopt id
      5 +  // One input for each value in frame state + context.
      5 +  // One input for each value in the parent frame state + context.
      1 +  // Function.
      1 +  // Context.
      1;   // Entrypoint tag.
  EXPECT_EQ(num_operands, call_instr->InputCount());
  // Code object.
  EXPECT_TRUE(call_instr->InputAt(0)->IsImmediate());

  // Deoptimization id.
  int32_t deopt_id_before = s.ToInt32(call_instr->InputAt(1));
  FrameStateDescriptor* desc_before =
      s.GetFrameStateDescriptor(deopt_id_before);
  FrameStateDescriptor* desc_before_outer = desc_before->outer_state();
  EXPECT_EQ(bailout_id_before, desc_before->bailout_id());
  EXPECT_EQ(1u, desc_before_outer->parameters_count());
  EXPECT_EQ(1u, desc_before_outer->locals_count());
  EXPECT_EQ(1u, desc_before_outer->stack_count());
  // Values from parent environment.
  EXPECT_EQ(63, s.ToInt32(call_instr->InputAt(3)));
  // Context:
  EXPECT_EQ(66, s.ToInt32(call_instr->InputAt(4)));
  EXPECT_EQ(64, s.ToInt32(call_instr->InputAt(5)));
  EXPECT_EQ(65, s.ToInt32(call_instr->InputAt(6)));
  // Values from the nested frame.
  EXPECT_EQ(1u, desc_before->parameters_count());
  EXPECT_EQ(1u, desc_before->locals_count());
  EXPECT_EQ(1u, desc_before->stack_count());
  EXPECT_EQ(43, s.ToInt32(call_instr->InputAt(8)));
  EXPECT_EQ(46, s.ToInt32(call_instr->InputAt(9)));
  EXPECT_EQ(0.25, s.ToFloat64(call_instr->InputAt(10)));
  EXPECT_EQ(44, s.ToInt32(call_instr->InputAt(11)));

  // Function.
  EXPECT_EQ(s.ToVreg(function_node), s.ToVreg(call_instr->InputAt(12)));
  // Context.
  EXPECT_EQ(s.ToVreg(context2), s.ToVreg(call_instr->InputAt(13)));
  // Entrypoint tag.
  EXPECT_TRUE(call_instr->InputAt(14)->IsImmediate());
  // Continuation.

  EXPECT_EQ(kArchRet, s[index++]->arch_opcode());
  EXPECT_EQ(index, s.size());
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```