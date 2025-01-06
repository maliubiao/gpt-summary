Response: The user wants a summary of the C++ source code file `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc`. This file name suggests it contains unit tests for the Turboshaft instruction selector.

Therefore, the functionality should revolve around setting up test scenarios, running the instruction selector on those scenarios, and then verifying the generated instructions.

If there's a connection to JavaScript, it's likely through how the instruction selector processes intermediate representations of JavaScript code. I can illustrate this with a simple JavaScript function and how it might be translated and then have instructions selected.

**Plan:**

1. Summarize the core functionality: Unit tests for the Turboshaft instruction selector.
2. Explain the testing mechanism: Building graphs, running the instruction selector, and checking the resulting instruction stream.
3. Identify key classes and methods used for testing: `TurboshaftInstructionSelectorTest`, `StreamBuilder`, `Build`, and assertions on the generated instructions.
4. Illustrate the connection to JavaScript with a simple example.
这个C++源代码文件 `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc` 是 V8 JavaScript 引擎中 Turboshaft 编译器的后端组件——指令选择器（instruction selector）的单元测试。

**功能归纳:**

该文件包含了大量的单元测试，用于验证 Turboshaft 指令选择器在不同场景下生成正确目标架构指令的能力。其主要功能可以概括为：

1. **搭建测试环境:**  它使用 `TurboshaftInstructionSelectorTest` 类作为测试基类，提供创建测试所需的上下文、Zone（内存管理区域）和随机数生成器等基础设施。
2. **构建中间表示 (IR) 图:**  测试用例通过 `StreamBuilder` 类来构建待进行指令选择的 Turboshaft IR 图。`StreamBuilder` 提供了一系列方法来创建各种操作符（例如：Return、Constant、Parameter、Phi、Truncate 等）。
3. **运行指令选择器:** `StreamBuilder::Build` 方法负责执行指令选择阶段。这个方法会创建一个 `InstructionSelector` 实例，并调用其 `SelectInstructions()` 方法，将 IR 图转换为目标架构的指令序列。
4. **检查生成的指令序列:**  测试用例通过断言 (ASSERT/EXPECT) 来验证生成的指令序列是否符合预期。这包括检查指令的数量、指令的操作码 (opcode)、输入输出操作数的类型和值等。例如，检查是否生成了正确的 `kArchRet` (返回) 指令，或者某个常量是否被正确加载。
5. **覆盖各种指令选择场景:**  测试用例涵盖了各种不同的指令选择场景，例如：
    *   返回不同类型的值（常量、参数等）。
    *   类型转换操作。
    *   参数的处理。
    *   Phi 节点的处理。
    *   函数调用（尽管这部分代码被注释掉了，但可以看出其意图）。
    *   不同机器类型 (MachineType) 的操作。

**与 JavaScript 的关系及 JavaScript 示例:**

指令选择器的作用是将高级的、平台无关的 IR 转换为特定的目标机器指令，以便 CPU 可以执行。Turboshaft 编译器处理的是 JavaScript 代码。因此，这些单元测试实际上是在验证当 Turboshaft 编译特定的 JavaScript 代码片段时，指令选择器能否正确地生成对应的机器指令。

**JavaScript 示例:**

假设我们有以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 Turboshaft 编译这个函数时，它可能会经历以下（简化的）过程：

1. **解析和词法分析:** 将 JavaScript 代码转换为抽象语法树 (AST)。
2. **生成中间表示 (IR):**  将 AST 转换为 Turboshaft 的 IR 图。这个 IR 图可能包含表示参数 `a` 和 `b` 的节点，表示加法操作的节点，以及表示返回值的节点。
3. **指令选择:** 指令选择器遍历 IR 图，为每个 IR 节点选择合适的目标架构指令。例如，对于加法操作，可能会选择 `ADD` 指令。对于返回操作，可能会选择 `RET` 指令。

在 `turboshaft-instruction-selector-unittest.cc` 中，许多测试用例模拟了这种 IR 图的构建和指令选择的过程。

**例如，测试用例 `ReturnZero` 模拟了 JavaScript 函数返回常量 `0` 的场景：**

```c++
TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReturnZero) {
  StreamBuilder m(this, MachineType::Int32()); // 假设返回类型是 Int32
  m.Return(m.Int32Constant(0)); // 构建返回常量 0 的 IR 节点
  Stream s = m.Build(kAllInstructions); // 运行指令选择器
  ASSERT_EQ(2U, s.size()); // 预期生成两条指令
  EXPECT_EQ(kArchNop, s[0]->arch_opcode()); // 第一条可能是 NOP 或加载常量
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(InstructionOperand::CONSTANT, s[0]->OutputAt(0)->kind());
  EXPECT_EQ(0, s.ToInt32(s[0]->OutputAt(0))); // 验证常量值是 0
  EXPECT_EQ(kArchRet, s[1]->arch_opcode()); // 第二条是返回指令
  EXPECT_EQ(2U, s[1]->InputCount());
}
```

这个 C++ 测试用例验证了当 Turboshaft 遇到一个返回整数常量 `0` 的 IR 节点时，指令选择器会生成正确的机器指令序列，其中通常包含一个加载常量的操作（如果需要）和一个返回指令。

虽然这个测试用例没有直接运行 JavaScript 代码，但它模拟了编译 JavaScript 代码过程中关键的指令选择步骤，并确保了指令选择器的正确性。其他的测试用例也类似地覆盖了 JavaScript 中各种不同的操作和控制流结构。

Prompt: 
```
这是目录为v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h"

#include "src/codegen/code-factory.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/schedule.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/turboshaft/instruction-selection-phase.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/flags/flags.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/compiler-test-utils.h"

namespace v8::internal::compiler::turboshaft {

TurboshaftInstructionSelectorTest::TurboshaftInstructionSelectorTest()
    : TestWithNativeContextAndZone(kCompressGraphZone),
      rng_(v8_flags.random_seed) {}

TurboshaftInstructionSelectorTest::~TurboshaftInstructionSelectorTest() =
    default;

TurboshaftInstructionSelectorTest::Stream
TurboshaftInstructionSelectorTest::StreamBuilder::Build(
    InstructionSelector::Features features,
    TurboshaftInstructionSelectorTest::StreamBuilderMode mode,
    InstructionSelector::SourcePositionMode source_position_mode) {
  if (v8_flags.trace_turbo) {
    StdoutStream{} << "=== Graph before instruction selection ===" << std::endl
                   << output_graph();
  }
  size_t const node_count = output_graph().NumberOfOperationsForDebugging();
  EXPECT_NE(0u, node_count);
  Linkage linkage(call_descriptor());

  Graph& graph = output_graph();

  // Compute special RPO order....
  TurboshaftSpecialRPONumberer numberer(graph, test_->zone());
  auto schedule = numberer.ComputeSpecialRPO();
  graph.ReorderBlocks(base::VectorOf(schedule));

  // Determine deferred blocks.
  PropagateDeferred(graph);

  // Initialize an instruction sequence.
  InstructionBlocks* instruction_blocks =
      InstructionSequence::InstructionBlocksFor(test_->zone(), graph);
  InstructionSequence sequence(test_->isolate(), test_->zone(),
                               instruction_blocks);

  TickCounter tick_counter;
  size_t max_unoptimized_frame_height = 0;
  size_t max_pushed_argument_count = 0;
  InstructionSelector selector = InstructionSelector::ForTurboshaft(
      test_->zone(), graph.op_id_count(), &linkage, &sequence, &graph, nullptr,
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

int TurboshaftInstructionSelectorTest::Stream::ToVreg(OpIndex index) const {
  VirtualRegisters::const_iterator i = virtual_registers_.find(index.id());
  CHECK(i != virtual_registers_.end());
  return i->second;
}

bool TurboshaftInstructionSelectorTest::Stream::IsFixed(
    const InstructionOperand* operand, Register reg) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  if (!unallocated->HasFixedRegisterPolicy()) return false;
  return unallocated->fixed_register_index() == reg.code();
}

bool TurboshaftInstructionSelectorTest::Stream::IsSameAsFirst(
    const InstructionOperand* operand) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->HasSameAsInputPolicy();
}

bool TurboshaftInstructionSelectorTest::Stream::IsSameAsInput(
    const InstructionOperand* operand, int input_index) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->HasSameAsInputPolicy() &&
         unallocated->input_index() == input_index;
}

bool TurboshaftInstructionSelectorTest::Stream::IsUsedAtStart(
    const InstructionOperand* operand) const {
  if (!operand->IsUnallocated()) return false;
  const UnallocatedOperand* unallocated = UnallocatedOperand::cast(operand);
  return unallocated->IsUsedAtStart();
}

const FrameStateFunctionInfo*
TurboshaftInstructionSelectorTest::StreamBuilder::GetFrameStateFunctionInfo(
    uint16_t parameter_count, int local_count) {
  const uint16_t max_arguments = 0;
  return test_->zone()->New<FrameStateFunctionInfo>(
      FrameStateType::kUnoptimizedFunction, parameter_count, max_arguments,
      local_count, Handle<SharedFunctionInfo>(), Handle<BytecodeArray>());
}

// -----------------------------------------------------------------------------
// Return.

TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReturnFloat32Constant) {
  const float kValue = 4.2f;
  StreamBuilder m(this, MachineType::Float32());
  m.Return(m.Float32Constant(kValue));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(InstructionOperand::CONSTANT, s[0]->OutputAt(0)->kind());
  EXPECT_FLOAT_EQ(kValue, s.ToFloat32(s[0]->OutputAt(0)));
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReturnParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Parameter(0));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReturnZero) {
  StreamBuilder m(this, MachineType::Int32());
  m.Return(m.Int32Constant(0));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(InstructionOperand::CONSTANT, s[0]->OutputAt(0)->kind());
  EXPECT_EQ(0, s.ToInt32(s[0]->OutputAt(0)));
  EXPECT_EQ(kArchRet, s[1]->arch_opcode());
  EXPECT_EQ(2U, s[1]->InputCount());
}

// -----------------------------------------------------------------------------
// Conversions.

TARGET_TEST_F(TurboshaftInstructionSelectorTest,
              TruncateFloat64ToWord32WithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  m.Return(m.JSTruncateFloat64ToWord32(m.Parameter(0)));
  Stream s = m.Build(kAllInstructions);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArchNop, s[0]->arch_opcode());
  EXPECT_EQ(kArchTruncateDoubleToI, s[1]->arch_opcode());
  EXPECT_EQ(1U, s[1]->InputCount());
  EXPECT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArchRet, s[2]->arch_opcode());
}

// -----------------------------------------------------------------------------
// Parameters.

TARGET_TEST_F(TurboshaftInstructionSelectorTest, DoubleParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex param = m.Parameter(0);
  m.Return(param);
  Stream s = m.Build(kAllInstructions);
  EXPECT_TRUE(s.IsDouble(param));
}

TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReferenceParameter) {
  StreamBuilder m(this, MachineType::AnyTagged(), MachineType::AnyTagged());
  OpIndex param = m.Parameter(0);
  m.Return(param);
  Stream s = m.Build(kAllInstructions);
  EXPECT_TRUE(s.IsReference(param));
}

// -----------------------------------------------------------------------------
// Phi.

using TurboshaftInstructionSelectorPhiTest =
    TurboshaftInstructionSelectorTestWithParam<MachineType>;

TARGET_TEST_P(TurboshaftInstructionSelectorPhiTest, Doubleness) {
  const MachineType type = GetParam();
  StreamBuilder m(this, type, type, type);
  OpIndex param0 = m.Parameter(0);
  OpIndex param1 = m.Parameter(1);
  Block *a = m.NewBlock(), *b = m.NewBlock(), *c = m.NewBlock();
  m.Branch(m.Int32Constant(0), a, b);
  m.Bind(a);
  m.Goto(c);
  m.Bind(b);
  m.Goto(c);
  m.Bind(c);
  OpIndex phi = m.Phi(type.representation(), param0, param1);
  m.Return(phi);
  Stream s = m.Build(kAllInstructions);
  EXPECT_EQ(s.IsDouble(phi), s.IsDouble(param0));
  EXPECT_EQ(s.IsDouble(phi), s.IsDouble(param1));
}

TARGET_TEST_P(TurboshaftInstructionSelectorPhiTest, Referenceness) {
  const MachineType type = GetParam();
  StreamBuilder m(this, type, type, type);
  OpIndex param0 = m.Parameter(0);
  OpIndex param1 = m.Parameter(1);
  Block *a = m.NewBlock(), *b = m.NewBlock(), *c = m.NewBlock();
  m.Branch(m.Int32Constant(1), a, b);
  m.Bind(a);
  m.Goto(c);
  m.Bind(b);
  m.Goto(c);
  m.Bind(c);
  OpIndex phi = m.Phi(type.representation(), param0, param1);
  m.Return(phi);
  Stream s = m.Build(kAllInstructions);
  EXPECT_EQ(s.IsReference(phi), s.IsReference(param0));
  EXPECT_EQ(s.IsReference(phi), s.IsReference(param1));
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest, TurboshaftInstructionSelectorPhiTest,
    ::testing::Values(MachineType::Float64(), MachineType::Int8(),
                      MachineType::Uint8(), MachineType::Int16(),
                      MachineType::Uint16(), MachineType::Int32(),
                      MachineType::Uint32(), MachineType::Int64(),
                      MachineType::Uint64(), MachineType::Pointer(),
                      MachineType::AnyTagged()));

// TODO(dmercadier): port following tests to Turboshaft.
#if 0

// -----------------------------------------------------------------------------
// Calls with deoptimization.

TARGET_TEST_F(TurboshaftInstructionSelectorTest, CallJSFunctionWithDeopt) {
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
  Node* nodes[] = {function_node,      receiver, m.UndefinedConstant(),
                   m.Int32Constant(1), context,  state_node};
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

#endif

}  // namespace v8::internal::compiler::turboshaft

"""

```