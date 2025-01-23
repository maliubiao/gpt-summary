Response:
The user wants to understand the functionality of the provided C++ source code file: `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc`.

Here's a breakdown of the request and how to address each part:

1. **List the functionalities:** This requires analyzing the code to identify its main purpose and the tests it performs. Key elements to look for are class definitions, test macros, and the logic within the test functions.

2. **Check for Torque source:**  The user wants to know if the file is a Torque file based on its extension. The prompt provides the information that a `.tq` extension signifies a Torque file.

3. **Relate to JavaScript functionality (if applicable):** If the tests are related to how JavaScript code is compiled and executed, provide a JavaScript example. This involves understanding the connection between the compiler components being tested and the JavaScript features they handle.

4. **Provide code logic reasoning with input/output:** For specific test cases, illustrate the flow of data and expected outcomes. This often involves understanding the purpose of the operations being tested (e.g., arithmetic, conversions, function calls).

5. **Highlight common programming errors:**  If the tests reveal scenarios that might lead to programmer errors in JavaScript or in the V8 internals, provide examples of these errors.

**Plan:**

1. **High-level overview:** Identify the main purpose of the file (unit testing the Turboshaft instruction selector).
2. **Functionality breakdown:** Analyze the test cases and categorize the functionalities being tested (e.g., return statements, type conversions, parameter handling, Phi nodes).
3. **Torque check:** Examine the file extension.
4. **JavaScript relation:** Connect the tested functionalities to corresponding JavaScript concepts.
5. **Input/output for specific tests:** Select a few representative tests (e.g., `ReturnFloat32Constant`, `TruncateFloat64ToWord32WithParameter`) and explain the input and expected output at the instruction selection level.
6. **Common programming errors:** Based on the tested compiler features, infer potential user-level programming errors.
这个C++源代码文件 `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc` 是 **V8 JavaScript 引擎** 的一部分，专门用于 **单元测试** Turboshaft 编译器的 **指令选择器 (Instruction Selector)** 组件。

以下是它的主要功能分解：

1. **测试指令选择器的核心逻辑:**  指令选择器是编译器后端的一个关键阶段，它的作用是将中间表示（IR）的操作（例如，加法、减法、函数调用等）转换为目标架构（例如，x64, ARM）的机器指令。这个文件包含了一系列的测试用例，用于验证指令选择器在处理不同IR操作时是否生成了正确的机器指令序列。

2. **模拟不同的IR输入:**  测试用例通过 `StreamBuilder` 类来构建不同的IR图结构，这些图代表了不同的计算逻辑和数据类型。这使得可以针对各种不同的场景测试指令选择器的行为。

3. **验证生成的指令序列:**  每个测试用例都会运行指令选择器，并将生成的机器指令序列存储在 `Stream` 对象中。然后，测试用例会检查 `Stream` 中的指令数量、指令类型（操作码，`arch_opcode`）以及指令的操作数（输入和输出）。

4. **检查操作数的属性:** 测试用例会验证生成指令的操作数的各种属性，例如：
    * **寄存器分配策略:** 是否分配了固定的寄存器 (`IsFixed`)，是否与某个输入操作数相同 (`IsSameAsFirst`, `IsSameAsInput`)。
    * **常数:**  验证常数值是否正确 (`ConstantOperand::cast`, `s.ToInt32`, `s.ToFloat32`).
    * **立即数:** 验证立即数值是否正确 (`ImmediateOperand::cast`, `s.GetImmediate`).
    * **数据类型:** 验证虚拟寄存器是否被正确标记为浮点数 (`IsDouble`) 或引用类型 (`IsReference`).

5. **测试不同数据类型的处理:**  测试用例涵盖了多种数据类型，例如 `Float32`, `Float64`, `Int32`, `AnyTagged` (表示 JavaScript 对象) 等，以确保指令选择器能够正确处理不同类型的数据。

6. **测试控制流结构:**  通过创建包含分支 (`Branch`) 和合并 (`Phi`) 的 IR 图，测试指令选择器如何处理控制流的转换。

7. **模拟函数调用和返回:**  测试用例包含模拟函数调用 (`CallNWithFrameState`) 和返回 (`Return`) 的场景，这涉及到更复杂的指令选择和寄存器分配。

8. **处理去优化 (Deoptimization):**  虽然代码中有被注释掉的部分 (`#if 0 ... #endif`)，但可以看出，这个文件原本也包含测试涉及去优化的场景。去优化是指在优化编译的代码执行过程中，如果某些假设条件不成立，需要返回到未优化的代码执行。指令选择器需要生成正确的指令来支持去优化。

**关于你的问题中的其他点：**

* **`.tq` 结尾:**  如果 `v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。 Torque 是 V8 使用的一种领域特定语言，用于定义 V8 内部的运行时函数和操作。 **但实际上，这个文件以 `.cc` 结尾，所以它是一个 C++ 文件。**

* **与 JavaScript 功能的关系:**  指令选择器直接参与将 JavaScript 代码转换为机器码的过程。因此，这个文件中的测试用例与 JavaScript 的各种功能都有关系，因为它们最终都会被编译成机器指令。例如：
    * **数值运算:** `ReturnFloat32Constant` 测试与 JavaScript 中的浮点数返回相关。
    * **类型转换:** `TruncateFloat64ToWord32WithParameter` 测试与 JavaScript 中将浮点数转换为整数的操作相关。
    * **函数调用:** 注释掉的 `CallJSFunctionWithDeopt` 和 `CallStubWithDeopt` 测试与 JavaScript 中的函数调用相关。
    * **控制流:** `TurboshaftInstructionSelectorPhiTest` 测试与 JavaScript 中的 `if` 语句、循环等控制流结构相关。

    **JavaScript 例子：**

    ```javascript
    function example(a) {
      return Math.trunc(a); // 对应 TruncateFloat64ToWord32WithParameter
    }

    function add(x, y) {
      return x + y; // 可能会有类似的测试用例，尽管这里没有直接展示
    }

    function conditional(flag, val1, val2) {
      if (flag) {
        return val1;
      } else {
        return val2;
      }
    } // 对应 Phi 节点的测试
    ```

* **代码逻辑推理、假设输入与输出:**

    **示例：`TARGET_TEST_F(TurboshaftInstructionSelectorTest, ReturnFloat32Constant)`**

    * **假设输入 (IR 构建):**  `StreamBuilder` 创建一个 IR 图，其中包含一个浮点数常量 `4.2f`，并且该常量被作为函数的返回值。
    * **指令选择器处理:** 指令选择器会为这个 IR 图生成对应的机器指令。
    * **预期输出 (生成的指令序列):**
        * 第一条指令 (`kArchNop`):  一个空操作，通常用于放置常量或作为占位符。它的输出是一个常量操作数，值为 `4.2f`。
        * 第二条指令 (`kArchRet`): 返回指令。它有两个输入：
            * 返回值 (来自前一个 `kArchNop` 指令的输出)。
            * 其他必要的返回信息 (在具体架构中可能不同)。

    **验证:** 测试代码会断言生成的指令数量为 2，第一条指令是 `kArchNop`，其输出是一个浮点数常量 `4.2f`，第二条指令是 `kArchRet`，并且有 2 个输入。

* **涉及用户常见的编程错误:**

    虽然这个文件主要测试编译器的内部逻辑，但某些测试场景可能与用户常见的编程错误间接相关。例如：

    * **类型错误:**  `TruncateFloat64ToWord32WithParameter` 测试了浮点数到整数的转换。 用户在 JavaScript 中不小心地对浮点数进行位运算或者期望整数结果时，可能会遇到类似的类型转换问题，导致意想不到的结果。

        ```javascript
        let floatValue = 3.14;
        let intValue = floatValue | 0; // 尝试将浮点数进行位运算，会触发类型转换
        console.log(intValue); // 输出 3
        ```

    * **函数调用参数错误:**  虽然代码中与函数调用相关的测试被注释掉了，但这些测试的目的在于验证编译器如何处理函数调用和参数传递。 用户在 JavaScript 中调用函数时，如果传递了错误数量或类型的参数，可能会导致运行时错误。

        ```javascript
        function greet(name) {
          console.log("Hello, " + name);
        }

        greet(); // 缺少参数，可能导致运行时错误
        greet(123); // 参数类型错误，虽然 JavaScript 是动态类型，但某些 V8 的优化路径可能对此敏感
        ```

总而言之，`v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc` 是一个重要的测试文件，用于确保 V8 引擎的 Turboshaft 编译器能够正确地将高级的 IR 操作转换为底层的机器指令，这是保证 JavaScript 代码高效执行的关键步骤。

### 提示词
```
这是目录为v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```