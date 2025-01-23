Response: My thinking process to summarize the given C++ code involved these steps:

1. **Identify the Core Purpose:**  The filename `instruction-selector-riscv64.cc` immediately suggests that this code is responsible for *instruction selection* on the RISC-V 64-bit architecture. Instruction selection is a crucial step in a compiler's backend, translating high-level intermediate representations into low-level machine instructions.

2. **Scan for Key Data Structures and Concepts:** I looked for prominent types and namespaces. The presence of `v8::internal::compiler`, `InstructionSelectorT`, `RiscvOperandGeneratorT`, and mentions of nodes (`Node*` or `typename Adapter::node_t`) confirms it's part of the V8 JavaScript engine's compiler, specifically dealing with instruction selection. The use of templates (`template <typename Adapter>`) indicates this code is designed to work with different compiler phases or intermediate representations.

3. **Analyze the Functions and Methods:**  I went through the defined functions, focusing on their names and what they seem to do:
    * `GetIntegerConstantValue`:  Retrieves integer constant values from compiler nodes.
    * `CanBeImmediate`:  Checks if a given value can be used as an immediate operand for a specific RISC-V instruction. This is vital for efficient instruction encoding.
    * `ExtendingLoadMatcher` and `TryEmitExtendingLoad`:  Deal with optimizing loads by potentially loading smaller data sizes and extending them, specifically looking for patterns like loading a 32-bit value within a 64-bit load followed by a shift.
    * `EmitLoad` and `EmitS128Load`: Generate RISC-V load instructions, handling different addressing modes (immediate, register+register, root register).
    * `VisitStoreLane` and `VisitLoadLane`:  Handle SIMD lane load and store operations.
    * `GetLoadOpcode` and `GetStoreOpcode`:  Determine the correct RISC-V load and store opcodes based on memory representation and register representation.
    * `VisitLoad`, `VisitStore`, `VisitProtectedLoad`, `VisitProtectedStore`: Implement the logic for selecting and emitting load and store instructions for various scenarios (including protected memory access and write barriers).
    * `VisitWord32And`, `VisitWord64And`, etc.:  These `Visit...` functions are the core of instruction selection. They handle specific intermediate representation opcodes (like bitwise AND, OR, XOR, shifts) and translate them into the corresponding RISC-V instructions, potentially with optimizations.
    * Functions related to arithmetic operations (`VisitInt32Add`, `VisitInt64Sub`, `VisitInt32Mul`, `VisitInt32Div`, etc.) and floating-point conversions (`VisitChangeFloat32ToFloat64`, `VisitTruncateFloat64ToInt32`, etc.).

4. **Identify JavaScript Relevance (If Any):**  Since this is part of V8, there *must* be a connection to JavaScript. The compiler's job is to take JavaScript code and turn it into machine code. Therefore, this file is involved in the process of compiling JavaScript operations (like arithmetic, memory access, etc.) into RISC-V assembly instructions.

5. **Formulate the Summary:** Based on the analysis, I constructed the summary, focusing on:
    * **Primary Function:** Instruction selection for RISC-V 64-bit.
    * **Key Responsibilities:** Translating compiler IR nodes into RISC-V instructions, handling memory access (loads/stores), bitwise operations, arithmetic operations, floating-point conversions, and applying optimizations.
    * **Relationship to JavaScript:**  It's a core component of the V8 compiler backend responsible for generating machine code from JavaScript.

6. **Create a JavaScript Example (If Requested):** To illustrate the connection, I thought of simple JavaScript operations that would correspond to the C++ code's functionality. Basic arithmetic (`+`, `-`, `*`), bitwise operations (`&`, `|`, `^`, `>>`, `<<`), and memory access (variable assignment/access) are good examples. I then showed how these JavaScript operations would, at a low level, involve the types of RISC-V instructions being selected in the C++ code.

7. **Refine and Organize:** I made sure the summary was clear, concise, and logically organized, highlighting the most important aspects of the code's functionality. I explicitly addressed the "Part 1" aspect, indicating that this is only a portion of the complete instruction selector.

By following these steps, I could effectively understand the purpose of the C++ code and its relationship to JavaScript execution within the V8 engine.
这个C++源代码文件是V8 JavaScript引擎中用于RISC-V 64位架构的**指令选择器**的一部分。它的主要功能是将编译器生成的中间表示（IR，Intermediate Representation）节点转换为具体的RISC-V 64位机器指令。

更具体地说，这部分代码（Part 1）主要关注以下几个方面：

1. **辅助函数和数据结构定义:**
   - 定义了 `RiscvOperandGeneratorT` 模板类，用于生成RISC-V指令的操作数。这个类包含了一些辅助方法，例如：
     - `GetIntegerConstantValue`:  从IR节点中获取整数常量值。
     - `CanBeImmediate`: 判断一个值是否能作为特定RISC-V指令的立即数。
   - 定义了 `ExtendingLoadMatcher` 结构体，用于匹配特定的加载模式，并尝试优化加载操作（例如，将加载一个64位的值并右移32位优化为直接加载一个32位的值）。
   - 定义了一些模板函数，如 `TryEmitExtendingLoad`，用于尝试发出优化后的加载指令。

2. **加载指令的选择和生成:**
   - 提供了 `EmitLoad` 模板函数，用于根据不同的寻址模式（例如，基于寄存器、基于立即数、基于根寄存器）生成 RISC-V 的加载指令 (`Lb`, `Lbu`, `Lh`, `Lhu`, `Lw`, `Lwu`, `Ld`, `LoadFloat`, `LoadDouble`, 以及压缩指针和保护指针相关的加载指令)。
   - 针对Turboshaft和Turbofan两种不同的编译器后端，提供了特化的 `EmitLoad` 版本。
   - 提供了 `EmitS128Load` 模板函数，用于生成SIMD (向量) 寄存器的加载指令。

3. **存储指令的选择和生成 (部分):**
   - 提供了 `VisitStoreLane` 函数的模板特化版本，用于处理 SIMD 寄存器的存储操作。
   -  虽然 `VisitStore` 等更通用的存储指令选择函数没有完全展示在这部分代码中，但可以推断，后续的部分会继续处理各种存储操作。

4. **位运算指令的选择和生成 (部分):**
   - 提供了针对 `Word32And`, `Word64And`, `Word32Or`, `Word64Or`, `Word32Xor`, `Word64Xor`, `Word64Shl` 等位运算的 `Visit` 函数，用于将这些 IR 节点转换为相应的 RISC-V 位运算指令。
   - 针对 Turboshaft 和 Turbofan 两种后端，部分位运算指令有不同的处理逻辑。

5. **类型转换指令的选择和生成 (部分):**
   - 提供了针对 `ChangeFloat32ToFloat64`, `RoundInt32ToFloat32`, `ChangeInt32ToFloat64` 等浮点数类型转换的 `Visit` 函数。
   -  也提供了一些整数类型转换的 `Visit` 函数，如 `BitcastWord32ToWord64`, `ChangeInt32ToInt64` 等。

**与 JavaScript 的关系及示例:**

指令选择器的功能是将 JavaScript 代码编译成机器码的关键步骤。当 V8 引擎执行 JavaScript 代码时，它首先将源代码解析成抽象语法树 (AST)，然后通过不同的编译器阶段生成中间表示 (IR)。指令选择器就负责将这些 IR 节点转换成 RISC-V CPU 可以执行的指令。

例如，以下 JavaScript 代码：

```javascript
let a = 10;
let b = 20;
let c = a + b;
console.log(c);

let d = a & b; // 位运算 AND
```

在这个例子中，指令选择器会处理以下操作并生成相应的 RISC-V 指令（简化示例）：

- **`let a = 10;`**:  可能会生成将常量 `10` 加载到寄存器的指令。
- **`let b = 20;`**: 可能会生成将常量 `20` 加载到另一个寄存器的指令。
- **`let c = a + b;`**:  `VisitInt32Add` (或其他类似的函数) 会被调用，生成 RISC-V 的加法指令 (`addw` 或 `add`)，将 `a` 和 `b` 对应的寄存器中的值相加，并将结果存储到 `c` 对应的寄存器中。
- **`console.log(c);`**:  会生成调用 `console.log` 函数的指令，这涉及到函数调用约定和参数传递。
- **`let d = a & b;`**: `VisitWord32And` (或其他类似的函数) 会被调用，生成 RISC-V 的位与指令 (`and`)，将 `a` 和 `b` 对应寄存器中的值进行按位与运算，并将结果存储到 `d` 对应的寄存器中。

再例如，对于以下 JavaScript 位移操作：

```javascript
let x = 5;
let y = x << 2; // 左移
```

`VisitWord32Shl` 或 `VisitWord64Shl` 会被调用，并根据操作数类型生成 RISC-V 的左移指令 (`slliw` 或 `sll`)。

**总结 Part 1 的功能:**

这部分代码主要负责 RISC-V 64 位架构中**基本操作数生成**和**部分指令的选择和生成**，重点在于：

- **辅助工具**: 提供用于生成操作数和判断立即数的工具函数。
- **加载指令**: 处理各种类型的加载操作。
- **部分存储指令**:  开始处理存储操作，特别是 SIMD 相关的存储。
- **部分位运算指令**:  处理一些基本的位运算。
- **部分类型转换指令**: 处理一些基本的数值类型转换。

这只是指令选择器的一部分，后续的部分会继续处理其他类型的指令，例如控制流指令（跳转、分支）、比较指令、更复杂的算术运算以及函数调用等。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/riscv/instruction-selector-riscv.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {
template <typename Adapter>
int64_t RiscvOperandGeneratorT<Adapter>::GetIntegerConstantValue(Node* node) {
  if (node->opcode() == IrOpcode::kInt32Constant) {
    return OpParameter<int32_t>(node->op());
  } else if (node->opcode() == IrOpcode::kInt64Constant) {
    return OpParameter<int64_t>(node->op());
  }
  DCHECK_EQ(node->opcode(), IrOpcode::kNumberConstant);
  const double value = OpParameter<double>(node->op());
  DCHECK_EQ(base::bit_cast<int64_t>(value), 0);
  return base::bit_cast<int64_t>(value);
}

template <typename Adapter>
bool RiscvOperandGeneratorT<Adapter>::CanBeImmediate(int64_t value,
                                                     InstructionCode opcode) {
  switch (ArchOpcodeField::decode(opcode)) {
    case kRiscvShl32:
    case kRiscvSar32:
    case kRiscvShr32:
      return is_uint5(value);
    case kRiscvShl64:
    case kRiscvSar64:
    case kRiscvShr64:
      return is_uint6(value);
    case kRiscvAdd32:
    case kRiscvAnd32:
    case kRiscvAnd:
    case kRiscvAdd64:
    case kRiscvOr32:
    case kRiscvOr:
    case kRiscvTst64:
    case kRiscvTst32:
    case kRiscvXor:
      return is_int12(value);
    case kRiscvLb:
    case kRiscvLbu:
    case kRiscvSb:
    case kRiscvLh:
    case kRiscvLhu:
    case kRiscvSh:
    case kRiscvLw:
    case kRiscvSw:
    case kRiscvLd:
    case kRiscvSd:
    case kRiscvLoadFloat:
    case kRiscvStoreFloat:
    case kRiscvLoadDouble:
    case kRiscvStoreDouble:
      return is_int32(value);
    default:
      return is_int12(value);
  }
}

template <typename Adapter>
struct ExtendingLoadMatcher {
  ExtendingLoadMatcher(typename Adapter::node_t node,
                       InstructionSelectorT<Adapter>* selector)
      : matches_(false), selector_(selector), immediate_(0) {
    Initialize(node);
  }

  bool Matches() const { return matches_; }

  typename Adapter::node_t base() const {
    DCHECK(Matches());
    return base_;
  }
  int64_t immediate() const {
    DCHECK(Matches());
    return immediate_;
  }
  ArchOpcode opcode() const {
    DCHECK(Matches());
    return opcode_;
  }

 private:
  bool matches_;
  InstructionSelectorT<Adapter>* selector_;
  typename Adapter::node_t base_{};
  int64_t immediate_;
  ArchOpcode opcode_;

  void Initialize(Node* node) {
    Int64BinopMatcher m(node);
    // When loading a 64-bit value and shifting by 32, we should
    // just load and sign-extend the interesting 4 bytes instead.
    // This happens, for example, when we're loading and untagging SMIs.
    DCHECK(m.IsWord64Sar());
    if (m.left().IsLoad() && m.right().Is(32) &&
        selector_->CanCover(m.node(), m.left().node())) {
      DCHECK_EQ(selector_->GetEffectLevel(node),
                selector_->GetEffectLevel(m.left().node()));
      MachineRepresentation rep =
          LoadRepresentationOf(m.left().node()->op()).representation();
      DCHECK_EQ(3, ElementSizeLog2Of(rep));
      if (rep != MachineRepresentation::kTaggedSigned &&
          rep != MachineRepresentation::kTaggedPointer &&
          rep != MachineRepresentation::kTagged &&
          rep != MachineRepresentation::kWord64) {
        return;
      }

      RiscvOperandGeneratorT<Adapter> g(selector_);
      Node* load = m.left().node();
      Node* offset = load->InputAt(1);
      base_ = load->InputAt(0);
      opcode_ = kRiscvLw;
      if (g.CanBeImmediate(offset, opcode_)) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
        immediate_ = g.GetIntegerConstantValue(offset) + 4;
#elif defined(V8_TARGET_BIG_ENDIAN)
        immediate_ = g.GetIntegerConstantValue(offset);
#endif
        matches_ = g.CanBeImmediate(immediate_, kRiscvLw);
      }
    }
  }

  void Initialize(turboshaft::OpIndex node) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift = selector_->Get(node).template Cast<ShiftOp>();
    DCHECK(shift.kind == ShiftOp::Kind::kShiftRightArithmetic ||
           shift.kind == ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros);
    // When loading a 64-bit value and shifting by 32, we should
    // just load and sign-extend the interesting 4 bytes instead.
    // This happens, for example, when we're loading and untagging SMIs.
    const Operation& lhs = selector_->Get(shift.left());
    int64_t constant_rhs;

    if (lhs.Is<LoadOp>() &&
        selector_->MatchIntegralWord64Constant(shift.right(), &constant_rhs) &&
        constant_rhs == 32 && selector_->CanCover(node, shift.left())) {
      RiscvOperandGeneratorT<Adapter> g(selector_);
      const LoadOp& load = lhs.Cast<LoadOp>();
      base_ = load.base();
      opcode_ = kRiscvLw;
      if (load.index().has_value()) {
        int64_t index_constant;
        if (selector_->MatchIntegralWord64Constant(load.index().value(),
                                                   &index_constant)) {
          DCHECK_EQ(load.element_size_log2, 0);
          immediate_ = index_constant + 4;
          matches_ = g.CanBeImmediate(immediate_, kRiscvLw);
        }
      } else {
        immediate_ = load.offset + 4;
        matches_ = g.CanBeImmediate(immediate_, kRiscvLw);
      }
    }
  }
};

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          typename Adapter::node_t output_node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  RiscvOperandGeneratorT<Adapter> g(selector);
  if (m.Matches()) {
    InstructionOperand inputs[2];
    inputs[0] = g.UseRegister(m.base());
    InstructionCode opcode =
        m.opcode() | AddressingModeField::encode(kMode_MRI);
    DCHECK(is_int32(m.immediate()));
    inputs[1] = g.TempImmediate(static_cast<int32_t>(m.immediate()));
    InstructionOperand outputs[] = {g.DefineAsRegister(output_node)};
    selector->Emit(opcode, arraysize(outputs), outputs, arraysize(inputs),
                   inputs);
    return true;
  }
  return false;
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  Node* base = selector->input_at(node, 0);
  Node* index = selector->input_at(node, 1);

  ExternalReferenceMatcher m(base);
  if (m.HasResolvedValue() && g.IsIntegerConstant(index) &&
      selector->CanAddressRelativeToRootsRegister(m.ResolvedValue())) {
    ptrdiff_t const delta =
        g.GetIntegerConstantValue(index) +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            selector->isolate(), m.ResolvedValue());
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode,
                     g.DefineAsRegister(output == nullptr ? node : output),
                     g.UseImmediate(static_cast<int32_t>(delta)));
      return;
    }
  }

  if (base != nullptr && base->opcode() == IrOpcode::kLoadRootRegister) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_Root),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   g.UseImmediate(index));
    return;
  }

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   g.UseRegister(base), g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(base), g.UseRegister(index));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   addr_reg, g.TempImmediate(0));
  }
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              typename TurboshaftAdapter::node_t output) {
  RiscvOperandGeneratorT<TurboshaftAdapter> g(selector);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(node);
  const LoadOp& load = op.Cast<LoadOp>();

  // The LoadStoreSimplificationReducer transforms all loads into
  // *(base + index).
  OpIndex base = load.base();
  OpIndex index = load.index().value();
  DCHECK_EQ(load.offset, 0);
  DCHECK_EQ(load.element_size_log2, 0);

  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand output_op;

  // If output is valid, use that as the output register. This is used when we
  // merge a conversion into the load.
  output_op = g.DefineAsRegister(output.valid() ? output : node);

  const Operation& base_op = selector->Get(base);
  if (base_op.Is<Opmask::kExternalConstant>() &&
      selector->is_integer_constant(index)) {
    const ConstantOp& constant_base = base_op.Cast<ConstantOp>();
    if (selector->CanAddressRelativeToRootsRegister(
            constant_base.external_reference())) {
      ptrdiff_t const delta =
          selector->integer_constant(index) +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector->isolate(), constant_base.external_reference());
      input_count = 1;
      // Check that the delta is a 32-bit integer due to the limitations of
      // immediate operands.
      if (is_int32(delta)) {
        inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
        opcode |= AddressingModeField::encode(kMode_Root);
        selector->Emit(opcode, 1, &output_op, input_count, inputs);
        return;
      }
    }
  }

  if (base_op.Is<LoadRootRegisterOp>()) {
    DCHECK(selector->is_integer_constant(index));
    input_count = 1;
    inputs[0] = g.UseImmediate64(selector->integer_constant(index));
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, &output_op, input_count, inputs);
    return;
  }

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node),
                   g.UseRegister(base), g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node), addr_reg,
                   g.TempImmediate(0));
  }
}

template <typename Adapter>
void EmitS128Load(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  VSew sew, Vlmul lmul) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t base = selector->input_at(node, 0);
  typename Adapter::node_t index = selector->input_at(node, 1);
  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index), g.UseImmediate(sew),
                   g.UseImmediate(lmul));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0),
                   g.UseImmediate(sew), g.UseImmediate(lmul));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kRiscvS128StoreLane;
  opcode |= LaneSizeField::encode(store.lane_size() * kBitsPerByte);
  if (store.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd64, addr_reg, g.UseRegister(base), g.UseRegister(index));
  InstructionOperand inputs[4] = {
      g.UseRegister(input_at(node, 2)),
      g.UseImmediate(store.lane),
      addr_reg,
      g.TempImmediate(0),
  };
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep, params.laneidx);
  InstructionCode opcode = kRiscvS128StoreLane;
  opcode |=
      LaneSizeField::encode(ElementSizeInBytes(params.rep) * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = this->input_at(node, 0);
  Node* index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd64, addr_reg, g.UseRegister(base), g.UseRegister(index));
  InstructionOperand inputs[4] = {
      g.UseRegister(this->input_at(node, 2)),
      g.UseImmediate(f.laneidx),
      addr_reg,
      g.TempImmediate(0),
  };
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kRiscvS128LoadLane;
  opcode |= LaneSizeField::encode(load.lane_size() * kBitsPerByte);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd64, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 2)), g.UseImmediate(load.lane),
       addr_reg, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  DCHECK(
      params.rep == MachineType::Int8() || params.rep == MachineType::Int16() ||
      params.rep == MachineType::Int32() || params.rep == MachineType::Int64());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode = kRiscvS128LoadLane;
  opcode |= LaneSizeField::encode(params.rep.MemSize() * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = this->input_at(node, 0);
  Node* index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd64, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(params.laneidx), addr_reg, g.TempImmediate(0));
}

namespace {
ArchOpcode GetLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                         turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLb;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLbu;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLh;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLhu;
    case MemoryRepresentation::Int32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLw;
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kRiscvLwu;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kRiscvLd;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kRiscvLoadFloat;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kRiscvLoadDouble;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kRiscvLwu;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kRiscvLoadDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kRiscvLwu;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kRiscvLoadDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kRiscvLd;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kRiscvLd;
    case MemoryRepresentation::ProtectedPointer():
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return kRiscvLoadDecompressProtected;
    case MemoryRepresentation::IndirectPointer():
      UNREACHABLE();
    case MemoryRepresentation::SandboxedPointer():
      return kRiscvLoadDecodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      return kRiscvRvvLd;
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode GetLoadOpcode(LoadRepresentation load_rep) {
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      return kRiscvLoadFloat;
    case MachineRepresentation::kFloat64:
      return kRiscvLoadDouble;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
    case MachineRepresentation::kWord16:
      return load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
    case MachineRepresentation::kWord32:
      return load_rep.IsUnsigned() ? kRiscvLwu : kRiscvLw;
#ifdef V8_COMPRESS_POINTERS
      case MachineRepresentation::kTaggedSigned:
        return kRiscvLoadDecompressTaggedSigned;
      case MachineRepresentation::kTaggedPointer:
        return kRiscvLoadDecompressTagged;
      case MachineRepresentation::kTagged:
        return kRiscvLoadDecompressTagged;
#else
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
#endif
      case MachineRepresentation::kWord64:
        return kRiscvLd;
      case MachineRepresentation::kSimd128:
        return kRiscvRvvLd;
      case MachineRepresentation::kCompressedPointer:
      case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
        return kRiscvLwu;
#else
#endif
      case MachineRepresentation::kProtectedPointer:
        CHECK(V8_ENABLE_SANDBOX_BOOL);
        return kRiscvLoadDecompressProtected;
      case MachineRepresentation::kSandboxedPointer:
        return kRiscvLoadDecodeSandboxedPointer;
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kIndirectPointer:  // Fall through.
      case MachineRepresentation::kFloat16:          // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }
}
ArchOpcode GetStoreOpcode(turboshaft::MemoryRepresentation stored_rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      return kRiscvSb;
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      return kRiscvSh;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return kRiscvSw;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return kRiscvSd;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      return kRiscvStoreFloat;
    case MemoryRepresentation::Float64():
      return kRiscvStoreDouble;
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      return kRiscvStoreCompressTagged;
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      return kRiscvSd;
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return kRiscvStoreIndirectPointer;
    case MemoryRepresentation::SandboxedPointer():
      return kRiscvStoreEncodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      return kRiscvRvvSt;
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kRiscvStoreFloat;
    case MachineRepresentation::kFloat64:
      return kRiscvStoreDouble;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return kRiscvSb;
    case MachineRepresentation::kWord16:
      return kRiscvSh;
    case MachineRepresentation::kWord32:
      return kRiscvSw;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
#ifdef V8_COMPRESS_POINTERS
      return kRiscvStoreCompressTagged;
#endif
    case MachineRepresentation::kWord64:
      return kRiscvSd;
    case MachineRepresentation::kSimd128:
      return kRiscvRvvSt;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kRiscvStoreCompressTagged;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kSandboxedPointer:
      return kRiscvStoreEncodeSandboxedPointer;
    case MachineRepresentation::kIndirectPointer:
      return kRiscvStoreIndirectPointer;
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kNone:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kFloat16:
      UNREACHABLE();
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();

  InstructionCode opcode = kArchNop;
  if constexpr (Adapter::IsTurboshaft) {
    opcode = GetLoadOpcode(load.ts_loaded_rep(), load.ts_result_rep());
  } else {
    opcode = GetLoadOpcode(load_rep);
  }
  bool traps_on_null;
  if (load.is_protected(&traps_on_null)) {
    if (traps_on_null) {
      opcode |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    } else {
      opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
    }
  }
  EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  VisitLoad(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  const MachineRepresentation rep = store_view.stored_rep().representation();

  // TODO(riscv): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      V8_LIKELY(!v8_flags.disable_write_barriers)) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(rep));
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(index);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code;
    if (rep == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate64(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= RecordWriteModeField::encode(record_write_mode);
    if (store_view.is_store_trap_on_null()) {
      code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    }
    Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
    return;
  }

  MachineRepresentation approx_rep = rep;
  InstructionCode code;
  if constexpr (Adapter::IsTurboshaft) {
    code = GetStoreOpcode(store_view.ts_stored_rep());
  } else {
    code = GetStoreOpcode(approx_rep);
  }

  if (this->is_load_root_register(base)) {
    Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
         g.UseRegisterOrImmediateZero(value), g.UseImmediate(index));
    return;
  }

  if (store_view.is_store_trap_on_null()) {
    code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
  } else if (store_view.access_kind() ==
             MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
         g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
         g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    Emit(kRiscvAdd64 | AddressingModeField::encode(kMode_None), addr_reg,
         g.UseRegister(index), g.UseRegister(base));
    // Emit desired store opcode, using temp addr_reg.
    Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
         g.UseRegisterOrImmediateZero(value), addr_reg, g.TempImmediate(0));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  VisitStore(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAnd32, true,
                                         kRiscvAnd32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAnd, true,
                                           kRiscvAnd);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if (m.left().IsWord64Shr() && CanCover(node, m.left().node()) &&
        m.right().HasResolvedValue()) {
      uint64_t mask = m.right().ResolvedValue();
      uint32_t mask_width = base::bits::CountPopulation(mask);
      uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
        // The mask must be contiguous, and occupy the least-significant bits.
        DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

        // Select Dext for And(Shr(x, imm), mask) where the mask is in the least
        // significant bits.
        Int64BinopMatcher mleft(m.left().node());
        if (mleft.right().HasResolvedValue()) {
          // Any shift value can match; int64 shifts use `value % 64`.
          uint32_t lsb =
              static_cast<uint32_t>(mleft.right().ResolvedValue() & 0x3F);

          // Dext cannot extract bits past the register size, however since
          // shifting the original value would have introduced some zeros we can
          // still use Dext with a smaller mask and the remaining bits will be
          // zeros.
          if (lsb + mask_width > 64) mask_width = 64 - lsb;

          if (lsb == 0 && mask_width == 64) {
            Emit(kArchNop, g.DefineSameAsFirst(node),
                 g.Use(mleft.left().node()));
            return;
          }
        }
        // Other cases fall through to the normal And operation.
      }
    }
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAnd, true,
                                           kRiscvAnd);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvOr32, true,
                                           kRiscvOr32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvOr, true,
                                           kRiscvOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor32, true,
                                           kRiscvXor32);
  } else {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor32, true,
                                           kRiscvXor32);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  } else {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift_op = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shift_op.left());
    const Operation& rhs = this->Get(shift_op.right());
    if ((lhs.Is<Opmask::kChangeInt32ToInt64>() ||
         lhs.Is<Opmask::kChangeUint32ToUint64>()) &&
        rhs.Is<Opmask::kWord32Constant>()) {
      int64_t shift_by = rhs.Cast<ConstantOp>().signed_integral();
      if (base::IsInRange(shift_by, 32, 63) &&
          CanCover(node, shift_op.left())) {
        RiscvOperandGeneratorT<Adapter> g(this);
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kRiscvShl64, g.DefineSameAsFirst(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate64(shift_by));
        return;
      }
    }
    VisitRRO(this, kRiscvShl64, node);
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kRiscvShl64, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    if (m.left().IsWord64And() && CanCover(node, m.left().node()) &&
        m.right().IsInRange(1, 63)) {
      // Match Word64Shl(Word64And(x, mask), imm) to Dshl where the mask is
      // contiguous, and the shift immediate non-zero.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        uint64_t mask = mleft.right().ResolvedValue();
        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
          uint64_t shift = m.right().ResolvedValue();
          DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));
          DCHECK_NE(0u, shift);

          if ((shift + mask_width) >= 64) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kRiscvShl64, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
      }
    }
    VisitRRO(this, kRiscvShl64, node);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    VisitRRO(this, kRiscvShr64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
    if (TryEmitExtendingLoad(this, node, node)) return;
    Int64BinopMatcher m(node);
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue() &&
        is_uint5(m.right().ResolvedValue()) &&
        CanCover(node, m.left().node())) {
      if ((m.left().InputAt(0)->opcode() != IrOpcode::kLoad &&
           m.left().InputAt(0)->opcode() != IrOpcode::kLoadImmutable) ||
          !CanCover(m.left().node(), m.left().InputAt(0))) {
        RiscvOperandGeneratorT<Adapter> g(this);
        Emit(kRiscvSar32, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()));
        return;
      }
    }
    VisitRRO(this, kRiscvSar64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Sar(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitExtendingLoad(this, node, node)) return;
  // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
  // where possible
  const ShiftOp& shiftop = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shiftop.left());

  int64_t constant_rhs;
  if (lhs.Is<Opmask::kChangeInt32ToInt64>() &&
      MatchIntegralWord64Constant(shiftop.right(), &constant_rhs) &&
      is_uint5(constant_rhs) && CanCover(node, shiftop.left())) {
    // Don't select Sbfx here if Asr(Ldrsw(x), imm) can be selected for
    // Word64Sar(ChangeInt32ToInt64(Load(x)), imm)
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kRiscvSar32, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right));
      return;
    }
  }
  VisitRRO(this, kRiscvSar64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kRiscvRor32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      Emit(kRiscvRev8, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      Emit(kRiscvByteSwap64, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvRev8, temp, g.UseRegister(this->input_at(node, 0)));
      Emit(kRiscvShr64, g.DefineAsRegister(node), temp, g.TempImmediate(32));
    } else {
      Emit(kRiscvByteSwap32, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvCtz64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
    VisitRRO(this, kRiscvRor64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
    VisitRR(this, kRiscvClz64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(this, node, kRiscvAdd32,
                                                   true, kRiscvAdd32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  VisitBinop<TurbofanAdapter, Int32BinopMatcher>(this, node, kRiscvAdd32, true,
                                         kRiscvAdd32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
    VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvAdd64, true,
                                           kRiscvAdd64);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  VisitBinop<Adapter, Int64BinopMatcher>(this, node, kRiscvSub64);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  node_t left = this->input_at(node, 0);
  node_t right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    const Operation& left_op = this->Get(left);
    const Operation& right_op = this->Get(right);
    if (left_op.Is<Opmask::kWord64ShiftRightLogical>() &&
        right_op.Is<Opmask::kWord64ShiftRightLogical>()) {
      RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
      if (this->integer_constant(this->input_at(left, 1)) == 32 &&
          this->integer_constant(this->input_at(right, 1)) == 32) {
        // Combine untagging shifts with Dmul high.
        Emit(kRiscvMulHigh64, g.DefineSameAsFirst(node),
             g.UseRegister(this->input_at(left, 0)),
             g.UseRegister(this->input_at(right, 0)));
        return;
      }
    }
  }
  VisitRRR(this, kRiscvMul32, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint32_t value = static_cast<uint32_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kRiscvSub32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher leftInput(left), rightInput(right);
      if (leftInput.right().Is(32) && rightInput.right().Is(32)) {
        // Combine untagging shifts with Dmul high.
        Emit(kRiscvMulHigh64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  VisitRRR(this, kRiscvMul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHigh32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64MulHigh(node_t node) {
    return VisitRRR(this, kRiscvMulHigh64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHighU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64MulHigh(node_t node) {
    VisitRRR(this, kRiscvMulHighU64, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt64Mul(node_t node) {
  VisitRRR(this, kRiscvMul64, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt64Mul(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  // TODO(dusmil): Add optimization for shifts larger than 32.
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint64_t value = static_cast<uint64_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kRiscvShl64 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvShl64 | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kRiscvSub64 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Emit(kRiscvMul64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvDiv32, node,
             OperandGenerator::RegisterUseKind::kUseUniqueRegister);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher rightInput(right), leftInput(left);
      if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
        // Combine both shifted operands with Ddiv.
        Emit(kRiscvDiv64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  Emit(kRiscvDiv32, g.DefineSameAsFirst(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node(),
                     OperandGenerator::RegisterUseKind::kUseUniqueRegister));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitRRR(this, kRiscvDivU32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvMod32, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  Node* left = this->input_at(node, 0);
  Node* right = this->input_at(node, 1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopMatcher rightInput(right), leftInput(left);
      if (rightInput.right().Is(32) && leftInput.right().Is(32)) {
        // Combine both shifted operands with Dmod.
        Emit(kRiscvMod64, g.DefineSameAsFirst(node),
             g.UseRegister(leftInput.left().node()),
             g.UseRegister(rightInput.left().node()));
        return;
      }
    }
  }
  Emit(kRiscvMod32, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kRiscvModU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Div(node_t node) {
  VisitRRR(this, kRiscvDiv64, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Div(node_t node) {
  VisitRRR(this, kRiscvDivU64, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvMod64, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);
  Emit(kRiscvMod64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint64Mod(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitRRR(this, kRiscvModU64, node);
  } else {
  RiscvOperandGeneratorT<Adapter> g(this);
  Int64BinopMatcher m(node);
  Emit(kRiscvModU64, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
       g.UseRegister(m.right().node()));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
  VisitRR(this, kRiscvCvtDW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt64ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDL, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncWS;
    opcode |= MiscField::encode(
        op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>());
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kRiscvTruncWS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncUwS;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kRiscvTruncUwS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitChangeFloat64ToInt32(
    node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  auto value = this->input_at(node, 0);
  if (CanCover(node, value)) {
    const Operation& op = this->Get(value);
    if (const FloatUnaryOp* load = op.TryCast<FloatUnaryOp>()) {
      DCHECK(load->rep == FloatRepresentation::Float64());
      switch (load->kind) {
        case FloatUnaryOp::Kind::kRoundDown:
          Emit(kRiscvFloorWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundUp:
          Emit(kRiscvCeilWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundToZero:
          Emit(kRiscvTruncWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        case FloatUnaryOp::Kind::kRoundTiesEven:
          Emit(kRiscvRoundWD, g.DefineAsRegister(node),
               g.UseRegister(this->input_at(value, 0)));
          return;
        default:
          break;
      }
    }
    if (op.Is<ChangeOp>()) {
      const ChangeOp& change = op.Cast<ChangeOp>();
      using Rep = turboshaft::RegisterRepresentation;
      if (change.from == Rep::Float32() && change.to == Rep::Float64()) {
        auto next = this->input_at(value, 0);
        if (CanCover(value, next)) {
          const Operation& next_op = this->Get(next);
          if (const FloatUnaryOp* round = next_op.TryCast<FloatUnaryOp>()) {
            DCHECK(round->rep == FloatRepresentation::Float32());
            switch (round->kind) {
              case FloatUnaryOp::Kind::kRoundDown:
                Emit(kRiscvFloorWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundUp:
                Emit(kRiscvCeilWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundToZero:
                Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              case FloatUnaryOp::Kind::kRoundTiesEven:
                Emit(kRiscvRoundWS, g.DefineAsRegister(node),
                     g.UseRegister(this->input_at(next, 0)));
                return;
              default:
                break;
            }
          }
        }
        // Match float32 -> float64 -> int32 representation change path.
        Emit(kRiscvTruncWS, g.DefineAsRegister(node),
             g.UseRegister(this->input_at(value, 0)));
        return;
      }
    }
  }
  VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* value = this->input_at(node, 0);
    // Match ChangeFloat64ToInt32(Float64Round##OP) to corresponding instruction
    // which does rounding and conversion to integer format.
    if (CanCover(node, value)) {
      switch (value->opcode()) {
        case IrOpcode::kFloat64RoundDown:
          Emit(kRiscvFloorWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundUp:
          Emit(kRiscvCeilWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTiesEven:
          Emit(kRiscvRoundWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        case IrOpcode::kFloat64RoundTruncate:
          Emit(kRiscvTruncWD, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        default:
          break;
      }
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        Node* next = value->InputAt(0);
        if (CanCover(value, next)) {
          // Match
          // ChangeFloat64ToInt32(ChangeFloat32ToFloat64(Float64Round##OP))
          switch (next->opcode()) {
            case IrOpcode::kFloat32RoundDown:
              Emit(kRiscvFloorWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundUp:
              Emit(kRiscvCeilWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTiesEven:
              Emit(kRiscvRoundWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            case IrOpcode::kFloat32RoundTruncate:
              Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                   g.UseRegister(next->InputAt(0)));
              return;
            default:
              Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                   g.UseRegister(value->InputAt(0)));
              return;
          }
        } else {
          // Match float32 -> float64 -> int32 representation change path.
          Emit(kRiscvTruncWS, g.DefineAsRegister(node),
               g.UseRegister(value->InputAt(0)));
          return;
        }
      }
    }
    VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt32(
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
    InstructionOperand outputs[2];
    size_t output_count = 0;
    outputs[output_count++] = g.DefineAsRegister(node);

    node_t success_output = FindProjection(node, 1);
    if (this->valid(success_output)) {
      outputs[output_count++] = g.DefineAsRegister(success_output);
    }

    this->Emit(kRiscvTruncWD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint32(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUwD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt64(node_t node) {
    VisitRR(this, kRiscvTruncLD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
    VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint64(node_t node) {
    VisitRR(this, kRiscvTruncUlD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToInt64(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    InstructionCode opcode = kRiscvTruncLD;
    const Operation& op = this->Get(node);
    if (op.Is<Opmask::kTruncateFloat64ToInt64OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kRiscvTruncLD;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToInt64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  this->Emit(kRiscvTruncLS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToInt64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncLD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat32ToUint64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUlS, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTryTruncateFloat64ToUint64(
    node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);

  InstructionOperand inputs[] = {g.UseRegister(this->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = FindProjection(node, 1);
  if (this->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  Emit(kRiscvTruncUlD, output_count, outputs, 1, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastWord32ToWord64(node_t node) {
    DCHECK(SmiValuesAre31Bits());
    DCHECK(COMPRESS_POINTERS_BOOL);
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvZeroExtendWord, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void EmitSignExtendWord(InstructionSelectorT<Adapter>* selector,
                        typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t value = selector->input_at(node, 0);
  selector->Emit(kRiscvSignExtendWord, g.DefineAsRegister(node),
                 g.UseRegister(value));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToInt64(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ChangeOp& change_op = this->Get(node).template Cast<ChangeOp>();
    const Operation& input_op = this->Get(change_op.input());
    if (input_op.Is<LoadOp>() && CanCover(node, change_op.input())) {
      // Generate sign-extending load.
      LoadRepresentation load_rep =
          this->load_view(change_op.input()).loaded_rep();
      MachineRepresentation rep = load_rep.representation();
      InstructionCode opcode = kArchNop;
      switch (rep) {
        case MachineRepresentation::kBit:  // Fall through.
        case MachineRepresentation::kWord8:
          opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
          break;
        case MachineRepresentation::kWord16:
          opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
          break;
        case MachineRepresentation::kWord32:
        case MachineRepresentation::kWord64:
          // Since BitcastElider may remove nodes of
          // IrOpcode::kTruncateInt64ToInt32 and directly use the inputs, values
          // with kWord64 can also reach this line.
        case MachineRepresentation::kTaggedSigned:
        case MachineRepresentation::kTaggedPointer:
        case MachineRepresentation::kTagged:
          opcode = kRiscvLw;
          break;
        default:
          UNREACHABLE();
      }
      EmitLoad(this, change_op.input(), opcode, node);
      return;
    }
    EmitSignExtendWord(this, node);
  } else {
    Node* value = this->input_at(node, 0);
    if ((value->opcode() == IrOpcode::kLoad ||
         value->opcode() == IrOpcode::kLoadImmutable) &&
        CanCover(node, value)) {
      // Generate sign-extending load.
      LoadRepresentation load_rep = LoadRepresentationOf(value->op());
      InstructionCode opcode = kArchNop;
      switch (load_rep.representation()) {
        case MachineRepresentation::kBit:  // Fall through.
        case Ma
```