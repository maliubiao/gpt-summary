Response: The user wants me to summarize the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine, specifically for the RISC-V 32-bit architecture.

Therefore, the main function of this code is to select the appropriate RISC-V instructions for operations performed in the V8 engine. This involves mapping higher-level operations (represented in the intermediate representation of the compiler) to specific RISC-V assembly instructions.

Given the file name `instruction-selector-riscv32.cc`, I can infer that this file is responsible for instruction selection for the RISC-V 32-bit architecture. It likely contains implementations for various operations like loading, storing, arithmetic, logical operations, and comparisons.

Regarding the relationship with JavaScript, this code is a crucial part of how JavaScript code gets executed. The V8 engine compiles JavaScript into machine code, and this file helps in that compilation process by choosing the right RISC-V instructions.

To illustrate with JavaScript, I need to identify a common JavaScript operation and explain how this C++ code helps in executing it on a RISC-V 32-bit system. A simple arithmetic operation like addition would be a good example.这个C++代码文件 `instruction-selector-riscv32.cc` 是V8 JavaScript引擎的一部分，它的主要功能是 **为RISC-V 32位架构选择合适的机器指令**。

更具体地说，这个文件实现了 `InstructionSelector` 类的一些方法，这个类负责将V8的中间表示（IR，Intermediate Representation）中的操作（例如加载、存储、算术运算、比较等）转换为RISC-V 32位架构的机器指令。

这个文件的主要职责包括：

1. **定义操作数的生成方式**:  `RiscvOperandGeneratorT` 类负责生成RISC-V指令的操作数，例如寄存器、立即数等。
2. **判断常量是否可以作为立即数**: `CanBeImmediate` 函数判断一个给定的整数值是否可以作为特定RISC-V指令的立即数。
3. **实现各种IR节点的指令选择逻辑**: 文件中包含大量的 `Visit` 函数，每个函数对应一种IR节点（例如 `VisitLoad` 对应加载操作， `VisitInt32Add` 对应32位整数加法等）。这些函数会根据IR节点的类型和参数，选择合适的RISC-V指令并将其添加到指令序列中。
4. **处理内存访问**:  `EmitLoad` 和 `EmitStore` 等函数负责生成加载和存储指令，并考虑不同的寻址模式（例如基于寄存器、基于立即数、基于根寄存器等）。
5. **处理原子操作**:  文件中包含了 `VisitWord32AtomicLoad`, `VisitWord32AtomicStore`, `VisitWord32AtomicExchange` 等函数，用于选择RISC-V的原子操作指令。
6. **处理浮点数运算**:  例如 `VisitFloat32Neg`, `VisitFloat64Ieee754Binop` 等函数负责选择浮点数运算指令。
7. **处理比较操作和条件跳转**:  例如 `VisitWord32Equal`, `VisitInt32LessThan` 等函数，结合 `FlagsContinuation` 类，负责生成比较指令并设置条件码，以便后续的条件跳转指令使用。

**与JavaScript的功能的关系以及JavaScript示例：**

这个文件直接参与了JavaScript代码的执行过程。当V8引擎编译JavaScript代码时，会将JavaScript代码转换为中间表示（IR）。然后，`InstructionSelector` 类（以及这个文件中的RISC-V 32位特定实现）会将这些IR操作转换为实际的RISC-V机器指令，这些指令最终会在RISC-V处理器上执行。

**JavaScript 示例：**

假设有以下简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当V8引擎编译这段代码时，对于 `a + b` 这个操作，`instruction-selector-riscv32.cc` 文件中的 `VisitInt32Add` 函数（或者类似的函数，取决于V8的内部表示）会被调用。这个函数会根据操作数的类型和上下文，选择合适的RISC-V 32位加法指令，例如 `addw` 指令。

例如，`VisitInt32Add` 函数可能会生成如下的RISC-V汇编指令序列（简化示例）：

```assembly
  # 假设 'a' 的值在寄存器 x10，'b' 的值在寄存器 x11
  addw  a0, x10, x11  # 将 x10 和 x11 的值相加，结果存储到 a0 寄存器 (通常用于存储函数返回值)
```

在这个例子中，`instruction-selector-riscv32.cc` 的作用就是决定使用 `addw` 指令来实现 JavaScript 中的加法操作。它还会处理更复杂的情况，例如操作数是立即数、内存中的值等等，并选择最合适的RISC-V指令和寻址模式。

总而言之，`instruction-selector-riscv32.cc` 是V8引擎将高级的JavaScript操作转化为底层RISC-V机器指令的关键组成部分，确保了JavaScript代码能够在RISC-V 32位架构上高效地执行。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/bits.h"
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

#define TRACE(...) PrintF(__VA_ARGS__)

template <typename Adapter>
int64_t RiscvOperandGeneratorT<Adapter>::GetIntegerConstantValue(Node* node) {
  DCHECK_EQ(IrOpcode::kInt32Constant, node->opcode());
  return OpParameter<int32_t>(node->op());
}

template <typename Adapter>
bool RiscvOperandGeneratorT<Adapter>::CanBeImmediate(int64_t value,
                                                     InstructionCode opcode) {
  switch (ArchOpcodeField::decode(opcode)) {
    case kRiscvShl32:
    case kRiscvSar32:
    case kRiscvShr32:
      return is_uint5(value);
    case kRiscvAdd32:
    case kRiscvAnd32:
    case kRiscvAnd:
    case kRiscvOr32:
    case kRiscvOr:
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
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);

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
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
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
  OptionalOpIndex index = load.index();
  DCHECK_EQ(load.offset, 0);
  DCHECK_EQ(load.element_size_log2, 0);

  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand output_op;

  // If output is valid, use that as the output register. This is used when we
  // merge a conversion into the load.
  output_op = g.DefineAsRegister(output.valid() ? output : node);

  const Operation& base_op = selector->Get(base);
  if (base_op.Is<Opmask::kExternalConstant>() && index.has_value() &&
      selector->is_integer_constant(selector->value(index))) {
    const ConstantOp& constant_base = base_op.Cast<ConstantOp>();
    if (selector->CanAddressRelativeToRootsRegister(
            constant_base.external_reference())) {
      ptrdiff_t const delta =
          selector->integer_constant(selector->value(index)) +
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
    DCHECK(selector->is_integer_constant(selector->value(index)));
    input_count = 1;
    inputs[0] =
        g.UseImmediate64(selector->integer_constant(selector->value(index)));
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, &output_op, input_count, inputs);
    return;
  }

  if (index.has_value() && g.CanBeImmediate(selector->value(index), opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node),
                   g.UseRegister(base),
                   index.has_value() ? g.UseImmediate(selector->value(index))
                                     : g.UseImmediate(0));
  } else {
    if (index.has_value()) {
      InstructionOperand addr_reg = g.TempRegister();
      selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                     addr_reg, g.UseRegister(selector->value(index)),
                     g.UseRegister(base));
      // Emit desired load opcode, using temp addr_reg.
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.DefineAsRegister(output.valid() ? output : node),
                     addr_reg, g.TempImmediate(0));
    } else {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.DefineAsRegister(output.valid() ? output : node),
                     g.UseRegister(base), g.TempImmediate(0));
    }
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
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
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
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
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
  opcode |= MiscField::encode(f.sz);

  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  InstructionOperand inputs[4] = {
      g.UseRegister(node->InputAt(2)),
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
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 2)), g.UseImmediate(load.lane),
       addr_reg, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode = kRiscvS128LoadLane;
  opcode |= MiscField::encode(f.sz);

  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(params.laneidx), addr_reg, g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kRiscvLoadFloat;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kRiscvLoadDouble;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kRiscvLw;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kRiscvRvvLd;
      break;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kSandboxedPointer:
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kWord64:
    case MachineRepresentation::kNone:
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kProtectedPointer:  // Fall through.
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kFloat16:
      UNREACHABLE();
    }

    EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStore(node_t node) {
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  typename TurboshaftAdapter::StoreView store_view = this->store_view(node);
  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  MachineRepresentation rep = store_view.stored_rep().representation();

  // TODO(riscv): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier && index.has_value() &&
      V8_LIKELY(!v8_flags.disable_write_barriers)) {
    DCHECK(CanBeTaggedPointer(rep));
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(this->value(index));
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
  } else {
    InstructionCode code;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        code = kRiscvStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        code = kRiscvStoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        code = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        code = kRiscvSh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kWord32:
        code = kRiscvSw;
        break;
      case MachineRepresentation::kSimd128:
        code = kRiscvRvvSt;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (this->is_load_root_register(base)) {
      Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value),
           index.has_value() ? g.UseImmediate(this->value(index))
                             : g.UseImmediate(0));
      return;
    }

    if (index.has_value() && g.CanBeImmediate(this->value(index), code)) {
      Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
           index.has_value() ? g.UseImmediate(this->value(index))
                             : g.UseImmediate(0));
    } else {
      if (index.has_value()) {
        InstructionOperand addr_reg = g.TempRegister();
        Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
             g.UseRegister(this->value(index)), g.UseRegister(base));
        // Emit desired store opcode, using temp addr_reg.
        Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
             g.UseRegisterOrImmediateZero(value), addr_reg, g.TempImmediate(0));
      } else {
        Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
             g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
             g.UseImmediate(0));
      }
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStore(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  Node* value = node->InputAt(2);

  StoreRepresentation store_rep = StoreRepresentationOf(node->op());
  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  // TODO(riscv): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      V8_LIKELY(!v8_flags.disable_write_barriers)) {
    DCHECK(CanBeTaggedPointer(rep));
    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(index);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
    Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvStoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        opcode = kRiscvSh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kWord32:
        opcode = kRiscvSw;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvSt;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
        UNREACHABLE();
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (base != nullptr && base->opcode() == IrOpcode::kLoadRootRegister) {
      Emit(opcode | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseImmediate(index));
      return;
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
           g.UseImmediate(index));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), addr_reg, g.TempImmediate(0));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAnd, true,
                                         kRiscvAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvOr, true,
                                           kRiscvOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  } else {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  }
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
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kRiscvRor32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      Emit(kRiscvRev8, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
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
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Add(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd32, true,
                                         kRiscvAdd32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
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

  VisitRRR(this, kRiscvMul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitRRR(this, kRiscvMulHigh32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitRRR(this, kRiscvMulHighU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitRRR(this, kRiscvDiv32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitRRR(this, kRiscvDivU32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitRRR(this, kRiscvMod32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kRiscvModU32, node);
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
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
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

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kRiscvTruncUwS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  node_t value = this->input_at(node, 0);
  if constexpr (Adapter::IsTurboshaft) {
    using Rep = turboshaft::RegisterRepresentation;
    if (CanCover(node, value)) {
      const turboshaft::Operation& op = this->Get(value);
      if (op.Is<turboshaft::ChangeOp>()) {
        const turboshaft::ChangeOp& change = op.Cast<turboshaft::ChangeOp>();
        if (change.kind == turboshaft::ChangeOp::Kind::kFloatConversion) {
          if (change.from == Rep::Float32() && change.to == Rep::Float64()) {
            Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                 g.UseRegister(this->input_at(value, 0)));
            return;
          }
        }
      }
    }
  } else {
    if (CanCover(node, value)) {
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
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
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
    VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
    VisitRR(this, kRiscvBitcastFloat32ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvBitcastInt32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kRiscvFloat32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kRiscvNegS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kRiscvNegD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(opcode, g.DefineAsFixed(node, fa0),
         g.UseFixed(this->input_at(node, 0), fa0),
         g.UseFixed(this->input_at(node, 1), fa1))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t node, InstructionCode opcode) {
  RiscvOperandGeneratorT<Adapter> g(this);
  Emit(opcode, g.DefineAsFixed(node, fa0),
       g.UseFixed(this->input_at(node, 0), fa1))
      ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EmitPrepareArguments(
    ZoneVector<PushParameter>* arguments, const CallDescriptor* call_descriptor,
    node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);

    // Prepare for C function call.
    if (call_descriptor->IsCFunctionCall()) {
      Emit(kArchPrepareCallCFunction | MiscField::encode(static_cast<int>(
                                           call_descriptor->ParameterCount())),
           0, nullptr, 0, nullptr);

      // Poke any stack arguments.
      int slot = kCArgSlotCount;
      for (PushParameter input : (*arguments)) {
        Emit(kRiscvStoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
             g.TempImmediate(slot << kSystemPointerSizeLog2));
        ++slot;
      }
    } else {
      int push_count = static_cast<int>(call_descriptor->ParameterSlotCount());
      if (push_count > 0) {
        Emit(kRiscvStackClaim, g.NoOutput(),
             g.TempImmediate(arguments->size() << kSystemPointerSizeLog2));
      }
      for (size_t n = 0; n < arguments->size(); ++n) {
        PushParameter input = (*arguments)[n];
        if (this->valid(input.node)) {
          Emit(kRiscvStoreToStackSlot, g.NoOutput(), g.UseRegister(input.node),
               g.TempImmediate(static_cast<int>(n << kSystemPointerSizeLog2)));
        }
      }
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    LoadRepresentation load_rep = LoadRepresentationOf(node->op());
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* base = node->InputAt(0);
    Node* index = node->InputAt(1);

    ArchOpcode opcode;
    switch (load_rep.representation()) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvULoadFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvULoadDouble;
        break;
      case MachineRepresentation::kWord8:
        opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
        break;
      case MachineRepresentation::kWord16:
        opcode = load_rep.IsUnsigned() ? kRiscvUlhu : kRiscvUlh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
      case MachineRepresentation::kWord32:
        opcode = kRiscvUlw;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvLd;
        break;
      case MachineRepresentation::kSimd256:            // Fall through.
      case MachineRepresentation::kBit:                // Fall through.
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:         // Fall through.
      case MachineRepresentation::kSandboxedPointer:   // Fall through.
      case MachineRepresentation::kMapWord:            // Fall through.
      case MachineRepresentation::kProtectedPointer:   // Fall through.
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kNone:
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), g.UseRegister(base),
           g.UseImmediate(index));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired load opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI),
           g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    RiscvOperandGeneratorT<Adapter> g(this);
    Node* base = node->InputAt(0);
    Node* index = node->InputAt(1);
    Node* value = node->InputAt(2);

    UnalignedStoreRepresentation rep =
        UnalignedStoreRepresentationOf(node->op());
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvUStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvUStoreDouble;
        break;
      case MachineRepresentation::kWord8:
        opcode = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        opcode = kRiscvUsh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
      case MachineRepresentation::kWord32:
        opcode = kRiscvUsw;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvSt;
        break;
      case MachineRepresentation::kSimd256:            // Fall through.
      case MachineRepresentation::kBit:                // Fall through.
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:         // Fall through.
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kNone:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegister(base), g.UseImmediate(index),
           g.UseRegisterOrImmediateZero(value));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           addr_reg, g.TempImmediate(0), g.UseRegisterOrImmediateZero(value));
    }
  }
}

namespace {

template <typename Adapter>
void VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      FlagsContinuationT<Adapter>* cont) {
  VisitWordCompare(selector, node, kRiscvCmp, cont, false);
}

template <typename Adapter>
void VisitAtomicLoad(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, ArchOpcode opcode,
                     AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  auto load = selector->load_view(node);
  node_t base = load.base();
  node_t index = load.index();
  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0));
  }
}

template <typename Adapter>
void VisitAtomicStore(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode,
                      AtomicWidth width) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  auto store = selector->store_view(node);
  node_t base = store.base();
  node_t index = selector->value(store.index());
  node_t value = store.value();

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegisterOrImmediateZero(value),
                   g.UseRegister(base), g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired store opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI) |
                       AtomicWidthField::encode(width),
                   g.NoOutput(), g.UseRegisterOrImmediateZero(value), addr_reg,
                   g.TempImmediate(0));
  }
}

template <typename Adapter>
void VisitAtomicBinop(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node, ArchOpcode opcode) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temps[4];
  temps[0] = g.TempRegister();
  temps[1] = g.TempRegister();
  temps[2] = g.TempRegister();
  temps[3] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, 1, outputs, input_count, inputs, 4, temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuationT<Adapter>* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  RiscvOperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry ? 1 : 0);
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

// Shared routine for word comparisons against zero.
template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuationT<TurbofanAdapter>* cont) {
  // Try to combine with comparisons against 0 by simply inverting the branch.
  while (CanCover(user, value)) {
    if (value->opcode() == IrOpcode::kWord32Equal) {
      Int32BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else if (value->opcode() == IrOpcode::kWord64Equal) {
      Int64BinopMatcher m(value);
      if (!m.right().Is(0)) break;
      user = value;
      value = m.left().node();
    } else {
      break;
    }

    cont->Negate();
  }

  if (CanCover(user, value)) {
    switch (value->opcode()) {
      case IrOpcode::kWord32Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitWordCompare(this, value, cont);
      case IrOpcode::kInt32LessThan:
        cont->OverwriteAndNegateIfEqual(kSignedLessThan);
        return VisitWordCompare(this, value, cont);
      case IrOpcode::kInt32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kSignedLessThanOrEqual);
        return VisitWordCompare(this, value, cont);
      case IrOpcode::kUint32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitWordCompare(this, value, cont);
      case IrOpcode::kUint32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitWordCompare(this, value, cont);
      case IrOpcode::kFloat32Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat32LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitFloat32Compare(this, value, cont);
      case IrOpcode::kFloat64Equal:
        cont->OverwriteAndNegateIfEqual(kEqual);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kFloat64LessThan:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThan);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kFloat64LessThanOrEqual:
        cont->OverwriteAndNegateIfEqual(kUnsignedLessThanOrEqual);
        return VisitFloat64Compare(this, value, cont);
      case IrOpcode::kProjection:
        // Check if this is the overflow output projection of an
        // <Operation>WithOverflow node.
        if (ProjectionIndexOf(value->op()) == 1u) {
          // We cannot combine the <Operation>WithOverflow with this branch
          // unless the 0th projection (the use of the actual value of the
          // <Operation> is either nullptr, which means there's no use of the
          // actual value, or was already defined, which means it is scheduled
          // *AFTER* this branch).
          Node* const node = value->InputAt(0);
          Node* const result = NodeProperties::FindProjection(node, 0);
          if (result == nullptr || IsDefined(result)) {
            switch (node->opcode()) {
              case IrOpcode::kInt32AddWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvAddOvf, cont);
              case IrOpcode::kInt32SubWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvSubOvf, cont);
              case IrOpcode::kInt32MulWithOverflow:
                cont->OverwriteAndNegateIfEqual(kOverflow);
                return VisitBinop<TurbofanAdapter, Int32BinopMatcher>(
                    this, node, kRiscvMulOvf32, cont);
              case IrOpcode::kInt64AddWithOverflow:
              case IrOpcode::kInt64SubWithOverflow:
                TRACE("UNIMPLEMENTED instr_sel: %s at line %d\n", __FUNCTION__,
                      __LINE__);
                break;
              default:
                break;
            }
          }
        }
        break;
      case IrOpcode::kWord32And:
        VisitWordCompare(this, value, kRiscvTst32, cont, true);
        return;
      case IrOpcode::kStackPointerGreaterThan:
        cont->OverwriteAndNegateIfEqual(kStackPointerGreaterThanCondition);
        return VisitStackPointerGreaterThan(value, cont);
      default:
        break;
    }
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  EmitWordCompareZero(this, value, cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWordCompareZero(
    node_t user, node_t value, FlagsContinuation* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  // Try to combine with comparisons against 0 by simply inverting the branch.
  while (const ComparisonOp* equal =
             this->TryCast<Opmask::kWord32Equal>(value)) {
    if (!CanCover(user, value)) break;
    if (!MatchIntegralZero(equal->right())) break;

    user = value;
    value = equal->left();
    cont->Negate();
  }

  const Operation& value_op = Get(value);
  if (CanCover(user, value)) {
    if (const ComparisonOp* comparison = value_op.TryCast<ComparisonOp>()) {
      switch (comparison->rep.value()) {
        case RegisterRepresentation::Word32():
          cont->OverwriteAndNegateIfEqual(
              GetComparisonFlagCondition(*comparison));
          return VisitWordCompare(this, value, cont);
        case RegisterRepresentation::Float32():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat32Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
              return VisitFloat32Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        case RegisterRepresentation::Float64():
          switch (comparison->kind) {
            case ComparisonOp::Kind::kEqual:
              cont->OverwriteAndNegateIfEqual(kEqual);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThan:
              cont->OverwriteAndNegateIfEqual(kFloatLessThan);
              return VisitFloat64Compare(this, value, cont);
            case ComparisonOp::Kind::kSignedLessThanOrEqual:
              cont->OverwriteAndNegateIfEqual(kFloatLessThanOrEqual);
              return VisitFloat64Compare(this, value, cont);
            default:
              UNREACHABLE();
          }
        default:
          break;
      }
    } else if (const ProjectionOp* projection =
                   value_op.TryCast<ProjectionOp>()) {
      // Check if this is the overflow output projection of an
      // <Operation>WithOverflow node.
      if (projection->index == 1u) {
        // We cannot combine the <Operation>WithOverflow with this branch
        // unless the 0th projection (the use of the actual value of the
        // <Operation> is either nullptr, which means there's no use of the
        // actual value, or was already defined, which means it is scheduled
        // *AFTER* this branch).
        OpIndex node = projection->input();
        OpIndex result = FindProjection(node, 0);
        if (!result.valid() || IsDefined(result)) {
          if (const OverflowCheckedBinopOp* binop =
                  TryCast<OverflowCheckedBinopOp>(node)) {
            const bool is64 = binop->rep == WordRepresentation::Word64();
            if (is64) {
              UNREACHABLE();
            } else {
              switch (binop->kind) {
                case OverflowCheckedBinopOp::Kind::kSignedAdd:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                      this, node, kRiscvAddOvf, cont);
                case OverflowCheckedBinopOp::Kind::kSignedSub:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                      this, node, kRiscvSubOvf, cont);
                case OverflowCheckedBinopOp::Kind::kSignedMul:
                  cont->OverwriteAndNegateIfEqual(kOverflow);
                  return VisitBinop<TurboshaftAdapter, Int32BinopMatcher>(
                      this, node, kRiscvMulOvf32, cont);
              }
            }
          }
        }
      }
    }
  }

  // Continuation could not be combined with a compare, emit compare against
  // 0.
  EmitWordCompareZero(this, value, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Equal(node_t node) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);
    Int32BinopMatcher m(node);
    if (m.right().Is(0)) {
      return VisitWordCompareZero(m.node(), m.left().node(), &cont);
    }

    VisitWordCompare(this, node, &cont);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Equal(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& equal = Get(node);
  DCHECK(equal.Is<ComparisonOp>());
  OpIndex left = equal.input(0);
  OpIndex right = equal.input(1);
  OpIndex user = node;
  FlagsContinuation cont = FlagsContinuation::ForSet(kEqual, node);

  if (MatchZero(right)) {
    return VisitWordCompareZero(user, left, &cont);
  }
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kSignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kSignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThan(node_t node) {
  FlagsContinuation cont = FlagsContinuation::ForSet(kUnsignedLessThan, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32LessThanOrEqual(node_t node) {
  FlagsContinuation cont =
      FlagsContinuation::ForSet(kUnsignedLessThanOrEqual, node);
  VisitWordCompare(this, node, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32AddWithOverflow(node_t node) {
  node_t ovf = this->FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAddOvf,
                                                  &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAddOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32SubWithOverflow(node_t node) {
  node_t ovf = this->FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSubOvf,
                                                  &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSubOvf, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulWithOverflow(node_t node) {
  node_t ovf = this->FindProjection(node, 1);
  if (this->valid(ovf)) {
    FlagsContinuation cont = FlagsContinuation::ForSet(kOverflow, ovf);
    return VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvMulOvf32,
                                                  &cont);
  }
    FlagsContinuation cont;
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvMulOvf32, &cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicLoad(node_t node) {
  auto load = this->load_view(node);
  ArchOpcode opcode;
  LoadRepresentation load_rep = load.loaded_rep();
  switch (load_rep.representation()) {
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt8 : kAtomicLoadUint8;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kAtomicLoadInt16 : kAtomicLoadUint16;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kAtomicLoadWord32;
      break;
    default:
      UNREACHABLE();
  }
  VisitAtomicLoad(this, node, opcode, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicStore(node_t node) {
  auto store = this->store_view(node);
  AtomicStoreParameters store_params(store.stored_rep().representation(),
                                     store.stored_rep().write_barrier_kind(),
                                     store.memory_order().value(),
                                     store.access_kind());
  MachineRepresentation rep = store_params.representation();
  ArchOpcode opcode;
  switch (rep) {
    case MachineRepresentation::kWord8:
      opcode = kAtomicStoreWord8;
      break;
    case MachineRepresentation::kWord16:
      opcode = kAtomicStoreWord16;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kWord32:
      opcode = kAtomicStoreWord32;
      break;
    default:
      UNREACHABLE();
  }

    VisitAtomicStore(this, node, opcode, AtomicWidth::kWord32);
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         AtomicWidth width) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[3];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void VisitAtomicCompareExchange(InstructionSelectorT<Adapter>* selector,
                                typename Adapter::node_t node,
                                ArchOpcode opcode, AtomicWidth width) {
  using node_t = typename Adapter::node_t;
  RiscvOperandGeneratorT<Adapter> g(selector);
  auto atomic_op = selector->atomic_rmw_view(node);
  node_t base = atomic_op.base();
  node_t index = atomic_op.index();
  node_t old_value = atomic_op.expected();
  node_t new_value = atomic_op.value();

  AddressingMode addressing_mode = kMode_MRI;
  InstructionOperand inputs[4];
  size_t input_count = 0;
  inputs[input_count++] = g.UseUniqueRegister(base);
  inputs[input_count++] = g.UseUniqueRegister(index);
  inputs[input_count++] = g.UseUniqueRegister(old_value);
  inputs[input_count++] = g.UseUniqueRegister(new_value);
  InstructionOperand outputs[1];
  outputs[0] = g.UseUniqueRegister(node);
  InstructionOperand temp[3];
  temp[0] = g.TempRegister();
  temp[1] = g.TempRegister();
  temp[2] = g.TempRegister();
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode) |
                         AtomicWidthField::encode(width);
  selector->Emit(code, 1, outputs, input_count, inputs, 3, temp);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicExchange(node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kAtomicExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kAtomicExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kAtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kAtomicExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kAtomicExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kAtomicExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }

  VisitAtomicExchange(this, node, opcode, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicCompareExchange(
    node_t node) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = kAtomicCompareExchangeUint8;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = kAtomicCompareExchangeUint16;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
               atomic_op.memory_rep == MemoryRepresentation::Uint32()) {
      opcode = kAtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  } else {
    MachineType type = AtomicOpType(node->op());
    if (type == MachineType::Int8()) {
      opcode = kAtomicCompareExchangeInt8;
    } else if (type == MachineType::Uint8()) {
      opcode = kAtomicCompareExchangeUint8;
    } else if (type == MachineType::Int16()) {
      opcode = kAtomicCompareExchangeInt16;
    } else if (type == MachineType::Uint16()) {
      opcode = kAtomicCompareExchangeUint16;
    } else if (type == MachineType::Int32() || type == MachineType::Uint32()) {
      opcode = kAtomicCompareExchangeWord32;
    } else {
      UNREACHABLE();
    }
  }

    VisitAtomicCompareExchange(this, node, opcode, AtomicWidth::kWord32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32AtomicBinaryOperation(
    node_t node, ArchOpcode int8_op, ArchOpcode uint8_op, ArchOpcode int16_op,
    ArchOpcode uint16_op, ArchOpcode word32_op) {
  ArchOpcode opcode;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const AtomicRMWOp& atomic_op = this->Get(node).template Cast<AtomicRMWOp>();
    if (atomic_op.memory_rep == MemoryRepresentation::Int8()) {
      opcode = int8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint8()) {
      opcode = uint8_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int16()) {
      opcode = int16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Uint16()) {
      opcode = uint16_op;
    } else if (atomic_op.memory_rep == MemoryRepresentation::Int32() ||
```