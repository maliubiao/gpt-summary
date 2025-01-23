Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc`.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:**  This requires analyzing the code and identifying the key actions and data structures it manipulates. The code seems to be involved in instruction selection for the RISC-V 64-bit architecture within the V8 compiler.

2. **`.tq` file check:** This is a simple check of the file extension. The provided code is `.cc`, so it's not a Torque file.

3. **Relationship to JavaScript:**  Instruction selection is a crucial step in compiling JavaScript code. I need to explain how this process connects high-level JavaScript concepts to low-level machine instructions.

4. **JavaScript example:** Provide a simple JavaScript code snippet that would likely trigger some of the instruction selection logic described in the C++ code. Memory access operations are a good candidate.

5. **Code logic reasoning (input/output):**  Focus on a specific function or template within the code and describe its behavior with a hypothetical input and the expected output. The `GetIntegerConstantValue` function is a good example.

6. **Common programming errors:** Identify potential pitfalls related to the functionalities described in the code, particularly concerning memory access and data representation.

7. **Summarize the functionality (part 1 of 5):**  Provide a concise overview of the role of this specific code snippet within the larger context of the V8 compiler.

**Plan:**

*   Analyze the provided C++ code, focusing on template specializations, function names (like `EmitLoad`, `VisitStore`, `VisitWord32And`), and data structures (like `InstructionOperand`).
*   Identify the core function: selecting RISC-V instructions based on the intermediate representation (IR) of the JavaScript code.
*   Explain the connection to JavaScript compilation.
*   Create a simple JavaScript example involving memory access.
*   Detail the logic of `GetIntegerConstantValue` with an input and output example.
*   Discuss common errors related to memory access (e.g., incorrect data types, out-of-bounds access).
*   Write a summary emphasizing the instruction selection aspect for RISC-V64.
```cpp
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
void InstructionSelectorT<Adapter>::Visit
### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    VisitBinop<
```