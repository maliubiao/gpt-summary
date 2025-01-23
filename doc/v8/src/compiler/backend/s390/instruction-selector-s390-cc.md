Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Skim and Overall Goal:** The first thing is to quickly read through the code to get a general idea of what it's doing. Keywords like "compiler," "backend," "instruction selector," "S390" immediately jump out. The goal seems to be selecting the right S390 machine instructions for higher-level operations. The "part 1 of 6" indicates this is a larger piece of a system.

2. **Identify Key Data Structures:**  Look for core data types and structures. `OperandMode` (an enum) and `OperandModes` (a bitfield based on `OperandMode`) are clearly central, defining the types of operands allowed for instructions. The `BaseWithScaledIndexAndDisplacementMatch` struct suggests handling memory access patterns.

3. **Understand `OperandMode` and its Combinations:** This enum is crucial. Go through each member and understand its meaning. `kShift32Imm`, `kInt32Imm`, etc., represent immediate value types. `kAllowRRR`, `kAllowRM`, etc., represent instruction formats. The `#define` directives like `AndCommonMode` show how these flags are combined for specific operations. This is about defining the *constraints* on operands for different S390 instructions.

4. **Analyze `TryMatchBaseWithScaledIndexAndDisplacement64`:** This function name is descriptive. It's trying to recognize common memory addressing patterns (base register, index register with scaling, and displacement). This is a standard compiler optimization technique to map high-level memory accesses to efficient machine instructions. The comments listing the possible patterns are very helpful. Note the support for both `LoadOp` and `StoreOp`, and even `Simd128LaneMemoryOp`.

5. **Examine `S390OperandGeneratorT`:** This is the workhorse for generating operands. It has methods like `UseOperand`, `UseImmediate`, `CanBeImmediate`, `GenerateMemoryOperandInputs`, etc. The template nature suggests it can work with different compiler representations (likely Turboshaft and the older Sea of Nodes). The logic within `GenerateMemoryOperandInputs` shows how it constructs memory operands based on the available base, index, and displacement.

6. **Look for Helper Functions and Constants:** The anonymous namespace contains functions like `S390OpcodeOnlySupport12BitDisp` and `SelectLoadOpcode`. These are specific to the S390 architecture and help in selecting the correct instruction variant. `SelectLoadOpcode` is particularly important as it maps high-level load representations to specific S390 load instructions.

7. **Understand `ProduceWord32Result`:** This function seems to determine if the result of an operation is a 32-bit value. It has different implementations for Turboshaft and the older system. The list of `IrOpcode`s in the older version provides valuable clues about which operations produce 32-bit results. The Turboshaft version checks the `WordRepresentation` of the operation.

8. **Identify Code Generation Patterns:** The `VisitTryTruncateDouble` and `GenerateRightOperands` functions show how the instruction selector emits machine instructions. They take high-level nodes and translate them into specific S390 instructions with the appropriate operands. The logic in `GenerateRightOperands` for handling immediates and memory operands is key.

9. **Infer Functionality (Step-by-Step Summary):**  Based on the above analysis, start summarizing the functionality piece by piece:
    * Defines operand modes and instruction formats for S390.
    * Detects common memory access patterns.
    * Generates machine instruction operands.
    * Selects specific S390 load instructions based on the data type.
    * Determines if an operation produces a 32-bit result.
    * Contains code for handling specific operations like truncation.
    * Helps in selecting the correct instruction and operand combinations.

10. **Address Specific Questions (if any):** The prompt asks about Torque, JavaScript examples, logic inference, and common errors.
    * **Torque:** The file extension is `.cc`, not `.tq`, so it's not Torque.
    * **JavaScript:** Since this code deals with low-level instruction selection, the connection to JavaScript is indirect. JavaScript code is compiled by V8, and this code is part of that compilation process. Provide a simple JS example that might involve integer arithmetic or memory access, which would then be handled by this instruction selector.
    * **Logic Inference:** Choose a simple function like addition and show how the instruction selector might choose an `Add` instruction with registers or an immediate.
    * **Common Errors:**  Think about what could go wrong when writing assembly or low-level code. Incorrect operand types, using immediates outside the allowed range, and incorrect addressing modes are common issues.

11. **Finalize the Summary:**  Combine all the individual observations into a concise summary that addresses the main functionalities of the code. Emphasize its role in the V8 compilation pipeline and its target architecture (S390).

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretation:** I might initially focus too much on a specific function without understanding its context. It's important to step back and see how the different parts relate to each other.
* **Overlooking Details:** I might miss subtle points in the `OperandMode` definitions or the logic in `GenerateMemoryOperandInputs`. Careful reading and re-reading are necessary.
* **Assuming Too Much:** Don't assume that a function does something without verifying it in the code. For example, initially, I might have assumed `ProduceWord32Result` was about *generating* 32-bit results, but a closer look reveals it *checks* if the result *is* 32-bit.
* **Clarity of Explanation:**  Ensure the explanation is clear and uses appropriate terminology. Avoid jargon where possible or explain it when used.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and accurate summary of its functionality.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/logging.h"
#include "src/compiler/backend/instruction-selector-adapter.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/execution/frame-constants.h"

namespace v8 {
namespace internal {
namespace compiler {

enum class OperandMode : uint32_t {
  kNone = 0u,
  // Immediate mode
  kShift32Imm = 1u << 0,
  kShift64Imm = 1u << 1,
  kInt32Imm = 1u << 2,
  kInt32Imm_Negate = 1u << 3,
  kUint32Imm = 1u << 4,
  kInt20Imm = 1u << 5,
  kUint12Imm = 1u << 6,
  // Instr format
  kAllowRRR = 1u << 7,
  kAllowRM = 1u << 8,
  kAllowRI = 1u << 9,
  kAllowRRI = 1u << 10,
  kAllowRRM = 1u << 11,
  // Useful combination
  kAllowImmediate = kAllowRI | kAllowRRI,
  kAllowMemoryOperand = kAllowRM | kAllowRRM,
  kAllowDistinctOps = kAllowRRR | kAllowRRI | kAllowRRM,
  kBitWiseCommonMode = kAllowRI,
  kArithmeticCommonMode = kAllowRM | kAllowRI
};

using OperandModes = base::Flags<OperandMode, uint32_t>;
DEFINE_OPERATORS_FOR_FLAGS(OperandModes)
OperandModes immediateModeMask =
    OperandMode::kShift32Imm | OperandMode::kShift64Imm |
    OperandMode::kInt32Imm | OperandMode::kInt32Imm_Negate |
    OperandMode::kUint32Imm | OperandMode::kInt20Imm;

#define AndCommonMode                                                \
  ((OperandMode::kAllowRM |                                          \
    (CpuFeatures::IsSupported(DISTINCT_OPS) ? OperandMode::kAllowRRR \
                                            : OperandMode::kNone)))
#define And64OperandMode AndCommonMode
#define Or64OperandMode And64OperandMode
#define Xor64OperandMode And64OperandMode

#define And32OperandMode \
  (AndCommonMode | OperandMode::kAllowRI | OperandMode::kUint32Imm)
#define Or32OperandMode And32OperandMode
#define Xor32OperandMode And32OperandMode

#define Shift32OperandMode                                   \
  ((OperandMode::kAllowRI | OperandMode::kShift64Imm |       \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                  \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI) \
         : OperandMode::kNone)))

#define Shift64OperandMode                             \
  ((OperandMode::kAllowRI | OperandMode::kShift64Imm | \
    OperandMode::kAllowRRR | OperandMode::kAllowRRI))

#define AddOperandMode                                            \
  ((OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm | \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                       \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI)      \
         : OperandMode::kArithmeticCommonMode)))
#define SubOperandMode                                                   \
  ((OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm_Negate | \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                              \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI)             \
         : OperandMode::kArithmeticCommonMode)))
#define MulOperandMode \
  (OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm)

template <typename Adapter>
struct BaseWithScaledIndexAndDisplacementMatch {
  using node_t = typename Adapter::node_t;

  node_t base = {};
  node_t index = {};
  int scale = 0;
  int64_t displacement = 0;
  DisplacementMode displacement_mode = kPositiveDisplacement;
};

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // The BaseWithIndexAndDisplacementMatcher canonicalizes the order of
  // displacements and scale factors that are used as inputs, so instead of
  // enumerating all possible patterns by brute force, checking for node
  // clusters using the following templates in the following order suffices
  // to find all of the interesting cases (S = index * scale, B = base
  // input, D = displacement input):
  //
  // (S + (B + D))
  // (S + (B + B))
  // (S + D)
  // (S + B)
  // ((S + D) + B)
  // ((S + B) + D)
  // ((B + D) + B)
  // ((B + B) + D)
  // (B + D)
  // (B + B)
  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  const Operation& op = selector->Get(node);
  if (const LoadOp* load = op.TryCast<LoadOp>()) {
    result.base = load->base();
    result.index = load->index().value_or_invalid();
    result.scale = load->element_size_log2;
    result.displacement = load->offset;
    if (load->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const StoreOp* store = op.TryCast<StoreOp>()) {
    result.base = store->base();
    result.index = store->index().value_or_invalid();
    result.scale = store->element_size_log2;
    result.displacement = store->offset;
    if (store->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (op.Is<WordBinopOp>()) {
    UNIMPLEMENTED();
#ifdef V8_ENABLE_WEBASSEMBLY
  } else if (const Simd128LaneMemoryOp* lane_op =
                 op.TryCast<Simd128LaneMemoryOp>()) {
    result.base = lane_op->base();
    result.index = lane_op->index();
    result.scale = 0;
    result.displacement = 0;
    if (lane_op->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const Simd128LoadTransformOp* load_transform =
                 op.TryCast<Simd128LoadTransformOp>()) {
    result.base = load_transform->base();
    result.index = load_transform->index();
    DCHECK_EQ(load_transform->offset, 0);
    result.scale = 0;
    result.displacement = 0;
    DCHECK(!load_transform->load_kind.tagged_base);
    return result;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return std::nullopt;
}

// Adds S390-specific methods for generating operands.
template <typename Adapter>
class S390OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit S390OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(node_t node, OperandModes mode) {
    if (CanBeImmediate(node, mode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  InstructionOperand UseAnyExceptImmediate(node_t node) {
    if (this->is_integer_constant(node))
      return UseRegister(node);
    else
      return this->Use(node);
  }

  int64_t GetImmediate(node_t node) {
    if constexpr (Adapter::IsTurboshaft) {
      turboshaft::ConstantOp* op =
          this->turboshaft_graph()
              ->Get(node)
              .template TryCast<turboshaft::ConstantOp>();
      switch (op->kind) {
        case turboshaft::ConstantOp::Kind::kWord32:
          return op->word32();
        case turboshaft::ConstantOp::Kind::kWord64:
          return op->word64();
        default:
          UNIMPLEMENTED();
      }
    } else {
      if (node->opcode() == IrOpcode::kInt32Constant)
        return OpParameter<int32_t>(node->op());
      else if (node->opcode() == IrOpcode::kInt64Constant)
        return OpParameter<int64_t>(node->op());
      else
        UNIMPLEMENTED();
    }
  }

  bool CanBeImmediate(node_t node, OperandModes mode) {
    if (!selector()->is_integer_constant(node)) return false;
    int64_t value = selector()->integer_constant(node);
    return CanBeImmediate(value, mode);
  }

  bool CanBeImmediate(int64_t value, OperandModes mode) {
    if (mode & OperandMode::kShift32Imm)
      return 0 <= value && value < 32;
    else if (mode & OperandMode::kShift64Imm)
      return 0 <= value && value < 64;
    else if (mode & OperandMode::kInt32Imm)
      return is_int32(value);
    else if (mode & OperandMode::kInt32Imm_Negate)
      return is_int32(-value);
    else if (mode & OperandMode::kUint32Imm)
      return is_uint32(value);
    else if (mode & OperandMode::kInt20Imm)
      return is_int20(value);
    else if (mode & OperandMode::kUint12Imm)
      return is_uint12(value);
    else
      return false;
  }

  bool CanBeMemoryOperand(InstructionCode opcode, node_t user, node_t input,
                          int effect_level) {
    if (!this->IsLoadOrLoadImmutable(input)) return false;
    if (!selector()->CanCover(user, input)) return false;
    if (effect_level != selector()->GetEffectLevel(input)) {
      return false;
    }

    MachineRepresentation rep =
        this->load_view(input).loaded_rep().representation();
    switch (opcode) {
      case kS390_Cmp64:
      case kS390_LoadAndTestWord64:
        if (rep == MachineRepresentation::kWord64 ||
            (!COMPRESS_POINTERS_BOOL && IsAnyTagged(rep))) {
          DCHECK_EQ(ElementSizeInBits(rep), 64);
          return true;
        }
        break;
      case kS390_LoadAndTestWord32:
      case kS390_Cmp32:
        if (rep == MachineRepresentation::kWord32 ||
            (COMPRESS_POINTERS_BOOL && IsAnyCompressed(rep))) {
          DCHECK_EQ(ElementSizeInBits(rep), 32);
          return true;
        }
        break;
      default:
        break;
    }
    return false;
  }

  AddressingMode GenerateMemoryOperandInputs(
      optional_node_t index, node_t base, int64_t displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    AddressingMode mode = kMode_MRI;
    if (this->valid(base)) {
      inputs[(*input_count)++] = UseRegister(base, reg_kind);
      if (this->valid(index)) {
        inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        if (displacement != 0) {
          inputs[(*input_count)++] = UseImmediate(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRRI;
        } else {
          mode = kMode_MRR;
        }
      } else {
        if (displacement == 0) {
          mode = kMode_MR;
        } else {
          inputs[(*input_count)++] = UseImmediate(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRI;
        }
      }
    } else {
      DCHECK(this->valid(index));
      inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
      if (displacement != 0) {
        inputs[(*input_count)++] = UseImmediate(
            displacement_mode == kNegativeDisplacement ? -displacement
                                                       : displacement);
        mode = kMode_MRI;
      } else {
        mode = kMode_MR;
      }
    }
    return mode;
  }

  AddressingMode GenerateMemoryOperandInputs(
      Node* index, Node* base, Node* displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    if constexpr (Adapter::IsTurboshaft) {
      // Turboshaft is not using this overload.
      UNREACHABLE();
    } else {
      int64_t displacement_value;
      if (displacement == nullptr) {
        displacement_value = 0;
      } else if (displacement->opcode() == IrOpcode::kInt32Constant) {
        displacement_value = OpParameter<int32_t>(displacement->op());
      } else if (displacement->opcode() == IrOpcode::kInt64Constant) {
        displacement_value = OpParameter<int64_t>(displacement->op());
      } else {
        UNREACHABLE();
      }
      return GenerateMemoryOperandInputs(index, base, displacement_value,
                                         displacement_mode, inputs,
                                         input_count);
    }
  }

  AddressingMode GetEffectiveAddressMemoryOperand(
      typename Adapter::node_t operand, InstructionOperand inputs[],
      size_t* input_count,
      OperandModes immediate_mode = OperandMode::kInt20Imm) {
    if constexpr (Adapter::IsTurboshaft) {
      auto m =
          TryMatchBaseWithScaledIndexAndDisplacement64(selector(), operand);
      DCHECK(m.has_value());
      if (TurboshaftAdapter::valid(m->base) &&
          this->Get(m->base).template Is<turboshaft::LoadRootRegisterOp>()) {
        DCHECK(!this->valid(m->index));
        DCHECK_EQ(m->scale, 0);
        inputs[(*input_count)++] =
            UseImmediate(static_cast<int>(m.displacement));
        return kMode_Root;
      } else if (CanBeImmediate(m->displacement, immediate_mode)) {
        DCHECK_EQ(m->scale, 0);
        return GenerateMemoryOperandInputs(m->index, m->base, m->displacement,
                                           m->displacement_mode, inputs,
                                           input_count);
      } else {
        DCHECK_EQ(m->displacement, 0);
        inputs[(*input_count)++] = UseRegister(m->base);
        inputs[(*input_count)++] = UseRegister(m->index);
        return kMode_MRR;
      }

    } else {
    BaseWithIndexAndDisplacement64Matcher m(operand,
                                            AddressOption::kAllowInputSwap);
    DCHECK(m.matches());
    if (m.base() != nullptr &&
        m.base()->opcode() == IrOpcode::kLoadRootRegister) {
      DCHECK_EQ(m.index(), nullptr);
      DCHECK_EQ(m.scale(), 0);
      inputs[(*input_count)++] = UseImmediate(m.displacement());
      return kMode_Root;
    } else if ((m.displacement() == nullptr ||
                CanBeImmediate(m.displacement(), immediate_mode))) {
      DCHECK_EQ(0, m.scale());
      return GenerateMemoryOperandInputs(m.index(), m.base(), m.displacement(),
                                         m.displacement_mode(), inputs,
                                         input_count);
    } else {
      inputs[(*input_count)++] = UseRegister(operand->InputAt(0));
      inputs[(*input_count)++] = UseRegister(operand->InputAt(1));
      return kMode_MRR;
    }
    }
  }

  bool CanBeBetterLeftOperand(node_t node) const {
    return !selector()->IsLive(node);
  }

  MachineRepresentation GetRepresentation(Node* node) {
    return this->sequence()->GetRepresentation(
        selector()->GetVirtualRegister(node));
  }

  bool Is64BitOperand(Node* node) {
    return MachineRepresentation::kWord64 == GetRepresentation(node);
  }
};

namespace {

bool S390OpcodeOnlySupport12BitDisp(ArchOpcode opcode) {
  switch (opcode) {
    case kS390_AddFloat:
    case kS390_AddDouble:
    case kS390_CmpFloat:
    case kS390_CmpDouble:
    case kS390_Float32ToDouble:
      return true;
    default:
      return false;
  }
}

bool S390OpcodeOnlySupport12BitDisp(InstructionCode op) {
  ArchOpcode opcode = ArchOpcodeField::decode(op);
  return S390OpcodeOnlySupport12BitDisp(opcode);
}

#define OpcodeImmMode(op)                                       \
  (S390OpcodeOnlySupport12BitDisp(op) ? OperandMode::kUint12Imm \
                                      : OperandMode::kInt20Imm)

ArchOpcode SelectLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                            turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordS8;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU8;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordS16;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU16;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU32;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kS390_LoadWord64;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kS390_LoadFloat32;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kS390_LoadDouble;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kS390_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kS390_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadWord64;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadWord64;
    case MemoryRepresentation::Simd128():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd128());
      return kS390_LoadSimd128;
    case MemoryRepresentation::ProtectedPointer():
    case MemoryRepresentation::IndirectPointer():
    case MemoryRepresentation::SandboxedPointer():
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode SelectLoadOpcode(LoadRepresentation load_rep) {
  ArchOpcode opcode;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kS390_LoadFloat32;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kS390_LoadDouble;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kS390_LoadWordS8 : kS390_LoadWordU8;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kS390_LoadWordS16 : kS390_LoadWordU16;
      break;
    case MachineRepresentation::kWord32:
      opcode = kS390_LoadWordU32;
      break;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kIndirectPointer:  // Fall through.
    case MachineRepresentation::kSandboxedPointer:  // Fall through.
#ifdef V8_COMPRESS_POINTERS
      opcode = kS390_LoadWordS32;
      break;
#else
      UNREACHABLE();
#endif
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      opcode = kS390_LoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
      opcode = kS390_LoadDecompressTagged;
      break;
    case MachineRepresentation::kTagged:
      opcode = kS390_LoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      opcode = kS390_LoadWord64;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kS390_LoadSimd128;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kProtectedPointer:  // Fall through.
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kNone:
    default:
      UNREACHABLE();
  }
  return opcode;
}

#define RESULT_IS_WORD32_LIST(V)   \
  /* Float unary op*/              \
  V(BitcastFloat32ToInt32)         \
  /* V(TruncateFloat64ToWord32) */ \
  V(RoundFloat64ToInt32)           \
  V(TruncateFloat32ToInt32)        \
  V(TruncateFloat32ToUint32)       \
  V(TruncateFloat64ToUint32)       \
  V(ChangeFloat64ToInt32)          \
  V(ChangeFloat64ToUint32)         \
  /* Word32 unary op */            \
  V(Word32Clz)                     \
  V(Word32Popcnt)                  \
  V(Float64ExtractLowWord32)       \
  V(Float64ExtractHighWord32)      \
  V(SignExtendWord8ToInt32)        \
  V(SignExtendWord16ToInt32)       \
  /* Word32 bin op */              \
  V(Int32Add)                      \
  V(Int32Sub)                      \
  V(Int32Mul)                      \
  V(Int32AddWithOverflow)          \
  V(Int32SubWithOverflow)          \
  V(Int32MulWithOverflow)          \
  V(Int32MulHigh)                  \
  V(Uint32MulHigh)                 \
  V(Int32Div)                      \
  V(Uint32Div)                     \
  V(Int32Mod)                      \
  V(Uint32Mod)                     \
  V(Word32Ror)                     \
  V(Word32And)                     \
  V(Word32Or)                      \
  V(Word32Xor)                     \
  V(Word32Shl)                     \
  V(Word32Shr)                     \
  V(Word32Sar)

template <typename Adapter>
bool ProduceWord32Result(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    switch (op.opcode) {
      case Opcode::kWordBinop: {
        const auto& binop = op.Cast<WordBinopOp>();
        if (binop.rep != WordRepresentation::Word32()) return false;
        return binop.kind == WordBinopOp::Kind::kAdd ||
               binop.kind == WordBinopOp::Kind::kSub ||
               binop.kind == WordBinopOp::Kind::kMul ||
               binop.kind == WordBinopOp::Kind::kSignedDiv ||
               binop.kind == WordBinopOp::Kind::kUnsignedDiv ||
               binop.kind == WordBinopOp::Kind::kSignedMod ||
               binop.kind == WordBinopOp::Kind::kUnsignedMod ||
               binop.kind == WordBinopOp::Kind::kBitwiseAnd ||
               binop.kind ==
### 提示词
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-selector-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/logging.h"
#include "src/compiler/backend/instruction-selector-adapter.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/execution/frame-constants.h"

namespace v8 {
namespace internal {
namespace compiler {

enum class OperandMode : uint32_t {
  kNone = 0u,
  // Immediate mode
  kShift32Imm = 1u << 0,
  kShift64Imm = 1u << 1,
  kInt32Imm = 1u << 2,
  kInt32Imm_Negate = 1u << 3,
  kUint32Imm = 1u << 4,
  kInt20Imm = 1u << 5,
  kUint12Imm = 1u << 6,
  // Instr format
  kAllowRRR = 1u << 7,
  kAllowRM = 1u << 8,
  kAllowRI = 1u << 9,
  kAllowRRI = 1u << 10,
  kAllowRRM = 1u << 11,
  // Useful combination
  kAllowImmediate = kAllowRI | kAllowRRI,
  kAllowMemoryOperand = kAllowRM | kAllowRRM,
  kAllowDistinctOps = kAllowRRR | kAllowRRI | kAllowRRM,
  kBitWiseCommonMode = kAllowRI,
  kArithmeticCommonMode = kAllowRM | kAllowRI
};

using OperandModes = base::Flags<OperandMode, uint32_t>;
DEFINE_OPERATORS_FOR_FLAGS(OperandModes)
OperandModes immediateModeMask =
    OperandMode::kShift32Imm | OperandMode::kShift64Imm |
    OperandMode::kInt32Imm | OperandMode::kInt32Imm_Negate |
    OperandMode::kUint32Imm | OperandMode::kInt20Imm;

#define AndCommonMode                                                \
  ((OperandMode::kAllowRM |                                          \
    (CpuFeatures::IsSupported(DISTINCT_OPS) ? OperandMode::kAllowRRR \
                                            : OperandMode::kNone)))
#define And64OperandMode AndCommonMode
#define Or64OperandMode And64OperandMode
#define Xor64OperandMode And64OperandMode

#define And32OperandMode \
  (AndCommonMode | OperandMode::kAllowRI | OperandMode::kUint32Imm)
#define Or32OperandMode And32OperandMode
#define Xor32OperandMode And32OperandMode

#define Shift32OperandMode                                   \
  ((OperandMode::kAllowRI | OperandMode::kShift64Imm |       \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                  \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI) \
         : OperandMode::kNone)))

#define Shift64OperandMode                             \
  ((OperandMode::kAllowRI | OperandMode::kShift64Imm | \
    OperandMode::kAllowRRR | OperandMode::kAllowRRI))

#define AddOperandMode                                            \
  ((OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm | \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                       \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI)      \
         : OperandMode::kArithmeticCommonMode)))
#define SubOperandMode                                                   \
  ((OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm_Negate | \
    (CpuFeatures::IsSupported(DISTINCT_OPS)                              \
         ? (OperandMode::kAllowRRR | OperandMode::kAllowRRI)             \
         : OperandMode::kArithmeticCommonMode)))
#define MulOperandMode \
  (OperandMode::kArithmeticCommonMode | OperandMode::kInt32Imm)

template <typename Adapter>
struct BaseWithScaledIndexAndDisplacementMatch {
  using node_t = typename Adapter::node_t;

  node_t base = {};
  node_t index = {};
  int scale = 0;
  int64_t displacement = 0;
  DisplacementMode displacement_mode = kPositiveDisplacement;
};

std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement64(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // The BaseWithIndexAndDisplacementMatcher canonicalizes the order of
  // displacements and scale factors that are used as inputs, so instead of
  // enumerating all possible patterns by brute force, checking for node
  // clusters using the following templates in the following order suffices
  // to find all of the interesting cases (S = index * scale, B = base
  // input, D = displacement input):
  //
  // (S + (B + D))
  // (S + (B + B))
  // (S + D)
  // (S + B)
  // ((S + D) + B)
  // ((S + B) + D)
  // ((B + D) + B)
  // ((B + B) + D)
  // (B + D)
  // (B + B)
  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  const Operation& op = selector->Get(node);
  if (const LoadOp* load = op.TryCast<LoadOp>()) {
    result.base = load->base();
    result.index = load->index().value_or_invalid();
    result.scale = load->element_size_log2;
    result.displacement = load->offset;
    if (load->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const StoreOp* store = op.TryCast<StoreOp>()) {
    result.base = store->base();
    result.index = store->index().value_or_invalid();
    result.scale = store->element_size_log2;
    result.displacement = store->offset;
    if (store->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (op.Is<WordBinopOp>()) {
    UNIMPLEMENTED();
#ifdef V8_ENABLE_WEBASSEMBLY
  } else if (const Simd128LaneMemoryOp* lane_op =
                 op.TryCast<Simd128LaneMemoryOp>()) {
    result.base = lane_op->base();
    result.index = lane_op->index();
    result.scale = 0;
    result.displacement = 0;
    if (lane_op->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const Simd128LoadTransformOp* load_transform =
                 op.TryCast<Simd128LoadTransformOp>()) {
    result.base = load_transform->base();
    result.index = load_transform->index();
    DCHECK_EQ(load_transform->offset, 0);
    result.scale = 0;
    result.displacement = 0;
    DCHECK(!load_transform->load_kind.tagged_base);
    return result;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return std::nullopt;
}

// Adds S390-specific methods for generating operands.
template <typename Adapter>
class S390OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit S390OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(node_t node, OperandModes mode) {
    if (CanBeImmediate(node, mode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  InstructionOperand UseAnyExceptImmediate(node_t node) {
    if (this->is_integer_constant(node))
      return UseRegister(node);
    else
      return this->Use(node);
  }

  int64_t GetImmediate(node_t node) {
    if constexpr (Adapter::IsTurboshaft) {
      turboshaft::ConstantOp* op =
          this->turboshaft_graph()
              ->Get(node)
              .template TryCast<turboshaft::ConstantOp>();
      switch (op->kind) {
        case turboshaft::ConstantOp::Kind::kWord32:
          return op->word32();
        case turboshaft::ConstantOp::Kind::kWord64:
          return op->word64();
        default:
          UNIMPLEMENTED();
      }
    } else {
      if (node->opcode() == IrOpcode::kInt32Constant)
        return OpParameter<int32_t>(node->op());
      else if (node->opcode() == IrOpcode::kInt64Constant)
        return OpParameter<int64_t>(node->op());
      else
        UNIMPLEMENTED();
    }
  }

  bool CanBeImmediate(node_t node, OperandModes mode) {
    if (!selector()->is_integer_constant(node)) return false;
    int64_t value = selector()->integer_constant(node);
    return CanBeImmediate(value, mode);
  }

  bool CanBeImmediate(int64_t value, OperandModes mode) {
    if (mode & OperandMode::kShift32Imm)
      return 0 <= value && value < 32;
    else if (mode & OperandMode::kShift64Imm)
      return 0 <= value && value < 64;
    else if (mode & OperandMode::kInt32Imm)
      return is_int32(value);
    else if (mode & OperandMode::kInt32Imm_Negate)
      return is_int32(-value);
    else if (mode & OperandMode::kUint32Imm)
      return is_uint32(value);
    else if (mode & OperandMode::kInt20Imm)
      return is_int20(value);
    else if (mode & OperandMode::kUint12Imm)
      return is_uint12(value);
    else
      return false;
  }

  bool CanBeMemoryOperand(InstructionCode opcode, node_t user, node_t input,
                          int effect_level) {
    if (!this->IsLoadOrLoadImmutable(input)) return false;
    if (!selector()->CanCover(user, input)) return false;
    if (effect_level != selector()->GetEffectLevel(input)) {
      return false;
    }

    MachineRepresentation rep =
        this->load_view(input).loaded_rep().representation();
    switch (opcode) {
      case kS390_Cmp64:
      case kS390_LoadAndTestWord64:
        if (rep == MachineRepresentation::kWord64 ||
            (!COMPRESS_POINTERS_BOOL && IsAnyTagged(rep))) {
          DCHECK_EQ(ElementSizeInBits(rep), 64);
          return true;
        }
        break;
      case kS390_LoadAndTestWord32:
      case kS390_Cmp32:
        if (rep == MachineRepresentation::kWord32 ||
            (COMPRESS_POINTERS_BOOL && IsAnyCompressed(rep))) {
          DCHECK_EQ(ElementSizeInBits(rep), 32);
          return true;
        }
        break;
      default:
        break;
    }
    return false;
  }

  AddressingMode GenerateMemoryOperandInputs(
      optional_node_t index, node_t base, int64_t displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    AddressingMode mode = kMode_MRI;
    if (this->valid(base)) {
      inputs[(*input_count)++] = UseRegister(base, reg_kind);
      if (this->valid(index)) {
        inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
        if (displacement != 0) {
          inputs[(*input_count)++] = UseImmediate(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRRI;
        } else {
          mode = kMode_MRR;
        }
      } else {
        if (displacement == 0) {
          mode = kMode_MR;
        } else {
          inputs[(*input_count)++] = UseImmediate(
              displacement_mode == kNegativeDisplacement ? -displacement
                                                         : displacement);
          mode = kMode_MRI;
        }
      }
    } else {
      DCHECK(this->valid(index));
      inputs[(*input_count)++] = UseRegister(this->value(index), reg_kind);
      if (displacement != 0) {
        inputs[(*input_count)++] = UseImmediate(
            displacement_mode == kNegativeDisplacement ? -displacement
                                                       : displacement);
        mode = kMode_MRI;
      } else {
        mode = kMode_MR;
      }
    }
    return mode;
  }

  AddressingMode GenerateMemoryOperandInputs(
      Node* index, Node* base, Node* displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterUseKind reg_kind = RegisterUseKind::kUseRegister) {
    if constexpr (Adapter::IsTurboshaft) {
      // Turboshaft is not using this overload.
      UNREACHABLE();
    } else {
      int64_t displacement_value;
      if (displacement == nullptr) {
        displacement_value = 0;
      } else if (displacement->opcode() == IrOpcode::kInt32Constant) {
        displacement_value = OpParameter<int32_t>(displacement->op());
      } else if (displacement->opcode() == IrOpcode::kInt64Constant) {
        displacement_value = OpParameter<int64_t>(displacement->op());
      } else {
        UNREACHABLE();
      }
      return GenerateMemoryOperandInputs(index, base, displacement_value,
                                         displacement_mode, inputs,
                                         input_count);
    }
  }

  AddressingMode GetEffectiveAddressMemoryOperand(
      typename Adapter::node_t operand, InstructionOperand inputs[],
      size_t* input_count,
      OperandModes immediate_mode = OperandMode::kInt20Imm) {
    if constexpr (Adapter::IsTurboshaft) {
      auto m =
          TryMatchBaseWithScaledIndexAndDisplacement64(selector(), operand);
      DCHECK(m.has_value());
      if (TurboshaftAdapter::valid(m->base) &&
          this->Get(m->base).template Is<turboshaft::LoadRootRegisterOp>()) {
        DCHECK(!this->valid(m->index));
        DCHECK_EQ(m->scale, 0);
        inputs[(*input_count)++] =
            UseImmediate(static_cast<int>(m->displacement));
        return kMode_Root;
      } else if (CanBeImmediate(m->displacement, immediate_mode)) {
        DCHECK_EQ(m->scale, 0);
        return GenerateMemoryOperandInputs(m->index, m->base, m->displacement,
                                           m->displacement_mode, inputs,
                                           input_count);
      } else {
        DCHECK_EQ(m->displacement, 0);
        inputs[(*input_count)++] = UseRegister(m->base);
        inputs[(*input_count)++] = UseRegister(m->index);
        return kMode_MRR;
      }

    } else {
    BaseWithIndexAndDisplacement64Matcher m(operand,
                                            AddressOption::kAllowInputSwap);
    DCHECK(m.matches());
    if (m.base() != nullptr &&
        m.base()->opcode() == IrOpcode::kLoadRootRegister) {
      DCHECK_EQ(m.index(), nullptr);
      DCHECK_EQ(m.scale(), 0);
      inputs[(*input_count)++] = UseImmediate(m.displacement());
      return kMode_Root;
    } else if ((m.displacement() == nullptr ||
                CanBeImmediate(m.displacement(), immediate_mode))) {
      DCHECK_EQ(0, m.scale());
      return GenerateMemoryOperandInputs(m.index(), m.base(), m.displacement(),
                                         m.displacement_mode(), inputs,
                                         input_count);
    } else {
      inputs[(*input_count)++] = UseRegister(operand->InputAt(0));
      inputs[(*input_count)++] = UseRegister(operand->InputAt(1));
      return kMode_MRR;
    }
    }
  }

  bool CanBeBetterLeftOperand(node_t node) const {
    return !selector()->IsLive(node);
  }

  MachineRepresentation GetRepresentation(Node* node) {
    return this->sequence()->GetRepresentation(
        selector()->GetVirtualRegister(node));
  }

  bool Is64BitOperand(Node* node) {
    return MachineRepresentation::kWord64 == GetRepresentation(node);
  }
};

namespace {

bool S390OpcodeOnlySupport12BitDisp(ArchOpcode opcode) {
  switch (opcode) {
    case kS390_AddFloat:
    case kS390_AddDouble:
    case kS390_CmpFloat:
    case kS390_CmpDouble:
    case kS390_Float32ToDouble:
      return true;
    default:
      return false;
  }
}

bool S390OpcodeOnlySupport12BitDisp(InstructionCode op) {
  ArchOpcode opcode = ArchOpcodeField::decode(op);
  return S390OpcodeOnlySupport12BitDisp(opcode);
}

#define OpcodeImmMode(op)                                       \
  (S390OpcodeOnlySupport12BitDisp(op) ? OperandMode::kUint12Imm \
                                      : OperandMode::kInt20Imm)

ArchOpcode SelectLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                            turboshaft::RegisterRepresentation result_rep) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordS8;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU8;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordS16;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU16;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kS390_LoadWordU32;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kS390_LoadWord64;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kS390_LoadFloat32;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kS390_LoadDouble;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kS390_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kS390_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadWord64;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kS390_LoadWord64;
    case MemoryRepresentation::Simd128():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd128());
      return kS390_LoadSimd128;
    case MemoryRepresentation::ProtectedPointer():
    case MemoryRepresentation::IndirectPointer():
    case MemoryRepresentation::SandboxedPointer():
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode SelectLoadOpcode(LoadRepresentation load_rep) {
  ArchOpcode opcode;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kS390_LoadFloat32;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kS390_LoadDouble;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kS390_LoadWordS8 : kS390_LoadWordU8;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kS390_LoadWordS16 : kS390_LoadWordU16;
      break;
    case MachineRepresentation::kWord32:
      opcode = kS390_LoadWordU32;
      break;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kIndirectPointer:  // Fall through.
    case MachineRepresentation::kSandboxedPointer:  // Fall through.
#ifdef V8_COMPRESS_POINTERS
      opcode = kS390_LoadWordS32;
      break;
#else
      UNREACHABLE();
#endif
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      opcode = kS390_LoadDecompressTaggedSigned;
      break;
    case MachineRepresentation::kTaggedPointer:
      opcode = kS390_LoadDecompressTagged;
      break;
    case MachineRepresentation::kTagged:
      opcode = kS390_LoadDecompressTagged;
      break;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      opcode = kS390_LoadWord64;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kS390_LoadSimd128;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kProtectedPointer:  // Fall through.
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kNone:
    default:
      UNREACHABLE();
  }
  return opcode;
}

#define RESULT_IS_WORD32_LIST(V)   \
  /* Float unary op*/              \
  V(BitcastFloat32ToInt32)         \
  /* V(TruncateFloat64ToWord32) */ \
  V(RoundFloat64ToInt32)           \
  V(TruncateFloat32ToInt32)        \
  V(TruncateFloat32ToUint32)       \
  V(TruncateFloat64ToUint32)       \
  V(ChangeFloat64ToInt32)          \
  V(ChangeFloat64ToUint32)         \
  /* Word32 unary op */            \
  V(Word32Clz)                     \
  V(Word32Popcnt)                  \
  V(Float64ExtractLowWord32)       \
  V(Float64ExtractHighWord32)      \
  V(SignExtendWord8ToInt32)        \
  V(SignExtendWord16ToInt32)       \
  /* Word32 bin op */              \
  V(Int32Add)                      \
  V(Int32Sub)                      \
  V(Int32Mul)                      \
  V(Int32AddWithOverflow)          \
  V(Int32SubWithOverflow)          \
  V(Int32MulWithOverflow)          \
  V(Int32MulHigh)                  \
  V(Uint32MulHigh)                 \
  V(Int32Div)                      \
  V(Uint32Div)                     \
  V(Int32Mod)                      \
  V(Uint32Mod)                     \
  V(Word32Ror)                     \
  V(Word32And)                     \
  V(Word32Or)                      \
  V(Word32Xor)                     \
  V(Word32Shl)                     \
  V(Word32Shr)                     \
  V(Word32Sar)

template <typename Adapter>
bool ProduceWord32Result(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    switch (op.opcode) {
      case Opcode::kWordBinop: {
        const auto& binop = op.Cast<WordBinopOp>();
        if (binop.rep != WordRepresentation::Word32()) return false;
        return binop.kind == WordBinopOp::Kind::kAdd ||
               binop.kind == WordBinopOp::Kind::kSub ||
               binop.kind == WordBinopOp::Kind::kMul ||
               binop.kind == WordBinopOp::Kind::kSignedDiv ||
               binop.kind == WordBinopOp::Kind::kUnsignedDiv ||
               binop.kind == WordBinopOp::Kind::kSignedMod ||
               binop.kind == WordBinopOp::Kind::kUnsignedMod ||
               binop.kind == WordBinopOp::Kind::kBitwiseAnd ||
               binop.kind == WordBinopOp::Kind::kBitwiseOr ||
               binop.kind == WordBinopOp::Kind::kBitwiseXor ||
               binop.kind == WordBinopOp::Kind::kSignedMulOverflownBits ||
               binop.kind == WordBinopOp::Kind::kUnsignedMulOverflownBits;
      }
      case Opcode::kWordUnary: {
        const auto& unop = op.Cast<WordUnaryOp>();
        if (unop.rep != WordRepresentation::Word32()) return false;
        return unop.kind == WordUnaryOp::Kind::kCountLeadingZeros ||
               unop.kind == WordUnaryOp::Kind::kPopCount ||
               unop.kind == WordUnaryOp::Kind::kSignExtend8 ||
               unop.kind == WordUnaryOp::Kind::kSignExtend16;
      }
      case Opcode::kChange: {
        const auto& changeop = op.Cast<ChangeOp>();
        switch (changeop.kind) {
          // Float64ExtractLowWord32
          // Float64ExtractHighWord32
          case ChangeOp::Kind::kExtractLowHalf:
          case ChangeOp::Kind::kExtractHighHalf:
            CHECK_EQ(changeop.from, FloatRepresentation::Float64());
            CHECK_EQ(changeop.to, WordRepresentation::Word32());
            return true;
          // BitcastFloat32ToInt32
          case ChangeOp::Kind::kBitcast:
            return changeop.from == FloatRepresentation::Float32() &&
                   changeop.to == WordRepresentation::Word32();
          case ChangeOp::Kind::kSignedFloatTruncateOverflowToMin:
          case ChangeOp::Kind::kUnsignedFloatTruncateOverflowToMin:
            // RoundFloat64ToInt32
            // ChangeFloat64ToInt32
            // TruncateFloat64ToUint32
            // ChangeFloat64ToUint32
            if (changeop.from == FloatRepresentation::Float64() &&
                changeop.to == WordRepresentation::Word32()) {
              return true;
            }
            // TruncateFloat32ToInt32
            // TruncateFloat32ToUint32
            if (changeop.from == FloatRepresentation::Float32() &&
                changeop.to == WordRepresentation::Word32()) {
              return true;
            }
            return false;
          default:
            return false;
        }
        return false;
      }
      case Opcode::kShift: {
        const auto& shift = op.Cast<ShiftOp>();
        if (shift.rep != WordRepresentation::Word32()) return false;
        return shift.kind == ShiftOp::Kind::kShiftRightArithmetic ||
               shift.kind == ShiftOp::Kind::kShiftRightLogical ||
               shift.kind ==
                   ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros ||
               shift.kind == ShiftOp::Kind::kShiftLeft ||
               shift.kind == ShiftOp::Kind::kRotateRight;
      }
      case Opcode::kOverflowCheckedBinop: {
        const auto& ovfbinop = op.Cast<OverflowCheckedBinopOp>();
        if (ovfbinop.rep != WordRepresentation::Word32()) return false;
        return ovfbinop.kind == OverflowCheckedBinopOp::Kind::kSignedAdd ||
               ovfbinop.kind == OverflowCheckedBinopOp::Kind::kSignedSub ||
               ovfbinop.kind == OverflowCheckedBinopOp::Kind::kSignedMul;
      }
      case Opcode::kLoad: {
        LoadRepresentation load_rep = selector->load_view(node).loaded_rep();
        MachineRepresentation rep = load_rep.representation();
        switch (rep) {
          case MachineRepresentation::kWord32:
            return true;
          case MachineRepresentation::kWord8:
            if (load_rep.IsSigned())
              return false;
            else
              return true;
          default:
            return false;
        }
      }
      default:
        return false;
    }

  } else {
  switch (node->opcode()) {
#define VISITOR(name) case IrOpcode::k##name:
    RESULT_IS_WORD32_LIST(VISITOR)
#undef VISITOR
    return true;
    // TODO(john.yan): consider the following case to be valid
    // case IrOpcode::kWord32Equal:
    // case IrOpcode::kInt32LessThan:
    // case IrOpcode::kInt32LessThanOrEqual:
    // case IrOpcode::kUint32LessThan:
    // case IrOpcode::kUint32LessThanOrEqual:
    // case IrOpcode::kUint32MulHigh:
    //   // These 32-bit operations implicitly zero-extend to 64-bit on x64, so
    //   the
    //   // zero-extension is a no-op.
    //   return true;
    // case IrOpcode::kProjection: {
    //   Node* const value = node->InputAt(0);
    //   switch (value->opcode()) {
    //     case IrOpcode::kInt32AddWithOverflow:
    //     case IrOpcode::kInt32SubWithOverflow:
    //     case IrOpcode::kInt32MulWithOverflow:
    //       return true;
    //     default:
    //       return false;
    //   }
    // }
    case IrOpcode::kLoad:
    case IrOpcode::kLoadImmutable: {
      LoadRepresentation load_rep = LoadRepresentationOf(node->op());
      switch (load_rep.representation()) {
        case MachineRepresentation::kWord32:
          return true;
        case MachineRepresentation::kWord8:
          if (load_rep.IsSigned())
            return false;
          else
            return true;
        default:
          return false;
      }
    }
    default:
      return false;
  }
  }
}

template <typename Adapter>
static inline bool DoZeroExtForResult(InstructionSelectorT<Adapter>* selector,
                                      typename Adapter::node_t node) {
  return ProduceWord32Result<Adapter>(selector, node);
}

// TODO(john.yan): Create VisiteShift to match dst = src shift (R+I)
#if 0
void VisitShift() { }
#endif

template <typename Adapter>
void VisitTryTruncateDouble(InstructionSelectorT<Adapter>* selector,
                            ArchOpcode opcode, typename Adapter::node_t node) {
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[] = {g.UseRegister(selector->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = selector->FindProjection(node, 1);
  if (selector->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  selector->Emit(opcode, output_count, outputs, 1, inputs);
}

template <class CanCombineWithLoad>
void GenerateRightOperands(InstructionSelectorT<TurboshaftAdapter>* selector,
                           typename TurboshaftAdapter::node_t node,
                           typename TurboshaftAdapter::node_t right,
                           InstructionCode* opcode, OperandModes* operand_mode,
                           InstructionOperand* inputs, size_t* input_count,
                           CanCombineWithLoad canCombineWithLoad) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  S390OperandGeneratorT<TurboshaftAdapter> g(selector);

  if ((*operand_mode & OperandMode::kAllowImmediate) &&
      g.CanBeImmediate(right, *operand_mode)) {
    inputs[(*input_count)++] = g.UseImmediate(right);
    // Can only be RI or RRI
    *operand_mode &= OperandMode::kAllowImmediate;
  } else if (*operand_mode & OperandMode::kAllowMemoryOperand) {
    const Operation& right_op = selector->Get(right);
    if (right_op.Is<LoadOp>() && selector->CanCover(node, right) &&
        canCombineWithLoad(
            SelectLoadOpcode(selector->load_view(right).ts_loaded_rep(),
                             selector->load_view(right).ts_result_rep()))) {
      AddressingMode mode =
          g.GetEffectiveAddressMemoryOperand(right, inputs, input_count);
      *opcode |= AddressingModeField::encode(mode);
      *operand_mode &= ~OperandMode::kAllowImmediate;
      if (*operand_mode & OperandMode::kAllowRM)
        *operand_mode &= ~OperandMode::kAllowDistinctOps;
    } else if (*operand_mode & OperandMode::kAllowRM) {
      DCHECK(!(*operand_mode & OperandMode::kAllowRRM));
      inputs[(*input_count)++] = g.UseAnyExceptImmediate(right);
      // Can not be Immediate
      *operand_mode &=
          ~OperandMode::kAllowImmediate & ~OperandMode::kAllowDistinctOps;
    } else if (*operand_mode & OperandMode::kAllowRRM) {
      DCHECK(!(*operand_mode & OperandMode::kAllowRM));
      inputs[(*input_count)++] = g.UseAnyExceptImmediate(right);
      // Can not be Immediate
      *operand_mode &= ~OperandMode::kAllowImmediate;
    } else {
      UNREACHABLE();
    }
  } else {
    inputs[(*input_count)++] = g.UseRegister(right);
    // Can only be RR or RRR
    *operand_mode &= OperandMode::kAllowRRR;
  }
}

template <typename Adapter, class CanCombineWithLoad>
void GenerateRightOperands(InstructionSelectorT<Adapter>* selector,
                           typename Adapter::node_t node,
                           typename Adapter::node_t right,
                           InstructionCode* opcode, OperandModes* operand_mode,
                           InstructionOperand* inputs, size_t* input_count,
                           CanCombineWithLoad canCombineWithLoad) {
  S390OperandGeneratorT<Adapter> g(selector);

  if ((*operand_mode & OperandMode::kAllowImmediate) &&
      g.CanBeImmediate(right, *operand_mode)) {
    inputs[(*input_count)++] = g.UseImmediate(right);
    // Can only be RI or RRI
    *operand_mode &= OperandMode::kAllowImmediate;
  } else if (*operand_mode & OperandMode::kAllowMemoryOperand) {
    NodeMatcher mright(right);
    if (mright.IsLoad() && selector->CanCover(node, right) &&
        canCombineWithLoad(
            SelectLoadOpcode(LoadRepresentationOf(right->op())))) {
      AddressingMode mode = g.GetEffectiveAddressMemoryOperand(
          right, inputs, input_count, OpcodeImmMode(*opcode));
      *opcode |= AddressingModeField::encode(mode);
      *operand_mode &= ~OperandMode::kAllowImmediate;
      if (*operand_mode & OperandMode::kAllowRM)
        *operand_mode &= ~OperandMode::kAllowDistinctOps;
    } else if (*operand_mode & OperandMode::kAllowRM) {
      DCHECK(!(*operand_mode & OperandMode::kAllowRRM));
      inputs[(*input_count)++] = g.UseAnyExceptImmediate(right);
      // Can not be Immediate
      *oper
```