Response: The user wants a summary of the C++ code file `instruction-selector-s390.cc`.
This file seems to be part of the V8 JavaScript engine, specifically for the s390 architecture.
It likely handles the selection of machine instructions for a higher-level intermediate representation (IR) of JavaScript code.

Here's a breakdown of the code snippets to infer functionality:

1. **Includes and Namespaces:** Standard V8 includes related to compiler backend and Turboshaft (a compiler component). Indicates this file is part of the compilation process.
2. **OperandMode Enum:** Defines flags representing different operand types and instruction formats for the s390 architecture (immediate values, register-register, register-memory, etc.). This is core to instruction selection.
3. **OperandModes and Macros:** Uses bit flags and macros to define allowed operand combinations for various operations (AND, OR, XOR, Shift, Add, Sub, Mul). This is specific to the s390 instruction set.
4. **BaseWithScaledIndexAndDisplacementMatch:** A structure to represent memory access patterns (base register + index register * scale + displacement). Indicates support for complex addressing modes.
5. **TryMatchBaseWithScaledIndexAndDisplacement64:** A function to detect the aforementioned memory access patterns in the Turboshaft IR.
6. **S390OperandGeneratorT:** A template class to generate instruction operands (registers, immediates, memory addresses) based on the IR nodes and allowed operand modes. This is a crucial component for mapping IR to machine instructions.
7. **Helper Functions:** `S390OpcodeOnlySupport12BitDisp`, `SelectLoadOpcode`:  Functions related to specific s390 instruction characteristics (e.g., displacement size limits) and opcode selection for load operations based on data types.
8. **RESULT_IS_WORD32_LIST and ProduceWord32Result:**  Defines a list of operations that produce 32-bit results. The `ProduceWord32Result` function checks if a given IR node produces a 32-bit value.
9. **VisitTryTruncateDouble:** Handles the selection of instructions for truncating double-precision floating-point numbers.
10. **GenerateRightOperands, GenerateBinOpOperands:**  Functions to generate the operands for binary operations, considering immediate values, memory operands, and different instruction formats.
11. **VisitUnaryOp, VisitBinOp:** Template functions to handle the selection of instructions for unary and binary operations, respectively.
12. **VisitStackSlot, VisitAbortCSADcheck, VisitLoad, VisitProtectedLoad:** Functions to handle specific IR nodes like stack slot allocation, security checks, and load operations.
13. **VisitGeneralStore:**  Handles the selection of instructions for store operations, including write barriers for garbage collection.
14. **VisitStore, VisitProtectedStore, VisitUnalignedLoad/Store:** Functions for different kinds of store operations and handling (or lack thereof for s390) unaligned memory access.
15. **VisitStackPointerGreaterThan:** Handles stack overflow checks.
16. **IsContiguousMask64:**  A helper function to check if a 64-bit value represents a contiguous bitmask.
17. **VisitWord64And, VisitWord64Shl, VisitWord64Shr:** Functions to handle bitwise AND, left shift, and right shift operations specifically for 64-bit integers, potentially optimizing them using specific s390 instructions like `rldic`.这个C++源代码文件 `instruction-selector-s390.cc` 的主要功能是**为 V8 JavaScript 引擎的 s390 架构选择合适的机器指令**。它是编译器后端的一部分，负责将中间表示（IR，Intermediate Representation）的 JavaScript 代码转换为目标机器的汇编指令。

更具体地说，这个文件的功能可以归纳为：

1. **定义了 s390 架构特定的操作数模式（Operand Modes）：**  `OperandMode` 枚举定义了不同类型的操作数，例如立即数（不同大小的立即数），以及支持的指令格式（RRR, RM, RI 等）。这反映了 s390 指令集架构的特点。
2. **提供了方便的宏和类型别名来管理操作数模式：**  例如 `OperandModes` 和 `immediateModeMask`，以及像 `AndCommonMode` 这样的宏，用于更简洁地表达允许的操作数组合。
3. **实现了对复杂内存寻址模式的匹配：**  `BaseWithScaledIndexAndDisplacementMatch` 结构和 `TryMatchBaseWithScaledIndexAndDisplacement64` 函数用于识别和处理带有基址寄存器、索引寄存器（可缩放）和偏移量的内存访问模式。
4. **提供了一个 `S390OperandGeneratorT` 模板类：**  这个类负责根据 IR 节点和允许的操作数模式生成具体的机器指令操作数。它封装了获取立即数、判断是否可以是立即数、生成内存操作数等功能。
5. **包含了选择特定指令的逻辑：** 例如 `SelectLoadOpcode` 函数根据加载的数据类型选择合适的加载指令。
6. **处理了不同类型的操作符：**  例如 `VisitLoad`, `VisitStore`, `VisitWord64And`, `VisitWord64Shl` 等函数负责为加载、存储、位运算等不同的 IR 节点选择对应的 s390 指令。
7. **考虑了 s390 架构的特性和优化：**  例如，在处理 `Word64And` 和 `Word64Shl` 时，代码尝试利用 s390 特有的 `rldic` 指令进行优化。
8. **支持 Turboshaft 编译器：** 文件中存在针对 Turboshaft 编译器的特定实现和类型，例如 `TurboshaftAdapter`。
9. **处理了写屏障（Write Barriers）：** 在 `VisitGeneralStore` 函数中，考虑了垃圾回收所需的写屏障操作。
10. **处理了栈操作和安全检查：** 例如 `VisitStackSlot` 和 `VisitStackPointerGreaterThan`。

**与 JavaScript 的关系：**

这个文件是 V8 引擎将 JavaScript 代码编译成机器码的关键部分。当 V8 引擎执行 JavaScript 代码时，它会将代码转换为一种中间表示。然后，`instruction-selector-s390.cc` 的功能就是将这些中间表示的操作转换为可以在 s390 架构上执行的实际机器指令。

**JavaScript 示例：**

假设有以下简单的 JavaScript 代码：

```javascript
let a = 10;
let b = a + 5;
console.log(b);
```

V8 引擎在编译这段代码时，会生成相应的中间表示。  `instruction-selector-s390.cc` 会参与将类似 "加载常量 10 到寄存器"，"将寄存器中的值加 5"，"将结果存储到变量 b" 等中间操作转换为 s390 的汇编指令。

例如，对于 `let b = a + 5;` 中的加法操作，`VisitBinOp` 函数可能会被调用，并根据 `AddOperandMode` 中定义的允许操作数模式，选择一个合适的 s390 加法指令，例如：

* 如果 `a` 的值已经在一个寄存器中，并且 `5` 可以作为立即数，则可能选择 `AGFI` (Add Halfword Immediate) 指令。
* 如果 `a` 和 `5` 的值都在寄存器中，则可能选择 `AGR` (Add Register) 指令。
* 如果 `a` 的值在内存中，并且 `5` 可以作为立即数，则可能选择 `AGF` (Add Halfword) 指令。

这个 `.cc` 文件中定义的操作数模式和指令选择逻辑直接影响了最终生成的机器码的效率和正确性，从而影响了 JavaScript 代码在 s390 架构上的执行性能。

总而言之，`instruction-selector-s390.cc` 是 V8 引擎中一个高度专业化且与硬件架构紧密相关的组件，它负责将高级的 JavaScript 概念转换为底层的机器指令，使得 JavaScript 代码能够在 s390 架构的计算机上运行。

Prompt: 
```
这是目录为v8/src/compiler/backend/s390/instruction-selector-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
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
void GenerateBinOpOperands(InstructionSelectorT<Adapter>* selector,
                           typename Adapter::node_t node,
                           typename Adapter::node_t left,
                           typename Adapter::node_t right,
                           InstructionCode* opcode, OperandModes* operand_mode,
                           InstructionOperand* inputs, size_t* input_count,
                           CanCombineWithLoad canCombineWithLoad) {
  S390OperandGeneratorT<Adapter> g(selector);
  // left is always register
  InstructionOperand const left_input = g.UseRegister(left);
  inputs[(*input_count)++] = left_input;

  if (left == right) {
    inputs[(*input_count)++] = left_input;
    // Can only be RR or RRR
    *operand_mode &= OperandMode::kAllowRRR;
  } else {
    GenerateRightOperands(selector, node, right, opcode, operand_mode, inputs,
                          input_count, canCombineWithLoad);
  }
}

template <typename Adapter, class CanCombineWithLoad>
void VisitUnaryOp(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                  CanCombineWithLoad canCombineWithLoad);

template <typename Adapter, class CanCombineWithLoad>
void VisitBinOp(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                CanCombineWithLoad canCombineWithLoad);

// Generate The following variations:
//   VisitWord32UnaryOp, VisitWord32BinOp,
//   VisitWord64UnaryOp, VisitWord64BinOp,
//   VisitFloat32UnaryOp, VisitFloat32BinOp,
//   VisitFloat64UnaryOp, VisitFloat64BinOp
#define VISIT_OP_LIST_32(V)                                            \
  V(Word32, Unary, [](ArchOpcode opcode) {                             \
    return opcode == kS390_LoadWordS32 || opcode == kS390_LoadWordU32; \
  })                                                                   \
  V(Word64, Unary,                                                     \
    [](ArchOpcode opcode) { return opcode == kS390_LoadWord64; })      \
  V(Float32, Unary,                                                    \
    [](ArchOpcode opcode) { return opcode == kS390_LoadFloat32; })     \
  V(Float64, Unary,                                                    \
    [](ArchOpcode opcode) { return opcode == kS390_LoadDouble; })      \
  V(Word32, Bin, [](ArchOpcode opcode) {                               \
    return opcode == kS390_LoadWordS32 || opcode == kS390_LoadWordU32; \
  })                                                                   \
  V(Float32, Bin,                                                      \
    [](ArchOpcode opcode) { return opcode == kS390_LoadFloat32; })     \
  V(Float64, Bin, [](ArchOpcode opcode) { return opcode == kS390_LoadDouble; })

#define VISIT_OP_LIST(V) \
  VISIT_OP_LIST_32(V)    \
  V(Word64, Bin, [](ArchOpcode opcode) { return opcode == kS390_LoadWord64; })

#define DECLARE_VISIT_HELPER_FUNCTIONS(type1, type2, canCombineWithLoad)      \
  template <typename Adapter>                                                 \
  static inline void Visit##type1##type2##Op(                                 \
      InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node, \
      InstructionCode opcode, OperandModes operand_mode,                      \
      FlagsContinuationT<Adapter>* cont) {                                    \
    Visit##type2##Op(selector, node, opcode, operand_mode, cont,              \
                     canCombineWithLoad);                                     \
  }                                                                           \
  template <typename Adapter>                                                 \
  static inline void Visit##type1##type2##Op(                                 \
      InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node, \
      InstructionCode opcode, OperandModes operand_mode) {                    \
    FlagsContinuationT<Adapter> cont;                                         \
    Visit##type1##type2##Op(selector, node, opcode, operand_mode, &cont);     \
  }
VISIT_OP_LIST(DECLARE_VISIT_HELPER_FUNCTIONS)
#undef DECLARE_VISIT_HELPER_FUNCTIONS
#undef VISIT_OP_LIST_32
#undef VISIT_OP_LIST

template <typename Adapter, class CanCombineWithLoad>
void VisitUnaryOp(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                  CanCombineWithLoad canCombineWithLoad) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;
  node_t input = selector->input_at(node, 0);

  GenerateRightOperands(selector, node, input, &opcode, &operand_mode, inputs,
                        &input_count, canCombineWithLoad);

  bool input_is_word32 = ProduceWord32Result<Adapter>(selector, input);

  bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
  bool canEliminateZeroExt = input_is_word32;

  if (doZeroExt) {
    // Add zero-ext indication
    inputs[input_count++] = g.TempImmediate(!canEliminateZeroExt);
  }

  if (!cont->IsDeoptimize()) {
    // If we can deoptimize as a result of the binop, we need to make sure
    // that the deopt inputs are not overwritten by the binop result. One way
    // to achieve that is to declare the output register as same-as-first.
    if (doZeroExt && canEliminateZeroExt) {
      // we have to make sure result and left use the same register
      outputs[output_count++] = g.DefineSameAsFirst(node);
    } else {
      outputs[output_count++] = g.DefineAsRegister(node);
    }
  } else {
    outputs[output_count++] = g.DefineSameAsFirst(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter, class CanCombineWithLoad>
void VisitBinOp(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                OperandModes operand_mode, FlagsContinuationT<Adapter>* cont,
                CanCombineWithLoad canCombineWithLoad) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = typename Adapter::node_t;
  S390OperandGeneratorT<Adapter> g(selector);
  node_t left = selector->input_at(node, 0);
  node_t right = selector->input_at(node, 1);
  InstructionOperand inputs[8];
  size_t input_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;

  if constexpr (Adapter::IsTurboshaft) {
    const Operation& op = selector->Get(node);
    if (op.TryCast<WordBinopOp>() &&
        WordBinopOp::IsCommutative(
            selector->Get(node).template Cast<WordBinopOp>().kind) &&
        !g.CanBeImmediate(right, operand_mode) &&
        (g.CanBeBetterLeftOperand(right))) {
      std::swap(left, right);
    }
  } else {
    if (node->op()->HasProperty(Operator::kCommutative) &&
        !g.CanBeImmediate(right, operand_mode) &&
        (g.CanBeBetterLeftOperand(right))) {
      std::swap(left, right);
    }
  }

  GenerateBinOpOperands(selector, node, left, right, &opcode, &operand_mode,
                        inputs, &input_count, canCombineWithLoad);

  bool left_is_word32 = ProduceWord32Result<Adapter>(selector, left);

  bool doZeroExt = DoZeroExtForResult<Adapter>(selector, node);
  bool canEliminateZeroExt = left_is_word32;

  if (doZeroExt) {
    // Add zero-ext indication
    inputs[input_count++] = g.TempImmediate(!canEliminateZeroExt);
  }

  if ((operand_mode & OperandMode::kAllowDistinctOps) &&
      // If we can deoptimize as a result of the binop, we need to make sure
      // that the deopt inputs are not overwritten by the binop result. One way
      // to achieve that is to declare the output register as same-as-first.
      !cont->IsDeoptimize()) {
    if (doZeroExt && canEliminateZeroExt) {
      // we have to make sure result and left use the same register
      outputs[output_count++] = g.DefineSameAsFirst(node);
    } else {
      outputs[output_count++] = g.DefineAsRegister(node);
    }
  } else {
    outputs[output_count++] = g.DefineSameAsFirst(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Emit(kArchAbortCSADcheck, g.NoOutput(),
         g.UseFixed(this->input_at(node, 0), r3));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node, node_t value,
                                              InstructionCode opcode) {
    S390OperandGeneratorT<Adapter> g(this);
    InstructionOperand outputs[] = {g.DefineAsRegister(node)};
    InstructionOperand inputs[3];
    size_t input_count = 0;
    AddressingMode mode =
        g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
    opcode |= AddressingModeField::encode(mode);
    Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  InstructionCode opcode = SelectLoadOpcode(load_rep);
  VisitLoad(node, node, opcode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoad(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  TurboshaftAdapter::LoadView view = this->load_view(node);
  VisitLoad(node, node,
            SelectLoadOpcode(view.ts_loaded_rep(), view.ts_result_rep()));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

static void VisitGeneralStore(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    typename TurboshaftAdapter::node_t node, MachineRepresentation rep,
    WriteBarrierKind write_barrier_kind = kNoWriteBarrier) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = TurboshaftAdapter::node_t;
  using optional_node_t = TurboshaftAdapter::optional_node_t;
  S390OperandGeneratorT<TurboshaftAdapter> g(selector);

  auto store_view = selector->store_view(node);
  DCHECK_EQ(store_view.element_size_log2(), 0);

  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();
  int32_t displacement = store_view.displacement();

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedPointer(rep));
    // Uncompressed stores should not happen if we need a write barrier.
    CHECK((store_view.ts_stored_rep() !=
           MemoryRepresentation::AnyUncompressedTagged()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, base, displacement, DisplacementMode::kPositiveDisplacement,
        inputs, &input_count,
        S390OperandGeneratorT<
            TurboshaftAdapter>::RegisterUseKind::kUseUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;

    switch (store_view.ts_stored_rep()) {
      case MemoryRepresentation::Int8():
      case MemoryRepresentation::Uint8():
        opcode = kS390_StoreWord8;
        break;
      case MemoryRepresentation::Int16():
      case MemoryRepresentation::Uint16():
        opcode = kS390_StoreWord16;
        break;
      case MemoryRepresentation::Int32():
      case MemoryRepresentation::Uint32(): {
        opcode = kS390_StoreWord32;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord32ReverseBytes>()) {
          opcode = kS390_StoreReverse32;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::Int64():
      case MemoryRepresentation::Uint64(): {
        opcode = kS390_StoreWord64;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord64ReverseBytes>()) {
          opcode = kS390_StoreReverse64;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::Float16():
        UNIMPLEMENTED();
      case MemoryRepresentation::Float32():
        opcode = kS390_StoreFloat32;
        break;
      case MemoryRepresentation::Float64():
        opcode = kS390_StoreDouble;
        break;
      case MemoryRepresentation::AnyTagged():
      case MemoryRepresentation::TaggedPointer():
      case MemoryRepresentation::TaggedSigned():
        opcode = kS390_StoreCompressTagged;
        break;
      case MemoryRepresentation::AnyUncompressedTagged():
      case MemoryRepresentation::UncompressedTaggedPointer():
      case MemoryRepresentation::UncompressedTaggedSigned():
        opcode = kS390_StoreWord64;
        break;
      case MemoryRepresentation::Simd128(): {
        opcode = kS390_StoreSimd128;
        const Operation& reverse_op = selector->Get(value);
        // TODO(miladfarca): Rename this to `Opmask::kSimd128ReverseBytes` once
        // Turboshaft naming is decoupled from Turbofan naming.
        if (reverse_op.Is<Opmask::kSimd128Simd128ReverseBytes>()) {
          opcode = kS390_StoreReverseSimd128;
          value = selector->input_at(value, 0);
        }
        break;
      }
      case MemoryRepresentation::ProtectedPointer():
        // We never store directly to protected pointers from generated code.
        UNREACHABLE();
      case MemoryRepresentation::IndirectPointer():
      case MemoryRepresentation::SandboxedPointer():
      case MemoryRepresentation::Simd256():
        UNREACHABLE();
    }

    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    InstructionOperand value_operand = g.UseRegister(value);
    inputs[input_count++] = value_operand;
    selector->Emit(code, 0, static_cast<InstructionOperand*>(nullptr),
                   input_count, inputs);
  }
}

static void VisitGeneralStore(
    InstructionSelectorT<TurbofanAdapter>* selector,
    typename TurbofanAdapter::node_t node, MachineRepresentation rep,
    WriteBarrierKind write_barrier_kind = kNoWriteBarrier) {
  using node_t = TurbofanAdapter::node_t;
  using optional_node_t = TurbofanAdapter::optional_node_t;
  S390OperandGeneratorT<TurbofanAdapter> g(selector);

  auto store_view = selector->store_view(node);
  DCHECK_EQ(store_view.element_size_log2(), 0);

  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();
  int32_t displacement = store_view.displacement();

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, base, displacement, DisplacementMode::kPositiveDisplacement,
        inputs, &input_count,
        S390OperandGeneratorT<
            TurbofanAdapter>::RegisterUseKind::kUseUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kS390_StoreFloat32;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kS390_StoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kS390_StoreWord8;
        break;
      case MachineRepresentation::kWord16:
        opcode = kS390_StoreWord16;
        break;
      case MachineRepresentation::kWord32: {
        opcode = kS390_StoreWord32;
          NodeMatcher m(value);
          if (m.IsWord32ReverseBytes()) {
            opcode = kS390_StoreReverse32;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kIndirectPointer:  // Fall through.
      case MachineRepresentation::kSandboxedPointer:  // Fall through.
#ifdef V8_COMPRESS_POINTERS
        opcode = kS390_StoreCompressTagged;
        break;
#else
        UNREACHABLE();
#endif
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        opcode = kS390_StoreCompressTagged;
        break;
      case MachineRepresentation::kWord64: {
        opcode = kS390_StoreWord64;
          NodeMatcher m(value);
          if (m.IsWord64ReverseBytes()) {
            opcode = kS390_StoreReverse64;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kSimd128: {
        opcode = kS390_StoreSimd128;
          NodeMatcher m(value);
          if (m.IsSimd128ReverseBytes()) {
            opcode = kS390_StoreReverseSimd128;
            value = selector->input_at(value, 0);
          }
        break;
      }
      case MachineRepresentation::kFloat16:
        UNIMPLEMENTED();
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }
    InstructionOperand inputs[4];
    size_t input_count = 0;
    AddressingMode addressing_mode =
        g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    InstructionOperand value_operand = g.UseRegister(value);
    inputs[input_count++] = value_operand;
    selector->Emit(code, 0, static_cast<InstructionOperand*>(nullptr),
                   input_count, inputs);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  StoreRepresentation store_rep = this->store_view(node).stored_rep();
  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

    VisitGeneralStore(this, node, rep, write_barrier_kind);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

// Architecture supports unaligned access, therefore VisitLoad is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  UNREACHABLE();
}

// Architecture supports unaligned access, therefore VisitStore is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
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

  S390OperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry) ? 1 : 0;
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

#if 0
static inline bool IsContiguousMask32(uint32_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros32(value);
  int mask_lsb = base::bits::CountTrailingZeros32(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 32))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}
#endif

static inline bool IsContiguousMask64(uint64_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros64(value);
  int mask_lsb = base::bits::CountTrailingZeros64(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 64))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  S390OperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask64(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord64ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord64ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rldic
      int64_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord64Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 63)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord64ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      bool match = false;
      ArchOpcode opcode;
      int mask;
      if (me == 0) {
        match = true;
        opcode = kS390_RotLeftAndClearLeft64;
        mask = mb;
      } else if (mb == 63) {
        match = true;
        opcode = kS390_RotLeftAndClearRight64;
        mask = me;
      } else if (sh && me <= sh && lhs.Is<Opmask::kWord64ShiftLeft>()) {
        match = true;
        opcode = kS390_RotLeftAndClear64;
        mask = mb;
      }
      if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
        Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
             g.TempImmediate(sh), g.TempImmediate(mask));
        return;
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_And64, And64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    int mb = 0;
    int me = 0;
    if (m.right().HasResolvedValue() &&
        IsContiguousMask64(m.right().ResolvedValue(), &mb, &me)) {
      int sh = 0;
      Node* left = m.left().node();
      if ((m.left().IsWord64Shr() || m.left().IsWord64Shl()) &&
          CanCover(node, left)) {
        Int64BinopMatcher mleft(m.left().node());
        if (mleft.right().IsInRange(0, 63)) {
          left = mleft.left().node();
          sh = mleft.right().ResolvedValue();
          if (m.left().IsWord64Shr()) {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (mb > 63 - sh) mb = 63 - sh;
            sh = (64 - sh) & 0x3F;
          } else {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (me < sh) me = sh;
          }
        }
      }
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kS390_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kS390_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh && m.left().IsWord64Shl()) {
          match = true;
          opcode = kS390_RotLeftAndClear64;
          mask = mb;
        }
        if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
          Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
               g.TempImmediate(sh), g.TempImmediate(mask));
          return;
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_And64, And64OperandMode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shl(node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(this);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = this->Get(shl.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
      this->is_integer_constant(shl.right()) &&
      base::IsInRange(this->integer_constant(shl.right()), 0, 63)) {
    int sh = this->integer_constant(shl.right());
    int mb;
    int me;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    if (this->is_integer_constant(bitwise_and.right()) &&
        IsContiguousMask64(this->integer_constant(bitwise_and.right()) << sh,
                           &mb, &me)) {
      // Adjust the mask such that it doesn't include any rotated bits.
      if (me < sh) me = sh;
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kS390_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kS390_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh) {
          match = true;
          opcode = kS390_RotLeftAndClear64;
          mask = mb;
        }
        if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
          Emit(opcode, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mask));
          return;
        }
      }
    }
  }
  VisitWord64BinOp(this, node, kS390_ShiftLeft64, Shift64OperandMode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
    S390OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    // TODO(mbrandy): eliminate left sign extension if right >= 32
    if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
      Int64BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask64(mleft.right().ResolvedValue() << sh, &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          bool match = false;
          ArchOpcode opcode;
          int mask;
          if (me == 0) {
            match = true;
            opcode = kS390_RotLeftAndClearLeft64;
            mask = mb;
          } else if (mb == 63) {
            match = true;
            opcode = kS390_RotLeftAndClearRight64;
            mask = me;
          } else if (sh && me <= sh) {
            match = true;
            opcode = kS390_RotLeftAndClear64;
            mask = mb;
          }
          if (match && CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
            Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                 g.TempImmediate(mask));
            return;
          }
        }
      }
    }
    VisitWord64BinOp(this, node, kS390_ShiftLeft64, Shift64OperandMode);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(node_t node) {
  S390OperandGeneratorT<TurboshaftAdapter> g(this);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
  const Operation& lhs = this->Get(shr.left());
  if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
      this->is_integer_constant(shr.right()) &&
      base::IsInRange(this->integer_constant(shr.right()), 0, 63)) {
    int sh = this->integer_constant(shr.right());
    int mb;
    int me;
    const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
    if (this->is_integer_constant(bitwise_and.right()) &&
        IsContiguousMask64(
            static_cast<uint64_t>(this->integer_constant(bitwise_and.right()) >>
                                  sh),
            &mb, &me)) {
      // Adjust the mask such that it doesn't include any rotated bits.
  
"""


```