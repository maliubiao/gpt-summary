Response: The user wants a summary of the C++ source code file `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`.
This is the first of six parts.

The code snippet defines:
- `ImmediateMode` enum:  Specifies different types of immediate values allowed in ARM64 instructions.
- `Arm64OperandGeneratorT` class: A helper class to generate instruction operands, specifically for ARM64, handling immediate values and register assignments.
- Several helper functions and templates for instruction selection:
    - `VisitRR`, `VisitRRR`, `VisitRRO`:  Templates for emitting instructions with specific register/operand combinations.
    - `ExtendingLoadMatcher`:  Helps identify and potentially optimize load instructions followed by a right shift.
    - `TryMatchAnyShift`:  Attempts to match shift operations and incorporate them into the main instruction.
    - `TryMatchAnyExtend`:  Looks for opportunities to use extended register forms in instructions.
    - `TryMatchLoadStoreShift`:  Identifies load/store operations with a shifted index.
    - `GetBinopProperties`:  Returns properties of binary operators, such as commutativity.
    - `VisitBinop`:  A central function for handling binary operations, considering immediate operands, shifts, and extensions.
    - `VisitAddSub`:  Handles addition and subtraction, considering negative immediates.
    - `LeftShiftForReducedMultiply`: Detects multiplication by specific constants that can be optimized.
    - `TryEmitMulitplyAdd`, `TryEmitMultiplyNegate`, `TryEmitMultiplySub`: Attempt to recognize and emit fused multiply-add/subtract instructions.
    - `GetStoreOpcodeAndImmediate`: Determines the appropriate store instruction and immediate mode based on the data type.
    - `EmitLoad`:  Handles the emission of load instructions, considering different addressing modes.
    - `EmitAddBeforeLoadOrStore`:  A utility for calculating the effective address before a load or store.
    - `VisitLoadLane`, `VisitStoreLane`, `VisitLoadTransform`: Handle specific SIMD instructions for WebAssembly.
    - `VisitTraceInstruction`, `VisitStackSlot`, `VisitAbortCSADcheck`: Implement instruction selection for specific IR nodes.

The code is heavily involved in the process of converting high-level intermediate representation (IR) of code (likely from JavaScript compilation) into low-level ARM64 machine instructions. It optimizes instruction selection by recognizing patterns and using the most efficient ARM64 instructions available.
该C++代码文件是V8 JavaScript引擎中用于将中间表示（IR）转换为ARM64架构机器指令的指令选择器的一部分。这是该文件的前一部分，主要定义了以下功能：

1. **定义了ARM64特定的立即数模式 (`ImmediateMode` enum):**  这个枚举列出了ARM64指令中可以使用的不同类型的立即数，例如算术立即数、移位立即数、逻辑立即数以及加载/存储偏移量等。这有助于在后续的指令选择过程中判断一个值是否可以作为立即数直接编码到指令中。

2. **定义了 `Arm64OperandGeneratorT` 模板类:** 这个类继承自通用的 `OperandGeneratorT` 类，并添加了ARM64架构特有的方法来生成指令的操作数。它主要负责：
    - 判断一个节点的值是否可以作为特定模式的立即数。
    - 如果可以，则生成立即数操作数；否则，生成寄存器操作数。
    - 提供了一些便利的方法，例如判断是否为零立即数，以及在需要时使用零寄存器。
    - 提供了获取节点中整数和浮点数常量值的方法。

3. **定义了一些辅助模板函数用于生成常见的指令模式:**
    - `VisitRR`, `VisitRRR`: 用于生成两个或三个寄存器操作数的指令。
    - `VisitRRO`: 用于生成一个寄存器操作数和一个立即数或寄存器操作数的指令。

4. **定义了 `ExtendingLoadMatcher` 模板结构体:**  这个结构体的目的是识别一种特定的优化模式，即当加载一个64位值，然后进行右移32位的操作时，可以直接使用ARM64的 `LDRSW` 指令来加载并进行符号扩展，从而提高效率。

5. **定义了 `TryMatchAnyShift` 系列模板函数:** 这些函数尝试识别移位操作（左移、右移、算术右移、循环右移），并判断是否可以将移位操作融合到当前指令的操作数中，以减少指令数量。

6. **定义了 `TryMatchAnyExtend` 系列模板函数:** 这些函数尝试识别一些特定的位操作和类型转换模式，并判断是否可以使用ARM64的扩展寄存器模式，例如使用 `UXTB`、`UXTH`、`SXTB`、`SXTH` 或 `SXTW` 等指令，将较小的值扩展到更大的寄存器中。

7. **定义了 `TryMatchLoadStoreShift` 模板函数:**  这个函数尝试识别加载和存储操作中使用了移位后的索引的情况，以便生成更紧凑的指令。

8. **定义了 `GetBinopProperties` 函数:**  这个函数返回一个二进制操作的属性，例如是否可交换操作数，是否是比较操作等，这在后续选择最优指令时会用到。

9. **定义了 `VisitBinop` 系列模板函数:**  这是一个核心函数，用于处理各种二进制操作（例如加法、减法、与、或、异或等）。它会根据操作数的类型（寄存器或立即数），以及是否可以进行移位或扩展优化，来选择合适的ARM64指令。

10. **定义了 `VisitAddSub` 系列模板函数:**  专门用于处理加法和减法操作，并考虑了使用立即数优化的场景。

11. **定义了 `LeftShiftForReducedMultiply` 函数:**  用于检测乘以特定立即数（形如 2<sup>k</sup> + 1）的乘法操作，并返回 k 的值，以便将其转换为移位和加法操作，提高效率。

12. **定义了 `TryEmitMulitplyAdd`、`TryEmitMultiplyNegate`、`TryEmitMultiplySub` 系列模板函数:** 用于尝试识别并生成ARM64的融合乘加 (`Madd`)、乘负 (`Mneg`) 和乘减 (`Msub`) 指令，以提高性能。

13. **定义了 `GetStoreOpcodeAndImmediate` 函数:**  根据要存储的数据类型和是否是成对存储，确定合适的ARM64存储指令和立即数模式。

**与 JavaScript 的关系:**

该代码文件是V8引擎编译器的后端部分，负责将JavaScript代码编译成机器码。当JavaScript代码执行算术运算、位运算、内存访问等操作时，V8的编译器会生成相应的中间表示。而 `instruction-selector-arm64.cc` 的任务就是将这些中间表示转换为针对ARM64架构的机器指令。

**JavaScript 示例:**

```javascript
function addAndMultiply(a, b) {
  return (a + 10) * b;
}

let result = addAndMultiply(5, 3);
console.log(result); // 输出 45
```

在这个简单的 JavaScript 例子中，当 V8 编译 `addAndMultiply` 函数时，`instruction-selector-arm64.cc` 的相关代码会参与将 `a + 10` 和 `... * b` 这两个操作转换为 ARM64 指令。例如：

- 对于 `a + 10`，`Arm64OperandGeneratorT` 可能会判断 `10` 可以作为立即数，然后 `VisitBinop` 函数可能会生成一个 `ADD` 指令，其中一个操作数是寄存器 `a` 的值，另一个操作数是立即数 `10`。
- 对于 `... * b`，如果 V8 内部的优化允许，并且架构支持，可能会尝试使用融合乘加指令（如果前面的加法结果需要累加到某个地方）或者一个单独的乘法指令。`LeftShiftForReducedMultiply` 可能会检查乘数是否是特定的形式，以便用移位和加法代替乘法。

总而言之，`instruction-selector-arm64.cc` 是 V8 引擎将 JavaScript 代码转换为高效的 ARM64 机器码的关键组成部分，它通过仔细选择合适的指令和利用 ARM64 架构的特性来提高 JavaScript 的执行性能。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operation-matcher.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/flags/flags.h"

namespace v8 {
namespace internal {
namespace compiler {

enum ImmediateMode {
  kArithmeticImm,  // 12 bit unsigned immediate shifted left 0 or 12 bits
  kShift32Imm,     // 0 - 31
  kShift64Imm,     // 0 - 63
  kLogical32Imm,
  kLogical64Imm,
  kLoadStoreImm8,  // signed 8 bit or 12 bit unsigned scaled by access size
  kLoadStoreImm16,
  kLoadStoreImm32,
  kLoadStoreImm64,
  kConditionalCompareImm,
  kNoImmediate
};

// Adds Arm64-specific methods for generating operands.
template <typename Adapter>
class Arm64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit Arm64OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(node_t node, ImmediateMode mode) {
    if (CanBeImmediate(node, mode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  bool IsImmediateZero(typename Adapter::node_t node) {
    if (this->is_constant(node)) {
      auto constant = selector()->constant_view(node);
      if ((IsIntegerConstant(constant) &&
           GetIntegerConstantValue(constant) == 0) ||
          constant.is_float_zero()) {
        return true;
      }
    }
    return false;
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register.
  InstructionOperand UseRegisterOrImmediateZero(typename Adapter::node_t node) {
    if (IsImmediateZero(node)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register, keeping it alive for the whole sequence of continuation
  // instructions.
  InstructionOperand UseRegisterAtEndOrImmediateZero(
      typename Adapter::node_t node) {
    if (IsImmediateZero(node)) {
      return UseImmediate(node);
    }
    return this->UseRegisterAtEnd(node);
  }

  // Use the provided node if it has the required value, or create a
  // TempImmediate otherwise.
  InstructionOperand UseImmediateOrTemp(node_t node, int32_t value) {
    if (selector()->integer_constant(node) == value) {
      return UseImmediate(node);
    }
    return TempImmediate(value);
  }

  int64_t GetIntegerConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kInt32Constant) {
      return OpParameter<int32_t>(node->op());
    }
    DCHECK_EQ(IrOpcode::kInt64Constant, node->opcode());
    return OpParameter<int64_t>(node->op());
  }

  bool IsIntegerConstant(node_t node) const {
    return selector()->is_integer_constant(node);
  }

  int64_t GetIntegerConstantValue(typename Adapter::ConstantView constant) {
    if (constant.is_int32()) {
      return constant.int32_value();
    }
    DCHECK(constant.is_int64());
    return constant.int64_value();
  }

  std::optional<int64_t> GetOptionalIntegerConstant(node_t operation) {
    if (!this->IsIntegerConstant(operation)) return {};
    return this->GetIntegerConstantValue(selector()->constant_view(operation));
  }

  bool IsFloatConstant(Node* node) {
    return (node->opcode() == IrOpcode::kFloat32Constant) ||
           (node->opcode() == IrOpcode::kFloat64Constant);
  }

  double GetFloatConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kFloat32Constant) {
      return OpParameter<float>(node->op());
    }
    DCHECK_EQ(IrOpcode::kFloat64Constant, node->opcode());
    return OpParameter<double>(node->op());
  }

  bool CanBeImmediate(node_t node, ImmediateMode mode) {
    if (!this->is_constant(node)) return false;
    auto constant = this->constant_view(node);
    if (constant.is_compressed_heap_object()) {
      if (!COMPRESS_POINTERS_BOOL) return false;
      // For builtin code we need static roots
      if (selector()->isolate()->bootstrapper() && !V8_STATIC_ROOTS_BOOL) {
        return false;
      }
      const RootsTable& roots_table = selector()->isolate()->roots_table();
      RootIndex root_index;
      Handle<HeapObject> value = constant.heap_object_value();
      if (roots_table.IsRootHandle(value, &root_index)) {
        if (!RootsTable::IsReadOnly(root_index)) return false;
        return CanBeImmediate(MacroAssemblerBase::ReadOnlyRootPtr(
                                  root_index, selector()->isolate()),
                              mode);
      }
      return false;
    }

    return IsIntegerConstant(constant) &&
           CanBeImmediate(GetIntegerConstantValue(constant), mode);
  }

  bool CanBeImmediate(int64_t value, ImmediateMode mode) {
    unsigned ignored;
    switch (mode) {
      case kLogical32Imm:
        // TODO(dcarney): some unencodable values can be handled by
        // switching instructions.
        return Assembler::IsImmLogical(static_cast<uint32_t>(value), 32,
                                       &ignored, &ignored, &ignored);
      case kLogical64Imm:
        return Assembler::IsImmLogical(static_cast<uint64_t>(value), 64,
                                       &ignored, &ignored, &ignored);
      case kArithmeticImm:
        return Assembler::IsImmAddSub(value);
      case kLoadStoreImm8:
        return IsLoadStoreImmediate(value, 0);
      case kLoadStoreImm16:
        return IsLoadStoreImmediate(value, 1);
      case kLoadStoreImm32:
        return IsLoadStoreImmediate(value, 2);
      case kLoadStoreImm64:
        return IsLoadStoreImmediate(value, 3);
      case kNoImmediate:
        return false;
      case kConditionalCompareImm:
        return Assembler::IsImmConditionalCompare(value);
      case kShift32Imm:  // Fall through.
      case kShift64Imm:
        // Shift operations only observe the bottom 5 or 6 bits of the value.
        // All possible shifts can be encoded by discarding bits which have no
        // effect.
        return true;
    }
    return false;
  }

  bool CanBeLoadStoreShiftImmediate(node_t node, MachineRepresentation rep) {
    // TODO(arm64): Load and Store on 128 bit Q registers is not supported yet.
    DCHECK_GT(MachineRepresentation::kSimd128, rep);
    if (!selector()->is_constant(node)) return false;
    auto constant = selector()->constant_view(node);
    return IsIntegerConstant(constant) &&
           (GetIntegerConstantValue(constant) == ElementSizeLog2Of(rep));
  }

 private:
  bool IsLoadStoreImmediate(int64_t value, unsigned size) {
    return Assembler::IsImmLSScaled(value, size) ||
           Assembler::IsImmLSUnscaled(value);
  }
};

namespace {

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
             typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              Node* node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(node->InputAt(0)),
                 g.UseRegister(node->InputAt(1)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void VisitSimdShiftRRR(InstructionSelectorT<Adapter>* selector,
                       ArchOpcode opcode, typename Adapter::node_t node,
                       int width) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  if (selector->is_integer_constant(selector->input_at(node, 1))) {
    if (selector->integer_constant(selector->input_at(node, 1)) % width == 0) {
      selector->EmitIdentity(node);
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)));
    }
  } else {
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}

template <typename Adapter>
void VisitRRI(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    int imm = op.template Cast<Simd128ExtractLaneOp>().lane;
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(imm));
  } else {
    Arm64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm));
  }
}

template <typename Adapter>
void VisitRRIR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
               typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        selector->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Arm64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(op.lane), g.UseUniqueRegister(op.input(1)));
  } else {
    Arm64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm),
                   g.UseUniqueRegister(node->InputAt(1)));
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void VisitRRO(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              typename Adapter::node_t node, ImmediateMode operand_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseOperand(selector->input_at(node, 1), operand_mode));
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
      Arm64OperandGeneratorT<Adapter> g(selector_);
      Node* load = m.left().node();
      Node* offset = load->InputAt(1);
      base_ = load->InputAt(0);
      opcode_ = kArm64Ldrsw;
      if (g.IsIntegerConstant(offset)) {
        immediate_ = g.GetIntegerConstantValue(offset) + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
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
      Arm64OperandGeneratorT<Adapter> g(selector_);
      const LoadOp& load = lhs.Cast<LoadOp>();
      base_ = load.base();
      opcode_ = kArm64Ldrsw;
      if (load.index().has_value()) {
        int64_t index_constant;
        if (selector_->MatchIntegralWord64Constant(load.index().value(),
                                                   &index_constant)) {
          DCHECK_EQ(load.element_size_log2, 0);
          immediate_ = index_constant + 4;
          matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
        }
      } else {
        immediate_ = load.offset + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
      }
    }
  }
};

template <typename Adapter>
bool TryMatchExtendingLoad(InstructionSelectorT<Adapter>* selector,
                           typename Adapter::node_t node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  return m.Matches();
}

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  Arm64OperandGeneratorT<Adapter> g(selector);
  if (m.Matches()) {
    InstructionOperand inputs[2];
    inputs[0] = g.UseRegister(m.base());
    InstructionCode opcode =
        m.opcode() | AddressingModeField::encode(kMode_MRI);
    DCHECK(is_int32(m.immediate()));
    inputs[1] = g.TempImmediate(static_cast<int32_t>(m.immediate()));
    InstructionOperand outputs[] = {g.DefineAsRegister(node)};
    selector->Emit(opcode, arraysize(outputs), outputs, arraysize(inputs),
                   inputs);
    return true;
  }
  return false;
}

template <typename Adapter>
bool TryMatchAnyShift(InstructionSelectorT<Adapter>* selector, Node* node,
                      Node* input_node, InstructionCode* opcode, bool try_ror,
                      MachineRepresentation rep) {
  Arm64OperandGeneratorT<Adapter> g(selector);

  if (!selector->CanCover(node, input_node)) return false;
  if (input_node->InputCount() != 2) return false;
  if (!g.IsIntegerConstant(input_node->InputAt(1))) return false;

  switch (input_node->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord32Sar:
    case IrOpcode::kWord32Ror:
      if (rep != MachineRepresentation::kWord32) return false;
      break;
    case IrOpcode::kWord64Shl:
    case IrOpcode::kWord64Shr:
    case IrOpcode::kWord64Sar:
    case IrOpcode::kWord64Ror:
      if (rep != MachineRepresentation::kWord64) return false;
      break;
    default:
      return false;
  }

  switch (input_node->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord64Shl:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
      return true;
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord64Shr:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSR_I);
      return true;
    case IrOpcode::kWord32Sar:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
      return true;
    case IrOpcode::kWord64Sar:
      if (TryMatchExtendingLoad(selector, input_node)) return false;
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
      return true;
    case IrOpcode::kWord32Ror:
    case IrOpcode::kWord64Ror:
      if (try_ror) {
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_ROR_I);
        return true;
      }
      return false;
    default:
      UNREACHABLE();
  }
}

bool TryMatchAnyShift(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex node, turboshaft::OpIndex input_node,
                      InstructionCode* opcode, bool try_ror,
                      turboshaft::RegisterRepresentation rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);

  if (!selector->CanCover(node, input_node)) return false;
  if (const ShiftOp* shift = selector->Get(input_node).TryCast<ShiftOp>()) {
    // Differently to Turbofan, the representation should always match.
    DCHECK_EQ(shift->rep, rep);
    if (shift->rep != rep) return false;
    if (!g.IsIntegerConstant(shift->right())) return false;

    switch (shift->kind) {
      case ShiftOp::Kind::kShiftLeft:
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
        return true;
      case ShiftOp::Kind::kShiftRightLogical:
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSR_I);
        return true;
      case ShiftOp::Kind::kShiftRightArithmetic:
      case ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros:
        if (rep == WordRepresentation::Word64() &&
            TryMatchExtendingLoad(selector, input_node)) {
          return false;
        }
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
        return true;
      case ShiftOp::Kind::kRotateRight:
        if (try_ror) {
          *opcode |= AddressingModeField::encode(kMode_Operand2_R_ROR_I);
          return true;
        }
        return false;
      case ShiftOp::Kind::kRotateLeft:
        return false;
    }
  }
  return false;
}

bool TryMatchAnyExtend(Arm64OperandGeneratorT<TurbofanAdapter>* g,
                       InstructionSelectorT<TurbofanAdapter>* selector,
                       Node* node, Node* left_node, Node* right_node,
                       InstructionOperand* left_op,
                       InstructionOperand* right_op, InstructionCode* opcode) {
  if (!selector->CanCover(node, right_node)) return false;

  NodeMatcher nm(right_node);

  if (nm.IsWord32And()) {
    Int32BinopMatcher mright(right_node);
    if (mright.right().Is(0xFF) || mright.right().Is(0xFFFF)) {
      int32_t mask = mright.right().ResolvedValue();
      *left_op = g->UseRegister(left_node);
      *right_op = g->UseRegister(mright.left().node());
      *opcode |= AddressingModeField::encode(
          (mask == 0xFF) ? kMode_Operand2_R_UXTB : kMode_Operand2_R_UXTH);
      return true;
    }
  } else if (nm.IsWord32Sar()) {
    Int32BinopMatcher mright(right_node);
    if (selector->CanCover(mright.node(), mright.left().node()) &&
        mright.left().IsWord32Shl()) {
      Int32BinopMatcher mleft_of_right(mright.left().node());
      if ((mright.right().Is(16) && mleft_of_right.right().Is(16)) ||
          (mright.right().Is(24) && mleft_of_right.right().Is(24))) {
        int32_t shift = mright.right().ResolvedValue();
        *left_op = g->UseRegister(left_node);
        *right_op = g->UseRegister(mleft_of_right.left().node());
        *opcode |= AddressingModeField::encode(
            (shift == 24) ? kMode_Operand2_R_SXTB : kMode_Operand2_R_SXTH);
        return true;
      }
    }
  } else if (nm.IsChangeInt32ToInt64()) {
    // Use extended register form.
    *opcode |= AddressingModeField::encode(kMode_Operand2_R_SXTW);
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(right_node->InputAt(0));
    return true;
  }
  return false;
}

bool TryMatchBitwiseAndSmallMask(turboshaft::OperationMatcher& matcher,
                                 turboshaft::OpIndex op,
                                 turboshaft::OpIndex* left, int32_t* mask) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (const ChangeOp* change_op =
          matcher.TryCast<Opmask::kChangeInt32ToInt64>(op)) {
    return TryMatchBitwiseAndSmallMask(matcher, change_op->input(), left, mask);
  }
  if (const WordBinopOp* bitwise_and =
          matcher.TryCast<Opmask::kWord32BitwiseAnd>(op)) {
    if (matcher.MatchIntegralWord32Constant(bitwise_and->right(), mask) &&
        (*mask == 0xFF || *mask == 0xFFFF)) {
      *left = bitwise_and->left();
      return true;
    }
    if (matcher.MatchIntegralWord32Constant(bitwise_and->left(), mask) &&
        (*mask == 0xFF || *mask == 0xFFFF)) {
      *left = bitwise_and->right();
      return true;
    }
  }
  return false;
}

bool TryMatchSignExtendShift(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex op, turboshaft::OpIndex* left,
                             int32_t* shift_by) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (const ChangeOp* change_op =
          selector->TryCast<Opmask::kChangeInt32ToInt64>(op)) {
    return TryMatchSignExtendShift(selector, change_op->input(), left,
                                   shift_by);
  }

  if (const ShiftOp* sar =
          selector->TryCast<Opmask::kWord32ShiftRightArithmetic>(op)) {
    const Operation& sar_lhs = selector->Get(sar->left());
    if (sar_lhs.Is<Opmask::kWord32ShiftLeft>() &&
        selector->CanCover(op, sar->left())) {
      const ShiftOp& shl = sar_lhs.Cast<ShiftOp>();
      int32_t sar_by, shl_by;
      if (selector->MatchIntegralWord32Constant(sar->right(), &sar_by) &&
          selector->MatchIntegralWord32Constant(shl.right(), &shl_by) &&
          sar_by == shl_by && (sar_by == 16 || sar_by == 24)) {
        *left = shl.left();
        *shift_by = sar_by;
        return true;
      }
    }
  }
  return false;
}

bool TryMatchAnyExtend(Arm64OperandGeneratorT<TurboshaftAdapter>* g,
                       InstructionSelectorT<TurboshaftAdapter>* selector,
                       turboshaft::OpIndex node, turboshaft::OpIndex left_node,
                       turboshaft::OpIndex right_node,
                       InstructionOperand* left_op,
                       InstructionOperand* right_op, InstructionCode* opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (!selector->CanCover(node, right_node)) return false;

  const Operation& right = selector->Get(right_node);
  OpIndex bitwise_and_left;
  int32_t mask;
  if (TryMatchBitwiseAndSmallMask(*selector, right_node, &bitwise_and_left,
                                  &mask)) {
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(bitwise_and_left);
    *opcode |= AddressingModeField::encode(
        (mask == 0xFF) ? kMode_Operand2_R_UXTB : kMode_Operand2_R_UXTH);
    return true;
  }

  OpIndex shift_input_left;
  int32_t shift_by;
  if (TryMatchSignExtendShift(selector, right_node, &shift_input_left,
                              &shift_by)) {
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(shift_input_left);
    *opcode |= AddressingModeField::encode(
        (shift_by == 24) ? kMode_Operand2_R_SXTB : kMode_Operand2_R_SXTH);
    return true;
  }

  if (const ChangeOp* change_op =
          right.TryCast<Opmask::kChangeInt32ToInt64>()) {
    // Use extended register form.
    *opcode |= AddressingModeField::encode(kMode_Operand2_R_SXTW);
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(change_op->input());
    return true;
  }
  return false;
}

template <typename Adapter>
bool TryMatchLoadStoreShift(Arm64OperandGeneratorT<Adapter>* g,
                            InstructionSelectorT<Adapter>* selector,
                            MachineRepresentation rep,
                            typename Adapter::node_t node,
                            typename Adapter::node_t index,
                            InstructionOperand* index_op,
                            InstructionOperand* shift_immediate_op) {
  if (!selector->CanCover(node, index)) return false;
  if (index->InputCount() != 2) return false;
  switch (index->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord64Shl: {
      Node* left = index->InputAt(0);
      Node* right = index->InputAt(1);
      if (!g->CanBeLoadStoreShiftImmediate(right, rep)) {
        return false;
      }
      *index_op = g->UseRegister(left);
      *shift_immediate_op = g->UseImmediate(right);
      return true;
    }
    default:
      return false;
  }
}

template <>
bool TryMatchLoadStoreShift(Arm64OperandGeneratorT<TurboshaftAdapter>* g,
                            InstructionSelectorT<TurboshaftAdapter>* selector,
                            MachineRepresentation rep, turboshaft::OpIndex node,
                            turboshaft::OpIndex index,
                            InstructionOperand* index_op,
                            InstructionOperand* shift_immediate_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (!selector->CanCover(node, index)) return false;
  if (const ChangeOp* change =
          selector->Get(index).TryCast<Opmask::kChangeUint32ToUint64>();
      change && selector->CanCover(index, change->input())) {
    index = change->input();
  }
  const ShiftOp* shift = selector->Get(index).TryCast<Opmask::kShiftLeft>();
  if (shift == nullptr) return false;
  if (!g->CanBeLoadStoreShiftImmediate(shift->right(), rep)) return false;
  *index_op = g->UseRegister(shift->left());
  *shift_immediate_op = g->UseImmediate(shift->right());
  return true;
}

// Bitfields describing binary operator properties:
// CanCommuteField is true if we can switch the two operands, potentially
// requiring commuting the flags continuation condition.
using CanCommuteField = base::BitField8<bool, 1, 1>;
// MustCommuteCondField is true when we need to commute the flags continuation
// condition in order to switch the operands.
using MustCommuteCondField = base::BitField8<bool, 2, 1>;
// IsComparisonField is true when the operation is a comparison and has no other
// result other than the condition.
using IsComparisonField = base::BitField8<bool, 3, 1>;
// IsAddSubField is true when an instruction is encoded as ADD or SUB.
using IsAddSubField = base::BitField8<bool, 4, 1>;

// Get properties of a binary operator.
uint8_t GetBinopProperties(InstructionCode opcode) {
  uint8_t result = 0;
  switch (opcode) {
    case kArm64Cmp32:
    case kArm64Cmp:
      // We can commute CMP by switching the inputs and commuting
      // the flags continuation.
      result = CanCommuteField::update(result, true);
      result = MustCommuteCondField::update(result, true);
      result = IsComparisonField::update(result, true);
      // The CMP and CMN instructions are encoded as SUB or ADD
      // with zero output register, and therefore support the same
      // operand modes.
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Cmn32:
    case kArm64Cmn:
      result = CanCommuteField::update(result, true);
      result = IsComparisonField::update(result, true);
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Add32:
    case kArm64Add:
      result = CanCommuteField::update(result, true);
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Sub32:
    case kArm64Sub:
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Tst32:
    case kArm64Tst:
      result = CanCommuteField::update(result, true);
      result = IsComparisonField::update(result, true);
      break;
    case kArm64And32:
    case kArm64And:
    case kArm64Or32:
    case kArm64Or:
    case kArm64Eor32:
    case kArm64Eor:
      result = CanCommuteField::update(result, true);
      break;
    default:
      UNREACHABLE();
  }
  DCHECK_IMPLIES(MustCommuteCondField::decode(result),
                 CanCommuteField::decode(result));
  return result;
}

// Shared routine for multiple binary operations.
template <typename Adapter, typename Matcher>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                ImmediateMode operand_mode, FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[5];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  Node* left_node = node->InputAt(0);
  Node* right_node = node->InputAt(1);

  uint8_t properties = GetBinopProperties(opcode);
  bool can_commute = CanCommuteField::decode(properties);
  bool must_commute_cond = MustCommuteCondField::decode(properties);
  bool is_add_sub = IsAddSubField::decode(properties);

  if (g.CanBeImmediate(right_node, operand_mode)) {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseImmediate(right_node);
  } else if (can_commute && g.CanBeImmediate(left_node, operand_mode)) {
    if (must_commute_cond) cont->Commute();
    inputs[input_count++] = g.UseRegister(right_node);
    inputs[input_count++] = g.UseImmediate(left_node);
  } else if (is_add_sub &&
             TryMatchAnyExtend(&g, selector, node, left_node, right_node,
                               &inputs[0], &inputs[1], &opcode)) {
    input_count += 2;
  } else if (is_add_sub && can_commute &&
             TryMatchAnyExtend(&g, selector, node, right_node, left_node,
                               &inputs[0], &inputs[1], &opcode)) {
    if (must_commute_cond) cont->Commute();
    input_count += 2;
  } else if (TryMatchAnyShift(selector, node, right_node, &opcode, !is_add_sub,
                              Matcher::representation)) {
    Matcher m_shift(right_node);
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(m_shift.left().node());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(static_cast<int>(
        g.GetIntegerConstantValue(m_shift.right().node()) & 0x3F));
  } else if (can_commute &&
             TryMatchAnyShift(selector, node, left_node, &opcode, !is_add_sub,
                              Matcher::representation)) {
    if (must_commute_cond) cont->Commute();
    Matcher m_shift(left_node);
    inputs[input_count++] = g.UseRegisterOrImmediateZero(right_node);
    inputs[input_count++] = g.UseRegister(m_shift.left().node());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(static_cast<int>(
        g.GetIntegerConstantValue(m_shift.right().node()) & 0x3F));
  } else {
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(right_node);
  }

  if (!IsComparisonField::decode(properties)) {
    outputs[output_count++] = g.DefineAsRegister(node);
  }

  if (cont->IsSelect()) {
    // Keep the values live until the end so that we can use operations that
    // write registers to generate the condition, without accidently
    // overwriting the inputs.
    inputs[input_count++] =
        g.UseRegisterAtEndOrImmediateZero(cont->true_value());
    inputs[input_count++] =
        g.UseRegisterAtEndOrImmediateZero(cont->false_value());
  }

  DCHECK_NE(0u, input_count);
  DCHECK((output_count != 0) || IsComparisonField::decode(properties));
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
template <typename Adapter, typename Matcher>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, ArchOpcode opcode,
                ImmediateMode operand_mode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop<Adapter, Matcher>(selector, node, opcode, operand_mode, &cont);
}

void VisitBinopImpl(InstructionSelectorT<TurboshaftAdapter>* selector,
                    turboshaft::OpIndex binop_idx,
                    turboshaft::OpIndex left_node,
                    turboshaft::OpIndex right_node,
                    turboshaft::RegisterRepresentation rep,
                    InstructionCode opcode, ImmediateMode operand_mode,
                    FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  constexpr uint32_t kMaxFlagSetInputs = 3;
  constexpr uint32_t kMaxCcmpOperands =
      FlagsContinuationT<TurboshaftAdapter>::kMaxCompareChainSize *
      kNumCcmpOperands;
  constexpr uint32_t kExtraCcmpInputs = 2;
  constexpr uint32_t kMaxInputs =
      kMaxFlagSetInputs + kMaxCcmpOperands + kExtraCcmpInputs;
  InstructionOperand inputs[kMaxInputs];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  uint8_t properties = GetBinopProperties(opcode);
  bool can_commute = CanCommuteField::decode(properties);
  bool must_commute_cond = MustCommuteCondField::decode(properties);
  bool is_add_sub = IsAddSubField::decode(properties);

  // We've already commuted the flags while searching for the pattern.
  if (cont->IsConditionalSet() || cont->IsConditionalBranch()) {
    can_commute = false;
  }
  if (g.CanBeImmediate(right_node, operand_mode)) {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseImmediate(right_node);
  } else if (can_commute && g.CanBeImmediate(left_node, operand_mode)) {
    if (must_commute_cond) cont->Commute();
    inputs[input_count++] = g.UseRegister(right_node);
    inputs[input_count++] = g.UseImmediate(left_node);
  } else if (is_add_sub &&
             TryMatchAnyExtend(&g, selector, binop_idx, left_node, right_node,
                               &inputs[0], &inputs[1], &opcode)) {
    input_count += 2;
  } else if (is_add_sub && can_commute &&
             TryMatchAnyExtend(&g, selector, binop_idx, right_node, left_node,
                               &inputs[0], &inputs[1], &opcode)) {
    if (must_commute_cond) cont->Commute();
    input_count += 2;
  } else if (TryMatchAnyShift(selector, binop_idx, right_node, &opcode,
                              !is_add_sub, rep)) {
    const ShiftOp& shift = selector->Get(right_node).Cast<ShiftOp>();
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(shift.left());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(
        static_cast<int>(selector->integer_constant(shift.right()) & 0x3F));
  } else if (can_commute && TryMatchAnyShift(selector, binop_idx, left_node,
                                             &opcode, !is_add_sub, rep)) {
    if (must_commute_cond) cont->Commute();
    const ShiftOp& shift = selector->Get(left_node).Cast<ShiftOp>();
    inputs[input_count++] = g.UseRegisterOrImmediateZero(right_node);
    inputs[input_count++] = g.UseRegister(shift.left());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(
        static_cast<int>(selector->integer_constant(shift.right()) & 0x3F));
  } else {
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(right_node);
  }

  if (!IsComparisonField::decode(properties)) {
    outputs[output_count++] = g.DefineAsRegister(binop_idx);
  }

  if (cont->IsSelect()) {
    // Keep the values live until the end so that we can use operations that
    // write registers to generate the condition, without accidently
    // overwriting the inputs.
    inputs[input_count++] = g.UseRegisterAtEnd(cont->true_value());
    inputs[input_count++] = g.UseRegisterAtEnd(cont->false_value());
  } else if (cont->IsConditionalSet() || cont->IsConditionalBranch()) {
    DCHECK_LE(input_count, kMaxInputs);
    auto& compares = cont->compares();
    for (unsigned i = 0; i < cont->num_conditional_compares(); ++i) {
      auto compare = compares[i];
      inputs[input_count + kCcmpOffsetOfOpcode] = g.TempImmediate(compare.code);
      inputs[input_count + kCcmpOffsetOfLhs] = g.UseRegisterAtEnd(compare.lhs);
      if (g.CanBeImmediate(compare.rhs, kConditionalCompareImm)) {
        inputs[input_count + kCcmpOffsetOfRhs] = g.UseImmediate(compare.rhs);
      } else {
        inputs[input_count + kCcmpOffsetOfRhs] =
            g.UseRegisterAtEnd(compare.rhs);
      }
      inputs[input_count + kCcmpOffsetOfDefaultFlags] =
          g.TempImmediate(compare.default_flags);
      inputs[input_count + kCcmpOffsetOfCompareCondition] =
          g.TempImmediate(compare.compare_condition);
      input_count += kNumCcmpOperands;
    }
    inputs[input_count++] = g.TempImmediate(cont->final_condition());
    inputs[input_count++] =
        g.TempImmediate(static_cast<int32_t>(cont->num_conditional_compares()));
  }

  DCHECK_NE(0u, input_count);
  DCHECK((output_count != 0) || IsComparisonField::decode(properties));
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex binop_idx,
                turboshaft::RegisterRepresentation rep, InstructionCode opcode,
                ImmediateMode operand_mode,
                FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& binop = selector->Get(binop_idx);
  OpIndex left_node = binop.input(0);
  OpIndex right_node = binop.input(1);
  return VisitBinopImpl(selector, binop_idx, left_node, right_node, rep, opcode,
                        operand_mode, cont);
}

void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                turboshaft::OpIndex node,
                turboshaft::RegisterRepresentation rep, ArchOpcode opcode,
                ImmediateMode operand_mode) {
  FlagsContinuationT<TurboshaftAdapter> cont;
  VisitBinop(selector, node, rep, opcode, operand_mode, &cont);
}

template <typename Adapter, typename Matcher>
void VisitAddSub(InstructionSelectorT<Adapter>* selector, Node* node,
                 ArchOpcode opcode, ArchOpcode negate_opcode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Matcher m(node);
  if (m.right().HasResolvedValue() && (m.right().ResolvedValue() < 0) &&
      (m.right().ResolvedValue() > std::numeric_limits<int>::min()) &&
      g.CanBeImmediate(-m.right().ResolvedValue(), kArithmeticImm)) {
    selector->Emit(
        negate_opcode, g.DefineAsRegister(node), g.UseRegister(m.left().node()),
        g.TempImmediate(static_cast<int32_t>(-m.right().ResolvedValue())));
  } else {
    VisitBinop<Adapter, Matcher>(selector, node, opcode, kArithmeticImm);
  }
}

std::tuple<turboshaft::OpIndex, turboshaft::OpIndex>
GetBinopLeftRightCstOnTheRight(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    const turboshaft::WordBinopOp& binop) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  OpIndex left = binop.left();
  OpIndex right = binop.right();
  if (!selector->Is<ConstantOp>(right) &&
      WordBinopOp::IsCommutative(binop.kind) &&
      selector->Is<ConstantOp>(left)) {
    std::swap(left, right);
  }
  return {left, right};
}

void VisitAddSub(InstructionSelectorT<TurboshaftAdapter>* selector,
                 turboshaft::OpIndex node, ArchOpcode opcode,
                 ArchOpcode negate_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const WordBinopOp& add_sub = selector->Get(node).Cast<WordBinopOp>();
  auto [left, right] = GetBinopLeftRightCstOnTheRight(selector, add_sub);

  if (std::optional<int64_t> constant_rhs =
          g.GetOptionalIntegerConstant(right)) {
    if (constant_rhs < 0 && constant_rhs > std::numeric_limits<int>::min() &&
        g.CanBeImmediate(-*constant_rhs, kArithmeticImm)) {
      selector->Emit(negate_opcode, g.DefineAsRegister(node),
                     g.UseRegister(left),
                     g.TempImmediate(static_cast<int32_t>(-*constant_rhs)));
      return;
    }
  }
  VisitBinop(selector, node, add_sub.rep, opcode, kArithmeticImm);
}

// For multiplications by immediate of the form x * (2^k + 1), where k > 0,
// return the value of k, otherwise return zero. This is used to reduce the
// multiplication to addition with left shift: x + (x << k).
template <typename Matcher>
int32_t LeftShiftForReducedMultiply(Matcher* m) {
  DCHECK(m->IsInt32Mul() || m->IsInt64Mul());
  if (m->right().HasResolvedValue() && m->right().ResolvedValue() >= 3) {
    uint64_t value_minus_one = m->right().ResolvedValue() - 1;
    if (base::bits::IsPowerOfTwo(value_minus_one)) {
      return base::bits::WhichPowerOfTwo(value_minus_one);
    }
  }
  return 0;
}

// For multiplications by immediate of the form x * (2^k + 1), where k > 0,
// return the value of k, otherwise return zero. This is used to reduce the
// multiplication to addition with left shift: x + (x << k).
int32_t LeftShiftForReducedMultiply(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex rhs) {
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  if (auto constant = g.GetOptionalIntegerConstant(rhs)) {
    int64_t value_minus_one = constant.value() - 1;
    if (base::bits::IsPowerOfTwo(value_minus_one)) {
      return base::bits::WhichPowerOfTwo(value_minus_one);
    }
  }
  return 0;
}

// Try to match Add(Mul(x, y), z) and emit Madd(x, y, z) for it.
template <typename MultiplyOpmaskT>
bool TryEmitMulitplyAdd(InstructionSelectorT<TurboshaftAdapter>* selector,
                        turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                        turboshaft::OpIndex rhs, InstructionCode madd_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& add_lhs = selector->Get(lhs);
  if (!add_lhs.Is<MultiplyOpmaskT>() || !selector->CanCover(add, lhs)) {
    return false;
  }
  // Check that multiply can't be reduced to an addition with shift later on.
  const WordBinopOp& mul = add_lhs.Cast<WordBinopOp>();
  if (LeftShiftForReducedMultiply(selector, mul.right()) != 0) return false;

  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  selector->Emit(madd_opcode, g.DefineAsRegister(add),
                 g.UseRegister(mul.left()), g.UseRegister(mul.right()),
                 g.UseRegister(rhs));
  return true;
}

bool TryEmitMultiplyAddInt32(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                             turboshaft::OpIndex rhs) {
  return TryEmitMulitplyAdd<turboshaft::Opmask::kWord32Mul>(selector, add, lhs,
                                                            rhs, kArm64Madd32);
}

bool TryEmitMultiplyAddInt64(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex add, turboshaft::OpIndex lhs,
                             turboshaft::OpIndex rhs) {
  return TryEmitMulitplyAdd<turboshaft::Opmask::kWord64Mul>(selector, add, lhs,
                                                            rhs, kArm64Madd);
}

// Try to match Mul(Sub(0, x), y) and emit Mneg(x, y) for it.
template <typename SubtractOpmaskT>
bool TryEmitMultiplyNegate(InstructionSelectorT<TurboshaftAdapter>* selector,
                           turboshaft::OpIndex mul, turboshaft::OpIndex lhs,
                           turboshaft::OpIndex rhs,
                           InstructionCode mneg_opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& mul_lhs = selector->Get(lhs);
  if (!mul_lhs.Is<SubtractOpmaskT>() || !selector->CanCover(mul, lhs)) {
    return false;
  }
  const WordBinopOp& sub = mul_lhs.Cast<WordBinopOp>();
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  std::optional<int64_t> sub_lhs_constant =
      g.GetOptionalIntegerConstant(sub.left());
  if (!sub_lhs_constant.has_value() || sub_lhs_constant != 0) return false;
  selector->Emit(mneg_opcode, g.DefineAsRegister(mul),
                 g.UseRegister(sub.right()), g.UseRegister(rhs));
  return true;
}

bool TryEmitMultiplyNegateInt32(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex mul,
    turboshaft::OpIndex lhs, turboshaft::OpIndex rhs) {
  return TryEmitMultiplyNegate<turboshaft::Opmask::kWord32Sub>(
      selector, mul, lhs, rhs, kArm64Mneg32);
}

bool TryEmitMultiplyNegateInt64(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex mul,
    turboshaft::OpIndex lhs, turboshaft::OpIndex rhs) {
  return TryEmitMultiplyNegate<turboshaft::Opmask::kWord64Sub>(
      selector, mul, lhs, rhs, kArm64Mneg);
}

// Try to match Sub(a, Mul(x, y)) and emit Msub(x, y, a) for it.
template <typename MultiplyOpmaskT>
bool TryEmitMultiplySub(InstructionSelectorT<TurboshaftAdapter>* selector,
                        turboshaft::OpIndex node,
                        InstructionCode msub_opbocde) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const WordBinopOp& sub = selector->Get(node).Cast<WordBinopOp>();
  DCHECK_EQ(sub.kind, WordBinopOp::Kind::kSub);

  // Select Msub(x, y, a) for Sub(a, Mul(x, y)).
  const Operation& sub_rhs = selector->Get(sub.right());
  if (sub_rhs.Is<MultiplyOpmaskT>() && selector->CanCover(node, sub.right())) {
    const WordBinopOp& mul = sub_rhs.Cast<WordBinopOp>();
    if (LeftShiftForReducedMultiply(selector, mul.right()) == 0) {
      Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
      selector->Emit(msub_opbocde, g.DefineAsRegister(node),
                     g.UseRegister(mul.left()), g.UseRegister(mul.right()),
                     g.UseRegister(sub.left()));
      return true;
    }
  }
  return false;
}

std::tuple<InstructionCode, ImmediateMode> GetStoreOpcodeAndImmediate(
    turboshaft::MemoryRepresentation stored_rep, bool paired) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      CHECK(!paired);
      return {kArm64Strb, kLoadStoreImm8};
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      CHECK(!paired);
      return {kArm64Strh, kLoadStoreImm16};
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return {paired ? kArm64StrWPair : kArm64StrW, kLoadStoreImm32};
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return {paired ? kArm64StrPair : kArm64Str, kLoadStoreImm64};
    case MemoryRepresentation::Float16():
      CHECK(!paired);
      return {kArm64StrH, kLoadStoreImm16};
    case MemoryRepresentation::Float32():
      CHECK(!paired);
      return {kArm64StrS, kLoadStoreImm32};
    case MemoryRepresentation::Float64():
      CHECK(!paired);
      return {kArm64StrD, kLoadStoreImm64};
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      if (paired) {
        // There is an inconsistency here on how we treat stores vs. paired
        // stores. In the normal store case we have special opcodes for
        // compressed fields and the backend decides whether to write 32 or 64
        // bits. However, for pairs this does not make sense, since the
        // paired values could have different representations (e.g.,
        // compressed paired with word32). Therefore, we decide on the actual
        // machine representation already in instruction selection.
#ifdef V8_COMPRESS_POINTERS
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 2);
        return {kArm64StrWPair, kLoadStoreImm32};
#else
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 3);
        return {kArm64StrPair, kLoadStoreImm64};
#endif
      }
      return {kArm64StrCompressTagged,
              COMPRESS_POINTERS_BOOL ? kLoadStoreImm32 : kLoadStoreImm64};
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      CHECK(!paired);
      return {kArm64Str, kLoadStoreImm64};
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return {kArm64StrIndirectPointer, kLoadStoreImm32};
    case MemoryRepresentation::SandboxedPointer():
      CHECK(!paired);
      return {kArm64StrEncodeSandboxedPointer, kLoadStoreImm64};
    case MemoryRepresentation::Simd128():
      CHECK(!paired);
      return {kArm64StrQ, kNoImmediate};
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

std::tuple<InstructionCode, ImmediateMode> GetStoreOpcodeAndImmediate(
    MachineRepresentation rep, bool paired) {
  InstructionCode opcode = kArchNop;
  ImmediateMode immediate_mode = kNoImmediate;
  switch (rep) {
    case MachineRepresentation::kFloat16:
      CHECK(!paired);
      opcode = kArm64StrH;
      immediate_mode = kLoadStoreImm16;
      break;
    case MachineRepresentation::kFloat32:
      CHECK(!paired);
      opcode = kArm64StrS;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kFloat64:
      CHECK(!paired);
      opcode = kArm64StrD;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      CHECK(!paired);
      opcode = kArm64Strb;
      immediate_mode = kLoadStoreImm8;
      break;
    case MachineRepresentation::kWord16:
      CHECK(!paired);
      opcode = kArm64Strh;
      immediate_mode = kLoadStoreImm16;
      break;
    case MachineRepresentation::kWord32:
      opcode = paired ? kArm64StrWPair : kArm64StrW;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      opcode = paired ? kArm64StrWPair : kArm64StrCompressTagged;
      immediate_mode = kLoadStoreImm32;
      break;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      if (paired) {
        // There is an inconsistency here on how we treat stores vs. paired
        // stores. In the normal store case we have special opcodes for
        // compressed fields and the backend decides whether to write 32 or 64
        // bits. However, for pairs this does not make sense, since the
        // paired values could have different representations (e.g.,
        // compressed paired with word32). Therefore, we decide on the actual
        // machine representation already in instruction selection.
#ifdef V8_COMPRESS_POINTERS
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 2);
        opcode = kArm64StrWPair;
#else
        static_assert(ElementSizeLog2Of(MachineRepresentation::kTagged) == 3);
        opcode = kArm64StrPair;
#endif
      } else {
        opcode = kArm64StrCompressTagged;
      }
      immediate_mode =
          COMPRESS_POINTERS_BOOL ? kLoadStoreImm32 : kLoadStoreImm64;
      break;
    case MachineRepresentation::kIndirectPointer:
      opcode = kArm64StrIndirectPointer;
      immediate_mode = kLoadStoreImm32;
      break;
    case MachineRepresentation::kSandboxedPointer:
      CHECK(!paired);
      opcode = kArm64StrEncodeSandboxedPointer;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kWord64:
      opcode = paired ? kArm64StrPair : kArm64Str;
      immediate_mode = kLoadStoreImm64;
      break;
    case MachineRepresentation::kSimd128:
      CHECK(!paired);
      opcode = kArm64StrQ;
      immediate_mode = kNoImmediate;
      break;
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
  return std::tuple{opcode, immediate_mode};
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTraceInstruction(node_t node) {}

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
  Arm64OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), x1));
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              ImmediateMode immediate_mode, MachineRepresentation rep,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand outputs[1];

  // If output is not nullptr, use that as the output register. This
  // is used when we merge a conversion into the load.
  outputs[0] = g.DefineAsRegister(output == nullptr ? node : output);

  ExternalReferenceMatcher m(base);
  if (m.HasResolvedValue() && g.IsIntegerConstant(index) &&
      selector->CanAddressRelativeToRootsRegister(m.ResolvedValue())) {
    ptrdiff_t const delta =
        g.GetIntegerConstantValue(index) +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            selector->isolate(), m.ResolvedValue());
    input_count = 1;
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
      return;
    }
  }

  if (base->opcode() == IrOpcode::kLoadRootRegister) {
    input_count = 1;
    inputs[0] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
    return;
  }

  inputs[0] = g.UseRegister(base);

  if (g.CanBeImmediate(index, immediate_mode)) {
    input_count = 2;
    inputs[1] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_MRI);
  } else if (TryMatchLoadStoreShift(&g, selector, rep, node, index, &inputs[1],
                                    &inputs[2])) {
    input_count = 3;
    opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
  } else {
    input_count = 2;
    inputs[1] = g.UseRegister(index);
    opcode |= AddressingModeField::encode(kMode_MRR);
  }

  selector->Emit(opcode, arraysize(outputs), outputs, input_count, inputs);
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              ImmediateMode immediate_mode, MachineRepresentation rep,
              typename TurboshaftAdapter::node_t output) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);
  const LoadOp& load = selector->Get(node).Cast<LoadOp>();

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

  inputs[0] = g.UseRegister(base);

  if (selector->is_integer_constant(index)) {
    int64_t offset = selector->integer_constant(index);
    if (g.CanBeImmediate(offset, immediate_mode)) {
      input_count = 2;
      inputs[1] = g.UseImmediate64(offset);
      opcode |= AddressingModeField::encode(kMode_MRI);
    } else {
      input_count = 2;
      inputs[1] = g.UseRegister(index);
      opcode |= AddressingModeField::encode(kMode_MRR);
    }
  } else {
    if (TryMatchLoadStoreShift(&g, selector, rep, node, index, &inputs[1],
                               &inputs[2])) {
      input_count = 3;
      opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
    } else {
      input_count = 2;
      inputs[1] = g.UseRegister(index);
      opcode |= AddressingModeField::encode(kMode_MRR);
    }
  }
  selector->Emit(opcode, 1, &output_op, input_count, inputs);
}

namespace {
// Manually add base and index into a register to get the actual address.
// This should be used prior to instructions that only support
// immediate/post-index addressing, like ld1 and st1.
template <typename Adapter>
InstructionOperand EmitAddBeforeLoadOrStore(
    InstructionSelectorT<Adapter>* selector, typename Adapter::node_t node,
    InstructionCode* opcode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand addr = g.TempRegister();
  selector->Emit(kArm64Add, addr, g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
  *opcode |= AddressingModeField::encode(kMode_MRI);
  return addr;
}
}  // namespace

#if V8_ENABLE_WEBASSEMBLY
template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArm64LoadLane;
  opcode |= LaneSizeField::encode(load.lane_size() * kBitsPerByte);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(input_at(node, 2)),
       g.UseImmediate(load.lane), addr, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  DCHECK(
      params.rep == MachineType::Int8() || params.rep == MachineType::Int16() ||
      params.rep == MachineType::Int32() || params.rep == MachineType::Int64());

  InstructionCode opcode = kArm64LoadLane;
  opcode |= LaneSizeField::encode(params.rep.MemSize() * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(params.laneidx), addr, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kArm64StoreLane;
  opcode |= LaneSizeField::encode(store.lane_size() * kBitsPerByte);
  if (store.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  InstructionOperand inputs[4] = {
      g.UseRegister(input_at(node, 2)),
      g.UseImmediate(store.lane),
      addr,
      g.TempImmediate(0),
  };

  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  DCHECK_LE(MachineRepresentation::kWord8, params.rep);
  DCHECK_GE(MachineRepresentation::kWord64, params.rep);

  InstructionCode opcode = kArm64StoreLane;
  opcode |=
      LaneSizeField::encode(ElementSizeInBytes(params.rep) * kBitsPerByte);
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  Arm64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeLoadOrStore(this, node, &opcode);
  InstructionOperand inputs[4] = {
      g.UseRegister(node->InputAt(2)),
      g.UseImmediate(params.laneidx),
      addr,
      g.TempImmediate(0),
  };

  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  InstructionCode opcode = kArchNop;
  bool require_add = false;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(8);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(16);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(32);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kArm64LoadSplat;
      opcode |= LaneSizeField::encode(64);
      require_add = true;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kArm64S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kArm64S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kArm64S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kArm64S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kArm64S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kArm64S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kArm64LdrS;
      break;
    case Simd1
```