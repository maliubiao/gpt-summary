Response: The user wants a summary of the functionality of the C++ source code file `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc`.
This file seems to be part of the V8 JavaScript engine, specifically for the LoongArch64 architecture.
It appears to be responsible for selecting machine instructions based on the intermediate representation (IR) of the JavaScript code.

The code defines a class `Loong64OperandGeneratorT` to generate operands for the instructions.
It also defines several template functions `Visit...` which seem to handle the selection of instructions for different IR nodes (operations).

Key functionalities observed:
- **Operand Generation:**  Creating operands (registers, immediates, memory addresses) for LoongArch64 instructions.
- **Instruction Selection:** Choosing the appropriate LoongArch64 instructions for different high-level operations (like addition, subtraction, loads, stores, shifts, bitwise operations).
- **Architecture-Specific Optimizations:** Implementing optimizations specific to the LoongArch64 architecture.
- **Interaction with Turbofan/Turboshaft:**  The code supports both Turbofan and the newer Turboshaft compiler pipelines within V8.
- **Handling of Constants:**  Efficiently handling constant values, potentially embedding them as immediate operands.
- **Memory Access:** Generating instructions for loading and storing data from memory, including handling tagged values and write barriers.
- **SIMD Support:**  Initial signs of support for SIMD instructions.

To illustrate the relationship with JavaScript, I need to find a function or operation that is clearly related to a JavaScript concept. Arithmetic operations are a good candidate.

Example:  The `VisitInt32Add` function seems to be responsible for selecting the LoongArch64 instruction for adding two 32-bit integers.
This C++ source code file, `instruction-selector-loong64.cc`, is a crucial part of the V8 JavaScript engine's compiler for the LoongArch64 architecture. Its primary function is **instruction selection**, which is the process of translating high-level intermediate representation (IR) operations into specific low-level machine instructions that the LoongArch64 processor can execute.

Here's a breakdown of its key functionalities as seen in this first part of the file:

1. **Operand Generation:** It defines a class `Loong64OperandGeneratorT` that assists in creating the operands (registers, immediate values, memory addresses) needed by the LoongArch64 instructions. It handles different operand types and ensures they are compatible with the target instruction.

2. **Instruction Selection for Various Operations:** The code contains numerous template functions named `VisitRR`, `VisitRRI`, `VisitRRR`, `VisitBinop`, `EmitLoad`, `EmitStore`, etc. These functions are responsible for examining specific IR nodes (representing operations like addition, subtraction, loading, storing, bitwise operations, shifts) and selecting the most appropriate LoongArch64 instruction(s) to perform that operation.

3. **LoongArch64 Specific Optimizations:** The code implements optimizations tailored for the LoongArch64 architecture. For example, in the `VisitWord32And` and `VisitWord64And` functions, it looks for specific patterns (like masking after a shift) that can be implemented more efficiently using instructions like `Bstrpick_w` and `Bstrins_w`.

4. **Support for Different Compiler Pipelines (Turbofan/Turboshaft):** The code utilizes C++ templates and `if constexpr` to handle both the older Turbofan and the newer Turboshaft compiler pipelines within V8. This allows for different implementation strategies or access to different information depending on the active pipeline.

5. **Handling of Constants:** The code has logic to identify constant values in the IR and potentially use them as immediate operands in the generated instructions. This is often more efficient than loading the constant from memory.

6. **Memory Access (Loads and Stores):** The `EmitLoad` and `VisitStore` functions handle the generation of load and store instructions. This includes calculating memory addresses, handling different data sizes, and managing write barriers for garbage collection (ensuring that the garbage collector is aware of pointer updates).

7. **Write Barriers:** The `VisitStore` function demonstrates the handling of write barriers, which are essential for maintaining the integrity of the garbage-collected heap in JavaScript. When a pointer in the heap is modified, a write barrier ensures that the garbage collector is notified.

8. **Stack Slots:** The `VisitStackSlot` function deals with allocating and accessing variables on the stack.

9. **Immediate Value Handling:** The code has helper functions like `CanBeImmediate` to determine if a constant value can be directly embedded as an immediate operand in an instruction, which is a performance optimization.

Regarding the relationship with JavaScript, this code directly translates JavaScript's behavior into machine code. For example, a simple JavaScript addition operation will eventually be processed by functions like `VisitInt32Add` or `VisitInt64Add` in this file.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

When the V8 engine compiles this JavaScript code for the LoongArch64 architecture:

- The `+` operator in the `add` function will be represented as an IR node (likely an `Int32Add` or `Int64Add` node depending on the types of `a` and `b`).
- The `instruction-selector-loong64.cc` file's `VisitInt32Add` or `VisitInt64Add` function will be invoked for this IR node.
- Based on the types of `a` and `b`, and potential constant values, the `Visit...` function will select the appropriate LoongArch64 addition instruction (e.g., `ADD_W` for 32-bit integers, `ADD_D` for 64-bit integers).
- The `Loong64OperandGeneratorT` will generate the operands for the instruction, potentially using registers to hold the values of `a` and `b`, or embedding the constants `5` and `10` as immediate values if the compiler deems it efficient.

In essence, this C++ file is a translator, converting the abstract operations of JavaScript into the concrete instructions that the LoongArch64 hardware understands. It's a crucial link in the chain that allows JavaScript code to run efficiently on this specific processor architecture.

### 提示词
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds loong64-specific methods for generating InstructionOperands.
template <typename Adapter>
class Loong64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit Loong64OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(typename Adapter::node_t node,
                                InstructionCode opcode) {
    if (CanBeImmediate(node, opcode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register.
  InstructionOperand UseRegisterOrImmediateZero(typename Adapter::node_t node) {
    if (this->is_constant(node)) {
      auto constant = selector()->constant_view(node);
      if ((IsIntegerConstant(constant) &&
           GetIntegerConstantValue(constant) == 0) ||
          constant.is_float_zero()) {
        return UseImmediate(node);
      }
    }
    return UseRegister(node);
  }

  MachineRepresentation GetRepresentation(Node* node) {
    return this->sequence()->GetRepresentation(
        selector()->GetVirtualRegister(node));
  }

  bool IsIntegerConstant(node_t node) {
    return selector()->is_integer_constant(node);
  }

  int64_t GetIntegerConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kInt32Constant) {
      return OpParameter<int32_t>(node->op());
    }
    DCHECK_EQ(IrOpcode::kInt64Constant, node->opcode());
    return OpParameter<int64_t>(node->op());
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

  bool CanBeImmediate(node_t node, InstructionCode mode) {
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

  bool CanBeImmediate(int64_t value, InstructionCode opcode) {
    switch (ArchOpcodeField::decode(opcode)) {
      case kLoong64Cmp32:
      case kLoong64Cmp64:
        return true;
      case kLoong64Sll_w:
      case kLoong64Srl_w:
      case kLoong64Sra_w:
        return is_uint5(value);
      case kLoong64Sll_d:
      case kLoong64Srl_d:
      case kLoong64Sra_d:
        return is_uint6(value);
      case kLoong64And:
      case kLoong64And32:
      case kLoong64Or:
      case kLoong64Or32:
      case kLoong64Xor:
      case kLoong64Xor32:
      case kLoong64Tst:
        return is_uint12(value);
      case kLoong64Ld_w:
      case kLoong64St_w:
      case kLoong64Ld_d:
      case kLoong64St_d:
      case kAtomicLoadWord32:
      case kAtomicStoreWord32:
      case kLoong64Word64AtomicLoadUint64:
      case kLoong64Word64AtomicStoreWord64:
      case kLoong64StoreCompressTagged:
        return (is_int12(value) || (is_int16(value) && ((value & 0b11) == 0)));
      default:
        return is_int12(value);
    }
  }

 private:
  bool ImmediateFitsAddrMode1Instruction(int32_t imm) const {
    TRACE("UNIMPLEMENTED instr_sel: %s at line %d\n", __FUNCTION__, __LINE__);
    return false;
  }
};

template <typename Adapter>
static void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                    typename Adapter::node_t node) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
static void VisitRRI(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm));
  }
}

template <typename Adapter>
static void VisitSimdShift(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    if (g.IsIntegerConstant(node->InputAt(1))) {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(node->InputAt(0)),
                     g.UseImmediate(node->InputAt(1)));
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(node->InputAt(0)),
                     g.UseRegister(node->InputAt(1)));
    }
  }
}

template <typename Adapter>
static void VisitRRIR(InstructionSelectorT<Adapter>* selector,
                      ArchOpcode opcode, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm),
                   g.UseRegister(node->InputAt(1)));
  }
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              typename Adapter::node_t node) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
static void VisitUniqueRRR(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseUniqueRegister(selector->input_at(node, 0)),
                 g.UseUniqueRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitRRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
               typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Loong64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(
        opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
        g.UseRegister(node->InputAt(1)), g.UseRegister(node->InputAt(2)));
  }
}

template <typename Adapter>
static void VisitRRO(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
    Loong64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseOperand(selector->input_at(node, 1), opcode));
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

      Loong64OperandGeneratorT<Adapter> g(selector_);
      Node* load = m.left().node();
      Node* offset = load->InputAt(1);
      base_ = load->InputAt(0);
      opcode_ = kLoong64Ld_w;
      if (g.CanBeImmediate(offset, opcode_)) {
        immediate_ = g.GetIntegerConstantValue(offset) + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoong64Ld_w);
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
      Loong64OperandGeneratorT<Adapter> g(selector_);

      const LoadOp& load = lhs.Cast<LoadOp>();
      base_ = load.base();
      opcode_ = kLoong64Ld_w;
      if (load.index().has_value()) {
        int64_t index_constant;
        if (selector_->MatchIntegralWord64Constant(load.index().value(),
                                                   &index_constant)) {
          DCHECK_EQ(load.element_size_log2, 0);
          immediate_ = index_constant + 4;
          matches_ = g.CanBeImmediate(immediate_, kLoong64Ld_w);
        }
      } else {
        immediate_ = load.offset + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoong64Ld_w);
      }
    }
  }
};

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          typename Adapter::node_t output_node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  Loong64OperandGeneratorT<Adapter> g(selector);
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
bool TryMatchImmediate(InstructionSelectorT<Adapter>* selector,
                       InstructionCode* opcode_return,
                       typename Adapter::node_t node,
                       size_t* input_count_return, InstructionOperand* inputs) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  if (g.CanBeImmediate(node, *opcode_return)) {
    *opcode_return |= AddressingModeField::encode(kMode_MRI);
    inputs[0] = g.UseImmediate(node);
    *input_count_return = 1;
    return true;
  }
  return false;
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Loong64OperandGeneratorT<TurboshaftAdapter> g(selector);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  const Operation& binop = selector->Get(node);
  OpIndex left_node = binop.input(0);
  OpIndex right_node = binop.input(1);

  if (TryMatchImmediate(selector, &opcode, right_node, &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegister(left_node);
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, left_node,
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegister(right_node);
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseOperand(right_node, opcode);
  }

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<TurboshaftAdapter> cont;
  VisitBinop(selector, node, opcode, has_reverse_opcode, reverse_opcode, &cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  VisitBinop(selector, node, opcode, false, kArchNop, cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode) {
  VisitBinop(selector, node, opcode, false, kArchNop);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<Adapter>* cont) {
  Loong64OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  if (TryMatchImmediate(selector, &opcode, m.right().node(), &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegister(m.left().node());
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, m.left().node(),
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegister(m.right().node());
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(m.left().node());
    inputs[input_count++] = g.UseOperand(m.right().node(), opcode);
  }

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, has_reverse_opcode, reverse_opcode, &cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode,
                       FlagsContinuationT<Adapter>* cont) {
  VisitBinop(selector, node, opcode, false, kArchNop, cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode) {
  VisitBinop(selector, node, opcode, false, kArchNop);
}

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
  Loong64OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), a0));
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  Loong64OperandGeneratorT<Adapter> g(selector);
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
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   g.UseRegister(base), g.UseRegister(index));
  }
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              typename TurboshaftAdapter::node_t output) {
  Loong64OperandGeneratorT<TurboshaftAdapter> g(selector);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(node);
  const LoadOp& load = op.Cast<LoadOp>();

  // The LoadStoreSimplificationReducer transforms all loads into
  // *(base + index).
  OpIndex base = load.base();
  OpIndex index = load.index().value();
  CHECK_EQ(load.offset, 0);
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
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                   g.DefineAsRegister(output.valid() ? output : node),
                   g.UseRegister(base), g.UseRegister(index));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());

  InstructionCode opcode = kArchNop;
  switch (params.transformation) {
      // TODO(LOONG_dev): LOONG64 S128 LoadSplat
    case LoadTransformation::kS128Load8Splat:
      opcode = kLoong64S128LoadSplat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kLoong64S128LoadSplat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kLoong64S128LoadSplat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kLoong64S128LoadSplat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kLoong64S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kLoong64S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kLoong64S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kLoong64S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kLoong64S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kLoong64S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kLoong64S128Load32Zero;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kLoong64S128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }
  if (params.kind == MemoryAccessKind::kProtectedByTrapHandler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  EmitLoad(this, node, opcode);
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
      return kLoong64Ld_b;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kLoong64Ld_bu;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kLoong64Ld_h;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kLoong64Ld_hu;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kLoong64Ld_w;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      return kLoong64Ld_d;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kLoong64Fld_s;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kLoong64Fld_d;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kLoong64Ld_wu;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kLoong64LoadDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        return kLoong64Ld_wu;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kLoong64LoadDecompressTaggedSigned;
#else
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kLoong64Ld_d;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kLoong64Ld_d;
    case MemoryRepresentation::ProtectedPointer():
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return kLoong64LoadDecompressProtected;
    case MemoryRepresentation::IndirectPointer():
      UNREACHABLE();
    case MemoryRepresentation::SandboxedPointer():
      return kLoong64LoadDecodeSandboxedPointer;
    case MemoryRepresentation::Simd128():  // Fall through.
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode GetLoadOpcode(LoadRepresentation load_rep) {
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      return kLoong64Fld_s;
    case MachineRepresentation::kFloat64:
      return kLoong64Fld_d;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return load_rep.IsUnsigned() ? kLoong64Ld_bu : kLoong64Ld_b;
    case MachineRepresentation::kWord16:
      return load_rep.IsUnsigned() ? kLoong64Ld_hu : kLoong64Ld_h;
    case MachineRepresentation::kWord32:
      return kLoong64Ld_w;
#ifdef V8_COMPRESS_POINTERS
    case MachineRepresentation::kTaggedSigned:
      return kLoong64LoadDecompressTaggedSigned;
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return kLoong64LoadDecompressTagged;
#else
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
#endif
    case MachineRepresentation::kWord64:
      return kLoong64Ld_d;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kLoong64Ld_wu;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kProtectedPointer:
      CHECK(V8_ENABLE_SANDBOX_BOOL);
      return kLoong64LoadDecompressProtected;
    case MachineRepresentation::kSandboxedPointer:
      return kLoong64LoadDecodeSandboxedPointer;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kMapWord:          // Fall through.
    case MachineRepresentation::kIndirectPointer:  // Fall through.
    case MachineRepresentation::kNone:             // Fall through.
    case MachineRepresentation::kSimd128:          // Fall through.
    case MachineRepresentation::kSimd256:
      UNREACHABLE();
  }
}

ArchOpcode GetStoreOpcode(turboshaft::MemoryRepresentation stored_rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (stored_rep) {
    case MemoryRepresentation::Int8():
    case MemoryRepresentation::Uint8():
      return kLoong64St_b;
    case MemoryRepresentation::Int16():
    case MemoryRepresentation::Uint16():
      return kLoong64St_h;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      return kLoong64St_w;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      return kLoong64St_d;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      return kLoong64Fst_s;
    case MemoryRepresentation::Float64():
      return kLoong64Fst_d;
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      return kLoong64StoreCompressTagged;
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      return kLoong64St_d;
    case MemoryRepresentation::ProtectedPointer():
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
    case MemoryRepresentation::IndirectPointer():
      return kLoong64StoreIndirectPointer;
    case MemoryRepresentation::SandboxedPointer():
      return kLoong64StoreEncodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kLoong64Fst_s;
    case MachineRepresentation::kFloat64:
      return kLoong64Fst_d;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      return kLoong64St_b;
    case MachineRepresentation::kWord16:
      return kLoong64St_h;
    case MachineRepresentation::kWord32:
      return kLoong64St_w;
    case MachineRepresentation::kWord64:
      return kLoong64St_d;
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return kLoong64StoreCompressTagged;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kLoong64StoreCompressTagged;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kSandboxedPointer:
      return kLoong64StoreEncodeSandboxedPointer;
    case MachineRepresentation::kIndirectPointer:
      return kLoong64StoreIndirectPointer;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kNone:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  {
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
        opcode |=
            AccessModeField::encode(kMemoryAccessProtectedNullDereference);
      } else {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
    }

    EmitLoad(this, node, opcode);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  VisitLoad(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  const MachineRepresentation rep = store_view.stored_rep().representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  // TODO(loong64): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the index in an arithmetic instruction, so we
    // must check kArithmeticImm as well as kLoadStoreImm64.
    if (g.CanBeImmediate(index, kLoong64Add_d)) {
      inputs[input_count++] = g.UseImmediate(index);
      addressing_mode = kMode_MRI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(index);
      addressing_mode = kMode_MRR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
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
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    if (store_view.is_store_trap_on_null()) {
      code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    }
    Emit(code, 0, nullptr, input_count, inputs);
    return;
  }

  MachineRepresentation approx_rep = rep;
  InstructionCode code;
  if constexpr (Adapter::IsTurboshaft) {
    code = GetStoreOpcode(store_view.ts_stored_rep());
  } else {
    code = GetStoreOpcode(approx_rep);
  }

  std::optional<ExternalReference> external_base;
  if constexpr (Adapter::IsTurboshaft) {
    ExternalReference value;
    if (this->MatchExternalConstant(base, &value)) {
      external_base = value;
    }
  } else {
    ExternalReferenceMatcher m(base);
    if (m.HasResolvedValue()) {
      external_base = m.ResolvedValue();
    }
  }

  std::optional<int64_t> constant_index;
  if (this->valid(store_view.index())) {
    node_t index = this->value(store_view.index());
    constant_index = g.GetOptionalIntegerConstant(index);
  }
  if (external_base.has_value() && constant_index.has_value() &&
      CanAddressRelativeToRootsRegister(*external_base)) {
    ptrdiff_t const delta =
        *constant_index +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            isolate(), *external_base);
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseImmediate(static_cast<int32_t>(delta)),
           g.UseRegisterOrImmediateZero(value));
      return;
    }
  }

  if (this->is_load_root_register(base)) {
    // This will only work if {index} is a constant.
    Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
         g.UseImmediate(index), g.UseRegisterOrImmediateZero(value));
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
         g.UseRegister(base), g.UseImmediate(index),
         g.UseRegisterOrImmediateZero(value));
  } else {
    Emit(code | AddressingModeField::encode(kMode_MRR), g.NoOutput(),
         g.UseRegister(base), g.UseRegister(index),
         g.UseRegisterOrImmediateZero(value));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  VisitStore(node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64And32, true, kLoong64And32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32And(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.left().IsWord32Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Bstrpick_w for And(Shr(x, imm), mask) where the mask is in the
      // least significant bits.
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = mleft.right().ResolvedValue() & 0x1F;

        // Bstrpick_w cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use Bstrpick_w with a smaller mask and the remaining bits will
        // be zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kLoong64Bstrpick_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  if (m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t shift = base::bits::CountPopulation(~mask);
    uint32_t msb = base::bits::CountLeadingZeros32(~mask);
    if (shift != 0 && shift != 32 && msb + shift == 32) {
      // Insert zeros for (x >> K) << K => x & ~(2^K - 1) expression reduction
      // and remove constant loading of inverted mask.
      Emit(kLoong64Bstrins_w, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0),
           g.TempImmediate(shift));
      return;
    }
  }
  VisitBinop(this, node, kLoong64And32, true, kLoong64And32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64And, true, kLoong64And);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64And(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.left().IsWord64Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Bstrpick_d for And(Shr(x, imm), mask) where the mask is in the
      // least significant bits.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb =
            static_cast<uint32_t>(mleft.right().ResolvedValue() & 0x3F);

        // Bstrpick_d cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use Bstrpick_d with a smaller mask and the remaining bits will
        // be zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        if (lsb == 0 && mask_width == 64) {
          Emit(kArchNop, g.DefineSameAsFirst(node), g.Use(mleft.left().node()));
        } else {
          Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
               g.TempImmediate(static_cast<int32_t>(mask_width)));
        }
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  if (m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint32_t shift = base::bits::CountPopulation(~mask);
    uint32_t msb = base::bits::CountLeadingZeros64(~mask);
    if (shift != 0 && shift < 32 && msb + shift == 64) {
      // Insert zeros for (x >> K) << K => x & ~(2^K - 1) expression reduction
      // and remove constant loading of inverted mask. Dins cannot insert bits
      // past word size, so shifts smaller than 32 are covered.
      Emit(kLoong64Bstrins_d, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0),
           g.TempImmediate(shift));
      return;
    }
  }
  VisitBinop(this, node, kLoong64And, true, kLoong64And);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kLoong64Or32, true, kLoong64Or32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  VisitBinop(this, node, kLoong64Or, true, kLoong64Or);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Xor32, true, kLoong64Xor32);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32Or() && CanCover(node, m.left().node()) &&
        m.right().Is(-1)) {
      Int32BinopMatcher mleft(m.left().node());
      if (!mleft.right().HasResolvedValue()) {
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Nor32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()));
        return;
      }
    }
    if (m.right().Is(-1)) {
      // Use Nor for bit negation and eliminate constant loading for xori.
      Loong64OperandGeneratorT<Adapter> g(this);
      Emit(kLoong64Nor32, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0));
      return;
    }
    VisitBinop(this, node, kLoong64Xor32, true, kLoong64Xor32);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Xor, true, kLoong64Xor);
  } else {
    Int64BinopMatcher m(node);
    if (m.left().IsWord64Or() && CanCover(node, m.left().node()) &&
        m.right().Is(-1)) {
      Int64BinopMatcher mleft(m.left().node());
      if (!mleft.right().HasResolvedValue()) {
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Nor, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()));
        return;
      }
    }
    if (m.right().Is(-1)) {
      // Use Nor for bit negation and eliminate constant loading for xori.
      Loong64OperandGeneratorT<Adapter> g(this);
      Emit(kLoong64Nor, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0));
      return;
    }
    VisitBinop(this, node, kLoong64Xor, true, kLoong64Xor);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shl(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Sll_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shl(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && CanCover(node, m.left().node()) &&
      m.right().IsInRange(1, 31)) {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    Int32BinopMatcher mleft(m.left().node());
    // Match Word32Shl(Word32And(x, mask), imm) to Sll_w where the mask is
    // contiguous, and the shift immediate non-zero.
    if (mleft.right().HasResolvedValue()) {
      uint32_t mask = mleft.right().ResolvedValue();
      uint32_t mask_width = base::bits::CountPopulation(mask);
      uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
        uint32_t shift = m.right().ResolvedValue();
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
        DCHECK_NE(0u, shift);
        if ((shift + mask_width) >= 32) {
          // If the mask is contiguous and reaches or extends beyond the top
          // bit, only the shift is needed.
          Emit(kLoong64Sll_w, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()));
          return;
        }
      }
    }
  }
  VisitRRO(this, kLoong64Sll_w, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shr(node_t node) {
  VisitRRO(this, kLoong64Srl_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shr(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x1F;
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Bstrpick_w for Shr(And(x, mask), imm) where the result of the
      // mask is shifted into the least-significant bits.
      uint32_t mask = (mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Loong64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kLoong64Bstrpick_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kLoong64Srl_w, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Sar(
    turboshaft::OpIndex node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Sra_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Sar(Node* node) {
  Int32BinopMatcher m(node);
  if (CanCover(node, m.left().node())) {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    if (m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (m.right().HasResolvedValue() && mleft.right().HasResolvedValue()) {
        uint32_t sar = m.right().ResolvedValue();
        uint32_t shl = mleft.right().ResolvedValue();
        if ((sar == shl) && (sar == 16)) {
          Emit(kLoong64Ext_w_h, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 24)) {
          Emit(kLoong64Ext_w_b, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 32)) {
          Emit(kLoong64Sll_w, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        }
      }
    } else if (m.left().IsTruncateInt64ToInt32()) {
      Emit(kLoong64Sra_w, g.DefineAsRegister(node),
           g.UseRegister(m.left().InputAt(0)),
           g.UseOperand(node->InputAt(1), kLoong64Sra_w));
      return;
    }
  }
  VisitRRO(this, kLoong64Sra_w, node);
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
        Loong64OperandGeneratorT<Adapter> g(this);
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kLoong64Sll_d, g.DefineAsRegister(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate(shift_by));
        return;
      }
    }
    VisitRRO(this, kLoong64Sll_d, node);
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kLoong64Sll_d, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    if (m.left().IsWord64And() && CanCover(node, m.left().node()) &&
        m.right().IsInRange(1, 63)) {
      // Match Word64Shl(Word64And(x, mask), imm) to Sll_d where the mask is
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
            Emit(kLoong64Sll_d, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
      }
    }
    VisitRRO(this, kLoong64Sll_d, node);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Srl_d, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Shr(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().IsWord64And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x3F;
    Int64BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Bstrpick_d for Shr(And(x, mask), imm) where the result of the
      // mask is shifted into the least-significant bits.
      uint64_t mask = (mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Loong64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kLoong64Srl_d, node);
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
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Sra_w, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()));
        return;
      }
    }

    VisitRRO(this, kLoong64Sra_d, node);
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
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kLoong64Sra_w, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right));
      return;
    }
  }

  VisitRRO(this, kLoong64Sra_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitRRO(this, kLoong64Rotr_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
  VisitRRO(this, kLoong64Rotr_d, node);
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
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  VisitRR(this, kLoong64ByteSwap32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  VisitRR(this, kLoong64ByteSwap64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Clz(node_t node) {
  VisitRR(this, kLoong64Clz_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
  VisitRR(this, kLoong64Clz_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Add_w, true, kLoong64Add_w);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);

  // Select Alsl_w for (left + (left_of_right << imm)).
  if (m.right().opcode() == IrOpcode::kWord32Shl &&
      CanCover(node, m.left().node()) && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    if (mright.right().HasResolvedValue() && !m.left().HasResolvedValue()) {
      int32_t shift_value =
          static_cast<int32_t>(mright.right().ResolvedValue());
      if (shift_value > 0 && shift_value <= 31) {
        Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(m.left().node()), g.TempImmediate(shift_value));
        return;
      }
    }
  }

  // Select Alsl_w for ((left_of_left << imm) + right).
  if (m.left().opcode() == IrOpcode::kWord32Shl &&
      CanCover(node, m.right().node()) && CanCover(node, m.left().node())) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() && !m.right().HasResolvedValue()) {
      int32_t shift_value = static_cast<int32_t>(mleft.right().ResolvedValue());
      if (shift_value > 0 && shift_value <= 31) {
        Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(m.right().node()), g.TempImmediate(shift_value));
        return;
      }
    }
  }

  VisitBinop(this, node, kLoong64Add_w, true, kLoong64Add_w);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Add_d, true, kLoong64Add_d);
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);

    // Select Alsl_d for (left + (left_of_right << imm)).
    if (m.right().opcode() == IrOpcode::kWord64Shl &&
        CanCover(node, m.left().node()) && CanCover(node, m.right().node())) {
      Int64BinopMatcher mright(m.right().node());
      if (mright.right().HasResolvedValue() && !m.left().HasResolvedValue()) {
        int32_t shift_value =
            static_cast<int32_t>(mright.right().ResolvedValue());
        if (shift_value > 0 && shift_value <= 31) {
          Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
               g.UseRegister(mright.left().node()),
               g.UseRegister(m.left().node()), g.TempImmediate(shift_value));
          return;
        }
      }
    }

    // Select Alsl_d for ((left_of_left << imm) + right).
    if (m.left().opcode() == IrOpcode::kWord64Shl &&
        CanCover(node, m.right().node()) && CanCover(node, m.left().node())) {
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue() && !m.right().HasResolvedValue()) {
        int32_t shift_value =
            static_cast<int32_t>(mleft.right().ResolvedValue());
        if (shift_value > 0 && shift_value <= 31) {
          Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseRegister(m.right().node()), g.TempImmediate(shift_value));
          return;
        }
      }
    }

    VisitBinop(this, node, kLoong64Add_d, true, kLoong64Add_d);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  VisitBinop(this, node, kLoong64Sub_w);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  VisitBinop(this, node, kLoong64Sub_d);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Mul_w, true, kLoong64Mul_w);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint32_t value = static_cast<uint32_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kLoong64Sll_w | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value - 1) && value - 1 > 0 &&
        value - 1 <= 31) {
      Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kLoong64Sll_w | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kLoong64Sub_w | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopM
```