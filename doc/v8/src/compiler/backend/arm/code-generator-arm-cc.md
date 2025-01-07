Response:
The user wants a summary of the functionality of the provided C++ code snippet. The snippet is part of the V8 JavaScript engine, specifically the ARM backend's code generator.

Here's a plan to generate the summary:

1. **Identify the file's purpose:** Based on the path `v8/src/compiler/backend/arm/code-generator-arm.cc`, it's clear this file is responsible for generating ARM machine code from a higher-level intermediate representation.

2. **Analyze the included headers:** These headers provide clues about the functionalities:
    - `assembler-arm.h`, `constants-arm.h`, `register-arm.h`:  Deal with ARM assembly instructions, constants, and registers.
    - `code-generator-impl.h`, `code-generator.h`: Base classes and interfaces for code generation.
    - `instruction-codes.h`: Defines the instruction codes used in the intermediate representation.
    - `node-matchers.h`:  For pattern matching in the intermediate representation.
    - `osr.h`: On-stack replacement related functionalities.
    - `wasm/...`: WebAssembly support.

3. **Examine the `ArmOperandConverter` class:** This class helps in translating instruction operands into ARM-specific operands. It handles different addressing modes and immediate values.

4. **Analyze the out-of-line code generation classes:**  These classes handle less common or more complex operations, keeping the main code generation flow cleaner:
    - `OutOfLineRecordWrite`: Generates code for updating object properties, including handling write barriers for garbage collection.
    - `OutOfLineFloatMin/Max`: Handles floating-point minimum and maximum operations.

5. **Look at the helper functions and macros:** These reveal common patterns and operations:
    - `FlagsConditionToCondition`: Converts intermediate representation condition codes to ARM condition codes.
    - `ASSEMBLE_ATOMIC_*`:  Macros for generating code for atomic operations.
    - `ASSEMBLE_IEEE754_*`: Macros for calling C library functions for IEEE 754 floating-point operations.
    - `ASSEMBLE_NEON_*`, `ASSEMBLE_F64X2_*`, `ASSEMBLE_SIMD_SHIFT_*`: Macros for generating NEON (SIMD) instructions.
    - `FlushPendingPushRegisters`, `AdjustStackPointerForTailCall`: Helpers for managing the stack, especially for tail calls.

6. **Understand the `CodeGenerator` class methods:** Focus on the key methods like `AssembleDeconstructFrame`, `AssemblePrepareTailCall`, `AssembleTailCallBeforeGap`, `AssembleTailCallAfterGap`, `AssembleArchInstruction`. These methods are the core of the code generation process.

7. **Check for JavaScript relevance:**  The code interacts with JavaScript concepts like function calls, object properties, and floating-point numbers.

8. **Consider common programming errors:**  While the code itself is for code generation, it deals with operations where programmers might make mistakes (e.g., incorrect memory access, wrong function calls).

9. **Address the `.tq` extension question:**  The prompt asks about `.tq` files, which relate to Torque, V8's type definition language. The current file is `.cc`, so it's not a Torque source file.

10. **Structure the summary:** Organize the findings into logical sections covering the main functionalities.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/double.h"
#include "src/codegen/arm/assembler-arm.h"
#include "src/codegen/arm/constants-arm.h"
#include "src/codegen/arm/register-arm.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/utils/boxed-float.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

// Adds Arm-specific methods to convert InstructionOperands.
class ArmOperandConverter final : public InstructionOperandConverter {
 public:
  ArmOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  SBit OutputSBit() const {
    switch (instr_->flags_mode()) {
      case kFlags_branch:
      case kFlags_conditional_branch:
      case kFlags_deoptimize:
      case kFlags_set:
      case kFlags_conditional_set:
      case kFlags_trap:
      case kFlags_select:
        return SetCC;
      case kFlags_none:
        return LeaveCC;
    }
    UNREACHABLE();
  }

  Operand InputImmediate(size_t index) const {
    return ToImmediate(instr_->InputAt(index));
  }

  Operand InputOperand2(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Offset_RI:
      case kMode_Offset_RR:
      case kMode_Root:
        break;
      case kMode_Operand2_I:
        return InputImmediate(index + 0);
      case kMode_Operand2_R:
        return Operand(InputRegister(index + 0));
      case kMode_Operand2_R_ASR_I:
        return Operand(InputRegister(index + 0), ASR, InputInt5(index + 1));
      case kMode_Operand2_R_ASR_R:
        return Operand(InputRegister(index + 0), ASR, InputRegister(index + 1));
      case kMode_Operand2_R_LSL_I:
        return Operand(InputRegister(index + 0), LSL, InputInt5(index + 1));
      case kMode_Operand2_R_LSL_R:
        return Operand(InputRegister(index + 0), LSL, InputRegister(index + 1));
      case kMode_Operand2_R_LSR_I:
        return Operand(InputRegister(index + 0), LSR, InputInt5(index + 1));
      case kMode_Operand2_R_LSR_R:
        return Operand(InputRegister(index + 0), LSR, InputRegister(index + 1));
      case kMode_Operand2_R_ROR_I:
        return Operand(InputRegister(index + 0), ROR, InputInt5(index + 1));
      case kMode_Operand2_R_ROR_R:
        return Operand(InputRegister(index + 0), ROR, InputRegister(index + 1));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Operand2_I:
      case kMode_Operand2_R:
      case kMode_Operand2_R_ASR_I:
      case kMode_Operand2_R_ASR_R:
      case kMode_Operand2_R_LSL_R:
      case kMode_Operand2_R_LSR_I:
      case kMode_Operand2_R_LSR_R:
      case kMode_Operand2_R_ROR_I:
      case kMode_Operand2_R_ROR_R:
        break;
      case kMode_Operand2_R_LSL_I:
        *first_index += 3;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1),
                          LSL, InputInt32(index + 2));
      case kMode_Offset_RI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_Offset_RR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputInt32(index));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t first_index = 0) {
    return InputOffset(&first_index);
  }

  Operand ToImmediate(InstructionOperand* operand) const {
    Constant constant = ToConstant(operand);
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32(), constant.rmode());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kExternalReference:
        return Operand(constant.ToExternalReference());
      case Constant::kInt64:
      case Constant::kCompressedHeapObject:
      case Constant::kHeapObject:
      // TODO(dcarney): loading RPO constants on arm.
      case Constant::kRpoNumber:
        break;
    }
    UNREACHABLE();
  }

  MemOperand ToMemOperand(InstructionOperand* op) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand SlotToMemOperand(int slot) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }

  NeonMemOperand NeonInputOperand(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_Operand2_R:
        return NeonMemOperand(InputRegister(index + 0));
      default:
        break;
    }
    UNREACHABLE();
  }
};

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, Operand offset,
                       Register value, RecordWriteMode mode,
                       StubCallMode stub_mode,
                       UnwindingInfoWriter* unwinding_info_writer)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        value_(value),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()) {
  }

  void Generate() final {
    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ Push(lr);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset());
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop(lr);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  Operand const offset_;
  Register const value_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
};

template <typename T>
class OutOfLineFloatMin final : public OutOfLineCode {
 public:
  OutOfLineFloatMin(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMinOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Min = OutOfLineFloatMin<SwVfpRegister>;
using OutOfLineFloat64Min = OutOfLineFloatMin<DwVfpRegister>;

template <typename T>
class OutOfLineFloatMax final : public OutOfLineCode {
 public:
  OutOfLineFloatMax(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMaxOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Max = OutOfLineFloatMax<SwVfpRegister>;
using OutOfLineFloat64Max = OutOfLineFloatMax<DwVfpRegister>;

Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kSignedLessThan:
      return lt;
    case kSignedGreaterThanOrEqual:
      return ge;
    case kSignedLessThanOrEqual:
      return le;
    case kSignedGreaterThan:
      return gt;
    case kUnsignedLessThan:
      return lo;
    case kUnsignedGreaterThanOrEqual:
      return hs;
    case kUnsignedLessThanOrEqual:
      return ls;
    case kUnsignedGreaterThan:
      return hi;
    case kFloatLessThanOrUnordered:
      return lt;
    case kFloatGreaterThanOrEqual:
      return ge;
    case kFloatLessThanOrEqual:
      return ls;
    case kFloatGreaterThanOrUnordered:
      return hi;
    case kFloatLessThan:
      return lo;
    case kFloatGreaterThanOrEqualOrUnordered:
      return hs;
    case kFloatLessThanOrEqualOrUnordered:
      return le;
    case kFloatGreaterThan:
      return gt;
    case kOverflow:
      return vs;
    case kNotOverflow:
      return vc;
    case kPositiveOrZero:
      return pl;
    case kNegative:
      return mi;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                       \
  do {                                                                \
    __ asm_instr(i.OutputRegister(),                                  \
                 MemOperand(i.InputRegister(0), i.InputRegister(1))); \
    __ dmb(ISH);                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr, order)   \
  do {                                                    \
    __ dmb(ISH);                                          \
    __ asm_instr(i.InputRegister(0), i.InputOffset(1));   \
    if (order == AtomicMemoryOrder::kSeqCst) __ dmb(ISH); \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_instr, store_instr)             \
  do {                                                                        \
    Label exchange;                                                           \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));        \
    __ dmb(ISH);                                                              \
    __ bind(&exchange);                                                       \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ store_instr(i.TempRegister(0), i.InputRegister(2), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &exchange);                                                      \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_instr, store_instr,     \
                                                 cmp_reg)                     \
  do {                                                                        \
    Label compareExchange;                                                    \
    Label exit;                                                               \
    __ dmb(ISH);                                                              \
    __ bind(&compareExchange);                                                \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ teq(cmp_reg, Operand(i.OutputRegister(0)));                            \
    __ b(ne, &exit);                                                          \
    __ store_instr(i.TempRegister(0), i.InputRegister(3), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &compareExchange);                                               \
    __ bind(&exit);                                                           \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_instr, store_instr, bin_instr)            \
  do {                                                                       \
    Label binop;                                                             \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));       \
    __ dmb(ISH);                                                             \
    __ bind(&binop);                                                         \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                   \
    __ bin_instr(i.TempRegister(0), i.OutputRegister(0),                     \
                 Operand(i.InputRegister(2)));                               \
    __ store_instr(i.TempRegister(2), i.TempRegister(0), i.TempRegister(1)); \
    __ teq(i.TempRegister(2), Operand(0));                                   \
    __ b(ne, &binop);                                                        \
    __ dmb(ISH);                                                             \
  } while (0)

#define ASSEMBLE_ATOMIC64_ARITH_BINOP(instr1, instr2)                  \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr1(i.TempRegister(1), r2, i.InputRegister(0), SetCC);       \
    __ instr2(i.TempRegister(2), r3, Operand(i.InputRegister(1)));     \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr)                           \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr(i.TempRegister(1), r2, Operand(i.InputRegister(0)));      \
    __ instr(i.TempRegister(2), r3, Operand(i.InputRegister(1)));      \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                           \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 2);                                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                          \
                            i.InputDoubleRegister(1));                         \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                            \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 1);                                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_NEON_NARROWING_OP(dt, sdt)           \
  do {                                                \
    Simd128Register dst = i.OutputSimd128Register(),  \
                    src0 = i.InputSimd128Register(0), \
                    src1 = i.InputSimd128Register(1); \
    if (dst == src0 && dst == src1) {                 \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vmov(dst.high(), dst.low());                 \
    } else if (dst == src0) {                         \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
    } else {                                          \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
    }                                                 \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                                   \
  do {                                                                        \
    __ op(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low(),   \
          i.InputSimd128Register(1).low());                                   \
    __ op(i.OutputSimd128Register().high(), i.InputSimd128Register(0).high(), \
          i.InputSimd128Register(1).high());                                  \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl.
#define ASSEMBLE_SIMD_SHIFT_LEFT(asm_imm, width, sz, dt) \
  do {                                                   \
    QwNeonRegister dst = i.OutputSimd128Register();      \
    QwNeonRegister src = i.InputSimd128Register(0);      \
    if (instr->InputAt(1)->IsImmediate()) {              \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));    \
    } else {                                             \
      UseScratchRegisterScope temps(masm());             \
      Simd128Register tmp = temps.AcquireQ();            \
      Register shift = temps.Acquire();                  \
      constexpr int mask = (1 << width) - 1;             \
      __ and_(shift, i.InputRegister(1), Operand(mask)); \
      __ vdup(sz, tmp, shift);                           \
      __ vshl(dt, dst, src, tmp);                        \
    }                                                    \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl, passing in the negative shift value (treated as a right shift).
#define ASSEMBLE_SIMD_SHIFT_RIGHT(asm_imm, width, sz, dt) \
  do {                                                    \
    QwNeonRegister dst = i.OutputSimd128Register();       \
    QwNeonRegister src = i.InputSimd128Register(0);       \
    if (instr->InputAt(1)->IsImmediate()) {               \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));     \
    } else {                                              \
      UseScratchRegisterScope temps(masm());              \
      Simd128Register tmp = temps.AcquireQ();             \
      Register shift = temps.Acquire();                   \
      constexpr int mask = (1 << width) - 1;              \
      __ and_(shift, i.InputRegister(1), Operand(mask));  \
      __ vdup(sz, tmp, shift);                            \
      __ vneg(sz, tmp, tmp);                              \
      __ vshl(dt, dst, src, tmp);                         \
    }                                                     \
  } while (0)

void CodeGenerator::AssembleDeconstructFrame() {
  __ LeaveFrame(StackFrame::MANUAL);
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ ldm(ia, fp, {lr, fp});
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->add(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

#if DEBUG
bool VerifyOutputOfAtomicPairInstr(ArmOperandConverter* converter,
                                   const Instruction* instr, Register low,
                                   Register high) {
  DCHECK_GE(instr->OutputCount() + instr->TempCount(), 2);
  if (instr->OutputCount() == 2) {
    return (converter->OutputRegister(0) == low &&
            converter->OutputRegister(1) == high);
  }
  if (instr->OutputCount() == 1) {
    return (converter->OutputRegister(0) == low &&
            converter->TempRegister(instr->TempCount() - 1) == high) ||
           (converter->OutputRegister(0) == high &&
            converter->TempRegister(instr->TempCount() - 1) == low);
  }
  DCHECK_EQ(instr->OutputCount(), 0);
  return (converter->TempRegister(instr->TempCount() - 2) == low &&
          converter->TempRegister(instr->TempCount() - 1) == high);
}
#endif

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    ArmOperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  __ ComputeCodeStartAddress(scratch);
  __ cmp(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
Prompt: 
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/code-generator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/numbers/double.h"
#include "src/codegen/arm/assembler-arm.h"
#include "src/codegen/arm/constants-arm.h"
#include "src/codegen/arm/register-arm.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/backend/code-generator-impl.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/gap-resolver.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/osr.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/utils/boxed-float.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define __ masm()->

// Adds Arm-specific methods to convert InstructionOperands.
class ArmOperandConverter final : public InstructionOperandConverter {
 public:
  ArmOperandConverter(CodeGenerator* gen, Instruction* instr)
      : InstructionOperandConverter(gen, instr) {}

  SBit OutputSBit() const {
    switch (instr_->flags_mode()) {
      case kFlags_branch:
      case kFlags_conditional_branch:
      case kFlags_deoptimize:
      case kFlags_set:
      case kFlags_conditional_set:
      case kFlags_trap:
      case kFlags_select:
        return SetCC;
      case kFlags_none:
        return LeaveCC;
    }
    UNREACHABLE();
  }

  Operand InputImmediate(size_t index) const {
    return ToImmediate(instr_->InputAt(index));
  }

  Operand InputOperand2(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Offset_RI:
      case kMode_Offset_RR:
      case kMode_Root:
        break;
      case kMode_Operand2_I:
        return InputImmediate(index + 0);
      case kMode_Operand2_R:
        return Operand(InputRegister(index + 0));
      case kMode_Operand2_R_ASR_I:
        return Operand(InputRegister(index + 0), ASR, InputInt5(index + 1));
      case kMode_Operand2_R_ASR_R:
        return Operand(InputRegister(index + 0), ASR, InputRegister(index + 1));
      case kMode_Operand2_R_LSL_I:
        return Operand(InputRegister(index + 0), LSL, InputInt5(index + 1));
      case kMode_Operand2_R_LSL_R:
        return Operand(InputRegister(index + 0), LSL, InputRegister(index + 1));
      case kMode_Operand2_R_LSR_I:
        return Operand(InputRegister(index + 0), LSR, InputInt5(index + 1));
      case kMode_Operand2_R_LSR_R:
        return Operand(InputRegister(index + 0), LSR, InputRegister(index + 1));
      case kMode_Operand2_R_ROR_I:
        return Operand(InputRegister(index + 0), ROR, InputInt5(index + 1));
      case kMode_Operand2_R_ROR_R:
        return Operand(InputRegister(index + 0), ROR, InputRegister(index + 1));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t* first_index) {
    const size_t index = *first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_None:
      case kMode_Operand2_I:
      case kMode_Operand2_R:
      case kMode_Operand2_R_ASR_I:
      case kMode_Operand2_R_ASR_R:
      case kMode_Operand2_R_LSL_R:
      case kMode_Operand2_R_LSR_I:
      case kMode_Operand2_R_LSR_R:
      case kMode_Operand2_R_ROR_I:
      case kMode_Operand2_R_ROR_R:
        break;
      case kMode_Operand2_R_LSL_I:
        *first_index += 3;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1),
                          LSL, InputInt32(index + 2));
      case kMode_Offset_RI:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputInt32(index + 1));
      case kMode_Offset_RR:
        *first_index += 2;
        return MemOperand(InputRegister(index + 0), InputRegister(index + 1));
      case kMode_Root:
        *first_index += 1;
        return MemOperand(kRootRegister, InputInt32(index));
    }
    UNREACHABLE();
  }

  MemOperand InputOffset(size_t first_index = 0) {
    return InputOffset(&first_index);
  }

  Operand ToImmediate(InstructionOperand* operand) const {
    Constant constant = ToConstant(operand);
    switch (constant.type()) {
      case Constant::kInt32:
        return Operand(constant.ToInt32(), constant.rmode());
      case Constant::kFloat32:
        return Operand::EmbeddedNumber(constant.ToFloat32());
      case Constant::kFloat64:
        return Operand::EmbeddedNumber(constant.ToFloat64().value());
      case Constant::kExternalReference:
        return Operand(constant.ToExternalReference());
      case Constant::kInt64:
      case Constant::kCompressedHeapObject:
      case Constant::kHeapObject:
      // TODO(dcarney): loading RPO constants on arm.
      case Constant::kRpoNumber:
        break;
    }
    UNREACHABLE();
  }

  MemOperand ToMemOperand(InstructionOperand* op) const {
    DCHECK_NOT_NULL(op);
    DCHECK(op->IsStackSlot() || op->IsFPStackSlot());
    return SlotToMemOperand(AllocatedOperand::cast(op)->index());
  }

  MemOperand SlotToMemOperand(int slot) const {
    FrameOffset offset = frame_access_state()->GetFrameOffset(slot);
    return MemOperand(offset.from_stack_pointer() ? sp : fp, offset.offset());
  }

  NeonMemOperand NeonInputOperand(size_t first_index) {
    const size_t index = first_index;
    switch (AddressingModeField::decode(instr_->opcode())) {
      case kMode_Operand2_R:
        return NeonMemOperand(InputRegister(index + 0));
      default:
        break;
    }
    UNREACHABLE();
  }
};

namespace {

class OutOfLineRecordWrite final : public OutOfLineCode {
 public:
  OutOfLineRecordWrite(CodeGenerator* gen, Register object, Operand offset,
                       Register value, RecordWriteMode mode,
                       StubCallMode stub_mode,
                       UnwindingInfoWriter* unwinding_info_writer)
      : OutOfLineCode(gen),
        object_(object),
        offset_(offset),
        value_(value),
        mode_(mode),
#if V8_ENABLE_WEBASSEMBLY
        stub_mode_(stub_mode),
#endif  // V8_ENABLE_WEBASSEMBLY
        must_save_lr_(!gen->frame_access_state()->has_frame()),
        unwinding_info_writer_(unwinding_info_writer),
        zone_(gen->zone()) {
  }

  void Generate() final {
    __ CheckPageFlag(value_, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                     exit());
    SaveFPRegsMode const save_fp_mode = frame()->DidAllocateDoubleRegisters()
                                            ? SaveFPRegsMode::kSave
                                            : SaveFPRegsMode::kIgnore;
    if (must_save_lr_) {
      // We need to save and restore lr if the frame was elided.
      __ Push(lr);
      unwinding_info_writer_->MarkLinkRegisterOnTopOfStack(__ pc_offset());
    }
    if (mode_ == RecordWriteMode::kValueIsEphemeronKey) {
      __ CallEphemeronKeyBarrier(object_, offset_, save_fp_mode);
#if V8_ENABLE_WEBASSEMBLY
    } else if (stub_mode_ == StubCallMode::kCallWasmRuntimeStub) {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode,
                                          StubCallMode::kCallWasmRuntimeStub);
#endif  // V8_ENABLE_WEBASSEMBLY
    } else {
      __ CallRecordWriteStubSaveRegisters(object_, offset_, save_fp_mode);
    }
    if (must_save_lr_) {
      __ Pop(lr);
      unwinding_info_writer_->MarkPopLinkRegisterFromTopOfStack(__ pc_offset());
    }
  }

 private:
  Register const object_;
  Operand const offset_;
  Register const value_;
  RecordWriteMode const mode_;
#if V8_ENABLE_WEBASSEMBLY
  StubCallMode stub_mode_;
#endif  // V8_ENABLE_WEBASSEMBLY
  bool must_save_lr_;
  UnwindingInfoWriter* const unwinding_info_writer_;
  Zone* zone_;
};

template <typename T>
class OutOfLineFloatMin final : public OutOfLineCode {
 public:
  OutOfLineFloatMin(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMinOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Min = OutOfLineFloatMin<SwVfpRegister>;
using OutOfLineFloat64Min = OutOfLineFloatMin<DwVfpRegister>;

template <typename T>
class OutOfLineFloatMax final : public OutOfLineCode {
 public:
  OutOfLineFloatMax(CodeGenerator* gen, T result, T left, T right)
      : OutOfLineCode(gen), result_(result), left_(left), right_(right) {}

  void Generate() final { __ FloatMaxOutOfLine(result_, left_, right_); }

 private:
  T const result_;
  T const left_;
  T const right_;
};
using OutOfLineFloat32Max = OutOfLineFloatMax<SwVfpRegister>;
using OutOfLineFloat64Max = OutOfLineFloatMax<DwVfpRegister>;

Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kEqual:
      return eq;
    case kNotEqual:
      return ne;
    case kSignedLessThan:
      return lt;
    case kSignedGreaterThanOrEqual:
      return ge;
    case kSignedLessThanOrEqual:
      return le;
    case kSignedGreaterThan:
      return gt;
    case kUnsignedLessThan:
      return lo;
    case kUnsignedGreaterThanOrEqual:
      return hs;
    case kUnsignedLessThanOrEqual:
      return ls;
    case kUnsignedGreaterThan:
      return hi;
    case kFloatLessThanOrUnordered:
      return lt;
    case kFloatGreaterThanOrEqual:
      return ge;
    case kFloatLessThanOrEqual:
      return ls;
    case kFloatGreaterThanOrUnordered:
      return hi;
    case kFloatLessThan:
      return lo;
    case kFloatGreaterThanOrEqualOrUnordered:
      return hs;
    case kFloatLessThanOrEqualOrUnordered:
      return le;
    case kFloatGreaterThan:
      return gt;
    case kOverflow:
      return vs;
    case kNotOverflow:
      return vc;
    case kPositiveOrZero:
      return pl;
    case kNegative:
      return mi;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

#define ASSEMBLE_ATOMIC_LOAD_INTEGER(asm_instr)                       \
  do {                                                                \
    __ asm_instr(i.OutputRegister(),                                  \
                 MemOperand(i.InputRegister(0), i.InputRegister(1))); \
    __ dmb(ISH);                                                      \
  } while (0)

#define ASSEMBLE_ATOMIC_STORE_INTEGER(asm_instr, order)   \
  do {                                                    \
    __ dmb(ISH);                                          \
    __ asm_instr(i.InputRegister(0), i.InputOffset(1));   \
    if (order == AtomicMemoryOrder::kSeqCst) __ dmb(ISH); \
  } while (0)

#define ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(load_instr, store_instr)             \
  do {                                                                        \
    Label exchange;                                                           \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));        \
    __ dmb(ISH);                                                              \
    __ bind(&exchange);                                                       \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ store_instr(i.TempRegister(0), i.InputRegister(2), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &exchange);                                                      \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_instr, store_instr,     \
                                                 cmp_reg)                     \
  do {                                                                        \
    Label compareExchange;                                                    \
    Label exit;                                                               \
    __ dmb(ISH);                                                              \
    __ bind(&compareExchange);                                                \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                    \
    __ teq(cmp_reg, Operand(i.OutputRegister(0)));                            \
    __ b(ne, &exit);                                                          \
    __ store_instr(i.TempRegister(0), i.InputRegister(3), i.TempRegister(1)); \
    __ teq(i.TempRegister(0), Operand(0));                                    \
    __ b(ne, &compareExchange);                                               \
    __ bind(&exit);                                                           \
    __ dmb(ISH);                                                              \
  } while (0)

#define ASSEMBLE_ATOMIC_BINOP(load_instr, store_instr, bin_instr)            \
  do {                                                                       \
    Label binop;                                                             \
    __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));       \
    __ dmb(ISH);                                                             \
    __ bind(&binop);                                                         \
    __ load_instr(i.OutputRegister(0), i.TempRegister(1));                   \
    __ bin_instr(i.TempRegister(0), i.OutputRegister(0),                     \
                 Operand(i.InputRegister(2)));                               \
    __ store_instr(i.TempRegister(2), i.TempRegister(0), i.TempRegister(1)); \
    __ teq(i.TempRegister(2), Operand(0));                                   \
    __ b(ne, &binop);                                                        \
    __ dmb(ISH);                                                             \
  } while (0)

#define ASSEMBLE_ATOMIC64_ARITH_BINOP(instr1, instr2)                  \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr1(i.TempRegister(1), r2, i.InputRegister(0), SetCC);       \
    __ instr2(i.TempRegister(2), r3, Operand(i.InputRegister(1)));     \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr)                           \
  do {                                                                 \
    Label binop;                                                       \
    __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3)); \
    __ dmb(ISH);                                                       \
    __ bind(&binop);                                                   \
    __ ldrexd(r2, r3, i.TempRegister(0));                              \
    __ instr(i.TempRegister(1), r2, Operand(i.InputRegister(0)));      \
    __ instr(i.TempRegister(2), r3, Operand(i.InputRegister(1)));      \
    __ strexd(i.TempRegister(3), i.TempRegister(1), i.TempRegister(2), \
              i.TempRegister(0));                                      \
    __ teq(i.TempRegister(3), Operand(0));                             \
    __ b(ne, &binop);                                                  \
    __ dmb(ISH);                                                       \
  } while (0)

#define ASSEMBLE_IEEE754_BINOP(name)                                           \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 2);                                             \
    __ MovToFloatParameters(i.InputDoubleRegister(0),                          \
                            i.InputDoubleRegister(1));                         \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 2);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_IEEE754_UNOP(name)                                            \
  do {                                                                         \
    /* TODO(bmeurer): We should really get rid of this special instruction, */ \
    /* and generate a CallAddress instruction instead. */                      \
    FrameScope scope(masm(), StackFrame::MANUAL);                              \
    __ PrepareCallCFunction(0, 1);                                             \
    __ MovToFloatParameter(i.InputDoubleRegister(0));                          \
    __ CallCFunction(ExternalReference::ieee754_##name##_function(), 0, 1);    \
    /* Move the result in the double result register. */                       \
    __ MovFromFloatResult(i.OutputDoubleRegister());                           \
    DCHECK_EQ(LeaveCC, i.OutputSBit());                                        \
  } while (0)

#define ASSEMBLE_NEON_NARROWING_OP(dt, sdt)           \
  do {                                                \
    Simd128Register dst = i.OutputSimd128Register(),  \
                    src0 = i.InputSimd128Register(0), \
                    src1 = i.InputSimd128Register(1); \
    if (dst == src0 && dst == src1) {                 \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vmov(dst.high(), dst.low());                 \
    } else if (dst == src0) {                         \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
    } else {                                          \
      __ vqmovn(dt, sdt, dst.high(), src1);           \
      __ vqmovn(dt, sdt, dst.low(), src0);            \
    }                                                 \
  } while (0)

#define ASSEMBLE_F64X2_ARITHMETIC_BINOP(op)                                   \
  do {                                                                        \
    __ op(i.OutputSimd128Register().low(), i.InputSimd128Register(0).low(),   \
          i.InputSimd128Register(1).low());                                   \
    __ op(i.OutputSimd128Register().high(), i.InputSimd128Register(0).high(), \
          i.InputSimd128Register(1).high());                                  \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl.
#define ASSEMBLE_SIMD_SHIFT_LEFT(asm_imm, width, sz, dt) \
  do {                                                   \
    QwNeonRegister dst = i.OutputSimd128Register();      \
    QwNeonRegister src = i.InputSimd128Register(0);      \
    if (instr->InputAt(1)->IsImmediate()) {              \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));    \
    } else {                                             \
      UseScratchRegisterScope temps(masm());             \
      Simd128Register tmp = temps.AcquireQ();            \
      Register shift = temps.Acquire();                  \
      constexpr int mask = (1 << width) - 1;             \
      __ and_(shift, i.InputRegister(1), Operand(mask)); \
      __ vdup(sz, tmp, shift);                           \
      __ vshl(dt, dst, src, tmp);                        \
    }                                                    \
  } while (0)

// If shift value is an immediate, we can call asm_imm, taking the shift value
// modulo 2^width. Otherwise, emit code to perform the modulus operation, and
// call vshl, passing in the negative shift value (treated as a right shift).
#define ASSEMBLE_SIMD_SHIFT_RIGHT(asm_imm, width, sz, dt) \
  do {                                                    \
    QwNeonRegister dst = i.OutputSimd128Register();       \
    QwNeonRegister src = i.InputSimd128Register(0);       \
    if (instr->InputAt(1)->IsImmediate()) {               \
      __ asm_imm(dt, dst, src, i.InputInt##width(1));     \
    } else {                                              \
      UseScratchRegisterScope temps(masm());              \
      Simd128Register tmp = temps.AcquireQ();             \
      Register shift = temps.Acquire();                   \
      constexpr int mask = (1 << width) - 1;              \
      __ and_(shift, i.InputRegister(1), Operand(mask));  \
      __ vdup(sz, tmp, shift);                            \
      __ vneg(sz, tmp, tmp);                              \
      __ vshl(dt, dst, src, tmp);                         \
    }                                                     \
  } while (0)

void CodeGenerator::AssembleDeconstructFrame() {
  __ LeaveFrame(StackFrame::MANUAL);
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ ldm(ia, fp, {lr, fp});
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AllocateStackSpace(stack_slot_delta * kSystemPointerSize);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->add(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

#if DEBUG
bool VerifyOutputOfAtomicPairInstr(ArmOperandConverter* converter,
                                   const Instruction* instr, Register low,
                                   Register high) {
  DCHECK_GE(instr->OutputCount() + instr->TempCount(), 2);
  if (instr->OutputCount() == 2) {
    return (converter->OutputRegister(0) == low &&
            converter->OutputRegister(1) == high);
  }
  if (instr->OutputCount() == 1) {
    return (converter->OutputRegister(0) == low &&
            converter->TempRegister(instr->TempCount() - 1) == high) ||
           (converter->OutputRegister(0) == high &&
            converter->TempRegister(instr->TempCount() - 1) == low);
  }
  DCHECK_EQ(instr->OutputCount(), 0);
  return (converter->TempRegister(instr->TempCount() - 2) == low &&
          converter->TempRegister(instr->TempCount() - 1) == high);
}
#endif

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    ArmOperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  __ ComputeCodeStartAddress(scratch);
  __ cmp(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(); }

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  ArmOperandConverter i(this, instr);

  __ MaybeCheckConstPool();
  InstructionCode opcode = instr->opcode();
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);
  switch (arch_opcode) {
    case kArchCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!instr->InputAt(0)->IsImmediate());
      Register builtin_index = i.InputRegister(0);
      Register target =
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister)
              ? kJavaScriptCallCodeStartRegister
              : builtin_index;
      __ CallBuiltinByIndex(builtin_index, target);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt32());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (instr->InputAt(0)->IsImmediate()) {
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Check the function's context matches the context argument.
        __ ldr(scratch, FieldMemOperand(func, JSFunction::kContextOffset));
        __ cmp(cp, scratch);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters);
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, kReturnRegister0);
      DCHECK(IsAligned(bytes, kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      DCHECK(!caller_registers_saved_);
      caller_registers_saved_ = true;
      break;
    }
    case kArchRestoreCallerRegisters: {
      DCHECK(fp_mode_ ==
             static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode())));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // Don't overwrite
"""


```