Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, specifically the file `v8/src/maglev/riscv/maglev-ir-riscv.cc`. It also includes conditional checks (if the filename ended in `.tq`) and asks for JavaScript examples if the code is related to JavaScript functionality.

2. **Initial Scan and Key Observations:**
    * **File Path:** The path `v8/src/maglev/riscv/` strongly suggests this code is part of V8's Maglev compiler, targeting the RISC-V architecture.
    * **Includes:** The included headers provide clues:
        * `"src/codegen/riscv/..."`:  RISC-V specific code generation.
        * `"src/maglev/..."`: Code related to the Maglev compiler.
        * `"src/objects/..."`:  Interaction with V8's object model.
        * `"src/codegen/interface-descriptors-inl.h"`:  Likely deals with calling conventions and function interfaces.
    * **Namespace:** The code is within the `v8::internal::maglev` namespace.
    * **Macros:** The `__ masm->` macro suggests it's using a Maglev-specific assembler.
    * **Classes and Methods:** The code defines various classes like `Int32NegateWithOverflow`, `BuiltinStringFromCharCode`, `Float64Add`, etc. Each class has methods like `SetValueLocationConstraints` and `GenerateCode`.
    * **`GenerateCode`:** This method name is a strong indicator of code generation logic. It takes a `MaglevAssembler` as an argument.
    * **Register Usage:**  The code manipulates registers (e.g., `Register value = ToRegister(value_input());`, `DoubleRegister out = ToDoubleRegister(result());`).
    * **Deoptimization:**  References to `DeoptimizeReason` and `GetDeoptLabel` suggest the code handles cases where optimized code needs to fall back to a less optimized version.
    * **Overflow Handling:**  The "WithOverflow" suffix in some class names (`Int32NegateWithOverflow`, `Int32AddWithOverflow`) indicates specific logic for handling integer overflows.
    * **Floating-Point Operations:** Classes like `Float64Add`, `Float64Subtract` clearly deal with floating-point arithmetic.
    * **Built-ins and Inlining:** Classes like `BuiltinStringFromCharCode` and `InlinedAllocation` point to optimized implementations of built-in functions and memory allocation.
    * **Typed Arrays and Data Views:** Classes like `LoadTypedArrayLength` and `CheckJSDataViewBounds` suggest support for typed arrays and data views.
    * **Interrupts and Tiering:** The `HandleInterruptsAndTiering` function indicates interaction with V8's interrupt handling and tiering (optimization/deoptimization) mechanisms.

3. **Inferring Functionality of Individual Classes:** Based on the names and operations within the `GenerateCode` methods, I can deduce the purpose of each class:
    * **`Int32NegateWithOverflow`, `Int32AbsWithOverflow`, etc.:** Implement basic integer arithmetic operations with overflow detection and deoptimization.
    * **`BuiltinStringFromCharCode`:** Implements the `String.fromCharCode()` JavaScript function.
    * **`InlinedAllocation`:** Handles optimized object allocation within the Maglev compiler.
    * **`ArgumentsLength`, `RestLength`:** Determine the length of arguments objects and rest parameters.
    * **`Float64Add`, `Float64Subtract`, etc.:** Implement basic floating-point arithmetic operations.
    * **`Float64Modulus`, `Float64Exponentiate`, `Float64Ieee754Unary`:** Implement more complex floating-point operations, often by calling C library functions.
    * **`LoadTypedArrayLength`, `CheckJSDataViewBounds`:** Handle operations specific to typed arrays and data views, including bounds checking.

4. **Addressing Specific Questions:**
    * **`.tq` Extension:** The code is C++, not Torque, so this condition is false.
    * **Relationship to JavaScript:**  Many of the operations directly correspond to JavaScript language features (arithmetic operators, `String.fromCharCode()`, typed arrays, etc.).
    * **JavaScript Examples:** I provide JavaScript code snippets that illustrate the functionality implemented by the C++ code. For instance, `x + y` corresponds to the `Int32AddWithOverflow` or `Float64Add` logic.
    * **Code Logic Inference (Assumptions and Outputs):**  For the integer operations, I provide examples with potential overflow scenarios and how the deoptimization mechanism would be triggered. For `BuiltinStringFromCharCode`, I show how different input values lead to different outcomes (single-byte vs. two-byte strings).
    * **Common Programming Errors:** I highlight potential errors like integer overflow, division by zero, and out-of-bounds access in typed arrays, connecting them to the deoptimization logic in the C++ code.

5. **Summarizing Functionality:**  I synthesize the information gathered into a concise summary, emphasizing that the file implements Maglev IR nodes for RISC-V, covering various operations related to integer and floating-point arithmetic, string manipulation, object allocation, and interaction with JavaScript features like arguments objects, rest parameters, typed arrays, and data views. The code also includes mechanisms for handling overflows, deoptimization, and interacting with V8's runtime environment.

6. **Structuring the Output:** I organize the information according to the prompt's requests, providing clear headings and examples for each point. I make sure to address all parts of the prompt.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive and accurate summary of its functionality, addressing all the specific questions in the prompt. The key is to leverage the information within the code itself (names, included headers, operations) to infer its purpose and connect it to the broader context of the V8 JavaScript engine.
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/riscv/assembler-riscv-inl.h"
#include "src/codegen/riscv/register-riscv.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/maglev/riscv/maglev-assembler-riscv-inl.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/js-function.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

void Int32NegateWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32NegateWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  static_assert(Int32NegateWithOverflow::kProperties.can_eager_deopt());
  // Deopt when result would be -0.
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, equal, value, Operand(zero_reg));

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ neg(scratch, value);
  __ negw(out, value);

  // Are the results of NEG and NEGW on the operand different?
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register out = ToRegister(result());

  static_assert(Int32AbsWithOverflow::kProperties.can_eager_deopt());
  Label done;
  DCHECK(ToRegister(input()) == out);
  // fast-path
  __ MacroAssembler::Branch(&done, greater_equal, out, Operand(zero_reg),
                            Label::Distance::kNear);

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ neg(scratch, out);
  __ negw(out, out);

  // Are the results of NEG and NEGW on the operand different?
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  __ bind(&done);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ Add32(scratch, value, Operand(1));

  static_assert(Int32IncrementWithOverflow::kProperties.can_eager_deopt());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, less, scratch, Operand(value));
  __ Mv(out, scratch);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ Sub32(scratch, value, Operand(1));

  static_assert(Int32DecrementWithOverflow::kProperties.can_eager_deopt());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, greater, scratch, Operand(value));
  __ Mv(out, scratch);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

int BuiltinStringFromCharCode::MaxCallStackArgs() const {
  return AllocateDescriptor::GetStackParameterCount();
}
void BuiltinStringFromCharCode::SetValueLocationConstraints() {
  if (code_input().node()->Is<Int32Constant>()) {
    UseAny(code_input());
  } else {
    UseRegister(code_input());
  }
  set_temporaries_needed(2);
  DefineAsRegister(this);
}
void BuiltinStringFromCharCode::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ Move(scratch, char_code);
      __ Sh(scratch, FieldMemOperand(result_string,
                                     OFFSET_OF_DATA_START(SeqTwoByteString)));
    }
  } else {
    __ StringFromCharCode(register_snapshot(), nullptr, result_string,
                          ToRegister(code_input()), scratch,
                          MaglevAssembler::CharCodeMaskMode::kMustApplyMask);
  }
}

void InlinedAllocation::SetValueLocationConstraints() {
  UseRegister(allocation_block());
  if (offset() == 0) {
    DefineSameAsFirst(this);
  } else {
    DefineAsRegister(this);
  }
}

void InlinedAllocation::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register out = ToRegister(result());
  Register value = ToRegister(allocation_block());
  if (offset() != 0) {
    __ AddWord(out, value, Operand(offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register out = ToRegister(result());

  __ LoadWord(out, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub64(out, out, Operand(1));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ LoadWord(length, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub64(length, length, Operand(formal_parameter_count() + 1));
  __ MacroAssembler::Branch(&done, greater_equal, length, Operand(zero_reg),
                            Label::Distance::kNear);
  __ Mv(length, zero_reg);
  __ bind(&done);
  __ UncheckedSmiTagInt32(length);
}

int CheckedObjectToIndex::MaxCallStackArgs() const { return 0; }

void Int32AddWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Int32AddWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32AddWithOverflow::kProperties.can_eager_deopt());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ Add64(scratch, left, right);
  __ Add32(out, left, right);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32SubtractWithOverflow::kProperties.can_eager_deopt());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ Sub64(scratch, left, right);
  __ Sub32(out, left, right);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, ne, scratch, Operand(out));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}
void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise multiplication by a constant.

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.Acquire();
  }

  Register scratch = temps.Acquire();
  __ MulOverflow32(res, left, Operand(right), scratch);

  static_assert(Int32MultiplyWithOverflow::kProperties.can_eager_deopt());
  // if res != (res[0:31] sign extended to 64 bits), then the multiplication
  // result is too large for 32 bits.
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, ne, scratch, Operand(zero_reg));

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ MacroAssembler::Branch(&end, ne, res, Operand(zero_reg),
                            Label::Distance::kNear);
  {
    Register maybeNegative = scratch;
    __ Or(maybeNegative, left, Operand(right));
    // TODO(Vladimir Kempik): consider usage of bexti instruction if Zbs
    // extension is available
    __ And(maybeNegative, maybeNegative, Operand(0x80000000));  // 1 << 31
    // If one of them is negative, we must have a -0 result, which is non-int32,
    // so deopt.
    // TODO(leszeks): Consider splitting these deopts to have distinct deopt
    // reasons. Otherwise, the reason has to match the above.
    __ RecordComment("-- Jump to eager deopt if the result is negative zero");
    Label* deopt_label = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
    __ MacroAssembler::Branch(deopt_label, ne, maybeNegative,
                              Operand(zero_reg));
  }

  __ bind(&end);
  if (out_alias_input) {
    __ Move(out, res);
  }

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}
void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise division by a constant.

  static_assert(Int32DivideWithOverflow::kProperties.can_eager_deopt());
  ZoneLabelRef done(masm);
  Label* deferred_overflow_checks = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register left,
         Register right, Int32DivideWithOverflow* node) {
        // {right} is negative or zero.

        // TODO(leszeks): Using kNotInt32 here, but in same places
        // kDivisionByZerokMinusZero/kMinusZero/kOverflow would be better. Right
        // now all eager deopts in a node have to be the same -- we should allow
        // a node to emit multiple eager deopts with different reasons.
        Label* deopt = __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32);

        // Check if {right} is zero.
        __ RecordComment("-- Jump to eager deopt if right is zero");
        __ MacroAssembler::Branch(deopt, eq, right, Operand(zero_reg));

        // Check if {left} is zero, as that would produce minus zero.
        __ RecordComment("-- Jump to eager deopt if left is zero");
        __ MacroAssembler::Branch(deopt, eq, left, Operand(zero_reg));

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ MacroAssembler::Branch(*done, ne, left, Operand(kMinInt));
        __ MacroAssembler::Branch(*done, ne, right, Operand(-1));
        __ JumpToDeopt(deopt);
      },
      done, left, right, this);

  // Check if {right} is positive and not zero.
  __ MacroAssembler::Branch(deferred_overflow_checks, less_equal, right,
                            Operand(zero_reg));
  __ bind(*done);

  // Perform the actual integer division.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.Acquire();
  }
  __ Div32(res, left, right);

  // Check that the remainder is zero.
  Register temp = temps.Acquire();
  __ remw(temp, left, right);
  Label* deopt = __ GetDeoptLabel(this, DeoptimizeReason::kNotInt32);
  __ RecordComment("-- Jump to eager deopt if remainder is zero");
  __ MacroAssembler::Branch(deopt, ne, temp, Operand(zero_reg));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{res} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ Move(out, res);
}

void Int32ModulusWithOverflow::SetValueLocationConstraints() {
  UseAndClobberRegister(left_input());
  UseAndClobberRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void Int32ModulusWithOverflow::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  // If AreAliased(lhs, rhs):
  //   deopt if lhs < 0  // Minus zero.
  //   0
  //
  // Using same algorithm as in EffectControlLinearizer:
  //   if rhs <= 0 then
  //     rhs = -rhs
  //     deopt if rhs == 0
  //   if lhs < 0 then
  //     let lhs_abs = -lhs in
  //     let res = lhs_abs % rhs in
  //     deopt if res == 0
  //     -res
  //   else
  //     let msk = rhs - 1 in
  //     if rhs & msk == 0 then
  //       lhs & msk
  //     else
  //       lhs % rhs

  Register lhs = ToRegister(left_input());
  Register rhs = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32ModulusWithOverflow::kProperties.can_eager_deopt());
  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  // For the modulus algorithm described above, lhs and rhs must not alias
  // each other.
  if (lhs == rhs) {
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    Label* deopt = __ GetDeoptLabel(this, DeoptimizeReason::kDivisionByZero);
    __ RecordComment("-- Jump to eager deopt");
    __ MacroAssembler::Branch(deopt, less, lhs, Operand(zero_reg));
    __ Move(out, zero_reg);
    return;
  }

  DCHECK(!AreAliased(lhs, rhs));

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);

  Label* deferred_rhs_check = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ negw(rhs, rhs);
        __ MacroAssembler::Branch(*rhs_checked, ne, rhs, Operand(zero_reg));
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ MacroAssembler::Branch(deferred_rhs_check, less_equal, rhs,
                            Operand(zero_reg));
  __ bind(*rhs_checked);

  Label* deferred_lhs_check = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Register out, Int32ModulusWithOverflow* node) {
        MaglevAssembler::TemporaryRegisterScope temps(masm);
        Register lhs_abs = temps.AcquireScratch();
        __ negw(lhs_abs, lhs);
        Register res = lhs_abs;
        __ remw(res, lhs_abs, rhs);
        __ negw(out, res);
        __ MacroAssembler::Branch(*done, ne, res, Operand(zero_reg));
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev
        // only allows one deopt reason per IR.
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, out, this);
  __ MacroAssembler::Branch(deferred_lhs_check, less, lhs, Operand(zero_reg));

  Label rhs_not_power_of_2;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Register msk = temps.AcquireScratch();
  __ Sub32(msk, rhs, Operand(1));
  __ And(scratch, rhs, msk);
  __ MacroAssembler::Branch(&rhs_not_power_of_2, not_equal, scratch,
                            Operand(zero_reg), Label::kNear);
  // {rhs} is power of 2.
  __ And(out, lhs, msk);
  __ MacroAssembler::Branch(*done, Label::kNear);

  __ bind(&rhs_not_power_of_2);
  __ remw(out, lhs, rhs);

  __ bind(*done);
}

#define DEF_BITWISE_BINOP(Instruction, opcode)                   \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    UseRegister(right_input());                                  \
    DefineAsRegister(this);                                      \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register lhs = ToRegister(left_input());                     \
    Register rhs = ToRegister(right_input());                    \
    Register out = ToRegister(result());                         \
    __ opcode(out, lhs, Operand(rhs));                           \
    /* TODO: is zero extension really needed here? */            \
    __ ZeroExtendWord(out, out);                                 \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, And)
DEF_BITWISE_BINOP(Int32BitwiseOr, Or)
DEF_BITWISE_BINOP(Int32BitwiseXor, Xor)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                     \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    if (right_input().node()->Is<Int32Constant>()) {             \
      UseAny(right_input());                                     \
    } else {                                                     \
      UseRegister(right_input());                                \
    }                                                            \
    DefineAsRegister(this);                                      \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register out = ToRegister(result());                         \
    Register lhs = ToRegister(left_input());                     \
    if (Int32Constant* constant =                                \
            right_input().node()->TryCast<Int32Constant>()) {    \
      uint32_t shift = constant->value() & 31;                   \
      if (shift == 0) {                                          \
        __ ZeroExtendWord(out, lhs);                             \
        return;                                                  \
      }                                                          \
      __ opcode(out, lhs, Operand(shift));                       \
    } else {                                                     \
      Register rhs = ToRegister(right_input());                  \
      __ opcode(out, lhs, Operand(rhs));                         \
    }                                                            \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, Sll32)
DEF_SHIFT_BINOP(Int32ShiftRight, Sra32)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, Srl32)
#undef DEF_SHIFT_BINOP

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ not_(out, value);
  __ ZeroExtendWord(out, out);  // TODO(Yuri Gaevsky): is it really needed?
}

void Float64Add::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Add::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fadd_d(out, left, right);
}

void Float64Subtract::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Subtract::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fsub_d(out, left, right);
}

void Float64Multiply::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Multiply::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fmul_d(out, left, right);
}

void Float64Divide::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Divide::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fdiv_d(out, left, right);
}

int Float64Modulus::MaxCallStackArgs() const { return 0; }
void Float64Modulus::SetValueLocationConstraints() {
  UseFixed(left_input(), fa0);
  UseFixed(right_input(), fa1);
  DefineSameAsFirst(this);
}
void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope
### 提示词
```
这是目录为v8/src/maglev/riscv/maglev-ir-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/riscv/maglev-ir-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/riscv/assembler-riscv-inl.h"
#include "src/codegen/riscv/register-riscv.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/maglev/riscv/maglev-assembler-riscv-inl.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/js-function.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

void Int32NegateWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32NegateWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  static_assert(Int32NegateWithOverflow::kProperties.can_eager_deopt());
  // Deopt when result would be -0.
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, equal, value, Operand(zero_reg));

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ neg(scratch, value);
  __ negw(out, value);

  // Are the results of NEG and NEGW on the operand different?
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register out = ToRegister(result());

  static_assert(Int32AbsWithOverflow::kProperties.can_eager_deopt());
  Label done;
  DCHECK(ToRegister(input()) == out);
  // fast-path
  __ MacroAssembler::Branch(&done, greater_equal, out, Operand(zero_reg),
                            Label::Distance::kNear);

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ neg(scratch, out);
  __ negw(out, out);

  // Are the results of NEG and NEGW on the operand different?
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  __ bind(&done);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ Add32(scratch, value, Operand(1));

  static_assert(Int32IncrementWithOverflow::kProperties.can_eager_deopt());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, less, scratch, Operand(value));
  __ Mv(out, scratch);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  __ Sub32(scratch, value, Operand(1));

  static_assert(Int32DecrementWithOverflow::kProperties.can_eager_deopt());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, greater, scratch, Operand(value));
  __ Mv(out, scratch);

  // Output register must not be a register input into the eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

int BuiltinStringFromCharCode::MaxCallStackArgs() const {
  return AllocateDescriptor::GetStackParameterCount();
}
void BuiltinStringFromCharCode::SetValueLocationConstraints() {
  if (code_input().node()->Is<Int32Constant>()) {
    UseAny(code_input());
  } else {
    UseRegister(code_input());
  }
  set_temporaries_needed(2);
  DefineAsRegister(this);
}
void BuiltinStringFromCharCode::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ Move(scratch, char_code);
      __ Sh(scratch, FieldMemOperand(result_string,
                                     OFFSET_OF_DATA_START(SeqTwoByteString)));
    }
  } else {
    __ StringFromCharCode(register_snapshot(), nullptr, result_string,
                          ToRegister(code_input()), scratch,
                          MaglevAssembler::CharCodeMaskMode::kMustApplyMask);
  }
}

void InlinedAllocation::SetValueLocationConstraints() {
  UseRegister(allocation_block());
  if (offset() == 0) {
    DefineSameAsFirst(this);
  } else {
    DefineAsRegister(this);
  }
}

void InlinedAllocation::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register out = ToRegister(result());
  Register value = ToRegister(allocation_block());
  if (offset() != 0) {
    __ AddWord(out, value, Operand(offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register out = ToRegister(result());

  __ LoadWord(out, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub64(out, out, Operand(1));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ LoadWord(length, MemOperand(fp, StandardFrameConstants::kArgCOffset));
  __ Sub64(length, length, Operand(formal_parameter_count() + 1));
  __ MacroAssembler::Branch(&done, greater_equal, length, Operand(zero_reg),
                            Label::Distance::kNear);
  __ Mv(length, zero_reg);
  __ bind(&done);
  __ UncheckedSmiTagInt32(length);
}

int CheckedObjectToIndex::MaxCallStackArgs() const { return 0; }

void Int32AddWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Int32AddWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32AddWithOverflow::kProperties.can_eager_deopt());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ Add64(scratch, left, right);
  __ Add32(out, left, right);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, not_equal, scratch, Operand(out));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}
void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32SubtractWithOverflow::kProperties.can_eager_deopt());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ Sub64(scratch, left, right);
  __ Sub32(out, left, right);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, ne, scratch, Operand(out));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}
void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise multiplication by a constant.

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.Acquire();
  }

  Register scratch = temps.Acquire();
  __ MulOverflow32(res, left, Operand(right), scratch);

  static_assert(Int32MultiplyWithOverflow::kProperties.can_eager_deopt());
  // if res != (res[0:31] sign extended to 64 bits), then the multiplication
  // result is too large for 32 bits.
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
  __ RecordComment("-- Jump to eager deopt");
  __ MacroAssembler::Branch(fail, ne, scratch, Operand(zero_reg));

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ MacroAssembler::Branch(&end, ne, res, Operand(zero_reg),
                            Label::Distance::kNear);
  {
    Register maybeNegative = scratch;
    __ Or(maybeNegative, left, Operand(right));
    // TODO(Vladimir Kempik): consider usage of bexti instruction if Zbs
    // extension is available
    __ And(maybeNegative, maybeNegative, Operand(0x80000000));  // 1 << 31
    // If one of them is negative, we must have a -0 result, which is non-int32,
    // so deopt.
    // TODO(leszeks): Consider splitting these deopts to have distinct deopt
    // reasons. Otherwise, the reason has to match the above.
    __ RecordComment("-- Jump to eager deopt if the result is negative zero");
    Label* deopt_label = __ GetDeoptLabel(this, DeoptimizeReason::kOverflow);
    __ MacroAssembler::Branch(deopt_label, ne, maybeNegative,
                              Operand(zero_reg));
  }

  __ bind(&end);
  if (out_alias_input) {
    __ Move(out, res);
  }

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{out} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}
void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  Register out = ToRegister(result());

  // TODO(leszeks): peephole optimise division by a constant.

  static_assert(Int32DivideWithOverflow::kProperties.can_eager_deopt());
  ZoneLabelRef done(masm);
  Label* deferred_overflow_checks = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register left,
         Register right, Int32DivideWithOverflow* node) {
        // {right} is negative or zero.

        // TODO(leszeks): Using kNotInt32 here, but in same places
        // kDivisionByZerokMinusZero/kMinusZero/kOverflow would be better. Right
        // now all eager deopts in a node have to be the same -- we should allow
        // a node to emit multiple eager deopts with different reasons.
        Label* deopt = __ GetDeoptLabel(node, DeoptimizeReason::kNotInt32);

        // Check if {right} is zero.
        __ RecordComment("-- Jump to eager deopt if right is zero");
        __ MacroAssembler::Branch(deopt, eq, right, Operand(zero_reg));

        // Check if {left} is zero, as that would produce minus zero.
        __ RecordComment("-- Jump to eager deopt if left is zero");
        __ MacroAssembler::Branch(deopt, eq, left, Operand(zero_reg));

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ MacroAssembler::Branch(*done, ne, left, Operand(kMinInt));
        __ MacroAssembler::Branch(*done, ne, right, Operand(-1));
        __ JumpToDeopt(deopt);
      },
      done, left, right, this);

  // Check if {right} is positive and not zero.
  __ MacroAssembler::Branch(deferred_overflow_checks, less_equal, right,
                            Operand(zero_reg));
  __ bind(*done);

  // Perform the actual integer division.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  bool out_alias_input = out == left || out == right;
  Register res = out;
  if (out_alias_input) {
    res = temps.Acquire();
  }
  __ Div32(res, left, right);

  // Check that the remainder is zero.
  Register temp = temps.Acquire();
  __ remw(temp, left, right);
  Label* deopt = __ GetDeoptLabel(this, DeoptimizeReason::kNotInt32);
  __ RecordComment("-- Jump to eager deopt if remainder is zero");
  __ MacroAssembler::Branch(deopt, ne, temp, Operand(zero_reg));

  // The output register shouldn't be a register input into the eager deopt
  // info.
  DCHECK_REGLIST_EMPTY(RegList{res} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ Move(out, res);
}

void Int32ModulusWithOverflow::SetValueLocationConstraints() {
  UseAndClobberRegister(left_input());
  UseAndClobberRegister(right_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void Int32ModulusWithOverflow::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  // If AreAliased(lhs, rhs):
  //   deopt if lhs < 0  // Minus zero.
  //   0
  //
  // Using same algorithm as in EffectControlLinearizer:
  //   if rhs <= 0 then
  //     rhs = -rhs
  //     deopt if rhs == 0
  //   if lhs < 0 then
  //     let lhs_abs = -lhs in
  //     let res = lhs_abs % rhs in
  //     deopt if res == 0
  //     -res
  //   else
  //     let msk = rhs - 1 in
  //     if rhs & msk == 0 then
  //       lhs & msk
  //     else
  //       lhs % rhs

  Register lhs = ToRegister(left_input());
  Register rhs = ToRegister(right_input());
  Register out = ToRegister(result());

  static_assert(Int32ModulusWithOverflow::kProperties.can_eager_deopt());
  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  // For the modulus algorithm described above, lhs and rhs must not alias
  // each other.
  if (lhs == rhs) {
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    Label* deopt = __ GetDeoptLabel(this, DeoptimizeReason::kDivisionByZero);
    __ RecordComment("-- Jump to eager deopt");
    __ MacroAssembler::Branch(deopt, less, lhs, Operand(zero_reg));
    __ Move(out, zero_reg);
    return;
  }

  DCHECK(!AreAliased(lhs, rhs));

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);

  Label* deferred_rhs_check = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ negw(rhs, rhs);
        __ MacroAssembler::Branch(*rhs_checked, ne, rhs, Operand(zero_reg));
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ MacroAssembler::Branch(deferred_rhs_check, less_equal, rhs,
                            Operand(zero_reg));
  __ bind(*rhs_checked);

  Label* deferred_lhs_check = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Register out, Int32ModulusWithOverflow* node) {
        MaglevAssembler::TemporaryRegisterScope temps(masm);
        Register lhs_abs = temps.AcquireScratch();
        __ negw(lhs_abs, lhs);
        Register res = lhs_abs;
        __ remw(res, lhs_abs, rhs);
        __ negw(out, res);
        __ MacroAssembler::Branch(*done, ne, res, Operand(zero_reg));
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev
        // only allows one deopt reason per IR.
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, out, this);
  __ MacroAssembler::Branch(deferred_lhs_check, less, lhs, Operand(zero_reg));

  Label rhs_not_power_of_2;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Register msk = temps.AcquireScratch();
  __ Sub32(msk, rhs, Operand(1));
  __ And(scratch, rhs, msk);
  __ MacroAssembler::Branch(&rhs_not_power_of_2, not_equal, scratch,
                            Operand(zero_reg), Label::kNear);
  // {rhs} is power of 2.
  __ And(out, lhs, msk);
  __ MacroAssembler::Branch(*done, Label::kNear);

  __ bind(&rhs_not_power_of_2);
  __ remw(out, lhs, rhs);

  __ bind(*done);
}

#define DEF_BITWISE_BINOP(Instruction, opcode)                   \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    UseRegister(right_input());                                  \
    DefineAsRegister(this);                                      \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register lhs = ToRegister(left_input());                     \
    Register rhs = ToRegister(right_input());                    \
    Register out = ToRegister(result());                         \
    __ opcode(out, lhs, Operand(rhs));                           \
    /* TODO: is zero extension really needed here? */            \
    __ ZeroExtendWord(out, out);                                 \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, And)
DEF_BITWISE_BINOP(Int32BitwiseOr, Or)
DEF_BITWISE_BINOP(Int32BitwiseXor, Xor)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                     \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    if (right_input().node()->Is<Int32Constant>()) {             \
      UseAny(right_input());                                     \
    } else {                                                     \
      UseRegister(right_input());                                \
    }                                                            \
    DefineAsRegister(this);                                      \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register out = ToRegister(result());                         \
    Register lhs = ToRegister(left_input());                     \
    if (Int32Constant* constant =                                \
            right_input().node()->TryCast<Int32Constant>()) {    \
      uint32_t shift = constant->value() & 31;                   \
      if (shift == 0) {                                          \
        __ ZeroExtendWord(out, lhs);                             \
        return;                                                  \
      }                                                          \
      __ opcode(out, lhs, Operand(shift));                       \
    } else {                                                     \
      Register rhs = ToRegister(right_input());                  \
      __ opcode(out, lhs, Operand(rhs));                         \
    }                                                            \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, Sll32)
DEF_SHIFT_BINOP(Int32ShiftRight, Sra32)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, Srl32)
#undef DEF_SHIFT_BINOP

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineAsRegister(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Register out = ToRegister(result());
  __ not_(out, value);
  __ ZeroExtendWord(out, out);  // TODO(Yuri Gaevsky): is it really needed?
}

void Float64Add::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Add::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fadd_d(out, left, right);
}

void Float64Subtract::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Subtract::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fsub_d(out, left, right);
}

void Float64Multiply::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Multiply::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fmul_d(out, left, right);
}

void Float64Divide::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Divide::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fdiv_d(out, left, right);
}

int Float64Modulus::MaxCallStackArgs() const { return 0; }
void Float64Modulus::SetValueLocationConstraints() {
  UseFixed(left_input(), fa0);
  UseFixed(right_input(), fa1);
  DefineSameAsFirst(this);
}
void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(0, 2);
  __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fneg_d(out, value);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  __ fabs_d(out, in);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  DoubleRegister fscratch1 = temps.AcquireScratchDouble();

  // TODO(Yuri Gaevsky): can we be better here?
  if (kind_ == Kind::kNearest) {
    Register tmp = temps.AcquireScratch();
    DoubleRegister half_one = temps.AcquireDouble();  // available in this mode
    __ Round_d_d(out, in, fscratch1);
    // RISC-V Rounding Mode RNE means "Round to Nearest, ties to Even", while JS
    // expects it to round towards +Infinity (see ECMA-262, 20.2.2.28).
    // Fix the difference by checking if we rounded down by exactly 0.5, and
    // if so, round to the other side.
    DoubleRegister fsubtract = fscratch1;
    __ fmv_d(fsubtract, in);
    __ fsub_d(fsubtract, fsubtract, out);
    __ LoadFPRImmediate(half_one, 0.5);
    __ CompareF64(tmp, FPUCondition::NE, fsubtract, half_one);
    Label done;
    // (in - rounded(in)) != 0.5?
    __ MacroAssembler::Branch(&done, ne, tmp, Operand(zero_reg), Label::kNear);
    // Fix wrong tie-to-even by adding 0.5 twice.
    __ fadd_d(out, out, half_one);
    __ fadd_d(out, out, half_one);
    __ bind(&done);
  } else if (kind_ == Kind::kCeil) {
    __ Ceil_d_d(out, in, fscratch1);
  } else if (kind_ == Kind::kFloor) {
    __ Floor_d_d(out, in, fscratch1);
  } else {
    UNREACHABLE();
  }
}

int Float64Exponentiate::MaxCallStackArgs() const { return 0; }
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), fa0);
  UseFixed(right_input(), fa1);
  DefineSameAsFirst(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(0, 2);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 2);
}

int Float64Ieee754Unary::MaxCallStackArgs() const { return 0; }
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), fa0);
  DefineSameAsFirst(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(0, 1);
  __ CallCFunction(ieee_function_ref(), 1);
}

void LoadTypedArrayLength::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  DefineAsRegister(this);
}
void LoadTypedArrayLength::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  Register result_register = ToRegister(result());
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_TYPED_ARRAY_TYPE,
                        AbortReason::kUnexpectedValue);
  }
  __ LoadBoundedSizeFromObject(result_register, object,
                               JSTypedArray::kRawByteLengthOffset);
  int element_size = ElementsKindSize(elements_kind_);
  if (element_size > 1) {
    // TODO(leszeks): Merge this shift with the one in LoadBoundedSize.
    DCHECK(element_size == 2 || element_size == 4 || element_size == 8);
    __ SrlWord(result_register, result_register,
               Operand(base::bits::CountTrailingZeros(element_size)));
  }
}

int CheckJSDataViewBounds::MaxCallStackArgs() const { return 1; }
void CheckJSDataViewBounds::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  UseRegister(index_input());
  set_temporaries_needed(1);
}
void CheckJSDataViewBounds::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(receiver_input());
  Register index = ToRegister(index_input());
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_DATA_VIEW_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  // Normal DataView (backed by AB / SAB) or non-length tracking backed by GSAB.
  Register byte_length = temps.Acquire();
  __ LoadBoundedSizeFromObject(byte_length, object,
                               JSDataView::kRawByteLengthOffset);

  int element_size = compiler::ExternalArrayElementSize(element_type_);
  Label ok;
  if (element_size > 1) {
    __ SubWord(byte_length, byte_length, Operand(element_size - 1));
    __ MacroAssembler::Branch(&ok, ge, byte_length, Operand(zero_reg),
                              Label::Distance::kNear);
    __ EmitEagerDeopt(this, DeoptimizeReason::kOutOfBounds);
  }
  __ MacroAssembler::Branch(&ok, ult, index, Operand(byte_length),
                            Label::Distance::kNear);
  __ EmitEagerDeopt(this, DeoptimizeReason::kOutOfBounds);

  __ bind(&ok);
}

void HoleyFloat64ToMaybeNanFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void HoleyFloat64ToMaybeNanFloat64::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  // The hole value is a signalling NaN, so just silence it to get the float64
  // value.
  __ FPUCanonicalizeNaN(ToDoubleRegister(result()), ToDoubleRegister(input()));
}

namespace {

enum class ReduceInterruptBudgetType { kLoop, kReturn };

void HandleInterruptsAndTiering(MaglevAssembler* masm, ZoneLabelRef done,
                                Node* node, ReduceInterruptBudgetType type,
                                Register scratch0) {
  // For loops, first check for interrupts. Don't do this for returns, as we
  // can't lazy deopt to the end of a return.
  if (type == ReduceInterruptBudgetType::kLoop) {
    Label next;
    // Here, we only care about interrupts since we've already guarded against
    // real stack overflows on function entry.
    {
      Register stack_limit = scratch0;
      __ LoadStackLimit(stack_limit, StackLimitKind::kInterruptStackLimit);
      __ MacroAssembler::Branch(&next, ugt, sp, Operand(stack_limit),
                                Label::Distance::kNear);
    }

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      Register function = scratch0;
      __ LoadWord(function,
                  MemOperand(fp, StandardFrameConstants::kFunctionOffset));
      __ Push(function);
      // Move into kContextRegister after the load into scratch0, just in case
      // scratch0 happens to be kContextRegister.
      __ Move(kContextRegister, masm->native_context().object());
      __ CallRuntime(Runtime::kBytecodeBudgetInterruptWithStackCheck_Maglev, 1);
      save_register_state.DefineSafepointWithLazyDeopt(node->lazy_deopt_info());
    }
    __ MacroAssembler::Branch(*done);  // All done, continue.
    __ bind(&next);
  }

  // No pending interrupts. Call into the TieringManager if needed.
  {
    SaveRegisterStateForCall save_register_state(masm,
                                                 node->register_snapshot());
    Register function = scratch0;
    __ LoadWord(function,
                MemOperand(fp, StandardFrameConstants::kFunctionOffset));
    __ Push(function);
    // Move into kContextRegister
```