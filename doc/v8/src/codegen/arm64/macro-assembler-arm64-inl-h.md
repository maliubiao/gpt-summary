Response:
Let's break down the thought process for summarizing the provided C++ header file.

1. **Initial Scan and Goal Recognition:** The first step is to quickly scan the file and recognize its purpose. The filename `macro-assembler-arm64-inl.h` strongly suggests this is related to generating ARM64 assembly code within the V8 JavaScript engine. The `.inl` suffix typically means it contains inline implementations of methods declared in a corresponding `.h` file. The goal is to understand the *functionality* it provides.

2. **Identify Key Code Structures:**  Look for recurring patterns and important structures. In this file, several patterns stand out:
    * **`MacroAssembler::...` Function Definitions:**  The majority of the file is filled with definitions of methods belonging to the `MacroAssembler` class. This immediately tells us that this file *implements* the higher-level assembly instructions.
    * **`DCHECK(...)` Calls:**  These are assertions, indicating preconditions and sanity checks within the code. They aren't core functionality but provide insight into how the functions are *intended* to be used. For instance, `DCHECK(!rd.IsZero())` suggests that many operations don't work with the zero register.
    * **Calls to Lower-Level Functions:**  Observe calls to functions like `LogicalMacro`, `DataProcImmediate`, `LoadStoreMacro`, `b`, `bl`, etc. These are likely the *actual* assembly instruction emitters, defined in `assembler-arm64.h` or similar. The `macro-assembler-arm64-inl.h` acts as a convenient wrapper.
    * **`MemOperand` Usage:**  The `FieldMemOperand`, `ExitFrameStackSlotOperand`, and `ExitFrameCallerStackSlotOperand` functions indicate ways to access memory, particularly within the context of V8's object model and stack frames.
    * **Conditional Logic (`if` statements):**  Notice the conditional logic within functions like `Add`, `Sub`, `Cmp`, and `Ccmp`. This often involves handling immediate values and choosing the most efficient instruction.
    * **Macros (`DEFINE_FUNCTION`, `LS_MACRO_LIST`, etc.):**  The use of macros suggests a systematic way of defining related functions, often for different data sizes or access modes.

3. **Categorize Functionality by Instruction Type:**  Group the defined `MacroAssembler` methods by the type of assembly instruction they represent:
    * **Logical Operations:** `And`, `Orr`, `Eor`, `Tst`, `Bic`, etc.
    * **Arithmetic Operations:** `Add`, `Sub`, `Mul`, `Div`, `Neg`, `Adc`, `Sbc`, etc.
    * **Comparison Operations:** `Cmp`, `Tst`, `Ccmp`, `Ccmn`.
    * **Memory Access (Load/Store):** `Ldr`, `Str`, `Ldp`, `Stp`, `Lda`, `Stl`, `Cas`, `Swp`.
    * **Branching:** `B`, `Bl`, `Br`, `Blr`, `Ret`.
    * **Conditional Execution:** Functions taking a `Condition` argument like `B(Condition, Label*)`, `Cinc`, `Csel`.
    * **Bit Manipulation:** `Asr`, `Lsl`, `Lsr`, `Ror`, `Bfi`, `Sbfx`, `Ubfiz`.
    * **Floating-Point Operations:**  Functions starting with `F` like `Fadd`, `Fmul`, `Fcmp`, `Fmov`, `Fcvt`.
    * **System Instructions:** `Mrs`, `Msr`, `Dmb`, `Dsb`, `Isb`, `Hint`.
    * **Debugging/Breakpoints:** `Brk`, `Debug`.
    * **Atomic Operations:** Functions starting with `Lda`, `Stl`, `Cas`, `Swp`, and those in `ATOMIC_MEMORY_SIMPLE_MACRO_LIST`.
    * **Call Frame Management:**  `ExitFrameStackSlotOperand`, `ExitFrameCallerStackSlotOperand`.
    * **Code Labels and Targets:** `Bind`, `CodeEntry`, `ExceptionHandler`, `JumpTarget`, `CallTarget`.

4. **Infer Overall Purpose and Abstraction Level:**  Realize that `macro-assembler-arm64-inl.h` provides a *higher-level abstraction* over raw ARM64 assembly. It offers more convenient functions (macros) that often translate into one or more actual assembly instructions. This makes generating assembly code within V8 easier and less error-prone.

5. **Address Specific Questions in the Prompt:** Go back to the prompt and ensure all questions are answered:
    * **List of functionalities:** This is the categorized list from step 3.
    * **`.tq` extension:**  The file ends in `.h`, so it's not a Torque file.
    * **Relationship to JavaScript:** Since it's part of V8's codegen, it's directly responsible for generating the machine code that executes JavaScript. Provide a simple example of how a JavaScript operation might translate to assembly.
    * **Code logic reasoning:** Focus on simple cases like `Add` and `Sub` where immediate values are handled. Provide a clear input and output example.
    * **Common programming errors:** Think about typical mistakes when working with assembly or low-level code, like incorrect register usage or memory access.
    * **Summary of functionality:** Condense the findings into a concise summary statement.

6. **Refine and Organize:**  Structure the answer logically with clear headings and bullet points. Use precise language and avoid jargon where possible. Ensure the explanation is understandable to someone with a basic understanding of compilers and assembly. For example, instead of just saying "memory access," specify "loading and storing data."

7. **Self-Correction/Review:** Before submitting, reread the answer and check for accuracy and completeness. Did you miss any major functionalities? Is the explanation clear and concise?  Are the examples accurate?  For instance, initially, I might have just listed all the function names. But then I'd realize the value in *categorizing* them for better understanding. I would also double-check my JavaScript and assembly examples for correctness.

By following these steps, we can systematically analyze the C++ header file and provide a comprehensive and informative summary of its functionalities.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_INL_H_
#define V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_INL_H_

#include <ctype.h>

#include "src/base/bits.h"
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/globals.h"
#include "src/execution/isolate-data.h"

namespace v8 {
namespace internal {

MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

// Provides access to exit frame parameters (GC-ed).
MemOperand ExitFrameStackSlotOperand(int offset) {
  // The slot at [sp] is reserved in all ExitFrames for storing the return
  // address before doing the actual call, it's necessary for frame iteration
  // (see StoreReturnAddressAndCall for details).
  static constexpr int kSPOffset = 1 * kSystemPointerSize;
  return MemOperand(sp, kSPOffset + offset);
}

// Provides access to exit frame parameters (GC-ed).
MemOperand ExitFrameCallerStackSlotOperand(int index) {
  return MemOperand(fp, (ExitFrameConstants::kFixedSlotCountAboveFp + index) *
                            kSystemPointerSize);
}

void MacroAssembler::And(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, AND);
}

void MacroAssembler::Ands(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ANDS);
}

void MacroAssembler::Tst(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  LogicalMacro(AppropriateZeroRegFor(rn), rn, operand, ANDS);
}

void MacroAssembler::Bic(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, BIC);
}

void MacroAssembler::Bics(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, BICS);
}

void MacroAssembler::Orr(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ORR);
}

void MacroAssembler::Orn(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ORN);
}

void MacroAssembler::Eor(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, EOR);
}

void MacroAssembler::Eon(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, EON);
}

void MacroAssembler::Ccmp(const Register& rn, const Operand& operand,
                          StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0)) {
    ConditionalCompareMacro(rn, -operand.ImmediateValue(), nzcv, cond, CCMN);
  } else {
    ConditionalCompareMacro(rn, operand, nzcv, cond, CCMP);
  }
}

void MacroAssembler::CcmpTagged(const Register& rn, const Operand& operand,
                                StatusFlags nzcv, Condition cond) {
  if (COMPRESS_POINTERS_BOOL) {
    Ccmp(rn.W(), operand.ToW(), nzcv, cond);
  } else {
    Ccmp(rn, operand, nzcv, cond);
  }
}

void MacroAssembler::Ccmn(const Register& rn, const Operand& operand,
                          StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0)) {
    ConditionalCompareMacro(rn, -operand.ImmediateValue(), nzcv, cond, CCMP);
  } else {
    ConditionalCompareMacro(rn, operand, nzcv, cond, CCMN);
  }
}

void MacroAssembler::Add(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate()) {
    int64_t imm = operand.ImmediateValue();
    if ((imm > 0) && IsImmAddSub(imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(imm), ADD);
      return;
    } else if ((imm < 0) && IsImmAddSub(-imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(-imm), SUB);
      return;
    }
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() == 0)) {
    if (!rd.IsSP() && !rn.IsSP() && !operand.reg().IsSP() &&
        !operand.reg().IsZero()) {
      DataProcPlainRegister(rd, rn, operand.reg(), ADD);
      return;
    }
  }
  AddSubMacro(rd, rn, operand, LeaveFlags, ADD);
}

void MacroAssembler::Adds(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0) &&
      IsImmAddSub(-operand.ImmediateValue())) {
    AddSubMacro(rd, rn, -operand.ImmediateValue(), SetFlags, SUB);
  } else {
    AddSubMacro(rd, rn, operand, SetFlags, ADD);
  }
}

void MacroAssembler::Sub(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate()) {
    int64_t imm = operand.ImmediateValue();
    if ((imm > 0) && IsImmAddSub(imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(imm), SUB);
      return;
    } else if ((imm < 0) && IsImmAddSub(-imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(-imm), ADD);
      return;
    }
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() == 0)) {
    if (!rd.IsSP() && !rn.IsSP() && !operand.reg().IsSP() &&
        !operand.reg().IsZero()) {
      DataProcPlainRegister(rd, rn, operand.reg(), SUB);
      return;
    }
  }
  AddSubMacro(rd, rn, operand, LeaveFlags, SUB);
}

void MacroAssembler::Subs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0) &&
      IsImmAddSub(-operand.ImmediateValue())) {
    AddSubMacro(rd, rn, -operand.ImmediateValue(), SetFlags, ADD);
  } else {
    AddSubMacro(rd, rn, operand, SetFlags, SUB);
  }
}

void MacroAssembler::Cmn(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  Adds(AppropriateZeroRegFor(rn), rn, operand);
}

void MacroAssembler::Cmp(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsShiftedRegister() && operand.shift_amount() == 0) {
    if (!rn.IsSP() && !operand.reg().IsSP()) {
      CmpPlainRegister(rn, operand.reg());
      return;
    }
  }
  Subs(AppropriateZeroRegFor(rn), rn, operand);
}

void MacroAssembler::CmpTagged(const Register& rn, const Operand& operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Cmp(rn.W(), operand.ToW());
  } else {
    Cmp(rn, operand);
  }
}

void MacroAssembler::Neg(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  if (operand.IsImmediate()) {
    Mov(rd, -operand.ImmediateValue());
  } else {
    Sub(rd, AppropriateZeroRegFor(rd), operand);
  }
}

void MacroAssembler::Negs(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  Subs(rd, AppropriateZeroRegFor(rd), operand);
}

void MacroAssembler::Adc(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, LeaveFlags, ADC);
}

void MacroAssembler::Adcs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, SetFlags, ADC);
}

void MacroAssembler::Sbc(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, LeaveFlags, SBC);
}

void MacroAssembler::Sbcs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, SetFlags, SBC);
}

void MacroAssembler::Ngc(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Register zr = AppropriateZeroRegFor(rd);
  Sbc(rd, zr, operand);
}

void MacroAssembler::Ngcs(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Register zr = AppropriateZeroRegFor(rd);
  Sbcs(rd, zr, operand);
}

void MacroAssembler::Mvn(const Register& rd, uint64_t imm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Mov(rd, ~imm);
}

#define DEFINE_FUNCTION(FN, REGTYPE, REG, OP)                          \
  void MacroAssembler::FN(const REGTYPE REG, const MemOperand& addr) { \
    DCHECK(allow_macro_instructions());                                \
    LoadStoreMacro(REG, addr, OP);                                     \
  }
LS_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, REGTYPE, REG, REG2, OP)              \
  void MacroAssembler::FN(const REGTYPE REG, const REGTYPE REG2, \
                          const MemOperand& addr) {              \
    DCHECK(allow_macro_instructions());                          \
    LoadStorePairMacro(REG, REG2, addr, OP);                     \
  }
LSPAIR_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                     \
  void MacroAssembler::FN(const Register& rt, const Register& rn) { \
    DCHECK(allow_macro_instructions());                             \
    OP(rt, rn);                                                     \
  }
LDA_STL_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                   \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const Register& rn) {                   \
    DCHECK(allow_macro_instructions());                           \
    OP(rs, rt, rn);                                               \
  }
STLX_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                   \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions());                           \
    OP(rs, rt, src);                                              \
  }
CAS_SINGLE_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                    \
  void MacroAssembler::FN(const Register& rs, const Register& rs2, \
                          const Register& rt, const Register& rt2, \
                          const MemOperand& src) {                 \
    DCHECK(allow_macro_instructions());                            \
    OP(rs, rs2, rt, rt2, src);                                     \
  }
CAS_PAIR_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_LOAD_FUNCTION(FN, OP)                              \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions_);                            \
    OP(rs, rt, src);                                              \
  }
#define DEFINE_STORE_FUNCTION(FN, OP)                                  \
  void MacroAssembler::FN(const Register& rs, const MemOperand& src) { \
    DCHECK(allow_macro_instructions_);                                 \
    OP(rs, src);                                                       \
  }

ATOMIC_MEMORY_SIMPLE_MACRO_LIST(ATOMIC_MEMORY_LOAD_MACRO_MODES,
                                DEFINE_LOAD_FUNCTION, Ld, ld)
ATOMIC_MEMORY_SIMPLE_MACRO_LIST(ATOMIC_MEMORY_STORE_MACRO_MODES,
                                DEFINE_STORE_FUNCTION, St, st)

#define DEFINE_SWP_FUNCTION(FN, OP)                               \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions_);                            \
    OP(rs, rt, src);                                              \
  }

ATOMIC_MEMORY_LOAD_MACRO_MODES(DEFINE_SWP_FUNCTION, Swp, swp)

void MacroAssembler::Asr(const Register& rd, const Register& rn,
                         unsigned shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  asr(rd, rn, shift);
}

void MacroAssembler::Asr(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  asrv(rd, rn, rm);
}

void MacroAssembler::B(Label* label) {
  DCHECK(allow_macro_instructions());
  b(label);
  CheckVeneerPool(false, false);
}

void MacroAssembler::B(Condition cond, Label* label) {
  DCHECK(allow_macro_instructions());
  B(label, cond);
}

void MacroAssembler::Bfi(const Register& rd, const Register& rn, unsigned lsb,
                         unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  bfi(rd, rn, lsb, width);
}

void MacroAssembler::Bfxil(const Register& rd, const Register& rn, unsigned lsb,
                           unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  bfxil(rd, rn, lsb, width);
}

void MacroAssembler::Bind(Label* label, BranchTargetIdentifier id) {
  DCHECK(allow_macro_instructions());
  if (id == BranchTargetIdentifier::kNone) {
    bind(label);
  } else {
    // Emit this inside an InstructionAccurateScope to ensure there are no extra
    // instructions between the bind and the target identifier instruction.
    InstructionAccurateScope scope(this, 1);
    bind(label);
    if (id == BranchTargetIdentifier::kPacibsp) {
      pacibsp();
    } else {
      bti(id);
    }
  }
}

void MacroAssembler::CodeEntry() { CallTarget(); }

void MacroAssembler::ExceptionHandler() { JumpTarget(); }

void MacroAssembler::BindExceptionHandler(Label* label) {
  BindJumpTarget(label);
}

void MacroAssembler::JumpTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiJump);
#endif
}

void MacroAssembler::BindJumpTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiJump);
#else
  Bind(label);
#endif
}

void MacroAssembler::CallTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiCall);
#endif
}

void MacroAssembler::JumpOrCallTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiJumpCall);
#endif
}

void MacroAssembler::BindCallTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiCall);
#else
  Bind(label);
#endif
}

void MacroAssembler::BindJumpOrCallTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiJumpCall);
#else
  Bind(label);
#endif
}

void MacroAssembler::Bl(Label* label) {
  DCHECK(allow_macro_instructions());
  bl(label);
}

void MacroAssembler::Blr(const Register& xn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!xn.IsZero());
  blr(xn);
}

void MacroAssembler::Br(const Register& xn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!xn.IsZero());
  br(xn);
}

void MacroAssembler::Brk(int code) {
  DCHECK(allow_macro_instructions());
  brk(code);
}

void MacroAssembler::Cinc(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cinc(rd, rn, cond);
}

void MacroAssembler::Cinv(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cinv(rd, rn, cond);
}

void MacroAssembler::Cls(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  cls(rd, rn);
}

void MacroAssembler::Clz(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  clz(rd, rn);
}

void MacroAssembler::Cneg(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cneg(rd, rn, cond);
}

// Conditionally zero the destination register. Only X registers are supported
// due to the truncation side-effect when used on W registers.
void MacroAssembler::CzeroX(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsSP() && rd.Is64Bits());
  DCHECK((cond != al) && (cond != nv));
  csel(rd, xzr, rd, cond);
}

// Conditionally move a value into the destination register. Only X registers
// are supported due to the truncation side-effect when used on W registers.
void MacroAssembler::CmovX(const Register& rd, const Register& rn,
                           Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsSP());
  DCHECK(rd.Is64Bits() && rn.Is64Bits());
  DCHECK((cond != al) && (cond != nv));
  if (rd != rn) {
    csel(rd, rn, rd, cond);
  }
}

void MacroAssembler::Csdb() {
  DCHECK(allow_macro_instructions());
  csdb();
}

void MacroAssembler::Cset(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cset(rd, cond);
}

void MacroAssembler::Csetm(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csetm(rd, cond);
}

void MacroAssembler::Csinc(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csinc(rd, rn, rm, cond);
}

void MacroAssembler::Csinv(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csinv(rd, rn, rm, cond);
}

void MacroAssembler::Csneg(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csneg(rd, rn, rm, cond);
}

void MacroAssembler::Dmb(BarrierDomain domain, BarrierType type) {
  DCHECK(allow_macro_instructions());
  dmb(domain, type);
}

void MacroAssembler::Dsb(BarrierDomain domain, BarrierType type) {
  DCHECK(allow_macro_instructions());
  dsb(domain, type);
}

void MacroAssembler::Debug(const char* message, uint32_t code, Instr params) {
  DCHECK(allow_macro_instructions());
  debug(message, code, params);
}

void MacroAssembler::Extr(const Register& rd, const Register& rn,
                          const Register& rm, unsigned lsb) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  extr(rd, rn, rm, lsb);
}

void MacroAssembler::Fabs(const VRegister& fd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  fabs(fd, fn);
}

void MacroAssembler::Fadd(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fadd(fd, fn, fm);
}

void MacroAssembler::Fccmp(const VRegister& fn, const VRegister& fm,
                           StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));
  fccmp(fn, fm, nzcv, cond);
}

void MacroAssembler::Fccmp(const VRegister& fn, const double value,
                           StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  UseScratchRegisterScope temps(this);
  VRegister tmp = temps.AcquireSameSizeAs(fn);
  Fmov(tmp, value);
  Fccmp(fn, tmp, nzcv, cond);
}

void MacroAssembler::Fcmp(const VRegister& fn, const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fcmp(fn, fm);
}

void MacroAssembler::Fcmp(const VRegister& fn, double value) {
  DCHECK(allow_macro_instructions());
  if (value != 0.0) {
    UseScratchRegisterScope temps(this);
    VRegister tmp = temps.AcquireSameSizeAs(fn);
    Fmov(tmp, value);
    fcmp(fn, tmp);
  } else {
    fcmp(fn, value);
  }
}

void MacroAssembler::Fcsel(const VRegister& fd, const VRegister& fn,
                           const VRegister& fm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));
  fcsel(fd, fn, fm, cond);
}

void MacroAssembler::Fcvt(const VRegister& fd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  fcvt(fd, fn);
}

void MacroAssembler::Fcvtas(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtas(rd, fn);
}

void MacroAssembler::Fcvtau(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtau(rd, fn);
}

void MacroAssembler::Fcvtms(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtms(rd, fn);
}

void MacroAssembler::Fcvtmu(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtmu(rd, fn);
}

void MacroAssembler::Fcvtns(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtns(rd, fn);
}

void MacroAssembler::Fcvtnu(const Register& rd, const VRegister& fn) {
  
### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_INL_H_
#define V8_CODEGEN_ARM64_MACRO_ASSEMBLER_ARM64_INL_H_

#include <ctype.h>

#include "src/base/bits.h"
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/globals.h"
#include "src/execution/isolate-data.h"

namespace v8 {
namespace internal {

MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

// Provides access to exit frame parameters (GC-ed).
MemOperand ExitFrameStackSlotOperand(int offset) {
  // The slot at [sp] is reserved in all ExitFrames for storing the return
  // address before doing the actual call, it's necessary for frame iteration
  // (see StoreReturnAddressAndCall for details).
  static constexpr int kSPOffset = 1 * kSystemPointerSize;
  return MemOperand(sp, kSPOffset + offset);
}

// Provides access to exit frame parameters (GC-ed).
MemOperand ExitFrameCallerStackSlotOperand(int index) {
  return MemOperand(fp, (ExitFrameConstants::kFixedSlotCountAboveFp + index) *
                            kSystemPointerSize);
}

void MacroAssembler::And(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, AND);
}

void MacroAssembler::Ands(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ANDS);
}

void MacroAssembler::Tst(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  LogicalMacro(AppropriateZeroRegFor(rn), rn, operand, ANDS);
}

void MacroAssembler::Bic(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, BIC);
}

void MacroAssembler::Bics(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, BICS);
}

void MacroAssembler::Orr(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ORR);
}

void MacroAssembler::Orn(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, ORN);
}

void MacroAssembler::Eor(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, EOR);
}

void MacroAssembler::Eon(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  LogicalMacro(rd, rn, operand, EON);
}

void MacroAssembler::Ccmp(const Register& rn, const Operand& operand,
                          StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0)) {
    ConditionalCompareMacro(rn, -operand.ImmediateValue(), nzcv, cond, CCMN);
  } else {
    ConditionalCompareMacro(rn, operand, nzcv, cond, CCMP);
  }
}

void MacroAssembler::CcmpTagged(const Register& rn, const Operand& operand,
                                StatusFlags nzcv, Condition cond) {
  if (COMPRESS_POINTERS_BOOL) {
    Ccmp(rn.W(), operand.ToW(), nzcv, cond);
  } else {
    Ccmp(rn, operand, nzcv, cond);
  }
}

void MacroAssembler::Ccmn(const Register& rn, const Operand& operand,
                          StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0)) {
    ConditionalCompareMacro(rn, -operand.ImmediateValue(), nzcv, cond, CCMP);
  } else {
    ConditionalCompareMacro(rn, operand, nzcv, cond, CCMN);
  }
}

void MacroAssembler::Add(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate()) {
    int64_t imm = operand.ImmediateValue();
    if ((imm > 0) && IsImmAddSub(imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(imm), ADD);
      return;
    } else if ((imm < 0) && IsImmAddSub(-imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(-imm), SUB);
      return;
    }
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() == 0)) {
    if (!rd.IsSP() && !rn.IsSP() && !operand.reg().IsSP() &&
        !operand.reg().IsZero()) {
      DataProcPlainRegister(rd, rn, operand.reg(), ADD);
      return;
    }
  }
  AddSubMacro(rd, rn, operand, LeaveFlags, ADD);
}

void MacroAssembler::Adds(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0) &&
      IsImmAddSub(-operand.ImmediateValue())) {
    AddSubMacro(rd, rn, -operand.ImmediateValue(), SetFlags, SUB);
  } else {
    AddSubMacro(rd, rn, operand, SetFlags, ADD);
  }
}

void MacroAssembler::Sub(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate()) {
    int64_t imm = operand.ImmediateValue();
    if ((imm > 0) && IsImmAddSub(imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(imm), SUB);
      return;
    } else if ((imm < 0) && IsImmAddSub(-imm)) {
      DataProcImmediate(rd, rn, static_cast<int>(-imm), ADD);
      return;
    }
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() == 0)) {
    if (!rd.IsSP() && !rn.IsSP() && !operand.reg().IsSP() &&
        !operand.reg().IsZero()) {
      DataProcPlainRegister(rd, rn, operand.reg(), SUB);
      return;
    }
  }
  AddSubMacro(rd, rn, operand, LeaveFlags, SUB);
}

void MacroAssembler::Subs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsImmediate() && (operand.ImmediateValue() < 0) &&
      IsImmAddSub(-operand.ImmediateValue())) {
    AddSubMacro(rd, rn, -operand.ImmediateValue(), SetFlags, ADD);
  } else {
    AddSubMacro(rd, rn, operand, SetFlags, SUB);
  }
}

void MacroAssembler::Cmn(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  Adds(AppropriateZeroRegFor(rn), rn, operand);
}

void MacroAssembler::Cmp(const Register& rn, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  if (operand.IsShiftedRegister() && operand.shift_amount() == 0) {
    if (!rn.IsSP() && !operand.reg().IsSP()) {
      CmpPlainRegister(rn, operand.reg());
      return;
    }
  }
  Subs(AppropriateZeroRegFor(rn), rn, operand);
}

void MacroAssembler::CmpTagged(const Register& rn, const Operand& operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Cmp(rn.W(), operand.ToW());
  } else {
    Cmp(rn, operand);
  }
}

void MacroAssembler::Neg(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  if (operand.IsImmediate()) {
    Mov(rd, -operand.ImmediateValue());
  } else {
    Sub(rd, AppropriateZeroRegFor(rd), operand);
  }
}

void MacroAssembler::Negs(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  Subs(rd, AppropriateZeroRegFor(rd), operand);
}

void MacroAssembler::Adc(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, LeaveFlags, ADC);
}

void MacroAssembler::Adcs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, SetFlags, ADC);
}

void MacroAssembler::Sbc(const Register& rd, const Register& rn,
                         const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, LeaveFlags, SBC);
}

void MacroAssembler::Sbcs(const Register& rd, const Register& rn,
                          const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  AddSubWithCarryMacro(rd, rn, operand, SetFlags, SBC);
}

void MacroAssembler::Ngc(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Register zr = AppropriateZeroRegFor(rd);
  Sbc(rd, zr, operand);
}

void MacroAssembler::Ngcs(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Register zr = AppropriateZeroRegFor(rd);
  Sbcs(rd, zr, operand);
}

void MacroAssembler::Mvn(const Register& rd, uint64_t imm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  Mov(rd, ~imm);
}

#define DEFINE_FUNCTION(FN, REGTYPE, REG, OP)                          \
  void MacroAssembler::FN(const REGTYPE REG, const MemOperand& addr) { \
    DCHECK(allow_macro_instructions());                                \
    LoadStoreMacro(REG, addr, OP);                                     \
  }
LS_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, REGTYPE, REG, REG2, OP)              \
  void MacroAssembler::FN(const REGTYPE REG, const REGTYPE REG2, \
                          const MemOperand& addr) {              \
    DCHECK(allow_macro_instructions());                          \
    LoadStorePairMacro(REG, REG2, addr, OP);                     \
  }
LSPAIR_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                     \
  void MacroAssembler::FN(const Register& rt, const Register& rn) { \
    DCHECK(allow_macro_instructions());                             \
    OP(rt, rn);                                                     \
  }
LDA_STL_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                   \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const Register& rn) {                   \
    DCHECK(allow_macro_instructions());                           \
    OP(rs, rt, rn);                                               \
  }
STLX_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                   \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions());                           \
    OP(rs, rt, src);                                              \
  }
CAS_SINGLE_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_FUNCTION(FN, OP)                                    \
  void MacroAssembler::FN(const Register& rs, const Register& rs2, \
                          const Register& rt, const Register& rt2, \
                          const MemOperand& src) {                 \
    DCHECK(allow_macro_instructions());                            \
    OP(rs, rs2, rt, rt2, src);                                     \
  }
CAS_PAIR_MACRO_LIST(DEFINE_FUNCTION)
#undef DEFINE_FUNCTION

#define DEFINE_LOAD_FUNCTION(FN, OP)                              \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions_);                            \
    OP(rs, rt, src);                                              \
  }
#define DEFINE_STORE_FUNCTION(FN, OP)                                  \
  void MacroAssembler::FN(const Register& rs, const MemOperand& src) { \
    DCHECK(allow_macro_instructions_);                                 \
    OP(rs, src);                                                       \
  }

ATOMIC_MEMORY_SIMPLE_MACRO_LIST(ATOMIC_MEMORY_LOAD_MACRO_MODES,
                                DEFINE_LOAD_FUNCTION, Ld, ld)
ATOMIC_MEMORY_SIMPLE_MACRO_LIST(ATOMIC_MEMORY_STORE_MACRO_MODES,
                                DEFINE_STORE_FUNCTION, St, st)

#define DEFINE_SWP_FUNCTION(FN, OP)                               \
  void MacroAssembler::FN(const Register& rs, const Register& rt, \
                          const MemOperand& src) {                \
    DCHECK(allow_macro_instructions_);                            \
    OP(rs, rt, src);                                              \
  }

ATOMIC_MEMORY_LOAD_MACRO_MODES(DEFINE_SWP_FUNCTION, Swp, swp)

void MacroAssembler::Asr(const Register& rd, const Register& rn,
                         unsigned shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  asr(rd, rn, shift);
}

void MacroAssembler::Asr(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  asrv(rd, rn, rm);
}

void MacroAssembler::B(Label* label) {
  DCHECK(allow_macro_instructions());
  b(label);
  CheckVeneerPool(false, false);
}

void MacroAssembler::B(Condition cond, Label* label) {
  DCHECK(allow_macro_instructions());
  B(label, cond);
}

void MacroAssembler::Bfi(const Register& rd, const Register& rn, unsigned lsb,
                         unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  bfi(rd, rn, lsb, width);
}

void MacroAssembler::Bfxil(const Register& rd, const Register& rn, unsigned lsb,
                           unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  bfxil(rd, rn, lsb, width);
}

void MacroAssembler::Bind(Label* label, BranchTargetIdentifier id) {
  DCHECK(allow_macro_instructions());
  if (id == BranchTargetIdentifier::kNone) {
    bind(label);
  } else {
    // Emit this inside an InstructionAccurateScope to ensure there are no extra
    // instructions between the bind and the target identifier instruction.
    InstructionAccurateScope scope(this, 1);
    bind(label);
    if (id == BranchTargetIdentifier::kPacibsp) {
      pacibsp();
    } else {
      bti(id);
    }
  }
}

void MacroAssembler::CodeEntry() { CallTarget(); }

void MacroAssembler::ExceptionHandler() { JumpTarget(); }

void MacroAssembler::BindExceptionHandler(Label* label) {
  BindJumpTarget(label);
}

void MacroAssembler::JumpTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiJump);
#endif
}

void MacroAssembler::BindJumpTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiJump);
#else
  Bind(label);
#endif
}

void MacroAssembler::CallTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiCall);
#endif
}

void MacroAssembler::JumpOrCallTarget() {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  bti(BranchTargetIdentifier::kBtiJumpCall);
#endif
}

void MacroAssembler::BindCallTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiCall);
#else
  Bind(label);
#endif
}

void MacroAssembler::BindJumpOrCallTarget(Label* label) {
#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  Bind(label, BranchTargetIdentifier::kBtiJumpCall);
#else
  Bind(label);
#endif
}

void MacroAssembler::Bl(Label* label) {
  DCHECK(allow_macro_instructions());
  bl(label);
}

void MacroAssembler::Blr(const Register& xn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!xn.IsZero());
  blr(xn);
}

void MacroAssembler::Br(const Register& xn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!xn.IsZero());
  br(xn);
}

void MacroAssembler::Brk(int code) {
  DCHECK(allow_macro_instructions());
  brk(code);
}

void MacroAssembler::Cinc(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cinc(rd, rn, cond);
}

void MacroAssembler::Cinv(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cinv(rd, rn, cond);
}

void MacroAssembler::Cls(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  cls(rd, rn);
}

void MacroAssembler::Clz(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  clz(rd, rn);
}

void MacroAssembler::Cneg(const Register& rd, const Register& rn,
                          Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cneg(rd, rn, cond);
}

// Conditionally zero the destination register. Only X registers are supported
// due to the truncation side-effect when used on W registers.
void MacroAssembler::CzeroX(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsSP() && rd.Is64Bits());
  DCHECK((cond != al) && (cond != nv));
  csel(rd, xzr, rd, cond);
}

// Conditionally move a value into the destination register. Only X registers
// are supported due to the truncation side-effect when used on W registers.
void MacroAssembler::CmovX(const Register& rd, const Register& rn,
                           Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsSP());
  DCHECK(rd.Is64Bits() && rn.Is64Bits());
  DCHECK((cond != al) && (cond != nv));
  if (rd != rn) {
    csel(rd, rn, rd, cond);
  }
}

void MacroAssembler::Csdb() {
  DCHECK(allow_macro_instructions());
  csdb();
}

void MacroAssembler::Cset(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  cset(rd, cond);
}

void MacroAssembler::Csetm(const Register& rd, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csetm(rd, cond);
}

void MacroAssembler::Csinc(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csinc(rd, rn, rm, cond);
}

void MacroAssembler::Csinv(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csinv(rd, rn, rm, cond);
}

void MacroAssembler::Csneg(const Register& rd, const Register& rn,
                           const Register& rm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  csneg(rd, rn, rm, cond);
}

void MacroAssembler::Dmb(BarrierDomain domain, BarrierType type) {
  DCHECK(allow_macro_instructions());
  dmb(domain, type);
}

void MacroAssembler::Dsb(BarrierDomain domain, BarrierType type) {
  DCHECK(allow_macro_instructions());
  dsb(domain, type);
}

void MacroAssembler::Debug(const char* message, uint32_t code, Instr params) {
  DCHECK(allow_macro_instructions());
  debug(message, code, params);
}

void MacroAssembler::Extr(const Register& rd, const Register& rn,
                          const Register& rm, unsigned lsb) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  extr(rd, rn, rm, lsb);
}

void MacroAssembler::Fabs(const VRegister& fd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  fabs(fd, fn);
}

void MacroAssembler::Fadd(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fadd(fd, fn, fm);
}

void MacroAssembler::Fccmp(const VRegister& fn, const VRegister& fm,
                           StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));
  fccmp(fn, fm, nzcv, cond);
}

void MacroAssembler::Fccmp(const VRegister& fn, const double value,
                           StatusFlags nzcv, Condition cond) {
  DCHECK(allow_macro_instructions());
  UseScratchRegisterScope temps(this);
  VRegister tmp = temps.AcquireSameSizeAs(fn);
  Fmov(tmp, value);
  Fccmp(fn, tmp, nzcv, cond);
}

void MacroAssembler::Fcmp(const VRegister& fn, const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fcmp(fn, fm);
}

void MacroAssembler::Fcmp(const VRegister& fn, double value) {
  DCHECK(allow_macro_instructions());
  if (value != 0.0) {
    UseScratchRegisterScope temps(this);
    VRegister tmp = temps.AcquireSameSizeAs(fn);
    Fmov(tmp, value);
    fcmp(fn, tmp);
  } else {
    fcmp(fn, value);
  }
}

void MacroAssembler::Fcsel(const VRegister& fd, const VRegister& fn,
                           const VRegister& fm, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));
  fcsel(fd, fn, fm, cond);
}

void MacroAssembler::Fcvt(const VRegister& fd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  fcvt(fd, fn);
}

void MacroAssembler::Fcvtas(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtas(rd, fn);
}

void MacroAssembler::Fcvtau(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtau(rd, fn);
}

void MacroAssembler::Fcvtms(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtms(rd, fn);
}

void MacroAssembler::Fcvtmu(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtmu(rd, fn);
}

void MacroAssembler::Fcvtns(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtns(rd, fn);
}

void MacroAssembler::Fcvtnu(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtnu(rd, fn);
}

void MacroAssembler::Fcvtzs(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtzs(rd, fn);
}
void MacroAssembler::Fcvtzu(const Register& rd, const VRegister& fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fcvtzu(rd, fn);
}

void MacroAssembler::Fdiv(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fdiv(fd, fn, fm);
}

void MacroAssembler::Fmadd(const VRegister& fd, const VRegister& fn,
                           const VRegister& fm, const VRegister& fa) {
  DCHECK(allow_macro_instructions());
  fmadd(fd, fn, fm, fa);
}

void MacroAssembler::Fmax(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fmax(fd, fn, fm);
}

void MacroAssembler::Fmaxnm(const VRegister& fd, const VRegister& fn,
                            const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fmaxnm(fd, fn, fm);
}

void MacroAssembler::Fmin(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fmin(fd, fn, fm);
}

void MacroAssembler::Fminnm(const VRegister& fd, const VRegister& fn,
                            const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fminnm(fd, fn, fm);
}

void MacroAssembler::Fmov(VRegister fd, VRegister fn) {
  DCHECK(allow_macro_instructions());
  // Only emit an instruction if fd and fn are different, and they are both D
  // registers. fmov(s0, s0) is not a no-op because it clears the top word of
  // d0. Technically, fmov(d0, d0) is not a no-op either because it clears the
  // top of q0, but VRegister does not currently support Q registers.
  if (fd != fn || !fd.Is64Bits()) {
    fmov(fd, fn);
  }
}

void MacroAssembler::Fmov(VRegister fd, Register rn) {
  DCHECK(allow_macro_instructions());
  fmov(fd, rn);
}

void MacroAssembler::Fmov(VRegister vd, double imm) {
  DCHECK(allow_macro_instructions());
  uint64_t bits = base::bit_cast<uint64_t>(imm);

  if (bits == 0) {
    Movi(vd.D(), 0);
    return;
  }

  if (vd.Is1S() || vd.Is2S() || vd.Is4S()) {
    Fmov(vd, static_cast<float>(imm));
    return;
  }

  DCHECK(vd.Is1D() || vd.Is2D());
  if (IsImmFP64(bits)) {
    fmov(vd, imm);
  } else {
    Movi64bitHelper(vd, bits);
  }
}

void MacroAssembler::Fmov(VRegister vd, float imm) {
  DCHECK(allow_macro_instructions());
  uint32_t bits = base::bit_cast<uint32_t>(imm);

  if (bits == 0) {
    Movi(vd.D(), 0);
    return;
  }

  if (vd.Is1D() || vd.Is2D()) {
    Fmov(vd, static_cast<double>(imm));
    return;
  }

  DCHECK(vd.Is1S() || vd.Is2S() || vd.Is4S());
  if (IsImmFP32(bits)) {
    fmov(vd, imm);
  } else if (vd.IsScalar()) {
    UseScratchRegisterScope temps(this);
    Register tmp = temps.AcquireW();
    Mov(tmp, bits);
    Fmov(vd, tmp);
  } else {
    Movi(vd, bits);
  }
}

void MacroAssembler::Fmov(Register rd, VRegister fn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  fmov(rd, fn);
}

void MacroAssembler::Fmsub(const VRegister& fd, const VRegister& fn,
                           const VRegister& fm, const VRegister& fa) {
  DCHECK(allow_macro_instructions());
  fmsub(fd, fn, fm, fa);
}

void MacroAssembler::Fmul(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fmul(fd, fn, fm);
}

void MacroAssembler::Fnmadd(const VRegister& fd, const VRegister& fn,
                            const VRegister& fm, const VRegister& fa) {
  DCHECK(allow_macro_instructions());
  fnmadd(fd, fn, fm, fa);
}

void MacroAssembler::Fnmsub(const VRegister& fd, const VRegister& fn,
                            const VRegister& fm, const VRegister& fa) {
  DCHECK(allow_macro_instructions());
  fnmsub(fd, fn, fm, fa);
}

void MacroAssembler::Fsub(const VRegister& fd, const VRegister& fn,
                          const VRegister& fm) {
  DCHECK(allow_macro_instructions());
  fsub(fd, fn, fm);
}

void MacroAssembler::Hint(SystemHint code) {
  DCHECK(allow_macro_instructions());
  hint(code);
}

void MacroAssembler::Hlt(int code) {
  DCHECK(allow_macro_instructions());
  hlt(code);
}

void MacroAssembler::Isb() {
  DCHECK(allow_macro_instructions());
  isb();
}

void MacroAssembler::Ldr(const CPURegister& rt, const Operand& operand) {
  DCHECK(allow_macro_instructions());
  ldr(rt, operand);
}

void MacroAssembler::Lsl(const Register& rd, const Register& rn,
                         unsigned shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  lsl(rd, rn, shift);
}

void MacroAssembler::Lsl(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  lslv(rd, rn, rm);
}

void MacroAssembler::Lsr(const Register& rd, const Register& rn,
                         unsigned shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  lsr(rd, rn, shift);
}

void MacroAssembler::Lsr(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  lsrv(rd, rn, rm);
}

void MacroAssembler::Madd(const Register& rd, const Register& rn,
                          const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  madd(rd, rn, rm, ra);
}

void MacroAssembler::Mneg(const Register& rd, const Register& rn,
                          const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  mneg(rd, rn, rm);
}

void MacroAssembler::Movk(const Register& rd, uint64_t imm, int shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  movk(rd, imm, shift);
}

void MacroAssembler::Mrs(const Register& rt, SystemRegister sysreg) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rt.IsZero());
  mrs(rt, sysreg);
}

void MacroAssembler::Msr(SystemRegister sysreg, const Register& rt) {
  DCHECK(allow_macro_instructions());
  msr(sysreg, rt);
}

void MacroAssembler::Msub(const Register& rd, const Register& rn,
                          const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  msub(rd, rn, rm, ra);
}

void MacroAssembler::Mul(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  mul(rd, rn, rm);
}

void MacroAssembler::Rbit(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  rbit(rd, rn);
}

void MacroAssembler::Ret(const Register& xn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!xn.IsZero());
  ret(xn);
  CheckVeneerPool(false, false);
}

void MacroAssembler::Rev(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  rev(rd, rn);
}

void MacroAssembler::Rev16(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  rev16(rd, rn);
}

void MacroAssembler::Rev32(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  rev32(rd, rn);
}

void MacroAssembler::Ror(const Register& rd, const Register& rs,
                         unsigned shift) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  ror(rd, rs, shift);
}

void MacroAssembler::Ror(const Register& rd, const Register& rn,
                         const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  rorv(rd, rn, rm);
}

void MacroAssembler::Sbfx(const Register& rd, const Register& rn, unsigned lsb,
                          unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sbfx(rd, rn, lsb, width);
}

void MacroAssembler::Scvtf(const VRegister& fd, const Register& rn,
                           unsigned fbits) {
  DCHECK(allow_macro_instructions());
  scvtf(fd, rn, fbits);
}

void MacroAssembler::Sdiv(const Register& rd, const Register& rn,
                          const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sdiv(rd, rn, rm);
}

void MacroAssembler::Smaddl(const Register& rd, const Register& rn,
                            const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  smaddl(rd, rn, rm, ra);
}

void MacroAssembler::Smsubl(const Register& rd, const Register& rn,
                            const Register& rm, const Register& ra) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  smsubl(rd, rn, rm, ra);
}

void MacroAssembler::Smull(const Register& rd, const Register& rn,
                           const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  smull(rd, rn, rm);
}

void MacroAssembler::Smulh(const Register& rd, const Register& rn,
                           const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  smulh(rd, rn, rm);
}

void MacroAssembler::Umull(const Register& rd, const Register& rn,
                           const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  umaddl(rd, rn, rm, xzr);
}

void MacroAssembler::Umulh(const Register& rd, const Register& rn,
                           const Register& rm) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  umulh(rd, rn, rm);
}

void MacroAssembler::Sxtb(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sxtb(rd, rn);
}

void MacroAssembler::Sxth(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sxth(rd, rn);
}

void MacroAssembler::Sxtw(const Register& rd, const Register& rn) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  sxtw(rd, rn);
}

void MacroAssembler::Ubfiz(const Register& rd, const Register& rn, unsigned lsb,
                           unsigned width) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  ubfiz(rd, rn, lsb, width);
}

void MacroAssembler::Sbfiz(const Register& rd, const Register& rn, unsigned lsb,
                           unsigned width) {
  DCH
```