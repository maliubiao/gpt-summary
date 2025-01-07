Response:
The user wants a summary of the provided C++ header file `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h`.
I need to identify the functionalities provided by this header file.

Based on the content, this header defines inline functions and templates used by the Liftoff compiler for the ARM architecture in V8. It provides utilities for:

1. **Stack Frame Management:** Defines the structure of the stack frame used by Liftoff on ARM and provides functions to access elements within the frame.
2. **Memory Access:** Offers functions to generate `MemOperand` objects for accessing memory, including stack slots and general memory locations with offsets.
3. **Register Handling:** Includes utilities for working with registers, such as acquiring temporary registers and ensuring no register aliasing.
4. **WASM Operation Implementation:** Provides inline functions and templates to implement various WASM operations, including:
    *   Arithmetic and logical operations on 64-bit integers.
    *   Shift operations on 64-bit integers.
    *   Floating-point min/max operations.
    *   SIMD operations (shifts, narrows, comparisons).
    *   Loading and storing values of different types (integers, floats, SIMD vectors).
5. **Code Generation Helpers:** Offers functions to emit specific ARM instructions and sequences for tasks like:
    *   Preparing and patching the stack frame.
    *   Calling builtins.
    *   Performing tail calls.
    *   Checking for tier-up and stack overflow.
    *   Loading constants and instance data.
    *   Loading data from memory with different sizes and signedness.

The header file is specific to the ARM architecture and the Liftoff compiler. It's written in C++ and uses V8's internal code structures like `Assembler`, `Register`, `MemOperand`, etc.

Regarding the user's specific questions:

*   **`.tq` suffix:** The file does not end with `.tq`, so it's not a Torque source file.
*   **Relationship with JavaScript:**  This code is part of V8's WebAssembly implementation. WebAssembly allows running code written in languages other than JavaScript in the browser. JavaScript can interact with WebAssembly modules by calling functions defined in the WASM module and vice-versa.
*   **Code logic inference:** The header contains many small inline functions that implement specific low-level tasks. I can provide examples of input and output for some of these functions.
*   **Common programming errors:** This header is for internal V8 development, so the "users" are V8 developers. Common errors would be related to incorrect register usage, memory access patterns, or misunderstandings of the ARM architecture.
This C++ header file, `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h`, is a core component of the V8 JavaScript engine's WebAssembly (Wasm) implementation, specifically for the ARM architecture. It defines inline functions and templates that are used by the **Liftoff compiler**, V8's baseline compiler for Wasm, to generate ARM assembly code.

Here's a breakdown of its functionalities:

1. **Stack Frame Management for ARM:**
    *   It defines the structure of the Wasm stack frame on ARM, outlining the layout of parameters, return address, frame pointer, instance data, etc.
    *   It provides inline functions like `GetStackSlot`, `GetHalfStackSlot`, `GetInstanceDataOperand` to easily calculate memory operands for accessing specific locations within the stack frame.

2. **Memory Access Helpers:**
    *   The `GetMemOp` function generates `MemOperand` objects for loading and storing data from memory, handling potential offset registers and immediate offsets.
    *   `CalculateActualAddress` calculates the final memory address, taking into account base register, offset register, and immediate offset.

3. **Register Manipulation:**
    *   It offers utilities for managing and using ARM registers within the Liftoff compiler.
    *   `EnsureNoAlias` helps in avoiding register conflicts by acquiring a temporary register if the desired register is already in use.
    *   The `CacheStatePreservingTempRegisters` class helps manage temporary registers while preserving the cached register state.

4. **Implementation of Wasm Operations for ARM:**
    *   It contains template functions (`I64Binop`, `I64BinopI`, `I64Shiftop`) to generate ARM instructions for 64-bit integer arithmetic and shift operations, handling carry flags correctly.
    *   `EmitFloatMinOrMax` generates code for floating-point minimum and maximum operations.
    *   `S128NarrowOp` and `F64x2Compare` implement specific SIMD (Single Instruction, Multiple Data) operations for 128-bit vectors.
    *   `EmitSimdShift` and `EmitSimdShiftImmediate` provide functionality for SIMD shift operations.
    *   `EmitAnyTrue` checks if any element in a SIMD vector is true.
    *   `Store` and `Load` functions generate appropriate ARM instructions (e.g., `str`, `ldr`, `strh`, `ldrh`, `vstr`, `vldr`) for storing and loading Wasm values of different types (i32, i64, f32, f64, s128) to and from memory.

5. **Liftoff-Specific Code Generation Helpers:**
    *   `PrepareStackFrame` generates the initial code for setting up the stack frame, with a placeholder for patching the final frame size.
    *   `PatchPrepareStackFrame` patches the placeholder in `PrepareStackFrame` to allocate the correct amount of stack space, handling cases where the frame size is large and requires out-of-line code for stack overflow checks.
    *   `CallFrameSetupStub` generates code to call a builtin function for setting up the call frame.
    *   `PrepareTailCall` generates code for performing tail calls, optimizing function calls in certain scenarios.
    *   `CheckTierUp` generates code to check if the function should be tiered up to a more optimizing compiler based on execution budget.
    *   `LoadConstant` generates code to load constant Wasm values into registers.
    *   `LoadInstanceDataFromFrame` loads the Wasm instance data pointer from the stack frame.
    *   `LoadTrustedPointer`, `LoadFromInstance`, and `LoadTaggedPointerFromInstance` handle loading data from the Wasm instance.
    *   `SpillInstanceData` stores the instance data pointer back to the stack frame.
    *   `CheckStackShrink` generates code to check and potentially shrink the stack in scenarios with growable stacks.

**Regarding your specific questions:**

*   **`.tq` extension:** The filename `liftoff-assembler-arm-inl.h` does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source file. Torque files are typically used for defining runtime builtins and often have a `.tq` extension.

*   **Relationship with JavaScript and JavaScript Examples:** This header file is part of the underlying implementation of V8 that enables the execution of WebAssembly code within a JavaScript environment. JavaScript can load and interact with Wasm modules.

    ```javascript
    // Example of loading and calling a WebAssembly function from JavaScript
    async function loadWasm() {
      const response = await fetch('my_wasm_module.wasm');
      const buffer = await response.arrayBuffer();
      const module = await WebAssembly.compile(buffer);
      const instance = await WebAssembly.instantiate(module);

      // Assuming the Wasm module exports a function named 'add' that takes two i32s
      const result = instance.exports.add(5, 10);
      console.log(result); // Output: 15
    }

    loadWasm();
    ```

    While this header file doesn't directly contain JavaScript code, the assembly code generated using its functions is what makes the `instance.exports.add(5, 10)` call in the JavaScript example possible. The Liftoff compiler, using the functions defined here, translates the Wasm `add` function into efficient ARM machine code that can be executed by the processor.

*   **Code Logic Inference (with assumptions):**

    Let's take the `GetStackSlot` function as an example:

    **Assumed Input:** `offset = 8`

    **Code:** `inline MemOperand GetStackSlot(int offset) { return MemOperand(fp, -offset); }`

    **Output:** `MemOperand(fp, -8)`

    This function will return a `MemOperand` representing the memory location 8 bytes below the frame pointer (`fp`). This is used to access parameters or local variables stored on the stack.

*   **User-Common Programming Errors (in the context of V8 development):**

    Since this is internal V8 code, the "users" are V8 developers. Common errors might include:

    *   **Incorrect offset calculations:**  Providing the wrong offset when accessing stack slots, leading to reading or writing to the wrong memory location.
    *   **Register allocation errors:** Using a register that is already in use, potentially overwriting important data. The `EnsureNoAlias` function is designed to help prevent this.
    *   **Incorrect instruction selection:** Choosing the wrong ARM instruction for a specific Wasm operation, leading to incorrect behavior or performance issues.
    *   **Forgetting to handle different data types correctly:**  Using instructions intended for 32-bit values on 64-bit values or vice-versa without proper handling of the high and low words.

**Summary of the File's Functionality (for Part 1):**

The header file `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` provides a set of low-level building blocks and utility functions specifically for the Liftoff compiler on the ARM architecture within V8. It defines the stack frame layout, offers helpers for memory access and register manipulation, and implements various Wasm operations by generating corresponding ARM assembly instructions. This file is crucial for the efficient compilation and execution of WebAssembly code in JavaScript environments running on ARM processors.

Prompt: 
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_ARM_LIFTOFF_ASSEMBLER_ARM_INL_H_
#define V8_WASM_BASELINE_ARM_LIFTOFF_ASSEMBLER_ARM_INL_H_

#include <optional>

#include "src/codegen/arm/assembler-arm-inl.h"
#include "src/codegen/arm/register-arm.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/common/globals.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

namespace liftoff {

//  half
//  slot        Frame
//  -----+--------------------+---------------------------
//  n+3  |   parameter n      |
//  ...  |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   1   | return addr (lr)   |
//   0   | previous frame (fp)|
//  -----+--------------------+  <-- frame ptr (fp)
//  -1   | StackFrame::WASM   |
//  -2   |    instance        |
//  -3   |    feedback vector |
//  -4   |    tiering budget  |
//  -----+--------------------+---------------------------
//  -5   |    slot 0 (high)   |   ^
//  -6   |    slot 0 (low)    |   |
//  -7   |    slot 1 (high)   | Frame slots
//  -8   |    slot 1 (low)    |   |
//       |                    |   v
//  -----+--------------------+  <-- stack ptr (sp)
//
static_assert(2 * kSystemPointerSize == LiftoffAssembler::kStackSlotSize,
              "Slot size should be twice the size of the 32 bit pointer.");
// kPatchInstructionsRequired sets a maximum limit of how many instructions that
// PatchPrepareStackFrame will use in order to increase the stack appropriately.
// Three instructions are required to sub a large constant, movw + movt + sub.
constexpr int32_t kPatchInstructionsRequired = 3;
constexpr int kHalfStackSlotSize = LiftoffAssembler::kStackSlotSize >> 1;

inline MemOperand GetStackSlot(int offset) { return MemOperand(fp, -offset); }

inline MemOperand GetHalfStackSlot(int offset, RegPairHalf half) {
  int32_t half_offset =
      half == kLowWord ? 0 : LiftoffAssembler::kStackSlotSize / 2;
  return MemOperand(offset > 0 ? fp : sp, -offset + half_offset);
}

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline MemOperand GetMemOp(LiftoffAssembler* assm,
                           UseScratchRegisterScope* temps, Register addr,
                           Register offset, int32_t offset_imm,
                           unsigned shift_amount = 0) {
  if (offset != no_reg) {
    if (offset_imm == 0) return MemOperand(addr, offset, LSL, shift_amount);
    Register tmp = temps->Acquire();
    if (shift_amount == 0) {
      assm->add(tmp, offset, Operand(offset_imm));
    } else {
      assm->lsl(tmp, offset, Operand(shift_amount));
      assm->add(tmp, tmp, Operand(offset_imm));
    }
    return MemOperand(addr, tmp);
  }
  return MemOperand(addr, offset_imm);
}

inline Register CalculateActualAddress(LiftoffAssembler* assm,
                                       UseScratchRegisterScope* temps,
                                       Register addr_reg, Register offset_reg,
                                       uintptr_t offset_imm,
                                       Register result_reg = no_reg) {
  if (offset_reg == no_reg && offset_imm == 0) {
    if (result_reg == addr_reg || result_reg == no_reg) return addr_reg;
    assm->mov(result_reg, addr_reg);
    return result_reg;
  }
  if (result_reg == no_reg) result_reg = temps->Acquire();
  if (offset_reg == no_reg) {
    assm->add(result_reg, addr_reg, Operand(offset_imm));
  } else {
    assm->add(result_reg, addr_reg, Operand(offset_reg));
    if (offset_imm != 0) assm->add(result_reg, result_reg, Operand(offset_imm));
  }
  return result_reg;
}

inline Condition MakeUnsigned(Condition cond) {
  switch (cond) {
    case kLessThan:
      return kUnsignedLessThan;
    case kLessThanEqual:
      return kUnsignedLessThanEqual;
    case kGreaterThan:
      return kUnsignedGreaterThan;
    case kGreaterThanEqual:
      return kUnsignedGreaterThanEqual;
    case kEqual:
    case kNotEqual:
    case kUnsignedLessThan:
    case kUnsignedLessThanEqual:
    case kUnsignedGreaterThan:
    case kUnsignedGreaterThanEqual:
      return cond;
    default:
      UNREACHABLE();
  }
}

template <void (Assembler::*op)(Register, Register, Register, SBit, Condition),
          void (Assembler::*op_with_carry)(Register, Register, const Operand&,
                                           SBit, Condition)>
inline void I64Binop(LiftoffAssembler* assm, LiftoffRegister dst,
                     LiftoffRegister lhs, LiftoffRegister rhs) {
  Register dst_low = dst.low_gp();
  if (dst_low == lhs.high_gp() || dst_low == rhs.high_gp()) {
    dst_low =
        assm->GetUnusedRegister(kGpReg, LiftoffRegList{lhs, rhs, dst.high_gp()})
            .gp();
  }
  (assm->*op)(dst_low, lhs.low_gp(), rhs.low_gp(), SetCC, al);
  (assm->*op_with_carry)(dst.high_gp(), lhs.high_gp(), Operand(rhs.high_gp()),
                         LeaveCC, al);
  if (dst_low != dst.low_gp()) assm->mov(dst.low_gp(), dst_low);
}

template <void (Assembler::*op)(Register, Register, const Operand&, SBit,
                                Condition),
          void (Assembler::*op_with_carry)(Register, Register, const Operand&,
                                           SBit, Condition)>
inline void I64BinopI(LiftoffAssembler* assm, LiftoffRegister dst,
                      LiftoffRegister lhs, int64_t imm) {
  // The compiler allocated registers such that either {dst == lhs} or there is
  // no overlap between the two.
  DCHECK_NE(dst.low_gp(), lhs.high_gp());
  int32_t imm_low_word = static_cast<int32_t>(imm);
  int32_t imm_high_word = static_cast<int32_t>(imm >> 32);
  (assm->*op)(dst.low_gp(), lhs.low_gp(), Operand(imm_low_word), SetCC, al);
  (assm->*op_with_carry)(dst.high_gp(), lhs.high_gp(), Operand(imm_high_word),
                         LeaveCC, al);
}

template <void (MacroAssembler::*op)(Register, Register, Register, Register,
                                     Register),
          bool is_left_shift>
inline void I64Shiftop(LiftoffAssembler* assm, LiftoffRegister dst,
                       LiftoffRegister src, Register amount) {
  Register src_low = src.low_gp();
  Register src_high = src.high_gp();
  Register dst_low = dst.low_gp();
  Register dst_high = dst.high_gp();
  // Left shift writes {dst_high} then {dst_low}, right shifts write {dst_low}
  // then {dst_high}.
  Register clobbered_dst_reg = is_left_shift ? dst_high : dst_low;
  LiftoffRegList pinned{clobbered_dst_reg, src};
  Register amount_capped =
      pinned.set(assm->GetUnusedRegister(kGpReg, pinned)).gp();
  assm->and_(amount_capped, amount, Operand(0x3F));

  // Ensure that writing the first half of {dst} does not overwrite the still
  // needed half of {src}.
  Register* later_src_reg = is_left_shift ? &src_low : &src_high;
  if (*later_src_reg == clobbered_dst_reg) {
    *later_src_reg = assm->GetUnusedRegister(kGpReg, pinned).gp();
    assm->MacroAssembler::Move(*later_src_reg, clobbered_dst_reg);
  }

  (assm->*op)(dst_low, dst_high, src_low, src_high, amount_capped);
}

inline FloatRegister GetFloatRegister(DoubleRegister reg) {
  DCHECK_LT(reg.code(), kDoubleCode_d16);
  return LowDwVfpRegister::from_code(reg.code()).low();
}

inline Simd128Register GetSimd128Register(DoubleRegister reg) {
  return QwNeonRegister::from_code(reg.code() / 2);
}

inline Simd128Register GetSimd128Register(LiftoffRegister reg) {
  return liftoff::GetSimd128Register(reg.low_fp());
}

enum class MinOrMax : uint8_t { kMin, kMax };
template <typename RegisterType>
inline void EmitFloatMinOrMax(LiftoffAssembler* assm, RegisterType dst,
                              RegisterType lhs, RegisterType rhs,
                              MinOrMax min_or_max) {
  DCHECK(RegisterType::kSizeInBytes == 4 || RegisterType::kSizeInBytes == 8);
  if (lhs == rhs) {
    assm->MacroAssembler::Move(dst, lhs);
    return;
  }
  Label done, is_nan;
  if (min_or_max == MinOrMax::kMin) {
    assm->MacroAssembler::FloatMin(dst, lhs, rhs, &is_nan);
  } else {
    assm->MacroAssembler::FloatMax(dst, lhs, rhs, &is_nan);
  }
  assm->b(&done);
  assm->bind(&is_nan);
  // Create a NaN output.
  assm->vadd(dst, lhs, rhs);
  assm->bind(&done);
}

inline Register EnsureNoAlias(Assembler* assm, Register reg,
                              Register must_not_alias,
                              UseScratchRegisterScope* temps) {
  if (reg != must_not_alias) return reg;
  Register tmp = temps->Acquire();
  DCHECK_NE(reg, tmp);
  assm->mov(tmp, reg);
  return tmp;
}

inline void S128NarrowOp(LiftoffAssembler* assm, NeonDataType dt,
                         NeonDataType sdt, LiftoffRegister dst,
                         LiftoffRegister lhs, LiftoffRegister rhs) {
  if (dst == lhs) {
    assm->vqmovn(dt, sdt, dst.low_fp(), liftoff::GetSimd128Register(lhs));
    assm->vqmovn(dt, sdt, dst.high_fp(), liftoff::GetSimd128Register(rhs));
  } else {
    assm->vqmovn(dt, sdt, dst.high_fp(), liftoff::GetSimd128Register(rhs));
    assm->vqmovn(dt, sdt, dst.low_fp(), liftoff::GetSimd128Register(lhs));
  }
}

inline void F64x2Compare(LiftoffAssembler* assm, LiftoffRegister dst,
                         LiftoffRegister lhs, LiftoffRegister rhs,
                         Condition cond) {
  DCHECK(cond == eq || cond == ne || cond == lt || cond == le);

  QwNeonRegister dest = liftoff::GetSimd128Register(dst);
  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);
  UseScratchRegisterScope temps(assm);
  Register scratch = temps.Acquire();

  assm->mov(scratch, Operand(0));
  assm->VFPCompareAndSetFlags(left.low(), right.low());
  assm->mov(scratch, Operand(-1), LeaveCC, cond);
  if (cond == lt || cond == le) {
    // Check for NaN.
    assm->mov(scratch, Operand(0), LeaveCC, vs);
  }
  assm->vmov(dest.low(), scratch, scratch);

  assm->mov(scratch, Operand(0));
  assm->VFPCompareAndSetFlags(left.high(), right.high());
  assm->mov(scratch, Operand(-1), LeaveCC, cond);
  if (cond == lt || cond == le) {
    // Check for NaN.
    assm->mov(scratch, Operand(0), LeaveCC, vs);
  }
  assm->vmov(dest.high(), scratch, scratch);
}

inline void Store(LiftoffAssembler* assm, LiftoffRegister src, MemOperand dst,
                  ValueKind kind) {
#ifdef DEBUG
  // The {str} instruction needs a temp register when the immediate in the
  // provided MemOperand does not fit into 12 bits. This happens for large stack
  // frames. This DCHECK checks that the temp register is available when needed.
  DCHECK(UseScratchRegisterScope{assm}.CanAcquire());
#endif
  switch (kind) {
    case kI16:
      assm->strh(src.gp(), dst);
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->str(src.gp(), dst);
      break;
    case kI64:
      // Positive offsets should be lowered to kI32.
      assm->str(src.low_gp(), MemOperand(dst.rn(), dst.offset()));
      assm->str(
          src.high_gp(),
          MemOperand(dst.rn(), dst.offset() + liftoff::kHalfStackSlotSize));
      break;
    case kF32:
      assm->vstr(liftoff::GetFloatRegister(src.fp()), dst);
      break;
    case kF64:
      assm->vstr(src.fp(), dst);
      break;
    case kS128: {
      UseScratchRegisterScope temps(assm);
      Register addr = liftoff::CalculateActualAddress(assm, &temps, dst.rn(),
                                                      no_reg, dst.offset());
      assm->vst1(Neon8, NeonListOperand(src.low_fp(), 2), NeonMemOperand(addr));
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, MemOperand src,
                 ValueKind kind) {
  switch (kind) {
    case kI16:
      assm->ldrh(dst.gp(), src);
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->ldr(dst.gp(), src);
      break;
    case kI64:
      assm->ldr(dst.low_gp(), MemOperand(src.rn(), src.offset()));
      assm->ldr(
          dst.high_gp(),
          MemOperand(src.rn(), src.offset() + liftoff::kHalfStackSlotSize));
      break;
    case kF32:
      assm->vldr(liftoff::GetFloatRegister(dst.fp()), src);
      break;
    case kF64:
      assm->vldr(dst.fp(), src);
      break;
    case kS128: {
      // Get memory address of slot to fill from.
      UseScratchRegisterScope temps(assm);
      Register addr = liftoff::CalculateActualAddress(assm, &temps, src.rn(),
                                                      no_reg, src.offset());
      assm->vld1(Neon8, NeonListOperand(dst.low_fp(), 2), NeonMemOperand(addr));
      break;
    }
    default:
      UNREACHABLE();
  }
}

constexpr int MaskFromNeonDataType(NeonDataType dt) {
  switch (dt) {
    case NeonS8:
    case NeonU8:
      return 7;
    case NeonS16:
    case NeonU16:
      return 15;
    case NeonS32:
    case NeonU32:
      return 31;
    case NeonS64:
    case NeonU64:
      return 63;
    default:
      UNREACHABLE();
      return 0;
  }
}

enum ShiftDirection { kLeft, kRight };

template <ShiftDirection dir = kLeft, NeonDataType dt, NeonSize sz>
inline void EmitSimdShift(LiftoffAssembler* assm, LiftoffRegister dst,
                          LiftoffRegister lhs, LiftoffRegister rhs) {
  constexpr int mask = MaskFromNeonDataType(dt);
  UseScratchRegisterScope temps(assm);
  QwNeonRegister tmp = temps.AcquireQ();
  Register shift = temps.Acquire();
  assm->and_(shift, rhs.gp(), Operand(mask));
  assm->vdup(sz, tmp, shift);
  if (dir == kRight) {
    assm->vneg(sz, tmp, tmp);
  }
  assm->vshl(dt, liftoff::GetSimd128Register(dst),
             liftoff::GetSimd128Register(lhs), tmp);
}

template <ShiftDirection dir, NeonDataType dt>
inline void EmitSimdShiftImmediate(LiftoffAssembler* assm, LiftoffRegister dst,
                                   LiftoffRegister lhs, int32_t rhs) {
  // vshr by 0 is not allowed, so check for it, and only move if dst != lhs.
  int32_t shift = rhs & MaskFromNeonDataType(dt);
  if (shift) {
    if (dir == kLeft) {
      assm->vshl(dt, liftoff::GetSimd128Register(dst),
                 liftoff::GetSimd128Register(lhs), shift);
    } else {
      assm->vshr(dt, liftoff::GetSimd128Register(dst),
                 liftoff::GetSimd128Register(lhs), shift);
    }
  } else if (dst != lhs) {
    assm->vmov(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(lhs));
  }
}

inline void EmitAnyTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src) {
  UseScratchRegisterScope temps(assm);
  DwVfpRegister scratch = temps.AcquireD();
  assm->vpmax(NeonU32, scratch, src.low_fp(), src.high_fp());
  assm->vpmax(NeonU32, scratch, scratch, scratch);
  assm->ExtractLane(dst.gp(), scratch, NeonS32, 0);
  assm->cmp(dst.gp(), Operand(0));
  assm->mov(dst.gp(), Operand(1), LeaveCC, ne);
}

class CacheStatePreservingTempRegisters {
 public:
  explicit CacheStatePreservingTempRegisters(LiftoffAssembler* assm,
                                             LiftoffRegList pinned = {})
      : assm_(assm), pinned_(pinned) {}

  ~CacheStatePreservingTempRegisters() {
    for (Register reg : must_pop_) {
      assm_->Pop(reg);
    }
  }

  Register Acquire() {
    if (assm_->cache_state()->has_unused_register(kGpReg, pinned_)) {
      return pinned_.set(
          assm_->cache_state()->unused_register(kGpReg, pinned_).gp());
    }

    RegList available =
        kLiftoffAssemblerGpCacheRegs - pinned_.GetGpList() - must_pop_;
    DCHECK(!available.is_empty());
    // Use {last()} here so we can just iterate forwards in the destructor.
    Register reg = available.last();
    assm_->Push(reg);
    must_pop_.set(reg);
    return reg;
  }

 private:
  LiftoffAssembler* const assm_;
  LiftoffRegList pinned_;
  RegList must_pop_;
};

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  if (!CpuFeatures::IsSupported(ARMv7)) {
    bailout(kUnsupportedArchitecture, "Liftoff needs ARMv7");
    return 0;
  }
  uint32_t offset = static_cast<uint32_t>(pc_offset());
  // PatchPrepareStackFrame will patch this in order to increase the stack
  // appropriately. Additional nops are required as the bytes operand might
  // require extra moves to encode.
  for (int i = 0; i < liftoff::kPatchInstructionsRequired; i++) {
    nop();
  }
  DCHECK_EQ(offset + liftoff::kPatchInstructionsRequired * kInstrSize,
            pc_offset());
  return offset;
}

void LiftoffAssembler::CallFrameSetupStub(int declared_function_index) {
// The standard library used by gcc tryjobs does not consider `std::find` to be
// `constexpr`, so wrap it in a `#ifdef __clang__` block.
#ifdef __clang__
  static_assert(std::find(std::begin(wasm::kGpParamRegisters),
                          std::end(wasm::kGpParamRegisters),
                          kLiftoffFrameSetupFunctionReg) ==
                std::end(wasm::kGpParamRegisters));
#endif

  // On ARM, we must push at least {lr} before calling the stub, otherwise
  // it would get clobbered with no possibility to recover it.
  Register scratch = r7;
  mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  PushCommonFrame(scratch);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();

  // Push the return address and frame pointer to complete the stack frame.
  sub(sp, sp, Operand(8));
  ldr(scratch, MemOperand(fp, 4));
  str(scratch, MemOperand(sp, 4));
  ldr(scratch, MemOperand(fp, 0));
  str(scratch, MemOperand(sp, 0));

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    ldr(scratch, MemOperand(sp, i * 4));
    str(scratch, MemOperand(fp, (i - stack_param_delta) * 4));
  }

  // Set the new stack and frame pointer.
  sub(sp, fp, Operand(stack_param_delta * 4));
  Pop(lr, fp);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  // The frame_size includes the frame marker and the instance slot. Both are
  // pushed as part of frame construction, so we don't need to allocate memory
  // for them anymore.
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  PatchingAssembler patching_assembler(AssemblerOptions{},
                                       buffer_start_ + offset,
                                       liftoff::kPatchInstructionsRequired);
  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.sub(sp, sp, Operand(frame_size));
    patching_assembler.PadWithNops();
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ sub(sp, sp, framesize)} with a jump to OOL code that does
  // this "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.

  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).
  patching_assembler.b(pc_offset() - offset - Instruction::kPcLoadDelta);
  patching_assembler.PadWithNops();

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    UseScratchRegisterScope temps(this);
    Register stack_limit = temps.Acquire();
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    add(stack_limit, stack_limit, Operand(frame_size));
    cmp(sp, stack_limit);
    b(cs /* higher or same */, &continuation);
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    mov(WasmHandleStackOverflowDescriptor::GapRegister(), Operand(frame_size));
    add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
        Operand(stack_param_slots * kStackSlotSize +
                CommonFrameConstants::kFixedFrameSizeAboveFp));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    Call(static_cast<Address>(Builtin::kWasmStackOverflow),
         RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    if (v8_flags.debug_code) stop();
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  AllocateStackSpace(frame_size);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  int func_start_offset =
      offset + liftoff::kPatchInstructionsRequired * kInstrSize;
  b(func_start_offset - pc_offset() - Instruction::kPcLoadDelta);
}

void LiftoffAssembler::FinishCode() { CheckConstPool(true, false); }

void LiftoffAssembler::AbortCompilation() { AbortedCodeGeneration(); }

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  switch (kind) {
    case kS128:
      return value_kind_size(kind);
    default:
      return kStackSlotSize;
  }
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return kind == kS128 || is_reference(kind);
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  {
    liftoff::CacheStatePreservingTempRegisters temps{this};
    Register budget_array = temps.Acquire();

    Register instance_data = cache_state_.cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = budget_array;  // Reuse the temp register.
      LoadInstanceDataFromFrame(instance_data);
    }

    constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
        WasmTrustedInstanceData::kTieringBudgetArrayOffset);
    ldr(budget_array, MemOperand{instance_data, kArrayOffset});

    int budget_arr_offset = kInt32Size * declared_func_index;
    // If the offset cannot be used in the operand directly, add it once to the
    // budget array to avoid doing this multiple times below.
    if (!ImmediateFitsAddrMode2Instruction(budget_arr_offset)) {
      add(budget_array, budget_array, Operand{budget_arr_offset});
      budget_arr_offset = 0;
    }

    Register budget = temps.Acquire();
    MemOperand budget_addr{budget_array, budget_arr_offset};
    ldr(budget, budget_addr);
    sub(budget, budget, Operand{budget_used}, SetCC);
    str(budget, budget_addr);
  }
  b(ool_label, mi);
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return fp;
  }
  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  ldr(old_fp.gp(), MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  cmp(old_fp.gp(),
      Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  b(&call_runtime, eq);
  mov(old_fp.gp(), fp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  MacroAssembler::Move(kCArgRegs[0], ExternalReference::isolate_address());
  PrepareCallCFunction(1);
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    mov(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  {
    UseScratchRegisterScope temps{this};
    Register scratch = temps.Acquire();
    ldr(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
    cmp(scratch,
        Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  }
  Label done;
  b(&done, ne);
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  PushRegisters(regs_to_save);
  MacroAssembler::Move(kCArgRegs[0], ExternalReference::isolate_address());
  PrepareCallCFunction(1);
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  // Restore old FP. We don't need to restore old SP explicitly, because
  // it will be restored from FP in LeaveFrame before return.
  mov(fp, kReturnRegister0);
  PopRegisters(regs_to_save);
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::Move(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::Move(reg.low_gp(), Operand(low_word));
      MacroAssembler::Move(reg.high_gp(), Operand(high_word));
      break;
    }
    case kF32:
      vmov(liftoff::GetFloatRegister(reg.fp()), value.to_f32_boxed());
      break;
    case kF64: {
      Register extra_scratch = GetUnusedRegister(kGpReg, {}).gp();
      vmov(reg.fp(), base::Double(value.to_f64_boxed().get_bits()),
           extra_scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  ldr(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  static_assert(!COMPRESS_POINTERS_BOOL);
  ldr(dst, MemOperand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  MemOperand src{instance, offset};
  switch (size) {
    case 1:
      ldrb(dst, src);
      break;
    case 4:
      ldr(dst, src);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  static_assert(kTaggedSize == kSystemPointerSize);
  ldr(dst, MemOperand{instance, offset});
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  str(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

namespace liftoff {
#define __ lasm->
inline void LoadInternal(LiftoffAssembler* lasm, LiftoffRegister dst,
                         Register src_addr, Register offset_reg,
                         int32_t offset_imm, LoadType type,
                         uint32_t* protected_load_pc = nullptr,
                         bool needs_shift = false) {
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  DCHECK_IMPLIES(type.value_type() == kWasmI64, dst.is_gp_pair());
  UseScratchRegisterScope temps(lasm);
  if (type.value() == LoadType::kF64Load ||
      type.value() == LoadType::kF32Load ||
      type.value() == LoadType::kS128Load) {
    // Remove the DCHECK and implement scaled offsets for these types if needed.
    // For now this path is never used.
    DCHECK(!needs_shift);
    Register actual_src_addr = liftoff::CalculateActualAddress(
        lasm, &temps, src_addr, offset_reg, offset_imm);
    if (type.value() == LoadType::kF64Load) {
      // Armv6 is not supported so Neon can be used to avoid alignment issues.
      CpuFeatureScope scope(lasm, NEON);
      __ vld1(Neon64, NeonListOperand(dst.fp()),
              NeonMemOperand(actual_src_addr));
    } else if (type.value() == LoadType::kF32Load) {
      // TODO(arm): Use vld1 for f32 when implemented in simulator as used for
      // f64. It supports unaligned access.
      Register scratch =
          (actual_src_addr == src_addr) ? temps.Acquire() : actual_src_addr;
      __ ldr(scratch, MemOperand(actual_src_addr));
      __ vmov(liftoff::GetFloatRegister(dst.fp()), scratch);
    } else {
      // Armv6 is not supported so Neon can be used to avoid alignment issues.
      CpuFeatureScope scope(lasm, NEON);
      __ vld1(Neon8, NeonListOperand(dst.low_fp(), 2),
              NeonMemOperand(actual_src_addr));
    }
  } else {
    MemOperand src_op = liftoff::GetMemOp(lasm, &temps, src_addr, offset_reg,
                                          offset_imm, shift_amount);
    if (protected_load_pc) *protected_load_pc = __ pc_offset();
    switch (type.value()) {
      case LoadType::kI32Load8U:
        __ ldrb(dst.gp(), src_op);
        break;
      case LoadType::kI64Load8U:
        __ ldrb(dst.low_gp(), src_op);
        __ mov(dst.high_gp(), Operand(0));
        break;
      case LoadType::kI32Load8S:
        __ ldrsb(dst.gp(), src_op);
        break;
      case LoadType::kI64Load8S:
        __ ldrsb(dst.low_gp(), src_op);
        __ asr(dst.high_gp(), dst.low_gp(), Operand(31));
        break;
      case LoadType::kI32Load16U:
        __ ldrh(dst.gp(), src_op);
        break;
      case LoadType::kI64Load16U:
        __ ldrh(dst.low_gp(), src_op);
        __ mov(dst.high_gp(), Operand(0));
        break;
      case LoadType::kI32Load16S:
        __ ldrsh(dst.gp(), src_op);
        break;
      case LoadType::kI32Load:
        __ ldr(dst.gp(), src_op);
        break;
      case LoadType::kI64Load16S:
        __ ldrsh(dst.low_gp(), src_op);
        __ asr(dst.high_gp(), dst.low_gp(), Operand(31));
        break;
      case LoadType::kI64Load32U:
        __ ldr(dst.low_gp(), src_op);
        __ mov(dst.high_gp(), Operand(0));
        break;
      case LoadType::kI64Load32S:
        __ ldr(dst.low_gp(), src_op);
        __ asr(dst.high_gp(), dst.low_gp(), Operand(31));
        break;
      case LoadType::kI64Load:
        __ ldr(dst.low_gp(), src_op);
        // GetMemOp may use a scratch register as the offset register, in which
        // case, calling GetMemOp again will fail due to the assembler having
        // ran out of scratch registers.
        if (temps.CanAcquire()) {
          src_op = liftoff::GetMemOp(lasm, &temps, src_addr, offset_reg,
                                     offset_imm + kSystemPointerSize);
        } else {
          __ add(src_op.rm(), src_op.rm(), Operand(kSystemPointerSize));
        }
        __ ldr(dst.high_gp(), src_op);
        break;
      default:
        UNREACHABLE();
    }
  }
}
#undef __
}  // namespace liftoff

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  static_assert(kTaggedSize == kInt32Size);
  liftoff::LoadInternal(this, LiftoffRegister(dst), src_addr, offset_reg,
                        of
"""


```