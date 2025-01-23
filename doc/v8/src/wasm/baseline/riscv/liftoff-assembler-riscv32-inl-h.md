Response:
The user wants a summary of the provided C++ header file. I need to identify the key functionalities exposed by this file.

Here's a breakdown of the thought process:

1. **Identify the file's purpose:** The filename `liftoff-assembler-riscv32-inl.h` and the namespace `v8::internal::wasm::liftoff` strongly suggest this file provides inline helper functions for the Liftoff compiler on the RISC-V 32-bit architecture within the V8 JavaScript engine's WebAssembly module. The `.inl.h` suffix indicates inline implementations.

2. **Analyze the included headers:** The included files provide context:
    * `"src/heap/mutable-page-metadata.h"`:  Suggests interaction with memory management.
    * `"src/wasm/baseline/liftoff-assembler.h"`: Indicates this file extends or specializes the base Liftoff assembler.
    * `"src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h"`: Implies a common RISC-V base with specific 32-bit additions.
    * `"src/wasm/wasm-objects.h"`:  Shows interaction with WebAssembly specific objects.

3. **Examine the defined constants and the `GetHalfStackSlot` function:**
    * `kLowWordOffset` and `kHighWordOffset`:  Define byte offsets for accessing the low and high words of multi-word values, handling endianness.
    * `GetHalfStackSlot`: Calculates the memory operand for accessing half of a stack slot, useful for accessing parts of larger data types on the stack.

4. **Analyze the `GetMemOp` function:** This function is crucial for generating memory operands. It handles cases where the offset is an immediate value or a register, and it uses a scratch register for complex offset calculations. It also deals with potential large immediate offsets.

5. **Focus on the `Load` and `Store` functions:** These are fundamental operations for moving data between memory and registers. They handle different data types (`kI32`, `kI64`, `kF32`, `kF64`, `kS128`) and use appropriate RISC-V instructions. The `kS128` case suggests support for SIMD operations.

6. **Examine the `push` function:**  This function pushes different data types onto the stack, adjusting the stack pointer (`sp`) accordingly.

7. **Analyze `EnsureNoAlias`:** This helper function ensures that two registers do not refer to the same physical register, using a temporary register if necessary. This is important for avoiding unintended side effects in assembly code.

8. **Look at `LiftoffAssembler::LoadConstant`:** This function loads constant values into registers, handling different data types.

9. **Analyze `LiftoffAssembler::LoadTaggedPointer`, `LoadProtectedPointer`, `LoadFullPointer`, and `StoreTaggedPointer`:** These functions deal with loading and storing pointers, with `LoadTaggedPointer` and `StoreTaggedPointer` being aware of V8's tagged pointer representation and potential write barriers for garbage collection.

10. **Analyze the overloaded `LiftoffAssembler::Load` and `LiftoffAssembler::Store` functions:** These are more general load and store operations that take `LoadType` and `StoreType` enums, providing more fine-grained control over the load/store size and signedness. They also handle endianness adjustments and protected loads/stores.

11. **Examine the `liftoff` namespace functions (`CalculateActualAddress`, `AtomicBinop64`, `AtomicBinop`):**
    * `CalculateActualAddress`:  Calculates the effective memory address.
    * `AtomicBinop64` and `AtomicBinop`: Implement atomic read-modify-write operations for different data sizes, crucial for thread safety. They use either C function calls for 64-bit operations or RISC-V atomic instructions for smaller sizes.

12. **Analyze `LiftoffAssembler::AtomicLoad`, `LiftoffAssembler::AtomicStore`, and the specialized atomic operations (`AtomicAdd`, `AtomicSub`, etc.):** These functions provide higher-level atomic operations, utilizing the lower-level atomic primitives.

13. **Consider the naming conventions:**  The consistent use of `LiftoffAssembler`, `MemOperand`, `LiftoffRegister`, and the prefixing of functions with architectural details (`riscv32`) helps understand the scope and purpose.

14. **Synthesize the information:** Combine the observations to create a high-level summary of the file's functionality.

15. **Address the specific questions in the prompt:**
    * **Is it a Torque file?** No, it doesn't end with `.tq`.
    * **Relationship to JavaScript?** Yes, it's part of V8, the JavaScript engine. Provide a JavaScript example of how WASM interacts.
    * **Code logic reasoning?** Focus on `GetMemOp` and the atomic operations, providing hypothetical inputs and outputs.
    * **Common programming errors?**  Address incorrect offset calculations, type mismatches, and forgetting write barriers.

This step-by-step analysis allows for a comprehensive understanding of the header file's purpose and functionalities, leading to the desired summary.```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_RISCV_LIFTOFF_ASSEMBLER_RISCV32_INL_H_
#define V8_WASM_BASELINE_RISCV_LIFTOFF_ASSEMBLER_RISCV32_INL_H_

#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h"
#include "src/wasm/wasm-objects.h"
namespace v8::internal::wasm {

namespace liftoff {

// Liftoff Frames.
//
//  slot      Frame
//       +--------------------+---------------------------
//  n+4  | optional padding slot to keep the stack 16 byte aligned.
//  n+3  |   parameter n      |
//  ... |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   1   | return addr (ra)   |
//   0   | previous frame (fp)|
//  -----+--------------------+  <-- frame ptr (fp)
//  -1   | StackFrame::WASM   |
//  -2   |     instance       |
//  -3   |     feedback vector|
//  -----+--------------------+---------------------------
//  -4   |     slot 0         |   ^
//  -5   |     slot 1         |   |
//       |                    | Frame slots
//       |                    |   |
//       |                    |   v
//       | optional padding slot to keep the stack 16 byte aligned.
//  -----+--------------------+  <-- stack ptr (sp)
//

#if defined(V8_TARGET_BIG_ENDIAN)
constexpr int32_t kLowWordOffset = 4;
constexpr int32_t kHighWordOffset = 0;
#else
constexpr int32_t kLowWordOffset = 0;
constexpr int32_t kHighWordOffset = 4;
#endif

inline MemOperand GetHalfStackSlot(int offset, RegPairHalf half) {
  int32_t half_offset =
      half == kLowWord ? 0 : LiftoffAssembler::kStackSlotSize / 2;
  return MemOperand(offset > 0 ? fp : sp, -offset + half_offset);
}

inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, uintptr_t offset_imm,
                           unsigned shift_amount = 0) {
  DCHECK_NE(addr, kScratchReg2);
  DCHECK_NE(offset, kScratchReg2);
  if (is_uint31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    if (offset == no_reg) return MemOperand(addr, offset_imm32);
    if (shift_amount != 0) {
      assm->CalcScaledAddress(kScratchReg2, addr, offset, shift_amount);
    } else {
      assm->AddWord(kScratchReg2, offset, addr);
    }
    return MemOperand(kScratchReg2, offset_imm32);
  }
  // Offset immediate does not fit in 31 bits.
  assm->li(kScratchReg2, offset_imm);
  assm->AddWord(kScratchReg2, kScratchReg2, addr);
  if (offset != no_reg) {
    if (shift_amount != 0) {
      assm->CalcScaledAddress(kScratchReg2, kScratchReg2, offset, shift_amount);
    } else {
      assm->AddWord(kScratchReg2, kScratchReg2, offset);
    }
  }
  return MemOperand(kScratchReg2, 0);
}

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, Register base,
                 int32_t offset, ValueKind kind) {
  MemOperand src(base, offset);

  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->Lw(dst.gp(), src);
      break;
    case kI64:
      assm->Lw(dst.low_gp(),
               MemOperand(base, offset + liftoff::kLowWordOffset));
      assm->Lw(dst.high_gp(),
               MemOperand(base, offset + liftoff::kHighWordOffset));
      break;
    case kF32:
      assm->LoadFloat(dst.fp(), src);
      break;
    case kF64:
      assm->LoadDouble(dst.fp(), src);
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      Register src_reg = src.offset() == 0 ? src.rm() : kScratchReg;
      if (src.offset() != 0) {
        assm->AddWord(src_reg, src.rm(), src.offset());
      }
      assm->vl(dst.fp().toV(), src_reg, 0, E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  MemOperand dst(base, offset);
  switch (kind) {
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->Sw(src.gp(), dst);
      break;
    case kI64:
      assm->Sw(src.low_gp(),
               MemOperand(base, offset + liftoff::kLowWordOffset));
      assm->Sw(src.high_gp(),
               MemOperand(base, offset + liftoff::kHighWordOffset));
      break;
    case kF32:
      assm->StoreFloat(src.fp(), dst);
      break;
    case kF64:
      assm->StoreDouble(src.fp(), dst);
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      Register dst_reg = dst.offset() == 0 ? dst.rm() : kScratchReg;
      if (dst.offset() != 0) {
        assm->AddWord(kScratchReg, dst.rm(), dst.offset());
      }
      assm->vs(src.fp().toV(), dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind) {
  switch (kind) {
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->addi(sp, sp, -kSystemPointerSize);
      assm->Sw(reg.gp(), MemOperand(sp, 0));
      break;
    case kI64:
      assm->Push(reg.high_gp(), reg.low_gp());
      break;
    case kF32:
      assm->addi(sp, sp, -kSystemPointerSize);
      assm->StoreFloat(reg.fp(), MemOperand(sp, 0));
      break;
    case kF64:
      assm->addi(sp, sp, -kDoubleSize);
      assm->StoreDouble(reg.fp(), MemOperand(sp, 0));
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      assm->addi(sp, sp, -kSystemPointerSize * 4);
      assm->vs(reg.fp().toV(), sp, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline Register EnsureNoAlias(Assembler* assm, Register reg,
                              LiftoffRegister must_not_alias,
                              UseScratchRegisterScope* temps) {
  if (reg != must_not_alias.low_gp() && reg != must_not_alias.high_gp())
    return reg;
  Register tmp = temps->Acquire();
  DCHECK_NE(must_not_alias.low_gp(), tmp);
  DCHECK_NE(must_not_alias.high_gp(), tmp);
  assm->mv(tmp, reg);
  return tmp;
}
}  // namespace liftoff

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::li(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::li(reg.low_gp(), Operand(low_word));
      MacroAssembler::li(reg.high_gp(), Operand(high_word));
      break;
    }
    case kF32:
      MacroAssembler::LoadFPRImmediate(reg.fp(),
                                       value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::LoadFPRImmediate(reg.fp(),
                                       value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  static_assert(kTaggedSize == kSystemPointerSize);
  Load(LiftoffRegister(dst), src_addr, offset_reg,
       static_cast<uint32_t>(offset_imm), LoadType::kI32Load, protected_load_pc,
       false, false, needs_shift);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  MemOperand src_op = MemOperand(src_addr, offset_imm);
  LoadWord(dst, src_op);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  static_assert(kTaggedSize == kInt32Size);
  UseScratchRegisterScope temps{this};
  Register actual_offset_reg = offset_reg;
  if (offset_reg != no_reg && offset_imm != 0) {
    if (cache_state()->is_used(LiftoffRegister(offset_reg))) {
      // The code below only needs a scratch register if the {MemOperand} given
      // to {str} has an offset outside the uint12 range. After doing the
      // addition below we will not pass an immediate offset to {str} though, so
      // we can use the scratch register here.
      actual_offset_reg = temps.Acquire();
    }
    Add32(actual_offset_reg, offset_reg, Operand(offset_imm));
  }
  MemOperand dst_op = MemOperand(kScratchReg, 0);
  if (actual_offset_reg == no_reg) {
    dst_op = MemOperand(dst_addr, offset_imm);
  } else {
    AddWord(kScratchReg, dst_addr, actual_offset_reg);
    dst_op = MemOperand(kScratchReg, 0);
  }
  auto trapper = [protected_store_pc](int offset) {
    if (protected_store_pc) *protected_store_pc = static_cast<uint32_t>(offset);
  };
  StoreWord(src, dst_op, trapper);
  if (protected_store_pc) {
    DCHECK(InstructionAt(*protected_store_pc)->IsStore());
  }

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  // The write barrier.
  Label exit;
  CheckPageFlag(dst_addr, MemoryChunk::kPointersFromHereAreInterestingMask,
                kZero, &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, MemoryChunk::kPointersToHereAreInterestingMask, eq, &exit);
  CallRecordWriteStubSaveRegisters(
      dst_addr,
      actual_offset_reg == no_reg ? Operand(offset_imm)
                                  : Operand(actual_offset_reg),
      SaveFPRegsMode::kSave, StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool /* i64_offset */,
                            bool needs_shift) {
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  MemOperand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm, shift_amount);
  auto trapper = [protected_load_pc](int offset) {
    if (protected_load_pc) *protected_load_pc = static_cast<uint32_t>(offset);
  };
  switch (type.value()) {
    case LoadType::kI32Load8U:
      Lbu(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load8U:
      Lbu(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI32Load8S:
      Lb(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load8S:
      Lb(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI32Load16U:
      Lhu(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load16U:
      Lhu(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI32Load16S:
      Lh(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load16S:
      Lh(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI64Load32U:
      Lw(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI64Load32S:
      Lw(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI32Load:
      Lw(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load: {
      Lw(dst.low_gp(), src_op, trapper);
      src_op = liftoff::GetMemOp(this, src_addr, offset_reg,
                                 offset_imm + kSystemPointerSize);
      Lw(dst.high_gp(), src_op);
    } break;
    case LoadType::kF32Load:
      LoadFloat(dst.fp(), src_op, trapper);
      break;
    case LoadType::kF64Load:
      LoadDouble(dst.fp(), src_op, trapper);
      break;
    case LoadType::kS128Load: {
      VU.set(kScratchReg, E8, m1);
      Register src_reg = src_op.offset() == 0 ? src_op.rm() : kScratchReg;
      if (src_op.offset() != 0) {
        AddWord(src_reg, src_op.rm(), src_op.offset());
      }
      trapper(pc_offset());
      vl(dst.fp().toV(), src_reg, 0, E8);
      break;
    }
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
    default:
      UNREACHABLE();
  }
  if (protected_load_pc) {
    DCHECK(InstructionAt(*protected_load_pc)->IsLoad());
  }

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_load_mem) {
    pinned.set(src_op.rm());
    liftoff::ChangeEndiannessLoad(this, dst, type, pinned);
  }
#endif
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  MemOperand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_store_mem) {
    pinned.set(dst_op.rm());
    LiftoffRegister tmp = GetUnusedRegister(src.reg_class(), pinned);
    // Save original value.
    Move(tmp, src, type.value_type());

    src = tmp;
    pinned.set(tmp);
    liftoff::ChangeEndiannessStore(this, src, type, pinned);
  }
#endif
  auto trapper = [protected_store_pc](int offset) {
    if (protected_store_pc) *protected_store_pc = static_cast<uint32_t>(offset);
  };
  switch (type.value()) {
    case StoreType::kI32Store8:
      Sb(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store8:
      Sb(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI32Store16:
      Sh(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store16:
      Sh(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI32Store:
      Sw(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store32:
      Sw(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store: {
      Sw(src.low_gp(), dst_op, trapper);
      dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg,
                                 offset_imm + kSystemPointerSize);
      Sw(src.high_gp(), dst_op, trapper);
      break;
    }
    case StoreType::kF32Store:
      StoreFloat(src.fp(), dst_op, trapper);
      break;
    case StoreType::kF64Store:
      StoreDouble(src.fp(), dst_op, trapper);
      break;
    case StoreType::kS128Store: {
      VU.set(kScratchReg, E8, m1);
      Register dst_reg = dst_op.offset() == 0 ? dst_op.rm() : kScratchReg;
      if (dst_op.offset() != 0) {
        AddWord(kScratchReg, dst_op.rm(), dst_op.offset());
      }
      trapper(pc_offset());
      vs(src.fp().toV(), dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
  if (protected_store_pc) {
    DCHECK(InstructionAt(*protected_store_pc)->IsStore());
  }
}

namespace liftoff {
#define __ lasm->

inline Register CalculateActualAddress(LiftoffAssembler* lasm,
                                       UseScratchRegisterScope& temps,
                                       Register addr_reg, Register offset_reg,
                                       uintptr_t offset_imm,
                                       Register result_reg = no_reg) {
  if (offset_reg == no_reg && offset_imm == 0) {
    if (result_reg == addr_reg || result_reg == no_reg) return addr_reg;
    lasm->mv(result_reg, addr_reg);
    return result_reg;
  }
  if (result_reg == no_reg) result_reg = temps.Acquire();
  if (offset_reg == no_reg) {
    lasm->AddWord(result_reg, addr_reg, Operand(offset_imm));
  } else {
    lasm->AddWord(result_reg, addr_reg, Operand(offset_reg));
    if (offset_imm != 0)
      lasm->AddWord(result_reg, result_reg, Operand(offset_imm));
  }
  return result_reg;
}

enum class Binop { kAdd, kSub, kAnd, kOr, kXor, kExchange };
inline void AtomicBinop64(LiftoffAssembler* lasm, Register dst_addr,
                          Register offset_reg, uintptr_t offset_imm,
                          LiftoffRegister value, LiftoffRegister result,
                          StoreType type, Binop op) {
  ASM_CODE_COMMENT(lasm);
  FrameScope scope(lasm, StackFrame::MANUAL);
  RegList c_params = {kCArgRegs[0], kCArgRegs[1], kCArgRegs[2]};
  RegList result_list = {result.low_gp(), result.high_gp()};
  // Result registers does not need to be pushed.
  __ MultiPush(c_params - result_list);
  UseScratchRegisterScope temps(lasm);
  liftoff::CalculateActualAddress(lasm, temps, dst_addr, offset_reg, offset_imm,
                                  kScratchReg);
  __ Mv(kCArgRegs[1], value.low_gp());
  __ Mv(kCArgRegs[2], value.high_gp());
  __ Mv(kCArgRegs[0], kScratchReg);
  __ MultiPush(kJSCallerSaved - c_params - result_list);
  __ PrepareCallCFunction(3, 0, kScratchReg);
  ExternalReference extern_func_ref;
  switch (op) {
    case Binop::kAdd:
      extern_func_ref = ExternalReference::atomic_pair_add_function();
      break;
    case Binop::kSub:
      extern_func_ref = ExternalReference::atomic_pair_sub_function();
      break;
    case Binop::kAnd:
      extern_func_ref = ExternalReference::atomic_pair_and_function();
      break;
    case Binop::kOr:
      extern_func_ref = ExternalReference::atomic_pair_or_function();
      break;
    case Binop::kXor:
      extern_func_ref = ExternalReference::atomic_pair_xor_function();
      break;
    case Binop::kExchange:
      extern_func_ref = ExternalReference::atomic_pair_exchange_function();
      break;
    default:
      UNREACHABLE();
  }
  __ CallCFunction(extern_func_ref, 3, 0);
  __ MultiPop(kJSCallerSaved - c_params - result_list);
  __ Mv(result.low_gp(), kReturnRegister0);
  __ Mv(result.high_gp(), kReturnRegister1);
  __ MultiPop(c_params - result_list);
  return;
}

inline void AtomicBinop(LiftoffAssembler* lasm, Register dst_addr,
                        Register offset_reg, uintptr_t offset_imm,
                        LiftoffRegister value, LiftoffRegister result,
                        StoreType type, Binop op) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register store_result = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

  // Make sure that {result} is unique.
  Register result_reg = no_reg;
  Register value_reg = no_reg;
  bool change_result = false;
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI64Store16:
      __ LoadConstant(result.high(), WasmValue(0));
      result_reg = result.low_gp();
      value_reg = value.low_gp();
      break;
    case StoreType::kI32Store8:
    case StoreType::kI32Store16:
      result_reg = result.gp();
      value_reg = value.gp();
      break;
    default:
      UNREACHABLE();
  }
  if (result_reg == value_reg || result_reg == dst_addr ||
      result_reg == offset_reg) {
    result_reg = __ GetUnusedRegister(kGpReg, pinned).gp();
    change_result = true;
  }

  UseScratchRegisterScope temps(lasm);
  Register actual_addr = liftoff::CalculateActualAddress(
      lasm, temps, dst_addr, offset_reg, offset_imm);

  // Allocate an additional {temp} register to hold the result that should be
  // stored to memory. Note that {temp} and {store_result} are not allowed to be
  // the same register.
  Register temp = temps.Acquire();

  Label retry;
  __ bind(&retry);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      __ lbu(result_reg, actual_addr, 0);
      __ sync();
      break;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      __ lhu(result_reg, actual_addr, 0);
      __ sync();
      break;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      __ lr_w(true, false, result_reg, actual_addr);
      break;
    default:
      UNREACHABLE();
  }

  switch (op) {
    case Binop::kAdd:
      __ add(temp, result_reg, value_reg);
      break;
    case Binop::kSub:
      __ sub(temp, result_reg, value_reg);
      break;
    case Binop::kAnd:
      __ and_(temp, result_reg, value_reg);
      break;
    case Binop::kOr:
      __ or_(temp, result_reg, value_reg);
      break;
    case Binop::kXor:
      __ xor_(temp, result_reg, value_reg);
      break;
    
### 提示词
```
这是目录为v8/src/wasm/baseline/riscv/liftoff-assembler-riscv32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/riscv/liftoff-assembler-riscv32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_RISCV_LIFTOFF_ASSEMBLER_RISCV32_INL_H_
#define V8_WASM_BASELINE_RISCV_LIFTOFF_ASSEMBLER_RISCV32_INL_H_

#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/riscv/liftoff-assembler-riscv-inl.h"
#include "src/wasm/wasm-objects.h"
namespace v8::internal::wasm {

namespace liftoff {

// Liftoff Frames.
//
//  slot      Frame
//       +--------------------+---------------------------
//  n+4  | optional padding slot to keep the stack 16 byte aligned.
//  n+3  |   parameter n      |
//  ...  |       ...          |
//   4   |   parameter 1      | or parameter 2
//   3   |   parameter 0      | or parameter 1
//   2   |  (result address)  | or parameter 0
//  -----+--------------------+---------------------------
//   1   | return addr (ra)   |
//   0   | previous frame (fp)|
//  -----+--------------------+  <-- frame ptr (fp)
//  -1   | StackFrame::WASM   |
//  -2   |     instance       |
//  -3   |     feedback vector|
//  -----+--------------------+---------------------------
//  -4   |     slot 0         |   ^
//  -5   |     slot 1         |   |
//       |                    | Frame slots
//       |                    |   |
//       |                    |   v
//       | optional padding slot to keep the stack 16 byte aligned.
//  -----+--------------------+  <-- stack ptr (sp)
//

#if defined(V8_TARGET_BIG_ENDIAN)
constexpr int32_t kLowWordOffset = 4;
constexpr int32_t kHighWordOffset = 0;
#else
constexpr int32_t kLowWordOffset = 0;
constexpr int32_t kHighWordOffset = 4;
#endif

inline MemOperand GetHalfStackSlot(int offset, RegPairHalf half) {
  int32_t half_offset =
      half == kLowWord ? 0 : LiftoffAssembler::kStackSlotSize / 2;
  return MemOperand(offset > 0 ? fp : sp, -offset + half_offset);
}

inline MemOperand GetMemOp(LiftoffAssembler* assm, Register addr,
                           Register offset, uintptr_t offset_imm,
                           unsigned shift_amount = 0) {
  DCHECK_NE(addr, kScratchReg2);
  DCHECK_NE(offset, kScratchReg2);
  if (is_uint31(offset_imm)) {
    int32_t offset_imm32 = static_cast<int32_t>(offset_imm);
    if (offset == no_reg) return MemOperand(addr, offset_imm32);
    if (shift_amount != 0) {
      assm->CalcScaledAddress(kScratchReg2, addr, offset, shift_amount);
    } else {
      assm->AddWord(kScratchReg2, offset, addr);
    }
    return MemOperand(kScratchReg2, offset_imm32);
  }
  // Offset immediate does not fit in 31 bits.
  assm->li(kScratchReg2, offset_imm);
  assm->AddWord(kScratchReg2, kScratchReg2, addr);
  if (offset != no_reg) {
    if (shift_amount != 0) {
      assm->CalcScaledAddress(kScratchReg2, kScratchReg2, offset, shift_amount);
    } else {
      assm->AddWord(kScratchReg2, kScratchReg2, offset);
    }
  }
  return MemOperand(kScratchReg2, 0);
}

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, Register base,
                 int32_t offset, ValueKind kind) {
  MemOperand src(base, offset);

  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->Lw(dst.gp(), src);
      break;
    case kI64:
      assm->Lw(dst.low_gp(),
               MemOperand(base, offset + liftoff::kLowWordOffset));
      assm->Lw(dst.high_gp(),
               MemOperand(base, offset + liftoff::kHighWordOffset));
      break;
    case kF32:
      assm->LoadFloat(dst.fp(), src);
      break;
    case kF64:
      assm->LoadDouble(dst.fp(), src);
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      Register src_reg = src.offset() == 0 ? src.rm() : kScratchReg;
      if (src.offset() != 0) {
        assm->AddWord(src_reg, src.rm(), src.offset());
      }
      assm->vl(dst.fp().toV(), src_reg, 0, E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  MemOperand dst(base, offset);
  switch (kind) {
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->Sw(src.gp(), dst);
      break;
    case kI64:
      assm->Sw(src.low_gp(),
               MemOperand(base, offset + liftoff::kLowWordOffset));
      assm->Sw(src.high_gp(),
               MemOperand(base, offset + liftoff::kHighWordOffset));
      break;
    case kF32:
      assm->StoreFloat(src.fp(), dst);
      break;
    case kF64:
      assm->StoreDouble(src.fp(), dst);
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      Register dst_reg = dst.offset() == 0 ? dst.rm() : kScratchReg;
      if (dst.offset() != 0) {
        assm->AddWord(kScratchReg, dst.rm(), dst.offset());
      }
      assm->vs(src.fp().toV(), dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind) {
  switch (kind) {
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->addi(sp, sp, -kSystemPointerSize);
      assm->Sw(reg.gp(), MemOperand(sp, 0));
      break;
    case kI64:
      assm->Push(reg.high_gp(), reg.low_gp());
      break;
    case kF32:
      assm->addi(sp, sp, -kSystemPointerSize);
      assm->StoreFloat(reg.fp(), MemOperand(sp, 0));
      break;
    case kF64:
      assm->addi(sp, sp, -kDoubleSize);
      assm->StoreDouble(reg.fp(), MemOperand(sp, 0));
      break;
    case kS128:{
      assm->VU.set(kScratchReg, E8, m1);
      assm->addi(sp, sp, -kSystemPointerSize * 4);
      assm->vs(reg.fp().toV(), sp, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
}

inline Register EnsureNoAlias(Assembler* assm, Register reg,
                              LiftoffRegister must_not_alias,
                              UseScratchRegisterScope* temps) {
  if (reg != must_not_alias.low_gp() && reg != must_not_alias.high_gp())
    return reg;
  Register tmp = temps->Acquire();
  DCHECK_NE(must_not_alias.low_gp(), tmp);
  DCHECK_NE(must_not_alias.high_gp(), tmp);
  assm->mv(tmp, reg);
  return tmp;
}
}  // namespace liftoff

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::li(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::li(reg.low_gp(), Operand(low_word));
      MacroAssembler::li(reg.high_gp(), Operand(high_word));
      break;
    }
    case kF32:
      MacroAssembler::LoadFPRImmediate(reg.fp(),
                                       value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::LoadFPRImmediate(reg.fp(),
                                       value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  static_assert(kTaggedSize == kSystemPointerSize);
  Load(LiftoffRegister(dst), src_addr, offset_reg,
       static_cast<uint32_t>(offset_imm), LoadType::kI32Load, protected_load_pc,
       false, false, needs_shift);
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  MemOperand src_op = MemOperand(src_addr, offset_imm);
  LoadWord(dst, src_op);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  static_assert(kTaggedSize == kInt32Size);
  UseScratchRegisterScope temps{this};
  Register actual_offset_reg = offset_reg;
  if (offset_reg != no_reg && offset_imm != 0) {
    if (cache_state()->is_used(LiftoffRegister(offset_reg))) {
      // The code below only needs a scratch register if the {MemOperand} given
      // to {str} has an offset outside the uint12 range. After doing the
      // addition below we will not pass an immediate offset to {str} though, so
      // we can use the scratch register here.
      actual_offset_reg = temps.Acquire();
    }
    Add32(actual_offset_reg, offset_reg, Operand(offset_imm));
  }
  MemOperand dst_op = MemOperand(kScratchReg, 0);
  if (actual_offset_reg == no_reg) {
    dst_op = MemOperand(dst_addr, offset_imm);
  } else {
    AddWord(kScratchReg, dst_addr, actual_offset_reg);
    dst_op = MemOperand(kScratchReg, 0);
  }
  auto trapper = [protected_store_pc](int offset) {
    if (protected_store_pc) *protected_store_pc = static_cast<uint32_t>(offset);
  };
  StoreWord(src, dst_op, trapper);
  if (protected_store_pc) {
    DCHECK(InstructionAt(*protected_store_pc)->IsStore());
  }

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  // The write barrier.
  Label exit;
  CheckPageFlag(dst_addr, MemoryChunk::kPointersFromHereAreInterestingMask,
                kZero, &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, MemoryChunk::kPointersToHereAreInterestingMask, eq, &exit);
  CallRecordWriteStubSaveRegisters(
      dst_addr,
      actual_offset_reg == no_reg ? Operand(offset_imm)
                                  : Operand(actual_offset_reg),
      SaveFPRegsMode::kSave, StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool /* i64_offset */,
                            bool needs_shift) {
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  MemOperand src_op =
      liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm, shift_amount);
  auto trapper = [protected_load_pc](int offset) {
    if (protected_load_pc) *protected_load_pc = static_cast<uint32_t>(offset);
  };
  switch (type.value()) {
    case LoadType::kI32Load8U:
      Lbu(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load8U:
      Lbu(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI32Load8S:
      Lb(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load8S:
      Lb(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI32Load16U:
      Lhu(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load16U:
      Lhu(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI32Load16S:
      Lh(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load16S:
      Lh(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI64Load32U:
      Lw(dst.low_gp(), src_op, trapper);
      mv(dst.high_gp(), zero_reg);
      break;
    case LoadType::kI64Load32S:
      Lw(dst.low_gp(), src_op, trapper);
      srai(dst.high_gp(), dst.low_gp(), 31);
      break;
    case LoadType::kI32Load:
      Lw(dst.gp(), src_op, trapper);
      break;
    case LoadType::kI64Load: {
      Lw(dst.low_gp(), src_op, trapper);
      src_op = liftoff::GetMemOp(this, src_addr, offset_reg,
                                 offset_imm + kSystemPointerSize);
      Lw(dst.high_gp(), src_op);
    } break;
    case LoadType::kF32Load:
      LoadFloat(dst.fp(), src_op, trapper);
      break;
    case LoadType::kF64Load:
      LoadDouble(dst.fp(), src_op, trapper);
      break;
    case LoadType::kS128Load: {
      VU.set(kScratchReg, E8, m1);
      Register src_reg = src_op.offset() == 0 ? src_op.rm() : kScratchReg;
      if (src_op.offset() != 0) {
        AddWord(src_reg, src_op.rm(), src_op.offset());
      }
      trapper(pc_offset());
      vl(dst.fp().toV(), src_reg, 0, E8);
      break;
    }
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
    default:
      UNREACHABLE();
  }
  if (protected_load_pc) {
    DCHECK(InstructionAt(*protected_load_pc)->IsLoad());
  }

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_load_mem) {
    pinned.set(src_op.rm());
    liftoff::ChangeEndiannessLoad(this, dst, type, pinned);
  }
#endif
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  MemOperand dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm);

#if defined(V8_TARGET_BIG_ENDIAN)
  if (is_store_mem) {
    pinned.set(dst_op.rm());
    LiftoffRegister tmp = GetUnusedRegister(src.reg_class(), pinned);
    // Save original value.
    Move(tmp, src, type.value_type());

    src = tmp;
    pinned.set(tmp);
    liftoff::ChangeEndiannessStore(this, src, type, pinned);
  }
#endif
  auto trapper = [protected_store_pc](int offset) {
    if (protected_store_pc) *protected_store_pc = static_cast<uint32_t>(offset);
  };
  switch (type.value()) {
    case StoreType::kI32Store8:
      Sb(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store8:
      Sb(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI32Store16:
      Sh(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store16:
      Sh(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI32Store:
      Sw(src.gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store32:
      Sw(src.low_gp(), dst_op, trapper);
      break;
    case StoreType::kI64Store: {
      Sw(src.low_gp(), dst_op, trapper);
      dst_op = liftoff::GetMemOp(this, dst_addr, offset_reg,
                                 offset_imm + kSystemPointerSize);
      Sw(src.high_gp(), dst_op, trapper);
      break;
    }
    case StoreType::kF32Store:
      StoreFloat(src.fp(), dst_op, trapper);
      break;
    case StoreType::kF64Store:
      StoreDouble(src.fp(), dst_op, trapper);
      break;
    case StoreType::kS128Store: {
      VU.set(kScratchReg, E8, m1);
      Register dst_reg = dst_op.offset() == 0 ? dst_op.rm() : kScratchReg;
      if (dst_op.offset() != 0) {
        AddWord(kScratchReg, dst_op.rm(), dst_op.offset());
      }
      trapper(pc_offset());
      vs(src.fp().toV(), dst_reg, 0, VSew::E8);
      break;
    }
    default:
      UNREACHABLE();
  }
  if (protected_store_pc) {
    DCHECK(InstructionAt(*protected_store_pc)->IsStore());
  }
}

namespace liftoff {
#define __ lasm->

inline Register CalculateActualAddress(LiftoffAssembler* lasm,
                                       UseScratchRegisterScope& temps,
                                       Register addr_reg, Register offset_reg,
                                       uintptr_t offset_imm,
                                       Register result_reg = no_reg) {
  if (offset_reg == no_reg && offset_imm == 0) {
    if (result_reg == addr_reg || result_reg == no_reg) return addr_reg;
    lasm->mv(result_reg, addr_reg);
    return result_reg;
  }
  if (result_reg == no_reg) result_reg = temps.Acquire();
  if (offset_reg == no_reg) {
    lasm->AddWord(result_reg, addr_reg, Operand(offset_imm));
  } else {
    lasm->AddWord(result_reg, addr_reg, Operand(offset_reg));
    if (offset_imm != 0)
      lasm->AddWord(result_reg, result_reg, Operand(offset_imm));
  }
  return result_reg;
}

enum class Binop { kAdd, kSub, kAnd, kOr, kXor, kExchange };
inline void AtomicBinop64(LiftoffAssembler* lasm, Register dst_addr,
                          Register offset_reg, uintptr_t offset_imm,
                          LiftoffRegister value, LiftoffRegister result,
                          StoreType type, Binop op) {
  ASM_CODE_COMMENT(lasm);
  FrameScope scope(lasm, StackFrame::MANUAL);
  RegList c_params = {kCArgRegs[0], kCArgRegs[1], kCArgRegs[2]};
  RegList result_list = {result.low_gp(), result.high_gp()};
  // Result registers does not need to be pushed.
  __ MultiPush(c_params - result_list);
  UseScratchRegisterScope temps(lasm);
  liftoff::CalculateActualAddress(lasm, temps, dst_addr, offset_reg, offset_imm,
                                  kScratchReg);
  __ Mv(kCArgRegs[1], value.low_gp());
  __ Mv(kCArgRegs[2], value.high_gp());
  __ Mv(kCArgRegs[0], kScratchReg);
  __ MultiPush(kJSCallerSaved - c_params - result_list);
  __ PrepareCallCFunction(3, 0, kScratchReg);
  ExternalReference extern_func_ref;
  switch (op) {
    case Binop::kAdd:
      extern_func_ref = ExternalReference::atomic_pair_add_function();
      break;
    case Binop::kSub:
      extern_func_ref = ExternalReference::atomic_pair_sub_function();
      break;
    case Binop::kAnd:
      extern_func_ref = ExternalReference::atomic_pair_and_function();
      break;
    case Binop::kOr:
      extern_func_ref = ExternalReference::atomic_pair_or_function();
      break;
    case Binop::kXor:
      extern_func_ref = ExternalReference::atomic_pair_xor_function();
      break;
    case Binop::kExchange:
      extern_func_ref = ExternalReference::atomic_pair_exchange_function();
      break;
    default:
      UNREACHABLE();
  }
  __ CallCFunction(extern_func_ref, 3, 0);
  __ MultiPop(kJSCallerSaved - c_params - result_list);
  __ Mv(result.low_gp(), kReturnRegister0);
  __ Mv(result.high_gp(), kReturnRegister1);
  __ MultiPop(c_params - result_list);
  return;
}

inline void AtomicBinop(LiftoffAssembler* lasm, Register dst_addr,
                        Register offset_reg, uintptr_t offset_imm,
                        LiftoffRegister value, LiftoffRegister result,
                        StoreType type, Binop op) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register store_result = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

  // Make sure that {result} is unique.
  Register result_reg = no_reg;
  Register value_reg = no_reg;
  bool change_result = false;
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI64Store16:
      __ LoadConstant(result.high(), WasmValue(0));
      result_reg = result.low_gp();
      value_reg = value.low_gp();
      break;
    case StoreType::kI32Store8:
    case StoreType::kI32Store16:
      result_reg = result.gp();
      value_reg = value.gp();
      break;
    default:
      UNREACHABLE();
  }
  if (result_reg == value_reg || result_reg == dst_addr ||
      result_reg == offset_reg) {
    result_reg = __ GetUnusedRegister(kGpReg, pinned).gp();
    change_result = true;
  }

  UseScratchRegisterScope temps(lasm);
  Register actual_addr = liftoff::CalculateActualAddress(
      lasm, temps, dst_addr, offset_reg, offset_imm);

  // Allocate an additional {temp} register to hold the result that should be
  // stored to memory. Note that {temp} and {store_result} are not allowed to be
  // the same register.
  Register temp = temps.Acquire();

  Label retry;
  __ bind(&retry);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      __ lbu(result_reg, actual_addr, 0);
      __ sync();
      break;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      __ lhu(result_reg, actual_addr, 0);
      __ sync();
      break;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      __ lr_w(true, false, result_reg, actual_addr);
      break;
    default:
      UNREACHABLE();
  }

  switch (op) {
    case Binop::kAdd:
      __ add(temp, result_reg, value_reg);
      break;
    case Binop::kSub:
      __ sub(temp, result_reg, value_reg);
      break;
    case Binop::kAnd:
      __ and_(temp, result_reg, value_reg);
      break;
    case Binop::kOr:
      __ or_(temp, result_reg, value_reg);
      break;
    case Binop::kXor:
      __ xor_(temp, result_reg, value_reg);
      break;
    case Binop::kExchange:
      __ mv(temp, value_reg);
      break;
  }
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      __ sync();
      __ sb(temp, actual_addr, 0);
      __ sync();
      __ mv(store_result, zero_reg);
      break;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      __ sync();
      __ sh(temp, actual_addr, 0);
      __ sync();
      __ mv(store_result, zero_reg);
      break;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      __ sc_w(false, true, store_result, actual_addr, temp);
      break;
    default:
      UNREACHABLE();
  }

  __ bnez(store_result, &retry);
  if (change_result) {
    switch (type.value()) {
      case StoreType::kI64Store8:
      case StoreType::kI64Store16:
      case StoreType::kI64Store32:
        __ mv(result.low_gp(), result_reg);
        break;
      case StoreType::kI32Store8:
      case StoreType::kI32Store16:
      case StoreType::kI32Store:
        __ mv(result.gp(), result_reg);
        break;
      default:
        UNREACHABLE();
    }
  }
}

#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList pinned,
                                  bool i64_offset) {
  UseScratchRegisterScope temps(this);
  Register src_reg = liftoff::CalculateActualAddress(this, temps, src_addr,
                                                     offset_reg, offset_imm);
  Register dst_reg = no_reg;
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI32Load16U:
    case LoadType::kI32Load:
      dst_reg = dst.gp();
      break;
    case LoadType::kI64Load8U:
    case LoadType::kI64Load16U:
    case LoadType::kI64Load32U:
      dst_reg = dst.low_gp();
      LoadConstant(dst.high(), WasmValue(0));
      break;
    default:
      break;
  }
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      fence(PSR | PSW, PSR | PSW);
      lbu(dst_reg, src_reg, 0);
      fence(PSR, PSR | PSW);
      return;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      fence(PSR | PSW, PSR | PSW);
      lhu(dst_reg, src_reg, 0);
      fence(PSR, PSR | PSW);
      return;
    case LoadType::kI32Load:
    case LoadType::kI64Load32U:
      fence(PSR | PSW, PSR | PSW);
      lw(dst_reg, src_reg, 0);
      fence(PSR, PSR | PSW);
      return;
    case LoadType::kI64Load:
      fence(PSR | PSW, PSR | PSW);
      lw(dst.low_gp(), src_reg, liftoff::kLowWordOffset);
      lw(dst.high_gp(), src_reg, liftoff::kHighWordOffset);
      fence(PSR, PSR | PSW);
      return;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool i64_offset) {
  UseScratchRegisterScope temps(this);
  Register dst_reg = liftoff::CalculateActualAddress(this, temps, dst_addr,
                                                     offset_reg, offset_imm);
  Register src_reg = no_reg;
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI32Store16:
    case StoreType::kI32Store:
      src_reg = src.gp();
      break;
    case StoreType::kI64Store8:
    case StoreType::kI64Store16:
    case StoreType::kI64Store32:
      src_reg = src.low_gp();
      break;
    default:
      break;
  }
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      fence(PSR | PSW, PSW);
      sb(src_reg, dst_reg, 0);
      return;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      fence(PSR | PSW, PSW);
      sh(src_reg, dst_reg, 0);
      return;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      fence(PSR | PSW, PSW);
      sw(src_reg, dst_reg, 0);
      return;
    case StoreType::kI64Store:
      fence(PSR | PSW, PSW);
      sw(src.low_gp(), dst_reg, liftoff::kLowWordOffset);
      sw(src.high_gp(), dst_reg, liftoff::kHighWordOffset);
      return;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kAdd);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);  // High word of result is always 0.
      result = result.low();
      value = value.low();
    }
    amoadd_w(true, true, result.gp(), actual_addr, value.gp());
    return;
  }

  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kAdd);
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kSub);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);
      result = result.low();
      value = value.low();
    }
    sub(kScratchReg, zero_reg, value.gp());
    amoadd_w(true, true, result.gp(), actual_addr, kScratchReg);
    return;
  }
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kSub);
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kAnd);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);
      result = result.low();
      value = value.low();
    }
    amoand_w(true, true, result.gp(), actual_addr, value.gp());
    return;
  }
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kAnd);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uint32_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kOr);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);
      result = result.low();
      value = value.low();
    }
    amoor_w(true, true, result.gp(), actual_addr, value.gp());
    return;
  }
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kOr);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uint32_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kXor);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);
      result = result.low();
      value = value.low();
    }
    amoxor_w(true, true, result.gp(), actual_addr, value.gp());
    return;
  }
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kXor);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uint32_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  if (type.value() == StoreType::kI64Store) {
    liftoff::AtomicBinop64(this, dst_addr, offset_reg, offset_imm, value,
                           result, type, liftoff::Binop::kExchange);
    return;
  }
  if (type.value() == StoreType::kI32Store ||
      type.value() == StoreType::kI64Store32) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm);
    if (type.value() == StoreType::kI64Store32) {
      mv(result.high_gp(), zero_reg);
      result = result.low();
      value = value.low();
    }
    amoswap_w(true, true, result.gp(), actual_addr, value.gp());
    return;
  }
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kExchange);
}

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {
  ASM_CODE_COMMENT(this);
  LiftoffRegList pinned{dst_addr, expected, new_value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);

  if (type.value() == StoreType::kI64Store) {
    UseScratchRegisterScope temps(this);
    Register actual_addr = liftoff::CalculateActualAddress(
        this, temps, dst_addr, offset_reg, offset_imm, kScratchReg);
    FrameScope scope(this, StackFrame::MANUAL);
    // NOTE:
    // a0~a4 are caller-saved registers and also used
    // to pass parameters for C functions.
    RegList c_params = {kCArgRegs[0], kCArgRegs[1], kCArgRegs[2], kCArgRegs[3],
                        a4};
    RegList result_list = {result.low_gp(), result.high_gp()};
    MultiPush(c_params - result_list);

    Mv(a1, expected.low_gp());
    Mv(a2,
```