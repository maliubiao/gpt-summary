Response:
The user wants to understand the functionality of the provided C++ header file.

Here's a breakdown of how to approach this:

1. **Identify the file's purpose:** The filename `liftoff-assembler-s390-inl.h` suggests it's an inline header for the Liftoff assembler targeting the s390 architecture within the V8 JavaScript engine. Liftoff is V8's baseline compiler for WebAssembly.

2. **Analyze included headers:** The `#include` directives reveal dependencies:
    * `assembler.h`:  Provides base assembly functionality.
    * `mutable-page-metadata.h`: Deals with memory page metadata.
    * `liftoff-assembler.h`:  The main Liftoff assembler interface (this is the inline part).
    * `parallel-move-inl.h`:  Likely for efficient register moves.
    * `object-access.h`:  Helpers for accessing JavaScript objects from WASM.
    * `simd-shuffle.h`:  SIMD (Single Instruction, Multiple Data) shuffle operations.
    * `wasm-linkage.h`: Defines how WASM code interacts with the V8 runtime.
    * `wasm-objects.h`:  Definitions for WASM-related objects in V8.

3. **Examine the `namespace`:** The code is within `v8::internal::wasm::liftoff`, clearly indicating its role within V8's WebAssembly implementation.

4. **Understand the stack frame layout:** The comment block describing the stack frame layout is crucial. It defines how parameters, return addresses, frame pointers, and local variables are organized on the stack during WASM function calls on s390.

5. **Analyze inline functions:**  The `inline` functions are the core of this header. Focus on what each function does:
    * `GetStackSlot`: Calculates memory operands for accessing stack slots.
    * `GetInstanceDataOperand`:  Specifically retrieves the memory operand for the WASM instance data.
    * `StoreToMemory`:  A versatile function for storing values from registers or constants to memory, handling different data types.

6. **Analyze `LiftoffAssembler` methods:** The rest of the file defines inline implementations for methods of the `LiftoffAssembler` class. Group these by their apparent function:
    * **Frame setup/teardown:** `PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`, `AlignFrameSize`, `PatchPrepareStackFrame`.
    * **Tiering (optimization):** `CheckTierUp`.
    * **Stack management:** `CheckStackShrink`.
    * **Constant loading:** `LoadConstant`.
    * **Instance data access:** `LoadInstanceDataFromFrame`, `LoadTrustedPointer`, `LoadFromInstance`, `LoadTaggedPointerFromInstance`, `SpillInstanceData`.
    * **Pointers and memory access:** `LoadTaggedPointer`, `LoadProtectedPointer`, `LoadFullPointer`, `StoreTaggedPointer`, `Load`, `Store`.
    * **Atomic operations:** `AtomicLoad`, `AtomicStore`, `AtomicAdd`, `AtomicSub`, `AtomicAnd`, `AtomicOr`, `AtomicXor`.
    * **Other:** `FinishCode`, `AbortCompilation`, `StaticStackFrameSize`, `SlotSizeForType`, `NeedsAlignment`, `ResetOSRTarget`.

7. **Address specific questions:**
    * **`.tq` extension:**  The file does *not* end in `.tq`, so it's not a Torque file.
    * **JavaScript relationship:** Many of these operations are fundamental to executing WASM code, which is often called from JavaScript. Consider how storing to memory or calling builtins relates to JavaScript interaction.
    * **Code logic/input/output:** For functions like `GetStackSlot`, the input is an offset, and the output is a `MemOperand`. For `StoreToMemory`, the input is a destination memory location and a source variable state, and the output is the value stored in memory.
    * **Common programming errors:**  Consider issues like incorrect stack offsets, type mismatches when storing to memory, or misuse of atomic operations.

8. **Summarize the functionality:** Combine the observations into a concise summary.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level assembly details. The prompt asks for the *functionality*, so a higher-level description is better.
* I should double-check if any of the functionalities have direct JavaScript equivalents or implications.
* Ensure the explanation of the stack frame is clear and connects to the subsequent functions that manipulate stack memory.
* For the "common programming errors," think from a WASM developer's perspective, even though this is V8 internal code. What mistakes could they cause that this code helps implement or prevent?
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_S390_LIFTOFF_ASSEMBLER_S390_INL_H_
#define V8_WASM_BASELINE_S390_LIFTOFF_ASSEMBLER_S390_INL_H_

#include "src/codegen/assembler.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

namespace liftoff {

//  half
//  slot        Frame
//  -----+--------------------+---------------------------
//  n+3  |   parameter n      |
//  ... |       ...          |
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
inline MemOperand GetStackSlot(uint32_t offset) {
  return MemOperand(fp, -offset);
}

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src,
                          Register scratch) {
  if (src.is_reg()) {
    switch (src.kind()) {
      case kI16:
        assm->StoreU16(src.reg().gp(), dst);
        break;
      case kI32:
        assm->StoreU32(src.reg().gp(), dst);
        break;
      case kI64:
        assm->StoreU64(src.reg().gp(), dst);
        break;
      case kF32:
        assm->StoreF32(src.reg().fp(), dst);
        break;
      case kF64:
        assm->StoreF64(src.reg().fp(), dst);
        break;
      case kS128:
        assm->StoreV128(src.reg().fp(), dst, scratch);
        break;
      default:
        UNREACHABLE();
    }
  } else if (src.is_const()) {
    if (src.kind() == kI32) {
      assm->mov(scratch, Operand(src.i32_const()));
      assm->StoreU32(scratch, dst);
    } else {
      assm->mov(scratch, Operand(static_cast<int64_t>(src.i32_const())));
      assm->StoreU64(scratch, dst);
    }
  } else if (value_kind_size(src.kind()) == 4) {
    assm->LoadU32(scratch, liftoff::GetStackSlot(src.offset()), scratch);
    assm->StoreU32(scratch, dst);
  } else {
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->LoadU64(scratch, liftoff::GetStackSlot(src.offset()), scratch);
    assm->StoreU64(scratch, dst);
  }
}

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  lay(sp, MemOperand(sp));
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
  Register scratch = ip;
  mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  PushCommonFrame(scratch);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  Register scratch = r1;
  // Push the return address and frame pointer to complete the stack frame.
  lay(sp, MemOperand(sp, -2 * kSystemPointerSize));
  LoadU64(scratch, MemOperand(fp, kSystemPointerSize));
  StoreU64(scratch, MemOperand(sp, kSystemPointerSize));
  LoadU64(scratch, MemOperand(fp));
  StoreU64(scratch, MemOperand(sp));

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    LoadU64(scratch, MemOperand(sp, i * kSystemPointerSize));
    StoreU64(scratch,
             MemOperand(fp, (i - stack_param_delta) * kSystemPointerSize));
  }

  // Set the new stack and frame pointer.
  lay(sp, MemOperand(fp, -stack_param_delta * kSystemPointerSize));
  Pop(r14, fp);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  constexpr int LayInstrSize = 6;

  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, LayInstrSize + kGap));
  if (V8_LIKELY(frame_size < 4 * KB)) {
    patching_assembler.lay(sp, MemOperand(sp, -frame_size));
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

  int jump_offset = pc_offset() - offset;
  patching_assembler.branchOnCond(al, jump_offset, true, true);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    Register stack_limit = ip;
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    AddU64(stack_limit, Operand(frame_size));
    CmpU64(sp, stack_limit);
    bge(&continuation);
  }

  Call(static_cast<Address>(Builtin::kWasmStackOverflow),
       RelocInfo::WASM_STUB_CALL);
  // The call will not return; just define an empty safepoint.
  safepoint_table_builder->DefineSafepoint(this);
  if (v8_flags.debug_code) stop();

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  lay(sp, MemOperand(sp, -frame_size));

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  jump_offset = offset - pc_offset() + 6;
  branchOnCond(al, jump_offset, true);
}

void LiftoffAssembler::FinishCode() {}

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
  return (kind == kS128 || is_reference(kind));
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register budget_array = ip;
  Register instance_data = cache_state_.cached_instance_data;

  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the temp register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  LoadU64(budget_array, MemOperand(instance_data, kArrayOffset));

  int budget_arr_offset = kInt32Size * declared_func_index;
  Register budget = r1;
  MemOperand budget_addr(budget_array, budget_arr_offset);
  LoadS32(budget, budget_addr);
  SubS32(budget, Operand(budget_used));
  StoreU32(budget, budget_addr);
  blt(ool_label);
}

Register LiftoffAssembler::LoadOldFramePointer() { return fp; }

void LiftoffAssembler::CheckStackShrink() {
  // TODO(irezvov): 42202153
  UNIMPLEMENTED();
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      mov(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64:
      mov(reg.gp(), Operand(value.to_i64()));
      break;
    case kF32: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadF32(reg.fp(), value.to_f32(), scratch);
      break;
    }
    case kF64: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadF64(reg.fp(), value.to_f64(), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  LoadU64(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  LoadTaggedField(dst, MemOperand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  switch (size) {
    case 1:
      LoadU8(dst, MemOperand(instance, offset));
      break;
    case 4:
      LoadU32(dst, MemOperand(instance, offset));
      break;
    case 8:
      LoadU64(dst, MemOperand(instance, offset));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  DCHECK_LE(0, offset);
  LoadTaggedField(dst, MemOperand(instance, offset));
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  StoreU64(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  CHECK(is_int20(offset_imm));
  unsigned shift_amount = !needs_shift ? 0 : COMPRESS_POINTERS_BOOL ? 2 : 3;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  if (protected_load_pc) *protected_load_pc = pc_offset();
  LoadTaggedField(
      dst,
      MemOperand(src_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  LoadU64(dst, MemOperand(src_addr, offset_imm), r1);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList /* pinned */,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  MemOperand dst_op =
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  StoreTaggedField(src, dst_op);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  Label exit;
  CheckPageFlag(dst_addr, r1, MemoryChunk::kPointersFromHereAreInterestingMask,
                to_condition(kZero), &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, r1, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &exit);
  lay(r1, dst_op);
  CallRecordWriteStubSaveRegisters(dst_addr, r1, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool is_load_mem, bool i64_offset,
                            bool needs_shift) {
  UseScratchRegisterScope temps(this);
  if (offset_reg != no_reg && !i64_offset) {
    // Clear the upper 32 bits of the 64 bit offset register.
    llgfr(ip, offset_reg);
    offset_reg = ip;
  }
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  if (!is_int20(offset_imm)) {
    if (offset_reg != no_reg) {
      mov(r0, Operand(offset_imm));
      AddS64(r0, offset_reg);
      mov(ip, r0);
    } else {
      mov(ip, Operand(offset_imm));
    }
    offset_reg = ip;
    offset_imm = 0;
  }
  MemOperand src_op =
      MemOperand(src_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_load_pc) *protected_load_pc = pc_offset();
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      LoadU8(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
    case LoadType::kI64Load8S:
      LoadS8(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      if (is_load_mem) {
        LoadU16LE(dst.gp(), src_op);
      } else {
        LoadU16(dst.gp(), src_op);
      }
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      if (is_load_mem) {
        LoadS16LE(dst.gp(), src_op);
      } else {
        LoadS16(dst.gp(), src_op);
      }
      break;
    case LoadType::kI64Load32U:
      if (is_load_mem) {
        LoadU32LE(dst.gp(), src_op);
      } else {
        LoadU32(dst.gp(), src_op);
      }
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      if (is_load_mem) {
        LoadS32LE(dst.gp(), src_op);
      } else {
        LoadS32(dst.gp(), src_op);
      }
      break;
    case LoadType::kI64Load:
      if (is_load_mem) {
        LoadU64LE(dst.gp(), src_op);
      } else {
        LoadU64(dst.gp(), src_op);
      }
      break;
    case LoadType::kF32Load:
      if (is_load_mem) {
        LoadF32LE(dst.fp(), src_op, r0);
      } else {
        LoadF32(dst.fp(), src_op);
      }
      break;
    case LoadType::kF64Load:
      if (is_load_mem) {
        LoadF64LE(dst.fp(), src_op, r0);
      } else {
        LoadF64(dst.fp(), src_op);
      }
      break;
    case LoadType::kS128Load:
      if (is_load_mem) {
        LoadV128LE(dst.fp(), src_op, r1, r0);
      } else {
        LoadV128(dst.fp(), src_op, r1);
      }
      break;
    default:
      UNREACHABLE();
  }
}

#define PREP_MEM_OPERAND(offset_reg, offset_imm, scratch)       \
  if (offset_reg != no_reg && !i64_offset) {                    \
    /* Clear the upper 32 bits of the 64 bit offset register.*/ \
    llgfr(scratch, offset_reg);                                 \
    offset_reg = scratch;                                       \
  }                                                             \
  if (!is_int20(offset_imm)) {                                  \
    if (offset_reg != no_reg) {                                 \
      mov(r0, Operand(offset_imm));                             \
      AddS64(r0, offset_reg);                                   \
      mov(scratch, r0);                                         \
    } else {                                                    \
      mov(scratch, Operand(offset_imm));                        \
    }                                                           \
    offset_reg = scratch;                                       \
    offset_imm = 0;                                             \
  }
void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList /* pinned */,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  MemOperand dst_op =
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      StoreU8(src.gp(), dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      if (is_store_mem) {
        StoreU16LE(src.gp(), dst_op, r1);
      } else {
        StoreU16(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      if (is_store_mem) {
        StoreU32LE(src.gp(), dst_op, r1);
      } else {
        StoreU32(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kI64Store:
      if (is_store_mem) {
        StoreU64LE(src.gp(), dst_op, r1);
      } else {
        StoreU64(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kF32Store:
      if (is_store_mem) {
        StoreF32LE(src.fp(), dst_op, r1);
      } else {
        StoreF32(src.fp(), dst_op);
      }
      break;
    case StoreType::kF64Store:
      if (is_store_mem) {
        StoreF64LE(src.fp(), dst_op, r1);
      } else {
        StoreF64(src.fp(), dst_op);
      }
      break;
    case StoreType::kS128Store: {
      if (is_store_mem) {
        StoreV128LE(src.fp(), dst_op, r1, r0);
      } else {
        StoreV128(src.fp(), dst_op, r1);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool i64_offset) {
  Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true, i64_offset);
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList /* pinned */,
                                   bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      AtomicExchangeU8(ip, src.gp(), r1, r0);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, src.gp());
      ShiftRightU32(r1, r1, Operand(16));
#else
      LoadU16(r1, src.gp());
#endif
      Push(r2);
      AtomicExchangeU16(ip, r1, r2, r0);
      Pop(r2);
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, src.gp());
#else
      LoadU32(r1, src.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      cs(r0, r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
      break;
    }
    case StoreType::kI64Store: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(r1, src.gp());
#else
      mov(r1, src.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      csg(r0, r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label doadd;
      bind(&doadd);
      LoadU8(tmp
Prompt: 
```
这是目录为v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_S390_LIFTOFF_ASSEMBLER_S390_INL_H_
#define V8_WASM_BASELINE_S390_LIFTOFF_ASSEMBLER_S390_INL_H_

#include "src/codegen/assembler.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/parallel-move-inl.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
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
inline MemOperand GetStackSlot(uint32_t offset) {
  return MemOperand(fp, -offset);
}

inline MemOperand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src,
                          Register scratch) {
  if (src.is_reg()) {
    switch (src.kind()) {
      case kI16:
        assm->StoreU16(src.reg().gp(), dst);
        break;
      case kI32:
        assm->StoreU32(src.reg().gp(), dst);
        break;
      case kI64:
        assm->StoreU64(src.reg().gp(), dst);
        break;
      case kF32:
        assm->StoreF32(src.reg().fp(), dst);
        break;
      case kF64:
        assm->StoreF64(src.reg().fp(), dst);
        break;
      case kS128:
        assm->StoreV128(src.reg().fp(), dst, scratch);
        break;
      default:
        UNREACHABLE();
    }
  } else if (src.is_const()) {
    if (src.kind() == kI32) {
      assm->mov(scratch, Operand(src.i32_const()));
      assm->StoreU32(scratch, dst);
    } else {
      assm->mov(scratch, Operand(static_cast<int64_t>(src.i32_const())));
      assm->StoreU64(scratch, dst);
    }
  } else if (value_kind_size(src.kind()) == 4) {
    assm->LoadU32(scratch, liftoff::GetStackSlot(src.offset()), scratch);
    assm->StoreU32(scratch, dst);
  } else {
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->LoadU64(scratch, liftoff::GetStackSlot(src.offset()), scratch);
    assm->StoreU64(scratch, dst);
  }
}

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  lay(sp, MemOperand(sp));
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
  Register scratch = ip;
  mov(scratch, Operand(StackFrame::TypeToMarker(StackFrame::WASM)));
  PushCommonFrame(scratch);
  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  Register scratch = r1;
  // Push the return address and frame pointer to complete the stack frame.
  lay(sp, MemOperand(sp, -2 * kSystemPointerSize));
  LoadU64(scratch, MemOperand(fp, kSystemPointerSize));
  StoreU64(scratch, MemOperand(sp, kSystemPointerSize));
  LoadU64(scratch, MemOperand(fp));
  StoreU64(scratch, MemOperand(sp));

  // Shift the whole frame upwards.
  int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count - 1; i >= 0; --i) {
    LoadU64(scratch, MemOperand(sp, i * kSystemPointerSize));
    StoreU64(scratch,
             MemOperand(fp, (i - stack_param_delta) * kSystemPointerSize));
  }

  // Set the new stack and frame pointer.
  lay(sp, MemOperand(fp, -stack_param_delta * kSystemPointerSize));
  Pop(r14, fp);
}

void LiftoffAssembler::AlignFrameSize() {}

void LiftoffAssembler::PatchPrepareStackFrame(
    int offset, SafepointTableBuilder* safepoint_table_builder,
    bool feedback_vector_slot, size_t stack_param_slots) {
  int frame_size = GetTotalFrameSize() - 2 * kSystemPointerSize;
  // The frame setup builtin also pushes the feedback vector.
  if (feedback_vector_slot) {
    frame_size -= kSystemPointerSize;
  }

  constexpr int LayInstrSize = 6;

  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, LayInstrSize + kGap));
  if (V8_LIKELY(frame_size < 4 * KB)) {
    patching_assembler.lay(sp, MemOperand(sp, -frame_size));
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

  int jump_offset = pc_offset() - offset;
  patching_assembler.branchOnCond(al, jump_offset, true, true);

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    Register stack_limit = ip;
    LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    AddU64(stack_limit, Operand(frame_size));
    CmpU64(sp, stack_limit);
    bge(&continuation);
  }

  Call(static_cast<Address>(Builtin::kWasmStackOverflow),
       RelocInfo::WASM_STUB_CALL);
  // The call will not return; just define an empty safepoint.
  safepoint_table_builder->DefineSafepoint(this);
  if (v8_flags.debug_code) stop();

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  lay(sp, MemOperand(sp, -frame_size));

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  jump_offset = offset - pc_offset() + 6;
  branchOnCond(al, jump_offset, true);
}

void LiftoffAssembler::FinishCode() {}

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
  return (kind == kS128 || is_reference(kind));
}

void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register budget_array = ip;
  Register instance_data = cache_state_.cached_instance_data;

  if (instance_data == no_reg) {
    instance_data = budget_array;  // Reuse the temp register.
    LoadInstanceDataFromFrame(instance_data);
  }

  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmTrustedInstanceData::kTieringBudgetArrayOffset);
  LoadU64(budget_array, MemOperand(instance_data, kArrayOffset));

  int budget_arr_offset = kInt32Size * declared_func_index;
  Register budget = r1;
  MemOperand budget_addr(budget_array, budget_arr_offset);
  LoadS32(budget, budget_addr);
  SubS32(budget, Operand(budget_used));
  StoreU32(budget, budget_addr);
  blt(ool_label);
}

Register LiftoffAssembler::LoadOldFramePointer() { return fp; }

void LiftoffAssembler::CheckStackShrink() {
  // TODO(irezvov): 42202153
  UNIMPLEMENTED();
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      mov(reg.gp(), Operand(value.to_i32()));
      break;
    case kI64:
      mov(reg.gp(), Operand(value.to_i64()));
      break;
    case kF32: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadF32(reg.fp(), value.to_f32(), scratch);
      break;
    }
    case kF64: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadF64(reg.fp(), value.to_f64(), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  LoadU64(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  LoadTaggedField(dst, MemOperand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  switch (size) {
    case 1:
      LoadU8(dst, MemOperand(instance, offset));
      break;
    case 4:
      LoadU32(dst, MemOperand(instance, offset));
      break;
    case 8:
      LoadU64(dst, MemOperand(instance, offset));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  DCHECK_LE(0, offset);
  LoadTaggedField(dst, MemOperand(instance, offset));
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  StoreU64(instance, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  CHECK(is_int20(offset_imm));
  unsigned shift_amount = !needs_shift ? 0 : COMPRESS_POINTERS_BOOL ? 2 : 3;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  if (protected_load_pc) *protected_load_pc = pc_offset();
  LoadTaggedField(
      dst,
      MemOperand(src_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));
}

void LiftoffAssembler::LoadProtectedPointer(Register dst, Register src_addr,
                                            int32_t offset) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  LoadTaggedPointer(dst, src_addr, no_reg, offset);
}

void LiftoffAssembler::LoadFullPointer(Register dst, Register src_addr,
                                       int32_t offset_imm) {
  UseScratchRegisterScope temps(this);
  LoadU64(dst, MemOperand(src_addr, offset_imm), r1);
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList /* pinned */,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  MemOperand dst_op =
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  StoreTaggedField(src, dst_op);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  Label exit;
  CheckPageFlag(dst_addr, r1, MemoryChunk::kPointersFromHereAreInterestingMask,
                to_condition(kZero), &exit);
  JumpIfSmi(src, &exit);
  CheckPageFlag(src, r1, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &exit);
  lay(r1, dst_op);
  CallRecordWriteStubSaveRegisters(dst_addr, r1, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uintptr_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool is_load_mem, bool i64_offset,
                            bool needs_shift) {
  UseScratchRegisterScope temps(this);
  if (offset_reg != no_reg && !i64_offset) {
    // Clear the upper 32 bits of the 64 bit offset register.
    llgfr(ip, offset_reg);
    offset_reg = ip;
  }
  unsigned shift_amount = needs_shift ? type.size_log_2() : 0;
  if (offset_reg != no_reg && shift_amount != 0) {
    ShiftLeftU64(ip, offset_reg, Operand(shift_amount));
    offset_reg = ip;
  }
  if (!is_int20(offset_imm)) {
    if (offset_reg != no_reg) {
      mov(r0, Operand(offset_imm));
      AddS64(r0, offset_reg);
      mov(ip, r0);
    } else {
      mov(ip, Operand(offset_imm));
    }
    offset_reg = ip;
    offset_imm = 0;
  }
  MemOperand src_op =
      MemOperand(src_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_load_pc) *protected_load_pc = pc_offset();
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      LoadU8(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
    case LoadType::kI64Load8S:
      LoadS8(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      if (is_load_mem) {
        LoadU16LE(dst.gp(), src_op);
      } else {
        LoadU16(dst.gp(), src_op);
      }
      break;
    case LoadType::kI32Load16S:
    case LoadType::kI64Load16S:
      if (is_load_mem) {
        LoadS16LE(dst.gp(), src_op);
      } else {
        LoadS16(dst.gp(), src_op);
      }
      break;
    case LoadType::kI64Load32U:
      if (is_load_mem) {
        LoadU32LE(dst.gp(), src_op);
      } else {
        LoadU32(dst.gp(), src_op);
      }
      break;
    case LoadType::kI32Load:
    case LoadType::kI64Load32S:
      if (is_load_mem) {
        LoadS32LE(dst.gp(), src_op);
      } else {
        LoadS32(dst.gp(), src_op);
      }
      break;
    case LoadType::kI64Load:
      if (is_load_mem) {
        LoadU64LE(dst.gp(), src_op);
      } else {
        LoadU64(dst.gp(), src_op);
      }
      break;
    case LoadType::kF32Load:
      if (is_load_mem) {
        LoadF32LE(dst.fp(), src_op, r0);
      } else {
        LoadF32(dst.fp(), src_op);
      }
      break;
    case LoadType::kF64Load:
      if (is_load_mem) {
        LoadF64LE(dst.fp(), src_op, r0);
      } else {
        LoadF64(dst.fp(), src_op);
      }
      break;
    case LoadType::kS128Load:
      if (is_load_mem) {
        LoadV128LE(dst.fp(), src_op, r1, r0);
      } else {
        LoadV128(dst.fp(), src_op, r1);
      }
      break;
    default:
      UNREACHABLE();
  }
}

#define PREP_MEM_OPERAND(offset_reg, offset_imm, scratch)       \
  if (offset_reg != no_reg && !i64_offset) {                    \
    /* Clear the upper 32 bits of the 64 bit offset register.*/ \
    llgfr(scratch, offset_reg);                                 \
    offset_reg = scratch;                                       \
  }                                                             \
  if (!is_int20(offset_imm)) {                                  \
    if (offset_reg != no_reg) {                                 \
      mov(r0, Operand(offset_imm));                             \
      AddS64(r0, offset_reg);                                   \
      mov(scratch, r0);                                         \
    } else {                                                    \
      mov(scratch, Operand(offset_imm));                        \
    }                                                           \
    offset_reg = scratch;                                       \
    offset_imm = 0;                                             \
  }
void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList /* pinned */,
                             uint32_t* protected_store_pc, bool is_store_mem,
                             bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  MemOperand dst_op =
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8:
      StoreU8(src.gp(), dst_op);
      break;
    case StoreType::kI32Store16:
    case StoreType::kI64Store16:
      if (is_store_mem) {
        StoreU16LE(src.gp(), dst_op, r1);
      } else {
        StoreU16(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kI32Store:
    case StoreType::kI64Store32:
      if (is_store_mem) {
        StoreU32LE(src.gp(), dst_op, r1);
      } else {
        StoreU32(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kI64Store:
      if (is_store_mem) {
        StoreU64LE(src.gp(), dst_op, r1);
      } else {
        StoreU64(src.gp(), dst_op, r1);
      }
      break;
    case StoreType::kF32Store:
      if (is_store_mem) {
        StoreF32LE(src.fp(), dst_op, r1);
      } else {
        StoreF32(src.fp(), dst_op);
      }
      break;
    case StoreType::kF64Store:
      if (is_store_mem) {
        StoreF64LE(src.fp(), dst_op, r1);
      } else {
        StoreF64(src.fp(), dst_op);
      }
      break;
    case StoreType::kS128Store: {
      if (is_store_mem) {
        StoreV128LE(src.fp(), dst_op, r1, r0);
      } else {
        StoreV128(src.fp(), dst_op, r1);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool i64_offset) {
  Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true, i64_offset);
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList /* pinned */,
                                   bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      AtomicExchangeU8(ip, src.gp(), r1, r0);
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, src.gp());
      ShiftRightU32(r1, r1, Operand(16));
#else
      LoadU16(r1, src.gp());
#endif
      Push(r2);
      AtomicExchangeU16(ip, r1, r2, r0);
      Pop(r2);
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, src.gp());
#else
      LoadU32(r1, src.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      cs(r0, r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
      break;
    }
    case StoreType::kI64Store: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(r1, src.gp());
#else
      mov(r1, src.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      csg(r0, r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label doadd;
      bind(&doadd);
      LoadU8(tmp1, MemOperand(ip));
      AddS32(tmp2, tmp1, value.gp());
      AtomicCmpExchangeU8(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &doadd);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label doadd;
      bind(&doadd);
      LoadU16(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      ShiftRightU32(tmp2, tmp2, Operand(16));
      AddS32(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      AddS32(tmp2, tmp1, value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &doadd);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label doadd;
      bind(&doadd);
      LoadU32(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      AddS32(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
#else
      AddS32(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &doadd);
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
      Label doadd;
      bind(&doadd);
      LoadU64(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp2, tmp1);
      AddS64(tmp2, tmp2, value.gp());
      lrvgr(tmp2, tmp2);
#else
      AddS64(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &doadd);
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label do_again;
      bind(&do_again);
      LoadU8(tmp1, MemOperand(ip));
      SubS32(tmp2, tmp1, value.gp());
      AtomicCmpExchangeU8(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label do_again;
      bind(&do_again);
      LoadU16(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      ShiftRightU32(tmp2, tmp2, Operand(16));
      SubS32(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      SubS32(tmp2, tmp1, value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label do_again;
      bind(&do_again);
      LoadU32(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      SubS32(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
#else
      SubS32(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
      Label do_again;
      bind(&do_again);
      LoadU64(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp2, tmp1);
      SubS64(tmp2, tmp2, value.gp());
      lrvgr(tmp2, tmp2);
#else
      SubS64(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label do_again;
      bind(&do_again);
      LoadU8(tmp1, MemOperand(ip));
      AndP(tmp2, tmp1, value.gp());
      AtomicCmpExchangeU8(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label do_again;
      bind(&do_again);
      LoadU16(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      ShiftRightU32(tmp2, tmp2, Operand(16));
      AndP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      AndP(tmp2, tmp1, value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label do_again;
      bind(&do_again);
      LoadU32(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      AndP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
#else
      AndP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
      Label do_again;
      bind(&do_again);
      LoadU64(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp2, tmp1);
      AndP(tmp2, tmp2, value.gp());
      lrvgr(tmp2, tmp2);
#else
      AndP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uintptr_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label do_again;
      bind(&do_again);
      LoadU8(tmp1, MemOperand(ip));
      OrP(tmp2, tmp1, value.gp());
      AtomicCmpExchangeU8(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label do_again;
      bind(&do_again);
      LoadU16(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      ShiftRightU32(tmp2, tmp2, Operand(16));
      OrP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      OrP(tmp2, tmp1, value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label do_again;
      bind(&do_again);
      LoadU32(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      OrP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
#else
      OrP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
      Label do_again;
      bind(&do_again);
      LoadU64(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp2, tmp1);
      OrP(tmp2, tmp2, value.gp());
      lrvgr(tmp2, tmp2);
#else
      OrP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool i64_offset) {
  LiftoffRegList pinned = LiftoffRegList{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Re
"""


```