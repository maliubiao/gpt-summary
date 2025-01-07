Response:
The user wants a summary of the provided C++ header file. Here's a breakdown of the thinking process to generate the answer:

1. **Identify the Core Purpose:** The file name `liftoff-assembler-ia32-inl.h` strongly suggests it's related to the Liftoff compiler for WebAssembly on the IA-32 architecture. The `.inl` extension signifies it contains inline function definitions, likely for performance.

2. **Scan for Key Concepts:** Quickly read through the code, looking for recurring terms and patterns. Keywords like `LiftoffAssembler`, `Operand`, `Register`, `ValueKind`, `Load`, `Store`, `push`, `pop`, `Atomic`, `StackFrame`, and processor-specific instructions (`mov`, `push`, `pop`, `movss`, `movsd`, etc.) are significant.

3. **Group Functionality:** Categorize the identified concepts into logical groups. The prominent functionalities seem to be:
    * **Stack Manipulation:**  Functions like `GetStackSlot`, `GetHalfStackSlot`, `push`, `pop`, and related constants indicate stack management.
    * **Memory Access (Load/Store):**  The `Load` and `Store` functions, along with variations for different data sizes and atomic operations, are central.
    * **Register Management:**  Functions for obtaining temporary registers (`GetTmpByteRegister`, `CacheStatePreservingTempRegisters`) and understanding register usage.
    * **Function Call Support:**  Functions and logic related to setting up and tearing down stack frames (`PrepareStackFrame`, `CallFrameSetupStub`, `PrepareTailCall`).
    * **Tiering Up/Stack Growth:**  Code related to performance optimization (`CheckTierUp`) and handling stack overflows/shrinking (`CheckStackShrink`).
    * **Constant Loading:**  The `LoadConstant` function.
    * **Instance Data Access:** Functions to access WebAssembly instance data.
    * **Atomic Operations:**  Functions with `Atomic` prefixes.

4. **Analyze Individual Functions/Sections:** For each functional group, delve deeper into the purpose of specific functions. For example:
    * `GetStackSlot`:  Calculates the memory address of a variable on the stack.
    * `Load`:  Moves data from memory to a register, handling different data types.
    * `Store`:  Moves data from a register to memory.
    * `PrepareStackFrame`:  Allocates space on the stack for a function's local variables.
    * `AtomicLoad/Store`: Handles concurrent memory access with specific ordering guarantees.

5. **Infer Relationships:**  Understand how the different parts interact. For instance, the stack manipulation functions are used by the function call setup/teardown logic. The memory access functions rely on the `Operand` structure to define memory locations.

6. **Address Specific Questions:** Now, address the points raised in the prompt:
    * **Functionality List:**  Summarize the grouped functionalities in clear bullet points.
    * **`.tq` Extension:** State that the file is *not* a Torque file based on its `.h` extension.
    * **JavaScript Relation:** Since this is low-level assembly code for WebAssembly, it doesn't have a direct, simple JavaScript equivalent. Focus on the *outcomes* in JavaScript—e.g., reading and writing variables, function calls, and the underlying memory model. Provide JavaScript examples that demonstrate these higher-level concepts that the assembly code helps implement.
    * **Code Logic Reasoning:** Choose a relatively simple function like `GetStackSlot` and provide an example input (offset) and the corresponding output (operand representation).
    * **Common Programming Errors:** Think about common errors in low-level programming or related to WebAssembly concepts. Examples include stack overflow, incorrect memory access, and data type mismatches.
    * **Overall Function Summary:**  Provide a concise summary that captures the essence of the header file.

7. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure the language is precise and avoids unnecessary jargon where possible. Review and refine the explanation for clarity and accuracy. For example, initially, I might have just listed individual functions, but grouping them into logical functionalities makes the explanation much clearer. I also made sure to explicitly address each part of the user's request.

8. **Consider the "Part 1 of 6" Context:**  This implies that the current file likely deals with fundamental aspects of the Liftoff assembler. Keep the summary focused on these core functionalities.

By following these steps, we can generate a comprehensive and accurate summary of the provided C++ header file, addressing all the user's specific questions.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_IA32_LIFTOFF_ASSEMBLER_IA32_INL_H_
#define V8_WASM_BASELINE_IA32_LIFTOFF_ASSEMBLER_IA32_INL_H_

#include <optional>

#include "src/codegen/assembler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

#define RETURN_FALSE_IF_MISSING_CPU_FEATURE(name)    \
  if (!CpuFeatures::IsSupported(name)) return false; \
  CpuFeatureScope feature(this, name);

namespace liftoff {

inline Operand GetStackSlot(int offset) { return Operand(ebp, -offset); }

inline MemOperand GetHalfStackSlot(int offset, RegPairHalf half) {
  int32_t half_offset =
      half == kLowWord ? 0 : LiftoffAssembler::kStackSlotSize / 2;
  return Operand(offset > 0 ? ebp : esp, -offset + half_offset);
}

// TODO(clemensb): Make this a constexpr variable once Operand is constexpr.
inline Operand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline Operand MemOperand(Register base, Register offset_reg, int offset_imm) {
  return offset_reg == no_reg ? Operand(base, offset_imm)
                              : Operand(base, offset_reg, times_1, offset_imm);
}

static constexpr LiftoffRegList kByteRegs =
    LiftoffRegList::FromBits<RegList{eax, ecx, edx}.bits()>();

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, Register base,
                 int32_t offset, ValueKind kind) {
  Operand src(base, offset);
  switch (kind) {
    case kI16:
      assm->mov_w(dst.gp(), src);
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->mov(dst.gp(), src);
      break;
    case kI64:
      assm->mov(dst.low_gp(), src);
      assm->mov(dst.high_gp(), Operand(base, offset + 4));
      break;
    case kF32:
      assm->movss(dst.fp(), src);
      break;
    case kF64:
      assm->movsd(dst.fp(), src);
      break;
    case kS128:
      assm->movdqu(dst.fp(), src);
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kF16:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  Operand dst(base, offset);
  switch (kind) {
    case kI16:
      assm->mov_w(dst, src.gp());
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->mov(dst, src.gp());
      break;
    case kI64:
      assm->mov(dst, src.low_gp());
      assm->mov(Operand(base, offset + 4), src.high_gp());
      break;
    case kF32:
      assm->movss(dst, src.fp());
      break;
    case kF64:
      assm->movsd(dst, src.fp());
      break;
    case kS128:
      assm->movdqu(dst, src.fp());
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kF16:
      UNREACHABLE();
  }
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind,
                 int padding = 0) {
  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->AllocateStackSpace(padding);
      assm->push(reg.gp());
      break;
    case kI64:
      assm->AllocateStackSpace(padding);
      assm->push(reg.high_gp());
      assm->push(reg.low_gp());
      break;
    case kF32:
      assm->AllocateStackSpace(sizeof(float) + padding);
      assm->movss(Operand(esp, 0), reg.fp());
      break;
    case kF64:
      assm->AllocateStackSpace(sizeof(double) + padding);
      assm->movsd(Operand(esp, 0), reg.fp());
      break;
    case kS128:
      assm->AllocateStackSpace(sizeof(double) * 2 + padding);
      assm->movdqu(Operand(esp, 0), reg.fp());
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kI16:
    case kF16:
      UNREACHABLE();
  }
}

inline void SignExtendI32ToI64(Assembler* assm, LiftoffRegister reg) {
  assm->mov(reg.high_gp(), reg.low_gp());
  assm->sar(reg.high_gp(), 31);
}

// Get a temporary byte register, using {candidate} if possible.
// Might spill, but always keeps status flags intact.
inline Register GetTmpByteRegister(LiftoffAssembler* assm, Register candidate) {
  if (candidate.is_byte_register()) return candidate;
  // {GetUnusedRegister()} may insert move instructions to spill registers to
  // the stack. This is OK because {mov} does not change the status flags.
  return assm->GetUnusedRegister(liftoff::kByteRegs).gp();
}

inline void MoveStackValue(LiftoffAssembler* assm, const Operand& src,
                           const Operand& dst) {
  if (assm->cache_state()->has_unused_register(kGpReg)) {
    Register tmp = assm->cache_state()->unused_register(kGpReg).gp();
    assm->mov(tmp, src);
    assm->mov(dst, tmp);
  } else {
    // No free register, move via the stack.
    assm->push(src);
    assm->pop(dst);
  }
}

class CacheStatePreservingTempRegisters {
 public:
  explicit CacheStatePreservingTempRegisters(LiftoffAssembler* assm,
                                             LiftoffRegList pinned = {})
      : assm_(assm), pinned_(pinned) {}

  ~CacheStatePreservingTempRegisters() {
    for (Register reg : must_pop_) {
      assm_->pop(reg);
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
    assm_->push(reg);
    must_pop_.set(reg);
    return reg;
  }

 private:
  LiftoffAssembler* const assm_;
  LiftoffRegList pinned_;
  RegList must_pop_;
};

constexpr DoubleRegister kScratchDoubleReg = xmm7;

constexpr int kSubSpSize = 6;  // 6 bytes for "sub esp, <imm32>"

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  // Next we reserve the memory for the whole stack frame. We do not know yet
  // how big the stack frame will be so we just emit a placeholder instruction.
  // PatchPrepareStackFrame will patch this in order to increase the stack
  // appropriately.
  sub_sp_32(0);
  DCHECK_EQ(liftoff::kSubSpSize, pc_offset() - offset);
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

  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  // Push the return address and frame pointer to complete the stack frame.
  push(Operand(ebp, 4));
  push(Operand(ebp, 0));

  // Shift the whole frame upwards.
  Register scratch = eax;
  push(scratch);
  const int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count; i > 0; --i) {
    mov(scratch, Operand(esp, i * 4));
    mov(Operand(ebp, (i - stack_param_delta - 1) * 4), scratch);
  }
  pop(scratch);

  // Set the new stack and frame pointers.
  lea(esp, Operand(ebp, -stack_param_delta * 4));
  pop(ebp);
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
  DCHECK_EQ(0, frame_size % kSystemPointerSize);

  // We can't run out of space when patching, just pass anything big enough to
  // not cause the assembler to try to grow the buffer.
  constexpr int kAvailableSpace = 64;
  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, kAvailableSpace));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.sub_sp_32(frame_size);
    DCHECK_EQ(liftoff::kSubSpSize, patching_assembler.pc_offset());
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ sub(sp, framesize)} with a jump to OOL code that does this
  // "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.

  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).
  patching_assembler.jmp_rel(pc_offset() - offset);
  DCHECK_GE(liftoff::kSubSpSize, patching_assembler.pc_offset());
  patching_assembler.Nop(liftoff::kSubSpSize - patching_assembler.pc_offset());

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    // We do not have a scratch register, so pick any and push it first.
    Register stack_limit = eax;
    push(stack_limit);
    mov(stack_limit, esp);
    sub(stack_limit, Immediate(frame_size));
    CompareStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    pop(stack_limit);
    j(above_equal, &continuation, Label::kNear);
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    mov(WasmHandleStackOverflowDescriptor::GapRegister(),
        Immediate(frame_size));
    mov(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), ebp);
    add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
        Immediate(static_cast<int32_t>(
            stack_param_slots * kStackSlotSize +
            CommonFrameConstants::kFixedFrameSizeAboveFp)));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    wasm_call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  AllocateStackSpace(frame_size);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  int func_start_offset = offset + liftoff::kSubSpSize;
  jmp_rel(func_start_offset - pc_offset());
}

void LiftoffAssembler::FinishCode() {}

void LiftoffAssembler::AbortCompilation() {}

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  return value_kind_full_size(kind);
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return is_reference(kind);
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
    mov(budget_array, Operand{instance_data, kArrayOffset});

    int array_offset = kInt32Size * declared_func_index;
    sub(Operand{budget_array, array_offset}, Immediate(budget_used));
  }
  j(negative, ool_label);
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return ebp;
  }
  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  mov(old_fp.gp(), MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
  cmp(old_fp.gp(),
      Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  j(equal, &call_runtime);
  mov(old_fp.gp(), ebp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1, eax);
  MacroAssembler::Move(Operand(esp, 0 * kSystemPointerSize),
                       Immediate(ExternalReference::isolate_address()));
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    mov(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  LiftoffRegister tmp = GetUnusedRegister(RegClass::kGpReg, regs_to_save);
  mov(tmp.gp(), MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
  cmp(tmp.gp(),
      Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  Label done;
  j(not_equal, &done);
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1, kReturnRegister0);
  MacroAssembler::Move(Operand(esp, 0 * kSystemPointerSize),
                       Immediate(ExternalReference::isolate_address()));
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  // Restore old ebp. We don't need to restore old esp explicitly, because
  // it will be restored from ebp in LeaveFrame before return.
  mov(ebp, kReturnRegister0);
  PopRegisters(regs_to_save);
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::Move(reg.gp(), Immediate(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::Move(reg.low_gp(), Immediate(low_word));
      MacroAssembler::Move(reg.high_gp(), Immediate(high_word));
      break;
    }
    case kF32:
      MacroAssembler::Move(reg.fp(), value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::Move(reg.fp(), value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  mov(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  static_assert(!COMPRESS_POINTERS_BOOL);
  mov(dst, Operand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  Operand src{instance, offset};
  switch (size) {
    case 1:
      movzx_b(dst, src);
      break;
    case 4:
      mov(dst, src);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  static_assert(kTaggedSize == kSystemPointerSize);
  mov(dst, Operand{instance, offset});
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  mov(liftoff::GetInstanceDataOperand(), instance);
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  DCHECK_GE(offset_imm, 0);
  static_assert(kTaggedSize == kInt32Size);
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
  mov(dst, Operand(src_addr, offset_imm));
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  DCHECK_GE(offset_imm, 0);
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  static_assert(kTaggedSize == kInt32Size);
  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);

  if (protected_store_pc) *protected_store_pc = pc_offset();

  mov(dst_op, src);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  liftoff::CacheStatePreservingTempRegisters temps{this, pinned};
  Register scratch = temps.Acquire();

  Label exit;
  CheckPageFlag(dst_addr, scratch,
                MemoryChunk::kPointersFromHereAreInterestingMask, zero, &exit,
                Label::kNear);
  JumpIfSmi(src, &exit, Label::kNear);
  CheckPageFlag(src, scratch, MemoryChunk::kPointersToHereAreInterestingMask,
                zero, &exit, Label::kNear);
  lea(scratch, dst_op);
  CallRecordWriteStubSaveRegisters(dst_addr, scratch, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uint32_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool /* i64_offset */,
                            bool needs_shift) {
  // Offsets >=2GB are statically OOB on 32-bit systems.
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  DCHECK_EQ(type.value_type() == kWasmI64, dst.is_gp_pair());
  ScaleFactor scale_factor =
      !needs_shift ? times_1 : static_cast<ScaleFactor>(type.size_log_2());
  Operand src_op = offset_reg == no_reg ? Operand(src_addr, offset_imm)
                                        : Operand(src_addr, offset_reg,
                                                  scale_factor, offset_imm);
  if (protected_load_pc) *protected_load_pc = pc_offset();

  switch (type.value()) {
    case LoadType::kI32Load8U:
      movzx_b(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
      movsx_b(dst.gp(), src_op);
      break;
    case LoadType::kI64Load8U:
      movzx_b(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load8S:
      movsx_b(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI32Load16U:
      movzx_w(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16S:
      movsx_w(dst.gp(), src_op);
      break;
    case LoadType::kI64Load16U:
      movzx_w(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load16S:
      movsx_w(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI32Load:
      mov(dst.gp(), src_op);
      break;
    case LoadType::kI64Load32U:
      mov(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load32S:
      mov(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI64Load: {
      // Compute the operand for the load of the upper half.
      Operand upper_src_op =
          liftoff::MemOperand(src_addr, offset_reg, offset_imm + 4);
      // The high word has to be mov'ed first, such that this is the protected
      // instruction. The mov of the low word cannot segfault.
      mov(dst.high_gp(), upper_src_op);
      mov(dst.low_gp(), src_op);
      break;
    }
    case LoadType::kF32Load:
      movss(dst.fp(), src_op);
      break;
    case LoadType::kF64Load:
      movsd(dst.fp(), src_op);
      break;
    case LoadType::kS128Load:
      movdqu(dst.fp(), src_op);
      break;
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uint32_t offset_imm, Liftoff
Prompt: 
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_IA32_LIFTOFF_ASSEMBLER_IA32_INL_H_
#define V8_WASM_BASELINE_IA32_LIFTOFF_ASSEMBLER_IA32_INL_H_

#include <optional>

#include "src/codegen/assembler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/wasm/baseline/liftoff-assembler.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/object-access.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::wasm {

#define RETURN_FALSE_IF_MISSING_CPU_FEATURE(name)    \
  if (!CpuFeatures::IsSupported(name)) return false; \
  CpuFeatureScope feature(this, name);

namespace liftoff {

inline Operand GetStackSlot(int offset) { return Operand(ebp, -offset); }

inline MemOperand GetHalfStackSlot(int offset, RegPairHalf half) {
  int32_t half_offset =
      half == kLowWord ? 0 : LiftoffAssembler::kStackSlotSize / 2;
  return Operand(offset > 0 ? ebp : esp, -offset + half_offset);
}

// TODO(clemensb): Make this a constexpr variable once Operand is constexpr.
inline Operand GetInstanceDataOperand() {
  return GetStackSlot(WasmLiftoffFrameConstants::kInstanceDataOffset);
}

inline Operand MemOperand(Register base, Register offset_reg, int offset_imm) {
  return offset_reg == no_reg ? Operand(base, offset_imm)
                              : Operand(base, offset_reg, times_1, offset_imm);
}

static constexpr LiftoffRegList kByteRegs =
    LiftoffRegList::FromBits<RegList{eax, ecx, edx}.bits()>();

inline void Load(LiftoffAssembler* assm, LiftoffRegister dst, Register base,
                 int32_t offset, ValueKind kind) {
  Operand src(base, offset);
  switch (kind) {
    case kI16:
      assm->mov_w(dst.gp(), src);
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->mov(dst.gp(), src);
      break;
    case kI64:
      assm->mov(dst.low_gp(), src);
      assm->mov(dst.high_gp(), Operand(base, offset + 4));
      break;
    case kF32:
      assm->movss(dst.fp(), src);
      break;
    case kF64:
      assm->movsd(dst.fp(), src);
      break;
    case kS128:
      assm->movdqu(dst.fp(), src);
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kF16:
      UNREACHABLE();
  }
}

inline void Store(LiftoffAssembler* assm, Register base, int32_t offset,
                  LiftoffRegister src, ValueKind kind) {
  Operand dst(base, offset);
  switch (kind) {
    case kI16:
      assm->mov_w(dst, src.gp());
      break;
    case kI32:
    case kRefNull:
    case kRef:
    case kRtt:
      assm->mov(dst, src.gp());
      break;
    case kI64:
      assm->mov(dst, src.low_gp());
      assm->mov(Operand(base, offset + 4), src.high_gp());
      break;
    case kF32:
      assm->movss(dst, src.fp());
      break;
    case kF64:
      assm->movsd(dst, src.fp());
      break;
    case kS128:
      assm->movdqu(dst, src.fp());
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kF16:
      UNREACHABLE();
  }
}

inline void push(LiftoffAssembler* assm, LiftoffRegister reg, ValueKind kind,
                 int padding = 0) {
  switch (kind) {
    case kI32:
    case kRef:
    case kRefNull:
    case kRtt:
      assm->AllocateStackSpace(padding);
      assm->push(reg.gp());
      break;
    case kI64:
      assm->AllocateStackSpace(padding);
      assm->push(reg.high_gp());
      assm->push(reg.low_gp());
      break;
    case kF32:
      assm->AllocateStackSpace(sizeof(float) + padding);
      assm->movss(Operand(esp, 0), reg.fp());
      break;
    case kF64:
      assm->AllocateStackSpace(sizeof(double) + padding);
      assm->movsd(Operand(esp, 0), reg.fp());
      break;
    case kS128:
      assm->AllocateStackSpace(sizeof(double) * 2 + padding);
      assm->movdqu(Operand(esp, 0), reg.fp());
      break;
    case kVoid:
    case kTop:
    case kBottom:
    case kI8:
    case kI16:
    case kF16:
      UNREACHABLE();
  }
}

inline void SignExtendI32ToI64(Assembler* assm, LiftoffRegister reg) {
  assm->mov(reg.high_gp(), reg.low_gp());
  assm->sar(reg.high_gp(), 31);
}

// Get a temporary byte register, using {candidate} if possible.
// Might spill, but always keeps status flags intact.
inline Register GetTmpByteRegister(LiftoffAssembler* assm, Register candidate) {
  if (candidate.is_byte_register()) return candidate;
  // {GetUnusedRegister()} may insert move instructions to spill registers to
  // the stack. This is OK because {mov} does not change the status flags.
  return assm->GetUnusedRegister(liftoff::kByteRegs).gp();
}

inline void MoveStackValue(LiftoffAssembler* assm, const Operand& src,
                           const Operand& dst) {
  if (assm->cache_state()->has_unused_register(kGpReg)) {
    Register tmp = assm->cache_state()->unused_register(kGpReg).gp();
    assm->mov(tmp, src);
    assm->mov(dst, tmp);
  } else {
    // No free register, move via the stack.
    assm->push(src);
    assm->pop(dst);
  }
}

class CacheStatePreservingTempRegisters {
 public:
  explicit CacheStatePreservingTempRegisters(LiftoffAssembler* assm,
                                             LiftoffRegList pinned = {})
      : assm_(assm), pinned_(pinned) {}

  ~CacheStatePreservingTempRegisters() {
    for (Register reg : must_pop_) {
      assm_->pop(reg);
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
    assm_->push(reg);
    must_pop_.set(reg);
    return reg;
  }

 private:
  LiftoffAssembler* const assm_;
  LiftoffRegList pinned_;
  RegList must_pop_;
};

constexpr DoubleRegister kScratchDoubleReg = xmm7;

constexpr int kSubSpSize = 6;  // 6 bytes for "sub esp, <imm32>"

}  // namespace liftoff

int LiftoffAssembler::PrepareStackFrame() {
  int offset = pc_offset();
  // Next we reserve the memory for the whole stack frame. We do not know yet
  // how big the stack frame will be so we just emit a placeholder instruction.
  // PatchPrepareStackFrame will patch this in order to increase the stack
  // appropriately.
  sub_sp_32(0);
  DCHECK_EQ(liftoff::kSubSpSize, pc_offset() - offset);
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

  LoadConstant(LiftoffRegister(kLiftoffFrameSetupFunctionReg),
               WasmValue(declared_function_index));
  CallBuiltin(Builtin::kWasmLiftoffFrameSetup);
}

void LiftoffAssembler::PrepareTailCall(int num_callee_stack_params,
                                       int stack_param_delta) {
  // Push the return address and frame pointer to complete the stack frame.
  push(Operand(ebp, 4));
  push(Operand(ebp, 0));

  // Shift the whole frame upwards.
  Register scratch = eax;
  push(scratch);
  const int slot_count = num_callee_stack_params + 2;
  for (int i = slot_count; i > 0; --i) {
    mov(scratch, Operand(esp, i * 4));
    mov(Operand(ebp, (i - stack_param_delta - 1) * 4), scratch);
  }
  pop(scratch);

  // Set the new stack and frame pointers.
  lea(esp, Operand(ebp, -stack_param_delta * 4));
  pop(ebp);
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
  DCHECK_EQ(0, frame_size % kSystemPointerSize);

  // We can't run out of space when patching, just pass anything big enough to
  // not cause the assembler to try to grow the buffer.
  constexpr int kAvailableSpace = 64;
  Assembler patching_assembler(
      AssemblerOptions{},
      ExternalAssemblerBuffer(buffer_start_ + offset, kAvailableSpace));

  if (V8_LIKELY(frame_size < 4 * KB)) {
    // This is the standard case for small frames: just subtract from SP and be
    // done with it.
    patching_assembler.sub_sp_32(frame_size);
    DCHECK_EQ(liftoff::kSubSpSize, patching_assembler.pc_offset());
    return;
  }

  // The frame size is bigger than 4KB, so we might overflow the available stack
  // space if we first allocate the frame and then do the stack check (we will
  // need some remaining stack space for throwing the exception). That's why we
  // check the available stack space before we allocate the frame. To do this we
  // replace the {__ sub(sp, framesize)} with a jump to OOL code that does this
  // "extended stack check".
  //
  // The OOL code can simply be generated here with the normal assembler,
  // because all other code generation, including OOL code, has already finished
  // when {PatchPrepareStackFrame} is called. The function prologue then jumps
  // to the current {pc_offset()} to execute the OOL code for allocating the
  // large frame.

  // Emit the unconditional branch in the function prologue (from {offset} to
  // {pc_offset()}).
  patching_assembler.jmp_rel(pc_offset() - offset);
  DCHECK_GE(liftoff::kSubSpSize, patching_assembler.pc_offset());
  patching_assembler.Nop(liftoff::kSubSpSize - patching_assembler.pc_offset());

  // If the frame is bigger than the stack, we throw the stack overflow
  // exception unconditionally. Thereby we can avoid the integer overflow
  // check in the condition code.
  RecordComment("OOL: stack check for large frame");
  Label continuation;
  if (frame_size < v8_flags.stack_size * 1024) {
    // We do not have a scratch register, so pick any and push it first.
    Register stack_limit = eax;
    push(stack_limit);
    mov(stack_limit, esp);
    sub(stack_limit, Immediate(frame_size));
    CompareStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
    pop(stack_limit);
    j(above_equal, &continuation, Label::kNear);
  }

  if (v8_flags.experimental_wasm_growable_stacks) {
    LiftoffRegList regs_to_save;
    regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
    regs_to_save.set(WasmHandleStackOverflowDescriptor::FrameBaseRegister());
    for (auto reg : kGpParamRegisters) regs_to_save.set(reg);
    PushRegisters(regs_to_save);
    mov(WasmHandleStackOverflowDescriptor::GapRegister(),
        Immediate(frame_size));
    mov(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), ebp);
    add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
        Immediate(static_cast<int32_t>(
            stack_param_slots * kStackSlotSize +
            CommonFrameConstants::kFixedFrameSizeAboveFp)));
    CallBuiltin(Builtin::kWasmHandleStackOverflow);
    PopRegisters(regs_to_save);
  } else {
    wasm_call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
    // The call will not return; just define an empty safepoint.
    safepoint_table_builder->DefineSafepoint(this);
    AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  bind(&continuation);

  // Now allocate the stack space. Note that this might do more than just
  // decrementing the SP; consult {MacroAssembler::AllocateStackSpace}.
  AllocateStackSpace(frame_size);

  // Jump back to the start of the function, from {pc_offset()} to
  // right after the reserved space for the {__ sub(sp, sp, framesize)} (which
  // is a branch now).
  int func_start_offset = offset + liftoff::kSubSpSize;
  jmp_rel(func_start_offset - pc_offset());
}

void LiftoffAssembler::FinishCode() {}

void LiftoffAssembler::AbortCompilation() {}

// static
constexpr int LiftoffAssembler::StaticStackFrameSize() {
  return WasmLiftoffFrameConstants::kFeedbackVectorOffset;
}

int LiftoffAssembler::SlotSizeForType(ValueKind kind) {
  return value_kind_full_size(kind);
}

bool LiftoffAssembler::NeedsAlignment(ValueKind kind) {
  return is_reference(kind);
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
    mov(budget_array, Operand{instance_data, kArrayOffset});

    int array_offset = kInt32Size * declared_func_index;
    sub(Operand{budget_array, array_offset}, Immediate(budget_used));
  }
  j(negative, ool_label);
}

Register LiftoffAssembler::LoadOldFramePointer() {
  if (!v8_flags.experimental_wasm_growable_stacks) {
    return ebp;
  }
  LiftoffRegister old_fp = GetUnusedRegister(RegClass::kGpReg, {});
  Label done, call_runtime;
  mov(old_fp.gp(), MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
  cmp(old_fp.gp(),
      Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  j(equal, &call_runtime);
  mov(old_fp.gp(), ebp);
  jmp(&done);

  bind(&call_runtime);
  LiftoffRegList regs_to_save = cache_state()->used_registers;
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1, eax);
  MacroAssembler::Move(Operand(esp, 0 * kSystemPointerSize),
                       Immediate(ExternalReference::isolate_address()));
  CallCFunction(ExternalReference::wasm_load_old_fp(), 1);
  if (old_fp.gp() != kReturnRegister0) {
    mov(old_fp.gp(), kReturnRegister0);
  }
  PopRegisters(regs_to_save);

  bind(&done);
  return old_fp.gp();
}

void LiftoffAssembler::CheckStackShrink() {
  LiftoffRegList regs_to_save;
  for (auto reg : kGpReturnRegisters) regs_to_save.set(reg);
  LiftoffRegister tmp = GetUnusedRegister(RegClass::kGpReg, regs_to_save);
  mov(tmp.gp(), MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
  cmp(tmp.gp(),
      Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
  Label done;
  j(not_equal, &done);
  PushRegisters(regs_to_save);
  PrepareCallCFunction(1, kReturnRegister0);
  MacroAssembler::Move(Operand(esp, 0 * kSystemPointerSize),
                       Immediate(ExternalReference::isolate_address()));
  CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
  // Restore old ebp. We don't need to restore old esp explicitly, because
  // it will be restored from ebp in LeaveFrame before return.
  mov(ebp, kReturnRegister0);
  PopRegisters(regs_to_save);
  bind(&done);
}

void LiftoffAssembler::LoadConstant(LiftoffRegister reg, WasmValue value) {
  switch (value.type().kind()) {
    case kI32:
      MacroAssembler::Move(reg.gp(), Immediate(value.to_i32()));
      break;
    case kI64: {
      int32_t low_word = value.to_i64();
      int32_t high_word = value.to_i64() >> 32;
      MacroAssembler::Move(reg.low_gp(), Immediate(low_word));
      MacroAssembler::Move(reg.high_gp(), Immediate(high_word));
      break;
    }
    case kF32:
      MacroAssembler::Move(reg.fp(), value.to_f32_boxed().get_bits());
      break;
    case kF64:
      MacroAssembler::Move(reg.fp(), value.to_f64_boxed().get_bits());
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadInstanceDataFromFrame(Register dst) {
  mov(dst, liftoff::GetInstanceDataOperand());
}

void LiftoffAssembler::LoadTrustedPointer(Register dst, Register src_addr,
                                          int offset, IndirectPointerTag tag) {
  static_assert(!V8_ENABLE_SANDBOX_BOOL);
  static_assert(!COMPRESS_POINTERS_BOOL);
  mov(dst, Operand{src_addr, offset});
}

void LiftoffAssembler::LoadFromInstance(Register dst, Register instance,
                                        int offset, int size) {
  DCHECK_LE(0, offset);
  Operand src{instance, offset};
  switch (size) {
    case 1:
      movzx_b(dst, src);
      break;
    case 4:
      mov(dst, src);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void LiftoffAssembler::LoadTaggedPointerFromInstance(Register dst,
                                                     Register instance,
                                                     int offset) {
  static_assert(kTaggedSize == kSystemPointerSize);
  mov(dst, Operand{instance, offset});
}

void LiftoffAssembler::SpillInstanceData(Register instance) {
  mov(liftoff::GetInstanceDataOperand(), instance);
}

void LiftoffAssembler::ResetOSRTarget() {}

void LiftoffAssembler::LoadTaggedPointer(Register dst, Register src_addr,
                                         Register offset_reg,
                                         int32_t offset_imm,
                                         uint32_t* protected_load_pc,
                                         bool needs_shift) {
  DCHECK_GE(offset_imm, 0);
  static_assert(kTaggedSize == kInt32Size);
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
  mov(dst, Operand(src_addr, offset_imm));
}

void LiftoffAssembler::StoreTaggedPointer(Register dst_addr,
                                          Register offset_reg,
                                          int32_t offset_imm, Register src,
                                          LiftoffRegList pinned,
                                          uint32_t* protected_store_pc,
                                          SkipWriteBarrier skip_write_barrier) {
  DCHECK_GE(offset_imm, 0);
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  static_assert(kTaggedSize == kInt32Size);
  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);

  if (protected_store_pc) *protected_store_pc = pc_offset();

  mov(dst_op, src);

  if (skip_write_barrier || v8_flags.disable_write_barriers) return;

  liftoff::CacheStatePreservingTempRegisters temps{this, pinned};
  Register scratch = temps.Acquire();

  Label exit;
  CheckPageFlag(dst_addr, scratch,
                MemoryChunk::kPointersFromHereAreInterestingMask, zero, &exit,
                Label::kNear);
  JumpIfSmi(src, &exit, Label::kNear);
  CheckPageFlag(src, scratch, MemoryChunk::kPointersToHereAreInterestingMask,
                zero, &exit, Label::kNear);
  lea(scratch, dst_op);
  CallRecordWriteStubSaveRegisters(dst_addr, scratch, SaveFPRegsMode::kSave,
                                   StubCallMode::kCallWasmRuntimeStub);
  bind(&exit);
}

void LiftoffAssembler::Load(LiftoffRegister dst, Register src_addr,
                            Register offset_reg, uint32_t offset_imm,
                            LoadType type, uint32_t* protected_load_pc,
                            bool /* is_load_mem */, bool /* i64_offset */,
                            bool needs_shift) {
  // Offsets >=2GB are statically OOB on 32-bit systems.
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  DCHECK_EQ(type.value_type() == kWasmI64, dst.is_gp_pair());
  ScaleFactor scale_factor =
      !needs_shift ? times_1 : static_cast<ScaleFactor>(type.size_log_2());
  Operand src_op = offset_reg == no_reg ? Operand(src_addr, offset_imm)
                                        : Operand(src_addr, offset_reg,
                                                  scale_factor, offset_imm);
  if (protected_load_pc) *protected_load_pc = pc_offset();

  switch (type.value()) {
    case LoadType::kI32Load8U:
      movzx_b(dst.gp(), src_op);
      break;
    case LoadType::kI32Load8S:
      movsx_b(dst.gp(), src_op);
      break;
    case LoadType::kI64Load8U:
      movzx_b(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load8S:
      movsx_b(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI32Load16U:
      movzx_w(dst.gp(), src_op);
      break;
    case LoadType::kI32Load16S:
      movsx_w(dst.gp(), src_op);
      break;
    case LoadType::kI64Load16U:
      movzx_w(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load16S:
      movsx_w(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI32Load:
      mov(dst.gp(), src_op);
      break;
    case LoadType::kI64Load32U:
      mov(dst.low_gp(), src_op);
      xor_(dst.high_gp(), dst.high_gp());
      break;
    case LoadType::kI64Load32S:
      mov(dst.low_gp(), src_op);
      liftoff::SignExtendI32ToI64(this, dst);
      break;
    case LoadType::kI64Load: {
      // Compute the operand for the load of the upper half.
      Operand upper_src_op =
          liftoff::MemOperand(src_addr, offset_reg, offset_imm + 4);
      // The high word has to be mov'ed first, such that this is the protected
      // instruction. The mov of the low word cannot segfault.
      mov(dst.high_gp(), upper_src_op);
      mov(dst.low_gp(), src_op);
      break;
    }
    case LoadType::kF32Load:
      movss(dst.fp(), src_op);
      break;
    case LoadType::kF64Load:
      movsd(dst.fp(), src_op);
      break;
    case LoadType::kS128Load:
      movdqu(dst.fp(), src_op);
      break;
    case LoadType::kF32LoadF16:
      UNIMPLEMENTED();
      break;
  }
}

void LiftoffAssembler::Store(Register dst_addr, Register offset_reg,
                             uint32_t offset_imm, LiftoffRegister src,
                             StoreType type, LiftoffRegList pinned,
                             uint32_t* protected_store_pc,
                             bool /* is_store_mem */, bool /* i64_offset */) {
  DCHECK_EQ(type.value_type() == kWasmI64, src.is_gp_pair());
  // Offsets >=2GB are statically OOB on 32-bit systems.
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();

  switch (type.value()) {
    case StoreType::kI64Store8:
      src = src.low();
      [[fallthrough]];
    case StoreType::kI32Store8:
      // Only the lower 4 registers can be addressed as 8-bit registers.
      if (src.gp().is_byte_register()) {
        mov_b(dst_op, src.gp());
      } else {
        // We know that {src} is not a byte register, so the only pinned byte
        // registers (beside the outer {pinned}) are {dst_addr} and potentially
        // {offset_reg}.
        LiftoffRegList pinned_byte = pinned | LiftoffRegList{dst_addr};
        if (offset_reg != no_reg) pinned_byte.set(offset_reg);
        LiftoffRegList candidates = liftoff::kByteRegs.MaskOut(pinned_byte);
        if (cache_state_.has_unused_register(candidates)) {
          Register byte_src = cache_state_.unused_register(candidates).gp();
          mov(byte_src, src.gp());
          mov_b(dst_op, byte_src);
        } else {
          // We have no available byte register. We will temporarily push the
          // root register to use it as a scratch register.
          static_assert(kRootRegister == ebx);
          Register byte_src = kRootRegister;
          Push(byte_src);
          mov(byte_src, src.gp());
          mov_b(dst_op, byte_src);
          Pop(byte_src);
        }
      }
      break;
    case StoreType::kI64Store16:
      src = src.low();
      [[fallthrough]];
    case StoreType::kI32Store16:
      mov_w(dst_op, src.gp());
      break;
    case StoreType::kI64Store32:
      src = src.low();
      [[fallthrough]];
    case StoreType::kI32Store:
      mov(dst_op, src.gp());
      break;
    case StoreType::kI64Store: {
      // Compute the operand for the store of the upper half.
      Operand upper_dst_op =
          liftoff::MemOperand(dst_addr, offset_reg, offset_imm + 4);
      // The high word has to be mov'ed first, such that this is the protected
      // instruction. The mov of the low word cannot segfault.
      mov(upper_dst_op, src.high_gp());
      mov(dst_op, src.low_gp());
      break;
    }
    case StoreType::kF32Store:
      movss(dst_op, src.fp());
      break;
    case StoreType::kF64Store:
      movsd(dst_op, src.fp());
      break;
    case StoreType::kS128Store:
      Movdqu(dst_op, src.fp());
      break;
    case StoreType::kF32StoreF16:
      UNIMPLEMENTED();
      break;
  }
}

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uint32_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool /* i64_offset */) {
  if (type.value() != LoadType::kI64Load) {
    Load(dst, src_addr, offset_reg, offset_imm, type, nullptr, true);
    return;
  }

  DCHECK_EQ(type.value_type() == kWasmI64, dst.is_gp_pair());
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand src_op = liftoff::MemOperand(src_addr, offset_reg, offset_imm);

  movsd(liftoff::kScratchDoubleReg, src_op);
  Pextrd(dst.low().gp(), liftoff::kScratchDoubleReg, 0);
  Pextrd(dst.high().gp(), liftoff::kScratchDoubleReg, 1);
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uint32_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList pinned,
                                   bool /* i64_offset */) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);

  // i64 store uses a totally different approach, hence implement it separately.
  if (type.value() == StoreType::kI64Store) {
    auto scratch2 = GetUnusedRegister(kFpReg, pinned).fp();
    movd(liftoff::kScratchDoubleReg, src.low().gp());
    movd(scratch2, src.high().gp());
    Punpckldq(liftoff::kScratchDoubleReg, scratch2);
    movsd(dst_op, liftoff::kScratchDoubleReg);
    // This lock+or is needed to achieve sequential consistency.
    lock();
    or_(Operand(esp, 0), Immediate(0));
    return;
  }

  // Other i64 stores actually only use the low word.
  if (src.is_pair()) src = src.low();
  Register src_gp = src.gp();

  bool is_byte_store = type.size() == 1;
  LiftoffRegList src_candidates =
      is_byte_store ? liftoff::kByteRegs : kGpCacheRegList;
  pinned = pinned | LiftoffRegList{dst_addr, src};
  if (offset_reg != no_reg) pinned.set(offset_reg);

  // Ensure that {src} is a valid and otherwise unused register.
  if (!src_candidates.has(src) || cache_state_.is_used(src)) {
    // If there are no unused candidate registers, but {src} is a candidate,
    // then spill other uses of {src}. Otherwise spill any candidate register
    // and use that.
    LiftoffRegList unpinned_candidates = src_candidates.MaskOut(pinned);
    if (!cache_state_.has_unused_register(unpinned_candidates) &&
        src_candidates.has(src)) {
      SpillRegister(src);
    } else {
      Register safe_src = GetUnusedRegister(unpinned_candidates).gp();
      mov(safe_src, src_gp);
      src_gp = safe_src;
    }
  }

  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      xchg_b(src_gp, dst_op);
      return;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      xchg_w(src_gp, dst_op);
      return;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      xchg(src_gp, dst_op);
      return;
    default:
      UNREACHABLE();
  }
}

namespace liftoff {
#define __ lasm->

enum Binop { kAdd, kSub, kAnd, kOr, kXor, kExchange };

inline void AtomicAddOrSubOrExchange32(LiftoffAssembler* lasm, Binop binop,
                                       Register dst_addr, Register offset_reg,
                                       uint32_t offset_imm,
                                       LiftoffRegister value,
                                       LiftoffRegister result, StoreType type) {
  DCHECK_EQ(value, result);
  DCHECK(!__ cache_state()->is_used(result));
  bool is_64_bit_op = type.value_type() == kWasmI64;

  Register value_reg = is_64_bit_op ? value.low_gp() : value.gp();
  Register result_reg = is_64_bit_op ? result.low_gp() : result.gp();

  bool is_byte_store = type.size() == 1;
  LiftoffRegList pinned{dst_addr, value_reg};
  if (offset_reg != no_reg) pinned.set(offset_reg);

  // Ensure that {value_reg} is a valid register.
  if (is_byte_store && !liftoff::kByteRegs.has(value_reg)) {
    Register safe_value_reg =
        __ GetUnusedRegister(liftoff::kByteRegs.MaskOut(pinned)).gp();
    __ mov(safe_value_reg, value_reg);
    value_reg = safe_value_reg;
  }

  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);
  if (binop == kSub) {
    __ neg(value_reg);
  }
  if (binop != kExchange) {
    __ lock();
  }
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      if (binop == kExchange) {
        __ xchg_b(value_reg, dst_op);
      } else {
        __ xadd_b(dst_op, value_reg);
      }
      __ movzx_b(result_reg, value_reg);
      break;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      if (binop == kExchange) {
        __ xchg_w(value_reg, dst_op);
      } else {
        __ xadd_w(dst_op, value_reg);
      }
      __ movzx_w(result_reg, value_reg);
      break;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      if (binop == kExchange) {
        __ xchg(value_reg, dst_op);
      } else {
        __ xadd(dst_op, value_reg);
      }
      if (value_reg != result_reg) {
        __ mov(result_reg, value_reg);
      }
      break;
    default:
      UNREACHABLE();
  }
  if (is_64_bit_op) {
    __ xor_(result.high_gp(), result.high_gp());
  }
}

inline void AtomicBinop32(LiftoffAssembler* lasm, Binop op, Register dst_addr,
                          Register offset_reg, uint32_t offset_imm,
                          LiftoffRegister value, LiftoffRegister result,
                          StoreType type) {
  DCHECK_EQ(value, result);
  DCHECK(!__ cache_state()->is_used(result));
  bool is_64_bit_op = type.value_type() == kWasmI64;

  Register value_reg = is_64_bit_op ? value.low_gp() : value.gp();
  Register result_reg = is_64_bit_op ? result.low_gp() : result.gp();

  // The cmpxchg instruction uses eax to store the old value of the
  // compare-exchange primitive. Therefore we have to spill the register and
  // move any use to another register.
  {
    LiftoffRegList pinned{dst_addr, value_reg};
    if (offset_reg != no_reg) pinned.set(offset_reg);
    __ ClearRegister(eax, {&dst_addr, &offset_reg, &value_reg}, pinned);
  }

  bool is_byte_store = type.size() == 1;
  Register scratch = no_reg;
  if (is_byte_store) {
    // The scratch register has to be a byte register. As we are already tight
    // on registers, we just use the root register here.
    static_assert(!kLiftoffAssemblerGpCacheRegs.has(kRootRegister),
                  "root register is not Liftoff cache register");
    DCHECK(kRootRegister.is_byte_register());
    __ push(kRootRegister);
    scratch = kRootRegister;
  } else {
    LiftoffRegList pinned{dst_addr, value_reg, eax};
    if (offset_reg != no_reg) pinned.set(offset_reg);
    scratch = __ GetUnusedRegister(kGpReg, pinned).gp();
  }

  Operand dst_op = liftoff::MemOperand(dst_addr, offset_reg, offset_imm);

  switch (type.value()) {
    case StoreType::kI32Store8:

"""


```