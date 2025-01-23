Response:
The user wants to understand the functionality of the `macro-assembler-loong64.cc` file in the V8 JavaScript engine. They've provided a snippet of the code and have specific questions about its nature and relationship to JavaScript.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose of the file:** The filename and the `#if V8_TARGET_ARCH_LOONG64` directive strongly suggest this file contains architecture-specific code generation logic for the LoongArch 64-bit architecture. The "macro-assembler" part indicates it provides a higher-level interface for generating assembly instructions.

2. **Analyze the included headers:** The headers provide further clues about the file's responsibilities:
    * `assembler-inl.h`, `macro-assembler.h`: Core components for assembly generation.
    * `codegen/...`:  Indicates this is part of the code generation pipeline.
    * `builtins-inl.h`, `runtime.h`: Interaction with built-in functions and the runtime system.
    * `objects/heap-number.h`: Handling of JavaScript objects in the heap.
    * `deoptimizer/deoptimizer.h`: Support for deoptimization.
    * `execution/frames-inl.h`: Management of execution frames.

3. **Examine the code snippets:** The provided code contains various methods like `PushCallerSaved`, `PopCallerSaved`, `LoadRoot`, `RecordWriteField`, `Add_d`, `Sub_w`, etc. These are clearly operations related to:
    * **Stack management:** Pushing and popping registers.
    * **Memory access:** Loading and storing data from memory, including handling tagged pointers and roots.
    * **Write barriers:** Implementing mechanisms for garbage collection.
    * **Basic arithmetic and logical operations:**  Wrappers around assembly instructions.
    * **Function calls:** Setting up call frames.
    * **Sandboxing and pointer protection:** Dealing with security-related memory management.

4. **Address the user's specific questions:**

    * **Functionality:**  Based on the analysis above, the primary function is to provide an architecture-specific abstraction layer for generating LoongArch64 assembly instructions, used during the compilation of JavaScript code.

    * **`.tq` extension:**  The file ends in `.cc`, not `.tq`. Therefore, it's a standard C++ source file, not a Torque file. Torque files are used for defining built-in functions in a more declarative way.

    * **Relationship to JavaScript:**  This file is *crucial* for V8's ability to execute JavaScript on LoongArch64. It's the bridge between V8's internal representations and the actual machine code. JavaScript code gets compiled into assembly instructions using this `MacroAssembler`. Provide a simple JavaScript example and illustrate how it might translate to low-level operations handled by this file (e.g., variable assignment leading to a memory write).

    * **Code logic reasoning (with assumptions):** Choose a simple function like `Add_d`. Assume inputs (registers and an immediate value) and describe the expected output (the result in the destination register).

    * **Common programming errors:** Focus on errors related to memory management and register usage, which are common in low-level programming and can be exposed through the functionalities of this file (e.g., incorrect stack pointer manipulation, using the wrong registers).

    * **Summary:** Concisely reiterate the main purpose: architecture-specific assembly generation for LoongArch64, used during JavaScript compilation.

5. **Structure the answer:** Organize the information logically, addressing each of the user's questions clearly and providing examples where requested. Use clear language and avoid overly technical jargon where possible.

By following these steps, we can provide a comprehensive and accurate answer to the user's request, explaining the purpose and significance of the `macro-assembler-loong64.cc` file within the V8 engine.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_LOONG64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/loong64/macro-assembler-loong64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

static inline bool IsZero(const Operand& rk) {
  if (rk.is_reg()) {
    return rk.rm() == zero_reg;
  } else {
    return rk.immediate() == 0;
  }
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  Ld_d(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}
void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    li(destination, (int32_t)ReadOnlyRootPtr(index));
    return;
  }
  Ld_w(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Push(ra, fp, marker_reg);
    Add_d(fp, sp, Operand(kSystemPointerSize));
  } else {
    Push(ra, fp);
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int offset = -StandardFrameConstants::kContextOffset;
  if (function_reg.is_valid()) {
    Push(ra, fp, cp, function_reg, kJavaScriptCallArgCountRegister);
    offset += 2 * kSystemPointerSize;
  } else {
    Push(ra, fp, cp, kJavaScriptCallArgCountRegister);
    offset += kSystemPointerSize;
  }
  Add_d(fp, sp, Operand(offset));
}

// Clobbers object, dst, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer. The heap object
// tag is shifted away.
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, RAStatus ra_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    Label ok;
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Add_d(scratch, object, offset - kHeapObjectTag);
    And(scratch, scratch, Operand(kTaggedSize - 1));
    Branch(&ok, eq, scratch, Operand(zero_reg));
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, ra_status,
              save_fp, SmiCheck::kOmit, slot);

  bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  srli_d(value, value, kSandboxedPointerShift);
  Add_d(value, value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ld_d(destination, field_operand);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(Register value,
                                                MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Sub_d(scratch, value, kPtrComprCageBaseRegister);
  slli_d(scratch, scratch, kSandboxedPointerShift);
  St_d(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.Acquire();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ld_d(external_table,
       MemOperand(isolate_root,
                  IsolateData::external_pointer_table_offset() +
                      Internals::kExternalPointerTableBasePointerOffset));
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kExternalPointerIndexShift);
  slli_d(destination, destination, kExternalPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(external_table, destination));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  li(tag_reg, Operand(~tag));
  And(destination, destination, tag_reg);
#else
  Ld_d(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand);
#else
  StoreTaggedField(value, dst_field_operand);
#endif
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register handle = temps.hasAvailable() ? temps.Acquire() : t8;
  Ld_wu(handle, field_operand);

  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Ld_w(scratch, FieldMemOperand(
                    value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  St_w(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    DCHECK(!AreAliased(destination, handle));
    And(destination, handle, kCodePointerHandleMarker);
    Branch(&is_trusted_pointer_handle, eq, destination, Operand(zero_reg));
    ResolveCodePointerHandle(destination, handle);
    Branch(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  DCHECK(root_array_available_);
  Register table = destination;
  Ld_d(table,
       MemOperand(kRootRegister, IsolateData::trusted_pointer_table_offset()));
  srli_d(handle, handle, kTrustedPointerHandleShift);
  Alsl_d(destination, handle, table, kTrustedPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(destination, 0));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  li(tag_reg, Operand(~(tag | kTrustedPointerTableMarkBit)));
  and_(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  li(table, ExternalReference::code_pointer_table_address());
  srli_d(handle, handle, kCodePointerHandleShift);
  Alsl_d(destination, handle, table, kCodePointerTableEntrySizeLog2);
  Ld_d(destination,
       MemOperand(destination, kCodePointerTableEntryCodeObjectOffset));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Or(destination, destination, Operand(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, ExternalReference::code_pointer_table_address());
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kCodePointerHandleShift);
  slli_d(destination, destination, kCodePointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    li(scratch, Operand(tag));
    xor_(destination, destination, scratch);
  }
}
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  Ld_d(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(parameter_count, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, parameter_count);
  Ld_d(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(parameter_count,
        MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object, Operand offset,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(
      IndirectPointerWriteBarrierDescriptor::ObjectRegister(),
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister(), object,
      offset);
  li(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
     Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Operand offset,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst_object, dst_slot);
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add_d(dst_slot, object, offset);
    mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.rm() != dst_object)) {
    mov(dst_object, dst_slot);
    Add_d(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add_d(dst_slot, dst_slot, dst_object);
  Sub_d(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
// TODO(LOONG_dev): LOONG64 Check this comment
// Clobbers object, address, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer. The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, RAStatus ra_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
    Add_d(scratch, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(scratch, MemOperand(scratch, 0),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(scratch, MemOperand(scratch, 0));
    }
    Assert(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite, scratch,
           Operand(value));
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &done);

  CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                &done);

  // Record the actual write.
  if (ra_status == kRAHasNotBeenSaved) {
    Push(ra);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    DCHECK(offset.IsImmediate());
    Add_d(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (ra_status == kRAHasNotBeenSaved) {
    Pop(ra);
  }

  bind(&done);
}

// ---------------------------------------------------------------------------
// Instruction macros.

void MacroAssembler::Add_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_w(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_w(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_w(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Add_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_d(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_d(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sub_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_w(rd, rj, rk.rm());
  } else {
    DCHECK(is_int32(rk.immediate()));
    if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
      // No subi_w instr, use addi_w(x, y, -imm).
      addi_w(rd, rj, static_cast<int32_t>(-rk.immediate()));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      if (-rk.immediate() >> 12 == 0 && !MustUseReg(rk.rmode())) {
        // Use load -imm and addu when loading -imm generates one instruction.
        li(scratch, -rk.immediate());
        add_w(rd, rj, scratch);
      } else {
        // li handles the relocation.
        li(scratch, rk);
        sub_w(rd, rj, scratch);
      }
    }
  }
}

void MacroAssembler::Sub_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_d(rd, rj, rk.rm());
  } else if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
    // No subi_d instr, use addi_d(x, y, -imm).
    addi_d(rd, rj, static_cast<int32_t>(-rk.immediate()));
  } else {
    DCHECK(rj != t7);
    int li_count = InstrCountForLi64Bit(rk.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rk.immediate());
    if (li_neg_count < li_count && !MustUseReg(rk.rmode())) {
      // Use load -imm and add_d when loading -imm generates one instruction.
      DCHECK(rk.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rk.immediate()));
      add_d(rd, rj, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rk);
      sub_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Mul_w(Register rd, Register rj, const Operand& rk) {
  if (rk.
### 提示词
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_LOONG64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/loong64/macro-assembler-loong64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

static inline bool IsZero(const Operand& rk) {
  if (rk.is_reg()) {
    return rk.rm() == zero_reg;
  } else {
    return rk.immediate() == 0;
  }
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kSystemPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kSystemPointerSize;

  return bytes;
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    DecompressTagged(destination, ReadOnlyRootPtr(index));
    return;
  }
  // Many roots have addresses that are too large to fit into addition immediate
  // operands. Evidence suggests that the extra instruction for decompression
  // costs us more than the load.
  Ld_d(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}
void MacroAssembler::LoadTaggedRoot(Register destination, RootIndex index) {
  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index) &&
      is_int12(ReadOnlyRootPtr(index))) {
    li(destination, (int32_t)ReadOnlyRootPtr(index));
    return;
  }
  Ld_w(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Push(ra, fp, marker_reg);
    Add_d(fp, sp, Operand(kSystemPointerSize));
  } else {
    Push(ra, fp);
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int offset = -StandardFrameConstants::kContextOffset;
  if (function_reg.is_valid()) {
    Push(ra, fp, cp, function_reg, kJavaScriptCallArgCountRegister);
    offset += 2 * kSystemPointerSize;
  } else {
    Push(ra, fp, cp, kJavaScriptCallArgCountRegister);
    offset += kSystemPointerSize;
  }
  Add_d(fp, sp, Operand(offset));
}

// Clobbers object, dst, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, RAStatus ra_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    Label ok;
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Add_d(scratch, object, offset - kHeapObjectTag);
    And(scratch, scratch, Operand(kTaggedSize - 1));
    Branch(&ok, eq, scratch, Operand(zero_reg));
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, ra_status,
              save_fp, SmiCheck::kOmit, slot);

  bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  srli_d(value, value, kSandboxedPointerShift);
  Add_d(value, value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ld_d(destination, field_operand);
  DecodeSandboxedPointer(destination);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::StoreSandboxedPointerField(Register value,
                                                MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Sub_d(scratch, value, kPtrComprCageBaseRegister);
  slli_d(scratch, scratch, kSandboxedPointerShift);
  St_d(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadExternalPointerField(Register destination,
                                              MemOperand field_operand,
                                              ExternalPointerTag tag,
                                              Register isolate_root) {
  DCHECK(!AreAliased(destination, isolate_root));
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  DCHECK(!IsSharedExternalPointerType(tag));
  UseScratchRegisterScope temps(this);
  Register external_table = temps.Acquire();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ld_d(external_table,
       MemOperand(isolate_root,
                  IsolateData::external_pointer_table_offset() +
                      Internals::kExternalPointerTableBasePointerOffset));
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kExternalPointerIndexShift);
  slli_d(destination, destination, kExternalPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(external_table, destination));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  li(tag_reg, Operand(~tag));
  And(destination, destination, tag_reg);
#else
  Ld_d(destination, field_operand);
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::LoadTrustedPointerField(Register destination,
                                             MemOperand field_operand,
                                             IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  LoadIndirectPointerField(destination, field_operand, tag);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::StoreTrustedPointerField(Register value,
                                              MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(value, dst_field_operand);
#else
  StoreTaggedField(value, dst_field_operand);
#endif
}

void MacroAssembler::LoadIndirectPointerField(Register destination,
                                              MemOperand field_operand,
                                              IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register handle = temps.hasAvailable() ? temps.Acquire() : t8;
  Ld_wu(handle, field_operand);

  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Ld_w(scratch, FieldMemOperand(
                    value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  St_w(scratch, dst_field_operand);
#else
  UNREACHABLE();
#endif
}

#ifdef V8_ENABLE_SANDBOX
void MacroAssembler::ResolveIndirectPointerHandle(Register destination,
                                                  Register handle,
                                                  IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    Label is_trusted_pointer_handle, done;
    DCHECK(!AreAliased(destination, handle));
    And(destination, handle, kCodePointerHandleMarker);
    Branch(&is_trusted_pointer_handle, eq, destination, Operand(zero_reg));
    ResolveCodePointerHandle(destination, handle);
    Branch(&done);
    bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    bind(&done);
  } else if (tag == kCodeIndirectPointerTag) {
    ResolveCodePointerHandle(destination, handle);
  } else {
    ResolveTrustedPointerHandle(destination, handle, tag);
  }
}

void MacroAssembler::ResolveTrustedPointerHandle(Register destination,
                                                 Register handle,
                                                 IndirectPointerTag tag) {
  DCHECK_NE(tag, kCodeIndirectPointerTag);
  DCHECK(!AreAliased(handle, destination));

  DCHECK(root_array_available_);
  Register table = destination;
  Ld_d(table,
       MemOperand(kRootRegister, IsolateData::trusted_pointer_table_offset()));
  srli_d(handle, handle, kTrustedPointerHandleShift);
  Alsl_d(destination, handle, table, kTrustedPointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(destination, 0));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  li(tag_reg, Operand(~(tag | kTrustedPointerTableMarkBit)));
  and_(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  li(table, ExternalReference::code_pointer_table_address());
  srli_d(handle, handle, kCodePointerHandleShift);
  Alsl_d(destination, handle, table, kCodePointerTableEntrySizeLog2);
  Ld_d(destination,
       MemOperand(destination, kCodePointerTableEntryCodeObjectOffset));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Or(destination, destination, Operand(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, ExternalReference::code_pointer_table_address());
  Ld_wu(destination, field_operand);
  srli_d(destination, destination, kCodePointerHandleShift);
  slli_d(destination, destination, kCodePointerTableEntrySizeLog2);
  Ld_d(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    li(scratch, Operand(tag));
    xor_(destination, destination, scratch);
  }
}
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  Ld_d(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(destination, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, destination);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli_d(index, dispatch_handle, kJSDispatchHandleShift);
  slli_d(parameter_count, index, kJSDispatchTableEntrySizeLog2);
  Add_d(scratch, scratch, parameter_count);
  Ld_d(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ld_hu(parameter_count,
        MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallIndirectPointerBarrier(Register object, Operand offset,
                                                SaveFPRegsMode fp_mode,
                                                IndirectPointerTag tag) {
  ASM_CODE_COMMENT(this);
  RegList registers =
      IndirectPointerWriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(
      IndirectPointerWriteBarrierDescriptor::ObjectRegister(),
      IndirectPointerWriteBarrierDescriptor::SlotAddressRegister(), object,
      offset);
  li(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
     Operand(tag));

  CallBuiltin(Builtins::IndirectPointerBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Operand offset,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  MoveObjectAndSlot(object_parameter, slot_address_parameter, object, offset);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

void MacroAssembler::MoveObjectAndSlot(Register dst_object, Register dst_slot,
                                       Register object, Operand offset) {
  ASM_CODE_COMMENT(this);
  DCHECK_NE(dst_object, dst_slot);
  // If `offset` is a register, it cannot overlap with `object`.
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.rm() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add_d(dst_slot, object, offset);
    mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.rm() != dst_object)) {
    mov(dst_object, dst_slot);
    Add_d(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.rm());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add_d(dst_slot, dst_slot, dst_object);
  Sub_d(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
// TODO(LOONG_dev): LOONG64 Check this comment
// Clobbers object, address, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, RAStatus ra_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 SlotDescriptor slot) {
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
    Add_d(scratch, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(scratch, MemOperand(scratch, 0),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(scratch, MemOperand(scratch, 0));
    }
    Assert(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite, scratch,
           Operand(value));
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                &done);

  CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                &done);

  // Record the actual write.
  if (ra_status == kRAHasNotBeenSaved) {
    Push(ra);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    DCHECK(offset.IsImmediate());
    Add_d(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (ra_status == kRAHasNotBeenSaved) {
    Pop(ra);
  }

  bind(&done);
}

// ---------------------------------------------------------------------------
// Instruction macros.

void MacroAssembler::Add_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_w(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_w(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_w(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Add_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    add_d(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      addi_d(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      add_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sub_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_w(rd, rj, rk.rm());
  } else {
    DCHECK(is_int32(rk.immediate()));
    if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
      // No subi_w instr, use addi_w(x, y, -imm).
      addi_w(rd, rj, static_cast<int32_t>(-rk.immediate()));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      if (-rk.immediate() >> 12 == 0 && !MustUseReg(rk.rmode())) {
        // Use load -imm and addu when loading -imm generates one instruction.
        li(scratch, -rk.immediate());
        add_w(rd, rj, scratch);
      } else {
        // li handles the relocation.
        li(scratch, rk);
        sub_w(rd, rj, scratch);
      }
    }
  }
}

void MacroAssembler::Sub_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sub_d(rd, rj, rk.rm());
  } else if (is_int12(-rk.immediate()) && !MustUseReg(rk.rmode())) {
    // No subi_d instr, use addi_d(x, y, -imm).
    addi_d(rd, rj, static_cast<int32_t>(-rk.immediate()));
  } else {
    DCHECK(rj != t7);
    int li_count = InstrCountForLi64Bit(rk.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rk.immediate());
    if (li_neg_count < li_count && !MustUseReg(rk.rmode())) {
      // Use load -imm and add_d when loading -imm generates one instruction.
      DCHECK(rk.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rk.immediate()));
      add_d(rd, rj, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rk);
      sub_d(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Mul_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mul_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mul_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Mul_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mul_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mul_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mulh_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mulh_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mulh_du(rd, rj, scratch);
  }
}

void MacroAssembler::Div_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_w(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_w(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Div_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_d(rd, rj, scratch);
  }
}

void MacroAssembler::Div_wu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_wu(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_wu(rd, rj, scratch);
  }
}

void MacroAssembler::Div_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    div_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    div_du(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_d(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_d(rd, rj, scratch);
  }
}

void MacroAssembler::Mod_du(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    mod_du(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    mod_du(rd, rj, scratch);
  }
}

void MacroAssembler::And(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    and_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      andi(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      and_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Or(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    or_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      ori(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      or_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Xor(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    xor_(rd, rj, rk.rm());
  } else {
    if (is_uint12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      xori(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rj != scratch);
      li(scratch, rk);
      xor_(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Nor(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    nor(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    nor(rd, rj, scratch);
  }
}

void MacroAssembler::Andn(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    andn(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    andn(rd, rj, scratch);
  }
}

void MacroAssembler::Orn(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    orn(rd, rj, rk.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rj != scratch);
    li(scratch, rk);
    orn(rd, rj, scratch);
  }
}

void MacroAssembler::Neg(Register rj, const Operand& rk) {
  DCHECK(rk.is_reg());
  sub_d(rj, zero_reg, rk.rm());
}

void MacroAssembler::Slt(Regis
```