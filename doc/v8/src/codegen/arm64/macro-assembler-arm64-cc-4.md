Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/macro-assembler-arm64.cc`.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose:** The filename `macro-assembler-arm64.cc` immediately suggests that this code is responsible for generating ARM64 assembly instructions. The class `MacroAssembler` is a common pattern in code generation, providing a higher-level interface than directly emitting bytes.

2. **Analyze individual functions:**  Go through each function and determine its specific role. Keywords like `CheckPageFlag`, `JumpIfMarking`, `RecordWriteField`, `DecodeSandboxedPointer`, `Load/Store...Field`, `Call...Barrier`, `Abort`, `Printf` provide strong hints.

3. **Group related functionalities:**  Notice patterns in the function names and their parameters. For example, many functions deal with memory access (`Load...`, `Store...`), garbage collection (`CheckPageFlag`, `JumpIfMarking`, `RecordWrite`), sandboxing (`DecodeSandboxedPointer`, `LoadSandboxedPointerField`, etc.), and debugging/error handling (`Check`, `Abort`, `Printf`).

4. **Determine if it's Torque:** The prompt specifically asks about `.tq` files. The provided code ends in `.cc`, so it's C++, not Torque.

5. **Check for JavaScript relevance and provide examples:**  Consider how the low-level assembly generation relates to JavaScript execution. Garbage collection, memory management, and function calls are fundamental. Think of simple JavaScript scenarios that would trigger these underlying mechanisms. For example, object creation and assignment would involve memory allocation and potentially write barriers.

6. **Identify code logic and provide input/output examples:** Look for functions that perform conditional logic or data manipulation. `CheckPageFlag` and the `JumpIf...` functions are good candidates. Create simple scenarios to illustrate their behavior. For `CheckPageFlag`, assume the `object` address and `mask` values, and show when the `condition_met` label would be reached.

7. **Pinpoint common programming errors:** Think about common mistakes that developers make that these low-level functions might help detect or prevent. Memory corruption (e.g., writing to read-only memory, writing to incorrect addresses) and type errors (trying to treat a Smi as a pointer) are relevant.

8. **Summarize the functionality:** Combine the observations from the previous steps into a concise summary. Emphasize the core purpose of assembly generation and the specific areas covered by the provided snippet.

9. **Address the "part 5 of 6" instruction:** Acknowledge that this is part of a larger file and that this snippet represents a specific set of functionalities within the broader assembler implementation.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus heavily on individual instruction mnemonics (e.g., `Ldr`, `Str`).
* **Correction:** Shift focus to the *higher-level purpose* of the functions. The individual instructions are the *implementation details*, but the user wants to understand the *what*, not just the *how*.
* **Initial thought:**  Assume the user has deep knowledge of V8 internals.
* **Correction:** Explain concepts like "write barrier" and "Smi" in a way that's understandable even without extensive V8 knowledge. Provide context and purpose.
* **Initial thought:**  Only provide C++ explanations.
* **Correction:**  As requested, provide JavaScript examples to illustrate the connection between the low-level code and higher-level language features.
* **Initial thought:**  List every single function's purpose individually in the summary.
* **Correction:** Group related functionalities into broader categories for a more concise and understandable summary.
```cpp
(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::CheckPageFlag(const Register& object, int mask,
                                   Condition cc, Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  And(scratch, object, ~MemoryChunk::GetAlignmentMaskForAssembler());
  Ldr(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  if (cc == ne) {
    TestAndBranchIfAnySet(scratch, mask, condition_met);
  } else {
    DCHECK_EQ(cc, eq);
    TestAndBranchIfAllClear(scratch, mask, condition_met);
  }
}

void MacroAssembler::JumpIfMarking(Label* is_marking,
                                   Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbnz(scratch, is_marking);
}

void MacroAssembler::JumpIfNotMarking(Label* not_marking,
                                      Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbz(scratch, not_marking);
}

void MacroAssembler::RecordWriteField(
    Register object, int offset, Register value, LinkRegisterStatus lr_status,
    SaveFPRegsMode save_fp, SmiCheck smi_check, ReadOnlyCheck ro_check,
    SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis and read-only objects.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  // Skip the barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();
    DCHECK(!AreAliased(object, value, scratch));
    Add(scratch, object, offset - kHeapObjectTag);
    Tst(scratch, kTaggedSize - 1);
    B(eq, &ok);
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    Bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, lr_status,
              save_fp, SmiCheck::kOmit, ReadOnlyCheck::kOmit, slot);

  Bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  Add(value, kPtrComprCageBaseRegister,
      Operand(value, LSR, kSandboxedPointerShift));
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ldr(destination, field_operand);
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
  Register scratch = temps.AcquireX();
  Sub(scratch, value, kPtrComprCageBaseRegister);
  Mov(scratch, Operand(scratch, LSL, kSandboxedPointerShift));
  Str(scratch, dst_field_operand);
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
  Register external_table = temps.AcquireX();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ldr(external_table,
      MemOperand(isolate_root,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset));
  Ldr(destination.W(), field_operand);
  Mov(destination, Operand(destination, LSR, kExternalPointerIndexShift));
  Ldr(destination, MemOperand(external_table, destination, LSL,
                              kExternalPointerTableEntrySizeLog2));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  Mov(tag_reg, Immediate(~tag));
  And(destination, destination, tag_reg);
#else
  Ldr(destination, field_operand);
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

  Register handle = temps.AcquireX();
  Ldr(handle.W(), field_operand);
  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldr(scratch.W(),
      FieldMemOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  Str(scratch.W(), dst_field_operand);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
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
    constexpr int kCodePointerHandleMarkerBit = 0;
    static_assert((1 << kCodePointerHandleMarkerBit) ==
                  kCodePointerHandleMarker);
    Tbz(handle, kCodePointerHandleMarkerBit, &is_trusted_pointer_handle);
    ResolveCodePointerHandle(destination, handle);
    B(&done);
    Bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    Bind(&done);
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

  Register table = destination;
  DCHECK(root_array_available_);
  Ldr(table,
      MemOperand{kRootRegister, IsolateData::trusted_pointer_table_offset()});
  Mov(handle, Operand(handle, LSR, kTrustedPointerHandleShift));
  Ldr(destination,
      MemOperand(table, handle, LSL, kTrustedPointerTableEntrySizeLog2));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  Mov(tag_reg, Immediate(~(tag | kTrustedPointerTableMarkBit)));
  And(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  Mov(table, ExternalReference::code_pointer_table_address());
  Mov(handle, Operand(handle, LSR, kCodePointerHandleShift));
  Add(destination, table, Operand(handle, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination,
      MemOperand(destination,
                 Immediate(kCodePointerTableEntryCodeObjectOffset)));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Orr(destination, destination, Immediate(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, ExternalReference::code_pointer_table_address());
  Ldr(destination.W(), field_operand);
  // TODO(saelo): can the offset computation be done more efficiently?
  Mov(destination, Operand(destination, LSR, kCodePointerHandleShift));
  Mov(destination, Operand(destination, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    Mov(scratch, Immediate(tag));
    Eor(destination, destination, scratch);
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
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(parameter_count,
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
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PushCPURegList(regs);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PopCPURegList(regs);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(WriteBarrierDescriptor::ObjectRegister(),
                    WriteBarrierDescriptor::SlotAddressRegister(), object,
                    offset);

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
  Mov(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
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
  ASM_CODE_COMMENT(this);
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
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.reg() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add(dst_slot, object, offset);
    Mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.reg() != dst_object)) {
    Mov(dst_object, dst_slot);
    Add(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.reg());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add(dst_slot, dst_slot, dst_object);
  Sub(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
//
// The register 'object' contains a heap object pointer. The heap object tag is
// shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 ReadOnlyCheck ro_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  ASM_LOCATION_IN_ASSEMBLER("MacroAssembler::RecordWrite");
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    DCHECK(!AreAliased(object, value, temp));
    Add(temp, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(temp, MemOperand(temp),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(temp, MemOperand(temp));
    }
    Cmp(temp, value);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smisand read-only objects, as well as stores into the
  // young generation.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  if (slot.contains_indirect_pointer()) {
    // The indirect pointer write barrier is only enabled during marking.
    JumpIfNotMarking(&done);
  } else {
    CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                  &done);

    CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                  &done);
  }

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    Push<MacroAssembler::kSignLR>(padreg, lr);
  }
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    // TODO(cbruni): Turn offset into int.
    DCHECK(offset.IsImmediate());
    Add(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (lr_status == kLRHasNotBeenSaved) {
    Pop<MacroAssembler::kAuthLR>(lr, padreg);
  }
  if (v8_flags.debug_code) Mov(slot_address, Operand(kZapValue));

  Bind(&done);
}

void MacroAssembler::Check(Condition cond, AbortReason reason) {
  Label ok;
  B(cond, &ok);
  Abort(reason);
  // Will not return here.
  Bind(&ok);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason) {
  Check(cc, reason);
}

void MacroAssembler::Trap() { Brk(0); }
void MacroAssembler::DebugBreak() { Debug("DebugBreak", 0, BREAK); }

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.code_comments) {
    RecordComment("Abort message: ");
    RecordComment(GetAbortReason(reason));
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    Brk(0);
    return;
  }

  // We need some scratch registers for the MacroAssembler, so make sure we have
  // some. This is safe here because Abort never returns.
  uint64_t old_tmp_list = TmpList()->bits();
  TmpList()->Combine(MacroAssembler::DefaultTmpList());

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    Mov(w0, static_cast<int>(reason));
    Call(ExternalReference::abort_with_reason());
    return;
  }

  // Avoid infinite recursion; Push contains some assertions that use Abort.
  HardAbortScope hard_aborts(this);

  Mov(x1, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      LoadEntryFromBuiltin(Builtin::kAbort, scratch);
      Call(scratch);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  TmpList()->set_bits(old_tmp_list);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    UseScratchRegisterScope temps(this);

    // The entry references a CodeWrapper object. Unwrap it now.
    LoadCodePointerField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    Register temp = temps.AcquireX();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      B(&fallthrough);
    } else {
      B(on_result);
    }
  }

  bind(&clear_slot);
  Mov(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  Mov(scratch_and_result, 0);
}

// This is the main Printf implementation. All other Printf variants call
// PrintfNoPreserve after setting up one or more PreserveRegisterScopes.
void MacroAssembler::PrintfNoPreserve(const char* format,
                                      const CPURegister& arg0,
                                      const CPURegister& arg1,
                                      const CPURegister& arg2,
                                      const CPURegister& arg3) {
  ASM_CODE_COMMENT(this);
  // We cannot handle a caller-saved stack pointer. It doesn't make much sense
  // in most cases anyway, so this restriction shouldn't be too serious.
  DCHECK(!kCallerSaved.IncludesAliasOf(sp));

  // The provided arguments, and their proper procedure-call standard registers.
  CPURegister args[kPrintfMaxArgCount] = {arg0, arg1, arg2, arg3};
  CPURegister pcs[kPrintfMaxArgCount] = {NoReg, NoReg, NoReg, NoReg};

  int arg_count = kPrintfMaxArgCount;

  // The PCS varargs registers for printf. Note that x0 is used for the printf
  // format string.
  static const CPURegList kPCSVarargs =
      CPURegList(CPURegister::kRegister, kXRegSizeInBits, 1, arg_count);
  static const CPURegList kPCSVarargsFP =
      CPURegList(CPURegister::kVRegister, kDRegSizeInBits, 0, arg_count - 1);

  // We can use caller-saved registers as scratch values, except for the
  // arguments and the PCS registers where they might need to go.
  CPURegList tmp_list = kCallerSaved;
  tmp_list.Remove(x0);  // Used to pass the format string.
  tmp_list.Remove(kPCSVarargs);
  tmp_list.Remove(arg0, arg1, arg2, arg3);

  CPURegList fp_tmp_list = kCallerSavedV;
  fp_tmp_list.Remove(kPCSVarargsFP);
  fp_tmp_list.Remove(arg0, arg1, arg2, arg3);

  // Override the MacroAssembler's scratch register list. The lists will be
  // reset automatically at the end of the UseScratchRegisterScope.
  UseScratchRegisterScope temps(this);
  TmpList()->set_bits(tmp_list.bits());
  FPTmpList()->set_bits(fp_tmp_list.bits());

  // Copies of the printf vararg registers that we can pop from.
  CPURegList pcs_varargs = kPCSVarargs;
#ifndef V8_OS_WIN
  CPURegList pcs_varargs_fp = kPCSVarargsFP;
#endif
### 提示词
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::CheckPageFlag(const Register& object, int mask,
                                   Condition cc, Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  And(scratch, object, ~MemoryChunk::GetAlignmentMaskForAssembler());
  Ldr(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  if (cc == ne) {
    TestAndBranchIfAnySet(scratch, mask, condition_met);
  } else {
    DCHECK_EQ(cc, eq);
    TestAndBranchIfAllClear(scratch, mask, condition_met);
  }
}

void MacroAssembler::JumpIfMarking(Label* is_marking,
                                   Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbnz(scratch, is_marking);
}

void MacroAssembler::JumpIfNotMarking(Label* not_marking,
                                      Label::Distance condition_met_distance) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldrb(scratch,
       MemOperand(kRootRegister, IsolateData::is_marking_flag_offset()));
  Cbz(scratch, not_marking);
}

void MacroAssembler::RecordWriteField(
    Register object, int offset, Register value, LinkRegisterStatus lr_status,
    SaveFPRegsMode save_fp, SmiCheck smi_check, ReadOnlyCheck ro_check,
    SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, value));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis and read-only objects.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  // Skip the barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kTaggedSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    Label ok;
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();
    DCHECK(!AreAliased(object, value, scratch));
    Add(scratch, object, offset - kHeapObjectTag);
    Tst(scratch, kTaggedSize - 1);
    B(eq, &ok);
    Abort(AbortReason::kUnalignedCellInWriteBarrier);
    Bind(&ok);
  }

  RecordWrite(object, Operand(offset - kHeapObjectTag), value, lr_status,
              save_fp, SmiCheck::kOmit, ReadOnlyCheck::kOmit, slot);

  Bind(&done);
}

void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  Add(value, kPtrComprCageBaseRegister,
      Operand(value, LSR, kSandboxedPointerShift));
#else
  UNREACHABLE();
#endif
}

void MacroAssembler::LoadSandboxedPointerField(Register destination,
                                               MemOperand field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  Ldr(destination, field_operand);
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
  Register scratch = temps.AcquireX();
  Sub(scratch, value, kPtrComprCageBaseRegister);
  Mov(scratch, Operand(scratch, LSL, kSandboxedPointerShift));
  Str(scratch, dst_field_operand);
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
  Register external_table = temps.AcquireX();
  if (isolate_root == no_reg) {
    DCHECK(root_array_available_);
    isolate_root = kRootRegister;
  }
  Ldr(external_table,
      MemOperand(isolate_root,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset));
  Ldr(destination.W(), field_operand);
  Mov(destination, Operand(destination, LSR, kExternalPointerIndexShift));
  Ldr(destination, MemOperand(external_table, destination, LSL,
                              kExternalPointerTableEntrySizeLog2));
  // We need another scratch register for the 64-bit tag constant. Instead of
  // forcing the `And` to allocate a new temp register (which we may not have),
  // reuse the temp register that we used for the external pointer table base.
  Register tag_reg = external_table;
  Mov(tag_reg, Immediate(~tag));
  And(destination, destination, tag_reg);
#else
  Ldr(destination, field_operand);
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

  Register handle = temps.AcquireX();
  Ldr(handle.W(), field_operand);
  ResolveIndirectPointerHandle(destination, handle, tag);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::StoreIndirectPointerField(Register value,
                                               MemOperand dst_field_operand) {
#ifdef V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Ldr(scratch.W(),
      FieldMemOperand(value, ExposedTrustedObject::kSelfIndirectPointerOffset));
  Str(scratch.W(), dst_field_operand);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
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
    constexpr int kCodePointerHandleMarkerBit = 0;
    static_assert((1 << kCodePointerHandleMarkerBit) ==
                  kCodePointerHandleMarker);
    Tbz(handle, kCodePointerHandleMarkerBit, &is_trusted_pointer_handle);
    ResolveCodePointerHandle(destination, handle);
    B(&done);
    Bind(&is_trusted_pointer_handle);
    ResolveTrustedPointerHandle(destination, handle,
                                kUnknownIndirectPointerTag);
    Bind(&done);
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

  Register table = destination;
  DCHECK(root_array_available_);
  Ldr(table,
      MemOperand{kRootRegister, IsolateData::trusted_pointer_table_offset()});
  Mov(handle, Operand(handle, LSR, kTrustedPointerHandleShift));
  Ldr(destination,
      MemOperand(table, handle, LSL, kTrustedPointerTableEntrySizeLog2));
  // Untag the pointer and remove the marking bit in one operation.
  Register tag_reg = handle;
  Mov(tag_reg, Immediate(~(tag | kTrustedPointerTableMarkBit)));
  And(destination, destination, tag_reg);
}

void MacroAssembler::ResolveCodePointerHandle(Register destination,
                                              Register handle) {
  DCHECK(!AreAliased(handle, destination));

  Register table = destination;
  Mov(table, ExternalReference::code_pointer_table_address());
  Mov(handle, Operand(handle, LSR, kCodePointerHandleShift));
  Add(destination, table, Operand(handle, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination,
      MemOperand(destination,
                 Immediate(kCodePointerTableEntryCodeObjectOffset)));
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  Orr(destination, destination, Immediate(kHeapObjectTag));
}

void MacroAssembler::LoadCodeEntrypointViaCodePointer(Register destination,
                                                      MemOperand field_operand,
                                                      CodeEntrypointTag tag) {
  DCHECK_NE(tag, kInvalidEntrypointTag);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, ExternalReference::code_pointer_table_address());
  Ldr(destination.W(), field_operand);
  // TODO(saelo): can the offset computation be done more efficiently?
  Mov(destination, Operand(destination, LSR, kCodePointerHandleShift));
  Mov(destination, Operand(destination, LSL, kCodePointerTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, destination));
  if (tag != 0) {
    Mov(scratch, Immediate(tag));
    Eor(destination, destination, scratch);
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
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = destination;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, dispatch_handle, scratch));
  ASM_CODE_COMMENT(this);

  Register index = parameter_count;
  Mov(scratch, ExternalReference::js_dispatch_table_address());
  Mov(index, Operand(dispatch_handle, LSR, kJSDispatchHandleShift));
  Add(scratch, scratch, Operand(index, LSL, kJSDispatchTableEntrySizeLog2));
  Ldr(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Ldrh(parameter_count,
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
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PushCPURegList(regs);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  ASM_CODE_COMMENT(this);
  CPURegList regs(kXRegSizeInBits, registers);
  // If we were saving LR, we might need to sign it.
  DCHECK(!regs.IncludesAliasOf(lr));
  regs.Align();
  PopCPURegList(regs);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object, Operand offset,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  RegList registers = WriteBarrierDescriptor::ComputeSavedRegisters(object);
  MaybeSaveRegisters(registers);

  MoveObjectAndSlot(WriteBarrierDescriptor::ObjectRegister(),
                    WriteBarrierDescriptor::SlotAddressRegister(), object,
                    offset);

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
  Mov(IndirectPointerWriteBarrierDescriptor::IndirectPointerTagRegister(),
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
  ASM_CODE_COMMENT(this);
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
  DCHECK_IMPLIES(!offset.IsImmediate(), offset.reg() != object);

  // If the slot register does not overlap with the object register, we can
  // overwrite it.
  if (dst_slot != object) {
    Add(dst_slot, object, offset);
    Mov(dst_object, object);
    return;
  }

  DCHECK_EQ(dst_slot, object);

  // If the destination object register does not overlap with the offset
  // register, we can overwrite it.
  if (offset.IsImmediate() || (offset.reg() != dst_object)) {
    Mov(dst_object, dst_slot);
    Add(dst_slot, dst_slot, offset);
    return;
  }

  DCHECK_EQ(dst_object, offset.reg());

  // We only have `dst_slot` and `dst_object` left as distinct registers so we
  // have to swap them. We write this as a add+sub sequence to avoid using a
  // scratch register.
  Add(dst_slot, dst_slot, dst_object);
  Sub(dst_object, dst_slot, dst_object);
}

// If lr_status is kLRHasBeenSaved, lr will be clobbered.
//
// The register 'object' contains a heap object pointer. The heap object tag is
// shifted away.
void MacroAssembler::RecordWrite(Register object, Operand offset,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check,
                                 ReadOnlyCheck ro_check, SlotDescriptor slot) {
  ASM_CODE_COMMENT(this);
  ASM_LOCATION_IN_ASSEMBLER("MacroAssembler::RecordWrite");
  DCHECK(!AreAliased(object, value));

  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT_STRING(this, "Verify slot_address");
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    DCHECK(!AreAliased(object, value, temp));
    Add(temp, object, offset);
    if (slot.contains_indirect_pointer()) {
      LoadIndirectPointerField(temp, MemOperand(temp),
                               slot.indirect_pointer_tag());
    } else {
      DCHECK(slot.contains_direct_pointer());
      LoadTaggedField(temp, MemOperand(temp));
    }
    Cmp(temp, value);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smisand read-only objects, as well as stores into the
  // young generation.
  Label done;

#if V8_STATIC_ROOTS_BOOL
  if (ro_check == ReadOnlyCheck::kInline) {
    // Quick check for Read-only and small Smi values.
    static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
    JumpIfUnsignedLessThan(value, kRegularPageSize, &done);
  }
#endif  // V8_STATIC_ROOTS_BOOL

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  if (slot.contains_indirect_pointer()) {
    // The indirect pointer write barrier is only enabled during marking.
    JumpIfNotMarking(&done);
  } else {
    CheckPageFlag(value, MemoryChunk::kPointersToHereAreInterestingMask, eq,
                  &done);

    CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask, eq,
                  &done);
  }

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    Push<MacroAssembler::kSignLR>(padreg, lr);
  }
  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  if (slot.contains_direct_pointer()) {
    // TODO(cbruni): Turn offset into int.
    DCHECK(offset.IsImmediate());
    Add(slot_address, object, offset);
    CallRecordWriteStub(object, slot_address, fp_mode,
                        StubCallMode::kCallBuiltinPointer);
  } else {
    DCHECK(slot.contains_indirect_pointer());
    CallIndirectPointerBarrier(object, offset, fp_mode,
                               slot.indirect_pointer_tag());
  }
  if (lr_status == kLRHasNotBeenSaved) {
    Pop<MacroAssembler::kAuthLR>(lr, padreg);
  }
  if (v8_flags.debug_code) Mov(slot_address, Operand(kZapValue));

  Bind(&done);
}

void MacroAssembler::Check(Condition cond, AbortReason reason) {
  Label ok;
  B(cond, &ok);
  Abort(reason);
  // Will not return here.
  Bind(&ok);
}

void MacroAssembler::SbxCheck(Condition cc, AbortReason reason) {
  Check(cc, reason);
}

void MacroAssembler::Trap() { Brk(0); }
void MacroAssembler::DebugBreak() { Debug("DebugBreak", 0, BREAK); }

void MacroAssembler::Abort(AbortReason reason) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.code_comments) {
    RecordComment("Abort message: ");
    RecordComment(GetAbortReason(reason));
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    Brk(0);
    return;
  }

  // We need some scratch registers for the MacroAssembler, so make sure we have
  // some. This is safe here because Abort never returns.
  uint64_t old_tmp_list = TmpList()->bits();
  TmpList()->Combine(MacroAssembler::DefaultTmpList());

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    Mov(w0, static_cast<int>(reason));
    Call(ExternalReference::abort_with_reason());
    return;
  }

  // Avoid infinite recursion; Push contains some assertions that use Abort.
  HardAbortScope hard_aborts(this);

  Mov(x1, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.AcquireX();
      LoadEntryFromBuiltin(Builtin::kAbort, scratch);
      Call(scratch);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }

  TmpList()->set_bits(old_tmp_list);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    UseScratchRegisterScope temps(this);

    // The entry references a CodeWrapper object. Unwrap it now.
    LoadCodePointerField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    Register temp = temps.AcquireX();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      B(&fallthrough);
    } else {
      B(on_result);
    }
  }

  bind(&clear_slot);
  Mov(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  Mov(scratch_and_result, 0);
}

// This is the main Printf implementation. All other Printf variants call
// PrintfNoPreserve after setting up one or more PreserveRegisterScopes.
void MacroAssembler::PrintfNoPreserve(const char* format,
                                      const CPURegister& arg0,
                                      const CPURegister& arg1,
                                      const CPURegister& arg2,
                                      const CPURegister& arg3) {
  ASM_CODE_COMMENT(this);
  // We cannot handle a caller-saved stack pointer. It doesn't make much sense
  // in most cases anyway, so this restriction shouldn't be too serious.
  DCHECK(!kCallerSaved.IncludesAliasOf(sp));

  // The provided arguments, and their proper procedure-call standard registers.
  CPURegister args[kPrintfMaxArgCount] = {arg0, arg1, arg2, arg3};
  CPURegister pcs[kPrintfMaxArgCount] = {NoReg, NoReg, NoReg, NoReg};

  int arg_count = kPrintfMaxArgCount;

  // The PCS varargs registers for printf. Note that x0 is used for the printf
  // format string.
  static const CPURegList kPCSVarargs =
      CPURegList(CPURegister::kRegister, kXRegSizeInBits, 1, arg_count);
  static const CPURegList kPCSVarargsFP =
      CPURegList(CPURegister::kVRegister, kDRegSizeInBits, 0, arg_count - 1);

  // We can use caller-saved registers as scratch values, except for the
  // arguments and the PCS registers where they might need to go.
  CPURegList tmp_list = kCallerSaved;
  tmp_list.Remove(x0);  // Used to pass the format string.
  tmp_list.Remove(kPCSVarargs);
  tmp_list.Remove(arg0, arg1, arg2, arg3);

  CPURegList fp_tmp_list = kCallerSavedV;
  fp_tmp_list.Remove(kPCSVarargsFP);
  fp_tmp_list.Remove(arg0, arg1, arg2, arg3);

  // Override the MacroAssembler's scratch register list. The lists will be
  // reset automatically at the end of the UseScratchRegisterScope.
  UseScratchRegisterScope temps(this);
  TmpList()->set_bits(tmp_list.bits());
  FPTmpList()->set_bits(fp_tmp_list.bits());

  // Copies of the printf vararg registers that we can pop from.
  CPURegList pcs_varargs = kPCSVarargs;
#ifndef V8_OS_WIN
  CPURegList pcs_varargs_fp = kPCSVarargsFP;
#endif

  // Place the arguments. There are lots of clever tricks and optimizations we
  // could use here, but Printf is a debug tool so instead we just try to keep
  // it simple: Move each input that isn't already in the right place to a
  // scratch register, then move everything back.
  for (unsigned i = 0; i < kPrintfMaxArgCount; i++) {
    // Work out the proper PCS register for this argument.
    if (args[i].IsRegister()) {
      pcs[i] = pcs_varargs.PopLowestIndex().X();
      // We might only need a W register here. We need to know the size of the
      // argument so we can properly encode it for the simulator call.
      if (args[i].Is32Bits()) pcs[i] = pcs[i].W();
    } else if (args[i].IsVRegister()) {
      // In C, floats are always cast to doubles for varargs calls.
#ifdef V8_OS_WIN
      // In case of variadic functions SIMD and Floating-point registers
      // aren't used. The general x0-x7 should be used instead.
      // https://docs.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions
      pcs[i] = pcs_varargs.PopLowestIndex().X();
#else
      pcs[i] = pcs_varargs_fp.PopLowestIndex().D();
#endif
    } else {
      DCHECK(args[i].IsNone());
      arg_count = i;
      break;
    }

    // If the argument is already in the right place, leave it where it is.
    if (args[i].Aliases(pcs[i])) continue;

    // Otherwise, if the argument is in a PCS argument register, allocate an
    // appropriate scratch register and then move it out of the way.
    if (kPCSVarargs.IncludesAliasOf(args[i]) ||
        kPCSVarargsFP.IncludesAliasOf(args[i])) {
      if (args[i].IsRegister()) {
        Register old_arg = args[i].Reg();
        Register new_arg = temps.AcquireSameSizeAs(old_arg);
        Mov(new_arg, old_arg);
        args[i] = new_arg;
      } else {
        VRegister old_arg = args[i].VReg();
        VRegister new_arg = temps.AcquireSameSizeAs(old_arg);
        Fmov(new_arg, old_arg);
        args[i] = new_arg;
      }
    }
  }

  // Do a second pass to move values into their final positions and perform any
  // conversions that may be required.
  for (int i = 0; i < arg_count; i++) {
#ifdef V8_OS_WIN
    if (args[i].IsVRegister()) {
      if (pcs[i].SizeInBytes() != args[i].SizeInBytes()) {
        // If the argument is half- or single-precision
        // converts to double-precision before that is
        // moved into the one of X scratch register.
        VRegister temp0 = temps.AcquireD();
        Fcvt(temp0.VReg(), args[i].VReg());
        Fmov(pcs[i].Reg(), temp0);
      } else {
        Fmov(pcs[i].Reg(), args[i].VReg());
      }
    } else {
      Mov(pcs[i].Reg(), args[i].Reg(), kDiscardForSameWReg);
    }
#else
    DCHECK(pcs[i].type() == args[i].type());
    if (pcs[i].IsRegister()) {
      Mov(pcs[i].Reg(), args[i].Reg(), kDiscardForSameWReg);
    } else {
      DCHECK(pcs[i].IsVRegister());
      if (pcs[i].SizeInBytes() == args[i].SizeInBytes()) {
        Fmov(pcs[i].VReg(), args[i].VReg());
      } else {
        Fcvt(pcs[i].VReg(), args[i].VReg());
      }
    }
#endif
  }

  // Load the format string into x0, as per the procedure-call standard.
  //
  // To make the code as portable as possible, the format string is encoded
  // directly in the instruction stream. It might be cleaner to encode it in a
  // literal pool, but since Printf is usually used for debugging, it is
  // beneficial for it to be minimally dependent on other features.
  Label format_address;
  Adr(x0, &format_address);

  // Emit the format string directly in the instruction stream.
  {
    BlockPoolsScope scope(this);
    Label after_data;
    B(&after_data);
    Bind(&format_address);
    EmitStringData(format);
    Unreachable();
    Bind(&after_data);
  }

  CallPrintf(arg_count, pcs);
}

void MacroAssembler::CallPrintf(int arg_count, const CPURegister* args) {
  ASM_CODE_COMMENT(this);
  // A call to printf needs special handling for the simulator, since the system
  // printf function will use a different instruction set and the procedure-call
  // standard will not be compatible.
  if (options().enable_simulator_code) {
    InstructionAccurateScope scope(this, kPrintfLength / kInstrSize);
    hlt(kImmExceptionIsPrintf);
    dc32(arg_count);  // kPrintfArgCountOffset

    // Determine the argument pattern.
    uint32_t arg_pattern_list = 0;
    for (int i = 0; i < arg_count; i++) {
      uint32_t arg_pattern;
      if (args[i].IsRegister()) {
        arg_pattern = args[i].Is32Bits() ? kPrintfArgW : kPrintfArgX;
      } else {
        DCHECK(args[i].Is64Bits());
        arg_pattern = kPrintfArgD;
      }
      DCHECK(arg_pattern < (1 << kPrintfArgPatternBits));
      arg_pattern_list |= (arg_pattern << (kPrintfArgPatternBits * i));
    }
    dc32(arg_pattern_list);  // kPrintfArgPatternListOffset
    return;
  }

  Call(ExternalReference::printf_function());
}

void MacroAssembler::Printf(const char* format, CPURegister arg0,
                            CPURegister arg1, CPURegister arg2,
                            CPURegister arg3) {
  ASM_CODE_COMMENT(this);
  // Printf is expected to preserve all registers, so make sure that none are
  // available as scratch registers until we've preserved them.
  uint64_t old_tmp_list = TmpList()->bits();
  uint64_t old_fp_tmp_list = FPTmpList()->bits();
  TmpList()->set_bits(0);
  FPTmpList()->set_bits(0);

  CPURegList saved_registers = kCallerSaved;
  saved_registers.Align();

  // Preserve all caller-saved registers as well as NZCV.
  // PushCPURegList asserts that the size of each list is a multiple of 16
  // bytes.
  PushCPURegList(saved_registers);
  PushCPURegList(kCallerSavedV);

  // We can use caller-saved registers as scratch values (except for argN).
  CPURegList tmp_list = saved_registers;
  CPURegList fp_tmp_list = kCallerSavedV;
  tmp_list.Remove(arg0, arg1, arg2, arg3);
  fp_tmp_list.Remove(arg0, arg1, arg2, arg3);
  TmpList()->set_bits(tmp_list.bits());
  FPTmpList()->set_bits(fp_tmp_list.bits());

  {
    UseScratchRegisterScope temps(this);
    // If any of the arguments are the current stack pointer, allocate a new
    // register for them, and adjust the value to compensate f
```