Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the file:** The filename suggests it's a macro assembler for the s390 architecture within V8's code generation. Macro assemblers provide higher-level abstractions over raw assembly instructions.

2. **Scan for keywords and common patterns:** Look for words like `Load`, `Store`, `Call`, `Push`, `Pop`, `Jump`, `Convert`, `Frame`, and specific V8 concepts like `RecordWrite`, `Smi`, `HeapObject`, `Builtins`, etc. These indicate common operations within a code generator.

3. **Group related functions:**  Notice patterns in the function names and their arguments. For example, several functions deal with stack frame manipulation (`PushCommonFrame`, `PopCommonFrame`, `PushStandardFrame`, `EnterFrame`, `LeaveFrame`). Others focus on memory operations (`LoadTaggedField`, `StoreTaggedField`). Some are related to floating-point conversions.

4. **Infer high-level functionalities from the grouped functions:**  Stack frame manipulation suggests function calls and returns. Memory operations indicate accessing and modifying data in the heap. Floating-point conversions point to handling numbers.

5. **Focus on the unique and important functions:**  `RecordWrite` and related functions are crucial for V8's garbage collection. Functions involving `Builtins` indicate calls to pre-compiled V8 code.

6. **Address specific instructions from the prompt:**
    * **`.tq` extension:** Explicitly check if the filename ends with `.tq`. In this case, it doesn't.
    * **Javascript relation:**  Connect the low-level operations to higher-level Javascript concepts. For instance, `RecordWrite` is essential for maintaining the integrity of the heap during object updates, which directly relates to how Javascript objects are managed.
    * **Example with Javascript:**  Provide a simple Javascript example that would trigger the kind of low-level operations seen in the C++ code. Object property assignment is a good candidate.
    * **Code logic inference:** Choose a relatively simple function with clear inputs and outputs, like `MaybeSaveRegisters`.
    * **Common programming errors:** Think about errors related to memory management or function calls that these low-level functions might help prevent or handle.

7. **Synthesize the findings into a concise summary:** Combine the identified functionalities into a clear description of what the code does.

8. **Review and refine:** Ensure the summary accurately reflects the code and addresses all parts of the user's prompt. For this "part 2 of 8" instruction, emphasize that this is a portion of a larger system.
```cpp
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kSystemPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  lay(slot_address, MemOperand(object, offset - kHeapObjectTag));
  if (v8_flags.debug_code) {
    Label ok;
    AndP(r0, slot_address, Operand(kTaggedSize - 1));
    beq(&ok, Label::kNear);
    stop();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, lr_status, save_fp, SmiCheck::kOmit);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 4)));
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 8)));
  }
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

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

// Will clobber 4 registers: object, address, scratch, ip. The
// register 'object' contains a heap object pointer. The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, slot_address, value));
  if (v8_flags.debug_code) {
    LoadTaggedField(r0, MemOperand(slot_address));
    CmpS64(value, r0);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }
  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    push(r14);
  }
  CallRecordWriteStubSaveRegisters(object, slot_address, fp_mode);
  if (lr_status == kLRHasNotBeenSaved) {
    pop(r14);
  }

  if (v8_flags.debug_code) mov(slot_address, Operand(kZapValue));

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 12)));
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 16)));
  }
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  ASM_CODE_COMMENT(this);
  int fp_delta = 0;
  if (marker_reg.is_valid()) {
    Push(r14, fp, marker_reg);
    fp_delta = 1;
  } else {
    Push(r14, fp);
    fp_delta = 0;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
}

void MacroAssembler::PopCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Pop(r14, fp, marker_reg);
  } else {
    Pop(r14, fp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int fp_delta = 0;
  if (function_reg.is_valid()) {
    Push(r14, fp, cp, function_reg);
    fp_delta = 2;
  } else {
    Push(r14, fp, cp);
    fp_delta = 1;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::RestoreFrameStateForTailCall() {
  // if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
  //   LoadU64(kConstantPoolRegister,
  //         MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
  //   set_constant_pool_available(false);
  // }
  DCHECK(!V8_EMBEDDED_CONSTANT_POOL_BOOL);
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
}

void MacroAssembler::CanonicalizeNaN(const DoubleRegister dst,
                                     const DoubleRegister src) {
  // Turn potential sNaN into qNaN
  if (dst != src) ldr(dst, src);
  lzdr(kDoubleRegZero);
  sdbr(dst, kDoubleRegZero);
}

void MacroAssembler::ConvertIntToDouble(DoubleRegister dst, Register src) {
  cdfbr(dst, src);
}

void MacroAssembler::ConvertUnsignedIntToDouble(DoubleRegister dst,
                                                Register src) {
  if (CpuFeatures::IsSupported(FLOATING_POINT_EXT)) {
    cdlfbr(Condition(5), Condition(0), dst, src);
  } else {
    // zero-extend src
    llgfr(src, src);
    // convert to double
    cdgbr(dst, src);
  }
}

void MacroAssembler::ConvertIntToFloat(DoubleRegister dst, Register src) {
  cefbra(Condition(4), dst, src);
}

void MacroAssembler::ConvertUnsignedIntToFloat(DoubleRegister dst,
                                               Register src) {
  celfbr(Condition(4), Condition(0), dst, src);
}

void MacroAssembler::ConvertInt64ToFloat(DoubleRegister double_dst,
                                         Register src) {
  cegbr(double_dst, src);
}

void MacroAssembler::ConvertInt64ToDouble(DoubleRegister double_dst,
                                          Register src) {
  cdgbr(double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToFloat(DoubleRegister double_dst,
                                                 Register src) {
  celgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToDouble(DoubleRegister double_dst,
                                                  Register src) {
  cdlgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertFloat32ToInt64(const Register dst,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgebr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt64(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgdbr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt32(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  cfdbr(m, dst, double_input);
}

void MacroAssembler::ConvertFloat32ToInt32(const Register result,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  cfebr(m, result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt32(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  clfebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt64(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt64(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt32(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  clfdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::MovDoubleToInt64(Register dst, DoubleRegister src) {
  lgdr(dst, src);
}

void MacroAssembler::MovInt64ToDouble(DoubleRegister dst, Register src) {
  ldgr(dst, src);
}

void MacroAssembler::StubPrologue(StackFrame::Type type, Register base,
                                  int prologue_offset) {
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(this);
    mov(r1, Operand(StackFrame::TypeToMarker(type)));
    PushCommonFrame(r1);
  }
}

void MacroAssembler::Prologue(Register base, int prologue_offset) {
  DCHECK(base != no_reg);
  PushStandardFrame(r3);
}

void MacroAssembler::DropArguments(Register count) {
  ShiftLeftU64(ip, count, Operand(kSystemPointerSizeLog2));
  lay(sp, MemOperand(sp, ip));
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  ASM_CODE_COMMENT(this);
  // We create a stack frame with:
  //    Return Addr <-- old sp
  //    Old FP      <-- new fp
  //    CP
  //    type
  //    CodeObject  <-- new sp

  Register scratch = no_reg;
  if (!StackFrame::IsJavaScript(type)) {
    scratch = ip;
    mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  }
  PushCommonFrame(scratch);
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type, int stack_adjustment) {
  ASM_CODE_COMMENT(this);
  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer, return address and constant pool pointer.
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  if (is_int20(StandardFrameConstants::kCallerSPOffset + stack_adjustment)) {
    lay(r1, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                               stack_adjustment));
  } else {
    AddS64(r1, fp,
           Operand(StandardFrameConstants::kCallerSPOffset + stack_adjustment));
  }
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  mov(sp, r1);
  int frame_ends = pc_offset();
  return frame_ends;
}

// ExitFrame layout (probably wrongish.. needs updating)
//
//  SP -> previousSP
//        LK reserved
//        sp_on_exit (for debug?)
// oldSP->prev SP
//        LK
//        <parameters on stack>

// Prior to calling EnterExitFrame, we've got a bunch of parameters
// on the stack that we need to wrap a real frame around.. so first
// we reserve a slot for LK and push the previous SP which is captured
// in the fp register (r11)
// Then - we buy a new frame

// r14
// oldFP <- newFP
// SP
// Floats
// gaps
// Args
// ABIRes <- newSP
void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);

  using ER = ExternalReference;

  // This is an opportunity to build a frame to wrap
  // all of the pushes that have happened inside of V8
  // since we were called from C code
  mov(r1, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(r1);
  // Reserve room for saved entry sp.
  lay(sp, MemOperand(fp, -ExitFrameConstants::kFixedFrameSizeFromFp));

  if (v8_flags.debug_code) {
    StoreU64(MemOperand(fp, ExitFrameConstants::kSPOffset), Operand::Zero(),
             r1);
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreU64(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

  lay(sp, MemOperand(sp, -(stack_space + 1) * kSystemPointerSize));

  // Allocate and align the frame preparing for calling the runtime
  // function.
  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  if (frame_alignment > 0) {
    DCHECK_EQ(frame_alignment, 8);
    ClearRightImm(sp, sp, Operand(3));  // equivalent to &= -8
  }

  lay(sp, MemOperand(sp, -kNumRequiredStackFrameSlots * kSystemPointerSize));
  StoreU64(MemOperand(sp), Operand::Zero(), r0);
  // Set the exit frame sp value to point just before the return address
  // location.
  lay(r1, MemOperand(sp, kStackFrameSPSlot * kSystemPointerSize));
  StoreU64(r1, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if !defined(USE_SIMULATOR)
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one S390
  // platform for another S390 platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else  // Simulated
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  StoreU64(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  StoreU64(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  LeaveFrame(StackFrame::EXIT);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, d0);
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, d0);
}

MemOperand MacroAssembler::StackLimitAsMemOperand(StackLimitKind kind) {
  DCHECK(root_array_available());
  Isolate* isolate = this->isolate();
  ExternalReference limit =
      kind == StackLimitKind::kRealStackLimit
          ? ExternalReference::address_of_real_jslimit(isolate)
          : ExternalReference::address_of_jslimit(isolate);
  DCHECK(MacroAssembler::IsAddressableThroughRootRegister(isolate, limit));

  intptr_t offset =
      MacroAssembler::RootRegisterOffsetForExternalReference(isolate, limit);
  CHECK(is_int32(offset));
  return MemOperand(kRootRegister, offset);
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadU64(scratch, StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  SubS64(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  ShiftLeftU64(r0, num_args, Operand(kSystemPointerSizeLog2));
  CmpS64(scratch, r0);
  ble(stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  r2: actual arguments count
  //  r3: function (passed through to callee)
  //  r4: expected arguments count

  DCHECK_EQ(actual_parameter_count, r2);
  DCHECK_EQ(expected_parameter_count, r4);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  SubS64(expected_parameter_count, expected_parameter_count,
         actual_parameter_count);
  ble(&regular_invoke);

  Label stack_overflow;
  Register scratch = r6;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register num = r7, src = r8, dest = ip;  // r7 and r8 are context and root.
    mov(src, sp);
    // Update stack pointer.
    ShiftLeftU64(scratch, expected_parameter_count,
                 Operand(kSystemPointerSizeLog2));
    SubS64(sp, sp, scratch);
    mov(dest, sp);
    ltgr(num, actual_parameter_count);
    b(&check);
    bind(&copy);
    LoadU64(r0, MemOperand(src));
    lay(src, MemOperand(src, kSystemPointerSize));
    StoreU64(r0, MemOperand(dest));
    lay(dest, MemOperand(dest, kSystemPointerSize));
    SubS64(num, num, Operand(1));
    bind(&check);
    b(gt, &copy);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    StoreU64(scratch, MemOperand(ip));
    lay(ip, MemOperand(ip, kSystemPointerSize));
    SubS64(expected_parameter_count, expected_parameter_count, Operand(1));
    bgt(&loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  ExternalReference debug_hook_active =
      ExternalReference::debug_hook_on_function_call_address(isolate());
  Move(r6, debug_hook_active);
  tm(MemOperand(r6), Operand(0xFF));
  beq(&skip_hook);

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(r6);
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun, fun, r6);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r3);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r5);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r5, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
tion, field_operand);
  } else {
    LoadU64(destination, field_operand);
  }
}

void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register slot_address,
                                      LinkRegisterStatus lr_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so so offset must be a multiple of kSystemPointerSize.
  DCHECK(IsAligned(offset, kTaggedSize));

  lay(slot_address, MemOperand(object, offset - kHeapObjectTag));
  if (v8_flags.debug_code) {
    Label ok;
    AndP(r0, slot_address, Operand(kTaggedSize - 1));
    beq(&ok, Label::kNear);
    stop();
    bind(&ok);
  }

  RecordWrite(object, slot_address, value, lr_status, save_fp, SmiCheck::kOmit);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 4)));
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 8)));
  }
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

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

// Will clobber 4 registers: object, address, scratch, ip.  The
// register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register slot_address,
                                 Register value, LinkRegisterStatus lr_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, slot_address, value));
  if (v8_flags.debug_code) {
    LoadTaggedField(r0, MemOperand(slot_address));
    CmpS64(value, r0);
    Check(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite);
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }
  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (lr_status == kLRHasNotBeenSaved) {
    push(r14);
  }
  CallRecordWriteStubSaveRegisters(object, slot_address, fp_mode);
  if (lr_status == kLRHasNotBeenSaved) {
    pop(r14);
  }

  if (v8_flags.debug_code) mov(slot_address, Operand(kZapValue));

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    mov(slot_address, Operand(base::bit_cast<intptr_t>(kZapValue + 12)));
    mov(value, Operand(base::bit_cast<intptr_t>(kZapValue + 16)));
  }
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  ASM_CODE_COMMENT(this);
  int fp_delta = 0;
  if (marker_reg.is_valid()) {
    Push(r14, fp, marker_reg);
    fp_delta = 1;
  } else {
    Push(r14, fp);
    fp_delta = 0;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
}

void MacroAssembler::PopCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Pop(r14, fp, marker_reg);
  } else {
    Pop(r14, fp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int fp_delta = 0;
  if (function_reg.is_valid()) {
    Push(r14, fp, cp, function_reg);
    fp_delta = 2;
  } else {
    Push(r14, fp, cp);
    fp_delta = 1;
  }
  la(fp, MemOperand(sp, fp_delta * kSystemPointerSize));
  Push(kJavaScriptCallArgCountRegister);
}

void MacroAssembler::RestoreFrameStateForTailCall() {
  // if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
  //   LoadU64(kConstantPoolRegister,
  //         MemOperand(fp, StandardFrameConstants::kConstantPoolOffset));
  //   set_constant_pool_available(false);
  // }
  DCHECK(!V8_EMBEDDED_CONSTANT_POOL_BOOL);
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
}

void MacroAssembler::CanonicalizeNaN(const DoubleRegister dst,
                                     const DoubleRegister src) {
  // Turn potential sNaN into qNaN
  if (dst != src) ldr(dst, src);
  lzdr(kDoubleRegZero);
  sdbr(dst, kDoubleRegZero);
}

void MacroAssembler::ConvertIntToDouble(DoubleRegister dst, Register src) {
  cdfbr(dst, src);
}

void MacroAssembler::ConvertUnsignedIntToDouble(DoubleRegister dst,
                                                Register src) {
  if (CpuFeatures::IsSupported(FLOATING_POINT_EXT)) {
    cdlfbr(Condition(5), Condition(0), dst, src);
  } else {
    // zero-extend src
    llgfr(src, src);
    // convert to double
    cdgbr(dst, src);
  }
}

void MacroAssembler::ConvertIntToFloat(DoubleRegister dst, Register src) {
  cefbra(Condition(4), dst, src);
}

void MacroAssembler::ConvertUnsignedIntToFloat(DoubleRegister dst,
                                               Register src) {
  celfbr(Condition(4), Condition(0), dst, src);
}

void MacroAssembler::ConvertInt64ToFloat(DoubleRegister double_dst,
                                         Register src) {
  cegbr(double_dst, src);
}

void MacroAssembler::ConvertInt64ToDouble(DoubleRegister double_dst,
                                          Register src) {
  cdgbr(double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToFloat(DoubleRegister double_dst,
                                                 Register src) {
  celgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertUnsignedInt64ToDouble(DoubleRegister double_dst,
                                                  Register src) {
  cdlgbr(Condition(0), Condition(0), double_dst, src);
}

void MacroAssembler::ConvertFloat32ToInt64(const Register dst,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgebr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt64(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  cgdbr(m, dst, double_input);
}

void MacroAssembler::ConvertDoubleToInt32(const Register dst,
                                          const DoubleRegister double_input,
                                          FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  cfdbr(m, dst, double_input);
}

void MacroAssembler::ConvertFloat32ToInt32(const Register result,
                                           const DoubleRegister double_input,
                                           FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      m = Condition(4);
      break;
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  cfebr(m, result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt32(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(result, Operand::Zero());
  clfebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertFloat32ToUnsignedInt64(
    const Register result, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgebr(m, Condition(0), result, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt64(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  clgdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::ConvertDoubleToUnsignedInt32(
    const Register dst, const DoubleRegister double_input,
    FPRoundingMode rounding_mode) {
  Condition m = Condition(0);
  switch (rounding_mode) {
    case kRoundToZero:
      m = Condition(5);
      break;
    case kRoundToNearest:
      UNIMPLEMENTED();
    case kRoundToPlusInf:
      m = Condition(6);
      break;
    case kRoundToMinusInf:
      m = Condition(7);
      break;
    default:
      UNIMPLEMENTED();
  }
  lghi(dst, Operand::Zero());
  clfdbr(m, Condition(0), dst, double_input);
}

void MacroAssembler::MovDoubleToInt64(Register dst, DoubleRegister src) {
  lgdr(dst, src);
}

void MacroAssembler::MovInt64ToDouble(DoubleRegister dst, Register src) {
  ldgr(dst, src);
}

void MacroAssembler::StubPrologue(StackFrame::Type type, Register base,
                                  int prologue_offset) {
  {
    ConstantPoolUnavailableScope constant_pool_unavailable(this);
    mov(r1, Operand(StackFrame::TypeToMarker(type)));
    PushCommonFrame(r1);
  }
}

void MacroAssembler::Prologue(Register base, int prologue_offset) {
  DCHECK(base != no_reg);
  PushStandardFrame(r3);
}

void MacroAssembler::DropArguments(Register count) {
  ShiftLeftU64(ip, count, Operand(kSystemPointerSizeLog2));
  lay(sp, MemOperand(sp, ip));
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

void MacroAssembler::EnterFrame(StackFrame::Type type,
                                bool load_constant_pool_pointer_reg) {
  ASM_CODE_COMMENT(this);
  // We create a stack frame with:
  //    Return Addr <-- old sp
  //    Old FP      <-- new fp
  //    CP
  //    type
  //    CodeObject  <-- new sp

  Register scratch = no_reg;
  if (!StackFrame::IsJavaScript(type)) {
    scratch = ip;
    mov(scratch, Operand(StackFrame::TypeToMarker(type)));
  }
  PushCommonFrame(scratch);
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM) Push(kWasmImplicitArgRegister);
#endif  // V8_ENABLE_WEBASSEMBLY
}

int MacroAssembler::LeaveFrame(StackFrame::Type type, int stack_adjustment) {
  ASM_CODE_COMMENT(this);
  // Drop the execution stack down to the frame pointer and restore
  // the caller frame pointer, return address and constant pool pointer.
  LoadU64(r14, MemOperand(fp, StandardFrameConstants::kCallerPCOffset));
  if (is_int20(StandardFrameConstants::kCallerSPOffset + stack_adjustment)) {
    lay(r1, MemOperand(fp, StandardFrameConstants::kCallerSPOffset +
                               stack_adjustment));
  } else {
    AddS64(r1, fp,
           Operand(StandardFrameConstants::kCallerSPOffset + stack_adjustment));
  }
  LoadU64(fp, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
  mov(sp, r1);
  int frame_ends = pc_offset();
  return frame_ends;
}

// ExitFrame layout (probably wrongish.. needs updating)
//
//  SP -> previousSP
//        LK reserved
//        sp_on_exit (for debug?)
// oldSP->prev SP
//        LK
//        <parameters on stack>

// Prior to calling EnterExitFrame, we've got a bunch of parameters
// on the stack that we need to wrap a real frame around.. so first
// we reserve a slot for LK and push the previous SP which is captured
// in the fp register (r11)
// Then - we buy a new frame

// r14
// oldFP <- newFP
// SP
// Floats
// gaps
// Args
// ABIRes <- newSP
void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the frame structure on the stack.
  DCHECK_EQ(2 * kSystemPointerSize, ExitFrameConstants::kCallerSPDisplacement);
  DCHECK_EQ(1 * kSystemPointerSize, ExitFrameConstants::kCallerPCOffset);
  DCHECK_EQ(0 * kSystemPointerSize, ExitFrameConstants::kCallerFPOffset);

  using ER = ExternalReference;

  // This is an opportunity to build a frame to wrap
  // all of the pushes that have happened inside of V8
  // since we were called from C code
  mov(r1, Operand(StackFrame::TypeToMarker(frame_type)));
  PushCommonFrame(r1);
  // Reserve room for saved entry sp.
  lay(sp, MemOperand(fp, -ExitFrameConstants::kFixedFrameSizeFromFp));

  if (v8_flags.debug_code) {
    StoreU64(MemOperand(fp, ExitFrameConstants::kSPOffset), Operand::Zero(),
             r1);
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreU64(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

  lay(sp, MemOperand(sp, -(stack_space + 1) * kSystemPointerSize));

  // Allocate and align the frame preparing for calling the runtime
  // function.
  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  if (frame_alignment > 0) {
    DCHECK_EQ(frame_alignment, 8);
    ClearRightImm(sp, sp, Operand(3));  // equivalent to &= -8
  }

  lay(sp, MemOperand(sp, -kNumRequiredStackFrameSlots * kSystemPointerSize));
  StoreU64(MemOperand(sp), Operand::Zero(), r0);
  // Set the exit frame sp value to point just before the return address
  // location.
  lay(r1, MemOperand(sp, kStackFrameSPSlot * kSystemPointerSize));
  StoreU64(r1, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

int MacroAssembler::ActivationFrameAlignment() {
#if !defined(USE_SIMULATOR)
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one S390
  // platform for another S390 platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else  // Simulated
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadU64(cp, ExternalReferenceAsOperand(context_address, no_reg));

#ifdef DEBUG
  mov(scratch, Operand(Context::kInvalidContext));
  StoreU64(scratch, ExternalReferenceAsOperand(context_address, no_reg));
#endif

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  mov(scratch, Operand::Zero());
  StoreU64(scratch, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Tear down the exit frame, pop the arguments, and return.
  LeaveFrame(StackFrame::EXIT);
}

void MacroAssembler::MovFromFloatResult(const DoubleRegister dst) {
  Move(dst, d0);
}

void MacroAssembler::MovFromFloatParameter(const DoubleRegister dst) {
  Move(dst, d0);
}

MemOperand MacroAssembler::StackLimitAsMemOperand(StackLimitKind kind) {
  DCHECK(root_array_available());
  Isolate* isolate = this->isolate();
  ExternalReference limit =
      kind == StackLimitKind::kRealStackLimit
          ? ExternalReference::address_of_real_jslimit(isolate)
          : ExternalReference::address_of_jslimit(isolate);
  DCHECK(MacroAssembler::IsAddressableThroughRootRegister(isolate, limit));

  intptr_t offset =
      MacroAssembler::RootRegisterOffsetForExternalReference(isolate, limit);
  CHECK(is_int32(offset));
  return MemOperand(kRootRegister, offset);
}

void MacroAssembler::StackOverflowCheck(Register num_args, Register scratch,
                                        Label* stack_overflow) {
  // Check the stack for overflow. We are not trying to catch
  // interruptions (e.g. debug break and preemption) here, so the "real stack
  // limit" is checked.
  LoadU64(scratch, StackLimitAsMemOperand(StackLimitKind::kRealStackLimit));
  // Make scratch the space we have left. The stack might already be overflowed
  // here which will cause scratch to become negative.
  SubS64(scratch, sp, scratch);
  // Check if the arguments will overflow the stack.
  ShiftLeftU64(r0, num_args, Operand(kSystemPointerSizeLog2));
  CmpS64(scratch, r0);
  ble(stack_overflow);  // Signed comparison.
}

void MacroAssembler::InvokePrologue(Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    Label* done, InvokeType type) {
  Label regular_invoke;

  //  r2: actual arguments count
  //  r3: function (passed through to callee)
  //  r4: expected arguments count

  DCHECK_EQ(actual_parameter_count, r2);
  DCHECK_EQ(expected_parameter_count, r4);

  // If overapplication or if the actual argument count is equal to the
  // formal parameter count, no need to push extra undefined values.
  SubS64(expected_parameter_count, expected_parameter_count,
         actual_parameter_count);
  ble(&regular_invoke);

  Label stack_overflow;
  Register scratch = r6;
  StackOverflowCheck(expected_parameter_count, scratch, &stack_overflow);

  // Underapplication. Move the arguments already in the stack, including the
  // receiver and the return address.
  {
    Label copy, check;
    Register num = r7, src = r8, dest = ip;  // r7 and r8 are context and root.
    mov(src, sp);
    // Update stack pointer.
    ShiftLeftU64(scratch, expected_parameter_count,
                 Operand(kSystemPointerSizeLog2));
    SubS64(sp, sp, scratch);
    mov(dest, sp);
    ltgr(num, actual_parameter_count);
    b(&check);
    bind(&copy);
    LoadU64(r0, MemOperand(src));
    lay(src, MemOperand(src, kSystemPointerSize));
    StoreU64(r0, MemOperand(dest));
    lay(dest, MemOperand(dest, kSystemPointerSize));
    SubS64(num, num, Operand(1));
    bind(&check);
    b(gt, &copy);
  }

  // Fill remaining expected arguments with undefined values.
  LoadRoot(scratch, RootIndex::kUndefinedValue);
  {
    Label loop;
    bind(&loop);
    StoreU64(scratch, MemOperand(ip));
    lay(ip, MemOperand(ip, kSystemPointerSize));
    SubS64(expected_parameter_count, expected_parameter_count, Operand(1));
    bgt(&loop);
  }
  b(&regular_invoke);

  bind(&stack_overflow);
  {
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);
    CallRuntime(Runtime::kThrowStackOverflow);
    bkpt(0);
  }

  bind(&regular_invoke);
}

void MacroAssembler::CheckDebugHook(Register fun, Register new_target,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count) {
  Label skip_hook;

  ExternalReference debug_hook_active =
      ExternalReference::debug_hook_on_function_call_address(isolate());
  Move(r6, debug_hook_active);
  tm(MemOperand(r6), Operand(0xFF));
  beq(&skip_hook);

  {
    // Load receiver to pass it later to DebugOnFunctionCall hook.
    LoadReceiver(r6);
    FrameScope frame(
        this, has_frame() ? StackFrame::NO_FRAME_TYPE : StackFrame::INTERNAL);

    SmiTag(expected_parameter_count);
    Push(expected_parameter_count);

    SmiTag(actual_parameter_count);
    Push(actual_parameter_count);

    if (new_target.is_valid()) {
      Push(new_target);
    }
    Push(fun, fun, r6);
    CallRuntime(Runtime::kDebugOnFunctionCall);
    Pop(fun);
    if (new_target.is_valid()) {
      Pop(new_target);
    }

    Pop(actual_parameter_count);
    SmiUntag(actual_parameter_count);

    Pop(expected_parameter_count);
    SmiUntag(expected_parameter_count);
  }
  bind(&skip_hook);
}

void MacroAssembler::InvokeFunctionCode(Register function, Register new_target,
                                        Register expected_parameter_count,
                                        Register actual_parameter_count,
                                        InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());
  DCHECK_EQ(function, r3);
  DCHECK_IMPLIES(new_target.is_valid(), new_target == r5);

  // On function call, call into the debugger if necessary.
  CheckDebugHook(function, new_target, expected_parameter_count,
                 actual_parameter_count);

  // Clear the new.target register if not given.
  if (!new_target.is_valid()) {
    LoadRoot(r5, RootIndex::kUndefinedValue);
  }

  Label done;
  InvokePrologue(expected_parameter_count, actual_parameter_count, &done, type);
  // We call indirectly through the code field in the function to
  // allow recompilation to take effect without changing any of the
  // call sites.
  constexpr int unused_argument_count = 0;
  switch (type) {
    case InvokeType::kCall:
      CallJSFunction(function, unused_argument_count);
      break;
    case InvokeType::kJump:
      JumpJSFunction(function);
      break;
  }
  // Continue here if InvokePrologue does handle the invocation due to
  // mismatched parameter counts.
  bind(&done);
}

void MacroAssembler::InvokeFunctionWithNewTarget(
    Register fun, Register new_target, Register actual_parameter_count,
    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r3.
  DCHECK_EQ(fun, r3);

  Register expected_reg = r4;
  Register temp_reg = r6;
  LoadTaggedField(cp, FieldMemOperand(fun, JSFunction::kContextOffset));
  LoadTaggedField(temp_reg,
                  FieldMemOperand(fun, JSFunction::kSharedFunctionInfoOffset));
  LoadU16(expected_reg,
          FieldMemOperand(temp_reg,
                          SharedFunctionInfo::kFormalParameterCountOffset));

  InvokeFunctionCode(fun, new_target, expected_reg, actual_parameter_count,
                     type);
}

void MacroAssembler::InvokeFunction(Register function,
                                    Register expected_parameter_count,
                                    Register actual_parameter_count,
                                    InvokeType type) {
  // You can't call a function without a valid frame.
  DCHECK_IMPLIES(type == InvokeType::kCall, has_frame());

  // Contract with called JS functions requires that function is passed in r3.
  DCHECK_EQ(function, r3);

  // Get the function and setup the context.
  LoadTaggedField(cp, FieldMemOperand(function, JSFunction::kContextOffset));

  InvokeFunctionCode(r3, no_reg, expected_parameter_count,
                     actual_parameter_count, type);
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0 * kSystemPointerSize);

  // Link the current handler as the next handler.
  Move(r7,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));

  // Buy the full stack frame for 5 slots.
  lay(sp, MemOperand(sp, -StackHandlerConstants::kSize));

  // Store padding.
  lghi(r0, Operand::Zero());
  StoreU64(r0, MemOperand(sp));  // Padding.

  // Copy the old handler into the next handler slot.
  MoveChar(MemOperand(sp, StackHandlerConstants::kNextOffset), MemOperand(r7),
           Operand(kSystemPointerSize));
  // Set this new handler as the current one.
  StoreU64(sp, MemOperand(r7));
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  // Pop the Next Handler into r3 and store it into Handler Address reference.
  Pop(r3);
  Move(ip,
       ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate()));
  StoreU64(r3, MemOperand(ip));

  Drop(1);  // Drop padding.
}

void MacroAssembler::IsObjectType(Register object, Register scratch1,
                                  Register scratch2, InstanceType type) {
  ASM_CODE_COMMENT(this);
  CompareObjectType(object, scratch1, scratch2, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    mov(scratch, value);
    slgfi(scratch, Operand(lower_limit));
    CmpU64(scratch, Operand(higher_limit - lower_limit));
  } else {
    CmpU64(value, Operand(higher_limit));
  }
}

void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  LoadU16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  if (!base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    LoadRoot(r0, index);
    CmpU64(obj, r0);
    return;
  }
  return CompareTaggedRoot(obj, index);
}

void MacroAssembler::CompareTaggedRoot(Register obj, RootIndex index) {
  if (CanBeImmediate(index)) {
    CompareTagged(obj, Operand(ReadOnlyRootPtr(index)));
    return;
  }
  int32_t offset = RootRegisterOffsetForRootIndex(index);
#ifdef V8_TARGET_BIG_ENDIAN
  offset += (COMPRESS_POINTERS_BOOL ? kTaggedSize : 0);
#endif
  CompareTagged(obj, MemOperand(kRootRegister, offset));
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  ble(on_in_range);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  push(r14);
  // Put input on stack.
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(double_input, MemOperand(sp));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }

  LoadU64(result, MemOperand(sp, 0));
  la(sp, MemOperand(sp, kDoubleSize));
  pop(r14);

  bind(&done);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  ConvertDoubleToInt64(result, double_input);

  // Test for overflow
  TestIfInt32(result
"""


```