Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`. The snippet is part 8 of 9, so it's likely to contain a cohesive set of related functionalities.

Here's a breakdown of the code's functionality, addressing the user's specific points:

1. **General Functionality**:  The code defines a `MacroAssembler` class, specifically for the RISC-V architecture, which provides an interface for emitting RISC-V assembly instructions. The functions within this snippet seem to focus on runtime assertions, floating-point min/max operations, C function calls, code object manipulation, and handling tagged pointers in V8's memory model.

2. **Torque Source Code Check**: The user asks if the file ends in `.tq`. It does not, so it's not a Torque source file.

3. **Relationship to Javascript**:  Many of these functions are used internally by the V8 engine when executing Javascript code. Assertions ensure runtime type correctness. C function calls facilitate interactions between Javascript and native code. Code object manipulation is crucial for executing Javascript functions efficiently. Tagged pointers are fundamental to V8's object representation.

4. **Javascript Examples**: I can provide Javascript examples that might trigger the execution of some of these internal functions. For example, calling a function or performing arithmetic operations might use these assembly-level helpers.

5. **Code Logic Inference**: I can analyze specific functions like `FloatMinMaxHelper` or `PrepareCallCFunction` to infer their input and output based on their logic.

6. **Common Programming Errors**: I can relate some of the assertions (e.g., `AssertFunction`, `AssertNotSmi`) to common Javascript type errors.

7. **Part 8 Summary**:  Given the surrounding code (assertions, floating-point ops, C calls, code objects, tagged pointers), this part likely deals with setting up and executing function calls, performing low-level operations on data, and ensuring type safety during runtime.

**Mental Sandbox**:

* **Assertions**: The `Assert...` functions clearly check type invariants. For instance, `AssertFunction` verifies if an object is indeed a Javascript function.
* **Floating-point**: `FloatMinMaxHelper` implements the `Math.min` and `Math.max` functions at the assembly level, handling NaN cases as specified by Javascript.
* **C Function Calls**: `PrepareCallCFunction` and `CallCFunction` handle the complexities of calling native C functions from within the V8 engine, managing stack frames and argument passing.
* **Code Objects**:  Functions like `CallCodeObject` and `JumpCodeObject` are central to executing compiled Javascript code.
* **Tagged Pointers**: The `LoadTaggedField` and `StoreTaggedField` functions are crucial for working with V8's object model, handling pointer compression if enabled.

**Confidence Score**: 5/5 - I'm quite confident I can address all the user's points based on the code provided.

**Strategizing complete.** I will now generate the response, incorporating the insights from the thought process above.
```cpp
void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(scratch, object);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, scratch,
          Operand(zero_reg));
    LoadMap(scratch, object);
    Lbu(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    And(scratch, scratch, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, scratch,
          Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, scratch,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    Register range = scratch;
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, range);
    Check(Uless_equal, AbortReason::kOperandIsNotAFunction, range,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  UseScratchRegisterScope temps(this);
  Register range = temps.Acquire();
  GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, range);
  Check(Uless_equal, AbortReason::kOperandIsNotACallableFunction, range,
        Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                FIRST_CALLABLE_JS_FUNCTION_TYPE));
  pop(object);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, scratch,
          Operand(zero_reg));
    GetObjectType(object, scratch, scratch);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, scratch,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
#if V8_TARGET_ARCH_RISCV64
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  // We may not have any scratch registers so we preserve our input register.
  Push(object, zero_reg);
  Label ok;
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SmiTst(object, scratch);
  BranchShort(&ok, kEqual, scratch, Operand(zero_reg));
  // Clear the lower 32 bits.
  Srl64(object, object, Operand(32));
  Sll64(object, object, Operand(32));
  // Either the value is now equal to the right-shifted pointer compression
  // cage base or it's zero if we got a compressed pointer register as input.
  BranchShort(&ok, kEqual, object, Operand(zero_reg));
  Check(kEqual, AbortReason::kObjectNotTagged, object,
        Operand(kPtrComprCageBaseRegister));
  bind(&ok);
  Pop(object, zero_reg);
#endif
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  static_assert(kSmiTag == 0);
  SmiTst(object, scratch);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, scratch,
        Operand(zero_reg));

  LoadMap(scratch, object);
  GetInstanceTypeRange(scratch, scratch, FIRST_JS_GENERATOR_OBJECT_TYPE,
                       scratch);
  Check(
      Uless_equal, AbortReason::kOperandIsNotAGeneratorObject, scratch,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    BranchShort(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

template <typename F_TYPE>
void MacroAssembler::FloatMinMaxHelper(FPURegister dst, FPURegister src1,
                                       FPURegister src2, MaxMinKind kind) {
  DCHECK((std::is_same<F_TYPE, float>::value) ||
         (std::is_same<F_TYPE, double>::value));

  if (src1 == src2 && dst != src1) {
    if (std::is_same<float, F_TYPE>::value) {
      fmv_s(dst, src1);
    } else {
      fmv_d(dst, src1);
    }
    return;
  }

  Label done, nan;

  // For RISCV, fmin_s returns the other non-NaN operand as result if only one
  // operand is NaN; but for JS, if any operand is NaN, result is Nan. The
  // following handles the discrepency between handling of NaN between ISA and
  // JS semantics
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (std::is_same<float, F_TYPE>::value) {
    CompareIsNotNanF32(scratch, src1, src2);
  } else {
    CompareIsNotNanF64(scratch, src1, src2);
  }
  BranchFalseF(scratch, &nan);

  if (kind == MaxMinKind::kMax) {
    if (std::is_same<float, F_TYPE>::value) {
      fmax_s(dst, src1, src2);
    } else {
      fmax_d(dst, src1, src2);
    }
  } else {
    if (std::is_same<float, F_TYPE>::value) {
      fmin_s(dst, src1, src2);
    } else {
      fmin_d(dst, src1, src2);
    }
  }
  j(&done);

  bind(&nan);
  // if any operand is NaN, return NaN (fadd returns NaN if any operand is NaN)
  if (std::is_same<float, F_TYPE>::value) {
    fadd_s(dst, src1, src2);
  } else {
    fadd_d(dst, src1, src2);
  }

  bind(&done);
}

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMin);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMin);
}

int MacroAssembler::CalculateStackPassedDWords(int num_gp_arguments,
                                               int num_fp_arguments) {
  int stack_passed_dwords = 0;

  // Up to eight integer arguments are passed in registers a0..a7 and
  // up to eight floating point arguments are passed in registers fa0..fa7
  if (num_gp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_gp_arguments - kRegisterPassedArguments;
  }
  if (num_fp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_fp_arguments - kRegisterPassedArguments;
  }
  stack_passed_dwords += kCArgSlotCount;
  return stack_passed_dwords;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // Up to eight simple arguments in a0..a7, fa0..fa7.
  // Remaining arguments are pushed on the stack (arg slot calculation handled
  // by CalculateStackPassedDWords()).
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments and the
    // original value of sp.
    Mv(scratch, sp);
    SubWord(sp, sp, Operand((stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));
    StoreWord(scratch,
              MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    SubWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t6, function);
  return CallCFunctionHelper(t6, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());
  ASM_CODE_COMMENT(this);
  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
  // The argument stots are presumed to have been set up by
  // PrepareCallCFunction.

#if V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kSystemPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        And(scratch, sp, Operand(frame_alignment_mask));
        BranchShort(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      ebreak();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Label get_pc;
  {
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t6) {
        Mv(t6, function);
        function = t6;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames.
      // 't' registers are caller-saved so this is safe as a scratch register.
      Register pc_scratch = t1;

      LoadAddress(pc_scratch, &get_pc);
      // See x64 code for reasoning about how to address the isolate data
      // fields.
      CHECK(root_array_available());
      StoreWord(pc_scratch,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      StoreWord(fp,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }
  }

  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    StoreWord(zero_reg,
              ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Remove frame bought in PrepareCallCFunction
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    LoadWord(sp, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    AddWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }

  return call_pc_offset;
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  temps.Include(t6);
  Register scratch = temps.Acquire();
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  LoadWord(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  ASM_CODE_COMMENT(this);
  auto pc = -pc_offset();
  auipc(dst, 0);
  if (pc != 0) {
    SubWord(dst, dst, pc);
  }
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(
      kScratchReg, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  Lw(kScratchReg, FieldMemOperand(kScratchReg, Code::kFlagsOffset));
  And(kScratchReg, kScratchReg,
      Operand(1 << Code::kMarkedForDeoptimizationBit));
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, kScratchReg,
                  Operand(zero_reg));
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  LoadWord(t6, MemOperand(kRootRegister,
                          IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t6);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), tag);
#else
  LoadWord(destination,
           FieldMemOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  UseScratchRegisterScope temps(this);
  Register dispatch_handle = t0;
  Register parameter_count = t1;
  Register scratch = temps.Acquire();
  Lw(dispatch_handle,
     FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);
  Label match;
  Branch(&match, le, parameter_count, Immediate(argument_count));
  // If the parameter count doesn't match, we force a safe crash by setting the
  // code entrypoint to zero, causing a nullptr dereference during the call.
  mv(code, zero_reg);
  bind(&match);
  Call(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  Call(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  LoadCodeEntrypointFromJSDispatchTable(
      code,
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  Ld(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, scratch));
  ASM_CODE_COMMENT(this);
  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);

  Ld(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(parameter_count, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand,
                     std::forward<Trapper>(trapper));
  } else {
    Ld(destination, field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Lw(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(const Register& destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    Sw(value, dst_field_operand, std::forward<Trapper>(trapper));
  } else {
    Sd(value, dst_field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::AtomicStoreTaggedField(Register src,
                                            const MemOperand& dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  AddWord(scratch, dst.rm(), dst.offset());
  if (COMPRESS_POINTERS_BOOL) {
    amoswap_w(true, true, zero_reg, src, scratch);
  } else {
    amoswap_d(true, true, zero_reg, src, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(const Register& destination,
                                            const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    AddWord(destination, destination,
            Operand(((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32));
  }
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const MemOperand& field_operand,
                                      Trapper&& trapper) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand, std::forward<Trapper>(trapper));
  AddWord(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const Register& source) {
  ASM_CODE_COMMENT(this);
  And(destination, source, Operand(0xFFFFFFFF));
  AddWord(destination, kPtrComprCageBaseRegister, Operand(destination));
}

void MacroAssembler::DecompressTagged(Register dst, Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  AddWord(dst, kPtrComprCageBaseRegister, static_cast<int32_t
### 提示词
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ratch, object);
    Lbu(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    And(scratch, scratch, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, scratch,
          Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, scratch,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    Register range = scratch;
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, range);
    Check(Uless_equal, AbortReason::kOperandIsNotAFunction, range,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  UseScratchRegisterScope temps(this);
  Register range = temps.Acquire();
  GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, range);
  Check(Uless_equal, AbortReason::kOperandIsNotACallableFunction, range,
        Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                FIRST_CALLABLE_JS_FUNCTION_TYPE));
  pop(object);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, scratch,
          Operand(zero_reg));
    GetObjectType(object, scratch, scratch);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, scratch,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
#if V8_TARGET_ARCH_RISCV64
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  // We may not have any scratch registers so we preserve our input register.
  Push(object, zero_reg);
  Label ok;
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SmiTst(object, scratch);
  BranchShort(&ok, kEqual, scratch, Operand(zero_reg));
  // Clear the lower 32 bits.
  Srl64(object, object, Operand(32));
  Sll64(object, object, Operand(32));
  // Either the value is now equal to the right-shifted pointer compression
  // cage base or it's zero if we got a compressed pointer register as input.
  BranchShort(&ok, kEqual, object, Operand(zero_reg));
  Check(kEqual, AbortReason::kObjectNotTagged, object,
        Operand(kPtrComprCageBaseRegister));
  bind(&ok);
  Pop(object, zero_reg);
#endif
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  static_assert(kSmiTag == 0);
  SmiTst(object, scratch);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, scratch,
        Operand(zero_reg));

  LoadMap(scratch, object);
  GetInstanceTypeRange(scratch, scratch, FIRST_JS_GENERATOR_OBJECT_TYPE,
                       scratch);
  Check(
      Uless_equal, AbortReason::kOperandIsNotAGeneratorObject, scratch,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    BranchShort(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

template <typename F_TYPE>
void MacroAssembler::FloatMinMaxHelper(FPURegister dst, FPURegister src1,
                                       FPURegister src2, MaxMinKind kind) {
  DCHECK((std::is_same<F_TYPE, float>::value) ||
         (std::is_same<F_TYPE, double>::value));

  if (src1 == src2 && dst != src1) {
    if (std::is_same<float, F_TYPE>::value) {
      fmv_s(dst, src1);
    } else {
      fmv_d(dst, src1);
    }
    return;
  }

  Label done, nan;

  // For RISCV, fmin_s returns the other non-NaN operand as result if only one
  // operand is NaN; but for JS, if any operand is NaN, result is Nan. The
  // following handles the discrepency between handling of NaN between ISA and
  // JS semantics
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (std::is_same<float, F_TYPE>::value) {
    CompareIsNotNanF32(scratch, src1, src2);
  } else {
    CompareIsNotNanF64(scratch, src1, src2);
  }
  BranchFalseF(scratch, &nan);

  if (kind == MaxMinKind::kMax) {
    if (std::is_same<float, F_TYPE>::value) {
      fmax_s(dst, src1, src2);
    } else {
      fmax_d(dst, src1, src2);
    }
  } else {
    if (std::is_same<float, F_TYPE>::value) {
      fmin_s(dst, src1, src2);
    } else {
      fmin_d(dst, src1, src2);
    }
  }
  j(&done);

  bind(&nan);
  // if any operand is NaN, return NaN (fadd returns NaN if any operand is NaN)
  if (std::is_same<float, F_TYPE>::value) {
    fadd_s(dst, src1, src2);
  } else {
    fadd_d(dst, src1, src2);
  }

  bind(&done);
}

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMin);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMin);
}

int MacroAssembler::CalculateStackPassedDWords(int num_gp_arguments,
                                               int num_fp_arguments) {
  int stack_passed_dwords = 0;

  // Up to eight integer arguments are passed in registers a0..a7 and
  // up to eight floating point arguments are passed in registers fa0..fa7
  if (num_gp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_gp_arguments - kRegisterPassedArguments;
  }
  if (num_fp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_fp_arguments - kRegisterPassedArguments;
  }
  stack_passed_dwords += kCArgSlotCount;
  return stack_passed_dwords;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // Up to eight simple arguments in a0..a7, fa0..fa7.
  // Remaining arguments are pushed on the stack (arg slot calculation handled
  // by CalculateStackPassedDWords()).
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments and the
    // original value of sp.
    Mv(scratch, sp);
    SubWord(sp, sp, Operand((stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));
    StoreWord(scratch,
              MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    SubWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t6, function);
  return CallCFunctionHelper(t6, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());
  ASM_CODE_COMMENT(this);
  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
  // The argument stots are presumed to have been set up by
  // PrepareCallCFunction.

#if V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kSystemPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        And(scratch, sp, Operand(frame_alignment_mask));
        BranchShort(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      ebreak();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Label get_pc;
  {
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t6) {
        Mv(t6, function);
        function = t6;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames.
      // 't' registers are caller-saved so this is safe as a scratch register.
      Register pc_scratch = t1;

      LoadAddress(pc_scratch, &get_pc);
      // See x64 code for reasoning about how to address the isolate data
      // fields.
      CHECK(root_array_available());
      StoreWord(pc_scratch,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      StoreWord(fp,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }
  }

  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    StoreWord(zero_reg,
              ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Remove frame bought in PrepareCallCFunction
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    LoadWord(sp, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    AddWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }

  return call_pc_offset;
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  temps.Include(t6);
  Register scratch = temps.Acquire();
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  LoadWord(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  ASM_CODE_COMMENT(this);
  auto pc = -pc_offset();
  auipc(dst, 0);
  if (pc != 0) {
    SubWord(dst, dst, pc);
  }
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(
      kScratchReg, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  Lw(kScratchReg, FieldMemOperand(kScratchReg, Code::kFlagsOffset));
  And(kScratchReg, kScratchReg,
      Operand(1 << Code::kMarkedForDeoptimizationBit));
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, kScratchReg,
                  Operand(zero_reg));
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  LoadWord(t6, MemOperand(kRootRegister,
                          IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t6);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), tag);
#else
  LoadWord(destination,
           FieldMemOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  UseScratchRegisterScope temps(this);
  Register dispatch_handle = t0;
  Register parameter_count = t1;
  Register scratch = temps.Acquire();
  Lw(dispatch_handle,
     FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);
  Label match;
  Branch(&match, le, parameter_count, Immediate(argument_count));
  // If the parameter count doesn't match, we force a safe crash by setting the
  // code entrypoint to zero, causing a nullptr dereference during the call.
  mv(code, zero_reg);
  bind(&match);
  Call(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  Call(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  LoadCodeEntrypointFromJSDispatchTable(
      code,
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  Ld(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, scratch));
  ASM_CODE_COMMENT(this);
  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);

  Ld(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(parameter_count, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand,
                     std::forward<Trapper>(trapper));
  } else {
    Ld(destination, field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Lw(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(const Register& destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    Sw(value, dst_field_operand, std::forward<Trapper>(trapper));
  } else {
    Sd(value, dst_field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::AtomicStoreTaggedField(Register src,
                                            const MemOperand& dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  AddWord(scratch, dst.rm(), dst.offset());
  if (COMPRESS_POINTERS_BOOL) {
    amoswap_w(true, true, zero_reg, src, scratch);
  } else {
    amoswap_d(true, true, zero_reg, src, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(const Register& destination,
                                            const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    AddWord(destination, destination,
            Operand(((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32));
  }
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const MemOperand& field_operand,
                                      Trapper&& trapper) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand, std::forward<Trapper>(trapper));
  AddWord(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const Register& source) {
  ASM_CODE_COMMENT(this);
  And(destination, source, Operand(0xFFFFFFFF));
  AddWord(destination, kPtrComprCageBaseRegister, Operand(destination));
}

void MacroAssembler::DecompressTagged(Register dst, Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  AddWord(dst, kPtrComprCageBaseRegister, static_cast<int32_t>(immediate));
}

void MacroAssembler::DecompressProtected(const Register& destination,
                                         const MemOperand& field_operand,
                                         Trapper&& trapper) {
#ifdef V8_ENABLE_SANDBOX
  CHECK(V8_ENABLE_SANDBOX_BOOL);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Lw(destination, field_operand, std::forward<Trapper>(trapper));
  LoadWord(scratch,
           MemOperand(kRootRegister, IsolateData::trusted_cage_base_offset()));
  Or(destination, destination, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::AtomicDecompressTaggedSigned(Register dst,
                                                  const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Lwu(dst, src);
  sync();
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    AddWord(dst, dst,
            Operand(((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32));
  }
}

void MacroAssembler::AtomicDecompressTagged(Register dst,
                                            const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Lwu(dst, src);
  sync();
  AddWord(dst, kPtrComprCageBaseRegister, dst);
}

#endif
void MacroAssembler::DropArguments(Register count) {
  CalcScaledAddress(sp, sp, count, kSystemPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  ASM_CODE_COMMENT(masm);
  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = a0;
  Register scratch = a4;
  Register scratch2 = a5;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
  Register prev_next_address_reg = kScratchReg;
  Register prev_limit_reg = s1;
  Register prev_level_reg = s2;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ LoadWord(prev_next_address_reg, next_mem_op);
    __ LoadWord(prev_limit_reg, limit_mem_op);
    __ Lw(prev_level_reg, level_mem_op);
    __ Add32(scratch, prev_level_reg, Operand(1));
    __ Sw(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ Lb(scratch,
          __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ Branch(&profiler_or_side_effects_check_enabled, ne, scratch,
              Operand(zero_reg));
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ li(scratch, ER::address_of_runtime_stats_flag());
    __ Lw(scratch, MemOperand(scratch, 0));
    __ Branch(&profiler_or_side_effects_check_enabled, ne, scratch,
              Operand(zero_reg));
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
  __ StoreReturnAddressAndCall(function_address);
  __ bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ LoadWord(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ StoreWord(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ Lw(scratch, level_mem_op);
      __ Sub32(scratch, scratch, Operand(1));
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall, scratch,
               Operand(prev_level_reg));
    }
    __ Sw(prev_level_reg, level_mem_op);
    __ LoadWord(scratch, limit_mem_op);
    __ Branch(&delete_allocated_handles, ne, prev_limit_reg, Operand(scratch));
  }
  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ LoadWord(argc_reg, *argc_operand);
  }

  __ LeaveExitFrame(scratch);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadRoot(scratch, RootIndex::kTheHoleValue);
    __ LoadWord(scratch2, __ ExternalReferenceAsOperand(
                              ER::exception_address(isolate), no_reg));
    __ Branch(&propagate_exception, ne, scratch, Operand(scratch2));
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ AddWord(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    if (slots_to_drop_on_return != 0) {
      __ AddWord(sp, sp, Operand(slots_t
```