Response:
The user wants a summary of the provided C++ code snippet from V8.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core functionality:** The code is part of the `builtins-arm64.cc` file and contains several function definitions related to interacting with WebAssembly and C++ from Javascript. The prefix `Generate_` suggests these functions generate assembly code.

2. **Analyze individual functions/sections:** Go through each function and understand its purpose.
    * `JSToWasmWrapperHelper`: This function appears to be a central point for setting up calls from JavaScript to WebAssembly, handling different scenarios like regular calls, promise returns, and stack switching.
    * `SwitchToTheCentralStackIfNeeded` and `SwitchFromTheCentralStackIfNeeded`: These functions deal with a "central stack," likely for managing stack switching in WebAssembly.
    * `Generate_CEntry`: This is a crucial function for calling C++ functions from JavaScript. It manages the stack frame, arguments, and return values.
    * `Generate_WasmHandleStackOverflow`: This handles stack overflow situations within WebAssembly.
    * `Generate_DoubleToI`: This function converts JavaScript doubles to integers.
    * `Generate_CallApiCallbackImpl`: This function handles calls to native JavaScript API callbacks.
    * `Generate_CallApiGetter`: This function handles calls to native JavaScript API getters.
    * `Generate_DirectCEntry`: This provides a direct, GC-safe entry point to C++.
    * `CopyRegListToFrame` and `RestoreRegList`: These are utility functions for saving and restoring CPU registers.
    * `Generate_DeoptimizationEntry`: This handles the process of deoptimizing code.

3. **Group related functionalities:** Notice that some functions work together. For example, the `JSToWasmWrapperHelper` is used by several `Generate_` functions related to WebAssembly. The stack switching functions are also tightly coupled.

4. **Infer high-level purpose:** Based on the function names and their actions, it's clear this part of the code is responsible for the low-level mechanics of calling between JavaScript, WebAssembly, and C++. It handles stack management, argument passing, exception handling, and type conversions.

5. **Address specific instructions:**
    * **".tq" extension:** The code is `.cc`, so it's C++, not Torque.
    * **Relationship to Javascript:**  Many functions directly facilitate calling from JavaScript to other environments (WebAssembly, C++). Examples should illustrate this.
    * **Code logic reasoning:** The `JSToWasmWrapperHelper` is a good candidate for demonstrating input/output based on the `stack_switch` flag.
    * **Common programming errors:** Integer overflow during double-to-integer conversion is a likely scenario.

6. **Formulate the summary:** Combine the insights into a concise description of the file's purpose. Emphasize the inter-language calling aspects and the different scenarios handled.

7. **Construct the examples:** Create simple JavaScript examples to demonstrate the interaction with WebAssembly and C++ that these builtins facilitate.

8. **Illustrate code logic:** Provide a clear example of the conditional logic in `JSToWasmWrapperHelper` based on the `stack_switch` flag.

9. **Give a programming error example:** Show a JavaScript scenario that would lead to the `Generate_DoubleToI` function being involved and potentially encountering overflow.

10. **Review and refine:** Ensure the answer is accurate, well-organized, and addresses all parts of the user's request. Specifically, double-check the function descriptions and ensure the examples are relevant. Since this is part 6 of 7, acknowledge that it's focusing on a subset of the file's complete functionality.
```cpp
WasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ Str(wasm::kGpReturnRegisters[0],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ Str(wasm::kGpReturnRegisters[1],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ Ldr(x1, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ Ldr(x0, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ Ldr(x1, MemOperand(
                   fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ Ldr(x0,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  Register scratch = x3;
  GetContextFromImplicitArg(masm, x0, scratch);
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, regs, mode, &return_promise);
  }
  __ Bind(&suspend, BranchTargetIdentifier::kBtiJump);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  constexpr int64_t stack_arguments_in = 2;
  __ DropArguments(stack_arguments_in);
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, regs, &return_promise);
  }
}
}  // namespace

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kNoPromise);
}

void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

namespace {
void SwitchSimulatorStackLimit(MacroAssembler* masm) {
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x16);
    __ LoadStackLimit(x16, StackLimitKind::kRealStackLimit);
    __ hlt(kImmExceptionIsSwitchStackLimit);
  }
}

static constexpr Register kOldSPRegister = x23;
static constexpr Register kSwitchFlagRegister = x24;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ Mov(kSwitchFlagRegister, 0);
  __ Mov(kOldSPRegister, sp);

  // Using x2-x4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = x2;
  __ Mov(on_central_stack_flag, on_central_stack_flag_loc);
  __ Ldrb(on_central_stack_flag, MemOperand(on_central_stack_flag));

  Label do_not_need_to_switch;
  __ Cbnz(on_central_stack_flag, &do_not_need_to_switch);
  // Switch to central stack.

  static constexpr Register central_stack_sp = x4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input, padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ Mov(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ Mov(central_stack_sp, kReturnRegister0);
    __ Pop(padreg, argv_input, target_input, argc_input);
  }
  {
    // Update the sp saved in the frame.
    // It will be used to calculate the callee pc during GC.
    // The pc is going to be on the new stack segment, so rewrite it here.
    UseScratchRegisterScope temps{masm};
    Register new_sp_after_call = temps.AcquireX();
    __ Sub(new_sp_after_call, central_stack_sp, kSystemPointerSize);
    __ Str(new_sp_after_call, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  SwitchSimulatorStackLimit(masm);

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ Sub(sp, central_stack_sp, kReturnAddressSlotOffset + kPadding);
  __ Mov(kSwitchFlagRegister, 1);

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ Cbz(kSwitchFlagRegister, &no_stack_change);

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister1, kReturnRegister0);
  }

  SwitchSimulatorStackLimit(masm);

  __ Mov(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  ASM_LOCATION("CEntry::Generate entry");

  using ER = ExternalReference;

  // Register parameters:
  //    x0: argc (including receiver, untagged)
  //    x1: target
  // If argv_mode == ArgvMode::kRegister:
  //    x11: argv (pointer to first argument)
  //
  // The stack on entry holds the arguments and the receiver, with the receiver
  // at the highest address:
  //
  //    sp[argc-1]: receiver
  //    sp[argc-2]: arg[argc-2]
  //    ...           ...
  //    sp[1]:      arg[1]
  //    sp[0]:      arg[0]
  //
  // The arguments are in reverse order, so that arg[argc-2] is actually the
  // first argument to the target function and arg[0] is the last.
  static constexpr Register argc_input = x0;
  static constexpr Register target_input = x1;
  // Initialized below if ArgvMode::kStack.
  static constexpr Register argv_input = x11;

  if (argv_mode == ArgvMode::kStack) {
    // Derive argv from the stack pointer so that it points to the first
    // argument.
    __ SlotAddress(argv_input, argc_input);
    __ Sub(argv_input, argv_input, kReceiverOnStackSize);
  }

  // If ArgvMode::kStack, argc is reused below and must be retained across the
  // call in a callee-saved register.
  static constexpr Register argc = x22;

  // Enter the exit frame.
  const int kNoExtraSpace = 0;
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      x10, kNoExtraSpace,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  if (argv_mode == ArgvMode::kStack) {
    __ Mov(argc, argc_input);
  }

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_input, argv_input);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // x21 : argv
  // x22 : argc
  // x23 : call target
  //
  // The stack (on entry) holds the arguments and the receiver, with the
  // receiver at the highest address:
  //
  //         argv[8]:     receiver
  // argv -> argv[0]:     arg[argc-2]
  //         ...          ...
  //         argv[...]:   arg[1]
  //         argv[...]:   arg[0]
  //
  // Immediately below (after) this is the exit frame, as constructed by
  // EnterExitFrame:
  //         fp[8]:    CallerPC (lr)
  //   fp -> fp[0]:    CallerFP (old fp)
  //         fp[-8]:   Space reserved for SPOffset.
  //         fp[-16]:  CodeObject()
  //         sp[...]:  Saved doubles, if saved_doubles is true.
  //         sp[16]:   Alignment padding, if necessary.
  //         sp[8]:   Preserved x22 (used for argc).
  //   sp -> sp[0]:    Space reserved for the return address.

  // TODO(jgruber): Swap these registers in the calling convention instead.
  static_assert(target_input == x1);
  static_assert(argv_input == x11);
  __ Swap(target_input, argv_input);
  static constexpr Register target = x11;
  static constexpr Register argv = x1;
  static_assert(!AreAliased(argc_input, argc, target, argv));

  // Prepare AAPCS64 arguments to pass to the builtin.
  static_assert(argc_input == x0);  // Already in the right spot.
  static_assert(argv == x1);        // Already in the right spot.
  __ Mov(x2, ER::isolate_address());

  __ StoreReturnAddressAndCall(target);

  // Result returned in x0 or x1:x0 - do not destroy these registers!

  //  x0    result0      The return code from the call.
  //  x1    result1      For calls which return ObjectPair.
  //  x22   argc         .. only if ArgvMode::kStack.
  const Register& result = x0;

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRoot(result, RootIndex::kException, ComparisonMode::kFullPointer);
  __ B(eq, &exception_returned);

  // The call succeeded, so unwind the stack and return.
  if (argv_mode == ArgvMode::kStack) {
    __ Mov(x11, argc);  // x11 used as scratch, just til DropArguments below.
    __ LeaveExitFrame(x10, x9);
    __ DropArguments(x11);
  } else {
    __ LeaveExitFrame(x10, x9);
  }

  __ AssertFPCRState();
  __ Ret();

  // Handling of exception.
  __ Bind(&exception_returned);

  // Ask the runtime for help to determine the handler. This will set x0 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Mov(x0, 0);  // argc.
    __ Mov(x1, 0);  // argv.
    __ Mov(x2, ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Mov(cp, ER::Create(IsolateAddressId::kPendingHandlerContextAddress,
                        masm->isolate()));
  __ Ldr(cp, MemOperand(cp));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, ER::Create(IsolateAddressId::kPendingHandlerSPAddress,
                               masm->isolate()));
    __ Ldr(scratch, MemOperand(scratch));
    __ Mov(sp, scratch);
  }
  __ Mov(fp, ER::Create(IsolateAddressId::kPendingHandlerFPAddress,
                        masm->isolate()));
  __ Ldr(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label not_js_frame;
  __ Cbz(cp, &not_js_frame);
  __ Str(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ Bind(&not_js_frame);

  {
    // Clear c_entry_fp, like we do in `LeaveExitFrame`.
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch,
           ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate()));
    __ Str(xzr, MemOperand(scratch));
  }

  // Compute the handler entry address and jump to it. We use x17 here for the
  // jump target, as this jump can occasionally end up at the start of
  // InterpreterEnterAtBytecode, which when CFI is enabled starts with
  // a "BTI c".
  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  __ Mov(x17, ER::Create(IsolateAddressId::kPendingHandlerEntrypointAddress,
                         masm->isolate()));
  __ Ldr(x17, MemOperand(x17));
  __ Br(x17);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base = WasmHandleStackOverflowDescriptor::FrameBaseRegister();
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();
  {
    DCHECK_NE(kCArgRegs[1], frame_base);
    DCHECK_NE(kCArgRegs[3], frame_base);
    __ Mov(kCArgRegs[3], gap);
    __ Mov(kCArgRegs[1], sp);
    __ Sub(kCArgRegs[2], frame_base, kCArgRegs[1]);
    __ Mov(kCArgRegs[4], fp);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kCArgRegs[3], padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ Pop(padreg, gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ Cbz(kReturnRegister0, &call_runtime);
  {
    UseScratchRegisterScope temps(masm);
    Register new_fp = temps.AcquireX();
    // Calculate old FP - SP offset to adjust FP accordingly to new SP.
    __ Mov(new_fp, sp);
    __ Sub(new_fp, fp, new_fp);
    __ Add(new_fp, kReturnRegister0, new_fp);
    __ Mov(fp, new_fp);
  }
  SwitchSimulatorStackLimit(masm);
  __ Mov(sp, kReturnRegister0);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START));
    __ Str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  }
  __ Ret();

  __ bind(&call_runtime);
  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ Ldr(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        cp, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ PushArgument(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ Ret();
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label done;
  Register result = x7;

  DCHECK(result.Is64Bits());

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  UseScratchRegisterScope temps(masm);
  Register scratch1 = temps.AcquireX();
  Register scratch2 = temps.AcquireX();
  DoubleRegister double_scratch = temps.AcquireD();

  // Account for saved regs.
  const int kArgumentOffset = 2 * kSystemPointerSize;

  __ Push(result, scratch1);  // scratch1 is also pushed to preserve alignment.
  __ Peek(double_scratch, kArgumentOffset);

  // Try to convert with a FPU convert instruction. This handles all
  // non-saturating cases.
  __ TryConvertDoubleToInt64(result, double_scratch, &done);
  __ Fmov(result, double_scratch);

  // If we reach here we need to manually convert the input to an int32.

  // Extract the exponent.
  Register exponent = scratch1;
  __ Ubfx(exponent, result, HeapNumber::kMantissaBits,
          HeapNumber::kExponentBits);

  // It the exponent is >= 84 (kMantissaBits + 32), the result is always 0 since
  // the mantissa gets shifted completely out of the int32_t result.
  __ Cmp(exponent, HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 32);
  __ CzeroX(result, ge);
  __ B(ge, &done);

  // The Fcvtzs sequence handles all cases except where the conversion causes
  // signed overflow in the int64_t target. Since we've already handled
  // exponents >= 84, we can guarantee that 63 <= exponent < 84.

  if (v8_flags.debug_code) {
    __ Cmp(exponent, HeapNumber::kExponentBias + 63);
    // Exponents less than this should have been handled by the Fcvt case.
    __ Check(ge, AbortReason::kUnexpectedValue);
  }

  // Isolate the mantissa bits, and set the implicit '1'.
  Register mantissa = scratch2;
  __ Ubfx(mantissa, result, 0, HeapNumber::kMantissaBits);
  __ Orr(mantissa, mantissa, 1ULL << HeapNumber::kMantissaBits);

  // Negate the mantissa if necessary.
  __ Tst(result, kXSignMask);
  __ Cneg(mantissa, mantissa, ne);

  // Shift the mantissa bits in the correct place. We know that we have to shift
  // it left here, because exponent >= 63 >= kMantissaBits.
  __ Sub(exponent, exponent,
         HeapNumber::kExponentBias + HeapNumber::kMantissaBits);
  __ Lsl(result, mantissa, exponent);

  __ Bind(&done);
  __ Poke(result, kArgumentOffset);
  __ Pop(scratch1, result);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- x1                  : api function address
  // Both modes:
  //  -- x2                  : arguments count (not including the receiver)
  //  -- x3                  : FunctionTemplateInfo
  //  -- x0                  : holder
  //  -- cp                  : context
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------

  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = x4;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  static constexpr int kStackSize = FCA::kArgsLength;
  static_assert(kStackSize % 2 == 0);
  __ Claim(kStackSize, kSystemPointerSize);

  // kHolder.
  __ Str(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ Mov(scratch, ER::isolate_address());
  __ Str(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ Str(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Str(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ Str(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ Str(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag);
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  // This is a workaround for performance regression observed on Apple Silicon
  // (https://crbug.com/347741609): reading argc value after the call via
  //   MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  // is noticeably slower than using sp-based access:
  MemOperand argc_operand = ExitFrameStackSlotOperand(FCA::kLengthOffset);
  if (v8_flags.debug_code) {
    // Ensure sp-based calculation of FC::length_'s address matches the
    // fp-based one.
    Label ok;
    // +kSystemPointerSize is for the slot at [sp] which is reserved in all
    // ExitFrames for storing the return PC.
    __ Add(scratch, sp,
           FCA::kLengthOffset + kSystemPointerSize - FC::kFCIArgcOffset);
    __ cmp(scratch, fp);
    __ B(eq, &ok);
    __ DebugBreak();
    __ Bind(&ok);
  }
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ Str(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Add(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Add(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Add(function_callback_info_arg, fp,
         Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;

  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- x1                  : receiver
  //  -- x3                  : accessor info
  //  -- x0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = x2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = x4;
  Register undef = x5;
  Register scratch2 = x6;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, undef, scratch2));

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name
Prompt: 
```
这是目录为v8/src/builtins/arm64/builtins-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm64/builtins-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
WasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2));
  __ Str(wasm::kGpReturnRegisters[0],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1));
  __ Str(wasm::kGpReturnRegisters[1],
         MemOperand(
             wrapper_buffer,
             JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2));
  // Call the return value builtin with
  // x0: wasm instance.
  // x1: the result JSArray for multi-return.
  // x2: pointer to the byte buffer which contains all parameters.
  if (stack_switch) {
    __ Ldr(x1, MemOperand(fp, StackSwitchFrameConstants::kResultArrayOffset));
    __ Ldr(x0, MemOperand(fp, StackSwitchFrameConstants::kImplicitArgOffset));
  } else {
    __ Ldr(x1, MemOperand(
                   fp, JSToWasmWrapperFrameConstants::kResultArrayParamOffset));
    __ Ldr(x0,
           MemOperand(fp, JSToWasmWrapperFrameConstants::kImplicitArgOffset));
  }
  Register scratch = x3;
  GetContextFromImplicitArg(masm, x0, scratch);
  __ CallBuiltin(Builtin::kJSToWasmHandleReturns);

  Label return_promise;
  if (stack_switch) {
    SwitchBackAndReturnPromise(masm, regs, mode, &return_promise);
  }
  __ Bind(&suspend, BranchTargetIdentifier::kBtiJump);

  __ LeaveFrame(stack_switch ? StackFrame::STACK_SWITCH
                             : StackFrame::JS_TO_WASM);
  // Despite returning to the different location for regular and stack switching
  // versions, incoming argument count matches both cases:
  // instance and result array without suspend or
  // or promise resolve/reject params for callback.
  constexpr int64_t stack_arguments_in = 2;
  __ DropArguments(stack_arguments_in);
  __ Ret();

  // Catch handler for the stack-switching wrapper: reject the promise with the
  // thrown exception.
  if (mode == wasm::kPromise) {
    GenerateExceptionHandlingLandingPad(masm, regs, &return_promise);
  }
}
}  // namespace

void Builtins::Generate_JSToWasmWrapperAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kNoPromise);
}

void Builtins::Generate_WasmReturnPromiseOnSuspendAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kPromise);
}

void Builtins::Generate_JSToWasmStressSwitchStacksAsm(MacroAssembler* masm) {
  JSToWasmWrapperHelper(masm, wasm::kStressSwitch);
}

namespace {
void SwitchSimulatorStackLimit(MacroAssembler* masm) {
  if (masm->options().enable_simulator_code) {
    UseScratchRegisterScope temps(masm);
    temps.Exclude(x16);
    __ LoadStackLimit(x16, StackLimitKind::kRealStackLimit);
    __ hlt(kImmExceptionIsSwitchStackLimit);
  }
}

static constexpr Register kOldSPRegister = x23;
static constexpr Register kSwitchFlagRegister = x24;

void SwitchToTheCentralStackIfNeeded(MacroAssembler* masm, Register argc_input,
                                     Register target_input,
                                     Register argv_input) {
  using ER = ExternalReference;

  __ Mov(kSwitchFlagRegister, 0);
  __ Mov(kOldSPRegister, sp);

  // Using x2-x4 as temporary registers, because they will be rewritten
  // before exiting to native code anyway.

  ER on_central_stack_flag_loc = ER::Create(
      IsolateAddressId::kIsOnCentralStackFlagAddress, masm->isolate());
  const Register& on_central_stack_flag = x2;
  __ Mov(on_central_stack_flag, on_central_stack_flag_loc);
  __ Ldrb(on_central_stack_flag, MemOperand(on_central_stack_flag));

  Label do_not_need_to_switch;
  __ Cbnz(on_central_stack_flag, &do_not_need_to_switch);
  // Switch to central stack.

  static constexpr Register central_stack_sp = x4;
  DCHECK(!AreAliased(central_stack_sp, argc_input, argv_input, target_input));
  {
    __ Push(argc_input, target_input, argv_input, padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ Mov(kCArgRegs[1], kOldSPRegister);
    __ CallCFunction(ER::wasm_switch_to_the_central_stack(), 2,
                     SetIsolateDataSlots::kNo);
    __ Mov(central_stack_sp, kReturnRegister0);
    __ Pop(padreg, argv_input, target_input, argc_input);
  }
  {
    // Update the sp saved in the frame.
    // It will be used to calculate the callee pc during GC.
    // The pc is going to be on the new stack segment, so rewrite it here.
    UseScratchRegisterScope temps{masm};
    Register new_sp_after_call = temps.AcquireX();
    __ Sub(new_sp_after_call, central_stack_sp, kSystemPointerSize);
    __ Str(new_sp_after_call, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  SwitchSimulatorStackLimit(masm);

  static constexpr int kReturnAddressSlotOffset = 1 * kSystemPointerSize;
  static constexpr int kPadding = 1 * kSystemPointerSize;
  __ Sub(sp, central_stack_sp, kReturnAddressSlotOffset + kPadding);
  __ Mov(kSwitchFlagRegister, 1);

  __ bind(&do_not_need_to_switch);
}

void SwitchFromTheCentralStackIfNeeded(MacroAssembler* masm) {
  using ER = ExternalReference;

  Label no_stack_change;
  __ Cbz(kSwitchFlagRegister, &no_stack_change);

  {
    __ Push(kReturnRegister0, kReturnRegister1);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_switch_from_the_central_stack(), 1,
                     SetIsolateDataSlots::kNo);
    __ Pop(kReturnRegister1, kReturnRegister0);
  }

  SwitchSimulatorStackLimit(masm);

  __ Mov(sp, kOldSPRegister);

  __ bind(&no_stack_change);
}

}  // namespace

#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_CEntry(MacroAssembler* masm, int result_size,
                               ArgvMode argv_mode, bool builtin_exit_frame,
                               bool switch_to_central_stack) {
  ASM_LOCATION("CEntry::Generate entry");

  using ER = ExternalReference;

  // Register parameters:
  //    x0: argc (including receiver, untagged)
  //    x1: target
  // If argv_mode == ArgvMode::kRegister:
  //    x11: argv (pointer to first argument)
  //
  // The stack on entry holds the arguments and the receiver, with the receiver
  // at the highest address:
  //
  //    sp[argc-1]: receiver
  //    sp[argc-2]: arg[argc-2]
  //    ...           ...
  //    sp[1]:      arg[1]
  //    sp[0]:      arg[0]
  //
  // The arguments are in reverse order, so that arg[argc-2] is actually the
  // first argument to the target function and arg[0] is the last.
  static constexpr Register argc_input = x0;
  static constexpr Register target_input = x1;
  // Initialized below if ArgvMode::kStack.
  static constexpr Register argv_input = x11;

  if (argv_mode == ArgvMode::kStack) {
    // Derive argv from the stack pointer so that it points to the first
    // argument.
    __ SlotAddress(argv_input, argc_input);
    __ Sub(argv_input, argv_input, kReceiverOnStackSize);
  }

  // If ArgvMode::kStack, argc is reused below and must be retained across the
  // call in a callee-saved register.
  static constexpr Register argc = x22;

  // Enter the exit frame.
  const int kNoExtraSpace = 0;
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(
      x10, kNoExtraSpace,
      builtin_exit_frame ? StackFrame::BUILTIN_EXIT : StackFrame::EXIT);

  if (argv_mode == ArgvMode::kStack) {
    __ Mov(argc, argc_input);
  }

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchToTheCentralStackIfNeeded(masm, argc_input, target_input, argv_input);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // x21 : argv
  // x22 : argc
  // x23 : call target
  //
  // The stack (on entry) holds the arguments and the receiver, with the
  // receiver at the highest address:
  //
  //         argv[8]:     receiver
  // argv -> argv[0]:     arg[argc-2]
  //         ...          ...
  //         argv[...]:   arg[1]
  //         argv[...]:   arg[0]
  //
  // Immediately below (after) this is the exit frame, as constructed by
  // EnterExitFrame:
  //         fp[8]:    CallerPC (lr)
  //   fp -> fp[0]:    CallerFP (old fp)
  //         fp[-8]:   Space reserved for SPOffset.
  //         fp[-16]:  CodeObject()
  //         sp[...]:  Saved doubles, if saved_doubles is true.
  //         sp[16]:   Alignment padding, if necessary.
  //         sp[8]:   Preserved x22 (used for argc).
  //   sp -> sp[0]:    Space reserved for the return address.

  // TODO(jgruber): Swap these registers in the calling convention instead.
  static_assert(target_input == x1);
  static_assert(argv_input == x11);
  __ Swap(target_input, argv_input);
  static constexpr Register target = x11;
  static constexpr Register argv = x1;
  static_assert(!AreAliased(argc_input, argc, target, argv));

  // Prepare AAPCS64 arguments to pass to the builtin.
  static_assert(argc_input == x0);  // Already in the right spot.
  static_assert(argv == x1);        // Already in the right spot.
  __ Mov(x2, ER::isolate_address());

  __ StoreReturnAddressAndCall(target);

  // Result returned in x0 or x1:x0 - do not destroy these registers!

  //  x0    result0      The return code from the call.
  //  x1    result1      For calls which return ObjectPair.
  //  x22   argc         .. only if ArgvMode::kStack.
  const Register& result = x0;

#if V8_ENABLE_WEBASSEMBLY
  if (switch_to_central_stack) {
    SwitchFromTheCentralStackIfNeeded(masm);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Check result for exception sentinel.
  Label exception_returned;
  // The returned value may be a trusted object, living outside of the main
  // pointer compression cage, so we need to use full pointer comparison here.
  __ CompareRoot(result, RootIndex::kException, ComparisonMode::kFullPointer);
  __ B(eq, &exception_returned);

  // The call succeeded, so unwind the stack and return.
  if (argv_mode == ArgvMode::kStack) {
    __ Mov(x11, argc);  // x11 used as scratch, just til DropArguments below.
    __ LeaveExitFrame(x10, x9);
    __ DropArguments(x11);
  } else {
    __ LeaveExitFrame(x10, x9);
  }

  __ AssertFPCRState();
  __ Ret();

  // Handling of exception.
  __ Bind(&exception_returned);

  // Ask the runtime for help to determine the handler. This will set x0 to
  // contain the current exception, don't clobber it.
  {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ Mov(x0, 0);  // argc.
    __ Mov(x1, 0);  // argv.
    __ Mov(x2, ER::isolate_address());
    __ CallCFunction(ER::Create(Runtime::kUnwindAndFindExceptionHandler), 3,
                     SetIsolateDataSlots::kNo);
  }

  // Retrieve the handler context, SP and FP.
  __ Mov(cp, ER::Create(IsolateAddressId::kPendingHandlerContextAddress,
                        masm->isolate()));
  __ Ldr(cp, MemOperand(cp));
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, ER::Create(IsolateAddressId::kPendingHandlerSPAddress,
                               masm->isolate()));
    __ Ldr(scratch, MemOperand(scratch));
    __ Mov(sp, scratch);
  }
  __ Mov(fp, ER::Create(IsolateAddressId::kPendingHandlerFPAddress,
                        masm->isolate()));
  __ Ldr(fp, MemOperand(fp));

  // If the handler is a JS frame, restore the context to the frame. Note that
  // the context will be set to (cp == 0) for non-JS frames.
  Label not_js_frame;
  __ Cbz(cp, &not_js_frame);
  __ Str(cp, MemOperand(fp, StandardFrameConstants::kContextOffset));
  __ Bind(&not_js_frame);

  {
    // Clear c_entry_fp, like we do in `LeaveExitFrame`.
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch,
           ER::Create(IsolateAddressId::kCEntryFPAddress, masm->isolate()));
    __ Str(xzr, MemOperand(scratch));
  }

  // Compute the handler entry address and jump to it. We use x17 here for the
  // jump target, as this jump can occasionally end up at the start of
  // InterpreterEnterAtBytecode, which when CFI is enabled starts with
  // a "BTI c".
  UseScratchRegisterScope temps(masm);
  temps.Exclude(x17);
  __ Mov(x17, ER::Create(IsolateAddressId::kPendingHandlerEntrypointAddress,
                         masm->isolate()));
  __ Ldr(x17, MemOperand(x17));
  __ Br(x17);
}

#if V8_ENABLE_WEBASSEMBLY
void Builtins::Generate_WasmHandleStackOverflow(MacroAssembler* masm) {
  using ER = ExternalReference;
  Register frame_base = WasmHandleStackOverflowDescriptor::FrameBaseRegister();
  Register gap = WasmHandleStackOverflowDescriptor::GapRegister();
  {
    DCHECK_NE(kCArgRegs[1], frame_base);
    DCHECK_NE(kCArgRegs[3], frame_base);
    __ Mov(kCArgRegs[3], gap);
    __ Mov(kCArgRegs[1], sp);
    __ Sub(kCArgRegs[2], frame_base, kCArgRegs[1]);
    __ Mov(kCArgRegs[4], fp);
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(kCArgRegs[3], padreg);
    __ Mov(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::wasm_grow_stack(), 5);
    __ Pop(padreg, gap);
    DCHECK_NE(kReturnRegister0, gap);
  }
  Label call_runtime;
  // wasm_grow_stack returns zero if it cannot grow a stack.
  __ Cbz(kReturnRegister0, &call_runtime);
  {
    UseScratchRegisterScope temps(masm);
    Register new_fp = temps.AcquireX();
    // Calculate old FP - SP offset to adjust FP accordingly to new SP.
    __ Mov(new_fp, sp);
    __ Sub(new_fp, fp, new_fp);
    __ Add(new_fp, kReturnRegister0, new_fp);
    __ Mov(fp, new_fp);
  }
  SwitchSimulatorStackLimit(masm);
  __ Mov(sp, kReturnRegister0);
  {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.AcquireX();
    __ Mov(scratch, StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START));
    __ Str(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
  }
  __ Ret();

  __ bind(&call_runtime);
  // If wasm_grow_stack returns zero interruption or stack overflow
  // should be handled by runtime call.
  {
    __ Ldr(kWasmImplicitArgRegister,
           MemOperand(fp, WasmFrameConstants::kWasmInstanceDataOffset));
    __ LoadTaggedField(
        cp, FieldMemOperand(kWasmImplicitArgRegister,
                            WasmTrustedInstanceData::kNativeContextOffset));
    FrameScope scope(masm, StackFrame::MANUAL);
    __ EnterFrame(StackFrame::INTERNAL);
    __ SmiTag(gap);
    __ PushArgument(gap);
    __ CallRuntime(Runtime::kWasmStackGuard);
    __ LeaveFrame(StackFrame::INTERNAL);
    __ Ret();
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

void Builtins::Generate_DoubleToI(MacroAssembler* masm) {
  Label done;
  Register result = x7;

  DCHECK(result.Is64Bits());

  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  UseScratchRegisterScope temps(masm);
  Register scratch1 = temps.AcquireX();
  Register scratch2 = temps.AcquireX();
  DoubleRegister double_scratch = temps.AcquireD();

  // Account for saved regs.
  const int kArgumentOffset = 2 * kSystemPointerSize;

  __ Push(result, scratch1);  // scratch1 is also pushed to preserve alignment.
  __ Peek(double_scratch, kArgumentOffset);

  // Try to convert with a FPU convert instruction.  This handles all
  // non-saturating cases.
  __ TryConvertDoubleToInt64(result, double_scratch, &done);
  __ Fmov(result, double_scratch);

  // If we reach here we need to manually convert the input to an int32.

  // Extract the exponent.
  Register exponent = scratch1;
  __ Ubfx(exponent, result, HeapNumber::kMantissaBits,
          HeapNumber::kExponentBits);

  // It the exponent is >= 84 (kMantissaBits + 32), the result is always 0 since
  // the mantissa gets shifted completely out of the int32_t result.
  __ Cmp(exponent, HeapNumber::kExponentBias + HeapNumber::kMantissaBits + 32);
  __ CzeroX(result, ge);
  __ B(ge, &done);

  // The Fcvtzs sequence handles all cases except where the conversion causes
  // signed overflow in the int64_t target. Since we've already handled
  // exponents >= 84, we can guarantee that 63 <= exponent < 84.

  if (v8_flags.debug_code) {
    __ Cmp(exponent, HeapNumber::kExponentBias + 63);
    // Exponents less than this should have been handled by the Fcvt case.
    __ Check(ge, AbortReason::kUnexpectedValue);
  }

  // Isolate the mantissa bits, and set the implicit '1'.
  Register mantissa = scratch2;
  __ Ubfx(mantissa, result, 0, HeapNumber::kMantissaBits);
  __ Orr(mantissa, mantissa, 1ULL << HeapNumber::kMantissaBits);

  // Negate the mantissa if necessary.
  __ Tst(result, kXSignMask);
  __ Cneg(mantissa, mantissa, ne);

  // Shift the mantissa bits in the correct place. We know that we have to shift
  // it left here, because exponent >= 63 >= kMantissaBits.
  __ Sub(exponent, exponent,
         HeapNumber::kExponentBias + HeapNumber::kMantissaBits);
  __ Lsl(result, mantissa, exponent);

  __ Bind(&done);
  __ Poke(result, kArgumentOffset);
  __ Pop(scratch1, result);
  __ Ret();
}

void Builtins::Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                            CallApiCallbackMode mode) {
  // ----------- S t a t e -------------
  // CallApiCallbackMode::kOptimizedNoProfiling/kOptimized modes:
  //  -- x1                  : api function address
  // Both modes:
  //  -- x2                  : arguments count (not including the receiver)
  //  -- x3                  : FunctionTemplateInfo
  //  -- x0                  : holder
  //  -- cp                  : context
  //  -- sp[0]               : receiver
  //  -- sp[8]               : first argument
  //  -- ...
  //  -- sp[(argc) * 8]      : last argument
  // -----------------------------------

  Register function_callback_info_arg = kCArgRegs[0];

  Register api_function_address = no_reg;
  Register argc = no_reg;
  Register func_templ = no_reg;
  Register holder = no_reg;
  Register topmost_script_having_context = no_reg;
  Register scratch = x4;

  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      argc = CallApiCallbackGenericDescriptor::ActualArgumentsCountRegister();
      topmost_script_having_context = CallApiCallbackGenericDescriptor::
          TopmostScriptHavingContextRegister();
      func_templ =
          CallApiCallbackGenericDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackGenericDescriptor::HolderRegister();
      break;

    case CallApiCallbackMode::kOptimizedNoProfiling:
    case CallApiCallbackMode::kOptimized:
      // Caller context is always equal to current context because we don't
      // inline Api calls cross-context.
      topmost_script_having_context = kContextRegister;
      api_function_address =
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();
      argc = CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister();
      func_templ =
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister();
      holder = CallApiCallbackOptimizedDescriptor::HolderRegister();
      break;
  }
  DCHECK(!AreAliased(api_function_address, topmost_script_having_context, argc,
                     holder, func_templ, scratch));

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= FCA::implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kData
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:            <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       topmost_script_having_context);

  if (mode == CallApiCallbackMode::kGeneric) {
    api_function_address = ReassignRegister(topmost_script_having_context);
  }

  // Reserve space on the stack.
  static constexpr int kStackSize = FCA::kArgsLength;
  static_assert(kStackSize % 2 == 0);
  __ Claim(kStackSize, kSystemPointerSize);

  // kHolder.
  __ Str(holder, MemOperand(sp, FCA::kHolderIndex * kSystemPointerSize));

  // kIsolate.
  __ Mov(scratch, ER::isolate_address());
  __ Str(scratch, MemOperand(sp, FCA::kIsolateIndex * kSystemPointerSize));

  // kContext.
  __ Str(cp, MemOperand(sp, FCA::kContextIndex * kSystemPointerSize));

  // kReturnValue.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  __ Str(scratch, MemOperand(sp, FCA::kReturnValueIndex * kSystemPointerSize));

  // kTarget.
  __ Str(func_templ, MemOperand(sp, FCA::kTargetIndex * kSystemPointerSize));

  // kNewTarget.
  __ Str(scratch, MemOperand(sp, FCA::kNewTargetIndex * kSystemPointerSize));

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  if (mode == CallApiCallbackMode::kGeneric) {
    __ LoadExternalPointerField(
        api_function_address,
        FieldMemOperand(func_templ,
                        FunctionTemplateInfo::kMaybeRedirectedCallbackOffset),
        kFunctionTemplateInfoCallbackTag);
  }

  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_CALLBACK_EXIT);

  // This is a workaround for performance regression observed on Apple Silicon
  // (https://crbug.com/347741609): reading argc value after the call via
  //   MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  // is noticeably slower than using sp-based access:
  MemOperand argc_operand = ExitFrameStackSlotOperand(FCA::kLengthOffset);
  if (v8_flags.debug_code) {
    // Ensure sp-based calculation of FC::length_'s address matches the
    // fp-based one.
    Label ok;
    // +kSystemPointerSize is for the slot at [sp] which is reserved in all
    // ExitFrames for storing the return PC.
    __ Add(scratch, sp,
           FCA::kLengthOffset + kSystemPointerSize - FC::kFCIArgcOffset);
    __ cmp(scratch, fp);
    __ B(eq, &ok);
    __ DebugBreak();
    __ Bind(&ok);
  }
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    // TODO(ishell): pass JSParameterCount(argc) to simplify things on the
    // caller end.
    __ Str(argc, argc_operand);

    // FunctionCallbackInfo::implicit_args_.
    __ Add(scratch, fp, Operand(FC::kImplicitArgsArrayOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIImplicitArgsOffset));

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ Add(scratch, fp, Operand(FC::kFirstArgumentOffset));
    __ Str(scratch, MemOperand(fp, FC::kFCIValuesOffset));
  }

  __ RecordComment("v8::FunctionCallback's argument.");
  // function_callback_info_arg = v8::FunctionCallbackInfo&
  __ Add(function_callback_info_arg, fp,
         Operand(FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  ExternalReference thunk_ref = ER::invoke_function_callback(mode);
  Register no_thunk_arg = no_reg;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots;

  const bool with_profiling =
      mode != CallApiCallbackMode::kOptimizedNoProfiling;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           &argc_operand, return_value_operand);
}

void Builtins::Generate_CallApiGetter(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- cp                  : context
  //  -- x1                  : receiver
  //  -- x3                  : accessor info
  //  -- x0                  : holder
  // -----------------------------------

  Register name_arg = kCArgRegs[0];
  Register property_callback_info_arg = kCArgRegs[1];

  Register api_function_address = x2;
  Register receiver = ApiGetterDescriptor::ReceiverRegister();
  Register holder = ApiGetterDescriptor::HolderRegister();
  Register callback = ApiGetterDescriptor::CallbackRegister();
  Register scratch = x4;
  Register undef = x5;
  Register scratch2 = x6;

  DCHECK(!AreAliased(receiver, holder, callback, scratch, undef, scratch2));

  // Build v8::PropertyCallbackInfo::args_ array on the stack and push property
  // name below the exit frame to make GC aware of them.
  using PCA = PropertyCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiAccessorExitFrameConstants;

  static_assert(PCA::kPropertyKeyIndex == 0);
  static_assert(PCA::kShouldThrowOnErrorIndex == 1);
  static_assert(PCA::kHolderIndex == 2);
  static_assert(PCA::kIsolateIndex == 3);
  static_assert(PCA::kHolderV2Index == 4);
  static_assert(PCA::kReturnValueIndex == 5);
  static_assert(PCA::kDataIndex == 6);
  static_assert(PCA::kThisIndex == 7);
  static_assert(PCA::kArgsLength == 8);

  // Set up v8::PropertyCallbackInfo's (PCI) args_ on the stack as follows:
  // Target state:
  //   sp[0 * kSystemPointerSize]: name                      <= PCI::args_
  //   sp[1 * kSystemPointerSize]: kShouldThrowOnErrorIndex
  //   sp[2 * kSystemPointerSize]: kHolderIndex
  //   sp[3 * kSystemPointerSize]: kIsolateIndex
  //   sp[4 * kSystemPointerSize]: kHolderV2Index
  //   sp[5 * kSystemPointerSize]: kReturnValueIndex
  //   sp[6 * kSystemPointerSize]: kDataIndex
  //   sp[7 * kSystemPointerSize]: kThisIndex / receiver

  __ LoadTaggedField(scratch,
                     FieldMemOperand(callback, AccessorInfo::kDataOffset));
  __ LoadRoot(undef, RootIndex::kUndefinedValue);
  __ Mov(scratch2, ER::isolate_address());
  Register holderV2 = xzr;
  __ Push(receiver, scratch,  // kThisIndex, kDataIndex
          undef, holderV2,    // kReturnValueIndex, kHolderV2Index
          scratch2, holder);  // kIsolateIndex, kHolderIndex

  // |name_arg| clashes with |holder|, so we need to push holder first.
  __ LoadTaggedField(name_arg,
                     FieldMemOperand(callback, AccessorInfo::kNameOffset));
  static_assert(kDontThrow == 0);
  Register should_throw_on_error = xzr;  // should_throw_on_error -> kDontThrow
  __ Push(should_throw_on_error, name_arg);

  __ RecordComment("Load api_function_address");
  __ LoadExternalPointerField(
      api_function_address,
      FieldMemOperand(callback, AccessorInfo::kMaybeRedirectedGetterOffset),
      kAccessorInfoGetterTag);

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EnterExitFrame(scratch, FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                    StackFrame::API_ACCESSOR_EXIT);

  __ RecordComment("Create v8::PropertyCallbackInfo object on the stack.");
  // property_callback_info_arg = v8::PropertyCallbackInfo&
  __ Add(property_callback_info_arg, fp, Operand(FC::kArgsArrayOffset));

  DCHECK(!AreAliased(api_function_address, property_callback_info_arg, name_arg,
                     callback, scratch, scratch2));

#ifdef V8_ENABLE_DIRECT_HANDLE
  // name_arg = Local<Name>(name), name value was pushed to GC-ed stack space.
  // |name_arg| is already initialized above.
#else
  // name_arg = Local<Name>(&name), which is &args_array[kPropertyKeyIndex].
  static_assert(PCA::kPropertyKeyIndex == 0);
  __ mov(name_arg, property_callback_info_arg);
#endif

  ExternalReference thunk_ref = ER::invoke_accessor_getter_callback();
  // Pass AccessorInfo to thunk wrapper in case profiler or side-effect
  // checking is enabled.
  Register thunk_arg = callback;

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  static constexpr int kSlotsToDropOnReturn =
      FC::kPropertyCallbackInfoArgsLength;
  MemOperand* const kUseStackSpaceConstant = nullptr;

  const bool with_profiling = true;
  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           thunk_ref, thunk_arg, kSlotsToDropOnReturn,
                           kUseStackSpaceConstant, return_value_operand);
}

void Builtins::Generate_DirectCEntry(MacroAssembler* masm) {
  // The sole purpose of DirectCEntry is for movable callers (e.g. any general
  // purpose InstructionStream object) to be able to call into C functions that
  // may trigger GC and thus move the caller.
  //
  // DirectCEntry places the return address on the stack (updated by the GC),
  // making the call GC safe. The irregexp backend relies on this.

  __ Poke<MacroAssembler::kSignLR>(lr, 0);  // Store the return address.
  __ Blr(x10);                              // Call the C++ function.
  __ Peek<MacroAssembler::kAuthLR>(lr, 0);  // Return to calling code.
  __ AssertFPCRState();
  __ Ret();
}

namespace {

template <typename RegisterT>
void CopyRegListToFrame(MacroAssembler* masm, const Register& dst,
                        int dst_offset, const CPURegList& reg_list,
                        const RegisterT& temp0, const RegisterT& temp1,
                        int src_offset = 0) {
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(reg_list.Count() % 2, 0);
  UseScratchRegisterScope temps(masm);
  CPURegList copy_to_input = reg_list;
  int reg_size = reg_list.RegisterSizeInBytes();
  DCHECK_EQ(temp0.SizeInBytes(), reg_size);
  DCHECK_EQ(temp1.SizeInBytes(), reg_size);

  // Compute some temporary addresses to avoid having the macro assembler set
  // up a temp with an offset for accesses out of the range of the addressing
  // mode.
  Register src = temps.AcquireX();
  masm->Add(src, sp, src_offset);
  masm->Add(dst, dst, dst_offset);

  // Write reg_list into the frame pointed to by dst.
  for (int i = 0; i < reg_list.Count(); i += 2) {
    masm->Ldp(temp0, temp1, MemOperand(src, i * reg_size));

    CPURegister reg0 = copy_to_input.PopLowestIndex();
    CPURegister reg1 = copy_to_input.PopLowestIndex();
    int offset0 = reg0.code() * reg_size;
    int offset1 = reg1.code() * reg_size;

    // Pair up adjacent stores, otherwise write them separately.
    if (offset1 == offset0 + reg_size) {
      masm->Stp(temp0, temp1, MemOperand(dst, offset0));
    } else {
      masm->Str(temp0, MemOperand(dst, offset0));
      masm->Str(temp1, MemOperand(dst, offset1));
    }
  }
  masm->Sub(dst, dst, dst_offset);
}

void RestoreRegList(MacroAssembler* masm, const CPURegList& reg_list,
                    const Register& src_base, int src_offset) {
  ASM_CODE_COMMENT(masm);
  DCHECK_EQ(reg_list.Count() % 2, 0);
  UseScratchRegisterScope temps(masm);
  CPURegList restore_list = reg_list;
  int reg_size = restore_list.RegisterSizeInBytes();

  // Compute a temporary addresses to avoid having the macro assembler set
  // up a temp with an offset for accesses out of the range of the addressing
  // mode.
  Register src = temps.AcquireX();
  masm->Add(src, src_base, src_offset);

  // No need to restore padreg.
  restore_list.Remove(padreg);

  // Restore every register in restore_list from src.
  while (!restore_list.IsEmpty()) {
    CPURegister reg0 = restore_list.PopLowestIndex();
    CPURegister reg1 = restore_list.PopLowestIndex();
    int offset0 = reg0.code() * reg_size;

    if (reg1 == NoCPUReg) {
      masm->Ldr(reg0, MemOperand(src, offset0));
      break;
    }

    int offset1 = reg1.code() * reg_size;

    // Pair up adjacent loads, otherwise read them separately.
    if (offset1 == offset0 + reg_size) {
      masm->Ldp(reg0, reg1, MemOperand(src, offset0));
    } else {
      masm->Ldr(reg0, MemOperand(src, offset0));
      masm->Ldr(reg1, MemOperand(src, offset1));
    }
  }
}

void Generate_DeoptimizationEntry(MacroAssembler* masm,
                                  DeoptimizeKind deopt_kind) {
  Isolate* isolate = masm->isolate();

  // TODO(all): This code needs to be revisited. We probably only need to save
  // caller-saved registers here. Callee-saved registers can be stored directly
  // in the input frame.

  // Save all allocatable simd128 / double registers.
  CPURegList saved_simd128_registers(
      kQRegSizeInBits,
      DoubleRegList::FromBits(
          RegisterConfiguration::Default()->allocatable_simd128_codes_mask()));
  DCHECK_EQ(saved_simd128_registers.Count() % 2, 0);
  __ PushCPURegList(saved_simd128_registers);

  // We save all the registers except sp, lr, platform register (x18) and the
  // masm scratches.
  CPURegList saved_registers(CPURegister::kRegister, kXRegSizeInBits, 0, 28);
  saved_registers.Remove(ip0);
  saved_registers.Remove(ip1);
  saved_registers.Remove(x18);
  saved_registers.Combine(fp);
  saved_registers.Align();
  DCHECK_EQ(saved_registers.Count() % 2, 0);
  __ PushCPURegList(saved_registers);

  __ Mov(x3, Operand(ExternalReference::Create(
                 IsolateAddressId::kCEntryFPAddress, isolate)));
  __ Str(fp, MemOperand(x3));

  const int kSavedRegistersAreaSize =
      (saved_registers.Count() * kXRegSize) +
      (saved_simd128_registers.Count() * kQRegSize);

  // Floating point registers are s
"""


```