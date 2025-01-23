Response:
The user wants a summary of the functionality of the provided IA-32 assembly code for V8. I need to identify the different built-in functions implemented in this file and explain their purpose.

Here's a breakdown of the thought process to analyze the code:

1. **Identify Built-in Functions:** Look for the `Builtins::Generate_` prefix. This clearly indicates the start of a built-in function implementation.

2. **Analyze Each Function:**  For each built-in function, carefully examine the assembly instructions and comments. Pay attention to:
    * **State Comments:**  These comments describe the register contents at the beginning of the function.
    * **Register Usage:** Track how registers are loaded, manipulated, and used.
    * **Function Calls:** Note calls to other built-ins (`TailCallBuiltin`) and runtime functions (`CallRuntime`).
    * **Conditional Jumps:** Understand the conditions under which different code paths are taken.
    * **Stack Manipulation:** Observe `push`, `pop`, and stack frame setup.

3. **Relate to JavaScript Concepts:** If a built-in function appears to be related to a JavaScript feature, try to connect it and provide a JavaScript example. Look for keywords like "Call," "Construct," "BoundFunction," etc.

4. **Infer Input and Output:** Based on the register state and the operations performed, deduce what the expected inputs and outputs of the function are.

5. **Identify Potential Errors:** Look for scenarios where the code checks for specific types or conditions and what happens if those conditions are not met. These often relate to common programming errors.

6. **Consider `.tq` Files (Torque):**  The prompt mentions `.tq` files. While this file is `.cc`, it's important to keep in mind that some of the logic might be defined in Torque and then lowered to assembly.

7. **Structure the Summary:** Organize the findings logically, grouping related functionalities together. Use clear and concise language. Address all the specific points raised in the prompt (functionality, `.tq`, JavaScript examples, input/output, errors).

**Applying the Process to the Code:**

* **`Builtins::Generate_CallFunction`:**  This handles regular function calls. It checks if the receiver needs to be converted to an object and then jumps to the actual function invocation.
* **`Builtins::Generate_PushBoundArguments`:** This helper function is used by bound functions to push their bound arguments onto the stack.
* **`Builtins::Generate_CallBoundFunctionImpl`:** Implements calling bound functions. It sets the receiver and calls the target function.
* **`Builtins::Generate_Call`:** A higher-level call handler that dispatches to different call implementations based on the target's type (JSFunction, BoundFunction, Proxy, etc.).
* **`Builtins::Generate_ConstructFunction`:**  Handles the `new` operator for regular JavaScript functions. It distinguishes between built-in constructors and regular ones.
* **`Builtins::Generate_ConstructBoundFunction`:** Handles the `new` operator for bound functions.
* **`Builtins::Generate_Construct`:** A high-level `new` operator handler, similar to `Generate_Call`, dispatching based on the constructor's type.
* **`Builtins::Generate_OSREntry`:** Deals with On-Stack Replacement (OSR) entry, allowing optimized code to take over execution.
* **`Builtins::Generate_InterpreterOnStackReplacement` / `Builtins::Generate_BaselineOnStackReplacement`:** Specific OSR entry points for interpreter and baseline code.
* **`Builtins::Generate_WasmLiftoffFrameSetup`:**  Sets up the stack frame for WebAssembly Liftoff execution.
* **`Builtins::Generate_WasmCompileLazy`:** Handles lazy compilation of WebAssembly functions.
* **`Builtins::Generate_WasmDebugBreak`:** Implements a WebAssembly debug break.
* **Code related to Continuations and Stack Switching:**  This section is more complex, dealing with advanced features like asynchronous operations and stack manipulation for WebAssembly.

By systematically analyzing each function, I can build a comprehensive understanding of the file's functionality and address all the user's requirements. The key is to break down the code into manageable parts and understand the purpose of each instruction and code block.
```cpp
  __ mov(ecx, eax);
        __ Pop(edi);
        __ Pop(eax);
        __ SmiUntag(eax);
      }
      __ mov(edx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ mov(args.GetReceiverOperand(), ecx);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the shared function info.
  //  -- edi : the function to call (checked to be a JSFunction)
  //  -- esi : the function context.
  // -----------------------------------

  __ movzx_w(
      ecx, FieldOperand(edx, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(edi, no_reg, ecx, eax, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : new.target (only in case of [[Construct]])
  //  -- edi : target (checked to be a JSBoundFunction)
  // -----------------------------------
  __ movd(xmm0, edx);  // Spill edx.

  // Load [[BoundArguments]] into ecx and length of that into edx.
  Label no_bound_arguments;
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
  __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
  __ SmiUntag(edx);
  __ test(edx, edx);
  __ j(zero, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- eax  : the number of arguments
    //  -- xmm0 : new.target (only in case of [[Construct]])
    //  -- edi  : target (checked to be a JSBoundFunction)
    //  -- ecx  : the [[BoundArguments]] (implemented as FixedArray)
    //  -- edx  : the number of [[BoundArguments]]
    // -----------------------------------

    // Check the stack for overflow.
    {
      Label done, stack_overflow;
      __ StackOverflowCheck(edx, ecx, &stack_overflow);
      __ jmp(&done);
      __ bind(&stack_overflow);
      {
        FrameScope frame(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
        __ int3();
      }
      __ bind(&done);
    }

    // Spill context.
    __ movd(xmm3, esi);

    // Save Return Address and Receiver into registers.
    __ pop(esi);
    __ movd(xmm1, esi);
    __ pop(esi);
    __ movd(xmm2, esi);

    // Push [[BoundArguments]] to the stack.
    {
      Label loop;
      __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
      __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
      __ SmiUntag(edx);
      // Adjust effective number of arguments (eax contains the number of
      // arguments from the call not including receiver plus the number of
      // [[BoundArguments]]).
      __ add(eax, edx);
      __ bind(&loop);
      __ dec(edx);
      __ mov(esi, FieldOperand(ecx, edx, times_tagged_size,
                               OFFSET_OF_DATA_START(FixedArray)));
      __ push(esi);
      __ j(greater, &loop);
    }

    // Restore Receiver and Return Address.
    __ movd(esi, xmm2);
    __ push(esi);
    __ movd(esi, xmm1);
    __ push(esi);

    // Restore context.
    __ movd(esi, xmm3);
  }

  __ bind(&no_bound_arguments);
  __ movd(edx, xmm0);  // Reload edx.
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(edi);

  // Patch the receiver to [[BoundThis]].
  StackArgumentsAccessor args(eax);
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundThisOffset));
  __ mov(args.GetReceiverOperand(), ecx);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the target to call (can be any Object).
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  Register instance_type = edx;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  Label non_callable, non_smi, non_callable_jsfunction, non_jsboundfunction,
      non_proxy, non_wrapped_function, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ bind(&non_smi);
  __ LoadMap(map, target);
  __ CmpInstanceTypeRange(map, instance_type, map,
                          FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ j(above, &non_callable_jsfunction);
  __ TailCallBuiltin(Builtins::CallFunction(mode));

  __ bind(&non_callable_jsfunction);
  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kCallBoundFunction);

  // Check if target is a proxy and call CallProxy external builtin
  __ bind(&non_jsboundfunction);
  __ LoadMap(map, target);
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsCallableBit::kMask));
  __ j(zero, &non_callable);

  // Call CallProxy external builtin
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kCallProxy);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ bind(&non_proxy);
  __ cmpw(instance_type, Immediate(JS_WRAPPED_FUNCTION_TYPE));
  __ j(not_equal, &non_wrapped_function);
  __ TailCallBuiltin(Builtin::kCallWrappedFunction);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ bind(&non_wrapped_function);
  __ cmpw(instance_type, Immediate(JS_CLASS_CONSTRUCTOR_TYPE));
  __ j(equal, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ mov(args.GetReceiverOperand(), target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Trap();  // Unreachable.
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Trap();  // Unreachable.
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertFunction(edi, ecx);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ test(FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(zero, &call_generic_stub, Label::kNear);

  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertBoundFunction(edi);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ cmp(edi, edx);
    __ j(not_equal, &done, Label::kNear);
    __ mov(edx, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- edi : the constructor to call (can be any Object)
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  DCHECK(!AreAliased(argc, target, map));

  StackArgumentsAccessor args(argc);

  // Check if target is a Smi.
  Label non_constructor, non_proxy, non_jsfunction, non_jsboundfunction;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Dispatch based on instance type.
  __ CmpInstanceTypeRange(map, map, map, FIRST_JS_FUNCTION_TYPE,
                          LAST_JS_FUNCTION_TYPE);
  __ j(above, &non_jsfunction);
  __ TailCallBuiltin(Builtin::kConstructFunction);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ bind(&non_jsfunction);
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ CmpInstanceType(map, JS_BOUND_FUNCTION_TYPE);
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kConstructBoundFunction);

  // Only dispatch to proxies after checking whether they are constructors.
  __ bind(&non_jsboundfunction);
  __ CmpInstanceType(map, JS_PROXY_TYPE);
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ mov(args.GetReceiverOperand(), target);
    // Let the "call_as_constructor_delegate" take care of the rest.
    __ LoadNativeContextSlot(target,
                             Context::CALL_AS_CONSTRUCTOR_DELEGATE_INDEX);
    __ TailCallBuiltin(Builtins::CallFunction());
  }

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address) {
  ASM_CODE_COMMENT(masm);
  // Overwrite the return address on the stack.
  __ mov(Operand(esp, 0), entry_address);

  // And "return" to the OSR entry point of the function.
  __ ret(0);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ cmp(maybe_target_code, Immediate(0));
    __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ cmp(eax, Immediate(0));
  __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  __ ret(0);

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, eax);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ cmpb(__ ExternalReferenceAsOperand(
                ExternalReference::address_of_log_or_trace_osr(), ecx),
            Immediate(0));
    __ j(equal, &next, Label::kNear);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(eax);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(eax);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ leave();
  }

  // Load deoptimization data from the code object.
  __ mov(ecx, Operand(eax, Code::kDeoptimizationDataOrInterpreterDataOffset -
                               kHeapObjectTag));

  // Load the OSR entrypoint offset from the deoptimization data.
  __ mov(ecx, Operand(ecx, FixedArray::OffsetOfElementAt(
                               DeoptimizationData::kOsrPcOffsetIndex) -
                               kHeapObjectTag));
  __ SmiUntag(ecx);

  __ LoadCodeInstructionStart(eax, eax);

  // Compute the target address = code_entry + osr_offset
  __ add(eax, ecx);

  Generate_OSREntry(masm, eax);
}

}  // namespace

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ mov(kContextRegister,
         MemOperand(ebp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

#if V8_ENABLE_WEBASSEMBLY

// Returns the offset beyond the last saved FP register.
int SaveWasmParams(MacroAssembler* masm) {
  // Save all parameter registers (see wasm-linkage.h). They might be
  // overwritten in the subsequent runtime call. We don't have any callee-saved
  // registers in wasm, so no need to store anything else.
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1 ==
                    arraysize(wasm::kGpParamRegisters),
                "frame size mismatch");
  for (Register reg : wasm::kGpParamRegisters) {
    __ Push(reg);
  }
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs ==
                    arraysize(wasm::kFpParamRegisters),
                "frame size mismatch");
  __ AllocateStackSpace(kSimd128Size * arraysize(wasm::kFpParamRegisters));
  int offset = 0;
  for (DoubleRegister reg : wasm::kFpParamRegisters) {
    __ movdqu(Operand(esp, offset), reg);
    offset += kSimd128Size;
  }
  return offset;
}

// Consumes the offset beyond the last saved FP register (as returned by
// {SaveWasmParams}).
void RestoreWasmParams(MacroAssembler* masm, int offset) {
  for (DoubleRegister reg : base::Reversed(wasm::kFpParamRegisters)) {
    offset -= kSimd128Size;
    __ movdqu(reg, Operand(esp, offset));
  }
  DCHECK_EQ(0, offset);
  __ add(esp, Immediate(kSimd128Size * arraysize(wasm::kFpParamRegisters)));
  for (Register reg : base::Reversed(wasm::kGpParamRegisters)) {
    __ Pop(reg);
  }
}

// When this builtin is called, the topmost stack entry is the calling pc.
// This is replaced with the following:
//
// [    calling pc      ]  <-- esp; popped by {ret}.
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [    saved ebp       ]  <-- ebp; this is where "calling pc" used to be.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  constexpr Register func_index = wasm::kLiftoffFrameSetupFunctionReg;

  // We have zero free registers at this point. Free up a temp. Its value
  // could be tagged, but we're only storing it on the stack for a short
  // while, and no GC or stack walk can happen during this time.
  Register tmp = eax;  // Arbitrarily chosen.
  __ Push(tmp);        // This is the "marker" slot.
  {
    Operand saved_ebp_slot = Operand(esp, kSystemPointerSize);
    __ mov(tmp, saved_ebp_slot);  // tmp now holds the "calling pc".
    __ mov(saved_ebp_slot, ebp);
    __ lea(ebp, Operand(esp, kSystemPointerSize));
  }
  __ Push(tmp);  // This is the "instance" slot.

  // Stack layout is now:
  // [calling pc]  <-- instance_data_slot  <-- esp
  // [saved tmp]   <-- marker_slot
  // [saved ebp]
  Operand marker_slot = Operand(ebp, WasmFrameConstants::kFrameTypeOffset);
  Operand instance_data_slot =
      Operand(ebp, WasmFrameConstants::kWasmInstanceDataOffset);

  // Load the feedback vector from the trusted instance data.
  __ mov(tmp, FieldOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ mov(tmp, FieldOperand(tmp, func_index, times_tagged_size,
                           OFFSET_OF_DATA_START(FixedArray)));
  Label allocate_vector;
  __ JumpIfSmi(tmp, &allocate_vector);

  // Vector exists. Finish setting up the stack frame.
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ mov(tmp, marker_slot);
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ ret(0);

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  // For the runtime call, we create the following stack layout:
  //
  // [ reserved slot for NativeModule ]  <-- arg[2]
  // [  ("declared") function index   ]  <-- arg[1] for runtime func.
  // [       Wasm instance data       ]  <-- arg[0]
  // [ ...spilled Wasm parameters... ]
  // [           calling pc           ]  <-- already in place
  // [   WASM_LIFTOFF_SETUP marker    ]
  // [           saved ebp            ]  <-- already in place

  __ mov(tmp, marker_slot);
  __ mov(marker_slot,
         Immediate(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));

  int offset = SaveWasmParams(masm);

  // Arguments to the runtime function: instance, func_index.
  __ Push(kWasmImplicitArgRegister);
  __ SmiTag(func_index);
  __ Push(func_index);
  // Allocate a stack slot where the runtime function can spill a pointer
  // to the NativeModule.
  __ Push(esp);
  __ Move(kContextRegister, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  tmp = func_index;
  __ mov(tmp, kReturnRegister0);

  RestoreWasmParams(masm, offset);

  // Finish setting up the stack frame:
  //                             [    calling pc      ]
  //              (tmp reg) ---> [  feedback vector   ]
  // [     calling pc     ]  =>  [ Wasm instance data ]  <-- instance_data_slot
  // [ WASM_LIFTOFF_SETUP ]      [       WASM         ]  <-- marker_slot
  // [      saved ebp     ]      [    saved ebp       ]
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ ret(0);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in edi by the jump table trampoline.
  // Convert to Smi for the runtime call.
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);
  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);
    int offset = SaveWasmParams(masm);

    // Push arguments for the runtime function.
    __ Push(kWasmImplicitArgRegister);
    __ Push(kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);
    // The runtime function returns the jump table slot offset as a Smi. Use
    // that to compute the jump target in edi.
    __ SmiUntag(kReturnRegister0);
    __ mov(edi, kReturnRegister0);

    RestoreWasmParams(masm, offset);

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in edi.
    __ add(edi, MemOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kJumpTableStartOffset -
                               kHeapObjectTag));
  }

  // Finally, jump to the jump table slot for the function.
  __ jmp(edi);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    for (Register reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedGpRegs)) {
      __ Push(reg);
    }

    constexpr int kFpStackSize =
        kSimd128Size * WasmDebugBreakFrameConstants::kNumPushedFpRegisters;
    __ AllocateStackSpace(kFpStackSize);
    int offset = kFpStackSize;
    for (DoubleRegister reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedFpRegs)) {
      offset -= kSimd128Size;
      __ movdqu(Operand(esp, offset), reg);
    }

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    for (DoubleRegister reg : WasmDebugBreakFrameConstants::kPushedFpRegs) {
      __ movdqu(reg, Operand(esp, offset));
      offset += kSimd128Size;
    }
    __ add(esp, Immediate(kFpStackSize));
    for (Register reg : WasmDebugBreakFrameConstants::kPushedGpRegs) {
      __ Pop(reg);
    }
  }

  __ ret(0);
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  __ cmp(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(old_state));
  Label ok;
  __ j(equal, &ok, Label::kNear);
  __ Trap();
  __ bind(&ok);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(new_state));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Register scratch,
                    Label* pc) {
  DCHECK(!AreAliased(scratch, jmpbuf));

  __ mov(MemOperand(jmpbuf, wasm::kJmpBufSpOffset), esp);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufFpOffset), ebp);
  __ mov(scratch, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset), scratch);
  __ LoadLabelAddress(scratch, pc);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufPcOffset), scratch);
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    wasm::JumpBuffer::StackState expected_state) {
  __ mov(esp, MemOperand(jmpbuf, wasm::kJmpBufSp
### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
__ mov(ecx, eax);
        __ Pop(edi);
        __ Pop(eax);
        __ SmiUntag(eax);
      }
      __ mov(edx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ mov(args.GetReceiverOperand(), ecx);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the shared function info.
  //  -- edi : the function to call (checked to be a JSFunction)
  //  -- esi : the function context.
  // -----------------------------------

  __ movzx_w(
      ecx, FieldOperand(edx, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(edi, no_reg, ecx, eax, InvokeType::kJump);
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : new.target (only in case of [[Construct]])
  //  -- edi : target (checked to be a JSBoundFunction)
  // -----------------------------------
  __ movd(xmm0, edx);  // Spill edx.

  // Load [[BoundArguments]] into ecx and length of that into edx.
  Label no_bound_arguments;
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
  __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
  __ SmiUntag(edx);
  __ test(edx, edx);
  __ j(zero, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- eax  : the number of arguments
    //  -- xmm0 : new.target (only in case of [[Construct]])
    //  -- edi  : target (checked to be a JSBoundFunction)
    //  -- ecx  : the [[BoundArguments]] (implemented as FixedArray)
    //  -- edx  : the number of [[BoundArguments]]
    // -----------------------------------

    // Check the stack for overflow.
    {
      Label done, stack_overflow;
      __ StackOverflowCheck(edx, ecx, &stack_overflow);
      __ jmp(&done);
      __ bind(&stack_overflow);
      {
        FrameScope frame(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
        __ int3();
      }
      __ bind(&done);
    }

    // Spill context.
    __ movd(xmm3, esi);

    // Save Return Address and Receiver into registers.
    __ pop(esi);
    __ movd(xmm1, esi);
    __ pop(esi);
    __ movd(xmm2, esi);

    // Push [[BoundArguments]] to the stack.
    {
      Label loop;
      __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundArgumentsOffset));
      __ mov(edx, FieldOperand(ecx, offsetof(FixedArray, length_)));
      __ SmiUntag(edx);
      // Adjust effective number of arguments (eax contains the number of
      // arguments from the call not including receiver plus the number of
      // [[BoundArguments]]).
      __ add(eax, edx);
      __ bind(&loop);
      __ dec(edx);
      __ mov(esi, FieldOperand(ecx, edx, times_tagged_size,
                               OFFSET_OF_DATA_START(FixedArray)));
      __ push(esi);
      __ j(greater, &loop);
    }

    // Restore Receiver and Return Address.
    __ movd(esi, xmm2);
    __ push(esi);
    __ movd(esi, xmm1);
    __ push(esi);

    // Restore context.
    __ movd(esi, xmm3);
  }

  __ bind(&no_bound_arguments);
  __ movd(edx, xmm0);  // Reload edx.
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(edi);

  // Patch the receiver to [[BoundThis]].
  StackArgumentsAccessor args(eax);
  __ mov(ecx, FieldOperand(edi, JSBoundFunction::kBoundThisOffset));
  __ mov(args.GetReceiverOperand(), ecx);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edi : the target to call (can be any Object).
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  Register instance_type = edx;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  Label non_callable, non_smi, non_callable_jsfunction, non_jsboundfunction,
      non_proxy, non_wrapped_function, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ bind(&non_smi);
  __ LoadMap(map, target);
  __ CmpInstanceTypeRange(map, instance_type, map,
                          FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ j(above, &non_callable_jsfunction);
  __ TailCallBuiltin(Builtins::CallFunction(mode));

  __ bind(&non_callable_jsfunction);
  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kCallBoundFunction);

  // Check if target is a proxy and call CallProxy external builtin
  __ bind(&non_jsboundfunction);
  __ LoadMap(map, target);
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsCallableBit::kMask));
  __ j(zero, &non_callable);

  // Call CallProxy external builtin
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kCallProxy);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ bind(&non_proxy);
  __ cmpw(instance_type, Immediate(JS_WRAPPED_FUNCTION_TYPE));
  __ j(not_equal, &non_wrapped_function);
  __ TailCallBuiltin(Builtin::kCallWrappedFunction);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ bind(&non_wrapped_function);
  __ cmpw(instance_type, Immediate(JS_CLASS_CONSTRUCTOR_TYPE));
  __ j(equal, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).
  // Overwrite the original receiver with the (original) target.
  __ mov(args.GetReceiverOperand(), target);
  // Let the "call_as_function_delegate" take care of the rest.
  __ LoadNativeContextSlot(target, Context::CALL_AS_FUNCTION_DELEGATE_INDEX);
  __ TailCallBuiltin(
      Builtins::CallFunction(ConvertReceiverMode::kNotNullOrUndefined));

  // 3. Call to something that is not callable.
  __ bind(&non_callable);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowCalledNonCallable);
    __ Trap();  // Unreachable.
  }

  // 4. The function is a "classConstructor", need to raise an exception.
  __ bind(&class_constructor);
  {
    FrameScope frame(masm, StackFrame::INTERNAL);
    __ Push(target);
    __ CallRuntime(Runtime::kThrowConstructorNonCallableError);
    __ Trap();  // Unreachable.
  }
}

// static
void Builtins::Generate_ConstructFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertFunction(edi, ecx);

  Label call_generic_stub;

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ test(FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(zero, &call_generic_stub, Label::kNear);

  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub);

  __ bind(&call_generic_stub);
  // Calling convention for function specific ConstructStubs require
  // ecx to contain either an AllocationSite or undefined.
  __ LoadRoot(ecx, RootIndex::kUndefinedValue);
  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (checked to be a constructor)
  //  -- edi : the constructor to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertConstructor(edi);
  __ AssertBoundFunction(edi);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ cmp(edi, edx);
    __ j(not_equal, &done, Label::kNear);
    __ mov(edx, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ mov(edi, FieldOperand(edi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- edx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- edi : the constructor to call (can be any Object)
  // -----------------------------------
  Register argc = eax;
  Register target = edi;
  Register map = ecx;
  DCHECK(!AreAliased(argc, target, map));

  StackArgumentsAccessor args(argc);

  // Check if target is a Smi.
  Label non_constructor, non_proxy, non_jsfunction, non_jsboundfunction;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ test_b(FieldOperand(map, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Dispatch based on instance type.
  __ CmpInstanceTypeRange(map, map, map, FIRST_JS_FUNCTION_TYPE,
                          LAST_JS_FUNCTION_TYPE);
  __ j(above, &non_jsfunction);
  __ TailCallBuiltin(Builtin::kConstructFunction);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ bind(&non_jsfunction);
  __ mov(map, FieldOperand(target, HeapObject::kMapOffset));
  __ CmpInstanceType(map, JS_BOUND_FUNCTION_TYPE);
  __ j(not_equal, &non_jsboundfunction);
  __ TailCallBuiltin(Builtin::kConstructBoundFunction);

  // Only dispatch to proxies after checking whether they are constructors.
  __ bind(&non_jsboundfunction);
  __ CmpInstanceType(map, JS_PROXY_TYPE);
  __ j(not_equal, &non_proxy);
  __ TailCallBuiltin(Builtin::kConstructProxy);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  __ bind(&non_proxy);
  {
    // Overwrite the original receiver with the (original) target.
    __ mov(args.GetReceiverOperand(), target);
    // Let the "call_as_constructor_delegate" take care of the rest.
    __ LoadNativeContextSlot(target,
                             Context::CALL_AS_CONSTRUCTOR_DELEGATE_INDEX);
    __ TailCallBuiltin(Builtins::CallFunction());
  }

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
}

namespace {

void Generate_OSREntry(MacroAssembler* masm, Register entry_address) {
  ASM_CODE_COMMENT(masm);
  // Overwrite the return address on the stack.
  __ mov(Operand(esp, 0), entry_address);

  // And "return" to the OSR entry point of the function.
  __ ret(0);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ cmp(maybe_target_code, Immediate(0));
    __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  }

  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ cmp(eax, Immediate(0));
  __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  __ ret(0);

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, eax);  // Already in the right spot.

  // OSR entry tracing.
  {
    Label next;
    __ cmpb(__ ExternalReferenceAsOperand(
                ExternalReference::address_of_log_or_trace_osr(), ecx),
            Immediate(0));
    __ j(equal, &next, Label::kNear);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(eax);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(eax);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame. This is the case then OSR is triggered from bytecode.
    __ leave();
  }

  // Load deoptimization data from the code object.
  __ mov(ecx, Operand(eax, Code::kDeoptimizationDataOrInterpreterDataOffset -
                               kHeapObjectTag));

  // Load the OSR entrypoint offset from the deoptimization data.
  __ mov(ecx, Operand(ecx, FixedArray::OffsetOfElementAt(
                               DeoptimizationData::kOsrPcOffsetIndex) -
                               kHeapObjectTag));
  __ SmiUntag(ecx);

  __ LoadCodeInstructionStart(eax, eax);

  // Compute the target address = code_entry + osr_offset
  __ add(eax, ecx);

  Generate_OSREntry(masm, eax);
}

}  // namespace

void Builtins::Generate_InterpreterOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kInterpreter,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_BaselineOnStackReplacement(MacroAssembler* masm) {
  using D = OnStackReplacementDescriptor;
  static_assert(D::kParameterCount == 1);

  __ mov(kContextRegister,
         MemOperand(ebp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

#if V8_ENABLE_WEBASSEMBLY

// Returns the offset beyond the last saved FP register.
int SaveWasmParams(MacroAssembler* masm) {
  // Save all parameter registers (see wasm-linkage.h). They might be
  // overwritten in the subsequent runtime call. We don't have any callee-saved
  // registers in wasm, so no need to store anything else.
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedGpParamRegs + 1 ==
                    arraysize(wasm::kGpParamRegisters),
                "frame size mismatch");
  for (Register reg : wasm::kGpParamRegisters) {
    __ Push(reg);
  }
  static_assert(WasmLiftoffSetupFrameConstants::kNumberOfSavedFpParamRegs ==
                    arraysize(wasm::kFpParamRegisters),
                "frame size mismatch");
  __ AllocateStackSpace(kSimd128Size * arraysize(wasm::kFpParamRegisters));
  int offset = 0;
  for (DoubleRegister reg : wasm::kFpParamRegisters) {
    __ movdqu(Operand(esp, offset), reg);
    offset += kSimd128Size;
  }
  return offset;
}

// Consumes the offset beyond the last saved FP register (as returned by
// {SaveWasmParams}).
void RestoreWasmParams(MacroAssembler* masm, int offset) {
  for (DoubleRegister reg : base::Reversed(wasm::kFpParamRegisters)) {
    offset -= kSimd128Size;
    __ movdqu(reg, Operand(esp, offset));
  }
  DCHECK_EQ(0, offset);
  __ add(esp, Immediate(kSimd128Size * arraysize(wasm::kFpParamRegisters)));
  for (Register reg : base::Reversed(wasm::kGpParamRegisters)) {
    __ Pop(reg);
  }
}

// When this builtin is called, the topmost stack entry is the calling pc.
// This is replaced with the following:
//
// [    calling pc      ]  <-- esp; popped by {ret}.
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [    saved ebp       ]  <-- ebp; this is where "calling pc" used to be.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  constexpr Register func_index = wasm::kLiftoffFrameSetupFunctionReg;

  // We have zero free registers at this point. Free up a temp. Its value
  // could be tagged, but we're only storing it on the stack for a short
  // while, and no GC or stack walk can happen during this time.
  Register tmp = eax;  // Arbitrarily chosen.
  __ Push(tmp);        // This is the "marker" slot.
  {
    Operand saved_ebp_slot = Operand(esp, kSystemPointerSize);
    __ mov(tmp, saved_ebp_slot);  // tmp now holds the "calling pc".
    __ mov(saved_ebp_slot, ebp);
    __ lea(ebp, Operand(esp, kSystemPointerSize));
  }
  __ Push(tmp);  // This is the "instance" slot.

  // Stack layout is now:
  // [calling pc]  <-- instance_data_slot  <-- esp
  // [saved tmp]   <-- marker_slot
  // [saved ebp]
  Operand marker_slot = Operand(ebp, WasmFrameConstants::kFrameTypeOffset);
  Operand instance_data_slot =
      Operand(ebp, WasmFrameConstants::kWasmInstanceDataOffset);

  // Load the feedback vector from the trusted instance data.
  __ mov(tmp, FieldOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ mov(tmp, FieldOperand(tmp, func_index, times_tagged_size,
                           OFFSET_OF_DATA_START(FixedArray)));
  Label allocate_vector;
  __ JumpIfSmi(tmp, &allocate_vector);

  // Vector exists. Finish setting up the stack frame.
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ mov(tmp, marker_slot);
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ ret(0);

  __ bind(&allocate_vector);
  // Feedback vector doesn't exist yet. Call the runtime to allocate it.
  // We temporarily change the frame type for this, because we need special
  // handling by the stack walker in case of GC.
  // For the runtime call, we create the following stack layout:
  //
  // [ reserved slot for NativeModule ]  <-- arg[2]
  // [  ("declared") function index   ]  <-- arg[1] for runtime func.
  // [       Wasm instance data       ]  <-- arg[0]
  // [ ...spilled Wasm parameters...  ]
  // [           calling pc           ]  <-- already in place
  // [   WASM_LIFTOFF_SETUP marker    ]
  // [           saved ebp            ]  <-- already in place

  __ mov(tmp, marker_slot);
  __ mov(marker_slot,
         Immediate(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));

  int offset = SaveWasmParams(masm);

  // Arguments to the runtime function: instance, func_index.
  __ Push(kWasmImplicitArgRegister);
  __ SmiTag(func_index);
  __ Push(func_index);
  // Allocate a stack slot where the runtime function can spill a pointer
  // to the NativeModule.
  __ Push(esp);
  __ Move(kContextRegister, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  tmp = func_index;
  __ mov(tmp, kReturnRegister0);

  RestoreWasmParams(masm, offset);

  // Finish setting up the stack frame:
  //                             [    calling pc      ]
  //              (tmp reg) ---> [  feedback vector   ]
  // [     calling pc     ]  =>  [ Wasm instance data ]  <-- instance_data_slot
  // [ WASM_LIFTOFF_SETUP ]      [       WASM         ]  <-- marker_slot
  // [      saved ebp     ]      [    saved ebp       ]
  __ mov(marker_slot, Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ Push(tmp);                // Feedback vector.
  __ mov(tmp, instance_data_slot);  // Calling PC.
  __ Push(tmp);
  __ mov(instance_data_slot, kWasmImplicitArgRegister);
  __ ret(0);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was put in edi by the jump table trampoline.
  // Convert to Smi for the runtime call.
  __ SmiTag(kWasmCompileLazyFuncIndexRegister);
  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);
    int offset = SaveWasmParams(masm);

    // Push arguments for the runtime function.
    __ Push(kWasmImplicitArgRegister);
    __ Push(kWasmCompileLazyFuncIndexRegister);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);
    // The runtime function returns the jump table slot offset as a Smi. Use
    // that to compute the jump target in edi.
    __ SmiUntag(kReturnRegister0);
    __ mov(edi, kReturnRegister0);

    RestoreWasmParams(masm, offset);

    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in edi.
    __ add(edi, MemOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kJumpTableStartOffset -
                               kHeapObjectTag));
  }

  // Finally, jump to the jump table slot for the function.
  __ jmp(edi);
}

void Builtins::Generate_WasmDebugBreak(MacroAssembler* masm) {
  HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
  {
    FrameScope scope(masm, StackFrame::WASM_DEBUG_BREAK);

    // Save all parameter registers. They might hold live values, we restore
    // them after the runtime call.
    for (Register reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedGpRegs)) {
      __ Push(reg);
    }

    constexpr int kFpStackSize =
        kSimd128Size * WasmDebugBreakFrameConstants::kNumPushedFpRegisters;
    __ AllocateStackSpace(kFpStackSize);
    int offset = kFpStackSize;
    for (DoubleRegister reg :
         base::Reversed(WasmDebugBreakFrameConstants::kPushedFpRegs)) {
      offset -= kSimd128Size;
      __ movdqu(Operand(esp, offset), reg);
    }

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    for (DoubleRegister reg : WasmDebugBreakFrameConstants::kPushedFpRegs) {
      __ movdqu(reg, Operand(esp, offset));
      offset += kSimd128Size;
    }
    __ add(esp, Immediate(kFpStackSize));
    for (Register reg : WasmDebugBreakFrameConstants::kPushedGpRegs) {
      __ Pop(reg);
    }
  }

  __ ret(0);
}

namespace {
// Check that the stack was in the old state (if generated code assertions are
// enabled), and switch to the new state.
void SwitchStackState(MacroAssembler* masm, Register jmpbuf,
                      wasm::JumpBuffer::StackState old_state,
                      wasm::JumpBuffer::StackState new_state) {
  __ cmp(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(old_state));
  Label ok;
  __ j(equal, &ok, Label::kNear);
  __ Trap();
  __ bind(&ok);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(new_state));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Register scratch,
                    Label* pc) {
  DCHECK(!AreAliased(scratch, jmpbuf));

  __ mov(MemOperand(jmpbuf, wasm::kJmpBufSpOffset), esp);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufFpOffset), ebp);
  __ mov(scratch, __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset), scratch);
  __ LoadLabelAddress(scratch, pc);
  __ mov(MemOperand(jmpbuf, wasm::kJmpBufPcOffset), scratch);
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    wasm::JumpBuffer::StackState expected_state) {
  __ mov(esp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ mov(ebp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ jmp(MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
  }
  // The stack limit is set separately under the ExecutionAccess lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Register tmp2, Label* suspend) {
  DCHECK(!AreAliased(active_continuation, tmp));
  Register jmpbuf = tmp;
  __ mov(jmpbuf, FieldOperand(active_continuation,
                              WasmContinuationObject::kJmpbufOffset));
  FillJumpBuffer(masm, jmpbuf, tmp2, suspend);
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ mov(target_jmpbuf, FieldOperand(target_continuation,
                                     WasmContinuationObject::kJmpbufOffset));
  MemOperand GCScanSlotPlace =
      MemOperand(ebp, StackSwitchFrameConstants::kGCScanSlotCountOffset);
  __ Move(GCScanSlotPlace, Immediate(0));
  // Switch stack!
  LoadJumpBuffer(masm, target_jmpbuf, false, expected_state);
}

// Updates the stack limit to match the new active stack.
// Pass the {finished_continuation} argument to indicate that the stack that we
// are switching from has returned, and in this case return its memory to the
// stack pool.
void SwitchStacks(MacroAssembler* masm, Register finished_continuation,
                  const Register& keep1, const Register& keep2 = no_reg,
                  const Register& keep3 = no_reg) {
  using ER = ExternalReference;
  __ Push(keep1);
  if (keep2 != no_reg) {
    __ Push(keep2);
  }
  if (keep3 != no_reg) {
    __ Push(keep3);
  }
  if (finished_continuation != no_reg) {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(2, eax);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address(masm->isolate())));
    __ mov(Operand(esp, 1 * kSystemPointerSize), finished_continuation);
    __ CallCFunction(ER::wasm_return_switch(), 2);
  } else {
    FrameScope scope(masm, StackFrame::MANUAL);
    __ PrepareCallCFunction(1, eax);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ER::isolate_address()));
    __ CallCFunction(ER::wasm_sync_stack_limit(), 1);
  }
  if (keep3 != no_reg) {
    __ Pop(keep3);
  }
  if (keep2 != no_reg) {
    __ Pop(keep2);
  }
  __ Pop(keep1);
}

void ReloadParentContinuation(MacroAssembler* masm, Register promise,
                              Register return_value, Register context,
                              Register tmp, Register tmp2) {
  Register active_continuation = tmp;
  __ LoadRoot(active_continuation, RootIndex::kActiveContinuation);

  DCHECK(!AreAliased(promise, return_value, context, tmp));

  __ Push(promise);

  // We don't need to save the full register state since we are switching out of
  // this stack for the last time. Mark the stack as retired.
  Register jmpbuf = promise;
  __ mov(jmpbuf, FieldOperand(active_continuation,
                              WasmContinuationObject::kJmpbufOffset));
  SwitchStackState(masm, jmpbuf, wasm::JumpBuffer::Active,
                   wasm::JumpBuffer::Retired);

  Register parent = tmp2;
  __ mov(parent, FieldOperand(active_continuation,
                              WasmContinuationObject::kParentOffset));

  // Update active continuation root.
  __ mov(masm->RootAsOperand(RootIndex::kActiveContinuation), parent);
  jmpbuf = parent;
  __ mov(jmpbuf, FieldOperand(parent, WasmContinuationObject::kJmpbufOffset));

  __ Pop(promise);
  // Switch stack!
  LoadJumpBuffer(masm, jmpbuf, false, wasm::JumpBuffer::Inactive);
  SwitchStacks(masm, active_continuation, promise, return_value, context);
}

// Loads the context field of the WasmTrustedInstanceData or WasmImportData
// depending on the data's type, and places the result in the input register.
void GetContextFromImplicitArg(MacroAssembler* masm, Register data,
                               Register scratch) {
  __ Move(scratch, FieldOperand(data, HeapObject::kMapOffset));
  __ CmpInstanceType(scratch, WASM_TRUSTED_INSTANCE_DATA_TYPE);
  Label instance;
  Label end;
  __ j(equal, &instance);
  __ Move(data, FieldOperand(data, WasmImportData::kNativeContextOffset));
  __ jmp(&end);
  __ bind(&instance);
  __ Move(data,
          FieldOperand(data, WasmTrustedInstanceData::kNativeContextOffset));
  __ bind(&end);
}

void RestoreParentSuspender(MacroAssembler* masm, Register tmp1,
                            Register tmp2) {
  Register suspender = tmp1;
  __ LoadRoot(suspender, RootIndex::kActiveSuspender);
  __ mov(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
         Immediate(Smi::FromInt(WasmSuspenderObject::kInactive)));
  __ Move(suspender,
          FieldOperand(suspender, WasmSuspenderObject::kParentOffset));
  __ CompareRoot(suspender, RootIndex::kUndefinedValue);
  Label undefined;
  __ j(equal, &undefined, Label::kNear);
#ifdef DEBUG
  // Check that the parent suspender is active.
  Label parent_inactive;
  Register state = tmp2;
  __ Move(state, FieldOperand(suspender, WasmSuspenderObject::kStateOffset));
  __ SmiCompare(state, Smi::FromInt(WasmSuspenderObject::kActive));
  __ j(equal, &parent_inactive, Label::kNear);
  __ Trap();
  __ bind(&parent_inactive);
#endif
  __ Move(FieldOperand(suspender, WasmSuspenderObject::kStateOffset),
          Immediate(Smi::FromInt(WasmSuspenderObject::kActive)));
  __ bind(&undefined);
  __ mov(masm->RootAsOperand(RootIndex::kActiveSuspender), suspender);
}

void ResetStackSwitchFrameStackSlots(MacroAssembler* masm) {
  __ mov(MemOperand(ebp, StackSwitchFrameConstants::kImplicitArgOffset),
         Immediate(0));
  __ mov(MemOperand(ebp, StackSwitchFrameConstants::kResultArrayOffset),
         Immediate(0));
}

void SwitchToAllocatedStack(MacroAssembler* masm, Register wrapper_buffer,
                            Register original_fp, Register new_wrapper_buffer,
                            Register scratch, Register scratch2,
                            Label* suspend) {
  ResetStackSwitchFrameStackSlots(masm);
  Register parent_continuation = new_wrapper_buffer;
  __ LoadRoot(parent_continuation, RootIndex::kActiveContinuation);
  __ Move(
      parent_continuation,
      FieldOperand(parent_continuation, WasmContinuationObject::kParentOffset));
  SaveState(masm, parent_continuation, scratch, scratch2, suspend);
  SwitchStacks(masm, no_reg, wrapper_buffer);
  parent_continuation = no_reg;
  Register target_continuation = scratch;
  __ LoadRoot(target_continuation, RootIndex::kActiveContinuation);
  // Save the old stack's ebp, and use it to access the parameters in
  // the parent frame.
  __ mov(original_fp, ebp);
  LoadTargetJumpBuffer(masm, target_continuation, wasm::JumpBuffer::Suspended);
  // Push the loaded ebp. We know it is null, because there is no frame yet,
  // so we could also push 0 directly. In any case we need to push it, because
  // this marks the base of the stack segment for the stack frame iterator.
  __ EnterFrame(StackFrame::STACK_SWITCH);
  int stack_space =
      StackSwitchFrameConstants::kNumSpillSlots * kSystemPointerSize +
      JSToWasmWrapperFrameConstants::kWrapperBufferSize;
  __ AllocateStackSpace(stack_space);
  __ AlignStackPointer();
  __ mov(new_wrapper_buffer, esp);
  // Copy data needed for return handling from old wrapper buffer to new one.
  __ mov(scratch,
         MemOperand(wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount));
  __ mov(MemOperand(new_wrapper_buffer,
                    JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount),
         scratch);
  __ mov(
      scratch,
      MemOperand(wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount));
  __ mov(
      MemOperand(new_wrapper_buffer,
                 JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount),
      scratch);
  __ mov(
      scratch,
      MemOperand(
          wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray));
  __ mov(
      MemOperand(
          new_wrapper_buffer,
          JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray),
      scratch);
  __ mov(
      scratch,
      MemOperand(
          wrappe
```