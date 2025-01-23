Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger file related to x64 architecture built-ins in V8. I need to focus on the code provided in this specific part and identify its main tasks. If any of these tasks are related to Javascript functionality, I need to illustrate that with a Javascript example.

Based on the code, I can see functions related to:
- **`Generate_InterpreterEnterBytecode` and `Generate_InterpreterEnterAtNextBytecode`**: These seem to deal with entering the Javascript interpreter at specific bytecode offsets.
- **`Generate_BaselineOutOfLinePrologue` and `Generate_BaselineOutOfLinePrologueDeopt`**: These are related to setting up and tearing down frames for baseline compiled Javascript code, including stack overflow checks and deoptimization.
- **`Generate_ContinueToCodeStubBuiltin`, `Generate_ContinueToJavaScriptBuiltin`**: These functions are involved in resuming execution after a deoptimization, targeting either CodeStubBuiltins or Javascript builtins.
- **`Generate_NotifyDeoptimized`**: This likely handles notifying the system about a deoptimization event.
- **`Generate_FunctionPrototypeApply` and `Generate_FunctionPrototypeCall`**: These are implementations of the Javascript `Function.prototype.apply` and `Function.prototype.call` methods.
- **`Generate_ReflectApply` and `Generate_ReflectConstruct`**: These implement the Javascript `Reflect.apply` and `Reflect.construct` methods.
- **`Generate_CallOrConstructVarargs` and `Generate_CallOrConstructForwardVarargs`**: These functions seem to handle calling or constructing Javascript functions with variable arguments.
- **`Generate_CallFunction`**: This function deals with calling Javascript functions, including receiver conversion.
- **`Generate_CallBoundFunctionImpl`**: This function handles calling Javascript bound functions.
- **`Generate_Call`**: This function is a general entry point for calling Javascript objects.
- **`Generate_ConstructFunction` and `Generate_ConstructBoundFunction`**: These functions handle constructing Javascript functions and bound functions, respectively.
- **`Generate_Construct`**: This is a general entry point for constructing Javascript objects.
- **`Generate_InterpreterOnStackReplacement`, `Generate_BaselineOnStackReplacement`, `Generate_MaglevOnStackReplacement`**: These functions are involved in on-stack replacement (OSR), a process of optimizing running code.
- **`Generate_AdaptShadowStackForDeopt`**: This function seems to be related to deoptimization in the context of Control-flow Enforcement Technology (CET).
- **`Generate_WasmLiftoffFrameSetup`, `Generate_WasmCompileLazy`, `Generate_WasmDebugBreak`**: These functions are specific to WebAssembly integration within V8.
- **Functions related to WebAssembly continuations**: These handle saving and restoring the state of WebAssembly execution for asynchronous operations.

I will now proceed with summarizing the functionality of this specific part of the code and providing Javascript examples where relevant.
```cpp
ot(rax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ movq(rax,
          Operand(rbp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(rax, RootIndex::kTheHoleValue, &do_throw, Label::kNear);

  __ bind(&leave_and_return);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ bind(&check_result);
  __ JumpIfSmi(rax, &use_receiver, Label::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(rax, rcx, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver);

  __ bind(&do_throw);
  __ movq(rsi, Operand(rbp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // We don't return here.
  __ int3();

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();

  Generate_CallToAdaptShadowStackForDeopt(masm, false);
  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());
  __ jmp(&deopt_entry);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ movq(rbx, Operand(rbp, StandardFrameConstants::kFunctionOffset));
  const Register shared_function_info(rbx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rbx, JSFunction::kSharedFunctionInfoOffset));

  __ LoadTrustedPointerField(
      rbx,
      FieldOperand(shared_function_info,
                   SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, kScratchRegister);
  __ IsObjectType(rbx, INTERPRETER_DATA_TYPE, kScratchRegister);
  __ j(not_equal, &builtin_trampoline, Label::kNear);
  __ LoadProtectedPointerField(
      rbx, FieldOperand(rbx, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(rbx, rbx, kJSEntrypointTag);
  __ jmp(&trampoline_loaded, Label::kNear);

  __ bind(&builtin_trampoline);
  // TODO(jgruber): Replace this by a lookup in the builtin entry table.
  __ movq(rbx,
          __ ExternalReferenceAsOperand(
              ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()),
              kScratchRegister));

  __ bind(&trampoline_loaded);
  __ addq(rbx, Immediate(interpreter_entry_return_pc_offset.value()));
  __ movq(kScratchRegister, rbx);

  // Initialize dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ IsObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                    kScratchRegister);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ cmpq(kInterpreterBytecodeOffsetRegister,
            Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ j(greater_equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ movzxbq(kScratchRegister,
             Operand(kInterpreterBytecodeArrayRegister,
                     kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ movq(kJavaScriptCallCodeStartRegister,
          Operand(kInterpreterDispatchTableRegister, kScratchRegister,
                  times_system_pointer_size, 0));

  // Jump to the interpreter entry, and call kJavaScriptCallCodeStartRegister.
  __ jmp(rbx);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  // Get bytecode array and bytecode offset from the stack frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Label enter_bytecode, function_entry_bytecode;
  __ cmpq(kInterpreterBytecodeOffsetRegister,
          Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));
  __ j(equal, &function_entry_bytecode);

  // Load the current bytecode.
  __ movzxbq(rbx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, rbx, rcx,
                                r8, &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(kInterpreterBytecodeOffsetRegister);
  __ movq(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
          kInterpreterBytecodeOffsetRegister);

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);
  __ jmp(&enter_bytecode);

  // We should never take the if_return path.
  __ bind(&if_return);
  __ Abort(AbortReason::kInvalidBytecodeAdvance);
}

void Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  Generate_InterpreterEnterBytecode(masm);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  Register feedback_cell = r8;
  Register feedback_vector = r9;
  Register return_address = r11;

#ifdef DEBUG
  for (auto reg : BaselineOutOfLinePrologueDescriptor::registers()) {
    DCHECK(!AreAliased(feedback_vector, return_address, reg));
  }
#endif

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  __ LoadTaggedField(feedback_cell,
                     FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(feedback_vector,
                     FieldOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, kScratchRegister);

#ifndef V8_ENABLE_LEAPTIERING
  // Check the tiering state.
  Label flags_need_processing;
  __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      feedback_vector, CodeKind::BASELINE, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, kScratchRegister);

  // Increment invocation count for the function.
  __ incl(
      FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

    // Save the return address, so that we can push it to the end of the newly
    // set-up frame once we're done setting it up.
    __ PopReturnAddressTo(return_address);
    FrameScope frame_scope(masm, StackFrame::MANUAL);
    {
      ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
      __ EnterFrame(StackFrame::BASELINE);

      __ Push(descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kCalleeContext));  // Callee's
                                                                  // context.
      Register callee_js_function = descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kClosure);
      DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
      DCHECK_EQ(callee_js_function, kJSFunctionRegister);
      ResetJSFunctionAge(masm, callee_js_function);
      __ Push(callee_js_function);  // Callee's JS function.
      __ Push(descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::
              kJavaScriptCallArgCount));  // Actual argument count.

      // We'll use the bytecode for both code age/OSR resetting, and pushing
      // onto the frame, so load it into a register.
      Register bytecode_array = descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
      __ Push(bytecode_array);
      __ Push(feedback_cell);
      __ Push(feedback_vector);
    }

  Register new_target = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kJavaScriptCallNewTarget);

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, " Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    //
    // TODO(v8:11429): Backport this folded check to the
    // InterpreterEntryTrampoline.
    __ Move(kScratchRegister, rsp);
    DCHECK_NE(frame_size, new_target);
    __ subq(kScratchRegister, frame_size);
    __ cmpq(kScratchRegister,
            __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
    __ j(below, &call_stack_guard);
  }

  // Push the return address back onto the stack for return.
  __ PushReturnAddressFrom(return_address);
  // Return to caller pushed pc, without any frame teardown.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the return address, rebalancing the return stack buffer by using
    // JumpMode::kPushAndReturn. We can't leave the slot and overwrite it on
    // return since we may do a runtime call along the way that requires the
    // stack to only contain valid frames.
    __ Drop(1);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(feedback_vector, closure,
                                               JumpMode::kPushAndReturn);
    __ Trap();
  }
#endif  //! V8_ENABLE_LEAPTIERING

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    {
      // Push the baseline code return address now, as if it had been pushed by
      // the call to this builtin.
      __ PushReturnAddressFrom(return_address);
      FrameScope inner_frame_scope(masm, StackFrame::INTERNAL);
      // Save incoming new target or generator
      __ Push(new_target);
#ifdef V8_ENABLE_LEAPTIERING
      // No need to SmiTag as dispatch handles always look like Smis.
      static_assert(kJSDispatchHandleShift > 0);
      __ Push(kJavaScriptCallDispatchHandleRegister);
#endif
      __ SmiTag(frame_size);
      __ Push(frame_size);
      __ CallRuntime(Runtime::kStackGuardWithGap, 1);
#ifdef V8_ENABLE_LEAPTIERING
      __ Pop(kJavaScriptCallDispatchHandleRegister);
#endif
      __ Pop(new_target);
    }

    // Return to caller pushed pc, without any frame teardown.
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ Ret();
  }
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop feedback vector.
  __ Pop(kScratchRegister);
  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt).
  __ Pop(kScratchRegister);
  // Drop bytecode array
  __ Pop(kScratchRegister);

  // argc.
  __ Pop(kJavaScriptCallArgCountRegister);
  // Closure.
  __ Pop(kJavaScriptCallTargetRegister);
  // Context.
  __ Pop(kContextRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}
```

This part of the `builtins-x64.cc` file in V8 focuses on the **entry and exit points for different execution modes** and the implementation of the **`Construct` operation** in JavaScript.

Here's a breakdown of the functionalities:

1. **`Generate_ConstructStubInvoke`**: This function generates assembly code for invoking the `Construct` operation. It handles:
    *   Fast construction paths where the constructor's result is directly used or the receiver object is used if the constructor returns a primitive.
    *   Handling cases where the constructor returns a non-object, throwing an error.
    *   Calling the constructor as a normal function if it's not a proper constructor.
    *   Handling stack overflow during construction.
    *   Setting up for deoptimization if needed.

2. **`Generate_InterpreterEnterBytecode`**: This function generates code to enter the JavaScript interpreter at a specific bytecode. It:
    *   Locates the correct interpreter entry point, potentially using a custom trampoline for profiling.
    *   Initializes the interpreter's dispatch table register.
    *   Retrieves the bytecode array and offset from the current stack frame.
    *   Dispatches execution to the target bytecode.

3. **`Generate_InterpreterEnterAtNextBytecode`**: This function builds upon `Generate_InterpreterEnterBytecode` to enter the interpreter at the *next* bytecode instruction. It:
    *   Advances the bytecode offset.
    *   Handles a special case for entering at the function entry point.
    *   Calls `Generate_InterpreterEnterBytecode` to actually enter the interpreter.

4. **`Generate_InterpreterEnterAtBytecode`**: This function directly calls `Generate_InterpreterEnterBytecode` to enter the interpreter at a specified bytecode.

5. **`Generate_BaselineOutOfLinePrologue`**: This function sets up the stack frame when entering a baseline-compiled JavaScript function. It includes:
    *   Loading feedback information for potential optimization.
    *   Incrementing the function's invocation count.
    *   Performing a stack overflow check.
    *   Saving necessary registers and function metadata on the stack.
    *   Handling tiering and potentially optimizing the code.

6. **`Generate_BaselineOutOfLinePrologueDeopt`**: This function handles deoptimization when it occurs during the prologue of a baseline function (specifically during the stack check). It undoes the frame setup done by `Generate_BaselineOutOfLinePrologue` and transfers control to the interpreter.

**Relationship with JavaScript and Examples:**

These functions are fundamental to how JavaScript code is executed within the V8 engine.

*   **`Generate_ConstructStubInvoke`** is directly related to the `new` keyword in JavaScript:

    ```javascript
    function MyClass(value) {
      this.value = value;
    }

    const instance = new MyClass(10); // This operation involves Generate_ConstructStubInvoke
    ```

*   **`Generate_InterpreterEnterBytecode`** and its related functions are involved whenever JavaScript code is initially executed or when optimized code needs to fall back to the interpreter:

    ```javascript
    function add(a, b) {
      return a + b;
    }

    add(5, 3); // Initially, this might be executed by the interpreter.
    ```

*   **`Generate_BaselineOutOfLinePrologue`** is relevant when a function has been executed enough times to be considered for baseline compilation, but it hasn't yet been fully optimized:

    ```javascript
    function expensiveCalculation(n) {
      let result = 0;
      for (let i = 0; i < n; i++) {
        result += i * 2;
      }
      return result;
    }

    for (let i = 0; i < 1000; i++) {
      expensiveCalculation(i); // After a few iterations, this might enter baseline compilation.
    }
    ```

In essence, this section of the code defines how V8 manages the execution flow when constructing objects and entering/exiting different execution tiers (interpreter and baseline compiler) for JavaScript code. It ensures proper stack frame setup, handles potential errors like stack overflow, and facilitates the process of optimizing code execution over time.

### 提示词
```
这是目录为v8/src/builtins/x64/builtins-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
ot(rax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ movq(rax,
          Operand(rbp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(rax, RootIndex::kTheHoleValue, &do_throw, Label::kNear);

  __ bind(&leave_and_return);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ bind(&check_result);
  __ JumpIfSmi(rax, &use_receiver, Label::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(rax, rcx, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver);

  __ bind(&do_throw);
  __ movq(rsi, Operand(rbp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // We don't return here.
  __ int3();

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunction(rdi, rdx, rax, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);

  // Throw stack overflow exception.
  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // This should be unreachable.
  __ int3();

  Generate_CallToAdaptShadowStackForDeopt(masm, false);
  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());
  __ jmp(&deopt_entry);
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ movq(rbx, Operand(rbp, StandardFrameConstants::kFunctionOffset));
  const Register shared_function_info(rbx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rbx, JSFunction::kSharedFunctionInfoOffset));

  __ LoadTrustedPointerField(
      rbx,
      FieldOperand(shared_function_info,
                   SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, kScratchRegister);
  __ IsObjectType(rbx, INTERPRETER_DATA_TYPE, kScratchRegister);
  __ j(not_equal, &builtin_trampoline, Label::kNear);
  __ LoadProtectedPointerField(
      rbx, FieldOperand(rbx, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(rbx, rbx, kJSEntrypointTag);
  __ jmp(&trampoline_loaded, Label::kNear);

  __ bind(&builtin_trampoline);
  // TODO(jgruber): Replace this by a lookup in the builtin entry table.
  __ movq(rbx,
          __ ExternalReferenceAsOperand(
              ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()),
              kScratchRegister));

  __ bind(&trampoline_loaded);
  __ addq(rbx, Immediate(interpreter_entry_return_pc_offset.value()));
  __ movq(kScratchRegister, rbx);

  // Initialize dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ IsObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                    kScratchRegister);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  if (v8_flags.debug_code) {
    Label okay;
    __ cmpq(kInterpreterBytecodeOffsetRegister,
            Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ j(greater_equal, &okay, Label::kNear);
    __ int3();
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  __ movzxbq(kScratchRegister,
             Operand(kInterpreterBytecodeArrayRegister,
                     kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ movq(kJavaScriptCallCodeStartRegister,
          Operand(kInterpreterDispatchTableRegister, kScratchRegister,
                  times_system_pointer_size, 0));

  // Jump to the interpreter entry, and call kJavaScriptCallCodeStartRegister.
  __ jmp(rbx);
}

void Builtins::Generate_InterpreterEnterAtNextBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  // Get bytecode array and bytecode offset from the stack frame.
  __ movq(kInterpreterBytecodeArrayRegister,
          Operand(rbp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ SmiUntagUnsigned(
      kInterpreterBytecodeOffsetRegister,
      Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  Label enter_bytecode, function_entry_bytecode;
  __ cmpq(kInterpreterBytecodeOffsetRegister,
          Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag +
                    kFunctionEntryBytecodeOffset));
  __ j(equal, &function_entry_bytecode);

  // Load the current bytecode.
  __ movzxbq(rbx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));

  // Advance to the next bytecode.
  Label if_return;
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, rbx, rcx,
                                r8, &if_return);

  __ bind(&enter_bytecode);
  // Convert new bytecode offset to a Smi and save in the stackframe.
  __ SmiTag(kInterpreterBytecodeOffsetRegister);
  __ movq(Operand(rbp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
          kInterpreterBytecodeOffsetRegister);

  Generate_InterpreterEnterBytecode(masm);

  __ bind(&function_entry_bytecode);
  // If the code deoptimizes during the implicit function entry stack interrupt
  // check, it will have a bailout ID of kFunctionEntryBytecodeOffset, which is
  // not a valid bytecode offset. Detect this case and advance to the first
  // actual bytecode.
  __ Move(kInterpreterBytecodeOffsetRegister,
          BytecodeArray::kHeaderSize - kHeapObjectTag);
  __ jmp(&enter_bytecode);

  // We should never take the if_return path.
  __ bind(&if_return);
  __ Abort(AbortReason::kInvalidBytecodeAdvance);
}

void Builtins::Generate_InterpreterEnterAtBytecode(MacroAssembler* masm) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  Generate_InterpreterEnterBytecode(masm);
}

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  Register feedback_cell = r8;
  Register feedback_vector = r9;
  Register return_address = r11;

#ifdef DEBUG
  for (auto reg : BaselineOutOfLinePrologueDescriptor::registers()) {
    DCHECK(!AreAliased(feedback_vector, return_address, reg));
  }
#endif

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  __ LoadTaggedField(feedback_cell,
                     FieldOperand(closure, JSFunction::kFeedbackCellOffset));
  __ LoadTaggedField(feedback_vector,
                     FieldOperand(feedback_cell, FeedbackCell::kValueOffset));
  __ AssertFeedbackVector(feedback_vector, kScratchRegister);

#ifndef V8_ENABLE_LEAPTIERING
  // Check the tiering state.
  Label flags_need_processing;
  __ CheckFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      feedback_vector, CodeKind::BASELINE, &flags_need_processing);
#endif  // !V8_ENABLE_LEAPTIERING

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, kScratchRegister);

  // Increment invocation count for the function.
  __ incl(
      FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

    // Save the return address, so that we can push it to the end of the newly
    // set-up frame once we're done setting it up.
    __ PopReturnAddressTo(return_address);
    FrameScope frame_scope(masm, StackFrame::MANUAL);
    {
      ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
      __ EnterFrame(StackFrame::BASELINE);

      __ Push(descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kCalleeContext));  // Callee's
                                                                  // context.
      Register callee_js_function = descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kClosure);
      DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
      DCHECK_EQ(callee_js_function, kJSFunctionRegister);
      ResetJSFunctionAge(masm, callee_js_function);
      __ Push(callee_js_function);  // Callee's JS function.
      __ Push(descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::
              kJavaScriptCallArgCount));  // Actual argument count.

      // We'll use the bytecode for both code age/OSR resetting, and pushing
      // onto the frame, so load it into a register.
      Register bytecode_array = descriptor.GetRegisterParameter(
          BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
      __ Push(bytecode_array);
      __ Push(feedback_cell);
      __ Push(feedback_vector);
    }

  Register new_target = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kJavaScriptCallNewTarget);

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, " Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    //
    // TODO(v8:11429): Backport this folded check to the
    // InterpreterEntryTrampoline.
    __ Move(kScratchRegister, rsp);
    DCHECK_NE(frame_size, new_target);
    __ subq(kScratchRegister, frame_size);
    __ cmpq(kScratchRegister,
            __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
    __ j(below, &call_stack_guard);
  }

  // Push the return address back onto the stack for return.
  __ PushReturnAddressFrom(return_address);
  // Return to caller pushed pc, without any frame teardown.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

#ifndef V8_ENABLE_LEAPTIERING
  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    // Drop the return address, rebalancing the return stack buffer by using
    // JumpMode::kPushAndReturn. We can't leave the slot and overwrite it on
    // return since we may do a runtime call along the way that requires the
    // stack to only contain valid frames.
    __ Drop(1);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(feedback_vector, closure,
                                               JumpMode::kPushAndReturn);
    __ Trap();
  }
#endif  //! V8_ENABLE_LEAPTIERING

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    {
      // Push the baseline code return address now, as if it had been pushed by
      // the call to this builtin.
      __ PushReturnAddressFrom(return_address);
      FrameScope inner_frame_scope(masm, StackFrame::INTERNAL);
      // Save incoming new target or generator
      __ Push(new_target);
#ifdef V8_ENABLE_LEAPTIERING
      // No need to SmiTag as dispatch handles always look like Smis.
      static_assert(kJSDispatchHandleShift > 0);
      __ Push(kJavaScriptCallDispatchHandleRegister);
#endif
      __ SmiTag(frame_size);
      __ Push(frame_size);
      __ CallRuntime(Runtime::kStackGuardWithGap, 1);
#ifdef V8_ENABLE_LEAPTIERING
      __ Pop(kJavaScriptCallDispatchHandleRegister);
#endif
      __ Pop(new_target);
    }

    // Return to caller pushed pc, without any frame teardown.
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ Ret();
  }
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop feedback vector.
  __ Pop(kScratchRegister);
  // Drop bytecode offset (was the feedback vector but got replaced during
  // deopt).
  __ Pop(kScratchRegister);
  // Drop bytecode array
  __ Pop(kScratchRegister);

  // argc.
  __ Pop(kJavaScriptCallArgCountRegister);
  // Closure.
  __ Pop(kJavaScriptCallTargetRegister);
  // Context.
  __ Pop(kContextRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

namespace {
void Generate_ContinueToBuiltinHelper(MacroAssembler* masm,
                                      bool javascript_builtin,
                                      bool with_result) {
  Generate_CallToAdaptShadowStackForDeopt(masm, true);
  masm->isolate()->heap()->SetDeoptPCOffsetAfterAdaptShadowStack(
      masm->pc_offset());

  ASM_CODE_COMMENT(masm);
  const RegisterConfiguration* config(RegisterConfiguration::Default());
  int allocatable_register_count = config->num_allocatable_general_registers();
  if (with_result) {
    if (javascript_builtin) {
      // kScratchRegister is not included in the allocateable registers.
      __ movq(kScratchRegister, rax);
    } else {
      // Overwrite the hole inserted by the deoptimizer with the return value
      // from the LAZY deopt point.
      __ movq(
          Operand(rsp, config->num_allocatable_general_registers() *
                               kSystemPointerSize +
                           BuiltinContinuationFrameConstants::kFixedFrameSize),
          rax);
    }
  }
  for (int i = allocatable_register_count - 1; i >= 0; --i) {
    int code = config->GetAllocatableGeneralCode(i);
    __ popq(Register::from_code(code));
    if (javascript_builtin && code == kJavaScriptCallArgCountRegister.code()) {
      __ SmiUntagUnsigned(Register::from_code(code));
    }
  }
  if (with_result && javascript_builtin) {
    // Overwrite the hole inserted by the deoptimizer with the return value from
    // the LAZY deopt point. rax contains the arguments count, the return value
    // from LAZY is always the last argument.
    __ movq(Operand(rsp, rax, times_system_pointer_size,
                    BuiltinContinuationFrameConstants::kFixedFrameSize -
                        kJSArgcReceiverSlots * kSystemPointerSize),
            kScratchRegister);
  }
  __ movq(
      rbp,
      Operand(rsp, BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp));
  const int offsetToPC =
      BuiltinContinuationFrameConstants::kFixedFrameSizeFromFp -
      kSystemPointerSize;
  __ popq(Operand(rsp, offsetToPC));
  __ Drop(offsetToPC / kSystemPointerSize);

  // Replace the builtin index Smi on the stack with the instruction start
  // address of the builtin from the builtins table, and then jump to this
  // address
  __ popq(kScratchRegister);
  __ movq(kScratchRegister,
          __ EntryFromBuiltinIndexAsOperand(kScratchRegister));
  __ jmp(kScratchRegister);
}
}  // namespace

void Builtins::Generate_ContinueToCodeStubBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, false);
}

void Builtins::Generate_ContinueToCodeStubBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, false, true);
}

void Builtins::Generate_ContinueToJavaScriptBuiltin(MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, false);
}

void Builtins::Generate_ContinueToJavaScriptBuiltinWithResult(
    MacroAssembler* masm) {
  Generate_ContinueToBuiltinHelper(masm, true, true);
}

void Builtins::Generate_NotifyDeoptimized(MacroAssembler* masm) {
  // Enter an internal frame.
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kNotifyDeoptimized);
    // Tear down internal frame.
  }

  DCHECK_EQ(kInterpreterAccumulatorRegister.code(), rax.code());
  __ movq(rax, Operand(rsp, kPCOnStackSize));
  __ ret(1 * kSystemPointerSize);  // Remove rax.
}

// static
void Builtins::Generate_FunctionPrototypeApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[1]  : receiver
  //  -- rsp[2]  : thisArg
  //  -- rsp[3]  : argArray
  // -----------------------------------

  // 1. Load receiver into rdi, argArray into rbx (if present), remove all
  // arguments from the stack (including the receiver), and push thisArg (if
  // present) instead.
  {
    Label no_arg_array, no_this_arg;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdx, RootIndex::kUndefinedValue);
    __ movq(rbx, rdx);
    __ movq(rdi, args[0]);
    __ cmpq(rax, Immediate(JSParameterCount(0)));
    __ j(equal, &no_this_arg, Label::kNear);
    {
      __ movq(rdx, args[1]);
      __ cmpq(rax, Immediate(JSParameterCount(1)));
      __ j(equal, &no_arg_array, Label::kNear);
      __ movq(rbx, args[2]);
      __ bind(&no_arg_array);
    }
    __ bind(&no_this_arg);
    __ DropArgumentsAndPushNewReceiver(rax, rdx, rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argArray
  //  -- rdi     : receiver
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : thisArg
  // -----------------------------------

  // 2. We don't need to check explicitly for callable receiver here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Tail call with no arguments if argArray is null or undefined.
  Label no_arguments;
  __ JumpIfRoot(rbx, RootIndex::kNullValue, &no_arguments, Label::kNear);
  __ JumpIfRoot(rbx, RootIndex::kUndefinedValue, &no_arguments, Label::kNear);

  // 4a. Apply the receiver to the given argArray.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);

  // 4b. The argArray is either null or undefined, so we tail call without any
  // arguments to the receiver. Since we did not create a frame for
  // Function.prototype.apply() yet, we use a normal Call builtin here.
  __ bind(&no_arguments);
  {
    __ Move(rax, JSParameterCount(0));
    __ TailCallBuiltin(Builtins::Call());
  }
}

// static
void Builtins::Generate_FunctionPrototypeCall(MacroAssembler* masm) {
  // Stack Layout:
  // rsp[0]           : Return address
  // rsp[8]           : Argument 0 (receiver: callable to call)
  // rsp[16]          : Argument 1
  //  ...
  // rsp[8 * n]       : Argument n-1
  // rsp[8 * (n + 1)] : Argument n
  // rax contains the number of arguments, n.

  // 1. Get the callable to call (passed as receiver) from the stack.
  {
    StackArgumentsAccessor args(rax);
    __ movq(rdi, args.GetReceiverOperand());
  }

  // 2. Save the return address and drop the callable.
  __ PopReturnAddressTo(rbx);
  __ Pop(kScratchRegister);

  // 3. Make sure we have at least one argument.
  {
    Label done;
    __ cmpq(rax, Immediate(JSParameterCount(0)));
    __ j(greater, &done, Label::kNear);
    __ PushRoot(RootIndex::kUndefinedValue);
    __ incq(rax);
    __ bind(&done);
  }

  // 4. Push back the return address one slot down on the stack (overwriting the
  // original callable), making the original first argument the new receiver.
  __ PushReturnAddressFrom(rbx);
  __ decq(rax);  // One fewer argument (first argument is new receiver).

  // 5. Call the callable.
  // Since we did not create a frame for Function.prototype.call() yet,
  // we use a normal Call builtin here.
  __ TailCallBuiltin(Builtins::Call());
}

void Builtins::Generate_ReflectApply(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver
  //  -- rsp[16] : target         (if argc >= 1)
  //  -- rsp[24] : thisArgument   (if argc >= 2)
  //  -- rsp[32] : argumentsList  (if argc == 3)
  // -----------------------------------

  // 1. Load target into rdi (if present), argumentsList into rbx (if present),
  // remove all arguments from the stack (including the receiver), and push
  // thisArgument (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdi, RootIndex::kUndefinedValue);
    __ movq(rdx, rdi);
    __ movq(rbx, rdi);
    __ cmpq(rax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ movq(rdi, args[1]);  // target
    __ j(equal, &done, Label::kNear);
    __ movq(rdx, args[2]);  // thisArgument
    __ cmpq(rax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ movq(rbx, args[3]);  // argumentsList
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(rax, rdx, rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argumentsList
  //  -- rdi     : target
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : thisArgument
  // -----------------------------------

  // 2. We don't need to check explicitly for callable target here,
  // since that's the first thing the Call/CallWithArrayLike builtins
  // will do.

  // 3. Apply the target to the given argumentsList.
  __ TailCallBuiltin(Builtin::kCallWithArrayLike);
}

void Builtins::Generate_ReflectConstruct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax     : argc
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver
  //  -- rsp[16] : target
  //  -- rsp[24] : argumentsList
  //  -- rsp[32] : new.target (optional)
  // -----------------------------------

  // 1. Load target into rdi (if present), argumentsList into rbx (if present),
  // new.target into rdx (if present, otherwise use target), remove all
  // arguments from the stack (including the receiver), and push thisArgument
  // (if present) instead.
  {
    Label done;
    StackArgumentsAccessor args(rax);
    __ LoadRoot(rdi, RootIndex::kUndefinedValue);
    __ movq(rdx, rdi);
    __ movq(rbx, rdi);
    __ cmpq(rax, Immediate(JSParameterCount(1)));
    __ j(below, &done, Label::kNear);
    __ movq(rdi, args[1]);                     // target
    __ movq(rdx, rdi);                         // new.target defaults to target
    __ j(equal, &done, Label::kNear);
    __ movq(rbx, args[2]);  // argumentsList
    __ cmpq(rax, Immediate(JSParameterCount(3)));
    __ j(below, &done, Label::kNear);
    __ movq(rdx, args[3]);  // new.target
    __ bind(&done);
    __ DropArgumentsAndPushNewReceiver(
        rax, masm->RootAsOperand(RootIndex::kUndefinedValue), rcx);
  }

  // ----------- S t a t e -------------
  //  -- rbx     : argumentsList
  //  -- rdx     : new.target
  //  -- rdi     : target
  //  -- rsp[0]  : return address
  //  -- rsp[8]  : receiver (undefined)
  // -----------------------------------

  // 2. We don't need to check explicitly for constructor target here,
  // since that's the first thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 3. We don't need to check explicitly for constructor new.target here,
  // since that's the second thing the Construct/ConstructWithArrayLike
  // builtins will do.

  // 4. Construct the target with the given new.target and argumentsList.
  __ TailCallBuiltin(Builtin::kConstructWithArrayLike);
}

namespace {

// Allocate new stack space for |count| arguments and shift all existing
// arguments already on the stack. |pointer_to_new_space_out| points to the
// first free slot on the stack to copy additional arguments to and
// |argc_in_out| is updated to include |count|.
void Generate_AllocateSpaceAndShiftExistingArguments(
    MacroAssembler* masm, Register count, Register argc_in_out,
    Register pointer_to_new_space_out, Register scratch1, Register scratch2) {
  DCHECK(!AreAliased(count, argc_in_out, pointer_to_new_space_out, scratch1,
                     scratch2, kScratchRegister));
  // Use pointer_to_new_space_out as scratch until we set it to the correct
  // value at the end.
  Register old_rsp = pointer_to_new_space_out;
  Register new_space = kScratchRegister;
  __ movq(old_rsp, rsp);

  __ leaq(new_space, Operand(count, times_system_pointer_size, 0));
  __ AllocateStackSpace(new_space);

  Register copy_count = argc_in_out;
  Register current = scratch2;
  Register value = kScratchRegister;

  Label loop, entry;
  __ Move(current, 0);
  __ jmp(&entry);
  __ bind(&loop);
  __ movq(value, Operand(old_rsp, current, times_system_pointer_size, 0));
  __ movq(Operand(rsp, current, times_system_pointer_size, 0), value);
  __ incq(current);
  __ bind(&entry);
  __ cmpq(current, copy_count);
  __ j(less_equal, &loop, Label::kNear);

  // Point to the next free slot above the shifted arguments (copy_count + 1
  // slot for the return address).
  __ leaq(
      pointer_to_new_space_out,
      Operand(rsp, copy_count, times_system_pointer_size, kSystemPointerSize));
  // We use addl instead of addq here because we can omit REX.W, saving 1 byte.
  // We are especially constrained here because we are close to reaching the
  // limit for a near jump to the stackoverflow label, so every byte counts.
  __ addl(argc_in_out, count);  // Update total number of arguments.
}

}  // namespace

// static
// TODO(v8:11615): Observe Code::kMaxArguments in CallOrConstructVarargs
void Builtins::Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                               Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- rdi    : target
  //  -- rax    : number of parameters on the stack
  //  -- rbx    : arguments list (a FixedArray)
  //  -- rcx    : len (number of elements to push from args)
  //  -- rdx    : new.target (for [[Construct]])
  //  -- rsp[0] : return address
  // -----------------------------------

  if (v8_flags.debug_code) {
    // Allow rbx to be a FixedArray, or a FixedDoubleArray if rcx == 0.
    Label ok, fail;
    __ AssertNotSmi(rbx);
    Register map = r9;
    __ LoadMap(map, rbx);
    __ CmpInstanceType(map, FIXED_ARRAY_TYPE);
    __ j(equal, &ok);
    __ CmpInstanceType(map, FIXED_DOUBLE_ARRAY_TYPE);
    __ j(not_equal, &fail);
    __ Cmp(rcx, 0);
    __ j(equal, &ok);
    // Fall through.
    __ bind(&fail);
    __ Abort(AbortReason::kOperandIsNotAFixedArray);

    __ bind(&ok);
  }

  Label stack_overflow;
  __ StackOverflowCheck(rcx, &stack_overflow,
                        DEBUG_BOOL ? Label::kFar : Label::kNear);

  // Push additional arguments onto the stack.
  // Move the arguments already in the stack,
  // including the receiver and the return address.
  // rcx: Number of arguments to make room for.
  // rax: Number of arguments already on the stack.
  // r8: Points to first free slot on the stack after arguments were shifted.
  Generate_AllocateSpaceAndShiftExistingArguments(masm, rcx, rax, r8, r9, r12);
  // Copy the additional arguments onto the stack.
  {
    Register value = r12;
    Register src = rbx, dest = r8, num = rcx, current = r9;
    __ Move(current, 0);
    Label done, push, loop;
    __ bind(&loop);
    __ cmpl(current, num);
    __ j(equal, &done, Label::kNear);
    // Turn the hole into undefined as we go.
    __ LoadTaggedField(value, FieldOperand(src, current, times_tagged_size,
                                           OFFSET_OF_DATA_START(FixedArray)));
    __ CompareRoot(value, RootIndex::kTheHoleValue);
    __ j(not_equal, &push, Label::kNear);
    __ LoadRoot(value, RootIndex::kUndefinedValue);
    __ bind(&push);
    __ movq(Operand(dest, current, times_system_pointer_size, 0), value);
    __ incl(current);
    __ jmp(&loop);
    __ bind(&done);
  }

  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallOrConstructForwardVarargs(MacroAssembler* masm,
                                                      CallOrConstructMode mode,
                                                      Builtin target_builtin) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (for [[Construct]] calls)
  //  -- rdi : the target to call (can be any Object)
  //  -- rcx : start index (to support rest parameters)
  // -----------------------------------

  // Check if new.target has a [[Construct]] internal method.
  if (mode == CallOrConstructMode::kConstruct) {
    Label new_target_constructor, new_target_not_constructor;
    __ JumpIfSmi(rdx, &new_target_not_constructor, Label::kNear);
    __ LoadMap(rbx, rdx);
    __ testb(FieldOperand(rbx, Map::kBitFieldOffset),
             Immediate(Map::Bits1::IsConstructorBit::kMask));
    __ j(not_zero, &new_target_constructor, Label::kNear);
    __ bind(&new_target_not_constructor);
    {
      FrameScope scope(masm, StackFrame::MANUAL);
      __ EnterFrame(StackFrame::INTERNAL);
      __ Push(rdx);
      __ CallRuntime(Runtime::kThrowNotConstructor);
    }
    __ bind(&new_target_constructor);
  }

  Label stack_done, stack_overflow;
  __ movq(r8, Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ decq(r8);  // Exclude receiver.
  __ subl(r8, rcx);
  __ j(less_equal, &stack_done);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments already in the stack
    //  -- rbp : point to the caller stack frame
    //  -- rcx : start index (to support rest parameters)
    //  -- rdx : the new target (for [[Construct]] calls)
    //  -- rdi : the target to call (can be any Object)
    //  -- r8  : number of arguments to copy, i.e. arguments count - start index
    // -----------------------------------

    // Check for stack overflow.
    __ StackOverflowCheck(r8, &stack_overflow, Label::kNear);

    // Forward the arguments from the caller frame.
    // Move the arguments already in the stack,
    // including the receiver and the return address.
    // r8: Number of arguments to make room for.
    // rax: Number of arguments already on the stack.
    // r9: Points to first free slot on the stack after arguments were shifted.
    Generate_AllocateSpaceAndShiftExistingArguments(masm, r8, rax, r9, r12,
                                                    r15);

    // Point to the first argument to copy (skipping receiver).
    __ leaq(rcx, Operand(rcx, times_system_pointer_size,
                         CommonFrameConstants::kFixedFrameSizeAboveFp +
                             kSystemPointerSize));
    __ addq(rcx, rbp);

    // Copy the additional caller arguments onto the stack.
    // TODO(victorgomes): Consider using forward order as potentially more cache
    // friendly.
    {
      Register src = rcx, dest = r9, num = r8;
      Label loop;
      __ bind(&loop);
      __ decq(num);
      __ movq(kScratchRegister,
              Operand(src, num, times_system_pointer_size, 0));
      __ movq(Operand(dest, num, times_system_pointer_size, 0),
              kScratchRegister);
      __ j(not_zero, &loop);
    }
  }
  __ bind(&stack_done);
  // Tail-call to the actual Call or Construct builtin.
  __ TailCallBuiltin(target_builtin);

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
}

// static
void Builtins::Generate_CallFunction(MacroAssembler* masm,
                                     ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the function to call (checked to be a JSFunction)
  // -----------------------------------

  StackArgumentsAccessor args(rax);
  __ AssertCallableFunction(rdi);

  __ LoadTaggedField(rdx,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the shared function info.
  //  -- rdi : the function to call (checked to be a JSFunction)
  // -----------------------------------

  // Enter the context of the function; ToObject has to run in the function
  // context, and we also need to take the global proxy from the function
  // context in case of conversion.
  __ LoadTaggedField(rsi, FieldOperand(rdi, JSFunction::kContextOffset));
  // We need to convert the receiver for non-native sloppy mode functions.
  Label done_convert;
  __ testl(FieldOperand(rdx, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::IsNativeBit::kMask |
                     SharedFunctionInfo::IsStrictBit::kMask));
  __ j(not_zero, &done_convert);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments
    //  -- rdx : the shared function info.
    //  -- rdi : the function to call (checked to be a JSFunction)
    //  -- rsi : the function context.
    // -----------------------------------

    if (mode == ConvertReceiverMode::kNullOrUndefined) {
      // Patch receiver to global proxy.
      __ LoadGlobalProxy(rcx);
    } else {
      Label convert_to_object, convert_receiver;
      __ movq(rcx, args.GetReceiverOperand());
      __ JumpIfSmi(rcx, &convert_to_object,
                   DEBUG_BOOL ? Label::kFar : Label::kNear);
      __ JumpIfJSAnyIsNotPrimitive(rcx, rbx, &done_convert,
                                   DEBUG_BOOL ? Label::kFar : Label::kNear);
      if (mode != ConvertReceiverMode::kNotNullOrUndefined) {
        Label convert_global_proxy;
        __ JumpIfRoot(rcx, RootIndex::kUndefinedValue, &convert_global_proxy,
                      DEBUG_BOOL ? Label::kFar : Label::kNear);
        __ JumpIfNotRoot(rcx, RootIndex::kNullValue, &convert_to_object,
                         DEBUG_BOOL ? Label::kFar : Label::kNear);
        __ bind(&convert_global_proxy);
        {
          // Patch receiver to global proxy.
          __ LoadGlobalProxy(rcx);
        }
        __ jmp(&convert_receiver);
      }
      __ bind(&convert_to_object);
      {
        // Convert receiver using ToObject.
        // TODO(bmeurer): Inline the allocation here to avoid building the frame
        // in the fast case? (fall back to AllocateInNewSpace?)
        FrameScope scope(masm, StackFrame::INTERNAL);
        __ SmiTag(rax);
        __ Push(rax);
        __ Push(rdi);
        __ movq(rax, rcx);
        __ Push(rsi);
        __ CallBuiltin(Builtin::kToObject);
        __ Pop(rsi);
        __ movq(rcx, rax);
        __ Pop(rdi);
        __ Pop(rax);
        __ SmiUntagUnsigned(rax);
      }
      __ LoadTaggedField(
          rdx, FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
      __ bind(&convert_receiver);
    }
    __ movq(args.GetReceiverOperand(), rcx);
  }
  __ bind(&done_convert);

  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the shared function info.
  //  -- rdi : the function to call (checked to be a JSFunction)
  //  -- rsi : the function context.
  // -----------------------------------

#ifdef V8_ENABLE_LEAPTIERING
  __ InvokeFunctionCode(rdi, no_reg, rax, InvokeType::kJump);
#else
  __ movzxwq(
      rbx, FieldOperand(rdx, SharedFunctionInfo::kFormalParameterCountOffset));
  __ InvokeFunctionCode(rdi, no_reg, rbx, rax, InvokeType::kJump);
#endif
}

namespace {

void Generate_PushBoundArguments(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : new.target (only in case of [[Construct]])
  //  -- rdi : target (checked to be a JSBoundFunction)
  // -----------------------------------

  // Load [[BoundArguments]] into rcx and length of that into rbx.
  Label no_bound_arguments;
  __ LoadTaggedField(rcx,
                     FieldOperand(rdi, JSBoundFunction::kBoundArgumentsOffset));
  __ SmiUntagFieldUnsigned(rbx,
                           FieldOperand(rcx, offsetof(FixedArray, length_)));
  __ testl(rbx, rbx);
  __ j(zero, &no_bound_arguments);
  {
    // ----------- S t a t e -------------
    //  -- rax : the number of arguments
    //  -- rdx : new.target (only in case of [[Construct]])
    //  -- rdi : target (checked to be a JSBoundFunction)
    //  -- rcx : the [[BoundArguments]] (implemented as FixedArray)
    //  -- rbx : the number of [[BoundArguments]] (checked to be non-zero)
    // -----------------------------------

    // TODO(victor): Use Generate_StackOverflowCheck here.
    // Check the stack for overflow.
    {
      Label done;
      __ shlq(rbx, Immediate(kSystemPointerSizeLog2));
      __ movq(kScratchRegister, rsp);
      __ subq(kScratchRegister, rbx);

      // We are not trying to catch interruptions (i.e. debug break and
      // preemption) here, so check the "real stack limit".
      __ cmpq(kScratchRegister,
              __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
      __ j(above_equal, &done, Label::kNear);
      {
        FrameScope scope(masm, StackFrame::MANUAL);
        __ EnterFrame(StackFrame::INTERNAL);
        __ CallRuntime(Runtime::kThrowStackOverflow);
      }
      __ bind(&done);
    }

    // Save Return Address and Receiver into registers.
    __ Pop(r8);
    __ Pop(r10);

    // Push [[BoundArguments]] to the stack.
    {
      Label loop;
      __ LoadTaggedField(
          rcx, FieldOperand(rdi, JSBoundFunction::kBoundArgumentsOffset));
      __ SmiUntagFieldUnsigned(
          rbx, FieldOperand(rcx, offsetof(FixedArray, length_)));
      __ addq(rax, rbx);  // Adjust effective number of arguments.
      __ bind(&loop);
      // Instead of doing decl(rbx) here subtract kTaggedSize from the header
      // offset in order to be able to move decl(rbx) right before the loop
      // condition. This is necessary in order to avoid flags corruption by
      // pointer decompression code.
      __ LoadTaggedField(
          r12, FieldOperand(rcx, rbx, times_tagged_size,
                            OFFSET_OF_DATA_START(FixedArray) - kTaggedSize));
      __ Push(r12);
      __ decl(rbx);
      __ j(greater, &loop);
    }

    // Recover Receiver and Return Address.
    __ Push(r10);
    __ Push(r8);
  }
  __ bind(&no_bound_arguments);
}

}  // namespace

// static
void Builtins::Generate_CallBoundFunctionImpl(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the function to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertBoundFunction(rdi);

  // Patch the receiver to [[BoundThis]].
  StackArgumentsAccessor args(rax);
  __ LoadTaggedField(rbx, FieldOperand(rdi, JSBoundFunction::kBoundThisOffset));
  __ movq(args.GetReceiverOperand(), rbx);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Call the [[BoundTargetFunction]] via the Call builtin.
  __ LoadTaggedField(
      rdi, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtins::Call());
}

// static
void Builtins::Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdi : the target to call (can be any Object)
  // -----------------------------------
  Register argc = rax;
  Register target = rdi;
  Register map = rcx;
  Register instance_type = rdx;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  Label non_callable, class_constructor;
  __ JumpIfSmi(target, &non_callable);
  __ LoadMap(map, target);
  __ CmpInstanceTypeRange(map, instance_type, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                          LAST_CALLABLE_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtins::CallFunction(mode), below_equal);

  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallBoundFunction, equal);

  // Check if target has a [[Call]] internal method.
  __ testb(FieldOperand(map, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsCallableBit::kMask));
  __ j(zero, &non_callable, Label::kNear);

  // Check if target is a proxy and call CallProxy external builtin
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kCallProxy, equal);

  // Check if target is a wrapped function and call CallWrappedFunction external
  // builtin
  __ cmpw(instance_type, Immediate(JS_WRAPPED_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kCallWrappedFunction, equal);

  // ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList)
  // Check that the function is not a "classConstructor".
  __ cmpw(instance_type, Immediate(JS_CLASS_CONSTRUCTOR_TYPE));
  __ j(equal, &class_constructor);

  // 2. Call to something else, which might have a [[Call]] internal method (if
  // not we raise an exception).

  // Overwrite the original receiver with the (original) target.
  __ movq(args.GetReceiverOperand(), target);
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
  //  -- rax : the number of arguments
  //  -- rdx : the new target (checked to be a constructor)
  //  -- rdi : the constructor to call (checked to be a JSFunction)
  // -----------------------------------
  __ AssertConstructor(rdi);
  __ AssertFunction(rdi);

  // Calling convention for function specific ConstructStubs require
  // rbx to contain either an AllocationSite or undefined.
  __ LoadRoot(rbx, RootIndex::kUndefinedValue);

  // Jump to JSBuiltinsConstructStub or JSConstructStubGeneric.
  const TaggedRegister shared_function_info(rcx);
  __ LoadTaggedField(shared_function_info,
                     FieldOperand(rdi, JSFunction::kSharedFunctionInfoOffset));
  __ testl(FieldOperand(shared_function_info, SharedFunctionInfo::kFlagsOffset),
           Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ TailCallBuiltin(Builtin::kJSBuiltinsConstructStub, not_zero);

  __ TailCallBuiltin(Builtin::kJSConstructStubGeneric);
}

// static
void Builtins::Generate_ConstructBoundFunction(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (checked to be a constructor)
  //  -- rdi : the constructor to call (checked to be a JSBoundFunction)
  // -----------------------------------
  __ AssertConstructor(rdi);
  __ AssertBoundFunction(rdi);

  // Push the [[BoundArguments]] onto the stack.
  Generate_PushBoundArguments(masm);

  // Patch new.target to [[BoundTargetFunction]] if new.target equals target.
  {
    Label done;
    __ cmpq(rdi, rdx);
    __ j(not_equal, &done, Label::kNear);
    __ LoadTaggedField(
        rdx, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
    __ bind(&done);
  }

  // Construct the [[BoundTargetFunction]] via the Construct builtin.
  __ LoadTaggedField(
      rdi, FieldOperand(rdi, JSBoundFunction::kBoundTargetFunctionOffset));
  __ TailCallBuiltin(Builtin::kConstruct);
}

// static
void Builtins::Generate_Construct(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- rax : the number of arguments
  //  -- rdx : the new target (either the same as the constructor or
  //           the JSFunction on which new was invoked initially)
  //  -- rdi : the constructor to call (can be any Object)
  // -----------------------------------
  Register argc = rax;
  Register target = rdi;
  Register map = rcx;
  Register instance_type = r8;
  DCHECK(!AreAliased(argc, target, map, instance_type));

  StackArgumentsAccessor args(argc);

  // Check if target is a Smi.
  Label non_constructor;
  __ JumpIfSmi(target, &non_constructor);

  // Check if target has a [[Construct]] internal method.
  __ LoadMap(map, target);
  __ testb(FieldOperand(map, Map::kBitFieldOffset),
           Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Dispatch based on instance type.
  __ CmpInstanceTypeRange(map, instance_type, FIRST_JS_FUNCTION_TYPE,
                          LAST_JS_FUNCTION_TYPE);
  __ TailCallBuiltin(Builtin::kConstructFunction, below_equal);

  // Only dispatch to bound functions after checking whether they are
  // constructors.
  __ cmpw(instance_type, Immediate(JS_BOUND_FUNCTION_TYPE));
  __ TailCallBuiltin(Builtin::kConstructBoundFunction, equal);

  // Only dispatch to proxies after checking whether they are constructors.
  __ cmpw(instance_type, Immediate(JS_PROXY_TYPE));
  __ TailCallBuiltin(Builtin::kConstructProxy, equal);

  // Called Construct on an exotic Object with a [[Construct]] internal method.
  {
    // Overwrite the original receiver with the (original) target.
    __ movq(args.GetReceiverOperand(), target);
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
  // Drop the return address on the stack and jump to the OSR entry
  // point of the function.
  __ Drop(1);
  // TODO(sroettger): Use the notrack prefix since not all OSR entries emit an
  // endbr instruction yet.
  __ jmp(entry_address, /*notrack=*/true);
}

enum class OsrSourceTier {
  kInterpreter,
  kBaseline,
  kMaglev,
};

void OnStackReplacement(MacroAssembler* masm, OsrSourceTier source,
                        Register maybe_target_code) {
  Label jump_to_optimized_code;
  {
    // If maybe_target_code is not null, no need to call into runtime. A
    // precondition here is: if maybe_target_code is an InstructionStream
    // object, it must NOT be marked_for_deoptimization (callers must ensure
    // this).
    __ testq(maybe_target_code, maybe_target_code);
    __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  }

  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ CallRuntime(Runtime::kCompileOptimizedOSR);
  }

  // If the code object is null, just return to the caller.
  __ testq(rax, rax);
  __ j(not_equal, &jump_to_optimized_code, Label::kNear);
  __ ret(0);

  __ bind(&jump_to_optimized_code);
  DCHECK_EQ(maybe_target_code, rax);  // Already in the right spot.

  if (source == OsrSourceTier::kMaglev) {
    // Maglev doesn't enter OSR'd code itself, since OSR depends on the
    // unoptimized (~= Ignition) stack frame layout. Instead, return to Maglev
    // code and let it deoptimize.
    __ ret(0);
    return;
  }

  // OSR entry tracing.
  {
    Label next;
    __ cmpb(
        __ ExternalReferenceAsOperand(
            ExternalReference::address_of_log_or_trace_osr(), kScratchRegister),
        Immediate(0));
    __ j(equal, &next, Label::kNear);

    {
      FrameScope scope(masm, StackFrame::INTERNAL);
      __ Push(rax);  // Preserve the code object.
      __ CallRuntime(Runtime::kLogOrTraceOptimizedOSREntry, 0);
      __ Pop(rax);
    }

    __ bind(&next);
  }

  if (source == OsrSourceTier::kInterpreter) {
    // Drop the handler frame that is be sitting on top of the actual
    // JavaScript frame.
    __ leave();
  }

  // Load deoptimization data from the code object.
  const Register deopt_data(rbx);
  __ LoadProtectedPointerField(
      deopt_data,
      FieldOperand(rax, Code::kDeoptimizationDataOrInterpreterDataOffset));

  // Load the OSR entrypoint offset from the deoptimization data.
  __ SmiUntagField(
      rbx,
      FieldOperand(deopt_data, TrustedFixedArray::OffsetOfElementAt(
                                   DeoptimizationData::kOsrPcOffsetIndex)));

  __ LoadCodeInstructionStart(rax, rax, kJSEntrypointTag);

  // Compute the target address = code_entry + osr_offset
  __ addq(rax, rbx);

  Generate_OSREntry(masm, rax);
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
  __ movq(kContextRegister,
          MemOperand(rbp, BaselineFrameConstants::kContextOffset));
  OnStackReplacement(masm, OsrSourceTier::kBaseline,
                     D::MaybeTargetCodeRegister());
}

void Builtins::Generate_MaglevOnStackReplacement(MacroAssembler* masm) {
  using D =
      i::CallInterfaceDescriptorFor<Builtin::kMaglevOnStackReplacement>::type;
  static_assert(D::kParameterCount == 1);
  OnStackReplacement(masm, OsrSourceTier::kMaglev,
                     D::MaybeTargetCodeRegister());
}

#ifdef V8_ENABLE_MAGLEV

// static
void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  // Input (rax): Stack size (Smi).
  // This builtin can be invoked just after Maglev's prologue.
  // All registers are available, except (possibly) new.target.
  ASM_CODE_COMMENT(masm);
  {
    FrameScope scope(masm, StackFrame::INTERNAL);
    __ AssertSmi(rax);
    if (save_new_target) {
      if (PointerCompressionIsEnabled()) {
        __ AssertSmiOrHeapObjectInMainCompressionCage(
            kJavaScriptCallNewTargetRegister);
      }
      __ Push(kJavaScriptCallNewTargetRegister);
    }
    __ Push(rax);
    __ CallRuntime(Runtime::kStackGuardWithGap, 1);
    if (save_new_target) {
      __ Pop(kJavaScriptCallNewTargetRegister);
    }
  }
  __ Ret();
}

#endif  // V8_ENABLE_MAGLEV

namespace {

void Generate_RestoreFrameDescriptionRegisters(MacroAssembler* masm,
                                               Register frame_description) {
  // Set the xmm (simd / double) registers.
  const RegisterConfiguration* config = RegisterConfiguration::Default();
  int simd128_regs_offset = FrameDescription::simd128_registers_offset();
  for (int i = 0; i < config->num_allocatable_simd128_registers(); ++i) {
    int code = config->GetAllocatableSimd128Code(i);
    XMMRegister xmm_reg = XMMRegister::from_code(code);
    int src_offset = code * kSimd128Size + simd128_regs_offset;
    __ movdqu(xmm_reg, Operand(frame_description, src_offset));
  }

  // Restore the non-xmm registers from the stack.
  for (int i = Register::kNumRegisters - 1; i >= 0; i--) {
    Register r = Register::from_code(i);
    // Do not restore rsp and kScratchRegister.
    if (r == rsp || r == kScratchRegister) continue;
    __ popq(r);
  }
}

}  // namespace

#ifdef V8_ENABLE_CET_SHADOW_STACK
// AdaptShadowStackForDeopt assists the deoptimizer in getting continuation
// addresses placed on the shadow stack. This can only be done with a call
// instruction. Earlier in the deoptimization process, the user stack was
// seeded with return addresses into the continuations. At this stage, we
// make calls into the continuations such that the shadow stack contains
// precisely those necessary return addresses back into those continuations,
// and in the appropriate order that the shadow stack and the user stack
// perfectly match up at the points where return instructions are executed.
//
// The stack layout on entry to AdaptShadowStackForDeopt is as follows:
//
// ReturnAddress_1
// ReturnAddress_2
// ...
// ReturnAddresss_N
// LastFrameDescription (for restoring registers)
// savedRegister_1
// savedRegister_2
// ...
//
// kAdaptShadowStackCountRegister, on entry, has the value N, matching the
// number of identifiers to pop from the stack above. It is decremented each
// time AdaptShadowStackForDeopt pops a return address from the stack. This
// happens once per invocation of AdaptShadowStackForDeopt. When the value
// is 0, the function jumps to the last return address and will not be called
// again for this deoptimization process.
//
// The other cpu registers have already been populated with the required values
// to kick off execution running the builtin continuation associated with
// ReturnAddress_N on the stack above. AdaptShadowStackForDeopt uses
// kScratchRegister and kAdaptShadowStackRegister for its own work, and
// that is why those registers are additionaly saved on the stack, to be
// restored at the end of the process.

// kAdaptShadowStackDispatchFirstEntryOffset marks the "kick-off" location in
// AdaptShadowStackForDeopt for the process.
constexpr int kAdaptShadowStackDispatchFirstEntryOffset = 1;

// kAdaptShadowStackCountRegister contains the number of identifiers on
// the stack to be consumed via repeated calls into AdaptShadowStackForDeopt.
constexpr Register kAdaptShadowStackCountRegister = r11;

void Builtins::Generate_AdaptShadowStackForDeopt(MacroAssembler* masm) {
  Register count_reg = kAdaptShadowStackCountRegister;
  Register addr = rax;

  // Pop unnecessary return address on stack.
  __ popq(addr);

  // DeoptimizationEntry enters here.
  CHECK_EQ(masm->pc_offset(), kAdaptShadowStackDispatchFirstEntryOffset);

  __ decl(count_reg);
  __ popq(addr);  // Pop the next target address.

  __ pushq(count_reg);
  __ Move(kCArgRegs[0], ExternalReference::isolate_address());
  __ movq(kCArgRegs[1], addr);
  __ PrepareCallCFunction(2);
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    // We should block jumps to arbitrary locations for a security reason.
    // This function will crash if the address is not in the allow list.
    // And, return the given address if it is valid.
    __ CallCFunction(ExternalReference::ensure_valid_return_address(), 2);
  }
  __ popq(count_reg);
  // Now `kReturnRegister0` is the address we want to jump to.

  __ cmpl(count_reg, Immediate(0));
  Label finished;
  __ j(equal, &finished, Label::kNear);
  // This will jump to CallToAdaptShadowStackForDeopt which call back into this
  // function and continue adapting shadow stack.
  __ jmp(kReturnRegister0);

  __ bind(&finished);
  __ movb(__ ExternalReferenceAsOperand(IsolateFieldId::kStackIsIterable),
          Immediate(1));
  __ movq(kScratchRegister, kReturnRegister0);

  __ popq(rbx);  // Restore the last FrameDescription.
  Generate_RestoreFrameDescriptionRegisters(masm, rbx);
  __ jmp(kScratchRegister);
}
#endif  // V8_ENABLE_CET_SHADOW_STACK

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
    __ movdqu(Operand(rsp, offset), reg);
    offset += kSimd128Size;
  }
  return offset;
}

// Consumes the offset beyond the last saved FP register (as returned by
// {SaveWasmParams}).
void RestoreWasmParams(MacroAssembler* masm, int offset) {
  for (DoubleRegister reg : base::Reversed(wasm::kFpParamRegisters)) {
    offset -= kSimd128Size;
    __ movdqu(reg, Operand(rsp, offset));
  }
  DCHECK_EQ(0, offset);
  __ addq(rsp, Immediate(kSimd128Size * arraysize(wasm::kFpParamRegisters)));
  for (Register reg : base::Reversed(wasm::kGpParamRegisters)) {
    __ Pop(reg);
  }
}

// When this builtin is called, the topmost stack entry is the calling pc.
// This is replaced with the following:
//
// [    calling pc      ]  <-- rsp; popped by {ret}.
// [  feedback vector   ]
// [ Wasm instance data ]
// [ WASM frame marker  ]
// [    saved rbp       ]  <-- rbp; this is where "calling pc" used to be.
void Builtins::Generate_WasmLiftoffFrameSetup(MacroAssembler* masm) {
  Register func_index = wasm::kLiftoffFrameSetupFunctionReg;
  Register vector = r15;
  Register calling_pc = rdi;

  __ Pop(calling_pc);
  __ Push(rbp);
  __ Move(rbp, rsp);
  __ Push(Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ LoadTaggedField(
      vector, FieldOperand(kWasmImplicitArgRegister,
                           WasmTrustedInstanceData::kFeedbackVectorsOffset));
  __ LoadTaggedField(vector, FieldOperand(vector, func_index, times_tagged_size,
                                          OFFSET_OF_DATA_START(FixedArray)));
  Label allocate_vector, done;
  __ JumpIfSmi(vector, &allocate_vector);
  __ bind(&done);
  __ Push(kWasmImplicitArgRegister);
  __ Push(vector);
  __ Push(calling_pc);
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
  // [           calling pc           ]
  // [   WASM_LIFTOFF_SETUP marker    ]
  // [           saved rbp            ]
  __ movq(Operand(rbp, TypedFrameConstants::kFrameTypeOffset),
          Immediate(StackFrame::TypeToMarker(StackFrame::WASM_LIFTOFF_SETUP)));
  __ set_has_frame(true);
  __ Push(calling_pc);
  int offset = SaveWasmParams(masm);

  // Arguments to the runtime function: instance data, func_index.
  __ Push(kWasmImplicitArgRegister);
  __ SmiTag(func_index);
  __ Push(func_index);
  // Allocate a stack slot where the runtime function can spill a pointer
  // to the NativeModule.
  __ Push(rsp);
  __ Move(kContextRegister, Smi::zero());
  __ CallRuntime(Runtime::kWasmAllocateFeedbackVector, 3);
  __ movq(vector, kReturnRegister0);

  RestoreWasmParams(masm, offset);
  __ Pop(calling_pc);
  // Restore correct frame type.
  __ movq(Operand(rbp, TypedFrameConstants::kFrameTypeOffset),
          Immediate(StackFrame::TypeToMarker(StackFrame::WASM)));
  __ jmp(&done);
}

void Builtins::Generate_WasmCompileLazy(MacroAssembler* masm) {
  // The function index was pushed to the stack by the caller as int32.
  __ Pop(r15);
  // Convert to Smi for the runtime call.
  __ SmiTag(r15);

  {
    HardAbortScope hard_abort(masm);  // Avoid calls to Abort.
    FrameScope scope(masm, StackFrame::INTERNAL);

    int offset = SaveWasmParams(masm);

    // Push arguments for the runtime function.
    __ Push(kWasmImplicitArgRegister);
    __ Push(r15);
    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmCompileLazy, 2);
    // The runtime function returns the jump table slot offset as a Smi. Use
    // that to compute the jump target in r15.
    __ SmiUntagUnsigned(kReturnRegister0);
    __ movq(r15, kReturnRegister0);

    RestoreWasmParams(masm, offset);
    // After the instance data register has been restored, we can add the jump
    // table start to the jump table offset already stored in r15.
    __ addq(r15,
            MemOperand(kWasmImplicitArgRegister,
                       wasm::ObjectAccess::ToTagged(
                           WasmTrustedInstanceData::kJumpTableStartOffset)));
  }

  // Finally, jump to the jump table slot for the function.
  __ jmp(r15);
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
      __ movdqu(Operand(rsp, offset), reg);
    }

    // Initialize the JavaScript context with 0. CEntry will use it to
    // set the current context on the isolate.
    __ Move(kContextRegister, Smi::zero());
    __ CallRuntime(Runtime::kWasmDebugBreak, 0);

    // Restore registers.
    for (DoubleRegister reg : WasmDebugBreakFrameConstants::kPushedFpRegs) {
      __ movdqu(reg, Operand(rsp, offset));
      offset += kSimd128Size;
    }
    __ addq(rsp, Immediate(kFpStackSize));
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
#if V8_ENABLE_SANDBOX
  __ cmpl(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(old_state));
  Label ok;
  __ j(equal, &ok, Label::kNear);
  __ Trap();
  __ bind(&ok);
#endif
  __ movl(MemOperand(jmpbuf, wasm::kJmpBufStateOffset), Immediate(new_state));
}

void FillJumpBuffer(MacroAssembler* masm, Register jmpbuf, Label* pc) {
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufSpOffset), rsp);
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufFpOffset), rbp);
  __ movq(kScratchRegister,
          __ StackLimitAsOperand(StackLimitKind::kRealStackLimit));
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufStackLimitOffset), kScratchRegister);
  __ leaq(kScratchRegister, MemOperand(pc, 0));
  __ movq(MemOperand(jmpbuf, wasm::kJmpBufPcOffset), kScratchRegister);
}

void LoadJumpBuffer(MacroAssembler* masm, Register jmpbuf, bool load_pc,
                    wasm::JumpBuffer::StackState expected_state) {
  __ movq(rsp, MemOperand(jmpbuf, wasm::kJmpBufSpOffset));
  __ movq(rbp, MemOperand(jmpbuf, wasm::kJmpBufFpOffset));
  SwitchStackState(masm, jmpbuf, expected_state, wasm::JumpBuffer::Active);
  if (load_pc) {
    __ jmp(MemOperand(jmpbuf, wasm::kJmpBufPcOffset));
  }
  // The stack limit is set separately under the ExecutionAccess lock.
}

void SaveState(MacroAssembler* masm, Register active_continuation, Register tmp,
               Label* suspend) {
  Register jmpbuf = tmp;
  __ LoadExternalPointerField(
      jmpbuf,
      FieldOperand(active_continuation, WasmContinuationObject::kJmpbufOffset),
      kWasmContinuationJmpbufTag, kScratchRegister);
  FillJumpBuffer(masm, jmpbuf, suspend);
}

void LoadTargetJumpBuffer(MacroAssembler* masm, Register target_continuation,
                          wasm::JumpBuffer::StackState expected_state) {
  Register target_jmpbuf = target_continuation;
  __ LoadExternalPointerField(
      target_jmpbuf,
      FieldOperand(target_continuation, WasmContinuationObject::kJmpbufOffset),
      kW
```