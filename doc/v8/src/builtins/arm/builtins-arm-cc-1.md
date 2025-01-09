Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/arm/builtins-arm.cc`.

Here's a breakdown of how to approach this:

1. **Identify Key Functions/Sections:** Scan the code for function definitions and major code blocks.
2. **Understand the Purpose of Each Section:** Analyze the code within each function/block to determine its role. Look for patterns like frame setup, argument handling, calls to other functions/builtins, and specific V8 concepts like bytecode, feedback vectors, etc.
3. **Relate to JavaScript Functionality (if applicable):**  Consider how the operations in the C++ code might correspond to actions taken when executing JavaScript code.
4. **Look for Control Flow and Logic:**  Pay attention to conditional jumps (e.g., `b(eq, ...)`, `b(ne, ...)`) and labels to understand the flow of execution and decision-making.
5. **Infer Input/Output:** Based on the function names and operations, deduce what inputs the functions might expect and what outputs they might produce (though direct output isn't always explicit in this kind of low-level code).
6. **Identify Potential User Errors:** Think about common mistakes JavaScript developers might make that could lead to the execution of this code.
7. **Address the `.tq` Check:**  Explicitly note whether the file ends in `.tq` and explain the implications.
8. **Synthesize a Summary:** Combine the understanding of individual parts into a concise overview of the file's purpose.

**Applying this to the provided code:**

* **`AdvanceBytecodeOffsetOrReturn`:**  This function seems crucial for the interpreter's execution loop, handling bytecode advancement or function return.
* **`ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`, `ResetFeedbackVectorOsrUrgency`:** These functions deal with resetting the age/urgency information related to functions and feedback, likely for optimization and deoptimization purposes.
* **`Generate_BaselineOutOfLinePrologue`:** This appears to be the entry point for baseline-compiled functions when they need to execute out-of-line code (like handling stack checks or tiering).
* **`Generate_BaselineOutOfLinePrologueDeopt`:** This function is specifically for handling deoptimization that happens during the baseline prologue.
* **`Generate_InterpreterEntryTrampoline`:** This is the main entry point for executing JavaScript functions in the interpreter. It involves frame setup, bytecode loading, dispatching, and handling returns.
* **`GenerateInterpreterPushArgs`, `Generate_InterpreterPushArgsThenCallImpl`, `Generate_InterpreterPushArgsThenConstructImpl`:** These functions handle pushing arguments onto the stack before making function calls or constructing new objects within the interpreter.
* **`Generate_ConstructForwardAllArgsImpl`:**  This function seems to be for forwarding arguments during constructor calls.
* **`Generate_InterpreterPushArgsThenFastConstructFunction`:** This function handles the optimized "fast construct" path for functions.
* **`Generate_InterpreterEnterBytecode`:** This function appears to be responsible for setting up the interpreter to start executing bytecode within a function.

By analyzing these sections, we can build a picture of the file's overall role in the V8 interpreter on ARM architecture.
Based on the provided code snippet from `v8/src/builtins/arm/builtins-arm.cc`, here's a summary of its functionality:

This code implements various **built-in functions and runtime support routines specifically for the ARM architecture** within the V8 JavaScript engine's interpreter. It deals with low-level operations necessary for executing JavaScript code in the interpreter, particularly focusing on function calls, constructor calls, and managing the execution stack.

Here's a breakdown of the key functionalities:

* **Bytecode Handling:**
    * **`AdvanceBytecodeOffsetOrReturn`:**  This function is crucial for the interpreter's execution loop. It determines whether to advance the current bytecode offset to the next instruction or to return from the current function. This is the core logic for moving through the bytecode.

* **Optimization and Tiering Support:**
    * **`ResetSharedFunctionInfoAge`, `ResetJSFunctionAge`:** These functions are involved in resetting the "age" of shared function information and JSFunction objects. This is likely related to V8's optimization pipeline, where frequently executed functions become candidates for optimization. Resetting the age might be a part of deoptimization or a mechanism to re-evaluate optimization opportunities.
    * **`ResetFeedbackVectorOsrUrgency`:** This function manipulates the "OSR (On-Stack Replacement) urgency" bits in a feedback vector. This is directly related to V8's tiering compilation system, where the engine decides whether and when to optimize a function further during its execution.

* **Function Prologues and Epilogues:**
    * **`Generate_BaselineOutOfLinePrologue`:** This generates the prologue code for baseline-compiled functions when they need to execute out-of-line code (code that isn't directly part of the main function body, like stack overflow checks or tiering decisions). It sets up the stack frame and performs checks related to optimization and stack limits.
    * **`Generate_BaselineOutOfLinePrologueDeopt`:** This generates code to handle deoptimization that occurs during the `BaselineOutOfLinePrologue`. It undoes the prologue's setup and transitions execution back to the interpreter.
    * **`Generate_InterpreterEntryTrampoline`:** This is the core entry point for executing JavaScript functions in the interpreter. It sets up the interpreter's stack frame, loads the bytecode, and dispatches to the appropriate bytecode handler. It also handles stack overflow checks and potential transitions to optimized code.

* **Function and Constructor Calls:**
    * **`GenerateInterpreterPushArgs`:**  A helper function to push arguments onto the stack in the correct order for function calls.
    * **`Generate_InterpreterPushArgsThenCallImpl`:** This generates code for calling JavaScript functions within the interpreter. It handles pushing arguments and then performing a tail call to the appropriate built-in call function. It also manages receiver handling (the `this` value).
    * **`Generate_InterpreterPushArgsThenConstructImpl`:** This generates code for calling JavaScript constructors within the interpreter. It pushes arguments, handles the `new.target`, and performs a tail call to the appropriate built-in construct function.
    * **`Generate_ConstructForwardAllArgsImpl`:** This generates code to forward all arguments from a current or parent frame to a constructor call. This is used in scenarios like extending built-in classes.
    * **`Generate_InterpreterPushArgsThenFastConstructFunction`:** This generates code for an optimized "fast path" for constructing JavaScript functions. It aims to be more efficient by avoiding certain checks and directly allocating the object. It also handles the creation of an implicit receiver for certain constructor types.

* **Entering Bytecode Execution:**
    * **`Generate_InterpreterEnterBytecode`:** This function sets up the execution context to begin interpreting bytecode. It loads the bytecode array and bytecode offset from the current frame and prepares to dispatch to the first bytecode instruction.

**If `v8/src/builtins/arm/builtins-arm.cc` ended with `.tq`, it would be a V8 Torque source file.** Torque is a domain-specific language used within V8 to define built-in functions in a more structured and type-safe way. The code provided is C++, which is the more traditional way to implement built-ins in V8.

**Relationship to JavaScript with Examples:**

Many of the functionalities in this code directly correspond to common JavaScript operations:

* **Function Calls:** When you call a JavaScript function like `myFunction(arg1, arg2)`, the `Generate_InterpreterPushArgsThenCallImpl` (or a similar optimized version) would be responsible for setting up the call stack and initiating the function's execution.

   ```javascript
   function myFunction(a, b) {
     return a + b;
   }

   myFunction(5, 10); // This call would involve the described built-ins.
   ```

* **Constructor Calls (`new` keyword):**  When you create a new object using `new MyClass()`, the `Generate_InterpreterPushArgsThenConstructImpl` or `Generate_InterpreterPushArgsThenFastConstructFunction` would be involved in allocating the new object and calling the constructor.

   ```javascript
   class MyClass {
     constructor(value) {
       this.myValue = value;
     }
   }

   const instance = new MyClass(42); // This `new` operation uses the built-ins.
   ```

* **Extending Classes:** When you use `super()` in a derived class constructor, `Generate_ConstructForwardAllArgsImpl` might be used to forward arguments to the parent class's constructor.

   ```javascript
   class Parent {
     constructor(name) {
       this.name = name;
     }
   }

   class Child extends Parent {
     constructor(name, age) {
       super(name); // Arguments forwarded to Parent's constructor.
       this.age = age;
     }
   }
   ```

**Code Logic Inference with Assumptions:**

Let's take the `AdvanceBytecodeOffsetOrReturn` function as an example:

**Assumed Input:**

* `bytecode`: The current bytecode instruction being executed.
* `bytecode_offset`: The current offset within the bytecode array.
* `original_bytecode_offset`: The original bytecode offset before considering wide/extra-wide prefixes.
* `bytecode_size_table`: A table mapping bytecode opcodes to their sizes.
* Registers `scratch1`, `scratch2`, `scratch3` as temporary storage.
* Labels `if_return`, `JUMP_IF_EQUAL`.

**Assumed Behavior and Output:**

1. **Check for Return:** If `bytecode` corresponds to a return instruction, jump to the `if_return` label.
2. **Check for Conditional Jump:** If `bytecode` is a conditional jump (and the condition is met), jump to the target specified by the jump instruction.
3. **Handle JumpLoop:** If `bytecode` is `JumpLoop`, restore the `bytecode_offset` to the `original_bytecode_offset` (to loop back).
4. **Advance Offset (Otherwise):** If none of the above, load the size of the current `bytecode` from the `bytecode_size_table` and add it to the `bytecode_offset` to point to the next instruction.

**Common Programming Errors (Indirectly Related):**

While this code is low-level, the JavaScript errors that might lead to the execution of these built-ins include:

* **Stack Overflow:**  Deeply nested function calls or excessively large local variable allocations can lead to stack overflow errors, which these built-ins try to detect and handle (`StackOverflowCheck`).
* **Type Errors:** Incorrectly using the `new` keyword on non-constructor functions can lead to errors that might involve the `Generate_ConstructedNonConstructable` builtin.
* **Incorrect `this` Binding:** Issues with the `this` keyword in JavaScript can sometimes be related to how the receiver is handled during function calls, which is a part of the `Generate_InterpreterPushArgsThenCallImpl` logic.
* **Exceeding Argument Limits:**  Calling functions with a very large number of arguments might trigger stack-related checks within these built-ins.

**Summary of Functionality (Part 2):**

This section of `v8/src/builtins/arm/builtins-arm.cc` primarily focuses on the **implementation of key interpreter functionalities for the ARM architecture**, specifically:

* **Managing the interpreter's execution flow** by handling bytecode advancement and returns.
* **Supporting V8's optimization and tiering mechanisms** through functions that reset function ages and manipulate feedback vector urgency.
* **Generating prologue and epilogue code** for baseline-compiled functions and the main interpreter entry point.
* **Implementing different strategies for function and constructor calls**, including argument handling and receiver setup.
* **Setting up the interpreter context** to begin executing bytecode.

Essentially, it lays the groundwork for how the V8 interpreter executes JavaScript code on ARM processors.

Prompt: 
```
这是目录为v8/src/builtins/arm/builtins-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/arm/builtins-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
                \
  __ cmp(bytecode, Operand(static_cast<int>(interpreter::Bytecode::k##NAME)), \
         flag);                                                               \
  flag = ne;
  RETURN_BYTECODE_LIST(JUMP_IF_EQUAL)
#undef JUMP_IF_EQUAL

  __ b(if_return, eq);

  // If this is a JumpLoop, re-execute it to perform the jump to the beginning
  // of the loop.
  Label end, not_jump_loop;
  __ cmp(bytecode, Operand(static_cast<int>(interpreter::Bytecode::kJumpLoop)));
  __ b(ne, &not_jump_loop);
  // We need to restore the original bytecode_offset since we might have
  // increased it to skip the wide / extra-wide prefix bytecode.
  __ Move(bytecode_offset, original_bytecode_offset);
  __ b(&end);

  __ bind(&not_jump_loop);
  // Otherwise, load the size of the current bytecode and advance the offset.
  __ ldrb(scratch1, MemOperand(bytecode_size_table, bytecode));
  __ add(bytecode_offset, bytecode_offset, scratch1);

  __ bind(&end);
}

namespace {

void ResetSharedFunctionInfoAge(MacroAssembler* masm, Register sfi,
                                Register scratch) {
  DCHECK(!AreAliased(sfi, scratch));
  __ mov(scratch, Operand(0));
  __ strh(scratch, FieldMemOperand(sfi, SharedFunctionInfo::kAgeOffset));
}

void ResetJSFunctionAge(MacroAssembler* masm, Register js_function,
                        Register scratch1, Register scratch2) {
  __ Move(scratch1,
          FieldMemOperand(js_function, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, scratch1, scratch2);
}

void ResetFeedbackVectorOsrUrgency(MacroAssembler* masm,
                                   Register feedback_vector, Register scratch) {
  DCHECK(!AreAliased(feedback_vector, scratch));
  __ ldrb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
  __ and_(scratch, scratch, Operand(~FeedbackVector::OsrUrgencyBits::kMask));
  __ strb(scratch,
          FieldMemOperand(feedback_vector, FeedbackVector::kOsrStateOffset));
}

}  // namespace

// static
void Builtins::Generate_BaselineOutOfLinePrologue(MacroAssembler* masm) {
  UseScratchRegisterScope temps(masm);
  // Need a few extra registers
  temps.Include({r4, r5, r8, r9});

  auto descriptor =
      Builtins::CallInterfaceDescriptorFor(Builtin::kBaselineOutOfLinePrologue);
  Register closure = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kClosure);
  // Load the feedback cell and vector from the closure.
  Register feedback_cell = temps.Acquire();
  Register feedback_vector = temps.Acquire();
  __ ldr(feedback_cell,
         FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
  __ ldr(feedback_vector,
         FieldMemOperand(feedback_cell, FeedbackCell::kValueOffset));
  {
    UseScratchRegisterScope temps(masm);
    Register temporary = temps.Acquire();
    __ AssertFeedbackVector(feedback_vector, temporary);
  }

  // Check the tiering state.
  Label flags_need_processing;
  Register flags = no_reg;
  {
    UseScratchRegisterScope temps(masm);
    // flags will be used only in |flags_need_processing|
    // and outside it can be reused.
    flags = temps.Acquire();
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);
  }

  {
    UseScratchRegisterScope temps(masm);
    ResetFeedbackVectorOsrUrgency(masm, feedback_vector, temps.Acquire());
  }

  // Increment invocation count for the function.
  {
    UseScratchRegisterScope temps(masm);
    Register invocation_count = temps.Acquire();
    __ ldr(invocation_count,
           FieldMemOperand(feedback_vector,
                           FeedbackVector::kInvocationCountOffset));
    __ add(invocation_count, invocation_count, Operand(1));
    __ str(invocation_count,
           FieldMemOperand(feedback_vector,
                           FeedbackVector::kInvocationCountOffset));
  }

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  {
    ASM_CODE_COMMENT_STRING(masm, "Frame Setup");
    // Normally the first thing we'd do here is Push(lr, fp), but we already
    // entered the frame in BaselineCompiler::Prologue, as we had to use the
    // value lr before the call to this BaselineOutOfLinePrologue builtin.

    Register callee_context = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kCalleeContext);
    Register callee_js_function = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kClosure);
    {
      UseScratchRegisterScope temps(masm);
      ResetJSFunctionAge(masm, callee_js_function, temps.Acquire(),
                         temps.Acquire());
    }
    __ Push(callee_context, callee_js_function);
    DCHECK_EQ(callee_js_function, kJavaScriptCallTargetRegister);
    DCHECK_EQ(callee_js_function, kJSFunctionRegister);

    Register argc = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kJavaScriptCallArgCount);
    // We'll use the bytecode for both code age/OSR resetting, and pushing onto
    // the frame, so load it into a register.
    Register bytecodeArray = descriptor.GetRegisterParameter(
        BaselineOutOfLinePrologueDescriptor::kInterpreterBytecodeArray);
    __ Push(argc, bytecodeArray);
    if (v8_flags.debug_code) {
      UseScratchRegisterScope temps(masm);
      Register scratch = temps.Acquire();
      __ CompareObjectType(feedback_vector, scratch, scratch,
                           FEEDBACK_VECTOR_TYPE);
      __ Assert(eq, AbortReason::kExpectedFeedbackVector);
    }
    __ Push(feedback_cell);
    __ Push(feedback_vector);
  }

  Label call_stack_guard;
  Register frame_size = descriptor.GetRegisterParameter(
      BaselineOutOfLinePrologueDescriptor::kStackFrameSize);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt check");
    // Stack check. This folds the checks for both the interrupt stack limit
    // check and the real stack limit into one by just checking for the
    // interrupt limit. The interrupt limit is either equal to the real stack
    // limit or tighter. By ensuring we have space until that limit after
    // building the frame we can quickly precheck both at once.
    UseScratchRegisterScope temps(masm);

    Register sp_minus_frame_size = temps.Acquire();
    __ sub(sp_minus_frame_size, sp, frame_size);
    Register interrupt_limit = temps.Acquire();
    __ LoadStackLimit(interrupt_limit, StackLimitKind::kInterruptStackLimit);
    __ cmp(sp_minus_frame_size, interrupt_limit);
    __ b(&call_stack_guard, lo);
  }

  // Do "fast" return to the caller pc in lr.
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();

  __ bind(&flags_need_processing);
  {
    ASM_CODE_COMMENT_STRING(masm, "Optimized marker check");
    UseScratchRegisterScope temps(masm);
    // Ensure the flags is not allocated again.
    temps.Exclude(flags);

    // Drop the frame created by the baseline call.
    __ ldm(ia_w, sp, {fp, lr});
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
    __ Trap();
  }

  __ bind(&call_stack_guard);
  {
    ASM_CODE_COMMENT_STRING(masm, "Stack/interrupt call");
    FrameScope frame_scope(masm, StackFrame::INTERNAL);
    // Save incoming new target or generator
    __ Push(kJavaScriptCallNewTargetRegister);
    __ SmiTag(frame_size);
    __ Push(frame_size);
    __ CallRuntime(Runtime::kStackGuardWithGap);
    __ Pop(kJavaScriptCallNewTargetRegister);
  }

  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
  __ Ret();
}

// static
void Builtins::Generate_BaselineOutOfLinePrologueDeopt(MacroAssembler* masm) {
  // We're here because we got deopted during BaselineOutOfLinePrologue's stack
  // check. Undo all its frame creation and call into the interpreter instead.

  // Drop the feedback vector, the bytecode offset (was the feedback vector but
  // got replaced during deopt) and bytecode array.
  __ Drop(3);

  // Context, closure, argc.
  __ Pop(kContextRegister, kJavaScriptCallTargetRegister,
         kJavaScriptCallArgCountRegister);

  // Drop frame pointer
  __ LeaveFrame(StackFrame::BASELINE);

  // Enter the interpreter.
  __ TailCallBuiltin(Builtin::kInterpreterEntryTrampoline);
}

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o r0: actual argument count
//   o r1: the JS function object being called.
//   o r3: the incoming new target or generator object
//   o cp: our context
//   o fp: the caller's frame pointer
//   o sp: stack pointer
//   o lr: return address
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  Register closure = r1;

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ ldr(r4, FieldMemOperand(closure, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, r4, r8);

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, r4,
                                          kInterpreterBytecodeArrayRegister, r8,
                                          &is_baseline, &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = r2;
  __ LoadFeedbackVector(feedback_vector, closure, r4, &push_stack_frame);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count.
  Register flags = r4;
  Label flags_need_processing;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, r4);

  // Increment invocation count for the function.
  __ ldr(r9, FieldMemOperand(feedback_vector,
                             FeedbackVector::kInvocationCountOffset));
  __ add(r9, r9, Operand(1));
  __ str(r9, FieldMemOperand(feedback_vector,
                             FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set up
  // the frame (that is done below).
#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ PushStandardFrame(closure);

  // Load the initial bytecode offset.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Push bytecode array and Smi tagged bytecode array offset.
  __ SmiTag(r4, kInterpreterBytecodeOffsetRegister);
  __ Push(kInterpreterBytecodeArrayRegister, r4, feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    __ ldr(r4, FieldMemOperand(kInterpreterBytecodeArrayRegister,
                               BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ sub(r9, sp, Operand(r4));
    __ LoadStackLimit(r2, StackLimitKind::kRealStackLimit);
    __ cmp(r9, Operand(r2));
    __ b(lo, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ b(&loop_check, al);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ sub(r4, r4, Operand(kPointerSize), SetCC);
    __ b(&loop_header, ge);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in r3.
  __ ldr(r9, FieldMemOperand(
                 kInterpreterBytecodeArrayRegister,
                 BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ cmp(r9, Operand::Zero());
  __ str(r3, MemOperand(fp, r9, LSL, kPointerSizeLog2), ne);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ LoadStackLimit(r4, StackLimitKind::kInterruptStackLimit);
  __ cmp(sp, r4);
  __ b(lo, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));
  __ ldrb(r4, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  __ ldr(
      kJavaScriptCallCodeStartRegister,
      MemOperand(kInterpreterDispatchTableRegister, r4, LSL, kPointerSizeLog2));
  __ Call(kJavaScriptCallCodeStartRegister);

  __ RecordComment("--- InterpreterEntryReturnPC point ---");
  if (mode == InterpreterEntryTrampolineMode::kDefault) {
    masm->isolate()->heap()->SetInterpreterEntryReturnPCOffset(
        masm->pc_offset());
  } else {
    DCHECK_EQ(mode, InterpreterEntryTrampolineMode::kForProfiling);
    // Both versions must be the same up to this point otherwise the builtins
    // will not be interchangable.
    CHECK_EQ(
        masm->isolate()->heap()->interpreter_entry_return_pc_offset().value(),
        masm->pc_offset());
  }

  // Any returns to the entry trampoline are either due to the return bytecode
  // or the interpreter tail calling a builtin and then a dispatch.

  // Get bytecode array and bytecode offset from the stack frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ ldrb(r1, MemOperand(kInterpreterBytecodeArrayRegister,
                         kInterpreterBytecodeOffsetRegister));
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, r1, r2, r3,
                                &do_return);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  // The return value is in r0.
  LeaveInterpreterFrame(masm, r2, r4);
  __ Jump(lr);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                              kFunctionEntryBytecodeOffset)));
  __ str(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  __ SmiTag(r4, kInterpreterBytecodeOffsetRegister);
  __ str(r4, MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);

  __ bind(&is_baseline);
  {
    // Load the feedback vector from the closure.
    __ ldr(feedback_vector,
           FieldMemOperand(closure, JSFunction::kFeedbackCellOffset));
    __ ldr(feedback_vector,
           FieldMemOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ ldr(r8, FieldMemOperand(feedback_vector, HeapObject::kMapOffset));
    __ ldrh(r8, FieldMemOperand(r8, Map::kInstanceTypeOffset));
    __ cmp(r8, Operand(FEEDBACK_VECTOR_TYPE));
    __ b(ne, &install_baseline_code);

    // Check the tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, feedback_vector, CodeKind::BASELINE, &flags_need_processing);

    // oad the baseline code into the closure.
    __ mov(r2, kInterpreterBytecodeArrayRegister);
    static_assert(kJavaScriptCallCodeStartRegister == r2, "ABI mismatch");
    __ ReplaceClosureCodeWithOptimizedCode(r2, closure);
    __ JumpCodeObject(r2);

    __ bind(&install_baseline_code);
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&compile_lazy);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ bkpt(0);  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm, Register num_args,
                                        Register start_address,
                                        Register scratch) {
  ASM_CODE_COMMENT(masm);
  // Find the argument with lowest address.
  __ sub(scratch, num_args, Operand(1));
  __ mov(scratch, Operand(scratch, LSL, kSystemPointerSizeLog2));
  __ sub(start_address, start_address, scratch);
  // Push the arguments.
  __ PushArray(start_address, num_args, scratch,
               MacroAssembler::PushArrayOrder::kReverse);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- r0 : the number of arguments
  //  -- r2 : the address of the first argument to be pushed. Subsequent
  //          arguments should be consecutive above this, in the same order as
  //          they are to be pushed onto the stack.
  //  -- r1 : the target to call (can be any Object).
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ sub(r0, r0, Operand(1));
  }

  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ sub(r3, r0, Operand(kJSArgcReceiverSlots));
  } else {
    __ mov(r3, r0);
  }

  __ StackOverflowCheck(r3, r4, &stack_overflow);

  // Push the arguments. r2 and r4 will be modified.
  GenerateInterpreterPushArgs(masm, r3, r2, r4);

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r2 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ sub(r2, r2, Operand(kSystemPointerSize));
    __ ldr(r2, MemOperand(r2));
  }

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r3 : new target
  // -- r1 : constructor to call
  // -- r2 : allocation site feedback if available, undefined otherwise.
  // -- r4 : address of the first argument
  // -----------------------------------
  Label stack_overflow;

  __ StackOverflowCheck(r0, r6, &stack_overflow);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ sub(r0, r0, Operand(1));
  }

  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r4, r5);

  // Push a slot for the receiver to be constructed.
  __ mov(r5, Operand::Zero());
  __ push(r5);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Pass the spread in the register r2.
    // r4 already points to the penultimate argument, the spread
    // lies in the next interpreter register.
    __ sub(r4, r4, Operand(kSystemPointerSize));
    __ ldr(r2, MemOperand(r4));
  } else {
    __ AssertUndefinedOrAllocationSite(r2, r5);
  }

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    __ AssertFunction(r1);

    // Tail call to the array construct stub (still in the caller
    // context at this point).
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // Call the constructor with r0, r1, and r3 unmodified.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    // Call the constructor with r0, r1, and r3 unmodified.
    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);
  }
}

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  // -- r3 : new target
  // -- r1 : constructor to call
  // -----------------------------------
  Label stack_overflow;

  // Load the frame pointer into r4.
  switch (which_frame) {
    case ForwardWhichFrame::kCurrentFrame:
      __ mov(r4, fp);
      break;
    case ForwardWhichFrame::kParentFrame:
      __ ldr(r4, MemOperand(fp, StandardFrameConstants::kCallerFPOffset));
      break;
  }

  // Load the argument count into r0.
  __ ldr(r0, MemOperand(r4, StandardFrameConstants::kArgCOffset));

  __ StackOverflowCheck(r0, r6, &stack_overflow);

  // Point r4 to the base of the argument list to forward, excluding the
  // receiver.
  __ add(r4, r4,
         Operand((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                 kSystemPointerSize));

  // Copy arguments on the stack. r5 is a scratch register.
  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  __ PushArray(r4, argc_without_receiver, r5);

  // Push a slot for the receiver to be constructed.
  __ mov(r5, Operand::Zero());
  __ push(r5);

  // Call the constructor with r0, r1, and r3 unmodified.
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    // Unreachable code.
    __ bkpt(0);
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r1 : constructor to call (checked to be a JSFunction)
  // -- r3 : new target
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------
  Register implicit_receiver = r4;

  // Save live registers.
  __ SmiTag(r0);
  __ Push(r0, r1, r3);
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ Move(implicit_receiver, r0);
  // Restore live registers.
  __ Pop(r0, r1, r3);
  __ SmiUntag(r0);

  // Patch implicit receiver (in arguments)
  __ str(implicit_receiver, MemOperand(sp, 0 * kPointerSize));
  // Patch second implicit (in construct frame)
  __ str(implicit_receiver,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));

  // Restore context.
  __ ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- r0 : argument count
  // -- r1 : constructor to call (checked to be a JSFunction)
  // -- r3 : new target
  // -- r4 : address of the first argument
  // -- cp/r7 : context pointer
  // -----------------------------------
  __ AssertFunction(r1);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  __ LoadMap(r2, r1);
  __ ldrb(r2, FieldMemOperand(r2, Map::kBitFieldOffset));
  __ tst(r2, Operand(Map::Bits1::IsConstructorBit::kMask));
  __ b(eq, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(r0, r2, &stack_overflow);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  // Implicit receiver stored in the construct frame.
  __ LoadRoot(r2, RootIndex::kTheHoleValue);
  __ Push(cp, r2);

  // Push arguments + implicit receiver.
  Register argc_without_receiver = r6;
  __ sub(argc_without_receiver, r0, Operand(kJSArgcReceiverSlots));
  // Push the arguments. r4 and r5 will be modified.
  GenerateInterpreterPushArgs(masm, argc_without_receiver, r4, r5);
  // Implicit receiver as part of the arguments (patched later if needed).
  __ push(r2);

  // Check if it is a builtin call.
  Label builtin_call;
  __ ldr(r2, FieldMemOperand(r1, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r2, FieldMemOperand(r2, SharedFunctionInfo::kFlagsOffset));
  __ tst(r2, Operand(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ b(ne, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(r2);
  __ JumpIfIsInRange(
      r2, r2, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor),
      &not_create_implicit_receiver);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the function.
  __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- r0     constructor result
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer
  // -----------------------------------

  // Store offset of return address for deoptimizer.
  masm->isolate()->heap()->SetConstructStubInvokeDeoptPCOffset(
      masm->pc_offset());

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label use_receiver, do_throw, leave_and_return, check_receiver;

  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(r0, RootIndex::kUndefinedValue, &check_receiver);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ ldr(r0,
         MemOperand(fp, FastConstructFrameConstants::kImplicitReceiverOffset));
  __ JumpIfRoot(r0, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  // Leave construct frame.
  __ LeaveFrame(StackFrame::CONSTRUCT);
  __ Jump(lr);

  __ bind(&check_receiver);
  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(r0, &use_receiver);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CompareObjectType(r0, r4, r5, FIRST_JS_RECEIVER_TYPE);
  __ b(ge, &leave_and_return);
  __ b(&use_receiver);

  __ bind(&builtin_call);
  // TODO(victorgomes): Check the possibility to turn this into a tailcall.
  __ InvokeFunctionWithNewTarget(r1, r3, r0, InvokeType::kCall);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ Jump(lr);

  __ bind(&do_throw);
  // Restore the context from the frame.
  __ ldr(cp, MemOperand(fp, FastConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  __ bkpt(0);

  __ bind(&stack_overflow);
  // Restore the context from the frame.
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  // Unreachable code.
  __ bkpt(0);

  // Called Construct on an Object that doesn't have a [[Construct]] internal
  // method.
  __ bind(&non_constructor);
  __ TailCallBuiltin(Builtin::kConstructedNonConstructable);
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
  __ ldr(r2, MemOperand(fp, StandardFrameConstants::kFunctionOffset));
  __ ldr(r2, FieldMemOperand(r2, JSFunction::kSharedFunctionInfoOffset));
  __ ldr(r2,
         FieldMemOperand(r2, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ CompareObjectType(r2, kInterpreterDispatchTableRegister,
                       kInterpreterDispatchTableRegister,
                       INTERPRETER_DATA_TYPE);
  __ b(ne, &builtin_trampoline);

  __ ldr(r2,
         FieldMemOperand(r2, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(r2, r2);
  __ b(&trampoline_loaded);

  __ bind(&builtin_trampoline);
  __ Move(r2, ExternalReference::
                  address_of_interpreter_entry_trampoline_instruction_start(
                      masm->isolate()));
  __ ldr(r2, MemOperand(r2));

  __ bind(&trampoline_loaded);
  __ add(lr, r2, Operand(interpreter_entry_return_pc_offset.value()));

  // Initialize the dispatch table register.
  __ Move(
      kInterpreterDispatchTableRegister,
      ExternalReference::interpreter_dispatch_table_address(masm->isolate()));

  // Get the bytecode array pointer from the frame.
  __ ldr(kInterpreterBytecodeArrayRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeArrayFromFp));

  if (v8_flags.debug_code) {
    // Check function data field is actually a BytecodeArray object.
    __ SmiTst(kInterpreterBytecodeArrayRegister);
    __ Assert(
        ne, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
    __ CompareObjectType(kInterpreterBytecodeArrayRegister, r1, no_reg,
                         BYTECODE_ARRAY_TYPE);
    __ Assert(
        eq, AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Get the target bytecode offset from the frame.
  __ ldr(kInterpreterBytecodeOffsetRegister,
         MemOperand(fp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  if (v8_flags.debug_code) {
    Label okay;
    __ cmp(kInterpreterBytecodeOffsetRegister,
           Operand(BytecodeArray::kHeaderSize - kHeapObjectTag));
    __ b(ge, &okay);
    __ bkpt(0);
    __ bind(&okay);
  }

  // Dispatch to the target bytecode.
  UseScratchRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ ldrb(scratch, MemOperand(kInterpreterBytecodeArrayRegister,
                              kInterpreterBytecodeOffsetRegister));
  __ ldr(kJavaScriptCallCodeStartRegister,
         MemOpera
"""


```