Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Assessment and Context:**

* **File Path:** `v8/src/builtins/ia32/builtins-ia32.cc`. This tells us several key things:
    * It's part of V8, the JavaScript engine for Chrome and Node.js.
    * It's located in the `builtins` directory, meaning it implements core JavaScript functionalities in C++.
    * The `ia32` subdirectory signifies that this specific code is for the 32-bit Intel architecture. This is important as it will involve assembly instructions specific to that architecture.
    * The `.cc` extension confirms it's a C++ source file.
* **First Line Comment:** "这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能". This directly asks for the functionality.
* **Torque Mention:** The prompt mentions `.tq` files, which indicates the presence of Torque, V8's domain-specific language for generating builtins. The absence of `.tq` is noted.
* **JavaScript Relationship:** The prompt specifically asks about the connection to JavaScript and provides an instruction to use JavaScript examples.
* **Logic Inference:** The request for input/output examples suggests a need to understand the data flow and transformation.
* **Common Errors:** Identifying common programming mistakes implies a need to look for patterns where developers might misuse these builtins or related concepts.
* **"Part 2 of 7":** This hints at a larger context and implies that this specific file deals with a subset of V8's built-in functionalities.
* **Code Snippet:** The provided C++ code uses V8's `MacroAssembler` to generate assembly instructions. Keywords like `__ mov`, `__ push`, `__ call`, `Label`, `Register`, etc., are strong indicators of assembly generation.

**2. Deeper Dive into the Code:**

* **Namespace:** The code is within the `v8::internal` namespace and further inside an anonymous namespace, then the `Builtins` namespace. This is standard V8 code organization.
* **`Generate_InterpreterEntryTrampoline`:** This is the most prominent function in the snippet. The name strongly suggests it's the entry point for executing JavaScript code in the interpreter. The comments within confirm this, mentioning "entering a JS function with the interpreter."
    * **Register State:**  The comments meticulously document the state of CPU registers upon entering this trampoline (eax, edi, edx, esi, ebp, esp). This is crucial for understanding the calling convention.
    * **Interpreter Frame:** The code builds an "interpreter frame" on the stack. The comment references `InterpreterFrameConstants`, which would be a good place to investigate further if more detail were needed.
    * **Bytecode Array:**  The code retrieves the bytecode array associated with the function. This is how JavaScript code is represented and executed in the interpreter.
    * **Feedback Vector:** There's logic related to the "feedback vector," which is used for optimization and performance tracking.
    * **Stack Checks:**  The code explicitly performs stack overflow checks.
    * **Dispatch Table:**  The code mentions a "dispatch table" and jumps to bytecode handlers. This is the core of the interpreter loop.
    * **Return Handling:**  The code handles returns from interpreted functions.
* **`Generate_InterpreterPushArgs` and Related Functions:**  These functions deal with pushing arguments onto the stack before calling a function. The different `InterpreterPushArgsMode` enums (kWithFinalSpread, kArrayFunction, etc.) indicate different calling conventions or scenarios.
* **`Generate_InterpreterPushArgsThenConstructImpl` and `Generate_ConstructForwardAllArgsImpl`:** These focus on the `new` operator and constructor calls. They involve manipulating the stack to set up the correct arguments and context for the constructor.
* **`Generate_InterpreterPushArgsThenFastConstructFunction`:** This appears to be an optimized path for constructor calls, potentially avoiding the full interpreter machinery when possible.
* **`Generate_InterpreterEnterBytecode`:** This seems responsible for setting up the execution environment when entering the interpreter.

**3. Answering the Prompt's Questions (Iterative Refinement):**

* **Functionality:**  Based on the code analysis, the primary function is to handle the entry and execution of JavaScript functions within V8's interpreter. It manages stack frames, argument passing, bytecode dispatch, and constructor calls.
* **Torque:** Explicitly state that the file is C++ and not a Torque file.
* **JavaScript Relationship (with examples):**
    * *Interpreter Entry:*  A simple function call `function foo() {} foo();` would trigger the `InterpreterEntryTrampoline`.
    * *Argument Passing:*  `function bar(a, b) {} bar(1, 2);` would involve the `InterpreterPushArgs` functions.
    * *Constructor Calls:* `function Baz() {} new Baz();` would utilize `InterpreterPushArgsThenConstructImpl` or `Generate_InterpreterPushArgsThenFastConstructFunction`.
* **Logic Inference:** Focus on the core actions: taking a function object, setting up the stack, fetching bytecode, and jumping to the interpreter loop. A simplified input/output might be:
    * *Input:* A compiled JavaScript function object (represented internally by V8).
    * *Output:* Execution of the function's bytecode within the interpreter.
* **Common Errors:**  Think about what developers might do wrong related to these low-level mechanisms. Examples include:
    * Stack overflow (though V8 handles this).
    * Incorrectly assuming argument order.
    * Issues with `this` binding (though this snippet doesn't directly show that).
    * Errors related to constructor calls (e.g., calling a non-constructor).
* **Summary:** Synthesize the key functionalities identified, emphasizing the role of this code in the interpreter's execution process.

**4. Self-Correction and Refinement:**

* **Initial thought:** Maybe focus heavily on the assembly instructions.
* **Correction:** Realize the prompt asks for *functionality*, so focus on the *purpose* of the assembly code rather than the exact instructions.
* **Initial thought:** Provide overly technical details about stack frame layout.
* **Correction:** Keep the explanation at a higher level, focusing on the *why* rather than the precise *how*. Mentioning `InterpreterFrameConstants` is sufficient for those who want to dig deeper.
* **Initial thought:**  Only focus on the `InterpreterEntryTrampoline`.
* **Correction:** Recognize the importance of the other functions related to argument passing and constructor calls and include them in the explanation.

By following this structured approach, combining code analysis with an understanding of V8's architecture and JavaScript's semantics, a comprehensive and accurate answer can be generated.
Based on the provided C++ source code snippet from `v8/src/builtins/ia32/builtins-ia32.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code defines architecture-specific (IA-32/x86) built-in functions for the V8 JavaScript engine's interpreter. Its primary purpose is to generate the assembly code required to:

1. **Enter and Execute JavaScript Functions in the Interpreter:** The `Generate_InterpreterEntryTrampoline` function is the heart of this. It sets up the necessary environment for the interpreter to begin executing a JavaScript function. This includes:
    * **Stack Frame Setup:** Creating an interpreter frame on the stack to hold local variables, arguments, and other necessary information.
    * **Accessing Bytecode:**  Retrieving the bytecode array associated with the JavaScript function.
    * **Dispatching to Bytecode Handlers:**  Loading the interpreter dispatch table and jumping to the appropriate handler for the current bytecode instruction.
    * **Handling Returns:** Processing the return value from an interpreted function and cleaning up the stack frame.
    * **OSR (On-Stack Replacement):**  Checking for opportunities to transition to optimized (compiled) code during execution.
    * **Stack Overflow Checks:** Ensuring the stack doesn't exceed its limits.
    * **Interrupt Handling:** Checking for interrupts during execution.

2. **Handle Function Calls with Argument Pushing:**  The `Generate_InterpreterPushArgsThenCallImpl` function generates code to push arguments onto the stack before making a function call. It supports different modes based on whether a receiver (`this`) needs to be explicitly provided and whether there's a spread operator involved.

3. **Handle Constructor Calls:**
   * `Generate_InterpreterPushArgsThenConstructImpl`: Generates code to push arguments onto the stack before calling a constructor using the `new` keyword.
   * `Generate_ConstructForwardAllArgsImpl`:  Implements a way to forward all arguments from an existing frame to a constructor call, useful for scenarios like extending classes.
   * `Generate_InterpreterPushArgsThenFastConstructFunction`: Provides an optimized path for constructing objects with functions, potentially bypassing some of the more general construction logic.

4. **Entering Bytecode Execution:** The `Generate_InterpreterEnterBytecode` function sets up the execution context to start interpreting bytecode. It ensures the return address points to the correct location in the interpreter entry trampoline.

**If `v8/src/builtins/ia32/builtins-ia32.cc` ended with `.tq`:**

It would indicate that the file was written using V8's **Torque** language. Torque is a domain-specific language used to generate efficient C++ code for built-in functions. While this file is in C++, if it were a `.tq` file, the high-level logic would be similar, but the syntax would be different, and Torque would handle the generation of the underlying assembly instructions.

**Relationship to JavaScript (with examples):**

This C++ code directly implements the underlying mechanics for executing JavaScript code in the interpreter. Here are JavaScript examples that would directly involve the functionalities in this file:

* **Function Call:**
   ```javascript
   function myFunction(a, b) {
     return a + b;
   }
   myFunction(5, 10); // This call would go through the interpreter entry trampoline.
   ```
   The `Generate_InterpreterEntryTrampoline` would be responsible for setting up the stack frame and initiating the execution of `myFunction`'s bytecode. `Generate_InterpreterPushArgsThenCallImpl` would handle pushing the arguments `5` and `10` onto the stack.

* **Constructor Call:**
   ```javascript
   function MyClass(name) {
     this.name = name;
   }
   const instance = new MyClass("Example"); // This involves constructor logic.
   ```
   The `Generate_InterpreterPushArgsThenConstructImpl` or `Generate_InterpreterPushArgsThenFastConstructFunction` would be involved in setting up the call to the `MyClass` constructor.

* **Function with Spread Operator:**
   ```javascript
   function sum(...numbers) {
     return numbers.reduce((acc, val) => acc + val, 0);
   }
   sum(1, 2, 3, 4); // This would likely use a variant of the argument pushing logic.
   ```
   `Generate_InterpreterPushArgsThenCallImpl` with the `kWithFinalSpread` mode would handle pushing the individual arguments from the spread operator.

**Code Logic Inference (Example with `Generate_InterpreterEntryTrampoline`):**

**Hypothetical Input:**

* A compiled `JSFunction` object representing the `myFunction` defined above.
* An argument count of 2 (for `5` and `10`).
* The arguments `5` and `10` placed on the stack.

**Expected Output:**

1. **Interpreter Frame Creation:** A new frame is pushed onto the stack, containing:
   * The previous frame pointer.
   * The current context.
   * The `JSFunction` object (`myFunction`).
   * The argument count (2).
   * The bytecode array of `myFunction`.
   * The initial bytecode offset.
   * Space for local variables.

2. **Bytecode Execution Begins:** The interpreter jumps to the first bytecode instruction of `myFunction`.

**Common Programming Errors (Related Concepts):**

While this code is low-level V8 implementation, it's related to common JavaScript errors:

* **Stack Overflow:**  While V8 handles this, excessive recursion in JavaScript can lead to stack overflow errors. The stack checks in `Generate_InterpreterEntryTrampoline` are part of the mechanism to detect this.
   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // Calls itself infinitely
   }
   recursiveFunction(); // Potential Stack Overflow
   ```

* **Incorrect Number of Arguments:** While JavaScript is flexible, calling a function with the wrong number of arguments can lead to unexpected behavior or errors, especially if the built-in logic relies on a specific argument count.

* **Calling a Non-Constructor as a Constructor:**
   ```javascript
   function notAConstructor() {
     return {};
   }
   const obj = new notAConstructor(); // May lead to unexpected results or errors depending on the function's implementation.
   ```
   The checks within `Generate_InterpreterPushArgsThenFastConstructFunction` (verifying the target has a `[[Construct]]` method) are related to preventing such errors at the engine level.

**Summary of Functionality (Part 2 of 7):**

This specific part of the `builtins-ia32.cc` file is responsible for implementing the **entry point and core mechanics for executing JavaScript code within V8's interpreter on the IA-32 architecture.** It handles setting up the execution environment, managing function calls (including those with spread operators), and facilitating constructor invocations. This code is fundamental to how V8 runs unoptimized JavaScript code.

### 提示词
```
这是目录为v8/src/builtins/ia32/builtins-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/ia32/builtins-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
backVector::kOsrStateOffset),
           scratch);
}

}  // namespace

// Generate code for entering a JS function with the interpreter.
// On entry to the function the receiver and arguments have been pushed on the
// stack left to right.
//
// The live registers are:
//   o eax: actual argument count
//   o edi: the JS function object being called
//   o edx: the incoming new target or generator object
//   o esi: our context
//   o ebp: the caller's frame pointer
//   o esp: stack pointer (pointing to return address)
//
// The function builds an interpreter frame. See InterpreterFrameConstants in
// frame-constants.h for its layout.
void Builtins::Generate_InterpreterEntryTrampoline(
    MacroAssembler* masm, InterpreterEntryTrampolineMode mode) {
  __ movd(xmm0, eax);  // Spill actual argument count.

  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));

  // The bytecode array could have been flushed from the shared function info,
  // if so, call into CompileLazy.
  Label is_baseline, compile_lazy;
  GetSharedFunctionInfoBytecodeOrBaseline(masm, ecx, ecx, eax, &is_baseline,
                                          &compile_lazy);

  Label push_stack_frame;
  Register feedback_vector = ecx;
  Register closure = edi;
  Register scratch = eax;
  __ LoadFeedbackVector(feedback_vector, closure, scratch, &push_stack_frame,
                        Label::kNear);

#ifndef V8_JITLESS
  // If feedback vector is valid, check for optimized code and update invocation
  // count. Load the optimization state from the feedback vector and re-use the
  // register.
  Label flags_need_processing;
  Register flags = ecx;
  XMMRegister saved_feedback_vector = xmm1;
  __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
      flags, saved_feedback_vector, CodeKind::INTERPRETED_FUNCTION,
      &flags_need_processing);

  // Reload the feedback vector.
  __ movd(feedback_vector, saved_feedback_vector);

  ResetFeedbackVectorOsrUrgency(masm, feedback_vector, scratch);

  // Increment the invocation count.
  __ inc(FieldOperand(feedback_vector, FeedbackVector::kInvocationCountOffset));

  // Open a frame scope to indicate that there is a frame on the stack.  The
  // MANUAL indicates that the scope shouldn't actually generate code to set
  // up the frame (that is done below).
#else
  // Note: By omitting the above code in jitless mode we also disable:
  // - kFlagsLogNextExecution: only used for logging/profiling; and
  // - kInvocationCountOffset: only used for tiering heuristics and code
  //   coverage.
#endif  // !V8_JITLESS

  __ bind(&push_stack_frame);
  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ push(ebp);  // Caller's frame pointer.
  __ mov(ebp, esp);
  __ push(kContextRegister);               // Callee's context.
  __ push(kJavaScriptCallTargetRegister);  // Callee's JS function.
  __ movd(kJavaScriptCallArgCountRegister, xmm0);
  __ push(kJavaScriptCallArgCountRegister);  // Actual argument count.

  // Get the bytecode array from the function object and load it into
  // kInterpreterBytecodeArrayRegister.
  __ mov(eax, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  ResetSharedFunctionInfoAge(masm, eax);
  __ mov(kInterpreterBytecodeArrayRegister,
         FieldOperand(eax, SharedFunctionInfo::kTrustedFunctionDataOffset));
  GetSharedFunctionInfoBytecode(masm, kInterpreterBytecodeArrayRegister, eax);

  // Check function data field is actually a BytecodeArray object.
  if (v8_flags.debug_code) {
    __ AssertNotSmi(kInterpreterBytecodeArrayRegister);
    __ CmpObjectType(kInterpreterBytecodeArrayRegister, BYTECODE_ARRAY_TYPE,
                     eax);
    __ Assert(
        equal,
        AbortReason::kFunctionDataShouldBeBytecodeArrayOnInterpreterEntry);
  }

  // Push bytecode array.
  __ push(kInterpreterBytecodeArrayRegister);
  // Push Smi tagged initial bytecode array offset.
  __ push(Immediate(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag)));
  __ push(feedback_vector);

  // Allocate the local and temporary register file on the stack.
  Label stack_overflow;
  {
    // Load frame size from the BytecodeArray object.
    Register frame_size = ecx;
    __ mov(frame_size, FieldOperand(kInterpreterBytecodeArrayRegister,
                                    BytecodeArray::kFrameSizeOffset));

    // Do a stack check to ensure we don't go over the limit.
    __ mov(eax, esp);
    __ sub(eax, frame_size);
    __ CompareStackLimit(eax, StackLimitKind::kRealStackLimit);
    __ j(below, &stack_overflow);

    // If ok, push undefined as the initial value for all register file entries.
    Label loop_header;
    Label loop_check;
    __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);
    __ jmp(&loop_check);
    __ bind(&loop_header);
    // TODO(rmcilroy): Consider doing more than one push per loop iteration.
    __ push(kInterpreterAccumulatorRegister);
    // Continue loop if not done.
    __ bind(&loop_check);
    __ sub(frame_size, Immediate(kSystemPointerSize));
    __ j(greater_equal, &loop_header);
  }

  // If the bytecode array has a valid incoming new target or generator object
  // register, initialize it with incoming value which was passed in edx.
  Label no_incoming_new_target_or_generator_register;
  __ mov(ecx, FieldOperand(
                  kInterpreterBytecodeArrayRegister,
                  BytecodeArray::kIncomingNewTargetOrGeneratorRegisterOffset));
  __ test(ecx, ecx);
  __ j(zero, &no_incoming_new_target_or_generator_register);
  __ mov(Operand(ebp, ecx, times_system_pointer_size, 0), edx);
  __ bind(&no_incoming_new_target_or_generator_register);

  // Perform interrupt stack check.
  // TODO(solanes): Merge with the real stack limit check above.
  Label stack_check_interrupt, after_stack_check_interrupt;
  __ CompareStackLimit(esp, StackLimitKind::kInterruptStackLimit);
  __ j(below, &stack_check_interrupt);
  __ bind(&after_stack_check_interrupt);

  // The accumulator is already loaded with undefined.

  __ mov(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));

  // Load the dispatch table into a register and dispatch to the bytecode
  // handler at the current bytecode offset.
  Label do_dispatch;
  __ bind(&do_dispatch);
  __ Move(kInterpreterDispatchTableRegister,
          Immediate(ExternalReference::interpreter_dispatch_table_address(
              masm->isolate())));
  __ movzx_b(ecx, Operand(kInterpreterBytecodeArrayRegister,
                          kInterpreterBytecodeOffsetRegister, times_1, 0));
  __ mov(kJavaScriptCallCodeStartRegister,
         Operand(kInterpreterDispatchTableRegister, ecx,
                 times_system_pointer_size, 0));
  __ call(kJavaScriptCallCodeStartRegister);

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
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp));
  __ SmiUntag(kInterpreterBytecodeOffsetRegister);

  // Either return, or advance to the next bytecode and dispatch.
  Label do_return;
  __ Push(eax);
  AdvanceBytecodeOffsetOrReturn(masm, kInterpreterBytecodeArrayRegister,
                                kInterpreterBytecodeOffsetRegister, ecx,
                                kInterpreterDispatchTableRegister, eax,
                                &do_return);
  __ Pop(eax);
  __ jmp(&do_dispatch);

  __ bind(&do_return);
  __ Pop(eax);
  // The return value is in eax.
  LeaveInterpreterFrame(masm, edx, ecx);
  __ ret(0);

  __ bind(&stack_check_interrupt);
  // Modify the bytecode offset in the stack to be kFunctionEntryBytecodeOffset
  // for the call to the StackGuard.
  __ mov(Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
         Immediate(Smi::FromInt(BytecodeArray::kHeaderSize - kHeapObjectTag +
                                kFunctionEntryBytecodeOffset)));
  __ CallRuntime(Runtime::kStackGuard);

  // After the call, restore the bytecode array, bytecode offset and accumulator
  // registers again. Also, restore the bytecode offset in the stack to its
  // previous value.
  __ mov(kInterpreterBytecodeArrayRegister,
         Operand(ebp, InterpreterFrameConstants::kBytecodeArrayFromFp));
  __ mov(kInterpreterBytecodeOffsetRegister,
         Immediate(BytecodeArray::kHeaderSize - kHeapObjectTag));
  __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue);

  // It's ok to clobber kInterpreterBytecodeOffsetRegister since we are setting
  // it again after continuing.
  __ SmiTag(kInterpreterBytecodeOffsetRegister);
  __ mov(Operand(ebp, InterpreterFrameConstants::kBytecodeOffsetFromFp),
         kInterpreterBytecodeOffsetRegister);

  __ jmp(&after_stack_check_interrupt);

#ifndef V8_JITLESS
  __ bind(&flags_need_processing);
  {
    // Restore actual argument count.
    __ movd(eax, xmm0);
    __ OptimizeCodeOrTailCallOptimizedCodeSlot(flags, xmm1);
  }

  __ bind(&compile_lazy);
  // Restore actual argument count.
  __ movd(eax, xmm0);
  __ GenerateTailCallToReturnedCode(Runtime::kCompileLazy);

  __ bind(&is_baseline);
  {
    __ movd(xmm2, ecx);  // Save baseline data.
    // Load the feedback vector from the closure.
    __ mov(feedback_vector,
           FieldOperand(closure, JSFunction::kFeedbackCellOffset));
    __ mov(feedback_vector,
           FieldOperand(feedback_vector, FeedbackCell::kValueOffset));

    Label install_baseline_code;
    // Check if feedback vector is valid. If not, call prepare for baseline to
    // allocate it.
    __ LoadMap(eax, feedback_vector);
    __ CmpInstanceType(eax, FEEDBACK_VECTOR_TYPE);
    __ j(not_equal, &install_baseline_code);

    // Check the tiering state.
    __ LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
        flags, xmm1, CodeKind::BASELINE, &flags_need_processing);

    // Load the baseline code into the closure.
    __ movd(ecx, xmm2);
    static_assert(kJavaScriptCallCodeStartRegister == ecx, "ABI mismatch");
    __ push(edx);  // Spill.
    __ push(ecx);
    __ Push(xmm0, eax);  // Save the argument count (currently in xmm0).
    __ ReplaceClosureCodeWithOptimizedCode(ecx, closure, eax, ecx);
    __ pop(eax);  // Restore the argument count.
    __ pop(ecx);
    __ pop(edx);
    __ JumpCodeObject(ecx);

    __ bind(&install_baseline_code);
    __ movd(eax, xmm0);  // Recover argument count.
    __ GenerateTailCallToReturnedCode(Runtime::kInstallBaselineCode);
  }
#endif  // !V8_JITLESS

  __ bind(&stack_overflow);
  __ CallRuntime(Runtime::kThrowStackOverflow);
  __ int3();  // Should not return.
}

static void GenerateInterpreterPushArgs(MacroAssembler* masm,
                                        Register array_limit,
                                        Register start_address) {
  // ----------- S t a t e -------------
  //  -- start_address : Pointer to the last argument in the args array.
  //  -- array_limit : Pointer to one before the first argument in the
  //                   args array.
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  Label loop_header, loop_check;
  __ jmp(&loop_check);
  __ bind(&loop_header);
  __ Push(Operand(array_limit, 0));
  __ bind(&loop_check);
  __ add(array_limit, Immediate(kSystemPointerSize));
  __ cmp(array_limit, start_address);
  __ j(below_equal, &loop_header, Label::kNear);
}

// static
void Builtins::Generate_InterpreterPushArgsThenCallImpl(
    MacroAssembler* masm, ConvertReceiverMode receiver_mode,
    InterpreterPushArgsMode mode) {
  DCHECK(mode != InterpreterPushArgsMode::kArrayFunction);
  // ----------- S t a t e -------------
  //  -- eax : the number of arguments
  //  -- ecx : the address of the first argument to be pushed. Subsequent
  //           arguments should be consecutive above this, in the same order as
  //           they are to be pushed onto the stack.
  //  -- edi : the target to call (can be any Object).
  // -----------------------------------

  const Register scratch = edx;
  const Register argv = ecx;

  Label stack_overflow;
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ dec(eax);
  }

  // Add a stack check before pushing the arguments.
  __ StackOverflowCheck(eax, scratch, &stack_overflow, true);
  __ movd(xmm0, eax);  // Spill number of arguments.

  // Compute the expected number of arguments.
  __ mov(scratch, eax);
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ dec(scratch);  // Exclude receiver.
  }

  // Pop return address to allow tail-call after pushing arguments.
  __ PopReturnAddressTo(eax);

  // Find the address of the last argument.
  __ shl(scratch, kSystemPointerSizeLog2);
  __ neg(scratch);
  __ add(scratch, argv);

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ movd(xmm1, scratch);
    GenerateInterpreterPushArgs(masm, scratch, argv);
    // Pass the spread in the register ecx.
    __ movd(ecx, xmm1);
    __ mov(ecx, Operand(ecx, 0));
  } else {
    GenerateInterpreterPushArgs(masm, scratch, argv);
  }

  // Push "undefined" as the receiver arg if we need to.
  if (receiver_mode == ConvertReceiverMode::kNullOrUndefined) {
    __ PushRoot(RootIndex::kUndefinedValue);
  }

  __ PushReturnAddressFrom(eax);
  __ movd(eax, xmm0);  // Restore number of arguments.

  // Call the target.
  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ TailCallBuiltin(Builtin::kCallWithSpread);
  } else {
    __ TailCallBuiltin(Builtins::Call(receiver_mode));
  }

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);

    // This should be unreachable.
    __ int3();
  }
}

namespace {

// This function modifies start_addr, and only reads the contents of num_args
// register. scratch1 and scratch2 are used as temporary registers.
void Generate_InterpreterPushZeroAndArgsAndReturnAddress(
    MacroAssembler* masm, Register num_args, Register start_addr,
    Register scratch1, Register scratch2, int num_slots_to_move,
    Label* stack_overflow) {
  // We have to move return address and the temporary registers above it
  // before we can copy arguments onto the stack. To achieve this:
  // Step 1: Increment the stack pointer by num_args + 1 for receiver (if it is
  // not included in argc already). Step 2: Move the return address and values
  // around it to the top of stack. Step 3: Copy the arguments into the correct
  // locations.
  //  current stack    =====>    required stack layout
  // |             |            | return addr   | (2) <-- esp (1)
  // |             |            | addtl. slot   |
  // |             |            | arg N         | (3)
  // |             |            | ....          |
  // |             |            | arg 1         |
  // | return addr | <-- esp    | arg 0         |
  // | addtl. slot |            | receiver slot |

  // Check for stack overflow before we increment the stack pointer.
  __ StackOverflowCheck(num_args, scratch1, stack_overflow, true);

  // Step 1 - Update the stack pointer.

  __ lea(scratch1, Operand(num_args, times_system_pointer_size, 0));
  __ AllocateStackSpace(scratch1);

  // Step 2 move return_address and slots around it to the correct locations.
  // Move from top to bottom, otherwise we may overwrite when num_args = 0 or 1,
  // basically when the source and destination overlap. We at least need one
  // extra slot for receiver, so no extra checks are required to avoid copy.
  for (int i = 0; i < num_slots_to_move + 1; i++) {
    __ mov(scratch1, Operand(esp, num_args, times_system_pointer_size,
                             i * kSystemPointerSize));
    __ mov(Operand(esp, i * kSystemPointerSize), scratch1);
  }

  // Step 3 copy arguments to correct locations.
  // Slot meant for receiver contains return address. Reset it so that
  // we will not incorrectly interpret return address as an object.
  __ mov(Operand(esp, (num_slots_to_move + 1) * kSystemPointerSize),
         Immediate(0));
  __ mov(scratch1, Immediate(0));

  Label loop_header, loop_check;
  __ jmp(&loop_check);
  __ bind(&loop_header);
  __ mov(scratch2, Operand(start_addr, 0));
  __ mov(Operand(esp, scratch1, times_system_pointer_size,
                 (num_slots_to_move + 1) * kSystemPointerSize),
         scratch2);
  __ sub(start_addr, Immediate(kSystemPointerSize));
  __ bind(&loop_check);
  __ inc(scratch1);
  __ cmp(scratch1, eax);
  __ j(less, &loop_header, Label::kNear);
}

}  // anonymous namespace

// static
void Builtins::Generate_InterpreterPushArgsThenConstructImpl(
    MacroAssembler* masm, InterpreterPushArgsMode mode) {
  // ----------- S t a t e -------------
  //  -- eax     : the number of arguments
  //  -- ecx     : the address of the first argument to be pushed. Subsequent
  //               arguments should be consecutive above this, in the same order
  //               as they are to be pushed onto the stack.
  //  -- esp[0]  : return address
  //  -- esp[4]  : allocation site feedback (if available or undefined)
  //  -- esp[8]  : the new target
  //  -- esp[12] : the constructor
  // -----------------------------------
  Label stack_overflow;

  if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    // The spread argument should not be pushed.
    __ dec(eax);
  }

  // Push arguments and move return address and stack spill slots to the top of
  // stack. The eax register is readonly. The ecx register will be modified. edx
  // and edi are used as scratch registers.
  Generate_InterpreterPushZeroAndArgsAndReturnAddress(
      masm, eax, ecx, edx, edi,
      InterpreterPushArgsThenConstructDescriptor::GetStackParameterCount(),
      &stack_overflow);

  // Call the appropriate constructor. eax and ecx already contain intended
  // values, remaining registers still need to be initialized from the stack.

  if (mode == InterpreterPushArgsMode::kArrayFunction) {
    // Tail call to the array construct stub (still in the caller context at
    // this point).

    __ movd(xmm0, eax);  // Spill number of arguments.
    __ PopReturnAddressTo(eax);
    __ Pop(kJavaScriptCallExtraArg1Register);
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    __ PushReturnAddressFrom(eax);

    __ AssertFunction(kJavaScriptCallTargetRegister, eax);
    __ AssertUndefinedOrAllocationSite(kJavaScriptCallExtraArg1Register, eax);

    __ movd(eax, xmm0);  // Reload number of arguments.
    __ TailCallBuiltin(Builtin::kArrayConstructorImpl);
  } else if (mode == InterpreterPushArgsMode::kWithFinalSpread) {
    __ movd(xmm0, eax);  // Spill number of arguments.
    __ PopReturnAddressTo(eax);
    __ Drop(1);  // The allocation site is unused.
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    // Pass the spread in the register ecx, overwriting ecx.
    __ mov(ecx, Operand(ecx, 0));
    __ PushReturnAddressFrom(eax);
    __ movd(eax, xmm0);  // Reload number of arguments.
    __ TailCallBuiltin(Builtin::kConstructWithSpread);
  } else {
    DCHECK_EQ(InterpreterPushArgsMode::kOther, mode);
    __ PopReturnAddressTo(ecx);
    __ Drop(1);  // The allocation site is unused.
    __ Pop(kJavaScriptCallNewTargetRegister);
    __ Pop(kJavaScriptCallTargetRegister);
    __ PushReturnAddressFrom(ecx);

    __ TailCallBuiltin(Builtin::kConstruct);
  }

  __ bind(&stack_overflow);
  __ TailCallRuntime(Runtime::kThrowStackOverflow);
  __ int3();
}

namespace {
void LoadFramePointer(MacroAssembler* masm, Register to,
                      Builtins::ForwardWhichFrame which_frame) {
  switch (which_frame) {
    case Builtins::ForwardWhichFrame::kCurrentFrame:
      __ mov(to, ebp);
      break;
    case Builtins::ForwardWhichFrame::kParentFrame:
      __ mov(to, Operand(ebp, StandardFrameConstants::kCallerFPOffset));
      break;
  }
}
}  // namespace

// static
void Builtins::Generate_ConstructForwardAllArgsImpl(
    MacroAssembler* masm, ForwardWhichFrame which_frame) {
  // ----------- S t a t e -------------
  //  -- edx     : the new target
  //  -- edi     : the constructor
  //  -- esp[0]  : return address
  // -----------------------------------
  Label stack_overflow;

  // Load the frame into ecx.
  LoadFramePointer(masm, ecx, which_frame);

  // Load the argument count into eax.
  __ mov(eax, Operand(ecx, StandardFrameConstants::kArgCOffset));

  // The following stack surgery is performed to forward arguments from the
  // interpreted frame.
  //
  //  current stack    =====>    required stack layout
  // |             |            | saved new target  | (2)
  // |             |            | saved constructor | (2)
  // |             |            | return addr       | (3) <-- esp (1)
  // |             |            | arg N             | (5)
  // |             |            | ....              | (5)
  // |             |            | arg 0             | (5)
  // | return addr | <-- esp    | 0 (receiver)      | (4)
  //
  // The saved new target and constructor are popped to their respective
  // registers before calling the Construct builtin.

  // Step 1
  //
  // Update the stack pointer, using ecx as a scratch register.
  __ StackOverflowCheck(eax, ecx, &stack_overflow, true);
  __ lea(ecx, Operand(eax, times_system_pointer_size, 0));
  __ AllocateStackSpace(ecx);

  // Step 2
  //
  // Save the new target and constructor on the stack so they can be used as
  // scratch registers.
  __ Push(edi);
  __ Push(edx);

  // Step 3
  //
  // Move the return address. Stack address computations have to be offset by
  // the saved constructor and new target on the stack.
  constexpr int spilledConstructorAndNewTargetOffset = 2 * kSystemPointerSize;
  __ mov(edx, Operand(esp, eax, times_system_pointer_size,
                      spilledConstructorAndNewTargetOffset));
  __ mov(Operand(esp, spilledConstructorAndNewTargetOffset), edx);

  // Step 4
  // Push a 0 for the receiver to be allocated.
  __ mov(
      Operand(esp, kSystemPointerSize + spilledConstructorAndNewTargetOffset),
      Immediate(0));

  // Step 5
  //
  // Forward the arguments from the frame.

  // First reload the frame pointer into ecx.
  LoadFramePointer(masm, ecx, which_frame);

  // Point ecx to the base of the arguments, excluding the receiver.
  __ add(ecx, Immediate((StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
                        kSystemPointerSize));
  {
    // Copy the arguments.
    Register counter = edx;
    Register scratch = edi;

    Label loop, entry;
    __ mov(counter, eax);
    __ jmp(&entry);
    __ bind(&loop);
    // The source frame's argument is offset by -kSystemPointerSize because the
    // counter with an argument count inclusive of the receiver.
    __ mov(scratch, Operand(ecx, counter, times_system_pointer_size,
                            -kSystemPointerSize));
    // Similarly, the target frame's argument is offset by +kSystemPointerSize
    // because we pushed a 0 for the receiver to be allocated.
    __ mov(Operand(esp, counter, times_system_pointer_size,
                   kSystemPointerSize + spilledConstructorAndNewTargetOffset),
           scratch);
    __ bind(&entry);
    __ dec(counter);
    __ j(greater_equal, &loop, Label::kNear);
  }

  // Pop the saved constructor and new target, then call the appropriate
  // constructor. eax already contains the argument count.
  __ Pop(kJavaScriptCallNewTargetRegister);
  __ Pop(kJavaScriptCallTargetRegister);
  __ TailCallBuiltin(Builtin::kConstruct);

  __ bind(&stack_overflow);
  {
    __ TailCallRuntime(Runtime::kThrowStackOverflow);
    __ int3();
  }
}

namespace {

void NewImplicitReceiver(MacroAssembler* masm) {
  // ----------- S t a t e -------------
  // -- eax : argument count
  // -- edi : constructor to call
  // -- edx : new target (checked to be a JSFunction)
  //
  //  Stack:
  //  -- Implicit Receiver
  //  -- [arguments without receiver]
  //  -- Implicit Receiver
  //  -- Context
  //  -- FastConstructMarker
  //  -- FramePointer

  Register implicit_receiver = ecx;

  // Save live registers.
  __ SmiTag(eax);
  __ Push(eax);  // Number of arguments
  __ Push(edx);  // NewTarget
  __ Push(edi);  // Target
  __ CallBuiltin(Builtin::kFastNewObject);
  // Save result.
  __ mov(implicit_receiver, eax);
  // Restore live registers.
  __ Pop(edi);
  __ Pop(edx);
  __ Pop(eax);
  __ SmiUntag(eax);

  // Patch implicit receiver (in arguments)
  __ mov(Operand(esp, 0 /* first argument */), implicit_receiver);
  // Patch second implicit (in construct frame)
  __ mov(Operand(ebp, FastConstructFrameConstants::kImplicitReceiverOffset),
         implicit_receiver);

  // Restore context.
  __ mov(esi, Operand(ebp, FastConstructFrameConstants::kContextOffset));
}

}  // namespace

// static
void Builtins::Generate_InterpreterPushArgsThenFastConstructFunction(
    MacroAssembler* masm) {
  // ----------- S t a t e -------------
  //  -- eax     : the number of arguments
  //  -- ecx     : the address of the first argument to be pushed. Subsequent
  //               arguments should be consecutive above this, in the same order
  //               as they are to be pushed onto the stack.
  //  -- esi     : the context
  //  -- esp[0]  : return address
  //  -- esp[4]  : allocation site feedback (if available or undefined)
  //  -- esp[8]  : the new target
  //  -- esp[12] : the constructor (checked to be a JSFunction)
  // -----------------------------------

  // Load constructor.
  __ mov(edi, Operand(esp, 3 * kSystemPointerSize));
  __ AssertFunction(edi, edx);

  // Check if target has a [[Construct]] internal method.
  Label non_constructor;
  // Load constructor.
  __ LoadMap(edx, edi);
  __ test_b(FieldOperand(edx, Map::kBitFieldOffset),
            Immediate(Map::Bits1::IsConstructorBit::kMask));
  __ j(zero, &non_constructor);

  // Add a stack check before pushing arguments.
  Label stack_overflow;
  __ StackOverflowCheck(eax, edx, &stack_overflow, true);

  // Spill number of arguments.
  __ movd(xmm0, eax);

  // Load NewTarget.
  __ mov(edx, Operand(esp, 2 * kSystemPointerSize));

  // Drop stub arguments from the stack.
  __ PopReturnAddressTo(eax);
  __ Drop(3);  // The allocation site is unused.
  __ PushReturnAddressFrom(eax);

  // Enter a construct frame.
  FrameScope scope(masm, StackFrame::MANUAL);
  __ EnterFrame(StackFrame::FAST_CONSTRUCT);
  __ Push(esi);
  // Implicit receiver stored in the construct frame.
  __ PushRoot(RootIndex::kTheHoleValue);

  // Push arguments + implicit receiver
  __ movd(eax, xmm0);  // Recover number of arguments.
  // Find the address of the last argument.
  __ lea(esi, Operand(eax, times_system_pointer_size,
                      -kJSArgcReceiverSlots * kSystemPointerSize));
  __ neg(esi);
  __ add(esi, ecx);
  GenerateInterpreterPushArgs(masm, esi, ecx);
  __ PushRoot(RootIndex::kTheHoleValue);

  // Restore context.
  __ mov(esi, Operand(ebp, FastConstructFrameConstants::kContextOffset));

  // Check if it is a builtin call.
  Label builtin_call;
  __ mov(ecx, FieldOperand(edi, JSFunction::kSharedFunctionInfoOffset));
  __ test(FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset),
          Immediate(SharedFunctionInfo::ConstructAsBuiltinBit::kMask));
  __ j(not_zero, &builtin_call);

  // Check if we need to create an implicit receiver.
  Label not_create_implicit_receiver;
  __ mov(ecx, FieldOperand(ecx, SharedFunctionInfo::kFlagsOffset));
  __ DecodeField<SharedFunctionInfo::FunctionKindBits>(ecx);
  __ JumpIfIsInRange(
      ecx, static_cast<uint32_t>(FunctionKind::kDefaultDerivedConstructor),
      static_cast<uint32_t>(FunctionKind::kDerivedConstructor), ecx,
      &not_create_implicit_receiver, Label::kNear);
  NewImplicitReceiver(masm);
  __ bind(&not_create_implicit_receiver);

  // Call the constructor.
  __ InvokeFunction(edi, edx, eax, InvokeType::kCall);

  // ----------- S t a t e -------------
  //  -- eax     constructor result
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

  Label check_result, use_receiver, do_throw, leave_and_return;
  // If the result is undefined, we jump out to using the implicit receiver.
  __ JumpIfNotRoot(eax, RootIndex::kUndefinedValue, &check_result,
                   Label::kNear);

  // Throw away the result of the constructor invocation and use the
  // on-stack receiver as the result.
  __ bind(&use_receiver);
  __ mov(eax, Operand(esp, 0 * kSystemPointerSize));
  __ JumpIfRoot(eax, RootIndex::kTheHoleValue, &do_throw);

  __ bind(&leave_and_return);
  __ LeaveFrame(StackFrame::FAST_CONSTRUCT);
  __ ret(0);

  // Otherwise we do a smi check and fall through to check if the return value
  // is a valid receiver.
  __ bind(&check_result);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(eax, &use_receiver, Label::kNear);

  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  __ CmpObjectType(eax, FIRST_JS_RECEIVER_TYPE, ecx);
  __ j(above_equal, &leave_and_return, Label::kNear);
  __ jmp(&use_receiver, Label::kNear);

  __ bind(&do_throw);
  // Restore context from the frame.
  __ mov(esi, Operand(ebp, ConstructFrameConstants::kContextOffset));
  __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
  // This should be unreachable.
  __ int3();

  __ bind(&builtin_call);
  __ InvokeFunction(edi, edx, eax, InvokeType::kCall);
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
}

static void Generate_InterpreterEnterBytecode(MacroAssembler* masm) {
  // Set the return address to the correct point in the interpreter entry
  // trampoline.
  Label builtin_trampoline, trampoline_loaded;
  Tagged<Smi> interpreter_entry_return_pc_offset(
      masm->isolate()->heap()->interpreter_entry_return_pc_offset());
  DCHECK_NE(interpreter_entry_return_pc_offset, Smi::zero());

  static constexpr Register scratch = ecx;

  // If the SFI function_data is an InterpreterData, the function will have a
  // custom copy of the interpreter entry trampoline for profiling. If so,
  // get the custom trampoline, otherwise grab the entry address of the global
  // trampoline.
  __ mov(scratch, Operand(ebp, StandardFrameConstants::kFunctionOffset));
  __ mov(scratch, FieldOperand(scratch, JSFunction::kSharedFunctionInfoOffset));
  __ mov(scratch,
         FieldOperand(scratch, SharedFunctionInfo::kTrustedFunctionDataOffset));
  __ Push(eax);
  __ CmpObjectType(scratch, INTERPRETER_DATA_TYPE, eax);
  __ j(not_equal, &builtin_trampoline, Label::kNear);

  __ mov(scratch,
         FieldOperand(scratch, InterpreterData::kInterpreterTrampolineOffset));
  __ LoadCodeInstructionStart(scratch, scratch);
  __ jmp(&trampoline_loaded, Label::kNear);

  __ bind(&builtin_trampoline);
  __ mov(scratch,
         __ ExternalReferenceAsOperand(
             ExternalReference::
                 address_of_interpreter_entry_trampoline_instruction_start(
                     masm->isolate()),
             scratch));

  __ bind(&trampoline_loaded);
  __ Pop(eax);
  __ add(scratch, Immediate(interpreter_entry_return_pc_offset.value()));
  __ push(scratch);

  // Initialize the dispatch
```